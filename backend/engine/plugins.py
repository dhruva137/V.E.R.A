"""The discovery plugin framework — VERA's sensor layer.

WHY THIS EXISTS
---------------
The first build treated discovery as a fixed set of four collectors called in a
row. A real estate is not like that: every organisation has a different mix of
sources (repos, container registries, load balancers, HSMs, key managers, agents
on hosts), and each source produces evidence of a *different quality*. A TLS
handshake actually observed on the wire is a fact. A regex match on a source file
is a hint. Treating both as "an asset" is how inventories become untrustworthy.

So discovery is a **plugin surface** with two properties the old design lacked:

1. **Plugins are registered, not hardcoded.** Each declares what it is, where it
   runs, and whether it is currently available. New sources (PKCS#11, KMIP, cloud
   KMS, eBPF) are added by registering a plugin, not by editing a scan function.

2. **Every finding carries its provenance, and provenance sets confidence.**
   An asset knows *how it was learned*, and that grade travels with it into the
   engine and onto the screen. Nothing is asserted at a confidence its evidence
   does not support.

DESIGN NOTES
------------
Confidence is a property of the *method*, not of the finding, and is therefore a
constant per provenance rather than a model output. That keeps it inspectable:
an operator can ask "why is this 0.55?" and get "because a regex matched a call
site, and that is what regex matches are worth", not "because a model said so".

Correlation is deliberately conservative. Two plugins reporting the same asset
raise confidence (independent corroboration), but never above the ceiling of the
strongest single method — agreement between two weak sensors does not manufacture
a fact.

No plugin here calls a language model. A model may later *triage* findings (see
`engine/triage.py`), but it never creates one and never sets a number.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Callable, Iterable, Optional

from models.schemas import RawCryptoFinding

# --------------------------------------------------------------------------
# Provenance — how a finding was learned, and what that is worth
# --------------------------------------------------------------------------

# Ordered strongest to weakest. The numbers are evidence grades, not
# probabilities: they express how much of the claim the method actually
# establishes, and they are used to rank and to label, never multiplied into the
# risk score. (Risk is about consequence; confidence is about knowledge. Mixing
# them would let a well-observed low-risk asset outrank a barely-seen critical
# one.)
PROVENANCE: dict[str, dict] = {
    "runtime_observed": {
        "label": "Observed at runtime",
        "confidence": 0.98,
        "rationale": (
            "The cryptography was seen in use — a completed handshake or a traced "
            "kernel call. This is the only method that proves an asset is live "
            "rather than merely present."
        ),
    },
    "artifact_parsed": {
        "label": "Parsed from an artifact",
        "confidence": 0.90,
        "rationale": (
            "A certificate, keystore or key object was parsed directly, so the "
            "algorithm and parameters are read, not inferred. Does not prove the "
            "artifact is in service."
        ),
    },
    "declared": {
        "label": "Declared by an authority",
        "confidence": 0.85,
        "rationale": (
            "Reported by a system of record that owns the object — an HSM over "
            "PKCS#11, a key manager over KMIP, a cloud KMS API. Authoritative "
            "about existence and parameters."
        ),
    },
    "config_parsed": {
        "label": "Read from configuration",
        "confidence": 0.70,
        "rationale": (
            "A protocol or cipher directive was read from a configuration file. "
            "Accurate about intent; the running process may differ."
        ),
    },
    "imported": {
        "label": "Imported",
        "confidence": 0.65,
        "rationale": (
            "Supplied by a third-party CBOM or inventory export. Trusted as far as "
            "its author is; VERA did not observe it."
        ),
    },
    "static_analysis": {
        "label": "Found by static analysis",
        "confidence": 0.55,
        "rationale": (
            "A cryptographic call site was matched in source. Proves the code "
            "exists; proves nothing about whether it runs, or with what parameters "
            "when the algorithm is chosen at runtime."
        ),
    },
    "heuristic": {
        "label": "Heuristic match",
        "confidence": 0.35,
        "rationale": (
            "Matched by shape alone — entropy, naming, or format — with no parser "
            "confirming it. Requires human review before it is treated as real."
        ),
    },
    "inferred": {
        "label": "Inferred",
        "confidence": 0.25,
        "rationale": (
            "Derived from a relationship rather than seen, such as a dependency "
            "implied by shared tags. Useful for structure, not for assertion."
        ),
    },
}

# The strongest grade any amount of corroboration can reach. Two independent
# weak sensors agreeing is meaningful, but it is not an observation.
_CORROBORATION_CEILING = 0.95
_CORROBORATION_BONUS = 0.06


def confidence_for(provenance: str) -> float:
    """Evidence grade for a provenance, defaulting to the weakest known grade."""
    return PROVENANCE.get(provenance, PROVENANCE["inferred"])["confidence"]


def corroborate(provenances: Iterable[str]) -> float:
    """Combined confidence when several methods report the same asset.

    Takes the strongest single grade and adds a small bonus per additional
    independent method, capped below "observed". Independence is assumed at the
    method level: two regex rules are one method, a regex and a handshake are two.
    """
    grades = sorted({p for p in provenances}, key=confidence_for, reverse=True)
    if not grades:
        return 0.0
    best = confidence_for(grades[0])
    if len(grades) == 1:
        return round(best, 4)
    combined = best + _CORROBORATION_BONUS * (len(grades) - 1)
    return round(min(combined, max(best, _CORROBORATION_CEILING)), 4)


# --------------------------------------------------------------------------
# Plugin surface
# --------------------------------------------------------------------------


@dataclass
class PluginResult:
    """What one plugin run produced, plus how it went.

    A failed run is a first-class outcome, not an exception that vanishes: an
    inventory with a silently dead sensor is more dangerous than one that says
    "this source did not report".
    """

    plugin_id: str
    findings: list[RawCryptoFinding] = field(default_factory=list)
    ok: bool = True
    detail: str = ""
    duration_ms: float = 0.0

    @property
    def count(self) -> int:
        return len(self.findings)


class DiscoveryPlugin(ABC):
    """One source of cryptographic findings.

    Subclasses declare their identity and provenance, and implement `collect`.
    Everything else — timing, error containment, provenance stamping — is handled
    by `run` so no plugin can forget to do it.
    """

    #: Stable machine identifier, used in the API and the UI.
    id: str = ""
    #: Human name shown on the discovery surface.
    name: str = ""
    #: Which provenance grade this plugin's findings carry.
    provenance: str = "inferred"
    #: Where the sensor runs, for the operator's mental model of the estate.
    zone: str = "local"
    #: One line describing what it actually reads.
    description: str = ""
    #: True when the plugin needs credentials or a reachable endpoint it lacks.
    requires_configuration: bool = False
    #: Optional adapter coverage contract (proves / cannot_prove / requires).
    coverage_contract: Optional[dict] = None
    #: Optional measurement status (file_dump vs live vs unavailable).
    measurement: Optional[dict] = None

    @abstractmethod
    def collect(self, **kwargs) -> list[RawCryptoFinding]:
        """Produce findings. Raise freely; `run` contains the failure."""

    def available(self) -> tuple[bool, str]:
        """Whether this plugin can run right now, and why not if it cannot."""
        return True, ""

    def run(self, **kwargs) -> PluginResult:
        """Execute `collect` with timing, error containment and provenance stamping."""
        started = time.perf_counter()
        ok_to_run, reason = self.available()
        if not ok_to_run:
            return PluginResult(
                plugin_id=self.id,
                ok=False,
                detail=reason or "Not available.",
                duration_ms=round((time.perf_counter() - started) * 1000, 2),
            )

        try:
            findings = self.collect(**kwargs) or []
        except Exception as exc:  # noqa: BLE001 - a dead sensor must be reported, not raised
            return PluginResult(
                plugin_id=self.id,
                ok=False,
                detail=f"{type(exc).__name__}: {exc}",
                duration_ms=round((time.perf_counter() - started) * 1000, 2),
            )

        # Stamp provenance and confidence on every finding, centrally, so a
        # plugin cannot claim a grade it was not registered with.
        for finding in findings:
            finding.raw_details.setdefault("provenance", self.provenance)
            finding.raw_details.setdefault("confidence", confidence_for(self.provenance))
            finding.raw_details.setdefault("discovered_by", self.id)

        return PluginResult(
            plugin_id=self.id,
            findings=findings,
            ok=True,
            duration_ms=round((time.perf_counter() - started) * 1000, 2),
        )

    def describe(self) -> dict:
        """The plugin's card on the discovery surface."""
        ok_to_run, reason = self.available()
        grade = PROVENANCE.get(self.provenance, PROVENANCE["inferred"])
        card = {
            "id": self.id,
            "name": self.name,
            "zone": self.zone,
            "description": self.description,
            "provenance": self.provenance,
            "provenance_label": grade["label"],
            "confidence": grade["confidence"],
            "confidence_rationale": grade["rationale"],
            "available": ok_to_run,
            "unavailable_reason": reason,
            "requires_configuration": self.requires_configuration,
        }
        if self.coverage_contract is not None:
            card["coverage_contract"] = self.coverage_contract
        if self.measurement is not None:
            card["measurement"] = self.measurement
            # Prefer the measurement label for UI when live is down but a dump exists.
            mode = self.measurement.get("mode")
            if mode == "file_dump" and not ok_to_run:
                card["status_label"] = self.measurement.get(
                    "label", "Measurable via file dump"
                )
            elif ok_to_run:
                card["status_label"] = "active"
            else:
                card["status_label"] = "not connected"
        return card



class FunctionPlugin(DiscoveryPlugin):
    """Adapts an existing collector function into a plugin.

    The original collectors are plain functions and there is no reason to rewrite
    them; this wraps one without changing its behaviour.
    """

    def __init__(
        self,
        *,
        id: str,
        name: str,
        provenance: str,
        zone: str,
        description: str,
        fn: Callable[..., list[RawCryptoFinding]],
        availability: Optional[Callable[[], tuple[bool, str]]] = None,
        requires_configuration: bool = False,
        coverage_contract: Optional[dict] = None,
        measurement: Optional[Callable[[], Optional[dict]]] = None,
    ):
        self.id = id
        self.name = name
        self.provenance = provenance
        self.zone = zone
        self.description = description
        self.requires_configuration = requires_configuration
        self.coverage_contract = coverage_contract
        self._fn = fn
        self._availability = availability
        self._measurement = measurement

    @property
    def measurement(self) -> Optional[dict]:
        if self._measurement is None:
            return None
        return self._measurement()

    def available(self) -> tuple[bool, str]:
        if self._availability is None:
            return True, ""
        return self._availability()

    def collect(self, **kwargs) -> list[RawCryptoFinding]:
        return self._fn(**kwargs)


# --------------------------------------------------------------------------
# Registry
# --------------------------------------------------------------------------


class PluginRegistry:
    """The set of discovery plugins this instance knows about."""

    def __init__(self):
        self._plugins: dict[str, DiscoveryPlugin] = {}

    def register(self, plugin: DiscoveryPlugin) -> DiscoveryPlugin:
        if not plugin.id:
            raise ValueError("A discovery plugin needs a stable id.")
        if plugin.id in self._plugins:
            raise ValueError(f"Duplicate plugin id: {plugin.id}")
        self._plugins[plugin.id] = plugin
        return plugin

    def get(self, plugin_id: str) -> Optional[DiscoveryPlugin]:
        return self._plugins.get(plugin_id)

    def all(self) -> list[DiscoveryPlugin]:
        return list(self._plugins.values())

    def describe_all(self) -> list[dict]:
        return [p.describe() for p in self._plugins.values()]

    def run(self, plugin_id: str, **kwargs) -> PluginResult:
        plugin = self._plugins.get(plugin_id)
        if plugin is None:
            return PluginResult(plugin_id=plugin_id, ok=False, detail="No such plugin.")
        return plugin.run(**kwargs)

    def coverage(self) -> dict:
        """What this estate can currently see, and what it is blind to.

        The honest counterpart to a discovery report: an inventory is only as
        complete as the sensors that produced it, so the gaps are stated
        alongside the findings rather than left to be assumed absent.
        """
        described = self.describe_all()
        active = [d for d in described if d["available"]]
        blind = [d for d in described if not d["available"]]
        return {
            "total_plugins": len(described),
            "active": len(active),
            "unavailable": len(blind),
            "active_ids": [d["id"] for d in active],
            "blind_spots": [
                {"id": d["id"], "name": d["name"], "reason": d["unavailable_reason"]}
                for d in blind
            ],
            "max_confidence_available": max(
                (d["confidence"] for d in active), default=0.0
            ),
        }


#: The process-wide registry. Populated by `engine.discovery`.
REGISTRY = PluginRegistry()
