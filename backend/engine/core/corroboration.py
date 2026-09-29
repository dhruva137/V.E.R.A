"""Corroboration: how many independent kinds of evidence stand behind an asset.

WHY PLANES
----------
A cryptographic asset can be evidenced in four fundamentally different ways,
and they fail differently:

    declared   what someone *intended*        configs, IaC, imported CBOMs
    built      what was *compiled and shipped* source, dependencies, binaries, images
    held       what *key material exists*      keystores, HSM, KMIP, cloud KMS, cert stores
    observed   what *actually runs on the wire* live TLS / SSH handshakes

Two sensors reading the same plane are not independent - a keystore listing and
a certificate file on the same host are two views of one artefact. So within a
plane only the strongest reading counts, and confidence only grows when a
*different* plane agrees. Across planes the combination is noisy-OR:

    c_plane = max(confidence of the readings in that plane)
    c       = 1 - prod(1 - c_plane)        capped at 0.99

Nothing here removes an asset from anything. A weakly evidenced asset is
*flagged* - shown with the reason next to its rank - so the operator knows which
findings to verify first. Hiding a finding because the evidence is thin would
turn an inventory into a guess about what is safe to ignore.
"""

from __future__ import annotations

from dataclasses import dataclass

from engine.plugins import confidence_for

PLANES = ("declared", "built", "held", "observed")

#: Confidence at or above which a single reading is considered strong on its own.
STRONG_SINGLE_READING = 0.70
#: Default flag threshold; the engine policy may override it.
DEFAULT_FLAG_THRESHOLD = 0.50
_CAP = 0.99

# Sensor id fragment -> (plane, provenance grade). Checked in order, first match
# wins, so the more specific fragments come first.
_SENSOR_MAP: tuple[tuple[str, str, str], ...] = (
    ("tls", "observed", "runtime_observed"),
    ("ssh_live", "observed", "runtime_observed"),
    ("pkcs11", "held", "declared"),
    ("kmip", "held", "declared"),
    ("cloud_kms", "held", "declared"),
    ("kms", "held", "declared"),
    ("keystore", "held", "artifact_parsed"),
    ("certificate", "held", "artifact_parsed"),
    ("vault", "held", "artifact_parsed"),
    ("config", "declared", "config_parsed"),
    ("cbom", "declared", "imported"),
    ("import", "declared", "imported"),
    ("binary", "built", "static_analysis"),
    ("container", "built", "static_analysis"),
    ("dependency", "built", "static_analysis"),
    ("source", "built", "static_analysis"),
    ("secret", "built", "heuristic"),
)

_SOURCE_TYPE_PLANE = {
    "tls": "observed",
    "ssh": "observed",
    "keystore": "held",
    "config": "declared",
    "cbom": "declared",
    "source": "built",
    "binary": "built",
    "container": "built",
    "dependency": "built",
    "ipsec": "declared",
}


@dataclass(frozen=True)
class Reading:
    """One sensor's claim about one asset."""

    source: str
    plane: str
    provenance: str
    confidence: float
    claim: str          # "vulnerable" | "safe"
    detail: str = ""

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "plane": self.plane,
            "provenance": self.provenance,
            "confidence": round(self.confidence, 4),
            "claim": self.claim,
            "detail": self.detail,
        }


def plane_for(sensor: str, source_type: str = "") -> str:
    """Which evidence plane a sensor id (or, failing that, a source type) belongs to."""
    key = (sensor or "").lower()
    for fragment, plane, _grade in _SENSOR_MAP:
        if fragment in key:
            return plane
    return _SOURCE_TYPE_PLANE.get((source_type or "").lower(), "declared")


def _grade_for(sensor: str) -> str | None:
    key = (sensor or "").lower()
    for fragment, _plane, grade in _SENSOR_MAP:
        if fragment in key:
            return grade
    return None


def observations_for(asset, policy=None) -> list[Reading]:
    """Every independent reading behind one asset.

    Merged assets (the same certificate seen in a keystore and in a chain file)
    carry the list of sensors that saw them; each becomes its own reading, graded
    by its method. A single-sensor asset becomes one reading, graded by its
    stamped provenance.
    """
    details = getattr(asset, "raw_details", {}) or {}
    source_type = getattr(asset, "source_type", "") or ""
    claim = "vulnerable" if getattr(asset, "quantum_vulnerable", False) else "safe"
    overrides = (getattr(policy, "provenance_confidences", None) or {}) if policy else {}

    # An algorithm static analysis could not resolve is not evidence of safety.
    if getattr(asset, "verdict", "") == "unknown":
        sensor = details.get("discovered_by") or source_type or "collector"
        return [Reading(
            source=str(sensor),
            plane=plane_for(str(sensor), source_type),
            provenance="heuristic",
            confidence=confidence_for("heuristic"),
            claim="vulnerable",
            detail="Algorithm not statically resolvable; reported, not guessed.",
        )]

    sensors = [s for s in details.get("corroborated_by", []) or [] if s]
    readings: list[Reading] = []
    if len(sensors) > 1:
        for sensor in sensors:
            grade = _grade_for(sensor) or details.get("provenance") or "imported"
            confidence = float(overrides.get(grade, confidence_for(grade)))
            readings.append(Reading(
                source=sensor,
                plane=plane_for(sensor, source_type),
                provenance=grade,
                confidence=confidence,
                claim=claim,
                detail=f"Seen by {sensor}.",
            ))
    else:
        sensor = str(details.get("discovered_by") or source_type or "collector")
        grade = details.get("provenance") or _grade_for(sensor) or "imported"
        if details.get("confidence") is not None and details.get("provenance"):
            confidence = float(details["confidence"])
        else:
            confidence = float(overrides.get(grade, confidence_for(grade)))
        readings.append(Reading(
            source=sensor,
            plane=plane_for(sensor, source_type),
            provenance=grade,
            confidence=confidence,
            claim=claim,
            detail=f"Provenance: {grade}.",
        ))

    # Explicit cross-sensor records (e.g. a live handshake confirming a keystore).
    for extra in details.get("corroboration", []) or []:
        try:
            sensor = str(extra["source"])
            readings.append(Reading(
                source=sensor,
                plane=str(extra.get("plane") or plane_for(sensor)),
                provenance=str(extra.get("provenance") or _grade_for(sensor) or "imported"),
                confidence=float(extra["confidence"]),
                claim=str(extra.get("claim") or claim),
                detail=str(extra.get("detail", "")),
            ))
        except (KeyError, TypeError, ValueError):
            continue  # a malformed record is ignored, never guessed at
    return readings


def corroborate(readings: list[Reading], flag_threshold: float = DEFAULT_FLAG_THRESHOLD) -> dict:
    """Combine readings into one confidence, and say whether to flag the asset.

    Only readings that *support* the leading claim add confidence - the claim of
    the single strongest reading. A reading that contradicts it never raises
    confidence; it is reported as disagreement and flags the asset instead.
    """
    if not readings:
        return {
            "claim": None, "confidence": 0.0, "planes": {}, "sources": [], "readings": [],
            "opposing": [], "flagged": True, "flag_reason": "No sensor evidence.",
            "disagreement": False,
        }

    leading = max(readings, key=lambda r: (r.confidence, r.claim == "vulnerable")).claim
    supporting = [r for r in readings if r.claim == leading]
    opposing = [r for r in readings if r.claim != leading]

    per_plane: dict[str, float] = {}
    for reading in supporting:
        per_plane[reading.plane] = max(per_plane.get(reading.plane, 0.0), reading.confidence)

    miss = 1.0
    for value in per_plane.values():
        miss *= 1.0 - min(max(value, 0.0), 1.0)
    confidence = min(1.0 - miss, _CAP)

    disagreement = bool(opposing)
    single_weak = len(per_plane) == 1 and max(per_plane.values()) < STRONG_SINGLE_READING

    reason = None
    if disagreement:
        reason = "Sensors disagree about whether this is quantum-vulnerable; verify."
    elif confidence < flag_threshold:
        reason = f"Evidence confidence {confidence:.2f} is below {flag_threshold:.2f}; verify with another sensor."
    elif single_weak:
        reason = "One weak reading only; confirm with a second evidence plane."

    return {
        "claim": leading,
        "confidence": round(confidence, 4),
        "planes": {plane: round(value, 4) for plane, value in sorted(per_plane.items())},
        "sources": sorted({r.source for r in readings}),
        "readings": [r.to_dict() for r in readings],
        "opposing": [r.to_dict() for r in opposing],
        "flagged": reason is not None,
        "flag_reason": reason,
        "disagreement": disagreement,
    }


def for_asset(asset, policy=None) -> dict:
    """Convenience: readings + corroboration for one asset."""
    threshold = float(getattr(policy, "flag_threshold", DEFAULT_FLAG_THRESHOLD)) if policy else DEFAULT_FLAG_THRESHOLD
    return corroborate(observations_for(asset, policy=policy), flag_threshold=threshold)
