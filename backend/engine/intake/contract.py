"""Intake contract — sensor envelopes and crypto-object views.

WHY THIS EXISTS
---------------
Adapters must emit one shape so the engine never sees PKCS#11 vs KMIP vs TLS.
Today's fusion `Observation` (vulnerable/safe) is one *claim kind*, not the
inlet envelope — naming this type `SensorObservation` keeps that distinction
hard. `CryptoObjectView` is the compressed subject the engine will score once
identity resolution lands; until then findings remain the working currency.

Custody is stamped on findings early so packs can map usage + custody → profile
without reading `source_type` or an adapter id.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, Optional

from models.schemas import RawCryptoFinding

# Closed set of claim kinds an adapter may assert. Fusion stays on
# quantum_status; other kinds correlate and constrain.
ClaimKind = Literal[
    "algorithm",
    "parameters",
    "usage",
    "lifecycle",
    "identity",
    "topology",
    "liveness",
    "capability",
    "quantum_status",
]

Custody = Literal["hsm", "kms", "keystore", "network", "unknown"]
Liveness = Literal["live", "idle", "unknown"]


@dataclass
class SensorObservation:
    """One sensor, one subject, one time. Never a score. Never key material.

    Named SensorObservation so it cannot be confused with the per-asset
    `Reading` used by `engine.core.corroboration`.
    """

    observation_id: str
    adapter_id: str
    observed_at: str
    provenance: str
    confidence: float
    subject_hints: dict[str, Any] = field(default_factory=dict)
    claims: list[dict[str, Any]] = field(default_factory=list)
    capability: Optional[dict[str, Any]] = None
    liveness: Liveness = "unknown"
    raw_ref: Optional[str] = None


@dataclass
class CryptoObjectView:
    """Compressed subject after identity resolution — what the engine scores.

    `observation_ids` keeps the disagreement trail; compression must not destroy
    it. `asset_class` may still appear on legacy findings until packs own the
    usage→profile map; it is a view field, not an adapter claim.
    """

    object_id: str
    identities: list[tuple[str, str]] = field(default_factory=list)
    observation_ids: list[str] = field(default_factory=list)
    algorithm: Optional[str] = None
    usage: Optional[str] = None
    custody: Custody = "unknown"
    asset_class: Optional[str] = None
    change_blocked: bool = False
    raw_finding_id: Optional[str] = None


def _custody_from_signals(discovered_by: str, tags: list[str]) -> Custody:
    """Map sensor stamps / tags onto the closed custody set."""
    discovered = (discovered_by or "").lower()
    tag_set = {t.lower() for t in tags}

    if (
        "pkcs11" in discovered
        or "hsm" in discovered
        or "hsm" in tag_set
    ):
        return "hsm"
    if (
        "cloud_kms" in discovered
        or "kms" in discovered
        or "kmip" in discovered
        or "cloud-kms" in tag_set
        or "kmip" in tag_set
    ):
        return "kms"
    if "keystore" in discovered or "keystore" in tag_set:
        return "keystore"
    if (
        "tls" in discovered
        or "certificate" in discovered
        or "certificate" in tag_set
        or "network" in tag_set
    ):
        return "network"
    return "unknown"


def stamp_finding_custody(finding: RawCryptoFinding) -> RawCryptoFinding:
    """Set `raw_details.custody` from discovered_by / tags.

    Packs and QIRS profile resolution need custody without branching on
    `source_type` or adapter id. Idempotent when custody is already present.
    """
    details = finding.raw_details
    if details.get("custody") in {"hsm", "kms", "keystore", "network", "unknown"}:
        return finding
    details["custody"] = _custody_from_signals(
        str(details.get("discovered_by", "")),
        list(finding.tags or []),
    )
    return finding
