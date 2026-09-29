"""Certificate expiry - the deadline that arrives before the quantum one.

WHY THIS EXISTS
---------------
Every other deadline in this product is statutory: a regulator says be
quantum-safe by 2030, and we compute whether the migration fits. That deadline
is years away and probabilistic, which is exactly why boards defer it - only
38% of organisations report actively transitioning, and that number fell year
over year.

A certificate expiry is the same shape of problem with none of the uncertainty.
It is a date, it is in the asset's own metadata, and when it passes, production
stops. 77% of organisations have had an outage caused by an expired
certificate; the average loss across roughly four such outages is $11.1M. The
Bank of England's CHAPS high-value payment system went offline in July 2024 for
exactly this reason.

The same inventory, the same dependency graph and the same deadline arithmetic
that plan a post-quantum migration answer this too. Modelling it costs nothing -
`cert_validity_end` is already collected - and it makes the product useful
before a quantum computer exists.

WHY BLAST RADIUS IS PART OF IT
------------------------------
An expiring leaf certificate on a staging box and an expiring issuing CA are
both "one certificate". They are not the same incident. Expiry urgency is
reported alongside the number of assets that depend on the thing expiring, for
the same reason the risk model has a second axis at all.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterable, Optional

from models.schemas import CryptoAsset

# Bands, in days remaining. Chosen to match how change management actually
# works rather than to be round numbers: under 30 days is inside most
# enterprise change-freeze and approval windows, so it is already an incident;
# 90 days is roughly one renewal cycle of warning.
CRITICAL_DAYS = 30
WARNING_DAYS = 90


def parse_expiry(value: Optional[str]) -> Optional[datetime]:
    """Read an ISO-8601 timestamp, tolerating the trailing Z form.

    Returns None rather than raising: an unparseable date is missing data, not
    a reason to fail a scan of the whole estate.
    """
    if not value:
        return None
    text = str(value).strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    # A naive timestamp is treated as UTC. Certificates are issued in UTC and
    # comparing a naive value against an aware one raises.
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def days_remaining(asset: CryptoAsset, now: Optional[datetime] = None) -> Optional[int]:
    """Whole days until this asset's certificate expires, negative if past."""
    expires = parse_expiry(getattr(asset, "cert_validity_end", None))
    if expires is None:
        return None
    reference = now or datetime.now(timezone.utc)
    return (expires - reference).days


def band_for(days: Optional[int]) -> str:
    """Bucket a day count into the band the UI colours on."""
    if days is None:
        return "none"
    if days < 0:
        return "expired"
    if days <= CRITICAL_DAYS:
        return "critical"
    if days <= WARNING_DAYS:
        return "warning"
    return "ok"


def expiry_for(asset: CryptoAsset, now: Optional[datetime] = None) -> dict:
    """Per-asset expiry position: the days, the band, and what depends on it."""
    days = days_remaining(asset, now)
    return {
        "asset_id": asset.id,
        "name": asset.name,
        "days_remaining": days,
        "band": band_for(days),
        "expires": getattr(asset, "cert_validity_end", None),
        # Populated by summarise() where a dependency graph is available. The
        # per-asset call has no graph, so it stays 0 rather than guessing.
        "dependents": 0,
    }


def summarise(
    assets: Iterable[CryptoAsset],
    dependents: Optional[dict[str, int]] = None,
    now: Optional[datetime] = None,
    worst_limit: int = 10,
) -> dict:
    """Estate-wide expiry posture.

    Returns counts per band plus a short worst-first list. Deliberately never
    returns the full asset set: the dashboard needs numbers, and an endpoint
    that can return the whole estate is the one that falls over first at scale.

    `dependents` maps asset id to transitive dependent count, so an expiring
    trust anchor outranks an expiring leaf certificate with the same date.
    """
    reference = now or datetime.now(timezone.utc)
    dependents = dependents or {}

    counts = {"expired": 0, "critical": 0, "warning": 0, "ok": 0, "none": 0}
    dated: list[dict] = []

    for asset in assets:
        days = days_remaining(asset, reference)
        band = band_for(days)
        counts[band] += 1
        if days is None:
            continue
        dated.append({
            "asset_id": asset.id,
            "name": asset.name,
            "days_remaining": days,
            "band": band,
            "expires": getattr(asset, "cert_validity_end", None),
            "dependents": dependents.get(asset.id, 0),
            "source_location": asset.source_location,
        })

    # Worst first: soonest to expire, and among equally urgent ones the entry
    # that takes the most down with it.
    dated.sort(key=lambda row: (row["days_remaining"], -row["dependents"]))

    at_risk = counts["expired"] + counts["critical"]
    return {
        "counts": counts,
        "tracked": len(dated),
        "at_risk": at_risk,
        "worst": dated[:worst_limit],
        "thresholds": {"critical_days": CRITICAL_DAYS, "warning_days": WARNING_DAYS},
    }
