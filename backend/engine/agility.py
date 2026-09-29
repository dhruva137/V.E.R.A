"""How hard an asset is to change - the axis risk scoring does not capture.

WHY THIS EXISTS
---------------
QIRS says how bad an asset is. It says nothing about whether anything can be
done about it today. Two assets with an identical score can be a one-line
server config change and a fleet-wide hardware refresh, and treating them as
interchangeable produces a migration plan nobody can execute.

This matters more than it sounds. As of mid-2025 no major HSM vendor shipped
general availability support for ML-KEM, ML-DSA or SLH-DSA, and HSM fleets run
on ten-to-twenty year replacement cycles. An asset ranked first that cannot be
touched for two years is not actually first - it is blocked, and the honest
output says so rather than leaving it at the top of a list forever.

GROUNDING
---------
The bands below follow the shape of the Crypto-Agility Maturity Model (CAMM,
Hohm et al. 2023), which NIST cites in CSWP 39 "Considerations for Achieving
Cryptographic Agility". CAMM measures an organisation's maturity; this measures
a single asset's changeability, which is the operational half of the same idea.

These are policy assumptions per asset class, exactly like the six QIRS
inputs - stated, not measured, and carrying their reasoning so an operator can
disagree with a specific number rather than the whole model.
"""

from __future__ import annotations

from typing import Iterable

from models.schemas import CryptoAsset

# Ordered easiest to hardest. The order is load-bearing: `rank` drives sorting
# and the "what can we actually do today" split.
BANDS: list[dict] = [
    {
        "key": "config",
        "label": "Config change",
        "rank": 0,
        "actionable_now": True,
        "detail": "A setting on the server. No new key material, no re-issue, no downtime.",
    },
    {
        "key": "automatable",
        "label": "Automatable re-issue",
        "rank": 1,
        "actionable_now": True,
        "detail": "Re-issued through existing certificate automation. Routine, already tooled.",
    },
    {
        "key": "coordinated",
        "label": "Coordinated change",
        "rank": 2,
        "actionable_now": True,
        "detail": "Needs several teams and a change window, but nothing external blocks it.",
    },
    {
        "key": "programme",
        "label": "Multi-team programme",
        "rank": 3,
        "actionable_now": False,
        "detail": "Every relying party must be updated. Months of coordination, not a task.",
    },
    {
        "key": "vendor_blocked",
        "label": "Blocked on vendor",
        "rank": 4,
        "actionable_now": False,
        "detail": "Cannot start until a supplier ships firmware. No major HSM vendor had "
                  "general availability post-quantum support as of mid-2025.",
    },
    {
        "key": "hardware_bound",
        "label": "Hardware refresh",
        "rank": 5,
        "actionable_now": False,
        "detail": "Migrates at the speed of physically replacing devices in the field.",
    },
]

_BY_KEY = {band["key"]: band for band in BANDS}

# Keyed on the same profile keys as PROFILES in qirs.py. Anything unmapped
# falls back to "coordinated" - the middle of the range, so an unknown asset
# class is neither optimistically waved through nor written off as impossible.
AGILITY_BY_PROFILE: dict[str, str] = {
    "tls_cipher_suite": "config",
    "tls_key_exchange": "config",
    "config": "config",
    "tls_certificate": "automatable",
    "database_tls": "automatable",
    "ssh_key": "coordinated",
    "vpn_ipsec": "coordinated",
    "token_signing": "coordinated",
    "backup_encryption": "coordinated",
    "generic_key": "coordinated",
    "source": "coordinated",
    "issuing_ca": "programme",
    "code_signing": "programme",
    "root_ca": "programme",
    "payment_hsm": "vendor_blocked",
    "device_identity": "hardware_bound",
    "firmware_signing": "hardware_bound",
}

DEFAULT_KEY = "coordinated"


def _profile_key(asset: CryptoAsset) -> str:
    """Recover the profile key an asset was scored under.

    `resolve_profile` in qirs.py picks the template but only the human label
    lands on the asset, so the key is recovered from asset_class first and the
    label second.
    """
    candidate = (getattr(asset, "asset_class", None) or "").strip().lower()
    if candidate in AGILITY_BY_PROFILE:
        return candidate
    label = (getattr(asset, "profile_label", None) or "").strip().lower()
    for key, band in _LABEL_HINTS.items():
        if key in label:
            return band
    return DEFAULT_KEY


# Matched against profile_label when asset_class is absent or unrecognised.
# Ordered most specific first - "root certificate authority" must not fall
# through to the "certificate" hint.
_LABEL_HINTS: dict[str, str] = {
    "root certificate": "root_ca",
    "issuing certificate": "issuing_ca",
    "firmware signing": "firmware_signing",
    "code signing": "code_signing",
    "payment hsm": "payment_hsm",
    "device identity": "device_identity",
    "cipher suite": "tls_cipher_suite",
    "key exchange": "tls_key_exchange",
    "token": "token_signing",
    "backup": "backup_encryption",
    "ssh": "ssh_key",
    "ipsec": "vpn_ipsec",
    "database": "database_tls",
    "certificate": "tls_certificate",
}


def agility_for(asset: CryptoAsset) -> dict:
    """The changeability band for one asset, with its reasoning."""
    key = AGILITY_BY_PROFILE.get(_profile_key(asset), DEFAULT_KEY)
    return dict(_BY_KEY[key])


def summarise(assets: Iterable[CryptoAsset]) -> dict:
    """Estate-wide changeability.

    The headline number is `actionable_now`: how much of the estate could be
    migrated today if someone decided to, as distinct from how much of it is
    risky. Those are different questions and only one of them is a plan.
    """
    counts = {band["key"]: 0 for band in BANDS}
    actionable = 0
    blocked = 0
    total = 0

    for asset in assets:
        band = agility_for(asset)
        counts[band["key"]] += 1
        total += 1
        if band["actionable_now"]:
            actionable += 1
        else:
            blocked += 1

    return {
        "counts": counts,
        "bands": BANDS,
        "total": total,
        "actionable_now": actionable,
        "blocked": blocked,
        "actionable_pct": round(100.0 * actionable / total, 1) if total else 0.0,
    }
