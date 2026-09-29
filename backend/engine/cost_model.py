"""Migration cost: declared effort per change, times a declared day rate.

Nothing here is measured, and nothing pretends to be. The model turns the
recommendation list into a planning figure a budget holder can argue with,
and it shows every assumption it used so that they can.

UNIT OF WORK
------------
One change fixes every asset that shares a need, a system and a place: the same
file, endpoint or key. A cipher list naming five weak algorithms on one line of
nginx.conf is one edit, not five. Assets are therefore grouped by
(need, system, location without its line number), and each group is costed once.

EFFORT
------
Effort is counted in person-days of the owning team's own work per change, set
by need. The defaults below are VERA planning assumptions, each with its
reasoning, and not survey data. The estate register overrides them under
`cost.effort_days`.

DAY RATE
--------
The register declares the day rate and currency under `cost.day_rate` and
`cost.currency`. Without a declared rate the model reports person-days only,
because a currency figure with no declared rate behind it would be a number
with no source.

Changes gated on a vendor or cloud provider are costed for the team's own
integration work once the supplier ships, and are counted separately, because
money alone cannot pull that date forward.
"""

from __future__ import annotations

import re
from pathlib import Path

DEFAULT_EFFORT_DAYS: dict[str, float] = {
    "replace_now": 3, "key_exchange": 2, "kem_at_rest": 8, "signature_high_volume": 3,
    "signature_long_lived": 15, "symmetric": 2, "hash": 2, "library_upgrade": 4,
    "secret_exposure": 2, "resolve_first": 1,
}
EFFORT_BASIS: dict[str, str] = {
    "replace_now": "Change the configuration or the call, test, redeploy.",
    "key_exchange": "Enable a hybrid group such as X25519MLKEM768 and run interoperability tests with clients.",
    "kem_at_rest": "Re-wrap or re-encrypt stored data under a new key, inside a planned migration window.",
    "signature_high_volume": "Issue a new key and certificate, deploy it, and move relying parties to trust it.",
    "signature_long_lived": "A root, CA or firmware-signing key: key ceremony, new hierarchy, cross-signing, re-issue.",
    "symmetric": "Move to a 256-bit key, re-key and redeploy.",
    "hash": "Change the digest and any stored values that depend on it.",
    "library_upgrade": "Upgrade the library, rebuild, and regression-test what depends on it.",
    "secret_exposure": "Rotate the key, remove it from the artefact, revoke the old one.",
    "resolve_first": "Review the call site to find which algorithm is chosen at runtime.",
}
GATED = ("vendor_firmware_gated", "provider_gated")
_LINE_SUFFIX = re.compile(r":\d+$")


def _place(item: dict, location: str) -> str:
    """Where the change is made: the location without a trailing line number."""
    return _LINE_SUFFIX.sub("", location or item.get("asset") or item["asset_id"])


def settings(declared: dict | None, register: str | None = None) -> dict:
    """The effective assumptions: register values where declared, defaults otherwise."""
    declared = declared or {}
    overrides = {k: float(v) for k, v in (declared.get("effort_days") or {}).items() if k in DEFAULT_EFFORT_DAYS}
    rate = declared.get("day_rate")
    if rate is not None and (not isinstance(rate, (int, float)) or rate <= 0):
        raise ValueError(f"cost.day_rate must be a positive number, got {rate!r}")
    # The file name identifies the register; the full path is in the scan's metadata.
    source = f"estate register ({Path(register).name})" if register else "estate register"
    return {
        "currency": str(declared.get("currency") or "INR") if rate is not None else None,
        "day_rate": float(rate) if rate is not None else None,
        "day_rate_source": source if rate is not None else None,
        "effort_days": {need: overrides.get(need, days) for need, days in DEFAULT_EFFORT_DAYS.items()},
        "effort_source": {need: source if need in overrides else "VERA planning default"
                          for need in DEFAULT_EFFORT_DAYS},
        "effort_basis": EFFORT_BASIS,
    }


def estimate(items: list[dict], locations: dict[str, str], declared: dict | None = None,
             register: str | None = None) -> dict:
    """Group recommendation items into changes and cost them.

    `items` are `recommendations.recommend_all()["items"]`; `locations` maps
    asset id to source location. Returns totals, breakdowns, the per-asset share
    of its change, and the assumptions used.
    """
    assumptions = settings(declared, register)
    days_for, rate = assumptions["effort_days"], assumptions["day_rate"]

    def money(days: float) -> float | None:
        return round(days * rate, 2) if rate is not None else None

    changes: dict[tuple, dict] = {}
    for item in items:
        key = (item["need"], item.get("system") or "", _place(item, locations.get(item["asset_id"], "")))
        change = changes.setdefault(key, {"need": item["need"], "system": item.get("system"), "place": key[2],
                                          "owner": item["who_can_fix"]["key"], "assets": []})
        change["assets"].append(item["asset_id"])

    per_asset: dict[str, dict] = {}
    by_owner: dict[str, dict] = {}
    by_system: dict[str, dict] = {}
    by_need: dict[str, dict] = {}
    total_days = gated_days = 0.0
    for change in changes.values():
        days = float(days_for.get(change["need"], 0.0))
        total_days += days
        if change["owner"] in GATED:
            gated_days += days
        for bucket, key in ((by_owner, change["owner"]), (by_system, change["system"] or "not in the register"),
                            (by_need, change["need"])):
            row = bucket.setdefault(key, {"changes": 0, "assets": 0, "person_days": 0.0})
            row["changes"] += 1
            row["assets"] += len(change["assets"])
            row["person_days"] += days
        share = days / len(change["assets"])
        for asset_id in change["assets"]:
            per_asset[asset_id] = {"person_days": round(share, 2), "change_person_days": days,
                                   "shared_with": len(change["assets"]) - 1, "cost": money(share)}

    def finish(bucket: dict) -> dict:
        return {k: {**v, "person_days": round(v["person_days"], 1), "cost": money(v["person_days"])}
                for k, v in sorted(bucket.items(), key=lambda kv: -kv[1]["person_days"])}

    return {
        "changes": len(changes),
        "assets": len(items),
        "person_days": round(total_days, 1),
        "cost": money(total_days),
        "gated_person_days": round(gated_days, 1),
        "by_owner": finish(by_owner),
        "by_system": finish(by_system),
        "by_need": finish(by_need),
        "per_asset": per_asset,
        "assumptions": assumptions,
        "method": ("Changes are grouped by need, system and location without line number; each change is "
                   "costed once at the declared person-days for its need, times the declared day rate."),
    }
