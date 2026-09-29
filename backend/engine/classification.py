"""Classification by type, lifetime and business criticality (PS clause iii).

    type         the asset class (TLS key exchange, code-signing key, library, ...)
    lifetime     X, how long the protected data must stay confidential, from the
                 data classes the estate register declares for the asset's system
                 (`kb/data_classes.yaml`); an operator override wins
    criticality  the business criticality the register declares, which sets a
                 floor under the sensitivity weight S

Before this, X came from a per-asset-class default: every TLS certificate got 7
years whether it protected card data or a lunch menu. Now a system that holds
customer identity data gets X = 20 and one that holds session tokens gets X = 1,
and the source of each number travels with the asset.

Unknown data-class names are reported, never mapped to a guess.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

import yaml

TABLE_PATH = Path(__file__).resolve().parent / "kb" / "data_classes.yaml"


@lru_cache(maxsize=1)
def table() -> dict:
    return yaml.safe_load(TABLE_PATH.read_text(encoding="utf-8"))


def lifetime(data_classes: list[str]) -> dict | None:
    """{years, classes, basis} for the longest-lived known class, or None."""
    known = [c for c in data_classes if c in table()["classes"]]
    if not known:
        return None
    longest = max(known, key=lambda c: table()["classes"][c]["years"])
    entry = table()["classes"][longest]
    return {"years": float(entry["years"]), "driving_class": longest, "classes": known,
            "basis": f"{entry['label']}: {entry['basis']} (default, confirm with the data owner)"}


def apply(asset) -> dict:
    """Set X_c and the S floor from the declared classification; return the record."""
    details = asset.raw_details if asset.raw_details is not None else {}
    classes = list(details.get("data_classes") or [])
    unknown = [c for c in classes if c not in table()["classes"]]
    record: dict = {
        "type": {"asset_class": asset.asset_class, "label": asset.profile_label or asset.asset_class},
        "data_classes": [c for c in classes if c not in unknown],
    }
    if unknown:
        record["unknown_data_classes"] = unknown

    override = details.get("x_years_override")
    life = lifetime(classes)
    if override is not None:
        asset.x_c = float(override)
        record["lifetime"] = {"years": float(override), "source": "operator override"}
    elif life:
        asset.x_c = life["years"]
        record["lifetime"] = {"years": life["years"], "source": "data classification",
                              "driving_class": life["driving_class"], "basis": life["basis"]}
    else:
        record["lifetime"] = {"years": asset.x_c, "source": "asset-class default",
                              "basis": asset.profile_rationale or "Policy profile default."}
    if asset.cert_validity_start and asset.cert_validity_end:
        record["credential_validity"] = {"from": asset.cert_validity_start, "to": asset.cert_validity_end}

    criticality = details.get("criticality")
    floor = table()["criticality"].get(criticality) if criticality else None
    if floor is not None:
        before = asset.s
        asset.s = max(asset.s, float(floor))
        record["criticality"] = {"level": criticality, "sensitivity_floor": floor, "s_before": before, "s": asset.s}
    else:
        record["criticality"] = {"level": criticality or "undeclared"}
    details["classification"] = record
    asset.raw_details = details
    return record
