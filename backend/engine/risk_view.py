"""The Risk screen's data: when each primitive breaks, and each asset's Mosca margin.

One call answers "when does each asset break?" for the estate:

* `primitives`: one row per quantum-resources entry, with its cited
  logical-qubit estimate, its shift from the reference curve, and the CRQC band
  (pessimistic, median, optimistic) in years from now and as calendar years;
* `assets`: every quantum-vulnerable asset with X, Y, its horizon, the Z band
  for its primitive, its median margin and its Mosca category;
* totals by category.

THE WHAT-IF
-----------
The doubling time D (engine.quantum_resources) is a stated assumption, so the
screen has a slider for it. `build(assets, model, doubling=D)` recomputes the
per-primitive shift at that D and re-reads each asset's margin against the
shifted band. Each asset's horizon (X + Y, or min(X, Y), on its dominant axis)
does not depend on D, so it is taken from the current assessment unchanged.
Nothing is written back: the what-if never changes a stored score, and the
response says which D produced it.
"""

from __future__ import annotations

import statistics

from engine import mosca
from engine.quantum_resources import (
    current_version, doubling_years, resources, row_for, shift_for,
)


def _z_band(z_now: dict[str, float], delta: float) -> dict[str, float]:
    return {r: round(max(z_now[r], 0.0) + delta, 3) for r in mosca.READINGS}


def build(assets, threat_model, *, doubling: float | None = None, now_year: float | None = None) -> dict:
    d = doubling_years() if doubling is None else float(doubling)
    now = mosca.current_year() if now_year is None else float(now_year)
    tick = mosca.clock(now)
    arrivals = mosca.arrival_years(threat_model)
    z_now = {r: round(max(arrivals[r] - tick["elapsed_years"], 0.0), 3) for r in mosca.READINGS}

    rows = resources()["rows"]
    primitives = {}
    for row in rows:
        shift = shift_for(row["algorithms"][0], (row.get("key_sizes") or [None])[0],
                          (row.get("curves") or [None])[0], doubling=d)
        band = _z_band(z_now, shift["delta_years"])
        primitives[row["id"]] = {
            "id": row["id"], "label": row["label"], "logical_qubits": row.get("logical_qubits"),
            "status": row.get("status"), "source": row.get("source"), "url": row.get("url"), "date": row.get("date"),
            "shift_years": shift["delta_years"], "basis": shift["basis"],
            "z_years": band, "z_calendar": {r: round(now + band[r], 1) for r in mosca.READINGS},
            "assets": 0, "by_category": {c: 0 for c in mosca.CATEGORIES},
        }
    reference = {"id": "reference", "label": "Reference curve (no primitive-specific estimate)",
                 "logical_qubits": None, "status": "reference", "source": None, "url": None, "date": None,
                 "shift_years": 0.0, "basis": "No resources row for this primitive; reference curve used.",
                 "z_years": _z_band(z_now, 0.0), "z_calendar": {r: round(now + z_now[r], 1) for r in mosca.READINGS},
                 "assets": 0, "by_category": {c: 0 for c in mosca.CATEGORIES}}

    out_assets, totals = [], {c: 0 for c in (*mosca.CATEGORIES, "not_applicable")}
    for asset in assets:
        if not asset.quantum_vulnerable:
            totals["not_applicable"] += 1
            continue
        reading = mosca.assess(asset, threat_model, now_year=now)
        if not reading.get("applicable"):
            totals["not_applicable"] += 1
            continue
        row = row_for(*mosca.primitive_of(asset))
        bucket = primitives.get(row["id"]) if row else None
        bucket = bucket or reference
        band = bucket["z_years"]
        horizon = reading["horizon_years"]
        margins = {r: round(horizon - band[r], 3) for r in mosca.READINGS}
        category = mosca._category(margins)
        bucket["assets"] += 1
        bucket["by_category"][category] += 1
        totals[category] += 1
        axis = reading["axis"]
        out_assets.append({
            "id": asset.id, "name": asset.name, "priority_rank": asset.priority_rank,
            "system": (asset.raw_details or {}).get("system"), "algorithm": asset.algorithm,
            "key_size": asset.key_size, "primitive": bucket["label"], "primitive_id": bucket["id"],
            "axis": axis, "x_years": reading["x_c"] if axis == "confidentiality" else reading["x_i"],
            "x_basis": reading.get("x_basis"), "y_years": reading["y_plan"], "horizon_years": horizon,
            "z_years": band, "margin_years": margins, "median_margin_years": margins["median"],
            "category": category, "label": mosca.CATEGORY_LABEL[category],
            "category_if_started_now": reading["category_if_started_now"],
            "vendor_gated": reading["vendor_gated"], "deadline_year": reading["deadline_year"],
        })

    out_assets.sort(key=lambda a: (mosca.category_rank(a["category"]), -a["median_margin_years"],
                                   a["priority_rank"] or 10**9))
    used = [p for p in primitives.values() if p["assets"]]
    listed = list(primitives.values()) + ([reference] if reference["assets"] else [])
    margins_all = [a["median_margin_years"] for a in out_assets]
    return {
        "doubling_years": d,
        "default_doubling_years": doubling_years(),
        "what_if": abs(d - doubling_years()) > 1e-9,
        "threat_model_version": current_version()["version"],
        "clock": tick,
        "crqc_arrival_years_from_report": arrivals,
        "z_reference_years": z_now,
        "primitives": listed,
        "primitives_in_use": len(used) + (1 if reference["assets"] else 0),
        "assets": out_assets,
        "totals": totals,
        "median_margin_years": round(statistics.median(margins_all), 2) if margins_all else None,
    }
