"""The Overview screen in one response: posture, what to do next, and whether to trust it.

Three readers open this screen. An assessor asks whether the inventory is
complete and trustworthy. An owner asks what breaks first and what to do this
quarter. An engineer asks where to start. The response answers all three in
the order the screen shows them (top to bottom):

1. a verdict sentence, with its numbers and the next DST milestone;
2. four figures, each with its source;
3. "do next": the five highest-priority changes, grouped when one change fixes many assets;
4. the DST milestone track, with the estate's readiness against each milestone;
5. exposure by system;
6. coverage (what was read, what failed, what was not looked at) and evidence status.

Every figure carries a `source` that names the scan, file or method it came
from. The module composes results the engines have already produced; it
computes no score of its own.
"""

from __future__ import annotations

import datetime

from engine.recommendations import behind as is_behind
from engine.regulatory import DEADLINES, TRACK_SOURCE, deadline_point

PHASES = (
    ("foundation", "Foundations in place",
     "Cryptographic inventory and CBOM complete, with owners, so migration can be planned."),
    ("high_priority", "High-priority systems migrated",
     "Widely trusted anchors and internet-facing systems moved to PQC or hybrid."),
    ("full", "Full migration",
     "Every remaining quantum-vulnerable asset moved to PQC or hybrid."),
)
_EXPOSED = ("certain", "likely")


def _system(asset) -> str | None:
    return (asset.raw_details or {}).get("system")


def _days_left(year: int, today: datetime.date) -> int:
    """Days to the moment the engine plans against (engine.regulatory.deadline_point)."""
    return (datetime.date(int(deadline_point(year)), 1, 1) - today).days


def verdict(assets, risk: dict, milestones: list[dict]) -> dict:
    total = len(assets)
    vulnerable = sum(1 for a in assets if a.quantum_vulnerable)
    totals = risk.get("totals", {})
    exposed = sum(totals.get(c, 0) for c in _EXPOSED)
    upcoming = next((m for m in milestones if m["days_left"] >= 0), milestones[-1] if milestones else None)
    sentence = (f"{vulnerable} of {total} assets are quantum-vulnerable; {exposed} will be exposed before "
                f"they can be migrated." if exposed else
                f"{vulnerable} of {total} assets are quantum-vulnerable; none is expected to be exposed "
                f"before it can be migrated.")
    return {"sentence": sentence, "total": total, "vulnerable": vulnerable, "exposed": exposed,
            "next_milestone": upcoming}


def figures(assets, risk: dict, resolution: dict, coverage: dict, gated: list[dict], scan: dict) -> list[dict]:
    totals = risk.get("totals", {})
    vulnerable = sum(1 for a in assets if a.quantum_vulnerable)
    broken = sum(1 for a in assets if a.classically_broken)
    exposed = sum(totals.get(c, 0) for c in _EXPOSED)
    gated_assets = sum(g.get("count", 0) for g in gated)
    findings = resolution.get("findings")
    runs, failed = coverage["runs"], coverage["failed_runs"]
    return [
        {"key": "inventoried", "label": "Assets inventoried", "value": len(assets),
         "detail": (f"{runs - failed} of {runs} collector runs read cleanly" if runs else "No collector runs recorded"),
         "source": (f"Scan {scan['id'][:8]}: {findings} findings from every collector, resolved to "
                    f"{len(assets)} assets" if findings is not None else f"Scan {scan['id'][:8]}")},
        {"key": "vulnerable", "label": "Quantum-vulnerable", "value": vulnerable,
         "detail": f"{broken} are also broken classically" if broken else "None is broken classically",
         "source": "Per-asset verdict from the algorithm taxonomy: breakable by Shor's algorithm"},
        {"key": "exposed", "label": "Exposed before migration", "value": exposed,
         "detail": f"{totals.get('possible', 0)} more possibly exposed",
         "source": (f"Mosca X + Y > Z per primitive, threat model {risk.get('threat_model_version')}, "
                    f"D = {risk.get('doubling_years')} yr")},
        {"key": "gated", "label": "Blocked on suppliers", "value": gated_assets,
         "detail": f"{len(gated)} supplier{'s' if len(gated) != 1 else ''} must ship PQC first" if gated
                   else "No asset is waiting on a supplier",
         "source": "Vendor- and provider-gated register (HSM firmware and cloud KMS capabilities)"},
    ]


def do_next(recommendations: list[dict], risk_assets: dict[str, dict], cost: dict, limit: int = 5) -> list[dict]:
    """The highest-priority changes. Items that share a system, need and fix are one row."""
    ranked = sorted(recommendations, key=lambda r: (r.get("priority_rank") or 10**9, r["asset_id"]))
    groups: dict[tuple, dict] = {}
    for item in ranked:
        key = (item.get("system"), item["need"], str(item["recommended"]))
        if key not in groups:
            if len(groups) == limit:
                continue
            reading = risk_assets.get(item["asset_id"], {})
            groups[key] = {
                "asset_id": item["asset_id"], "asset": item["asset"], "system": item.get("system"),
                "algorithm": item.get("algorithm"), "need": item["need"], "need_label": item["need_label"],
                "why": item["why"], "fix": item["recommended"], "owner": item["who_can_fix"],
                "effort": item["effort"], "mosca_category": item.get("mosca_category"),
                "deadline_year": reading.get("deadline_year"), "priority_rank": item.get("priority_rank"),
                "asset_ids": [], "person_days": 0.0,
            }
        group = groups[key]
        group["asset_ids"].append(item["asset_id"])
        group["person_days"] += (cost["per_asset"].get(item["asset_id"]) or {}).get("person_days", 0.0)
    rate = cost["assumptions"]["day_rate"]
    rows = []
    for group in groups.values():
        days = round(group["person_days"], 1)
        rows.append({**group, "count": len(group["asset_ids"]), "person_days": days,
                     "cost": round(days * rate, 2) if rate is not None else None})
    return rows


def milestone_track(assets, persona: str, today: datetime.date, conformance: dict | None,
                    unresolved: int, failed_runs: int) -> list[dict]:
    track = DEADLINES.get(persona, DEADLINES["General Enterprise"])
    out = []
    for phase, label, meaning in PHASES:
        year = track[phase]
        row = {"phase": phase, "label": label, "meaning": meaning, "year": year,
               "date": f"{int(deadline_point(year))}-01-01",
               "days_left": _days_left(year, today), "persona": persona, "source": TRACK_SOURCE}
        if phase == "foundation":
            pct = (conformance or {}).get("percent")
            open_items = []
            if unresolved:
                open_items.append(f"{unresolved} asset{'s' if unresolved != 1 else ''} with an unresolved algorithm")
            if failed_runs:
                open_items.append(f"{failed_runs} collector run{'s' if failed_runs != 1 else ''} failed")
            if pct is not None and pct < 100:
                missing = (conformance or {}).get("required", 0) - (conformance or {}).get("present", 0)
                open_items.append(f"{missing} CBOM elements required by CERT-In are missing")
            row.update({"readiness_pct": pct, "readiness_basis": "CERT-In Table 9 elements present in the CBOM",
                        "open": open_items, "behind": 0,
                        "status": "met" if pct == 100 and not unresolved else
                                  ("missed" if row["days_left"] < 0 else "in_progress")})
        else:
            in_scope = [a for a in assets if (a.quantum_vulnerable or a.verdict == "pqc")
                        and (phase == "full" or a.binding_phase == "high_priority")]
            migrated = sum(1 for a in in_scope if a.verdict == "pqc")
            behind = sum(1 for a in assets if a.binding_phase == phase and is_behind(a))
            pct = round(100.0 * migrated / len(in_scope), 1) if in_scope else None
            row.update({"readiness_pct": pct, "migrated": migrated, "in_scope": len(in_scope), "behind": behind,
                        "readiness_basis": ("Share of in-scope assets already on PQC or hybrid. In scope: "
                                            + ("assets this milestone binds (blast radius C >= 0.7 or exposure "
                                               "E >= 0.8)" if phase == "high_priority" else
                                               "every quantum-vulnerable or migrated asset")),
                        "open": [f"{behind} asset{'s' if behind != 1 else ''} cannot meet this milestone even if "
                                 f"work starts today"] if behind else [],
                        "status": "met" if pct == 100 else ("missed" if row["days_left"] < 0 else
                                                            "at_risk" if behind else "in_progress")})
        out.append(row)
    return out


def exposure_by_system(assets, declarations: list[dict]) -> list[dict]:
    declared = {d["name"]: d for d in declarations if d.get("kind") == "system"}
    rows: dict[str, dict] = {}
    for asset in assets:
        name = _system(asset) or ""
        row = rows.setdefault(name, {"system": name or None, "assets": 0, "vulnerable": 0, "exposed": 0,
                                     "behind": 0, "broken": 0})
        row["assets"] += 1
        row["vulnerable"] += int(bool(asset.quantum_vulnerable))
        row["broken"] += int(bool(asset.classically_broken))
        row["exposed"] += int(asset.mosca_category in _EXPOSED)
        row["behind"] += int(is_behind(asset))
    out = []
    for name, row in rows.items():
        decl = declared.get(name, {})
        out.append({**row, "owner": decl.get("owner"), "criticality": decl.get("criticality"),
                    "exposure": decl.get("exposure"), "data_classes": decl.get("data_classes", []),
                    "in_register": bool(decl),
                    "source": decl.get("location") or ("Seen on the network or in a key manager, "
                                                       "not declared in the estate register")})
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    return sorted(out, key=lambda r: (not r["in_register"], -r["exposed"], -r["vulnerable"],
                                      order.get(r["criticality"] or "", 9), r["system"] or ""))


def coverage(inputs: list[dict], events: list[dict], registry: list[dict]) -> dict:
    """What was read, what failed and what was not looked at, per collector."""
    per: dict[str, dict] = {c["name"]: {"collector": c["name"], "label": c["label"], "plane": c["plane"],
                                         "runs": 0, "findings": 0, "failed_runs": 0, "unreadable": 0,
                                         "errors": []}
                            for c in registry}
    for row in inputs:
        entry = per.setdefault(row["collector"], {"collector": row["collector"], "label": row["collector"],
                                                  "plane": None, "runs": 0, "findings": 0, "failed_runs": 0,
                                                  "unreadable": 0, "errors": []})
        entry["runs"] += 1
        entry["findings"] += row.get("findings", 0)
    for event in events:
        entry = per.get(event.get("collector") or "")
        if entry is None:
            continue
        if event.get("type") == "collector_failed":
            entry["failed_runs"] += 1
            entry["runs"] += 1
            if len(entry["errors"]) < 3:
                entry["errors"].append({"target": event.get("target"), "error": event.get("error")})
        elif event.get("type") == "collector_finished" and event.get("failures"):
            entry["unreadable"] += event["failures"]
            for sample in (event.get("failure_sample") or [])[: max(0, 3 - len(entry["errors"]))]:
                entry["errors"].append({"target": sample.get("target"), "error": sample.get("reason")})
    surfaces = list(per.values())
    not_run = [s for s in surfaces if s["runs"] == 0]
    return {
        "surfaces": surfaces,
        "runs": sum(s["runs"] for s in surfaces),
        "failed_runs": sum(s["failed_runs"] for s in surfaces),
        "unreadable": sum(s["unreadable"] for s in surfaces),
        "read": [s["collector"] for s in surfaces if s["runs"] and not s["failed_runs"]],
        "not_run": [{"collector": s["collector"], "label": s["label"],
                     "why": "No target in this scan is of a kind this collector reads."} for s in not_run],
        "planes": sorted({s["plane"] for s in surfaces if s["runs"] and s["plane"]}),
    }


def build(assets, *, risk: dict, recommendations: dict, gated: list[dict], cost: dict, conformance: dict | None,
          cbom_check: dict, manifest: dict | None, audit: dict, resolution: dict, inputs: list[dict],
          events: list[dict], registry: list[dict], declarations: list[dict], estate: dict, persona: str,
          scan: dict, drift: int, today: datetime.date | None = None) -> dict:
    today = today or datetime.date.today()
    cover = coverage(inputs, events, registry)
    unresolved = sum(1 for a in assets if a.verdict == "unknown")
    milestones = milestone_track(assets, persona, today, conformance, unresolved, cover["failed_runs"])
    risk_assets = {r["id"]: r for r in risk.get("assets", [])}
    return {
        "scan": scan,
        "estate": {"name": estate.get("name") or scan.get("label"), "systems": estate.get("systems"),
                   "synthetic": estate.get("synthetic", False), "register": estate.get("register")},
        "persona": persona,
        "verdict": verdict(assets, risk, milestones),
        "figures": figures(assets, risk, resolution, cover, gated, scan),
        "do_next": do_next(recommendations.get("items", []), risk_assets, cost),
        "milestones": milestones,
        "systems": exposure_by_system(assets, declarations),
        "coverage": {**cover, "unresolved": unresolved, "drift": drift,
                     "cross_plane_assets": resolution.get("cross_plane_assets")},
        "evidence": {
            "cbom": {"spec": cbom_check.get("spec"), "valid": cbom_check.get("valid"),
                     "components": cbom_check.get("components")},
            "certin": {"percent": (conformance or {}).get("percent"), "present": (conformance or {}).get("present"),
                       "required": (conformance or {}).get("required")},
            "manifest": manifest,
            "audit": {"valid": audit.get("valid"), "entries": audit.get("entries"),
                      "first_broken": audit.get("first_broken")},
        },
        "cost": {k: cost[k] for k in ("changes", "person_days", "cost", "gated_person_days")}
                | {"currency": cost["assumptions"]["currency"], "day_rate": cost["assumptions"]["day_rate"],
                   "day_rate_source": cost["assumptions"]["day_rate_source"]},
    }
