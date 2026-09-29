"""What the Inventory screen and its asset panel read.

The inventory list needs one small row per asset, plus counts for its filters.
It does not need every scoring input and raw detail. At 219 assets the
difference is small; at 20,000 it decides whether the screen opens. Rows are
built here from the scored assets, and the full record is fetched only for the
asset that is opened.

The asset panel answers the engineer's question: where exactly is it, and
what is the fix? It has six sections, each composed from an engine that
already owns the answer:

    summary        what it is, where it lives, who owns it, the verdict and its reason
    evidence       every location it was seen, on which evidence plane, and how sure that is
    risk           Mosca's X, Y and Z for its primitive, and the full derivation of its scores
    fix            the recommendation, its cost share, prerequisites and who can act
    dependencies   what it relies on and what relies on it
    history        how it looked in earlier scans of the same estate
"""

from __future__ import annotations

from engine.core.corroboration import for_asset, plane_for


def _algorithm(asset) -> str | None:
    return asset.algorithm or asset.key_exchange or asset.cipher_suite or asset.protocol


def _plane(asset) -> str:
    d = asset.raw_details or {}
    return d.get("plane") or plane_for(str(d.get("discovered_by") or asset.source_type), asset.source_type)


def status(asset) -> str:
    """One word for the list: broken, vulnerable, weakened, safe or unresolved."""
    if asset.classically_broken:
        return "broken"
    if asset.quantum_vulnerable:
        return "vulnerable"
    if asset.verdict == "grover":
        return "weakened"
    if asset.verdict == "unknown":
        return "unresolved"
    return "safe"


def rows(assets, needs: dict[str, dict], behind_ids: set[str], drift_ids: set[str]) -> list[dict]:
    out = []
    for asset in assets:
        d = asset.raw_details or {}
        rec = needs.get(asset.id) or {}
        out.append({
            "id": asset.id, "name": asset.name, "algorithm": _algorithm(asset), "key_size": asset.key_size,
            "class": asset.asset_class, "class_label": asset.profile_label or asset.asset_class,
            "system": d.get("system"), "location": asset.source_location, "source_type": asset.source_type,
            "plane": _plane(asset), "status": status(asset), "verdict": asset.verdict,
            "risk_level": asset.risk_level, "priority_rank": asset.priority_rank,
            "mosca": asset.mosca_category or None, "deadline_year": asset.statutory_deadline_year,
            "slack_months": round(asset.slack_months, 1), "behind": asset.id in behind_ids,
            "need": rec.get("need"), "fix": rec.get("recommended"), "owner": (rec.get("who_can_fix") or {}).get("key"),
            "drift": asset.id in drift_ids, "exposure": d.get("exposure"), "criticality": d.get("criticality"),
            "expiry_days": asset.expiry_days, "expiry_band": asset.expiry_band, "migrated": asset.migrated,
        })
    return out


_FACETS = ("status", "risk_level", "mosca", "system", "class_label", "plane", "need", "owner", "source_type")


def facets(rows_: list[dict]) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {}
    for key in _FACETS:
        counts: dict[str, int] = {}
        for row in rows_:
            value = row.get(key)
            counts[str(value) if value is not None else ""] = counts.get(str(value) if value is not None else "", 0) + 1
        out[key] = [{"value": v, "count": n} for v, n in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))]
    out["flags"] = [{"value": "behind", "count": sum(r["behind"] for r in rows_)},
                    {"value": "drift", "count": sum(r["drift"] for r in rows_)}]
    return out


def _edges_for(asset_id: str, graph: dict) -> dict:
    names = {n["id"]: n for n in graph.get("nodes", [])}
    kinds = graph.get("edge_kinds", {})

    def describe(other: str, edge: dict) -> dict:
        node = names.get(other, {})
        kind = kinds.get(edge["kind"], {})
        return {"id": other, "name": node.get("name", other), "algorithm": node.get("algorithm"),
                "status": ("broken" if node.get("classically_broken") else
                           "vulnerable" if node.get("quantum_vulnerable") else "safe") if node else None,
                "relation": kind.get("label", edge["kind"]), "derivation": kind.get("derivation")}

    node = names.get(asset_id, {})
    return {
        "depends_on": [describe(e["target"], e) for e in graph.get("edges", []) if e["source"] == asset_id],
        "dependents": [describe(e["source"], e) for e in graph.get("edges", []) if e["target"] == asset_id],
        "transitive_dependents": node.get("dependents", 0),
    }


def panel(asset, *, recommendation: dict | None, why_nothing: str, cost_share: dict | None, reading: dict,
          explain: dict, graph: dict, drift_records: list[dict], owner: str | None, history: list[dict]) -> dict:
    d = asset.raw_details or {}
    evidence = for_asset(asset)
    refs = d.get("evidence_refs") or []
    return {
        "id": asset.id,
        "summary": {
            "name": asset.name, "algorithm": _algorithm(asset), "key_size": asset.key_size,
            "class_label": asset.profile_label, "class_rationale": asset.profile_rationale,
            "system": d.get("system"), "owner": owner or asset.owner, "location": asset.source_location,
            "status": status(asset), "verdict": asset.verdict, "reason": asset.vulnerability_reason,
            "replacement": asset.pqc_replacement, "risk_level": asset.risk_level,
            "priority_rank": asset.priority_rank, "persona": asset.persona, "phase": asset.binding_phase,
            "phase_reason": asset.binding_phase_reason, "deadline_year": asset.statutory_deadline_year,
            "slack_months": round(asset.slack_months, 1), "exposure": d.get("exposure"),
            "exposure_basis": d.get("exposure_basis"), "criticality": d.get("criticality"),
            "data_classes": d.get("data_classes") or [], "expiry_days": asset.expiry_days,
            "expiry_band": asset.expiry_band, "migrated": asset.migrated, "migrated_from": asset.migrated_from,
            "certificate": {k: v for k, v in {
                "subject": asset.cert_subject, "issuer": asset.cert_issuer, "not_before": asset.cert_validity_start,
                "not_after": asset.cert_validity_end, "serial": asset.cert_serial}.items() if v} or None,
            # The PS asks for versions and modes: shown exactly as the evidence states them, never inferred.
            "version": d.get("library_version") if d.get("library_version") not in (None, "", "unknown") else None,
            "version_source": d.get("version_source"),
            "mode": d.get("mode"), "padding": d.get("padding"),
            "detection": {
                "method": d["detection_method"], "q_value": d.get("detection_q_value"),
                "alpha": d.get("detection_alpha"), "isa": d.get("detection_isa"),
                "functions_scored": d.get("functions_scored"), "functions_selected": d.get("functions_selected"),
                "selected_functions": d.get("selected_functions") or [],
            } if d.get("detection_method") else None,
        },
        "evidence": {
            "refs": refs, "plane": _plane(asset), "planes": evidence["planes"], "confidence": evidence["confidence"],
            "sources": evidence["sources"], "flagged": evidence["flagged"], "flag_reason": evidence["flag_reason"],
            "disagreement": evidence["disagreement"], "discovered_by": d.get("discovered_by"),
            "provenance": d.get("provenance"),
            "drift": [{"id": r["id"], "rule": r["rule"], "title": r["title"], "severity": r["severity"],
                       "explain": r["explain"]} for r in drift_records],
        },
        "risk": {"mosca": reading, "derivation": explain},
        "fix": ({**recommendation, "cost_estimate": cost_share} if recommendation else
                {"need": None, "why": why_nothing}),
        "dependencies": _edges_for(asset.id, graph),
        "history": history,
    }
