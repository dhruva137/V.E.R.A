"""Delta between two scans: what changed, how far migration got, and why scores moved.

    added / removed      assets present in only one scan (matched by stable asset id)
    changed              algorithm, key size, verdict, Mosca category, QIRS band shifts
    migration progress   of the assets quantum-vulnerable in the earlier scan, how many are now
                         migrated (present, no longer vulnerable) and how many were removed,
                         reported separately; a warning when the two scans barely overlap
    why scores moved     "clock" when both scans used the same threat-model version (time
                         passed, which is expected), "evidence" when the version changed, with
                         the changelog entries in between
"""

from __future__ import annotations

import datetime as dt

from engine import quantum_resources

_FIELDS = ("algorithm", "key_size", "verdict", "quantum_vulnerable", "mosca_category")
_BAND_TOLERANCE = 0.005


def _parse(ts: str | None) -> dt.datetime | None:
    try:
        return dt.datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except ValueError:
        return None


def why_scores_moved(before: dict, after: dict) -> dict:
    v_before = (before.get("summary") or {}).get("threat_model_version")
    v_after = (after.get("summary") or {}).get("threat_model_version")
    t_before, t_after = _parse(before.get("timestamp")), _parse(after.get("timestamp"))
    elapsed = round((t_after - t_before).total_seconds() / 86400, 2) if t_before and t_after else None
    if v_before and v_after and v_before != v_after:
        names = [v["version"] for v in quantum_resources.versions()]
        start = names.index(v_before) + 1 if v_before in names else 0
        end = names.index(v_after) + 1 if v_after in names else len(names)
        return {"reason": "evidence", "from_version": v_before, "to_version": v_after, "elapsed_days": elapsed,
                "changelog": [{"version": v["version"], "changelog": v["changelog"]}
                              for v in quantum_resources.versions()[start:end]],
                "explanation": "The threat model changed between these scans; see the changelog."}
    return {"reason": "clock", "from_version": v_before, "to_version": v_after, "elapsed_days": elapsed,
            "changelog": [],
            "explanation": ("Same threat-model version: score movement comes from time passing (Z is "
                            "measured from the report date) and from changes to the assets themselves.")}


def compare(before: dict, after: dict) -> dict:
    """Delta from scan `before` to scan `after` (store.get_scan records)."""
    old = {a["id"]: a for a in before.get("assets", [])}
    new = {a["id"]: a for a in after.get("assets", [])}

    def brief(a: dict) -> dict:
        return {"id": a["id"], "name": a.get("name"), "algorithm": a.get("algorithm") or a.get("key_exchange")
                or a.get("cipher_suite"), "quantum_vulnerable": a.get("quantum_vulnerable"),
                "system": (a.get("raw_details") or {}).get("system")}

    changed = []
    for asset_id in sorted(old.keys() & new.keys()):
        a, b = old[asset_id], new[asset_id]
        changes = {f: [a.get(f), b.get(f)] for f in _FIELDS if a.get(f) != b.get(f)}
        for bound in ("qirs_low", "qirs_high"):
            if abs(float(a.get(bound) or 0) - float(b.get(bound) or 0)) > _BAND_TOLERANCE:
                changes[bound] = [round(float(a.get(bound) or 0), 4), round(float(b.get(bound) or 0), 4)]
        if changes:
            changed.append({**brief(b), "changes": changes})

    vulnerable_before = {i for i, a in old.items() if a.get("quantum_vulnerable")}
    migrated = {i for i in vulnerable_before if i in new and not new[i].get("quantum_vulnerable")}
    removed_vulnerable = {i for i in vulnerable_before if i not in new}
    newly_vulnerable = {i for i, a in new.items() if a.get("quantum_vulnerable") and i not in vulnerable_before}
    progress = (round(100.0 * (len(migrated) + len(removed_vulnerable)) / len(vulnerable_before), 1)
                if vulnerable_before else None)
    overlap = len(old.keys() & new.keys()) / max(len(old.keys() | new.keys()), 1)

    return {
        "from": {"scan_id": before.get("scan_id"), "timestamp": before.get("timestamp"), "label": before.get("label"),
                 "assets": len(old)},
        "to": {"scan_id": after.get("scan_id"), "timestamp": after.get("timestamp"), "label": after.get("label"),
               "assets": len(new)},
        "added": [brief(new[i]) for i in sorted(new.keys() - old.keys())],
        "removed": [brief(old[i]) for i in sorted(old.keys() - new.keys())],
        "changed": changed,
        "migration": {"vulnerable_before": len(vulnerable_before), "migrated": len(migrated),
                      "removed": len(removed_vulnerable),
                      "still_vulnerable": len(vulnerable_before) - len(migrated) - len(removed_vulnerable),
                      "newly_vulnerable": len(newly_vulnerable), "progress_percent": progress,
                      "progress_basis": "(migrated + removed) / vulnerable in the earlier scan"},
        "overlap": round(overlap, 3),
        "warning": ("These scans share under 10% of their assets; they may describe different estates, so the "
                    "progress figure mostly counts removals.") if overlap < 0.10 else None,
        "why_scores_moved": why_scores_moved(before, after),
    }
