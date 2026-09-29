"""The scan pipeline: from a scored estate to a ranked, checked, reproducible run.

Six stages, each a pure function of what the previous one produced, each
recording what it did in a trace the UI renders stage by stage:

    1. INTAKE       Validate the inlet. An asset with no id, a duplicate id or a
                    score outside [0, 1] is quarantined with the reason - never
                    silently dropped, never scored.
    2. CORROBORATE  Count the independent kinds of evidence behind each asset
                    (engine/core/corroboration.py): noisy-OR across the
                    declared / built / held / observed planes.
    3. SCORE        The two-axis model: QIRS = w_H*H + w_T*T, reported as a band
                    across the optimistic and pessimistic survival readings.
    4. ORDER        Mosca category first (engine/mosca.py), QIRS inside each
                    category. Weakly evidenced assets are flagged, still ranked.
    5. CHECK        Plain invariants over the output. A failure is reported next
                    to the ranking; it never hides it.
    6. MANIFEST     A SHA-256 digest over the inputs, the policy and the threat
                    model, so two runs can be compared and a result reproduced.

The same estate, policy and threat model always produce the same run.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Any

from engine.core import corroboration
from engine.core.trace import Trace

STAGES = ["intake", "corroborate", "score", "order", "check", "manifest"]

STAGE_META = {
    "intake": {
        "label": "Intake",
        "role": "Validates every asset. Malformed input is quarantined with a reason.",
        "kind": "inlet",
    },
    "corroborate": {
        "label": "Corroborate",
        "role": "Counts independent evidence planes behind each asset (noisy-OR across planes).",
        "kind": "flow",
    },
    "score": {
        "label": "Score",
        "role": "Two-axis quantum risk (HNDL + TNFL), reported as a band across survival readings.",
        "kind": "flow",
    },
    "order": {
        "label": "Order",
        "role": "Mosca category first, QIRS within. Weak evidence is flagged, never hidden.",
        "kind": "flow",
    },
    "check": {
        "label": "Check",
        "role": "Invariants over the output, reported beside it.",
        "kind": "safety",
    },
    "manifest": {
        "label": "Manifest",
        "role": "Digest of inputs, policy and threat model - the run can be reproduced.",
        "kind": "outlet",
    },
}


@dataclass
class ScanRun:
    """Everything one pass of the scan pipeline produced."""

    trace: Trace
    ranked: list[dict] = field(default_factory=list)
    flagged: list[dict] = field(default_factory=list)
    quarantined: list[dict] = field(default_factory=list)
    corroboration: dict[str, dict] = field(default_factory=dict)
    checks: list[dict] = field(default_factory=list)
    checks_passed: bool = True
    stats: dict[str, Any] = field(default_factory=dict)
    manifest: dict[str, Any] = field(default_factory=dict)
    policy: dict[str, Any] | None = None


def _intake(assets: list) -> tuple[list, list[dict]]:
    accepted, quarantined, seen = [], [], set()
    for asset in assets:
        asset_id = getattr(asset, "id", None)
        name = getattr(asset, "name", asset_id)
        reason = None
        if not asset_id:
            reason = "Missing id."
        elif asset_id in seen:
            reason = "Duplicate id."
        else:
            try:
                qirs = float(getattr(asset, "qirs", 0.0) or 0.0)
                if not 0.0 <= qirs <= 1.0:
                    reason = f"QIRS {qirs} outside [0, 1]."
            except (TypeError, ValueError):
                reason = "QIRS is not a number."
        if reason:
            quarantined.append({"id": asset_id, "name": name, "reason": reason})
            continue
        seen.add(asset_id)
        accepted.append(asset)
    return accepted, quarantined


def _has_forbidden_key(payload: Any) -> bool:
    from engine.intake.scrub import FORBIDDEN

    if isinstance(payload, dict):
        return any(
            key in FORBIDDEN or _has_forbidden_key(value)
            for key, value in payload.items()
        )
    if isinstance(payload, list):
        return any(_has_forbidden_key(item) for item in payload)
    return False


def _digest(accepted: list, policy_dict: dict, threat_source: str) -> str:
    payload = {
        "assets": sorted(
            (a.id, getattr(a, "algorithm", None), getattr(a, "key_size", None),
             round(float(getattr(a, "qirs", 0.0) or 0.0), 6))
            for a in accepted
        ),
        "policy": policy_dict,
        "threat_model": threat_source,
    }
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def run(assets: list, detail_for: set[str] | None = None, *, policy=None) -> ScanRun:
    """One complete pass over an estate. Deterministic for a given input."""
    from engine import mosca
    from engine.core.policy import resolve_policy
    from engine.quantum_resources import current_version, doubling_years, table_hash
    from engine.threat_model import SOURCE as THREAT_SOURCE

    pol = resolve_policy(policy)
    flag_threshold = float(getattr(pol, "flag_threshold", corroboration.DEFAULT_FLAG_THRESHOLD))
    trace = Trace()

    # 1. Intake -------------------------------------------------------------
    trace.begin_stage("intake")
    accepted, quarantined = _intake(assets)
    trace.record(
        stage="intake", operation="validate", subject="*",
        rule="Accept if id present and unique and 0 <= QIRS <= 1; otherwise quarantine with the reason.",
        inputs={"submitted": len(assets)},
        output={"accepted": len(accepted), "quarantined": len(quarantined)},
    )
    for item in quarantined[:25]:
        trace.record(stage="intake", operation="quarantine", subject=str(item["id"]),
                     rule="Malformed input is quarantined, never scored.", output=item)
    trace.end_stage("intake")

    # 2. Corroborate --------------------------------------------------------
    trace.begin_stage("corroborate")
    started = time.perf_counter()
    evidence: dict[str, dict] = {}
    for asset in accepted:
        readings = corroboration.observations_for(asset, policy=pol)
        evidence[asset.id] = corroboration.corroborate(readings, flag_threshold=flag_threshold)
        if detail_for and asset.id in detail_for:
            trace.record(
                stage="corroborate", operation="combine_planes", subject=asset.id,
                rule="c = 1 - prod over planes of (1 - max confidence in plane), capped at 0.99",
                inputs={"readings": evidence[asset.id]["readings"]},
                output={"confidence": evidence[asset.id]["confidence"],
                        "planes": evidence[asset.id]["planes"]},
            )
    multi_plane = sum(1 for e in evidence.values() if len(e["planes"]) > 1)
    trace.record(
        stage="corroborate", operation="combine_planes", subject="*",
        rule="Max within a plane, noisy-OR across planes. Flag below the policy threshold.",
        inputs={"assets": len(accepted), "flag_threshold": flag_threshold},
        output={"multi_plane": multi_plane,
                "flagged": sum(1 for e in evidence.values() if e["flagged"])},
        duration_us=int((time.perf_counter() - started) * 1_000_000),
    )
    trace.end_stage("corroborate")

    # 3. Score --------------------------------------------------------------
    trace.begin_stage("score")
    started = time.perf_counter()
    w_h = float(getattr(pol, "w_H", 0.5))
    w_t = float(getattr(pol, "w_T", 0.5))
    arrivals = mosca.arrival_years()
    scored: list[dict] = []
    for asset in accepted:
        h = float(getattr(asset, "h_score", 0.0) or 0.0)
        t = float(getattr(asset, "t_score", 0.0) or 0.0)
        qirs = round(w_h * h + w_t * t, 6)
        low = float(getattr(asset, "qirs_low", qirs) or 0.0)
        high = float(getattr(asset, "qirs_high", qirs) or 0.0)
        low, high = min(low, qirs), max(high, qirs)
        m = mosca.assess(asset, arrivals=arrivals)
        ev = evidence[asset.id]
        scored.append({
            "id": asset.id,
            "name": getattr(asset, "name", asset.id),
            "asset_class": getattr(asset, "asset_class", None),
            "algorithm": getattr(asset, "algorithm", None),
            "quantum_vulnerable": bool(getattr(asset, "quantum_vulnerable", False)),
            "qirs": qirs,
            "band": {"low": round(low, 6), "high": round(high, 6)},
            "h_score": round(h, 6),
            "t_score": round(t, 6),
            "slack_months": float(getattr(asset, "slack_months", 0.0) or 0.0),
            "risk_level": getattr(asset, "risk_level", "unknown"),
            "verdict": getattr(asset, "verdict", "unknown"),
            "mosca_category": m["category"],
            "mosca_axis": m.get("axis"),
            "mosca_margin_years": (m.get("margin_years") or {}).get("median"),
            "confidence": ev["confidence"],
            "planes": ev["planes"],
            "sources": ev["sources"],
            "flagged": ev["flagged"],
            "flag_reason": ev["flag_reason"],
            "classically_broken": bool(getattr(asset, "classically_broken", False)),
        })
    trace.record(
        stage="score", operation="two_axis", subject="*",
        rule=f"QIRS = {w_h}*H + {w_t}*T; band across optimistic..pessimistic survival readings.",
        inputs={"assets": len(accepted)},
        output={"scored": len(scored)},
        duration_us=int((time.perf_counter() - started) * 1_000_000),
    )
    trace.end_stage("score")

    # 4. Order --------------------------------------------------------------
    trace.begin_stage("order")

    def sort_key(row: dict):
        if row["quantum_vulnerable"]:
            margin = row["mosca_margin_years"] if row["mosca_margin_years"] is not None else float("-inf")
            return (0, mosca.category_rank(row["mosca_category"]), -margin, -row["qirs"], row["name"])
        tier = 1 if row["classically_broken"] else (2 if row["verdict"] == "unknown" else 3)
        return (tier, 0, 0.0, row["name"])

    ranked = sorted(scored, key=sort_key)
    for index, row in enumerate(ranked, start=1):
        row["rank"] = index
    flagged = [row for row in ranked if row["flagged"]]
    trace.record(
        stage="order", operation="mosca_then_qirs", subject="*",
        rule="Quantum-vulnerable first, by Mosca category (certain > likely > possible > clear), "
             "then QIRS descending; then classically broken, unresolved, safe.",
        inputs={"scored": len(scored)},
        output={"ranked": len(ranked), "flagged": len(flagged)},
    )
    trace.end_stage("order")

    # 5. Check --------------------------------------------------------------
    trace.begin_stage("check")
    checks: list[dict] = []

    def check(key: str, description: str, passed: bool, detail: str = "") -> None:
        checks.append({"key": key, "description": description,
                       "passed": bool(passed), "detail": "" if passed else detail})

    check("conservation", "Every submitted asset is ranked or quarantined with a reason.",
          len(ranked) + len(quarantined) == len(assets),
          f"{len(assets)} submitted, {len(ranked)} ranked, {len(quarantined)} quarantined.")
    bad_band = [r["id"] for r in ranked if not r["band"]["low"] - 1e-9 <= r["qirs"] <= r["band"]["high"] + 1e-9]
    check("band_contains_score", "Every score lies inside its reported band.",
          not bad_band, f"Outside band: {', '.join(bad_band[:5])}")
    ranks = [r["rank"] for r in ranked]
    check("ranks_unique", "Ranks are 1..n with no gaps or repeats.",
          ranks == list(range(1, len(ranked) + 1)), "Rank sequence is broken.")
    leaked = [a.id for a in accepted if _has_forbidden_key(getattr(a, "raw_details", {}) or {})]
    check("no_key_material", "No private-key field is present anywhere in the estate.",
          not leaked, f"Key material fields on: {', '.join(leaked[:5])}")
    flagged_ids = {r["id"] for r in flagged}
    check("flags_never_hide", "Every flagged asset is still ranked.",
          flagged_ids <= {r["id"] for r in ranked}, "A flagged asset is missing from the ranking.")
    checks_passed = all(c["passed"] for c in checks)
    trace.record(
        stage="check", operation="invariants", subject="*",
        rule="Reported beside the output; a failure never withholds the ranking.",
        output={"passed": sum(c["passed"] for c in checks), "failed": sum(not c["passed"] for c in checks)},
    )
    trace.end_stage("check")

    # 6. Manifest -----------------------------------------------------------
    trace.begin_stage("manifest")
    policy_dict = pol.to_dict()
    version = current_version()
    threat_id = f"{THREAT_SOURCE} | model {version['version']} | resources {table_hash()[:16]}"
    digest = _digest(accepted, policy_dict, threat_id)
    manifest = {
        "run_id": trace.run_id,
        "digest_sha256": digest,
        "threat_model": THREAT_SOURCE,
        "threat_model_version": version["version"],
        "resources_table_hash": table_hash(),
        "qubit_doubling_years": doubling_years(),
        "crqc_arrival_years": arrivals,
        "policy": pol.name,
        "assets": len(accepted),
    }
    trace.record(stage="manifest", operation="digest", subject="*",
                 rule="SHA-256 over sorted asset identities, policy, threat-model source, version and resources table.",
                 output={"digest_sha256": digest})
    trace.end_stage("manifest")

    categories: dict[str, int] = {}
    for row in ranked:
        categories[row["mosca_category"]] = categories.get(row["mosca_category"], 0) + 1

    return ScanRun(
        trace=trace,
        ranked=ranked,
        flagged=flagged,
        quarantined=quarantined,
        corroboration=evidence,
        checks=checks,
        checks_passed=checks_passed,
        manifest=manifest,
        policy=policy_dict,
        stats={
            "submitted": len(assets),
            "assets": len(accepted),
            "quarantined": len(quarantined),
            "observations": sum(len(e["readings"]) for e in evidence.values()),
            "corroborated": multi_plane,
            "ranked": len(ranked),
            "flagged": len(flagged),
            "mean_confidence": round(
                sum(e["confidence"] for e in evidence.values()) / max(len(evidence), 1), 4
            ),
            "mosca_categories": categories,
            "checks_passed": checks_passed,
            "policy": pol.name,
        },
    )
