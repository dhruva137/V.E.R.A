"""The V.E.R.A. agent - a governed analyst over the scored estate.

WHAT IT IS
----------
A tool-calling loop between the operator's own language model (engine.llm_bridge)
and the estate the engine has already scored. The model contributes language; it
contributes no numbers. Every figure it can state comes back from a tool that
read the same objects the dashboard renders, so an answer in chat and the same
answer on the Dashboard page cannot disagree.

That constraint is the design. A model asked "what should I migrate first?"
without tools will produce a confident, plausible, invented ranking - which for a
migration-planning tool is the worst possible failure, because it is
indistinguishable from the real one. So the tools return the engine's own
fields, the system prompt forbids inventing figures, and the estate summary is
injected up front so the model knows what it is looking at before it asks.

WHAT IT CAN SEE
---------------
The whole field map, through twenty-eight read tools: the estate summary, any
asset's full derivation and Mosca reading (X, Y, per-primitive Z), the evidence
behind it, the dependency graph and transitive blast radius, drift between the
declared, built, held and observed planes, the vendor-gated register, the
recommended replacement with its measured cost, the roadmap against statutory
deadlines, the delta between two scans, the signed manifest and the audit
chain. `run_scan` re-collects from in-scope files, images and recordings; it
reads and changes none of them, so it is a read tool.

WHAT IT CAN CHANGE
------------------
Two things - `migrate_asset` (a simulated migration of the inventory record,
never of a production system) and `scan_key_vault` - and only through
engine.agent_control, which decides whether the call is allowed, caps how many
assets one action may touch, rate limits the loop, and writes an audit entry
either way. In the default posture (read-only, NTRO mode) the model is not even
shown them. See engine.agent_control for why each limit exists.

ROUTER FIRST
------------
engine.agent_router picks the tool for requests whose verb names it, before
the model is asked; see process_chat_events.
"""

from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path
from typing import Any, Callable

from engine import hybrid
from engine.agent_control import ControlRefusal, RateLimited, WRITE_TOOLS, get_control
from engine.llm_bridge import LLMError, chat, get_config

logger = logging.getLogger(__name__)

MAX_ROWS = 40  # rows any one tool will return, so a turn cannot blow the context

SYSTEM_PROMPT = """You are the V.E.R.A. agent, a post-quantum cryptography migration \
analyst embedded in the V.E.R.A. dashboard.

WHO YOU ARE, IF ASKED
You are a migration analyst built into VERA. You read the scored estate \
through tools and explain it: what to migrate first and why, how an asset's \
score is derived, what depends on what, and where an asset stands against \
its statutory deadline. You did not compute the scores - the engine did - \
and you can propose a migration but not apply one without human approval. \
Say that in your own words, briefly, when someone asks what you are.

WHEN TO REACH FOR A TOOL
Questions about the estate - what to migrate, why an asset ranks where it \
does, what depends on what, deadlines, any score - are answered from tools, \
always.

Questions about you, about what you can do, about what V.E.R.A. is, and plain \
conversational openers, are answered directly in a sentence or two with no \
tool call at all. Answering 'what are you' with a wall of estate statistics \
is not an answer to the question that was asked - it is an answer to a \
question nobody asked. Someone talking to you in ordinary English expects \
ordinary English back.

If a question mixes the two, answer the conversational half in a sentence \
and call tools for the half that needs a number.

VERA scores every cryptographic asset in an estate on two independent axes:

- HNDL (H) - confidentiality risk. Harvest now, decrypt later: an adversary \
records ciphertext today and decrypts it once a quantum computer exists. Its \
exposure horizon is x_c + y (data lifetime PLUS migration time), so delay makes \
it monotonically worse without bound.
- TNFL (T) - integrity risk. Trust now, forge later: signing and identity assets \
do not leak, they get forged. Its horizon is min(x_i, y), capped by the trust \
anchor's own retirement, so delay saturates rather than compounding.

QIRS is the weighted composite. Slack is months remaining against the asset's \
statutory deadline under India's DST framework; negative slack means the asset \
cannot meet its deadline even starting today.

PLATFORM CAPABILITIES

1. WHERE THE KEYS ACTUALLY LIVE. Most of an estate's worst assets are not on \
the network: they are objects inside an HSM, a KMIP key manager or a cloud KMS. \
scan_key_vault ingests that metadata; inspect_key reports, for one key, which \
token holds it and whether that token's firmware advertises any post-quantum \
mechanism at all. Metadata only — no key material is ever read, and these \
sources would not return any if asked.

2. CHANGEABILITY OUTRANKS RANK. An asset ranked first that sits on a token with \
no PQC mechanism cannot be started first; it is blocked on a vendor firmware \
release. Say so plainly, and name the next asset that *can* be started. A \
ranking that ignores whether anything can be done about the top entry is not a \
plan.

3. YOU CAN DRIVE THE DASHBOARD. open_page moves the operator to a page and can focus one asset. When someone asks to see or open something, call it first and then say what is on screen. Do not describe a page you have not opened as though they are already looking at it.

4. VERIFY WHAT YOU CHANGE. After any applied migration call verify_migration \
and report the result. If a check failed, say which and stop — do not describe \
a partial migration as a success.

5. MOSCA, DRIFT AND WHO CAN ACT. explain_mosca gives X, Y and Z for an asset \
with the published source of each number. list_drift reports where the \
declared policy and what was found disagree. list_vendor_gated names who must \
ship a PQC mechanism before an asset can move. recommend gives the replacement \
and its measured cost. verify_manifest checks the signed evidence and the \
audit chain.

6. COVERAGE IS PART OF THE ANSWER. Sensors that are not connected are blind \
spots, and get_connector_status reports them from the live registry. Never \
describe a sensor as active unless that registry says it is. Reporting an \
estate as complete when a required sensor was never connected is the failure \
this product exists to prevent.

RULES
1. Never state a number you did not get from a tool. If you need a figure, call \
a tool. Do not estimate, round from memory, or carry a number over from an \
earlier answer you are unsure of.
2. If a tool returns an error, say what it said. Do not substitute a guess.
3. Quote asset names and ids exactly as the tools return them.
4. Explain the reasoning in terms of the two axes. "RSA is weak" is not an \
answer; "this is the highest-TNFL asset because it is a root CA whose validity \
horizon exceeds the migration window" is.
5. Be concise and specific. You are talking to an engineer or a CISO.
6. When you propose or apply a migration, state the QIRS effect the tool reported.

Absolute scores come from a subjective expert-elicitation prior and are reported \
as bands. If asked for certainty, say the ordering is the defensible claim and \
the absolute value is not.
"""


# --------------------------------------------------------------------------
# Estate access
#
# The scan lives in api.routes.state. Imported inside functions rather than at
# module scope: routes imports this module lazily when the chat endpoint is hit,
# and a module-level import here would close that cycle at startup.
# --------------------------------------------------------------------------


def _state():
    from api.routes import state

    return state


def _assets() -> list:
    return _state().assets


def _find(asset_id: str):
    """Resolve by exact id, then by name, then by unique substring.

    A model that has just been shown a list of names will refer to an asset by
    name about as often as by id, and rejecting that is a worse experience than
    resolving it. Ambiguity is reported rather than guessed at.
    """
    if not asset_id:
        return None
    assets = _assets()
    for asset in assets:
        if asset.id == asset_id:
            return asset
    needle = asset_id.strip().lower()
    for asset in assets:
        if (asset.name or "").lower() == needle:
            return asset
    matches = [
        a for a in assets
        if needle in (a.name or "").lower() or needle in (a.source_location or "").lower()
    ]
    return matches[0] if len(matches) == 1 else None


def _asset_row(asset) -> dict:
    """The compact projection used in list results.

    Deliberately small: forty assets at full width is most of a context window,
    and the model can always ask for one asset's detail.
    """
    return {
        "id": asset.id,
        "name": asset.name,
        "asset_class": asset.asset_class,
        "class_label": asset.profile_label,
        "algorithm": asset.algorithm or asset.key_exchange or asset.cipher_suite,
        "verdict": asset.verdict,
        "quantum_vulnerable": asset.quantum_vulnerable,
        "h_score": round(asset.h_score, 4),
        "t_score": round(asset.t_score, 4),
        "qirs": round(asset.qirs, 4),
        "risk_level": asset.risk_level,
        "priority_rank": asset.priority_rank,
        "slack_months": round(asset.slack_months, 1),
        "deadline_year": asset.statutory_deadline_year,
        "persona": asset.persona,
        "migrated": asset.migrated,
    }


def _no_scan() -> dict:
    return {
        "error": "No estate is loaded.",
        "remedy": (
            "Ask the operator to open the Scanner page and load the demo estate, "
            "run a TLS scan, or import a CBOM."
        ),
    }


# --------------------------------------------------------------------------
# Read tools
# --------------------------------------------------------------------------


def _tool_estate_summary(_: dict) -> dict:
    from api.routes import _build_dashboard

    if not _assets():
        return _no_scan()
    summary = _build_dashboard().model_dump()
    # Trimmed to what a planning conversation needs. The full object carries six
    # breakdown dictionaries, most of which are noise in a chat turn.
    return {
        "total_assets": summary["total_assets"],
        "quantum_vulnerable": summary["quantum_vulnerable"],
        "quantum_safe": summary["quantum_safe"],
        "classically_broken": summary["classically_broken"],
        "avg_hndl": summary["avg_hndl"],
        "avg_tnfl": summary["avg_tnfl"],
        "avg_qirs": summary["avg_qirs"],
        "max_qirs": summary["max_qirs"],
        "negative_slack_count": summary["negative_slack_count"],
        "worst_slack_months": summary["worst_slack_months"],
        "org_persona": summary["org_persona"],
        "by_risk_level": summary["by_risk_level"],
        "by_verdict": summary["by_verdict"],
        "by_asset_class": summary["by_asset_class"],
        "scan_timestamp": summary["scan_timestamp"],
        # Operational state, not risk. Folded into the existing summary rather
        # than given its own tool: an agent asked "what should I worry about"
        # should see the certificate expiring in nine days without having to
        # know to ask a second question about it.
        "operational": _operational_snapshot(),
    }


def _operational_snapshot() -> dict:
    """Expiry, changeability and trust concentration in the shape a turn needs.

    Deliberately small. The full readiness payload carries per-asset lists that
    would dominate a chat turn's context without changing the answer.
    """
    from engine.agility import summarise as agility_summary
    from engine.dependencies import build_graph
    from engine.expiry import summarise as expiry_summary

    assets = _assets()
    graph = build_graph(assets)
    dependents = {n["id"]: n.get("dependents", 0) for n in graph.get("nodes", [])}

    expiry = expiry_summary(assets, dependents=dependents, worst_limit=3)
    agility = agility_summary(assets)
    top = graph.get("stats", {}).get("most_depended_on", [])

    return {
        "certificates_expiring_or_expired": expiry["at_risk"],
        "expiry_counts": expiry["counts"],
        "soonest_expiring": [
            {
                "name": row["name"],
                "days_remaining": row["days_remaining"],
                "dependents": row["dependents"],
            }
            for row in expiry["worst"]
        ],
        "changeable_today_pct": agility["actionable_pct"],
        "blocked_assets": agility["blocked"],
        "agility_counts": agility["counts"],
        "largest_trust_anchor": (
            {
                "name": top[0]["name"],
                "dependents": top[0]["dependents"],
                "pct_of_estate": round(100.0 * top[0]["dependents"] / len(assets), 1)
                if assets else 0.0,
            }
            if top else None
        ),
        "assets_without_owner": sum(1 for a in assets if not (a.owner or "").strip()),
    }


def _tool_list_assets(args: dict) -> dict:
    assets = _assets()
    if not assets:
        return _no_scan()

    sort_by = args.get("sort_by") or "qirs"
    limit = max(1, min(int(args.get("limit") or 10), MAX_ROWS))
    query = (args.get("query") or "").strip().lower()
    asset_class = (args.get("asset_class") or "").strip()
    risk_level = (args.get("risk_level") or "").strip()
    only_vulnerable = bool(args.get("only_vulnerable", True))

    rows = list(assets)
    if only_vulnerable:
        rows = [a for a in rows if a.quantum_vulnerable]
    if asset_class:
        rows = [
            a for a in rows
            if (a.asset_class or "").lower() == asset_class.lower()
            or (a.profile_label or "").lower() == asset_class.lower()
        ]
    if risk_level:
        rows = [a for a in rows if a.risk_level == risk_level]
    if query:
        rows = [
            a for a in rows
            if query in (a.name or "").lower()
            or query in (a.source_location or "").lower()
            or query in (a.algorithm or "").lower()
            or query in (a.profile_label or "").lower()
        ]

    keys: dict[str, Callable[[Any], Any]] = {
        "qirs": lambda a: -a.qirs,
        "hndl": lambda a: -a.h_score,
        "tnfl": lambda a: -a.t_score,
        # Ascending: the most negative slack is the most urgent.
        "slack": lambda a: a.slack_months,
        "priority": lambda a: a.priority_rank,
        "name": lambda a: (a.name or "").lower(),
    }
    rows.sort(key=keys.get(sort_by, keys["qirs"]))

    return {
        "sorted_by": sort_by if sort_by in keys else "qirs",
        "matched": len(rows),
        "returned": min(len(rows), limit),
        "assets": [_asset_row(a) for a in rows[:limit]],
    }


def _tool_get_asset(args: dict) -> dict:
    asset = _find(args.get("asset_id", ""))
    if not asset:
        return {"error": f"No asset matches {args.get('asset_id')!r}.",
                "remedy": "Call list_assets or search first and use an exact id."}
    row = _asset_row(asset)
    row.update({
        "source_location": asset.source_location,
        "source_type": asset.source_type,
        "key_size": asset.key_size,
        "protocol": asset.protocol,
        "cipher_suite": asset.cipher_suite,
        "key_exchange": asset.key_exchange,
        "signature_algorithm": asset.signature_algorithm,
        "vulnerability_reason": asset.vulnerability_reason,
        "primitive": asset.primitive,
        "classical_bits": asset.classical_bits,
        "pqc_replacement": asset.pqc_replacement,
        "qirs_band": [round(asset.qirs_low, 4), round(asset.qirs_high, 4)],
        "policy_inputs": {
            "x_c": asset.x_c, "x_i": asset.x_i, "y": asset.y,
            "s": asset.s, "e": asset.e, "c": asset.c,
        },
        "policy_rationale": asset.profile_rationale,
        "binding_phase": asset.binding_phase,
        "binding_phase_reason": asset.binding_phase_reason,
        "persona_source": asset.persona_source,
        "environment": asset.environment,
        "owner": asset.owner,
        "tags": asset.tags,
        "migrated_from": asset.migrated_from,
    })
    return row


def _tool_explain_asset(args: dict) -> dict:
    from engine.qirs import explain_asset

    asset = _find(args.get("asset_id", ""))
    if not asset:
        return {"error": f"No asset matches {args.get('asset_id')!r}."}
    return explain_asset(asset, _state().model())


def _tool_blast_radius(args: dict) -> dict:
    """Transitive dependents of one asset, from the dependency graph.

    This is `C` made concrete. A root CA with sixty certificates under it is not
    one migration, and the agent needs to be able to say so with the number.
    """
    from engine.dependencies import build_graph

    assets = _assets()
    if not assets:
        return _no_scan()
    asset = _find(args.get("asset_id", ""))
    if not asset:
        return {"error": f"No asset matches {args.get('asset_id')!r}."}

    graph = build_graph(assets)
    node = next((n for n in graph["nodes"] if n["id"] == asset.id), None)
    if not node:
        return {"error": "That asset is not in the dependency graph."}

    # Edges are directed: source depends on target.
    dependents = [e["source"] for e in graph["edges"] if e["target"] == asset.id]
    depends_on = [e["target"] for e in graph["edges"] if e["source"] == asset.id]
    by_id = {n["id"]: n for n in graph["nodes"]}

    return {
        "asset_id": asset.id,
        "name": asset.name,
        "transitive_dependents": node["dependents"],
        "direct_dependents": node["direct_dependents"],
        "estate_size": graph["stats"]["nodes"],
        "share_of_estate_pct": round(
            node["dependents"] / max(graph["stats"]["nodes"] - 1, 1) * 100, 1
        ),
        "direct_dependents_sample": [
            {"id": i, "name": by_id[i]["name"], "risk_level": by_id[i]["risk_level"]}
            for i in dependents[:15] if i in by_id
        ],
        "depends_on": [
            {"id": i, "name": by_id[i]["name"]} for i in depends_on[:15] if i in by_id
        ],
    }


def _tool_most_depended_on(args: dict) -> dict:
    from engine.dependencies import build_graph

    if not _assets():
        return _no_scan()
    graph = build_graph(_assets())
    limit = max(1, min(int(args.get("limit") or 8), 20))
    ranked = sorted(graph["nodes"], key=lambda n: -n["dependents"])[:limit]
    return {
        "estate_size": graph["stats"]["nodes"],
        "relationships": graph["stats"]["edges"],
        "assets": [
            {
                "id": n["id"], "name": n["name"],
                "transitive_dependents": n["dependents"],
                "qirs": n["qirs"], "risk_level": n["risk_level"],
                "class_label": n["class_label"],
            }
            for n in ranked
        ],
    }


def _tool_axis_extremes(args: dict) -> dict:
    """The dual-axis argument, in the form that makes it undeniable.

    The top of each axis is a different population. If the model is asked why two
    axes are needed, this is the evidence rather than the assertion.
    """
    from api.routes import get_axis_extremes

    if not _assets():
        return _no_scan()
    count = max(1, min(int(args.get("count") or 5), 10))
    return get_axis_extremes(count=count)


def _tool_deadlines(args: dict) -> dict:
    from engine.regulatory import deadline_table

    persona = (args.get("persona") or "").strip()
    table = deadline_table()
    if persona:
        deadlines = table.get("deadlines", table)
        match = {k: v for k, v in deadlines.items() if k.lower() == persona.lower()}
        if match:
            return {"persona": persona, "deadlines": match, "source": table.get("source")}
    return table


def _tool_roadmap(args: dict) -> dict:
    from api.routes import get_roadmap

    if not _assets():
        return _no_scan()
    limit = max(1, min(int(args.get("limit") or 15), MAX_ROWS))
    only_overrunning = bool(args.get("only_overrunning", False))
    items = [i.model_dump() for i in get_roadmap()]
    if only_overrunning:
        items = [i for i in items if i["overruns_deadline"]]
    return {
        "matched": len(items),
        "overrunning_deadline": sum(1 for i in items if i["overruns_deadline"]),
        "items": [
            {
                "asset_id": i["asset_id"], "asset_name": i["asset_name"],
                "algorithm": i["algorithm"], "phase": i["phase"],
                "migration_start": i["migration_start"], "migration_end": i["migration_end"],
                "deadline_year": i["deadline_year"], "slack_months": round(i["slack_months"], 1),
                "overruns_deadline": i["overruns_deadline"], "qirs": round(i["qirs"], 4),
            }
            for i in items[:limit]
        ],
    }


def _tool_threat_timeline(args: dict) -> dict:
    """Survival probability that a cryptographically relevant quantum computer
    has NOT arrived by a given year. Both axes are driven by this curve."""
    model = _state().model()
    years = args.get("years") or [5, 10, 15, 20, 25]
    if not isinstance(years, list):
        years = [years]
    readings = []
    for raw in years[:10]:
        try:
            horizon = float(raw)
        except (TypeError, ValueError):
            continue
        optimistic, median, pessimistic = model.survival(horizon)
        readings.append({
            "years_from_now": horizon,
            "survival_optimistic": round(optimistic, 4),
            "survival_median": round(median, 4),
            "survival_pessimistic": round(pessimistic, 4),
            "break_probability_median": round(1 - median, 4),
        })
    return {
        "source": (
            "Fitted to the Global Risk Institute Quantum Threat Timeline Report 2025 "
            "expert elicitation. A subjective prior, not a forecast."
        ),
        "readings": readings,
    }


def _tool_analytics(_: dict) -> dict:
    from api.routes import get_analytics

    if not _assets():
        return _no_scan()
    data = get_analytics()
    # The scatter is 100+ rows of per-asset coordinates the model cannot use in
    # prose; the aggregates are the part worth spending context on.
    return {
        "risk_distribution": data["risk_distribution"],
        "slack_summary": data["slack_summary"],
        "axis_dominance": data["axis_dominance"],
        "key_sizes": data["key_sizes"],
        "effort_distribution": data["effort_distribution"],
        "source_risk": data["source_risk"],
        "verdicts": {k: v["count"] for k, v in data["verdicts"].items()},
    }


def _tool_cbom_status(_: dict) -> dict:
    state = _state()
    if not state.assets:
        return _no_scan()
    report = state.cbom_report or {}
    failures = [
        {"id": c["id"], "description": c["description"],
         "violation_count": c["violation_count"], "examples": c["violations"][:3]}
        for c in report.get("checks", []) if not c.get("passed", True)
    ]
    return {
        "cbom_id": state.cbom.get("serialNumber", ""),
        "spec_version": report.get("spec_version") or state.cbom.get("specVersion", ""),
        "components": len(state.cbom.get("components", [])),
        "valid": report.get("valid"),
        "rules_total": report.get("rules_total"),
        "rules_passed": report.get("rules_passed"),
        "rules_failed": report.get("rules_failed"),
        "failures": failures[:10],
    }


def _tool_sensitivity(_: dict) -> dict:
    """Where the ordering claim holds and where it does not.

    Included so the agent can answer "how much should I trust this ranking?"
    with the measured rank correlation rather than reassurance.
    """
    from engine.sensitivity import analyse_invariance

    if not _assets():
        return _no_scan()
    result = analyse_invariance(_assets())
    if not result.get("sufficient_data"):
        return result
    return {
        "assets_compared": result["assets_compared"],
        "families_tested": result["families_tested"],
        "baseline": result["baseline"],
        "summary": result["summary"],
        "interpretation": result.get("interpretation"),
        "note": (
            "Stratified rho is the conditional theorem (equal sensitivity) and holds "
            "exactly. Global rho is the unconditional reading and does not."
        ),
    }


def _tool_migration_preview(args: dict) -> dict:
    """What a migration would change, without changing it.

    Separate from migrate_asset on purpose: an agent should be able to reason
    about consequences without needing write authority to do it.
    """
    assets = _assets()
    if not assets:
        return _no_scan()
    return _preview(args.get("target", ""), args.get("strategy", "hybrid"),
                    args.get("asset_id", ""))


# ---- Connector tools -------------------------------------------------------

# Mock partner and connector lists lived here. They were removed: the
# connector list claimed 2,341 assets discovered by an eBPF sensor that the
# discovery registry correctly reports as an unconfigured blind spot, so the
# agent contradicted the product. Both now read live state.


def _preview(target: str, strategy: str, asset_id: str = "") -> dict:
    """Shared by the preview tool and the approval card.

    Reads hybrid's own selection and replacement table so the preview cannot
    drift from what migrate would actually do.
    """
    from engine import recommendations

    assets = _assets()
    if asset_id:
        asset = _find(asset_id)
        if not asset:
            return {"error": f"No asset matches {asset_id!r}."}
        if not asset.quantum_vulnerable:
            return {
                "error": f"{asset.name} is not quantum-vulnerable; there is nothing to migrate.",
                "verdict": asset.verdict,
            }
        selected = [asset]
    else:
        selected = hybrid._select(assets, target or "", [])

    if not selected:
        return {
            "assets_affected": 0,
            "error": (
                f"No quantum-vulnerable asset matches target {target!r}."
                if target else "No quantum-vulnerable assets matched."
            ),
        }

    changes = []
    skipped = []
    for asset in selected[:20]:
        plan = hybrid.replacement_for(asset, strategy)
        if plan["replacement"] is None:
            skipped.append({"asset_id": asset.id, "name": asset.name, "reason": plan["reason"]})
            continue
        changes.append({
            "asset_id": asset.id,
            "name": asset.name,
            "from": getattr(asset, plan["field"], None) or asset.algorithm,
            "to": plan["replacement"],
            "qirs_before": round(asset.qirs, 4),
        })

    return {
        "assets_affected": len(selected),
        "strategy": strategy,
        "target": target or (selected[0].name if asset_id else "entire estate"),
        "avg_qirs_before": round(sum(a.qirs for a in selected) / len(selected), 4),
        "max_qirs_before": round(max(a.qirs for a in selected), 4),
        "negative_slack_before": sum(1 for a in selected if recommendations.behind(a)),
        "changes": changes,
        "skipped": skipped,
        "truncated": len(selected) > 20,
    }


# --------------------------------------------------------------------------
# Write tool
# --------------------------------------------------------------------------


def _tool_migrate_asset(args: dict) -> dict:
    """Apply a migration and rescore.

    Only reached after engine.agent_control has authorised it, which in the
    default posture means a human approved this specific call. The commit path
    is the same function the /harness/migrate endpoint uses, so an agent-driven
    migration and an operator-driven one leave the estate in identical shape -
    reprioritised, with a regenerated CBOM and a persisted scan.
    """
    from api.routes import commit_migration

    assets = _assets()
    if not assets:
        return _no_scan()

    asset_id = args.get("asset_id", "")
    target = args.get("target", "")
    strategy = args.get("strategy") or "hybrid"
    if strategy not in {"hybrid", "pqc_only"}:
        strategy = "hybrid"

    if asset_id:
        asset = _find(asset_id)
        if not asset:
            return {"error": f"No asset matches {asset_id!r}."}
        if not asset.quantum_vulnerable:
            return {"error": f"{asset.name} is not quantum-vulnerable; nothing to migrate."}
        # Matched by exact id through hybrid's own selector, so a substring
        # target cannot pull in a neighbour the operator did not approve.
        selected = [asset]
        result = hybrid.migrate(selected, _state().model(), strategy=strategy)
    else:
        result = hybrid.migrate(assets, _state().model(), target=target, strategy=strategy)

    if result.get("migrated"):
        commit_migration(result)

    return {
        "migrated": result.get("migrated", 0),
        "strategy": result.get("strategy"),
        "target": result.get("target"),
        "avg_qirs_before": result.get("before", {}).get("avg_qirs"),
        "avg_qirs_after": result.get("after", {}).get("avg_qirs"),
        "qirs_reduction": result.get("qirs_reduction"),
        "qirs_reduction_pct": result.get("qirs_reduction_pct"),
        "changes": result.get("changes", [])[:10],
        "message": result.get("message"),
    }


# --------------------------------------------------------------------------
# Tool registry
#
def _engine_run_cached(detail_for=None):
    from api.routes import state
    from engine.core import scan_pipeline

    return scan_pipeline.run(state.assets or [], detail_for=detail_for)


def _tool_get_engine_status(args: dict) -> dict:
    """Report the last pipeline run: its checks, flags and quarantine."""
    run = _engine_run_cached()
    return {
        "checks_passed": run.checks_passed,
        "stats": run.stats,
        "checks": [
            {"key": c["key"], "passed": c["passed"], "detail": c["detail"]}
            for c in run.checks
        ],
        "failed_checks": [c["key"] for c in run.checks if not c["passed"]],
        "flagged": len(run.flagged),
        "quarantined": len(run.quarantined),
        "manifest": run.manifest,
    }


def _tool_explain_evidence(args: dict) -> dict:
    """Why the pipeline ranks one asset where it does: evidence and Mosca."""
    from engine import mosca

    asset_id = (args or {}).get("asset_id", "")
    if not asset_id:
        return {"error": "asset_id is required."}

    run = _engine_run_cached(detail_for={asset_id})
    evidence = run.corroboration.get(asset_id)
    if evidence is None:
        return {"error": f"No such asset: {asset_id}"}

    asset = _find(asset_id)
    scored = next((r for r in run.ranked if r["id"] == asset_id), None)
    return {
        "asset_id": asset_id,
        "confidence": evidence["confidence"],
        "planes": evidence["planes"],
        "readings": evidence["readings"],
        "flagged": evidence["flagged"],
        "flag_reason": evidence["flag_reason"],
        "sensors_disagree": evidence["disagreement"],
        "mosca": mosca.assess(asset) if asset else None,
        "rank": (scored or {}).get("rank"),
        "qirs": (scored or {}).get("qirs"),
        "band": (scored or {}).get("band"),
    }


def _tool_list_flagged(args: dict) -> dict:
    """Assets to verify first: ranked, but on weak or disagreeing evidence."""
    limit = int((args or {}).get("limit", 10) or 10)
    run = _engine_run_cached()
    return {
        "flagged_count": len(run.flagged),
        "note": (
            "Flagged assets are still ranked. The flag says the evidence behind "
            "them is thin or the sensors disagree, so they are the first things "
            "to confirm with a second sensor."
        ),
        "flagged": [
            {
                "id": r["id"], "name": r["name"], "rank": r["rank"],
                "confidence": r["confidence"], "planes": r["planes"],
                "reason": r["flag_reason"],
            }
            for r in run.flagged[:limit]
        ],
    }


# --------------------------------------------------------------------------
# Discovery, risk, drift, recommendations and evidence (WP10)
# --------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parents[2]
DEMO_ESTATE = REPO_ROOT / "demo" / "estate" / "estate.yaml"
AGENT_TARGET_KINDS = ("path", "repo", "image", "capture", "vault")


def scan_roots() -> list[Path]:
    """Directories the agent may point a collector at.

    The demo tree, plus whatever the operator lists in VERA_SCAN_ROOTS. A model
    that can name any path could walk a whole disk; a model that can name only
    what the operator put in scope cannot.
    """
    roots = [REPO_ROOT / "demo"]
    for entry in os.environ.get("VERA_SCAN_ROOTS", "").split(os.pathsep):
        if entry.strip():
            roots.append(Path(entry.strip()))
    return [r.resolve() for r in roots]


def _in_scope(value: str) -> bool:
    path = Path(str(value).partition("#")[0])
    if not path.is_absolute():
        path = REPO_ROOT / path
    try:
        resolved = path.resolve()
    except OSError:
        return False
    return any(resolved == root or root in resolved.parents for root in scan_roots())


def _tool_run_scan(args: dict) -> dict:
    """Run the collectors over in-scope targets and re-score the estate.

    Collecting reads files, images and recordings and changes none of them,
    which is why this is not a write tool. Network probes are not offered: a
    live TLS or SSH handshake is started by an operator from Discovery, never
    by the model.
    """
    from api.routes import run_full_scan
    from collectors.registry import REGISTRY
    from engine import estate as estate_register
    from engine.estate import Target
    from engine.scan_job import collectors_for

    surfaces = [str(s).strip().lower() for s in (args or {}).get("surfaces") or [] if str(s).strip()]
    unknown = sorted(set(surfaces) - set(REGISTRY))
    if unknown:
        return {"error": f"Unknown surface(s): {', '.join(unknown)}.", "available_surfaces": sorted(REGISTRY)}
    if {"tls", "ssh"} & set(surfaces):
        return {"error": "Live TLS and SSH probes are started by an operator, not the agent.",
                "remedy": "Use the Scan screen, or ask for the recorded captures (surface 'capture')."}

    raw_targets = (args or {}).get("targets") or []
    declarations: list[dict] = []
    if raw_targets:
        targets, meta = [], {"name": f"Agent scan ({len(raw_targets)} targets)"}
        for raw in raw_targets:
            kind, value = str(raw.get("kind", "path")).lower(), str(raw.get("value", ""))
            if kind not in AGENT_TARGET_KINDS:
                return {"error": f"Target kind {kind!r} is not available to the agent.",
                        "allowed_kinds": list(AGENT_TARGET_KINDS)}
            if "://" in value or value.startswith("git@") or not _in_scope(value):
                return {"error": f"{value!r} is outside the scan scope.",
                        "scan_roots": [str(r) for r in scan_roots()],
                        "remedy": "An operator can add a directory to VERA_SCAN_ROOTS."}
            targets.append(Target(kind=kind, value=value, system=raw.get("system")))
    else:
        if not DEMO_ESTATE.is_file():
            return {"error": "No targets given and the demo estate is missing.",
                    "remedy": "Generate it with `python demo/estate/make_estate.py`."}
        targets, declarations, meta = estate_register.load(DEMO_ESTATE)
        targets = [t for t in targets if t.kind != "host"]

    if surfaces:
        for target in targets:
            target.collectors = [c for c in collectors_for(target) if c in surfaces]
        targets = [t for t in targets if t.collectors]
        if not targets:
            return {"error": "None of the targets has a collector among the requested surfaces.",
                    "surfaces": surfaces}

    state = _state()
    job = run_full_scan(targets, declarations, meta, org_persona=state.org_persona, merge=False, wait=True)
    finished = [e for e in job.events if e["type"] == "collector_finished"]
    by_surface: dict[str, int] = {}
    for event in finished:
        by_surface[event["collector"]] = by_surface.get(event["collector"], 0) + event["findings"]
    return {
        "job_id": job.id,
        "status": job.status,
        "error": job.error,
        "estate": meta.get("name"),
        "targets": len(targets),
        "findings_by_surface": by_surface,
        "collector_failures": [
            {"collector": e["collector"], "target": e["target"], "error": e["error"]}
            for e in job.events if e["type"] == "collector_failed"
        ],
        "result": job.result,
        "note": "Read-only collection: files, images and recordings were read; nothing was changed.",
    }


def _tool_explain_mosca(args: dict) -> dict:
    """X, Y and Z for one asset, with the per-primitive shift and its citation."""
    from engine import mosca
    from engine.quantum_resources import current_version

    asset = _find((args or {}).get("asset_id", ""))
    if asset is None:
        return {"error": f"No asset matches {(args or {}).get('asset_id')!r}.",
                "remedy": "Call list_assets first and use an exact id."}
    reading = mosca.assess(asset, _state().model())
    shift = reading.get("z_shift") or {}
    return {
        "asset_id": asset.id,
        "name": asset.name,
        "algorithm": asset.algorithm,
        "key_size": asset.key_size,
        "system": (asset.raw_details or {}).get("system"),
        "applicable": reading["applicable"],
        "category": reading["category"],
        "label": reading["label"],
        "axis": reading.get("axis"),
        "x_confidentiality_years": reading["x_c"],
        "x_integrity_years": reading["x_i"],
        "x_basis": reading.get("x_basis"),
        "y_plan_years": reading.get("y_plan"),
        "y_effort_years": reading.get("y_effort"),
        "vendor_gated": reading.get("vendor_gated"),
        "z_years": reading["z"],
        "z_shift_years": shift.get("delta_years"),
        "z_shift_basis": shift.get("basis"),
        "z_shift_source": {k: (shift.get("row") or {}).get(k) for k in ("label", "logical_qubits", "source", "url",
                                                                      "status")} if shift.get("row") else None,
        "margin_years": reading.get("margin_years"),
        "starting_now_helps": reading.get("starting_now_helps"),
        "probability_crqc_within_horizon": reading.get("probability_crqc_within_horizon"),
        "threat_model_version": current_version()["version"],
        "explanation": reading.get("explanation"),
    }


def _tool_list_drift(args: dict) -> dict:
    """Contradictions between what is declared, built, held and observed."""
    from engine import drift as drift_engine

    state = _state()
    if not state.drift and not state.declarations:
        return {"error": "No full scan has run, so there is nothing to compare.",
                "remedy": "Run run_scan, or start a full scan from Discovery."}
    rule = (args or {}).get("rule")
    severity = (args or {}).get("severity")
    limit = max(1, min(int((args or {}).get("limit", 10) or 10), MAX_ROWS))
    records = [r for r in state.drift
               if (not rule or r["rule"] == rule) and (not severity or r["severity"] == severity)]
    return {
        "summary": {k: v for k, v in drift_engine.summarise(state.drift).items() if k != "rules"},
        "matching": len(records),
        "records": [
            {"id": r["id"], "rule": r["rule"], "title": r["title"], "severity": r["severity"],
             "subject": r["subject"], "declared": r["declared"]["summary"], "observed": r["observed"]["summary"],
             "explain": r["explain"], "asset_ids": r["asset_ids"]}
            for r in records[:limit]
        ],
    }


def _tool_list_vendor_gated(_: dict) -> dict:
    """Work that cannot start until a vendor or provider ships a PQC mechanism."""
    from engine import recommendations

    assets = _assets()
    if not assets:
        return _no_scan()
    groups = recommendations.gated_register(assets)
    return {
        "groups": len(groups),
        "assets_gated": sum(g["count"] for g in groups),
        "register": [
            {"kind": g["kind"], "who": g["who"], "action": g["action"], "count": g["count"],
             "capabilities_needed": g["capabilities"], "earliest_deadline": g["earliest_deadline"],
             "assets": g["assets"][:5]}
            for g in groups
        ],
        "note": ("A gated asset ranked first cannot be started first: the next step is a "
                 "procurement ask, not a code change."),
    }


def _tool_recommend(args: dict) -> dict:
    """Target, alternatives, measured cost and owner for one asset."""
    from engine import recommendations

    asset = _find((args or {}).get("asset_id", ""))
    if asset is None:
        return {"error": f"No asset matches {(args or {}).get('asset_id')!r}.",
                "remedy": "Call list_assets first and use an exact id."}
    profile = (args or {}).get("profile") or None
    try:
        result = recommendations.recommend(asset, profile)
    except (ValueError, KeyError) as exc:
        return {"error": str(exc), "profiles": ["commercial", "cnsa"]}
    if result is None:
        return {"asset_id": asset.id, "name": asset.name, "need": None,
                "why": recommendations.need_for(asset, profile or recommendations.active_profile())[1]}
    return result


def _tool_compare_scans(args: dict) -> dict:
    """What changed between two stored scans, and why scores moved."""
    from fastapi import HTTPException

    from api.routes import get_delta

    try:
        return get_delta(from_scan=(args or {}).get("from") or None, to_scan=(args or {}).get("to") or None)
    except HTTPException as exc:
        return {"error": exc.detail, "remedy": "Run at least two scans, or call with scan ids from the Scans list."}


def _tool_verify_manifest(_: dict) -> dict:
    """Check the signed manifest for the current scan, and walk the audit chain."""
    from fastapi import HTTPException

    from api.routes import get_manifest, verify_manifest
    from engine import audit_chain

    chain = audit_chain.default().verify()
    try:
        manifest = get_manifest()
    except HTTPException as exc:
        return {"error": exc.detail, "audit_chain": chain}
    check = verify_manifest({"manifest": manifest})
    return {
        "manifest": {
            "valid": check["valid"],
            "algorithm": check["alg"],
            "reason": check["reason"],
            "key_trusted": check.get("key_trusted"),
            "cbom_matches_current_scan": check.get("cbom_matches_current_scan"),
            "scan_id": manifest.get("scan", {}).get("scan_id"),
        },
        "audit_chain": chain,
    }


# Declared in the OpenAI function shape; engine.llm_bridge translates it for
# providers that want a different one.
# --------------------------------------------------------------------------


def _tool_scan_key_vault(args: dict) -> dict:
    """Ingest key-manager metadata: HSM slots, KMIP objects, cloud KMS.

    This is a write in the sense that it changes what the estate contains, but
    it is not a *migration* — nothing about any key is altered. It is gated as a
    read because refusing an agent the ability to look is not a safety property.
    """
    from api.routes import process_findings
    from collectors import vault_collector

    findings, errors = vault_collector.scan_vault(args.get("vault_root") or None)
    if not findings:
        return {
            "error": "No key-manager metadata was found.",
            "remedy": (
                "Generate the demo vault with `python demo/vault/make_vault.py`, "
                "or point vault_root at a PKCS#11/KMIP/cloud-KMS export."
            ),
            "sources_unmeasured": errors,
        }

    state = _state()
    result = process_findings(
        findings, 0.0, kind="vault", label="Key manager metadata",
        org_persona=state.org_persona, merge=bool(args.get("merge", True)),
    )
    return {
        "ingested": len(findings),
        "estate_total": len(state.assets),
        "quantum_vulnerable": result.quantum_vulnerable,
        "behind_deadline": result.negative_slack_count,
        "cbom_valid": result.cbom_valid,
        "sources_unmeasured": errors,
        "note": (
            "Metadata only. No key material was read, and none of these sources "
            "would return any if asked."
        ),
    }


def _tool_inspect_key(args: dict) -> dict:
    """Everything known about one key, including whether it can be changed.

    Separate from get_asset because a key in a key manager carries facts an
    asset row does not: which token holds it, what mechanisms that token
    supports, and therefore whether migrating it is possible at all. An asset
    ranked first that cannot be touched for two years is not first, it is
    blocked, and that distinction is invisible in a score.
    """
    asset = _find(args.get("asset_id", ""))
    if not asset:
        return {"error": f"No asset matches {args.get('asset_id')!r}.",
                "remedy": "Call list_assets first and use an exact id."}

    raw = asset.raw_details or {}
    blocked = bool(raw.get("change_blocked"))
    return {
        "asset_id": asset.id,
        "name": asset.name,
        "algorithm": asset.algorithm,
        "key_size": asset.key_size,
        "asset_class": asset.asset_class,
        "class_label": asset.profile_label,
        "verdict": asset.verdict,
        "quantum_vulnerable": asset.quantum_vulnerable,
        "qirs": round(asset.qirs, 4),
        "h_score": round(asset.h_score, 4),
        "t_score": round(asset.t_score, 4),
        "slack_months": round(asset.slack_months, 1),
        "pqc_replacement": asset.pqc_replacement,
        # Where it physically lives.
        "custody": {
            "location": asset.source_location,
            "source_type": asset.source_type,
            "discovered_by": raw.get("discovered_by"),
            "provenance": raw.get("provenance"),
            "confidence": raw.get("confidence"),
            "corroborated_by": raw.get("corroborated_by", []),
            "hsm_token": raw.get("hsm_token"),
            "hsm_model": raw.get("hsm_model"),
            "hsm_firmware": raw.get("hsm_firmware"),
            "hsm_fips_mode": raw.get("hsm_fips_mode"),
            "lifecycle_state": raw.get("lifecycle_state"),
            "extractable": raw.get("CKA_EXTRACTABLE"),
        },
        # The operational verdict, which outranks the risk score.
        "changeability": {
            "change_blocked": blocked,
            "reason": (raw.get("hsm_pqc_note") if blocked else None),
            "hsm_pqc_ready": raw.get("hsm_pqc_ready"),
            "agility_band": asset.agility_label,
            "actionable_today": asset.agility_actionable and not blocked,
        },
        "expiry": {
            "expires": asset.cert_validity_end,
            "days_remaining": asset.expiry_days,
            "band": asset.expiry_band,
        },
        "guidance": (
            "This key cannot be migrated in place: the token holding it "
            "advertises no post-quantum mechanism. Ranking it first is correct "
            "and acting on it first is not — it needs a vendor firmware plan, "
            "and the next actionable asset should be started meanwhile."
            if blocked else
            "This key can be migrated in place. preview_migration shows what "
            "would change before anything is applied."
        ),
    }


def _tool_verify_migration(args: dict) -> dict:
    """Post-migration checks. The half of a migration nobody builds.

    Applying a change and reporting success because the function returned is
    not verification. Each check below reads state back and can fail, and a
    failed check is reported as a failure rather than smoothed over.
    """
    from engine.cbom_validate import validate_cbom
    from engine.dependencies import build_graph

    state = _state()
    assets = _assets()
    if not assets:
        return _no_scan()

    asset_id = args.get("asset_id", "")
    checks: list[dict] = []
    follow_up: dict = {}

    def check(name, passed, detail):
        checks.append({"check": name, "passed": bool(passed), "detail": detail})

    if asset_id:
        asset = _find(asset_id)
        if not asset:
            return {"error": f"No asset matches {asset_id!r}."}

        check(
            "algorithm_replaced", asset.migrated,
            f"{asset.migrated_from or 'unknown'} -> {asset.algorithm}"
            if asset.migrated else
            "This asset has not been migrated; there is nothing to verify.",
        )
        check(
            "no_longer_quantum_vulnerable", not asset.quantum_vulnerable,
            f"verdict is now '{asset.verdict}'",
        )
        check(
            "risk_reduced", asset.qirs <= 0.05 or not asset.quantum_vulnerable,
            f"QIRS {round(asset.qirs, 4)}",
        )

        # Chain consistency: migrating an issuer must not orphan what it signed.
        # This can genuinely fail — if the asset has left the graph, everything
        # that depended on it now points at nothing.
        graph = build_graph(assets)
        by_id = {a.id: a for a in assets}
        in_graph = any(n["id"] == asset.id for n in graph["nodes"])
        dependents = [e["source"] for e in graph["edges"] if e["target"] == asset.id]
        check(
            "chain_not_orphaned", in_graph,
            f"the asset is still resolvable in the dependency graph with "
            f"{len(dependents)} direct dependents"
            if in_graph else
            "the asset is no longer in the dependency graph; anything that "
            "depended on it is now orphaned",
        )

        # Not a check — migrating an anchor is *expected* to leave its children
        # vulnerable until they are re-issued under it. Reporting that as a
        # failed check would be wrong; leaving it out would be worse, because it
        # is the next thing to do.
        still_vulnerable = [
            by_id[d].name for d in dependents
            if d in by_id and by_id[d].quantum_vulnerable
        ]
        follow_up = {
            "dependents_still_vulnerable": len(still_vulnerable),
            "examples": still_vulnerable[:5],
            "note": (
                "Expected after migrating a trust anchor: these are re-issued "
                "under the new anchor, they do not migrate themselves. This is "
                "the next step, not a failure."
            ) if still_vulnerable else "Nothing downstream is left vulnerable.",
        }
    else:
        migrated = [a for a in assets if a.migrated]
        check("something_was_migrated", migrated,
              f"{len(migrated)} asset(s) carry a migration record")
        check("all_migrated_are_safe",
              all(not a.quantum_vulnerable for a in migrated),
              f"{sum(1 for a in migrated if a.quantum_vulnerable)} migrated asset(s) "
              f"are still quantum-vulnerable")

    # The estate-level invariants that must survive any change.
    report = validate_cbom(state.cbom) if state.cbom else {}
    check(
        "cbom_still_valid", report.get("valid", False),
        f"{report.get('rules_passed', 0)}/{report.get('rules_total', 0)} rules pass",
    )

    try:
        from engine.core import scan_pipeline
        run = scan_pipeline.run(assets)
        failed = [c["key"] for c in run.checks if not c["passed"]]
        check("checks_passed", not failed,
              "all pipeline checks pass" if not failed else f"failing: {', '.join(failed)}")
    except Exception as exc:  # noqa: BLE001 - verification must report, not crash
        check("checks_passed", False, f"pipeline did not run: {exc}")

    passed = sum(1 for c in checks if c["passed"])
    return {
        "asset_id": asset_id or None,
        "checks_run": len(checks),
        "checks_passed": passed,
        "checks_failed": len(checks) - passed,
        "verified": passed == len(checks),
        "checks": checks,
        "follow_up": follow_up,
        "note": (
            "These read the estate back after the change. A failed check means "
            "the migration did not do what it claimed, and should be reported "
            "as such rather than described as a success."
        ),
    }


def _tool_open_page(args: dict) -> dict:
    """Drive the dashboard: open a page, optionally focused on one asset.

    The agent does not navigate by itself - it returns a directive and the
    dashboard performs it. That separation matters: the model is asking the UI
    to move, not reaching into it, so a bad argument is a refused directive
    rather than a broken screen. The operator watches the app move, which is
    the point - an assistant that can only talk about a page you have to find
    yourself is a search box with extra steps.
    """
    # Page -> (dashboard route, what it shows). Routes are the dashboard's own
    # addresses (six destinations and Settings), so a directive
    # lands exactly where a person clicking would.
    pages = {
        "overview": ("/overview", "the verdict, what to do next, the DST milestones, coverage and evidence"),
        "scan": ("/scan", "run a scan and watch every surface being read"),
        "inventory": ("/inventory", "every asset as a work queue, in priority order"),
        "quantum_exposure": ("/risk/exposure", "when each primitive breaks and every asset's Mosca margin"),
        "drift": ("/risk/drift", "where declared policy and the evidence disagree"),
        "dependencies": ("/risk/dependencies", "trust anchors and how much of the estate relies on each"),
        "actions": ("/plan/actions", "what to change to, the cost, and who can act"),
        "suppliers": ("/plan/suppliers", "vendors and providers that must ship PQC first, with contract clauses"),
        "timeline": ("/plan/timeline", "each migration against its DST milestone"),
        "reports": ("/evidence/reports", "the CBOM, SARIF, manifest and PDF reports"),
        "certin": ("/evidence/certin", "the CBOM against CERT-In's minimum elements"),
        "integrity": ("/evidence/integrity", "the signed manifest and the audit chain"),
        "changes": ("/evidence/changes", "what moved between two scans"),
        "method": ("/evidence/method", "the threat model, its sources and the measured benchmarks"),
        "settings": ("/settings/runtime", "offline posture, users, the model and assistant authority"),
    }
    requested = str((args or {}).get("page", "")).strip().lower().replace(" ", "_").replace("-", "_")
    aliases = {
        "dashboard": "overview", "home": "overview", "assets": "inventory", "scanner": "scan",
        "sensors": "scan", "discovery": "scan", "risk": "quantum_exposure", "mosca": "quantum_exposure",
        "horizon": "quantum_exposure", "exposure": "quantum_exposure", "blast_radius": "dependencies",
        "graph": "dependencies", "trust": "dependencies", "recommendations": "actions",
        "recommendation": "actions", "fixes": "actions", "plan": "actions", "vendors": "suppliers",
        "procurement": "suppliers", "roadmap": "timeline", "programme": "timeline", "schedule": "timeline",
        "cbom": "reports", "report": "reports", "board_memo": "reports", "exports": "reports",
        "evidence": "reports", "conformance": "certin", "cert_in": "certin", "manifest": "integrity",
        "audit": "integrity", "delta": "changes", "engine": "method", "threat_model": "method",
    }
    requested = aliases.get(requested, requested)

    if requested not in pages:
        return {
            "error": f"There is no page called {args.get('page')!r}.",
            "available_pages": sorted(pages),
        }

    route, purpose = pages[requested]
    focus = (args or {}).get("focus_asset_id", "")
    asset = _find(focus) if focus else None
    if focus and not asset:
        return {"error": f"No asset matches {focus!r}.",
                "remedy": "Call list_assets first and use an exact id."}

    return {
        # The dashboard watches for this shape and performs the move.
        "action": "navigate",
        "page": requested,
        "route": route,
        "page_name": requested.replace("_", " "),
        "focus_asset_id": asset.id if asset else None,
        "focus_asset_name": asset.name if asset else None,
        "shows": purpose,
        "message": (
            f"Opened {requested.replace('_', ' ')}"
            + (f", focused on {asset.name}." if asset else ".")
            + " Tell the user what they are now looking at and why."
        ),
    }


def _tool_get_connector_status(args: dict) -> dict:
    """Live sensor health from the discovery registry.

    Reads the same registry the discovery page renders, so the agent cannot
    report a sensor as active that the product shows as a blind spot.
    """
    from engine.discovery import surface

    data = surface()
    coverage = data["coverage"]
    return {
        "active_connectors": coverage["active"],
        "total_connectors": coverage["total_plugins"],
        "unavailable": coverage["unavailable"],
        "max_confidence_available": coverage["max_confidence_available"],
        "blind_spots": coverage["blind_spots"],
        "connectors": [
            {
                "id": plugin["id"], "name": plugin["name"],
                "zone": plugin["zone"], "available": plugin["available"],
                "provenance": plugin["provenance"],
                "confidence": plugin["confidence"],
                "unavailable_reason": plugin["unavailable_reason"],
                "status_label": plugin.get("status_label"),
                "measurement": plugin.get("measurement"),
                "coverage_contract": plugin.get("coverage_contract"),
            }
            for plugin in data["plugins"]
        ],
        "adapters": data.get("adapters", []),
        "note": (
            "Asset counts are not attributed per sensor here: an asset seen by "
            "two sensors is one asset, and summing per-sensor counts would "
            "overstate the estate. Adapters may be measurable via file dump "
            "without live credentials — that is not Active live connectivity."
        ),
    }


# Declared in the OpenAI function shape; engine.llm_bridge translates it for
# providers that want a different one.
# --------------------------------------------------------------------------


def _tool(name: str, description: str, properties: dict, required: list[str] | None = None) -> dict:
    return {
        "type": "function",
        "function": {
            "name": name,
            "description": description,
            "parameters": {
                "type": "object",
                "properties": properties,
                "required": required or [],
            },
        },
    }


_ASSET_ID = {
    "type": "string",
    # Deliberately strict. "Asset id, or an exact asset name" read as an
    # invitation to a small model: asked "what are u", llama3.1:8b called
    # get_asset with asset_id="u" - a word lifted straight out of the
    # question - before answering. Naming the source of a valid id, and the
    # tool that produces one, costs nothing and removes the guess.
    "description": (
        "Exact asset id or full asset name, as returned by an earlier tool "
        "call. Never a word taken from the user's sentence. If you do not "
        "have an exact identifier, call list_assets first and use one from "
        "its results."
    ),
}

TOOLS_SCHEMA = [
    _tool(
        "get_estate_summary",
        "Estate-wide totals: asset counts, average and maximum HNDL/TNFL/QIRS, how "
        "many assets cannot meet their statutory deadline, and the sector track. Also "
        "returns an 'operational' block covering certificates expiring or already "
        "expired, what share of the estate can actually be changed today versus "
        "blocked on a vendor or a hardware refresh, the largest trust anchor, and how "
        "many assets have no owner. Call this first when asked anything general about "
        "the estate, or anything about expiry, outages, or what is safe to start now.",
        {},
    ),
    _tool(
        "list_assets",
        "List or search assets with sorting. Use sort_by='qirs' for overall risk, "
        "'hndl' for confidentiality exposure, 'tnfl' for integrity exposure, 'slack' "
        "for deadline urgency (most negative first), 'priority' for the engine's own "
        "migration order.",
        {
            "query": {"type": "string", "description": "Match name, location, algorithm or class."},
            "sort_by": {
                "type": "string",
                "enum": ["qirs", "hndl", "tnfl", "slack", "priority", "name"],
            },
            "asset_class": {"type": "string", "description": "Filter by asset class or class label."},
            "risk_level": {
                "type": "string",
                "enum": ["critical", "high", "medium", "low", "informational"],
            },
            "only_vulnerable": {
                "type": "boolean",
                "description": "Restrict to quantum-vulnerable assets. Defaults to true.",
            },
            "limit": {"type": "integer", "description": f"1-{MAX_ROWS}, default 10."},
        },
    ),
    _tool(
        "get_asset",
        "Full detail for one asset: scores, policy inputs (x_c, x_i, y, s, e, c), "
        "classification reason, regulatory phase and recommended PQC replacement.",
        {"asset_id": _ASSET_ID}, ["asset_id"],
    ),
    _tool(
        "explain_asset",
        "Step-by-step derivation of one asset's scores, from policy inputs through "
        "the survival curve to the final priority. Use this when asked WHY an asset "
        "scores as it does.",
        {"asset_id": _ASSET_ID}, ["asset_id"],
    ),
    _tool(
        "get_blast_radius",
        "How many assets transitively depend on this one, and which depend on it "
        "directly. Use this before recommending a migration order - a hub is a "
        "programme, not a task.",
        {"asset_id": _ASSET_ID}, ["asset_id"],
    ),
    _tool(
        "list_most_depended_on",
        "The estate's dependency hubs, ranked by transitive dependent count.",
        {"limit": {"type": "integer", "description": "1-20, default 8."}},
    ),
    _tool(
        "get_axis_extremes",
        "The top assets on the HNDL axis and the top on the TNFL axis, side by side, "
        "with the overlap between them. Evidence for why one score is not enough.",
        {"count": {"type": "integer", "description": "1-10, default 5."}},
    ),
    _tool(
        "get_deadlines",
        "Statutory deadlines by sector persona under India's DST framework, with the "
        "regulatory source for each.",
        {"persona": {"type": "string", "description": "Optional single persona."}},
    ),
    _tool(
        "get_roadmap",
        "Migration schedule per asset with start, end, deadline and whether the "
        "migration overruns its statutory deadline.",
        {
            "only_overrunning": {
                "type": "boolean",
                "description": "Only assets whose migration misses the deadline.",
            },
            "limit": {"type": "integer", "description": f"1-{MAX_ROWS}, default 15."},
        },
    ),
    _tool(
        "get_threat_timeline",
        "Survival probability that no cryptographically relevant quantum computer "
        "exists yet, at given horizons in years. This curve drives both axes.",
        {
            "years": {
                "type": "array",
                "items": {"type": "number"},
                "description": "Horizons in years from now, e.g. [5, 10, 15].",
            }
        },
    ),
    _tool(
        "get_analytics",
        "Estate aggregates: QIRS distribution, axis dominance counts, slack summary, "
        "key-size spread, migration-effort spread and risk by source type.",
        {},
    ),
    _tool(
        "get_cbom_status",
        "CycloneDX CBOM state for the current estate and which validation rules "
        "pass or fail.",
        {},
    ),
    _tool(
        "get_sensitivity",
        "Rank agreement (Spearman rho, plus the count of reordered pairs) across seven survival families. Use "
        "this when asked how robust or trustworthy the ordering is.",
        {},
    ),
    _tool(
        "preview_migration",
        "What a migration WOULD change, without changing anything: which assets are "
        "selected, their current scores and the replacement algorithm for each. "
        "Always safe to call.",
        {
            "asset_id": {"type": "string", "description": "Preview a single asset."},
            "target": {
                "type": "string",
                "description": "Substring of source_location; empty means the whole estate.",
            },
            "strategy": {"type": "string", "enum": ["hybrid", "pqc_only"]},
        },
    ),
    _tool(
        "migrate_asset",
        "Apply a migration: replace the asset's algorithm with its PQC equivalent and "
        "rescore it. This CHANGES the estate. Depending on the operator's control "
        "settings it may require human approval before it takes effect.",
        {
            "asset_id": _ASSET_ID,
            "target": {
                "type": "string",
                "description": "Alternative to asset_id: substring of source_location.",
            },
            "strategy": {
                "type": "string",
                "enum": ["hybrid", "pqc_only"],
                "description": "hybrid keeps a classical fallback; pqc_only drops it.",
            },
        },
    ),
    _tool(
        "scan_key_vault",
        "Ingest key-manager metadata into the estate: HSM slots over PKCS#11, "
        "KMIP managed objects, and cloud KMS keys. These are the systems of "
        "record for the keys with the worst timelines — signing anchors, "
        "payment keys, firmware keys — and they are invisible to a network "
        "scan. Metadata only; no key material is read. Call this when asked "
        "about HSMs, key managers, vaults, or where the keys actually live.",
        {
            "merge": {
                "type": "boolean",
                "description": "Fold into the loaded estate rather than replacing it. Defaults to true.",
            },
            "vault_root": {
                "type": "string",
                "description": "Optional path to a metadata export. Defaults to the bundled demo vault.",
            },
        },
    ),
    _tool(
        "inspect_key",
        "Deep detail for one key, including where it is held and — critically — "
        "whether it can be changed at all. Reports the HSM token, its firmware "
        "and whether that firmware advertises any post-quantum mechanism. Use "
        "this before recommending action on any key: an asset ranked first that "
        "is blocked on a vendor firmware release cannot be started first, and "
        "no score can tell you that.",
        {"asset_id": _ASSET_ID}, ["asset_id"],
    ),
    _tool(
        "verify_migration",
        "Check that a migration actually did what it claimed. Reads the estate "
        "back and runs: algorithm replaced, no longer quantum-vulnerable, risk "
        "reduced, downstream dependents still consistent, CBOM still valid, and "
        "the engine's safety invariants still hold. Call this after every "
        "applied migration, and report any failed check as a failure.",
        {
            "asset_id": {
                "type": "string",
                "description": "Verify one asset. Omit to verify every migrated asset.",
            },
        },
    ),
    _tool(
        "open_page",
        "Open a page in the dashboard the operator is looking at, optionally "
        "focused on one asset. Use this whenever someone asks to see, show, "
        "open or go to something — 'show me the blast radius', 'open the "
        "inventory', 'take me to the root CA'. Pages: overview, scan, inventory, "
        "quantum_exposure, drift, dependencies, actions, suppliers, timeline, "
        "reports, certin, integrity, changes, method, settings. Navigate first, "
        "then explain what is on screen.",
        {
            "page": {
                "type": "string",
                "enum": ["overview", "scan", "inventory", "quantum_exposure", "drift",
                         "dependencies", "actions", "suppliers", "timeline", "reports",
                         "certin", "integrity", "changes", "method", "settings"],
            },
            "focus_asset_id": {
                "type": "string",
                "description": "Optional exact asset id to select on that page.",
            },
        },
        ["page"],
    ),
    _tool(
        "get_connector_status",
        "Report every discovery sensor from the live registry: which are active, "
        "which are registered but not connected, the network zone each runs in, "
        "and the evidence grade its method carries. A sensor that is not "
        "connected is a stated blind spot with the requirement that would enable "
        "it. Call this when asked about coverage, discovery, connector health or "
        "how confident a finding is — and never describe a sensor as active "
        "unless this tool says it is.",
        {},
    ),
    {
        "type": "function",
        "function": {
            "name": "get_engine_status",
            "description": (
                "Report the last pipeline run: which output checks passed or "
                "failed, how many assets are flagged for verification, how many "
                "were quarantined at intake, and the run digest. Use this when "
                "asked how far an answer can be trusted."
            ),
            "parameters": {"type": "object", "properties": {}},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "explain_evidence",
            "description": (
                "Explain why one asset is ranked where it is: the evidence planes "
                "and readings behind it, its corroborated confidence, whether "
                "sensors disagree, and its full Mosca reading (X, Y, Z and the "
                "category). Use this for 'why is this ranked here' or 'how sure "
                "are you about X'."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "asset_id": {"type": "string", "description": "The asset's id."},
                },
                "required": ["asset_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_flagged",
            "description": (
                "List assets flagged for verification - still ranked, but standing "
                "on thin or disagreeing evidence - with the reason for each. Often "
                "the most useful answer to 'what should we confirm first'."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "limit": {"type": "integer", "description": "Max rows (default 10)."},
                },
            },
        },
    },
    _tool(
        "run_scan",
        "Run the collectors and re-score the estate. With no targets it scans the "
        "demo estate register on every file-based surface. Collecting only reads "
        "(source, dependencies, binaries, containers, configs, keystores, secrets, "
        "vault exports, recorded captures); live network probes are an operator "
        "action. Use this when asked to scan, rescan or refresh discovery.",
        {
            "surfaces": {
                "type": "array", "items": {"type": "string"},
                "description": "Optional collector names, e.g. ['source', 'config']. Omit for all.",
            },
            "targets": {
                "type": "array",
                "items": {"type": "object", "properties": {
                    "kind": {"type": "string", "enum": list(AGENT_TARGET_KINDS)},
                    "value": {"type": "string"}, "system": {"type": "string"}}},
                "description": "Optional in-scope paths. Omit to scan the demo estate.",
            },
        },
    ),
    _tool(
        "explain_mosca",
        "Mosca's inequality for one asset: X (how long the data or signature must "
        "stay safe, from its data class), Y (migration time, including vendor lead "
        "time), Z (years until a cryptographically relevant quantum computer, as a "
        "pessimistic/median/optimistic band) and the per-primitive shift with its "
        "published source. Use this for 'when does this become a problem' or 'why "
        "is this urgent'.",
        {"asset_id": _ASSET_ID}, ["asset_id"],
    ),
    _tool(
        "list_drift",
        "Contradictions between what the organisation declared, what was built, "
        "what is held and what was observed on the wire (rules D1-D8), most "
        "severe first. Use this for 'show drift' or 'what does not match the policy'.",
        {
            "rule": {"type": "string", "description": "Optional rule id, D1 to D8."},
            "severity": {"type": "string", "enum": ["critical", "high", "medium", "low"]},
            "limit": {"type": "integer", "description": f"1-{MAX_ROWS}, default 10."},
        },
    ),
    _tool(
        "list_vendor_gated",
        "Assets that cannot be migrated until a vendor firmware or a cloud provider "
        "ships a post-quantum mechanism, grouped by who has to act and what to ask "
        "them for. Use this for 'what is blocked' or 'what do we need from vendors'.",
        {},
    ),
    _tool(
        "recommend",
        "The recommended replacement for one asset: target algorithm, alternatives, "
        "measured handshake and size cost, library prerequisites and who owns the "
        "change. profile 'commercial' follows NIST; 'cnsa' follows CNSA 2.0.",
        {"asset_id": _ASSET_ID,
         "profile": {"type": "string", "enum": ["commercial", "cnsa"]}},
        ["asset_id"],
    ),
    _tool(
        "compare_scans",
        "What changed between two stored scans: added, removed and changed assets, "
        "migration progress, and whether scores moved because of new evidence or "
        "because time passed. Omit both ids to compare the latest scan with the one before.",
        {"from": {"type": "string", "description": "Earlier scan id."},
         "to": {"type": "string", "description": "Later scan id."}},
    ),
    _tool(
        "verify_manifest",
        "Verify the signed evidence manifest for the current scan (ML-DSA-65, or a "
        "labelled Ed25519 fallback), whether it still matches the current CBOM, and "
        "walk the hash-chained audit log for tampering. Use this for 'can I trust "
        "this report' or 'has the audit log been changed'.",
        {},
    ),
]
TOOL_IMPLEMENTATIONS: dict[str, Callable[[dict], dict]] = {
    "get_estate_summary": _tool_estate_summary,
    "list_assets": _tool_list_assets,
    "get_asset": _tool_get_asset,
    "explain_asset": _tool_explain_asset,
    "get_blast_radius": _tool_blast_radius,
    "list_most_depended_on": _tool_most_depended_on,
    "get_axis_extremes": _tool_axis_extremes,
    "get_deadlines": _tool_deadlines,
    "get_roadmap": _tool_roadmap,
    "get_threat_timeline": _tool_threat_timeline,
    "get_analytics": _tool_analytics,
    "get_cbom_status": _tool_cbom_status,
    "get_sensitivity": _tool_sensitivity,
    "preview_migration": _tool_migration_preview,
    "migrate_asset": _tool_migrate_asset,
    "open_page": _tool_open_page,
    "scan_key_vault": _tool_scan_key_vault,
    "inspect_key": _tool_inspect_key,
    "verify_migration": _tool_verify_migration,
    "get_connector_status": _tool_get_connector_status,
    "get_engine_status": _tool_get_engine_status,
    "explain_evidence": _tool_explain_evidence,
    "list_flagged": _tool_list_flagged,
    "run_scan": _tool_run_scan,
    "explain_mosca": _tool_explain_mosca,
    "list_drift": _tool_list_drift,
    "list_vendor_gated": _tool_list_vendor_gated,
    "recommend": _tool_recommend,
    "compare_scans": _tool_compare_scans,
    "verify_manifest": _tool_verify_manifest,
}



def available_tools() -> list[dict]:
    """Tools offered to the model under the current control mode.

    In read-only mode the write tools are removed from the schema rather than
    refused on call. A model that is never told it can migrate does not spend a
    turn trying, and does not tell the user it is about to.
    """
    control = get_control()
    return [t for t in TOOLS_SCHEMA if control.tool_is_allowed(t["function"]["name"])]


def tool_catalogue() -> list[dict]:
    """What the UI shows on the agent's capability panel."""
    control = get_control()
    return [
        {
            "name": t["function"]["name"],
            "description": t["function"]["description"],
            "mutating": t["function"]["name"] in WRITE_TOOLS,
            "available": control.tool_is_allowed(t["function"]["name"]),
        }
        for t in TOOLS_SCHEMA
    ]


# --------------------------------------------------------------------------
# Execution
# --------------------------------------------------------------------------


def execute_tool(name: str, arguments: dict) -> dict:
    """Run one tool through the control plane.

    Returns a dict destined for the model as a tool result. Refusals are returned
    as results rather than raised, because the model needs to read them and tell
    the user why nothing happened.
    """
    control = get_control()
    implementation = TOOL_IMPLEMENTATIONS.get(name)
    if not implementation:
        control.record(name, "error", arguments=arguments, detail="Unknown tool.")
        return {"error": f"No such tool: {name}"}

    mutating = name in WRITE_TOOLS

    # The blast-radius cap needs to know the size of the action before it runs,
    # which for a migration means previewing the selection first. Other write
    # tools (vault rescan) mutate state without a migrate selection.
    assets_affected = 0
    preview: dict = {}
    if name == "migrate_asset":
        preview = _preview(
            arguments.get("target", ""),
            arguments.get("strategy", "hybrid"),
            arguments.get("asset_id", ""),
        )
        if preview.get("error") and not preview.get("assets_affected"):
            control.record(name, "refused", arguments=arguments, mutating=True,
                           detail=preview["error"])
            return preview
        assets_affected = preview.get("assets_affected", 0)
    elif mutating:
        preview = {"assets_affected": 0, "tool": name}

    try:
        decision = control.authorise(name, arguments, assets_affected=assets_affected)
    except ControlRefusal as refusal:
        return {"error": refusal.message, "remedy": refusal.remedy, "refused_by": "control plane"}
    except RateLimited as limited:
        return {
            "error": str(limited),
            "remedy": "Wait for the window to clear, or raise the limit in Settings.",
            "refused_by": "rate limit",
            "retry_after_seconds": round(limited.retry_after, 1),
        }

    if decision == "propose":
        if name == "migrate_asset":
            summary = (
                f"Migrate {assets_affected} asset(s) to "
                f"{arguments.get('strategy', 'hybrid')}: "
                f"{preview.get('target', 'selection')}"
            )
        else:
            summary = f"Run write tool {name}."
        proposal = control.propose(name, arguments, summary, preview)
        return {
            "status": "awaiting_approval",
            "proposal_id": proposal.id,
            "summary": summary,
            "assets_affected": assets_affected,
            "expires_at": proposal.expires_at,
            "preview": preview,
            "message": (
                "This change has NOT been applied. It is queued for human approval "
                "and appears as an approval card in the dashboard. Tell the user what "
                "you are proposing and that it needs their confirmation."
            ),
        }

    started = time.perf_counter()
    try:
        result = implementation(arguments)
    except Exception as exc:  # a tool bug must not take the turn down
        logger.exception("Agent tool %s failed", name)
        control.record(
            name, "error", arguments=arguments, mutating=mutating,
            detail=f"{exc.__class__.__name__}: {exc}",
            duration_ms=round((time.perf_counter() - started) * 1000),
        )
        return {"error": f"{name} failed: {exc}"}

    control.record(
        name, "allowed", arguments=arguments, mutating=mutating,
        duration_ms=round((time.perf_counter() - started) * 1000),
        assets_affected=result.get("migrated", 0) if mutating else 0,
        detail=result.get("error", "") or "",
    )
    return result


def apply_proposal(proposal_id: str) -> dict:
    """Execute a proposal a human approved.

    Bypasses `authorise` deliberately - the approval *is* the authorisation, and
    re-running the gate would either double-count the rate limit or refuse the
    very action just approved. The audit trail records both halves.
    """
    control = get_control()
    proposal = control.get_proposal(proposal_id)
    if not proposal:
        return {"error": "No such proposal."}
    if proposal.status != "pending":
        return {"error": f"Proposal is already {proposal.status}."}

    implementation = TOOL_IMPLEMENTATIONS.get(proposal.tool)
    if not implementation:
        return {"error": f"No such tool: {proposal.tool}"}

    started = time.perf_counter()
    try:
        result = implementation(proposal.arguments)
    except Exception as exc:
        logger.exception("Approved proposal %s failed", proposal_id)
        control.record(
            proposal.tool, "error", arguments=proposal.arguments, mutating=True,
            detail=f"{exc.__class__.__name__}: {exc}",
        )
        return {"error": f"{proposal.tool} failed: {exc}"}

    control.resolve(proposal_id, "approved", result)
    control.record(
        proposal.tool, "allowed", arguments=proposal.arguments, mutating=True,
        duration_ms=round((time.perf_counter() - started) * 1000),
        assets_affected=result.get("migrated", 0),
        detail=f"Applied approved proposal {proposal_id}.",
    )
    return result


def reject_proposal(proposal_id: str) -> dict:
    control = get_control()
    proposal = control.get_proposal(proposal_id)
    if not proposal:
        return {"error": "No such proposal."}
    if proposal.status != "pending":
        return {"error": f"Proposal is already {proposal.status}."}
    control.resolve(proposal_id, "rejected")
    return {"status": "rejected", "proposal_id": proposal_id}


# --------------------------------------------------------------------------
# The chat loop
# --------------------------------------------------------------------------


def _estate_preamble() -> str:
    """Tell the model what it is looking at before it asks.

    Without this the first turn of every conversation is a tool call to find out
    whether an estate exists at all, which is a wasted round trip on a local
    model that takes ten seconds to produce one.
    """
    state = _state()
    if not state.assets:
        return (
            "CURRENT STATE: no estate is loaded. Tell the user to load the demo "
            "estate, run a TLS scan, or import a CBOM from the Scanner page before "
            "asking for analysis."
        )
    vulnerable = sum(1 for a in state.assets if a.quantum_vulnerable)
    behind = sum(1 for a in state.assets if a.slack_months < 0)
    control = get_control()
    return (
        f"CURRENT STATE: {len(state.assets)} assets scored, {vulnerable} "
        f"quantum-vulnerable, {behind} cannot meet their statutory deadline. Sector "
        f"track: {state.org_persona}. Scan taken {state.scan_timestamp or 'unknown'}. "
        f"Your control mode is '{control.settings.mode}'"
        + (
            " - you can read and explain but not change anything."
            if control.settings.mode == "read_only"
            else " - a migration you request needs human approval before it applies."
            if control.settings.mode == "approval"
            else " - a migration you request applies immediately."
        )
    )


def _tool_call_emitted_as_text(reply: dict) -> dict | None:
    """A tool call the model typed into its answer instead of calling.

    Small models do this under pressure, and the result reaches the dashboard as
    a raw JSON blob where an answer should be - asked "who are you?",
    llama3.1:8b replied with the literal text {"name": "explain_self",
    "parameters": {}}, inventing a tool that does not exist.

    Returns {"call": ...} when the blob names a real tool, so the turn can be
    recovered instead of wasted; {"unknown": name} when it does not, so the loop
    can correct the model rather than print its mistake at a CISO. None when the
    content is an ordinary answer.

    This is the same boundary and the same reasoning as _coerce_arguments in
    engine.llm_bridge: normalise provider misbehaviour once, here, so the rest
    of the loop never has to think about it.
    """
    if reply.get("tool_calls"):
        return None
    content = (reply.get("content") or "").strip()
    if not (content.startswith("{") and content.endswith("}")):
        return None
    try:
        blob = json.loads(content)
    except json.JSONDecodeError:
        return None
    if not isinstance(blob, dict):
        return None

    function = blob.get("function") if isinstance(blob.get("function"), dict) else blob
    name = function.get("name")
    if not isinstance(name, str) or not name:
        return None

    if name not in TOOL_IMPLEMENTATIONS:
        return {"unknown": name}

    raw = function.get("arguments")
    if raw is None:
        raw = function.get("parameters")
    arguments = raw if isinstance(raw, dict) else {}
    return {"call": {"id": "call_recovered", "name": name, "arguments": arguments}}


def control_payload() -> dict:
    """Control state plus the model that will serve the next turn.

    One shape, built in one place, because /agent/status and every chat
    response both hand this to the same dashboard object. They used to be
    assembled separately and the chat response omitted `llm`: the dashboard
    replaces its control state wholesale from each turn, so after the first
    message it lost the model and rendered "No language model is configured"
    directly underneath an answer the model had just produced.
    """
    from engine import ntro_mode

    config = get_config()
    return {
        **get_control().status(),
        "llm": {
            "is_configured": config.is_configured,
            "provider": config.provider,
            "model": config.model,
            "verified": config.verified,
        },
        "router": router_enabled(),
        "ntro": ntro_mode.status(),
    }


def router_enabled() -> bool:
    """The deterministic router is on unless VERA_AGENT_ROUTER=0 (the benchmark's LLM-only arm)."""
    return os.environ.get("VERA_AGENT_ROUTER", "1") != "0"


def _route(messages: list[dict]):
    """The router's decision for the newest user message, or None."""
    from engine import agent_router

    return agent_router.route_conversation(messages, _assets())


async def process_chat_events(messages: list[dict], *, use_router: bool | None = None):
    """Run one chat turn, yielding each step as it happens.

    WHY A GENERATOR
    ---------------
    A turn against a free gateway can take most of the 180s budget, and the
    dashboard used to see nothing until all of it had elapsed - including the
    navigation the agent had already asked for thirty seconds earlier. Yielding
    each tool call and result as it occurs lets the operator watch the agent
    work and lets the UI act on a directive the moment it is issued.

    Event shapes:
        {"type": "tool_call",   "name", "arguments"}
        {"type": "tool_result", "name", "message", "result"}
        {"type": "message",     "message"}          assistant prose or thinking
        {"type": "routed",      "route"}            the deterministic router chose the tool
        {"type": "done",        "payload"}          the full non-streaming reply

    ROUTER FIRST
    ------------
    engine.agent_router reads the newest user message before the model does.
    When the verb names the tool ("migrate X", "show drift"), the router picks
    it and resolves the asset; the call still goes through execute_tool and the
    control plane, and the model is only asked to phrase the result. When the
    asset is ambiguous, the turn ends with a question listing the candidates.
    With no model configured, a routed request is still answered, from the tool
    result alone.

    `process_chat` below drains this and returns the final payload, so the
    streaming and non-streaming paths are the same code and cannot drift.
    """
    from engine import agent_router

    control = get_control()
    config = get_config()
    started = time.perf_counter()
    routed = _route(messages) if (router_enabled() if use_router is None else use_router) else None
    router_meta = {"kind": routed.kind, "rule": routed.rule, "tool": routed.tool} if routed else None

    if routed is not None:
        yield {"type": "routed", "route": routed.to_dict()}
    if routed is not None and routed.kind == "clarify":
        reply = {"role": "assistant", "content": routed.question}
        yield {"type": "message", "message": reply}
        yield {"type": "done", "payload": {
            "messages": [m for m in messages if m.get("role") != "system"] + [reply],
            "meta": {"router": router_meta, "iterations": 0,
                     "elapsed_ms": round((time.perf_counter() - started) * 1000)},
            "control": control_payload(),
            "proposals": control.pending_proposals(),
            "error": None,
        }}
        return

    routed_messages: list[dict] = []
    if routed is not None:
        call = {"id": "call_router", "name": routed.tool, "arguments": routed.arguments}
        yield {"type": "tool_call", "name": routed.tool, "arguments": routed.arguments}
        result = execute_tool(routed.tool, routed.arguments)
        tool_message = {"role": "tool", "tool_call_id": call["id"], "name": routed.tool,
                        "content": json.dumps(result, default=str)}
        routed_messages = [{"role": "assistant", "content": "", "tool_calls": [call]}, tool_message]
        yield {"type": "tool_result", "name": routed.tool, "message": tool_message, "result": result}
        if not config.is_configured:
            reply = {"role": "assistant", "content": agent_router.describe(routed, result)}
            yield {"type": "message", "message": reply}
            yield {"type": "done", "payload": {
                "messages": [m for m in messages if m.get("role") != "system"] + routed_messages + [reply],
                "meta": {"router": router_meta, "iterations": 0, "llm": None,
                         "elapsed_ms": round((time.perf_counter() - started) * 1000)},
                "control": control_payload(),
                "proposals": control.pending_proposals(),
                "error": None,
            }}
            return

    if not config.is_configured:
        yield {"type": "done", "payload": {
            "messages": list(messages) + [{
                "role": "assistant",
                "content": (
                    "No language model is configured, so I cannot answer yet. Open "
                    "Settings, choose a provider (Ollama for a local model, or "
                    "OpenAI/Anthropic with an API key), click Load models, pick one "
                    "and save. Everything else in VERA works without me."
                ),
            }],
            "error": {
                "error": "No language model is configured.",
                "remedy": "Configure a provider in Settings.",
                "code": "not_configured",
            },
            "control": control_payload(),
            "proposals": control.pending_proposals(),
        }}
        return

    # The system prompt and the estate preamble are rebuilt every turn rather
    # than stored in the transcript: the estate changes under the conversation,
    # and a stale preamble is worse than none.
    working = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "system", "content": _estate_preamble()},
    ] + [m for m in messages if m.get("role") != "system"] + routed_messages
    if routed_messages:
        working.append({
            "role": "system",
            "content": (
                f"{routed.tool} has already been run for this request and its result is above. "
                "Answer the user from that result. Call another tool only if the question needs "
                "a figure the result does not contain."
            ),
        })

    transcript: list[dict] = list(routed_messages)
    iterations = 0
    meta: dict = {}
    error: dict | None = None

    while iterations < control.settings.max_iterations_per_turn:
        iterations += 1

        if time.perf_counter() - started > control.settings.turn_timeout_seconds:
            transcript.append({
                "role": "assistant",
                "content": (
                    "I ran out of time on this turn. The model is responding slowly - "
                    "try a smaller model, or ask a narrower question."
                ),
            })
            error = {"error": "Turn timed out.", "code": "timeout"}
            break

        try:
            reply = await chat(working, tools=available_tools())
        except LLMError as exc:
            transcript.append({
                "role": "assistant",
                "content": f"I could not reach the language model. {exc.message}"
                           + (f" {exc.remedy}" if exc.remedy else ""),
            })
            error = {**exc.to_dict(), "code": "llm_error"}
            break

        meta = reply.pop("_meta", meta)

        # A model that typed its tool call instead of making one. Recover it
        # where the tool is real, correct the model where it invented one, and
        # in neither case let the raw JSON reach the transcript.
        typed = _tool_call_emitted_as_text(reply)
        if typed and "call" in typed:
            reply = {"role": "assistant", "content": "", "tool_calls": [typed["call"]]}
        elif typed:
            working.append({
                "role": "system",
                "content": (
                    f"There is no tool named {typed['unknown']!r}, and a tool call "
                    f"belongs in the tool-call field, never in your message text. "
                    f"Answer the user directly, in prose."
                ),
            })
            continue

        transcript.append(reply)
        yield {"type": "message", "message": reply}
        # The operator sees the scratchpad; the model does not get it back. A
        # reasoning model re-derives its thinking each turn, so feeding the old
        # one in spends context to no effect - and on a small local model that
        # context is the scarce resource.
        working.append({k: v for k, v in reply.items() if k != "thinking"})

        tool_calls = reply.get("tool_calls")
        if not tool_calls:
            break  # a plain text answer ends the turn

        for call in tool_calls:
            name = call.get("name", "")
            arguments = call.get("arguments") or {}
            # Announced before it runs, so a slow tool is visibly running
            # rather than indistinguishable from a hung turn.
            yield {"type": "tool_call", "name": name, "arguments": arguments}

            result = execute_tool(name, arguments)
            message = {
                "role": "tool",
                "tool_call_id": call.get("id", ""),
                "name": name,
                "content": json.dumps(result, default=str),
            }
            working.append(message)
            transcript.append(message)
            # The UI acts on this immediately - a navigation directive should
            # move the page now, not once the model finishes writing prose.
            yield {"type": "tool_result", "name": name,
                   "message": message, "result": result}
    else:
        # Loop exhausted without a text answer: say so rather than returning a
        # transcript that ends mid-thought.
        transcript.append({
            "role": "assistant",
            "content": (
                f"I used my {control.settings.max_iterations_per_turn}-step budget for "
                f"this turn without reaching a conclusion. Ask me something more "
                f"specific, or raise the step budget in Settings."
            ),
        })
        error = {"error": "Iteration budget exhausted.", "code": "iteration_budget"}

    yield {
        "type": "done",
        "payload": {
            "messages": [m for m in messages if m.get("role") != "system"] + transcript,
            "meta": {
                **meta,
                "router": router_meta,
                "iterations": iterations,
                "elapsed_ms": round((time.perf_counter() - started) * 1000),
            },
            "control": control_payload(),
            "proposals": control.pending_proposals(),
            "error": error,
        },
    }


async def process_chat(messages: list[dict], *, use_router: bool | None = None) -> dict:
    """Run one chat turn to completion.

    Drains `process_chat_events` and returns its final payload, so the
    streaming endpoint and this one execute identical logic. Callers that do
    not want intermediate events use this.
    """
    payload: dict = {}
    async for event in process_chat_events(messages, use_router=use_router):
        if event.get("type") == "done":
            payload = event["payload"]
    return payload
