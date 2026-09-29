"""Tool-selection accuracy and latency of the agent: the model alone vs router + model.

    python bench/agent_bench.py [--model qwen3:1.7b] [--repeats 3]  ->  bench/agent_results.json

WHAT IS MEASURED
----------------
Every prompt in bench/agent_prompts.yaml is run as a real agent turn
(engine.agent.process_chat_events) against the scored demo estate, in two arms:

    llm_only     the router is off; the model sees the prompt and every tool schema
    router_llm   engine.agent_router decides first; unmatched prompts go to the model

A turn is scored on its **first decision**: the first tool it calls, a
clarifying question from the router, or a plain answer ("none"). The decision is
correct when it is in the prompt's `expect` list and, where the prompt names an
asset, the call's `asset_id` resolves to that asset. `turn_correct` also credits
a turn whose *later* call is right (a model that lists assets, then explains the
right one), and is reported separately.

Latency is wall time from the start of the turn to that first decision
("selection") and to the end of the turn ("turn"). Medians are per arm. The
model is warmed with one untimed call first, because the first call loads it.

The agent runs in approval mode so both write tools are in the schema; a
migration is only ever proposed. Scans, the audit chain and the model-health
registry go to a temporary directory, never to backend/data. The fresh health
registry also means the bridge has no probed fallback models, so every answer
comes from the named model; each turn records the model that answered, and a
turn that failed over would be reported, not hidden.

Nothing is estimated. If the model cannot be reached, the script exits without
writing a result file.
"""

from __future__ import annotations

import argparse
import asyncio
import datetime as dt
import hashlib
import json
import os
import platform
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
BACKEND = ROOT / "backend"
ESTATE = ROOT / "demo" / "estate" / "estate.yaml"
ARMS = ("llm_only", "router_llm")


def _prepare_environment(workdir: Path) -> None:
    """Before the backend is imported: throwaway stores, no thinking, router on by default."""
    os.environ["VERA_DB_PATH"] = str(workdir / "bench.db")
    os.environ["VERA_AUDIT_DB"] = str(workdir / "audit_chain.db")
    os.environ["VERA_LLM_THINKING"] = "0"
    sys.path.insert(0, str(BACKEND))
    os.chdir(BACKEND)


def _expected_asset(spec, assets):
    if spec is None:
        return None
    if isinstance(spec, dict):
        return lambda a: a is not None and a.priority_rank == int(spec["rank"])
    needle = str(spec).lower()
    return lambda a: a is not None and needle in (a.name or "").lower()


def _call_ok(call: dict, prompt: dict, agent) -> bool:
    if call["name"] not in prompt["expect"]:
        return False
    check = _expected_asset(prompt.get("asset"), agent._assets())
    if check is None:
        return True
    return check(agent._find(str((call.get("arguments") or {}).get("asset_id") or "")))


async def _run_turn(prompt: dict, arm: str, agent) -> dict:
    started = time.perf_counter()
    decision, selection_ms, calls, router, final, error, meta = None, None, [], None, "", None, {}
    async for event in agent.process_chat_events([{"role": "user", "content": prompt["text"]}],
                                                 use_router=(arm == "router_llm")):
        elapsed = round((time.perf_counter() - started) * 1000)
        kind = event["type"]
        if kind == "routed":
            router = {k: event["route"][k] for k in ("kind", "rule", "tool")}
            if event["route"]["kind"] == "clarify" and decision is None:
                decision, selection_ms = "clarify", elapsed
        elif kind == "tool_call":
            calls.append({"name": event["name"], "arguments": event["arguments"]})
            if decision is None:
                decision, selection_ms = event["name"], elapsed
        elif kind == "message":
            message = event["message"]
            if not message.get("tool_calls") and (message.get("content") or "").strip():
                final = message["content"].strip()
                if decision is None:
                    decision, selection_ms = "none", elapsed
        elif kind == "done":
            error = (event["payload"].get("error") or {}).get("code")
            meta = event["payload"].get("meta") or {}
    turn_ms = round((time.perf_counter() - started) * 1000)

    first_ok = decision in prompt["expect"] and (
        decision in ("none", "clarify") or _call_ok(calls[0], prompt, agent))
    turn_ok = first_ok or any(_call_ok(c, prompt, agent) for c in calls)
    return {"decision": decision or "no_decision", "first_correct": bool(first_ok), "turn_correct": bool(turn_ok),
            "selection_ms": selection_ms, "turn_ms": turn_ms, "router": router, "calls": calls,
            "answered_by": meta.get("model"), "failed_over_from": meta.get("failed_over_from") or [],
            "iterations": meta.get("iterations"), "answer": final[:240], "error": error}


def _summarise(rows: list[dict], prompts: list[dict]) -> dict:
    groups = sorted({p["group"] for p in prompts})
    by_id = {p["id"]: p for p in prompts}

    def rate(items, key):
        return round(sum(1 for r in items if r[key]) / len(items), 3) if items else None

    selections = [r["selection_ms"] for r in rows if r["selection_ms"] is not None]
    return {
        "runs": len(rows),
        "first_decision_accuracy": rate(rows, "first_correct"),
        "turn_accuracy": rate(rows, "turn_correct"),
        "median_selection_ms": round(statistics.median(selections)) if selections else None,
        "median_turn_ms": round(statistics.median(r["turn_ms"] for r in rows)) if rows else None,
        "routed": sum(1 for r in rows if r["router"]),
        "answered_by": sorted({r["answered_by"] for r in rows if r["answered_by"]}),
        "failovers": sum(1 for r in rows if r["failed_over_from"]),
        "by_group": {g: rate([r for r in rows if by_id[r["id"]]["group"] == g], "first_correct") for g in groups},
        "errors": sorted({r["error"] for r in rows if r["error"]}),
    }


def _attribute(per_prompt: list[dict]) -> tuple[list[str], list[str], list[str]]:
    """Which differences between the arms the router caused.

    A prompt the router did not match is sent to the model identically in both
    arms, so any difference there is the model sampling, not the router.
    """
    fixed, broken, variance = [], [], []
    for p in per_prompt:
        a, b = p["llm_only"]["first_correct"], p["router_llm"]["first_correct"]
        if a == b:
            continue
        if p["router_llm"]["router_rule"] is None:
            variance.append(p["id"])
        else:
            (fixed if b > a else broken).append(p["id"])
    return fixed, broken, variance


def _git_commit() -> str | None:
    try:
        return subprocess.run(["git", "-C", str(ROOT), "rev-parse", "HEAD"], capture_output=True, text=True,
                              check=True, timeout=10).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--model", default="qwen3:1.7b")
    parser.add_argument("--base-url", default="http://localhost:11434")
    parser.add_argument("--repeats", type=int, default=3, help="runs of each prompt per arm (the model samples)")
    parser.add_argument("--prompts", default=str(HERE / "agent_prompts.yaml"))
    parser.add_argument("--out", default=str(HERE / "agent_results.json"))
    args = parser.parse_args(argv)

    workdir = Path(tempfile.mkdtemp(prefix="vera-agent-bench-"))
    _prepare_environment(workdir)

    import httpx
    import yaml
    from fastapi.testclient import TestClient

    from engine import agent, llm_bridge
    from engine.agent_control import get_control
    from engine.core import agents as agent_pool
    from engine.core import model_health
    from main import app

    isolated = model_health.ModelRegistry(workdir / "model_health.json")
    model_health.REGISTRY = agent_pool._MODELS = llm_bridge._MODELS = isolated

    prompts_text = Path(args.prompts).read_text(encoding="utf-8")
    prompts = yaml.safe_load(prompts_text)["prompts"]

    try:
        tags = httpx.get(f"{args.base_url}/api/tags", timeout=10).json()
    except (httpx.HTTPError, ValueError) as exc:
        print(f"Model server not reachable at {args.base_url}: {exc}. No results written.")
        return 1
    model_info = next((m for m in tags.get("models", []) if m["name"] == args.model), None)
    if model_info is None:
        print(f"{args.model} is not pulled on {args.base_url}. No results written.")
        return 1

    config = llm_bridge.get_config()
    config.update(provider="ollama", model=args.model, base_url=args.base_url, show_thinking=False)
    client = TestClient(app)

    def load_estate() -> None:
        body = client.post("/api/scan/full", json={"estate": str(ESTATE), "wait": True}).json()
        if body.get("status") != "done":
            raise SystemExit(f"demo estate scan failed: {body}")

    load_estate()
    load_estate()  # two stored scans, so compare_scans has something to compare

    control = get_control()

    def reset_control() -> None:
        control.reset()
        control.update_settings(mode="approval", max_tool_calls_per_minute=240, max_iterations_per_turn=6,
                                 max_assets_per_action=25, turn_timeout_seconds=180)

    reset_control()
    warm_started = time.perf_counter()
    asyncio.run(llm_bridge.chat([{"role": "user", "content": "Reply with the word ready."}]))
    warmup_ms = round((time.perf_counter() - warm_started) * 1000)

    rows: dict[str, list[dict]] = {arm: [] for arm in ARMS}
    for repeat in range(args.repeats):
        for prompt in prompts:
            for arm in ARMS:
                reset_control()
                row = asyncio.run(_run_turn(prompt, arm, agent))
                rows[arm].append({"id": prompt["id"], "repeat": repeat, **row})
                print(f"[{repeat}] {arm:10} {prompt['id']:22} -> {row['decision']:22} "
                      f"{'ok ' if row['first_correct'] else 'BAD'} {row['selection_ms']} ms "
                      f"turn {row['turn_ms']} ms {row['error'] or ''}", flush=True)
                if any(c["name"] == "run_scan" for c in row["calls"]):
                    load_estate()  # a surface-limited rescan replaced the estate; restore it

    per_prompt = []
    for prompt in prompts:
        entry = {"id": prompt["id"], "group": prompt["group"], "text": prompt["text"], "expect": prompt["expect"]}
        for arm in ARMS:
            mine = [r for r in rows[arm] if r["id"] == prompt["id"]]
            entry[arm] = {"first_correct": sum(r["first_correct"] for r in mine), "of": len(mine),
                          "decisions": [r["decision"] for r in mine],
                          "router_rule": (mine[0]["router"] or {}).get("rule") if mine else None}
        per_prompt.append(entry)

    fixed, broken, variance = _attribute(per_prompt)
    result = {
        "measured": True,
        "measured_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "what": "Agent tool selection on bench/agent_prompts.yaml against demo/estate: model alone vs router + model.",
        "model": {"name": args.model, "digest": model_info.get("digest"), "details": model_info.get("details"),
                  "server": args.base_url, "temperature": config.temperature, "thinking": False,
                  "warmup_ms": warmup_ms},
        "host": {"platform": platform.platform(), "python": platform.python_version(),
                 "processor": platform.processor()},
        "git_commit": _git_commit(),
        "prompts": {"file": "bench/agent_prompts.yaml", "count": len(prompts),
                    "sha256": hashlib.sha256(prompts_text.encode("utf-8")).hexdigest()},
        "repeats": args.repeats,
        "scoring": ("first_decision_accuracy: the first tool called (or 'none' / 'clarify') is in the prompt's "
                    "expect list and, where given, its asset_id resolves to the named asset. turn_accuracy: any "
                    "call in the turn satisfies that. Latency: wall time to the first decision and to turn end."),
        "caveat": ("The prompts were written by the authors of the router's patterns; they are not a held-out set. "
                   "The 'natural' group holds phrasings the patterns do not cover. The model samples at the "
                   "temperature above, so model-side results vary between runs; the router's are deterministic."),
        "summary": {arm: _summarise(rows[arm], prompts) for arm in ARMS},
        "router_fixed": fixed,
        "router_regressed": broken,
        "unrouted_model_variance": variance,
        "per_prompt": per_prompt,
        "runs": rows,
    }
    Path(args.out).write_text(json.dumps(result, indent=2, default=str) + "\n", encoding="utf-8")
    for arm in ARMS:
        s = result["summary"][arm]
        print(f"{arm:10}: first-decision {s['first_decision_accuracy']:.1%}, turn {s['turn_accuracy']:.1%}, "
              f"median selection {s['median_selection_ms']} ms, median turn {s['median_turn_ms']} ms")
    print(f"router fixed {fixed}; regressed {broken}; model variance on unrouted prompts {variance}")
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
