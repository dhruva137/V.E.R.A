"""WP10: the agent's new tools, its router in the chat loop, and the three guardrail demos.

Runs on the full demo estate (demo/estate), because drift, vendor gating and
the signed manifest only exist after a full scan. No model is configured, so
every turn here takes the router's deterministic path; the model-dependent
half is measured by bench/agent_bench.py, not asserted here.
"""

from __future__ import annotations

import asyncio
import socket
import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from api.routes import state
from engine import agent, audit_chain, llm_bridge, ntro_mode, offline
from engine.agent_control import WRITE_TOOLS, ControlSettings, get_control
from main import app

ESTATE = Path(__file__).resolve().parents[2] / "demo" / "estate" / "estate.yaml"


@pytest.fixture(scope="module")
def client():
    client = TestClient(app)
    body = client.post("/api/scan/full", json={"estate": str(ESTATE), "wait": True}).json()
    assert body["status"] == "done", body
    return client


@pytest.fixture(autouse=True)
def no_model_and_approval_mode(client, monkeypatch):
    """Pin every turn to the model-free path, with a clean control plane."""
    monkeypatch.setattr(llm_bridge, "_config", llm_bridge.LLMConfig())
    llm_bridge._config.update(provider="", model="", base_url="", api_key="")
    control = get_control()
    control.reset()
    control.update_settings(mode="approval", max_tool_calls_per_minute=200, max_assets_per_action=25)
    yield
    control.reset()


def _turn(text: str, history: list[dict] | None = None) -> dict:
    return asyncio.run(agent.process_chat([*(history or []), {"role": "user", "content": text}]))


def _top_vulnerable():
    return min((a for a in state.assets if a.quantum_vulnerable), key=lambda a: a.priority_rank)


# --------------------------------------------------------------------------
# The new tools answer from the engine
# --------------------------------------------------------------------------


def test_new_read_tools_answer_on_the_full_estate():
    asset = _top_vulnerable()
    for name, args in {
        "explain_mosca": {"asset_id": asset.id},
        "list_drift": {"limit": 3},
        "list_vendor_gated": {},
        "recommend": {"asset_id": asset.id, "profile": "cnsa"},
        "verify_manifest": {},
    }.items():
        result = agent.execute_tool(name, args)
        assert "error" not in result, f"{name}: {result.get('error')}"


def test_explain_mosca_carries_the_numbers_and_their_source():
    asset = _top_vulnerable()
    result = agent.execute_tool("explain_mosca", {"asset_id": asset.id})
    assert result["applicable"] is True
    assert set(result["z_years"]) == {"pessimistic", "median", "optimistic"}
    assert result["threat_model_version"]
    assert result["z_shift_basis"]
    assert result["margin_years"] is not None


def test_list_drift_matches_the_drift_endpoint(client):
    endpoint = client.get("/api/drift").json()
    tool = agent.execute_tool("list_drift", {"limit": 40})
    assert tool["summary"]["total"] == endpoint["summary"]["total"] == len(state.drift)
    assert {r["rule"] for r in tool["records"]} <= {r["rule"] for r in endpoint["records"]}
    only_d8 = agent.execute_tool("list_drift", {"rule": "D8"})
    assert only_d8["matching"] >= 1 and {r["rule"] for r in only_d8["records"]} == {"D8"}


def test_vendor_gated_and_recommend_agree_with_the_recommendations_api(client):
    gated = agent.execute_tool("list_vendor_gated", {})
    assert gated["assets_gated"] == sum(g["count"] for g in client.get("/api/vendor-gated").json()["register"])
    asset = _top_vulnerable()
    assert (agent.execute_tool("recommend", {"asset_id": asset.id})["recommended"]
            == client.get(f"/api/recommendations/{asset.id}").json()["recommended"])


def test_compare_scans_needs_two_scans_and_then_reports_the_delta(client):
    client.post("/api/scan/full", json={"estate": str(ESTATE), "wait": True})
    result = agent.execute_tool("compare_scans", {})
    assert "error" not in result, result
    assert result["to"]["scan_id"] == state.scan_id
    assert result["overlap"] > 0.9  # the same estate twice


def test_run_scan_is_scoped_and_read_only(client):
    refused = [
        agent.execute_tool("run_scan", {"targets": [{"kind": "path", "value": "C:/Windows"}]}),
        agent.execute_tool("run_scan", {"targets": [{"kind": "repo", "value": "https://example.com/x.git"}]}),
        agent.execute_tool("run_scan", {"targets": [{"kind": "host", "value": "example.com:443"}]}),
        agent.execute_tool("run_scan", {"surfaces": ["tls"]}),
        agent.execute_tool("run_scan", {"surfaces": ["nonsense"]}),
    ]
    assert all("error" in r for r in refused), refused
    assert "run_scan" not in WRITE_TOOLS

    result = agent.execute_tool("run_scan", {"surfaces": ["config"]})
    assert result["status"] == "done", result
    assert set(result["findings_by_surface"]) == {"config"}
    assert not result["collector_failures"]
    # Leave the module's estate as the other tests expect it.
    client.post("/api/scan/full", json={"estate": str(ESTATE), "wait": True})


# --------------------------------------------------------------------------
# The router in the chat loop
# --------------------------------------------------------------------------


def test_a_routed_turn_answers_without_a_model_and_says_it_was_routed():
    payload = _turn("show me the drift")
    assert payload["meta"]["router"] == {"kind": "tool", "rule": "drift.list", "tool": "list_drift"}
    tool_messages = [m for m in payload["messages"] if m["role"] == "tool"]
    assert [m["name"] for m in tool_messages] == ["list_drift"]
    assert f"found {len(state.drift)} in all" in payload["messages"][-1]["content"]


def test_an_ambiguous_turn_asks_and_calls_nothing():
    payload = _turn("migrate CardVault.java")
    assert payload["meta"]["router"]["kind"] == "clarify"
    assert not [m for m in payload["messages"] if m["role"] == "tool"]
    assert "Which one do you mean?" in payload["messages"][-1]["content"]
    assert get_control().pending_proposals() == []

    picked = _turn("1", history=payload["messages"])
    assert picked["meta"]["router"]["rule"] == "migrate.asset.picked"
    assert len(get_control().pending_proposals()) == 1


def test_the_router_can_be_switched_off():
    payload = asyncio.run(agent.process_chat([{"role": "user", "content": "show me the drift"}], use_router=False))
    assert payload["error"]["code"] == "not_configured"
    assert not [m for m in payload["messages"] if m["role"] == "tool"]


# --------------------------------------------------------------------------
# Guardrail demos
# --------------------------------------------------------------------------


def test_demo_1_read_only_hides_write_tools_and_refuses_a_routed_migration():
    control = get_control()
    control.update_settings(mode="read_only")
    offered = {t["function"]["name"] for t in agent.available_tools()}
    assert not offered & WRITE_TOOLS

    asset = _top_vulnerable()
    before = asset.qirs
    payload = _turn(f"migrate {asset.id}")
    result = [m for m in payload["messages"] if m["role"] == "tool"][0]
    assert "read-only" in result["content"]
    assert asset.qirs == before
    assert control.audit[0].outcome == "refused"


def test_demo_2_a_200_asset_migration_is_refused_by_the_blast_radius_cap():
    vulnerable = sum(1 for a in state.assets if a.quantum_vulnerable)
    assert vulnerable > get_control().settings.max_assets_per_action
    payload = _turn("migrate 200 assets")
    assert payload["meta"]["router"]["tool"] == "migrate_asset"
    assert "cap" in payload["messages"][-1]["content"] or "limit" in payload["messages"][-1]["content"]
    assert sum(1 for a in state.assets if a.quantum_vulnerable) == vulnerable
    assert get_control().pending_proposals() == []

    refusal = get_control().audit[0]
    assert (refusal.tool, refusal.outcome) == ("migrate_asset", "refused")
    chained = [e for e in audit_chain.default().entries() if e["kind"] == "agent" and e["action"] == "migrate_asset"]
    assert chained and chained[-1]["detail"]["outcome"] == "refused"


def test_demo_3_audit_tamper_is_reported_with_the_broken_index():
    chain = audit_chain.default()
    for i in range(3):
        chain.append("export", "cbom", {"n": i})
    victim = chain.entries()[1]["idx"]
    db = sqlite3.connect(chain.path)
    db.execute("DROP TRIGGER audit_chain_no_update")
    db.execute("UPDATE audit_chain SET detail = '{\"n\": 99}' WHERE idx = ?", (victim,))
    db.commit()
    db.close()

    payload = _turn("has the audit log been tampered with?")
    result = [m for m in payload["messages"] if m["role"] == "tool"][0]
    assert '"first_broken": ' + str(victim) in result["content"]
    assert f"BROKEN at entry {victim}" in payload["messages"][-1]["content"]


# --------------------------------------------------------------------------
# NTRO mode and the offline guard
# --------------------------------------------------------------------------


def test_ntro_defaults_fill_only_what_is_unset():
    env: dict[str, str] = {}
    filled = ntro_mode.apply_defaults(env)
    assert env["VERA_AGENT_MODE"] == "read_only" and env["VERA_OFFLINE"] == "1"
    assert (env["VERA_LLM_PROVIDER"], env["VERA_LLM_MODEL"]) == ("ollama", "qwen3:1.7b")
    assert env["VERA_LLM_THINKING"] == "0" and len(filled) == 5

    cloud = {"VERA_LLM_API_KEY": "sk-test", "VERA_AGENT_MODE": "approval"}
    ntro_mode.apply_defaults(cloud)
    assert "VERA_LLM_PROVIDER" not in cloud and cloud["VERA_AGENT_MODE"] == "approval"


def test_the_agent_starts_read_only_unless_told_otherwise(monkeypatch):
    monkeypatch.delenv("VERA_AGENT_MODE", raising=False)
    assert ControlSettings().mode == "read_only"
    monkeypatch.setenv("VERA_AGENT_MODE", "approval")
    assert ControlSettings().mode == "approval"
    monkeypatch.setenv("VERA_AGENT_MODE", "yolo")
    assert ControlSettings().mode == "read_only"


def test_ntro_status_reports_what_is_in_force(client):
    get_control().update_settings(mode="read_only")
    llm_bridge._config.update(provider="ollama", model="qwen3:1.7b", base_url="http://localhost:11434")
    status = client.get("/api/ntro-mode").json()
    facts = {f["key"]: f["ok"] for f in status["facts"]}
    assert facts["agent"] and facts["model"]
    assert facts["offline"] is offline.enforced()
    assert status["ntro_mode"] is all(facts.values())

    llm_bridge._config.update(provider="openai", model="gpt-x", base_url="https://api.openai.com/v1", api_key="k")
    assert "leaves this machine" in ntro_mode.status()["facts"][1]["label"]


@pytest.fixture
def guard(monkeypatch):
    monkeypatch.setenv("VERA_OFFLINE", "1")
    assert offline.install()
    yield
    offline.uninstall()


def test_offline_guard_blocks_egress_but_not_loopback(guard):
    with pytest.raises(offline.OfflineBlocked, match="VERA_OFFLINE=1 blocked"):
        socket.create_connection(("203.0.113.7", 443), timeout=1)
    with pytest.raises(offline.OfflineBlocked):
        socket.getaddrinfo("example.com", 443)

    async def dial():
        await asyncio.open_connection("203.0.113.7", 443)

    with pytest.raises(offline.OfflineBlocked):
        asyncio.run(dial())

    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    try:
        socket.create_connection(server.getsockname(), timeout=2).close()
    finally:
        server.close()
    assert offline.status()["recently_blocked"]


def test_offline_guard_lets_an_operator_named_target_through(guard):
    offline.allow("203.0.113.9")
    assert offline.permitted("203.0.113.9")
    assert not offline.permitted("203.0.113.10")


def test_offline_guard_is_off_unless_requested(monkeypatch):
    monkeypatch.delenv("VERA_OFFLINE", raising=False)
    assert offline.install() is False
    assert offline.status()["enforced"] is False


def test_offline_self_test_passes_and_names_each_check(monkeypatch):
    monkeypatch.setenv("VERA_OFFLINE", "1")
    try:
        results = offline.self_test()
    finally:
        offline.uninstall()
    assert len(results) == 6
    assert all(r["ok"] for r in results), results
