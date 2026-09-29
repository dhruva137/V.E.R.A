"""The agent, its control plane, and the provider adapters.

These tests exist because the agent is a write path into the system of record.
The scoring tests prove the numbers are right; these prove that nothing can
change them without passing the control plane and landing in the audit log.

No network is touched. The provider call is stubbed, which is the point: the
adapters are pure translation and can be verified without a model.
"""

from __future__ import annotations

import asyncio
import json

import pytest

from api.routes import run_demo_scan, state
from engine import agent, llm_bridge
from engine.agent_control import get_control


@pytest.fixture(autouse=True)
def estate():
    """A freshly scored estate and a clean control plane for every test."""
    run_demo_scan(org_persona="Banking")
    control = get_control()
    control.reset()
    control.update_settings(
        mode="approval", max_tool_calls_per_minute=200,
        max_iterations_per_turn=6, max_assets_per_action=25,
    )
    yield
    control.reset()


def worst_asset() -> dict:
    return agent.execute_tool("list_assets", {"sort_by": "qirs", "limit": 1})["assets"][0]


# --------------------------------------------------------------------------
# Read tools
# --------------------------------------------------------------------------


def test_every_read_tool_answers_from_the_engine():
    """No tool may fail on a scored estate, and none may return an error.

    A tool that errors is worse than a missing one: the model reports the error
    as fact and the user cannot tell it from a finding.
    """
    asset_id = worst_asset()["id"]
    calls = {
        "get_estate_summary": {},
        "list_assets": {"limit": 5},
        "get_asset": {"asset_id": asset_id},
        "explain_asset": {"asset_id": asset_id},
        "get_blast_radius": {"asset_id": asset_id},
        "list_most_depended_on": {"limit": 3},
        "get_axis_extremes": {"count": 3},
        "get_deadlines": {},
        "get_roadmap": {"limit": 3},
        "get_threat_timeline": {"years": [5, 10]},
        "get_analytics": {},
        "get_cbom_status": {},
        "get_sensitivity": {},
        "preview_migration": {"asset_id": asset_id},
        "get_connector_status": {},
        "get_engine_status": {},
        "explain_evidence": {"asset_id": asset_id},
        "list_flagged": {"limit": 3},
        "inspect_key": {"asset_id": asset_id},
        "verify_migration": {"asset_id": asset_id},
        "explain_mosca": {"asset_id": asset_id},
        "list_vendor_gated": {},
        "recommend": {"asset_id": asset_id},
        "verify_manifest": {},
    }
    # Tools that change what the estate contains are excluded here and covered
    # where they own their own estate. Calling them under approval mode would
    # only propose, not apply. The drift, scan-history and scan tools need a
    # full scan or two, so tests/test_agent_wp10.py covers them on demo/estate.
    state_changing = {
        "migrate_asset", "scan_key_vault", "open_page",
        "run_scan", "list_drift", "compare_scans",
    }
    assert set(calls) | state_changing == set(agent.TOOL_IMPLEMENTATIONS), (
        "a tool was added or renamed without being covered here"
    )
    for name, args in calls.items():
        result = agent.execute_tool(name, args)
        assert isinstance(result, dict), name
        assert "error" not in result, f"{name}: {result.get('error')}"


def test_tool_figures_match_the_engine():
    """The agent must not be able to disagree with the dashboard."""
    summary = agent.execute_tool("get_estate_summary", {})
    assert summary["total_assets"] == len(state.assets)
    assert summary["quantum_vulnerable"] == sum(
        1 for a in state.assets if a.quantum_vulnerable
    )

    top = agent.execute_tool("list_assets", {"sort_by": "qirs", "limit": 1})["assets"][0]
    engine_top = max(
        (a for a in state.assets if a.quantum_vulnerable), key=lambda a: a.qirs
    )
    assert top["id"] == engine_top.id
    assert top["qirs"] == pytest.approx(engine_top.qirs, abs=5e-4)


def test_blast_radius_matches_the_dependency_graph():
    from engine.dependencies import build_graph

    graph = build_graph(state.assets)
    hub = max(graph["nodes"], key=lambda n: n["dependents"])
    traced = agent.execute_tool("get_blast_radius", {"asset_id": hub["id"]})
    assert traced["transitive_dependents"] == hub["dependents"]
    assert traced["estate_size"] == graph["stats"]["nodes"]


def test_assets_resolve_by_name_as_well_as_id():
    """A model that has just been shown a list of names will use a name."""
    asset = worst_asset()
    by_name = agent.execute_tool("get_asset", {"asset_id": asset["name"]})
    assert by_name["id"] == asset["id"]


def test_unknown_asset_is_reported_not_guessed():
    result = agent.execute_tool("get_asset", {"asset_id": "no-such-asset-anywhere"})
    assert "error" in result


def test_unknown_tool_is_refused_and_logged():
    result = agent.execute_tool("drop_the_database", {})
    assert "error" in result
    assert any(e.tool == "drop_the_database" for e in get_control().audit)


# --------------------------------------------------------------------------
# Control plane
# --------------------------------------------------------------------------


def test_read_only_mode_hides_the_write_tool_entirely():
    """Removed from the schema, not refused on call.

    A model never told it can migrate does not spend a turn trying, and does not
    tell the user it is about to.
    """
    from engine.agent_control import WRITE_TOOLS

    control = get_control()
    control.update_settings(mode="read_only")

    offered = {t["function"]["name"] for t in agent.available_tools()}
    for write in WRITE_TOOLS:
        assert write not in offered
    assert len(offered) == len(agent.TOOLS_SCHEMA) - len(WRITE_TOOLS)

    result = agent.execute_tool("migrate_asset", {"asset_id": worst_asset()["id"]})
    assert result["refused_by"] == "control plane"


def test_read_only_mode_leaves_the_estate_untouched():
    control = get_control()
    control.update_settings(mode="read_only")
    asset = worst_asset()
    before = asset["qirs"]
    agent.execute_tool("migrate_asset", {"asset_id": asset["id"]})
    after = agent.execute_tool("get_asset", {"asset_id": asset["id"]})["qirs"]
    assert after == before


def test_approval_mode_proposes_without_mutating():
    asset = worst_asset()
    before = asset["qirs"]

    proposed = agent.execute_tool("migrate_asset", {"asset_id": asset["id"]})
    assert proposed["status"] == "awaiting_approval"
    assert proposed["assets_affected"] == 1
    # The preview carries what a human is actually approving.
    assert proposed["preview"]["changes"][0]["to"]

    unchanged = agent.execute_tool("get_asset", {"asset_id": asset["id"]})
    assert unchanged["qirs"] == before


def test_approving_a_proposal_applies_it_and_reduces_risk():
    asset = worst_asset()
    before = asset["qirs"]
    proposal_id = agent.execute_tool(
        "migrate_asset", {"asset_id": asset["id"]}
    )["proposal_id"]

    result = agent.apply_proposal(proposal_id)
    assert result["migrated"] == 1
    assert result["qirs_reduction"] > 0

    after = agent.execute_tool("get_asset", {"asset_id": asset["id"]})
    assert after["qirs"] < before
    # Committed through the shared path, so the estate is settled, not half-done.
    assert state.scan_id
    assert state.cbom_report["valid"]


def test_a_proposal_cannot_be_applied_twice():
    proposal_id = agent.execute_tool(
        "migrate_asset", {"asset_id": worst_asset()["id"]}
    )["proposal_id"]
    assert agent.apply_proposal(proposal_id)["migrated"] == 1
    assert "error" in agent.apply_proposal(proposal_id)


def test_rejecting_a_proposal_changes_nothing():
    asset = worst_asset()
    before = asset["qirs"]
    proposal_id = agent.execute_tool(
        "migrate_asset", {"asset_id": asset["id"]}
    )["proposal_id"]

    assert agent.reject_proposal(proposal_id)["status"] == "rejected"
    after = agent.execute_tool("get_asset", {"asset_id": asset["id"]})
    assert after["qirs"] == before
    assert get_control().pending_proposals() == []


def test_blast_radius_cap_stops_a_whole_estate_migration():
    """One call with an empty target matches everything. Rate limiting cannot
    catch that, which is why the cap exists separately."""
    control = get_control()
    control.update_settings(mode="autonomous", max_assets_per_action=5)

    vulnerable_before = sum(1 for a in state.assets if a.quantum_vulnerable)
    result = agent.execute_tool("migrate_asset", {"target": ""})

    assert result["refused_by"] == "control plane"
    assert sum(1 for a in state.assets if a.quantum_vulnerable) == vulnerable_before


def test_rate_limit_refuses_once_the_bucket_empties():
    control = get_control()
    control.reset()
    control.update_settings(max_tool_calls_per_minute=3)

    outcomes = [agent.execute_tool("get_estate_summary", {}) for _ in range(5)]
    allowed = [o for o in outcomes if "error" not in o]
    refused = [o for o in outcomes if o.get("refused_by") == "rate limit"]

    assert len(allowed) == 3
    assert len(refused) == 2
    assert refused[0]["retry_after_seconds"] >= 0


def test_out_of_range_limits_are_rejected_not_silently_applied():
    """A limit that quietly becomes unlimited is worse than no limit."""
    control = get_control()
    with pytest.raises(Exception):
        control.update_settings(max_assets_per_action=0)
    assert control.settings.max_assets_per_action == 25


def test_every_action_and_refusal_reaches_the_audit_log():
    control = get_control()
    control.update_settings(mode="read_only")

    agent.execute_tool("get_estate_summary", {})
    agent.execute_tool("migrate_asset", {"asset_id": worst_asset()["id"]})

    outcomes = [e.outcome for e in control.audit]
    assert "allowed" in outcomes
    assert "refused" in outcomes
    assert control.total_refusals >= 1
    # Newest first, so the log reads the way anyone reading it wants.
    log = control.audit_log(limit=10)
    assert log[0]["timestamp"] >= log[-1]["timestamp"]


def test_audit_log_redacts_sensitive_arguments():
    control = get_control()
    control.record("get_asset", "allowed", arguments={"api_key": "sk-secret-value"})
    assert control.audit[-1].arguments["api_key"] == "[redacted]"


def test_audit_log_is_bounded():
    """An audit log that grows without limit is a memory leak with a compliance
    story attached."""
    control = get_control()
    for _ in range(600):
        control.record("get_asset", "allowed")
    assert len(control.audit) <= 500
    assert control.total_calls >= 600  # the count of everything is still right


# --------------------------------------------------------------------------
# Provider adapters
#
# Pure translation, verified without a network. The bug class these catch is
# real: OpenAI sends tool arguments as a JSON string and Ollama sends an object,
# and the previous implementation json.loads()-ed both.
# --------------------------------------------------------------------------


CANONICAL = [
    {"role": "system", "content": "be brief"},
    {"role": "user", "content": "what is worst?"},
    {"role": "assistant", "content": "",
     "tool_calls": [{"id": "c1", "name": "list_assets", "arguments": {"limit": 2}}]},
    {"role": "tool", "tool_call_id": "c1", "name": "list_assets", "content": "{}"},
]


def test_openai_adapter_serialises_arguments_as_a_string():
    converted = llm_bridge._to_openai_messages(CANONICAL)
    call = converted[2]["tool_calls"][0]
    assert isinstance(call["function"]["arguments"], str)
    assert json.loads(call["function"]["arguments"]) == {"limit": 2}


def test_ollama_adapter_keeps_arguments_as_an_object():
    converted = llm_bridge._to_ollama_messages(CANONICAL)
    assert converted[2]["tool_calls"][0]["function"]["arguments"] == {"limit": 2}


def test_anthropic_adapter_lifts_system_and_uses_content_blocks():
    system, converted = llm_bridge._to_anthropic(CANONICAL)
    assert system == "be brief"
    assert all(m["role"] != "system" for m in converted)
    # The assistant tool call becomes a tool_use block...
    assert converted[1]["content"][0]["type"] == "tool_use"
    # ...and its result comes back on a user turn, not a tool role.
    assert converted[2]["role"] == "user"
    assert converted[2]["content"][0]["type"] == "tool_result"


@pytest.mark.parametrize("raw,expected", [
    ({"limit": 3}, {"limit": 3}),          # Ollama: already an object
    ('{"limit": 3}', {"limit": 3}),        # OpenAI: a JSON string
    ("not json at all", {}),               # small local models do this
    (None, {}),
    ("[1,2,3]", {}),                       # valid JSON, wrong shape
])
def test_tool_arguments_are_always_coerced_to_a_dict(raw, expected):
    assert llm_bridge._coerce_arguments(raw) == expected


def test_tool_schema_translates_to_anthropic_shape():
    translated = llm_bridge._tools_for_provider("anthropic", agent.TOOLS_SCHEMA)
    assert len(translated) == len(agent.TOOLS_SCHEMA)
    assert "input_schema" in translated[0]
    assert "function" not in translated[0]


def test_openai_shape_is_passed_through_unchanged():
    assert llm_bridge._tools_for_provider("openai", agent.TOOLS_SCHEMA) is agent.TOOLS_SCHEMA


# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------


def test_api_key_is_never_exposed():
    config = llm_bridge.LLMConfig()
    config.update(provider="openai", api_key="sk-super-secret-1234", model="gpt-4o")
    published = config.to_dict()
    assert "sk-super-secret-1234" not in json.dumps(published)
    assert published["has_api_key"] is True
    assert published["api_key_hint"] == "...1234"


def test_switching_provider_moves_the_base_url_to_its_default():
    """Pointing an OpenAI key at localhost:11434 is a confusing way to fail."""
    config = llm_bridge.LLMConfig()
    config.update(provider="ollama")
    assert "11434" in config.base_url
    config.update(provider="anthropic")
    assert "anthropic" in config.base_url


def test_missing_fields_are_reported_precisely():
    config = llm_bridge.LLMConfig()
    config.update(provider="openai", model="", api_key="")
    assert set(config.missing()) == {"model", "api_key"}
    assert not config.is_configured


def test_ollama_needs_no_key():
    config = llm_bridge.LLMConfig()
    config.update(provider="ollama", model="llama3.1")
    assert config.is_configured


# --------------------------------------------------------------------------
# The chat loop
# --------------------------------------------------------------------------


def run(coro):
    return asyncio.get_event_loop_policy().new_event_loop().run_until_complete(coro)


def test_chat_says_so_plainly_when_no_model_is_configured():
    llm_bridge._config.update(provider="", model="")
    result = run(agent.process_chat([{"role": "user", "content": "hello"}]))
    assert result["error"]["code"] == "not_configured"
    assert "Settings" in result["messages"][-1]["content"]


def test_chat_grounds_its_answer_in_a_tool_result(monkeypatch):
    """The whole design in one test: the model asks a tool, the tool answers from
    the engine, and the reply carries the engine's number."""
    llm_bridge._config.update(provider="ollama", model="stub", base_url="http://x")
    turns = {"n": 0}

    async def fake_chat(messages, tools=None):
        turns["n"] += 1
        if turns["n"] == 1:
            assert tools, "tools must be offered to the model"
            return {
                "role": "assistant", "content": "",
                "tool_calls": [{"id": "c1", "name": "list_assets",
                                "arguments": {"sort_by": "tnfl", "limit": 1}}],
                "_meta": {"model": "stub", "latency_ms": 1, "usage": {}},
            }
        payload = json.loads(messages[-1]["content"])
        top = payload["assets"][0]
        return {
            "role": "assistant",
            "content": f"Highest TNFL is {top['name']} at T={top['t_score']}.",
            "_meta": {"model": "stub", "latency_ms": 1, "usage": {}},
        }

    monkeypatch.setattr(agent, "chat", fake_chat)
    result = run(agent.process_chat([{"role": "user", "content": "worst integrity risk?"}]))

    assert result["error"] is None
    assert result["meta"]["iterations"] == 2
    engine_top = max(state.assets, key=lambda a: a.t_score)
    assert engine_top.name in result["messages"][-1]["content"]
    assert any(m["role"] == "tool" for m in result["messages"])


def test_chat_surfaces_a_provider_failure_instead_of_inventing_an_answer():
    llm_bridge._config.update(provider="ollama", model="stub", base_url="http://x")

    async def failing_chat(messages, tools=None):
        raise llm_bridge.LLMError("Cannot reach Ollama.", remedy="Start `ollama serve`.")

    original = agent.chat
    agent.chat = failing_chat
    try:
        result = run(agent.process_chat([{"role": "user", "content": "hi"}]))
    finally:
        agent.chat = original

    assert result["error"]["code"] == "llm_error"
    assert "ollama serve" in result["messages"][-1]["content"]


def test_iteration_budget_terminates_a_model_that_never_answers():
    llm_bridge._config.update(provider="ollama", model="stub", base_url="http://x")
    get_control().update_settings(max_iterations_per_turn=3)

    async def always_calls_tools(messages, tools=None):
        return {
            "role": "assistant", "content": "",
            "tool_calls": [{"id": "c", "name": "get_estate_summary", "arguments": {}}],
            "_meta": {},
        }

    original = agent.chat
    agent.chat = always_calls_tools
    try:
        result = run(agent.process_chat([{"role": "user", "content": "loop"}]))
    finally:
        agent.chat = original

    assert result["error"]["code"] == "iteration_budget"
    assert result["meta"]["iterations"] == 3


def test_tool_catalogue_reports_which_tools_write():
    from engine.agent_control import WRITE_TOOLS

    catalogue = agent.tool_catalogue()
    writers = [t for t in catalogue if t["mutating"]]
    assert sorted(t["name"] for t in writers) == sorted(WRITE_TOOLS)
    assert len(catalogue) == len(agent.TOOLS_SCHEMA)


# --------------------------------------------------------------------------
# Endpoint construction
#
# Every provider but Ollama and Anthropic is reached through the same OpenAI
# adapter, so the only thing separating a working gateway from a broken one is
# the URL. These exist because a duplicated version segment produces a 404 whose
# message names the *model*, which reads as a wrong model identifier and sends
# an operator to change the wrong setting.
# --------------------------------------------------------------------------


def endpoint(provider: str, base_url: str, resource: str) -> str:
    config = llm_bridge.LLMConfig()
    config.provider = provider
    config.base_url = base_url
    return llm_bridge._endpoint(config, resource)


@pytest.mark.parametrize(
    "provider,base_url,expected",
    [
        # The version segment is added when the base URL lacks one.
        ("openai", "https://api.openai.com",
         "https://api.openai.com/v1/chat/completions"),
        # ...and not added twice when the operator pastes a documented base that
        # already ends in /v1 - which Groq, OpenRouter and most vLLM
        # deployments all publish.
        ("openai", "https://api.openai.com/v1",
         "https://api.openai.com/v1/chat/completions"),
        ("custom", "https://openrouter.ai/api/v1",
         "https://openrouter.ai/api/v1/chat/completions"),
        ("openai", "https://api.groq.com/openai/v1",
         "https://api.groq.com/openai/v1/chat/completions"),
        # Groq's bare compatibility root carries no version anywhere, so it
        # still needs one - unlike Gemini's, which is versioned a segment up.
        ("openai", "https://api.groq.com/openai",
         "https://api.groq.com/openai/v1/chat/completions"),
        ("openai", "https://generativelanguage.googleapis.com/v1beta/openai",
         "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions"),
        # A trailing slash is an operator's habit, not a different endpoint.
        ("openai", "https://generativelanguage.googleapis.com/v1beta/openai/",
         "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions"),
    ],
)
def test_openai_shaped_gateways_build_one_version_segment(provider, base_url, expected):
    assert endpoint(provider, base_url, "chat/completions") == expected


def test_native_provider_paths_are_unchanged():
    """Ollama and Anthropic do not go through the OpenAI adapter."""
    assert endpoint("ollama", "http://localhost:11434", "api/chat") == \
        "http://localhost:11434/api/chat"
    assert endpoint("ollama", "http://localhost:11434", "api/tags") == \
        "http://localhost:11434/api/tags"
    assert endpoint("anthropic", "https://api.anthropic.com", "messages") == \
        "https://api.anthropic.com/v1/messages"


def test_the_documented_providers_are_the_whole_set():
    """The Settings picker, `.env.example` and this table are the same claim
    stated three times, so they must not drift. OmniRoute, Groq and Gemini were
    added as first-class entries because a key alone does not identify its
    issuer - leaving them to `custom` meant an operator had to know the base
    URL and the API prefix by heart."""
    assert set(llm_bridge.PROVIDERS) == {
        "ollama", "openai", "anthropic", "custom",
        "omniroute", "groq", "gemini",
    }


def test_every_provider_states_whether_it_needs_a_key():
    """The Settings form shows or hides the key field from this flag; a wrong
    value means an operator is asked for a credential that is not used, or not
    asked for one that is required."""
    for name, preset in llm_bridge.PROVIDERS.items():
        assert isinstance(preset["needs_key"], bool), name
        assert preset["label"] and preset["note"], name
        assert preset["default_base_url"].startswith("http"), name


def test_the_free_gateway_providers_resolve_to_their_real_endpoints():
    """Gemini and Groq are only reachable at an OpenAI-compatible path that is
    not the obvious one, which is exactly why they are presets rather than
    something an operator types."""
    gemini = llm_bridge.PROVIDERS["gemini"]
    assert gemini["api_prefix"] == "v1beta/openai"
    assert llm_bridge.PROVIDERS["groq"]["api_prefix"] == "openai/v1"
    # OmniRoute is self-hosted, so it must not require a key by default.
    assert llm_bridge.PROVIDERS["omniroute"]["needs_key"] is False


def test_a_chat_turn_reports_the_model_that_served_it():
    """The dashboard replaces its control state wholesale from each turn.

    When the chat response omitted the `llm` block, the banner flipped to "No
    language model is configured" the moment the first answer arrived - under
    the answer itself.
    """
    llm_bridge._config.update(provider="ollama", model="stub", base_url="http://x")

    async def stub_chat(messages, tools=None):
        return {"role": "assistant", "content": "ok", "_meta": {}}

    original = agent.chat
    agent.chat = stub_chat
    try:
        result = run(agent.process_chat([{"role": "user", "content": "hi"}]))
    finally:
        agent.chat = original

    assert result["control"]["llm"]["is_configured"] is True
    assert result["control"]["llm"]["model"] == "stub"


def test_status_and_chat_agree_on_the_control_shape():
    """Two endpoints, one payload. Divergence is invisible until a demo."""
    from fastapi.testclient import TestClient

    from main import app

    llm_bridge._config.update(provider="ollama", model="stub", base_url="http://x")
    with TestClient(app) as client:
        status = client.get("/api/agent/status").json()

    assert set(status) == set(agent.control_payload())
    assert set(status["llm"]) == {"is_configured", "provider", "model", "verified"}


EXPECTED_TOOL_COUNT = 30


def test_the_agent_tool_count_is_pinned():
    """README and the technical documentation both pin the tool count, and the
    grounding argument rests on the count being stable. Adding one is a
    documentation change, not just a code change."""
    assert len(agent.TOOLS_SCHEMA) == EXPECTED_TOOL_COUNT
    # The schema and the implementation map must not drift apart: a declared
    # tool with no implementation is an error the model only finds at runtime.
    assert ({t["function"]["name"] for t in agent.TOOLS_SCHEMA}
            == set(agent.TOOL_IMPLEMENTATIONS))


# --------------------------------------------------------------------------
# Tool calls the model typed instead of calling
#
# Small models do this, and the raw JSON used to land in the dashboard where an
# answer belongs.
# --------------------------------------------------------------------------


def test_a_real_tool_typed_as_text_is_recovered_and_run():
    llm_bridge._config.update(provider="ollama", model="stub", base_url="http://x")
    turns = {"n": 0}

    async def types_its_tool_call(messages, tools=None):
        turns["n"] += 1
        if turns["n"] == 1:
            # No tool_calls field at all - the call is in the message body.
            return {
                "role": "assistant",
                "content": '{"name": "get_estate_summary", "parameters": {}}',
                "_meta": {},
            }
        return {"role": "assistant", "content": "195 assets are catalogued.", "_meta": {}}

    original = agent.chat
    agent.chat = types_its_tool_call
    try:
        result = run(agent.process_chat([{"role": "user", "content": "summarise"}]))
    finally:
        agent.chat = original

    assert result["error"] is None
    # The tool actually ran...
    assert any(m["role"] == "tool" and m["name"] == "get_estate_summary"
               for m in result["messages"])
    # ...and the JSON blob never reached the transcript as an answer.
    assert not any('"name": "get_estate_summary"' in (m.get("content") or "")
                   for m in result["messages"] if m["role"] == "assistant")


def test_an_invented_tool_is_corrected_rather_than_printed():
    """asked "who are you?", llama3.1:8b answered with the literal text
    {"name": "explain_self", "parameters": {}} - a tool that does not exist."""
    llm_bridge._config.update(provider="ollama", model="stub", base_url="http://x")
    turns = {"n": 0}

    async def invents_a_tool(messages, tools=None):
        turns["n"] += 1
        if turns["n"] == 1:
            return {
                "role": "assistant",
                "content": '{"name": "explain_self", "parameters": {}}',
                "_meta": {},
            }
        # The correction must arrive as a system turn before the retry.
        assert any("explain_self" in (m.get("content") or "")
                   for m in messages if m["role"] == "system")
        return {"role": "assistant", "content": "I am the VERA agent.", "_meta": {}}

    original = agent.chat
    agent.chat = invents_a_tool
    try:
        result = run(agent.process_chat([{"role": "user", "content": "who are you?"}]))
    finally:
        agent.chat = original

    assert result["messages"][-1]["content"] == "I am the VERA agent."
    assert not any("explain_self" in (m.get("content") or "") for m in result["messages"])


def test_an_ordinary_answer_that_happens_to_start_with_a_brace_is_untouched():
    llm_bridge._config.update(provider="ollama", model="stub", base_url="http://x")

    async def answers_with_json(messages, tools=None):
        # Valid JSON, but names no tool - a legitimate answer, not a call.
        return {"role": "assistant", "content": '{"assets": 195}', "_meta": {}}

    original = agent.chat
    agent.chat = answers_with_json
    try:
        result = run(agent.process_chat([{"role": "user", "content": "as json"}]))
    finally:
        agent.chat = original

    assert result["messages"][-1]["content"] == '{"assets": 195}'


# --------------------------------------------------------------------------
# A pasted key configures the rest of itself
#
# An API key already names the service that issued it. Asking an operator to
# also supply an endpoint and a model identifier is asking them to repeat
# themselves under time pressure, and a Gemini key sent to api.openai.com comes
# back as "Incorrect API key provided" - which reads as a bad key rather than a
# wrong endpoint, and sends them to regenerate a key that was fine.
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "api_key,base_url,model",
    [
        ("AIzaSyExample", "https://generativelanguage.googleapis.com/v1beta/openai",
         "gemini-2.5-flash"),
        # Google's newer key shape, which authenticates against the same endpoint.
        ("AQ.Ab8Example", "https://generativelanguage.googleapis.com/v1beta/openai",
         "gemini-2.5-flash"),
        ("gsk_Example", "https://api.groq.com/openai/v1", "openai/gpt-oss-20b"),
        ("sk-or-v1-Example", "https://openrouter.ai/api/v1", ""),
        ("sk-Example", "https://api.openai.com", "gpt-4o-mini"),
    ],
)
def test_a_pasted_key_fills_in_its_own_endpoint(api_key, base_url, model):
    """This is the payload Settings sends: the OpenAI tile plus a key."""
    config = llm_bridge.LLMConfig()
    config.update(provider="openai", base_url="https://api.openai.com",
                  model="", api_key=api_key)
    assert config.base_url == base_url
    assert config.model == model


def test_an_anthropic_key_selects_the_native_provider():
    config = llm_bridge.LLMConfig()
    config.update(provider="openai", base_url="https://api.openai.com", api_key="sk-ant-Example")
    assert config.provider == "anthropic"


def test_an_endpoint_someone_typed_is_never_overwritten():
    """Auto-configuration fills blanks. It does not overrule a choice."""
    config = llm_bridge.LLMConfig()
    config.update(provider="openai", base_url="https://vllm.internal:8000/v1",
                  model="my-model", api_key="AIzaSyExample")
    assert config.base_url == "https://vllm.internal:8000/v1"
    assert config.model == "my-model"


def test_an_unrecognised_key_changes_nothing():
    """A bare token from some gateway with no house style must not be guessed at."""
    config = llm_bridge.LLMConfig()
    config.update(provider="custom", base_url="http://localhost:8080", api_key="abc123")
    assert config.provider == "custom"
    assert config.base_url == "http://localhost:8080"
