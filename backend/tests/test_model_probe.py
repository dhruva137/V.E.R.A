"""Probing models, and failing over when one dies mid-turn.

The property under test throughout is that nothing is ever assumed. A model
nobody called is `unknown`, a probe that errored is a failure carrying its
reason, and an HTTP 200 with an empty body is a failure rather than a success.

The tool-call check earns its own tests because it is the one that protects the
product. A model that declares tool support and never calls a tool does not look
broken - it answers a migration question fluently, with invented key sizes,
citing an estate it never read. Measured against the live gateway on this
machine, 12 of 12 `auto/*` routes answered and called the tool, while 6 of 8
named free model ids failed outright (401 "API key expired", 404 "No active
credentials", 400 from the upstream). That gap is the whole reason this exists.
"""

import asyncio

import pytest

from engine import llm_bridge
from engine.core import agents
from engine.core.agents import (
    PROBE_MAX_CONCURRENCY,
    PROBE_MAX_LIMIT,
    PROBE_TOOL,
    PROBE_TOOL_NAME,
    AgentPool,
    probe_model,
    probe_models,
)
from engine.core.model_health import (
    PROBE_EMPTY,
    PROBE_TEXT_ONLY,
    PROBE_UNKNOWN,
    PROBE_UNREACHABLE,
    PROBE_WORKING,
    ModelRegistry,
)

ENDPOINT = "http://localhost:20128/v1"


@pytest.fixture
def registry(tmp_path):
    return ModelRegistry(tmp_path / "health.json")


# --------------------------------------------------------------------------
# Fake transports, shaped like what the live gateway actually returns
# --------------------------------------------------------------------------


def _reply(*, responds=True, content="ready", tool_calls=(), kind="",
           detail="", seconds=1.5, status=200, served_by="upstream/model"):
    return {
        "responds": responds, "kind": kind, "detail": detail,
        "seconds": seconds, "status": status, "content": content,
        "tool_calls": list(tool_calls), "served_by": served_by,
        "finish_reason": "tool_calls" if tool_calls else "stop",
    }


def working_transport(base_url, model, secret, prompt, tools, timeout):
    """A healthy model: text when asked for text, a tool call when given a tool.

    Mirrors the measured shape exactly - the tool turn returns empty content
    *and* a tool call, which is why one request can never answer both
    questions.
    """
    if tools:
        return _reply(content="", tool_calls=[PROBE_TOOL_NAME], seconds=6.0)
    return _reply(content="ready", seconds=5.0)


def text_only_transport(base_url, model, secret, prompt, tools, timeout):
    """Answers fluently, never calls the tool. The dangerous one."""
    return _reply(content="Sure, the status is ok!", seconds=2.0)


def counting(transport):
    calls = []

    def wrapped(base_url, model, secret, prompt, tools, timeout):
        calls.append({"model": model, "tools": bool(tools)})
        return transport(base_url, model, secret, prompt, tools, timeout)

    wrapped.calls = calls
    return wrapped


# --------------------------------------------------------------------------
# Grading a probe
# --------------------------------------------------------------------------


def test_a_model_that_answers_and_calls_a_tool_is_working():
    result = probe_model("auto/best-free", base_url=ENDPOINT,
                         transport=working_transport)
    assert result["responds"] and result["answers"] and result["calls_tools"]
    assert result["requests"] == 2


def test_a_model_that_answers_but_ignores_the_tool_is_not_working():
    """The failure this product cares about most. It is not an error, it is a
    model that will invent the estate and sound certain doing it."""
    result = probe_model("chatty", base_url=ENDPOINT,
                         transport=text_only_transport)
    assert result["answers"] is True
    assert result["calls_tools"] is False
    assert "no tool call" in result["detail"]


def test_an_empty_completion_is_a_failure_never_a_success():
    """A thinking model can spend its whole budget reasoning and return HTTP 200
    with nothing in it. Calling that a success hands the caller an empty string
    to parse."""
    def empty(base_url, model, secret, prompt, tools, timeout):
        return _reply(content="", seconds=3.0)

    result = probe_model("thinker", base_url=ENDPOINT, transport=empty)
    assert result["responds"] is True
    assert result["answers"] is False
    assert result["kind"] == "empty"
    assert "empty completion" in result["detail"]


def test_a_transport_failure_is_recorded_with_its_reason():
    def refused(base_url, model, secret, prompt, tools, timeout):
        return _reply(responds=False, kind="transient",
                      detail="ConnectError: connection refused",
                      content="", seconds=0.1, status=None)

    result = probe_model("gone", base_url=ENDPOINT, transport=refused)
    assert result["responds"] is False
    assert "connection refused" in result["detail"]


def test_an_unreachable_model_is_never_given_an_invented_latency():
    """Time spent failing is not a response time. A number there would make a
    dead model look merely slow."""
    def refused(base_url, model, secret, prompt, tools, timeout):
        return _reply(responds=False, kind="transient", detail="down",
                      content="", seconds=30.0, status=None)

    assert probe_model("gone", base_url=ENDPOINT, transport=refused)["latency_s"] is None


def test_a_model_that_cannot_answer_is_not_charged_a_second_request():
    """Asking a model that returned nothing whether it can call a tool tells us
    nothing and still costs quota."""
    transport = counting(
        lambda *a: _reply(responds=False, kind="http_500", detail="boom",
                          content="", status=500)
    )
    result = probe_model("broken", base_url=ENDPOINT, transport=transport)
    assert result["requests"] == 1
    assert len(transport.calls) == 1


def test_the_tool_probe_is_the_only_call_that_carries_a_tool():
    transport = counting(working_transport)
    probe_model("m", base_url=ENDPOINT, transport=transport)
    assert [c["tools"] for c in transport.calls] == [False, True]


# --------------------------------------------------------------------------
# What the registry does with a probe result
# --------------------------------------------------------------------------


def test_a_model_nobody_probed_is_unknown_not_working(registry):
    registry.record("m", ok=True, seconds=1.0)
    assert registry.get("m").probe_verdict == PROBE_UNKNOWN
    assert registry.known_good(endpoint=ENDPOINT) == []


def test_a_long_call_history_never_amounts_to_a_probe_verdict(registry):
    """A hundred successful prose calls still say nothing about tool calling."""
    for _ in range(100):
        registry.record("m", ok=True, seconds=1.0)
    assert registry.get("m").reliability > 0.9
    assert registry.get("m").probe_verdict == PROBE_UNKNOWN


@pytest.mark.parametrize("responds,answers,tools,expected", [
    (True, True, True, PROBE_WORKING),
    (True, True, False, PROBE_TEXT_ONLY),
    (True, False, False, PROBE_EMPTY),
    (False, False, False, PROBE_UNREACHABLE),
])
def test_every_probe_outcome_maps_to_its_own_verdict(
    registry, responds, answers, tools, expected,
):
    registry.record_probe("m", endpoint=ENDPOINT, responds=responds,
                          answers=answers, calls_tools=tools, latency=1.0)
    assert registry.get("m").probe_verdict == expected


def test_a_probe_counts_as_the_real_call_it_was(registry):
    """It was a genuine request against a genuine quota; hiding it from the
    reliability figure would make the registry less accurate, not more."""
    registry.record_probe("m", endpoint=ENDPOINT, responds=True, answers=True,
                          calls_tools=True, latency=4.0)
    assert registry.get("m").successes == 1
    assert registry.get("m").median_latency == 4.0


def test_a_text_only_model_is_not_punished_on_reliability(registry):
    """It answered. What it failed at is a capability, not a broken call -
    recording it as unreliability would retire a model that is fine for
    narrative work."""
    registry.record_probe("m", endpoint=ENDPOINT, responds=True, answers=True,
                          calls_tools=False, latency=2.0)
    assert registry.get("m").failures == 0
    assert registry.get("m").probe_verdict == PROBE_TEXT_ONLY


def test_a_failed_probe_is_recorded_as_a_failure(registry):
    registry.record_probe("m", endpoint=ENDPOINT, responds=False, answers=False,
                          calls_tools=False, detail="connection refused",
                          kind="transient")
    assert registry.get("m").failures == 1
    assert "connection refused" in registry.get("m").last_error


def test_probe_results_survive_a_restart(tmp_path):
    """Each result cost a real request; relearning them is the expensive part."""
    path = tmp_path / "h.json"
    first = ModelRegistry(path)
    first.record_probe("auto/best-free", endpoint=ENDPOINT, responds=True,
                       answers=True, calls_tools=True, latency=5.5,
                       served_by="claude-haiku-4.5")
    first.save()

    restored = ModelRegistry(path).get("auto/best-free")
    assert restored.probe_verdict == PROBE_WORKING
    assert restored.probe_served_by == "claude-haiku-4.5"
    assert restored.probe_endpoint == ENDPOINT


def test_a_file_written_before_probing_existed_loads_as_unprobed(tmp_path):
    """Defaulting the missing fields to True would turn every historical record
    into a working model nobody ever tested."""
    path = tmp_path / "h.json"
    path.write_text('[{"model": "m", "successes": 9, "failures": 0}]',
                    encoding="utf-8")
    assert ModelRegistry(path).get("m").probe_verdict == PROBE_UNKNOWN


def test_a_trailing_slash_does_not_split_one_endpoint_in_two(registry):
    registry.record_probe("m", endpoint=ENDPOINT + "/", responds=True,
                          answers=True, calls_tools=True, latency=1.0)
    assert registry.known_good(endpoint=ENDPOINT) == ["m"]


def test_a_verdict_earned_elsewhere_does_not_count_here(registry):
    """The same model id behind a different gateway is a different thing, and
    falling back to it is a 404 dressed up as resilience."""
    registry.record_probe("shared-name", endpoint="https://other.example/v1",
                          responds=True, answers=True, calls_tools=True,
                          latency=1.0)
    assert registry.known_good(endpoint=ENDPOINT) == []


def test_a_stale_verdict_is_reported_but_not_treated_as_current(registry):
    import time as _time

    registry.record_probe("old", endpoint=ENDPOINT, responds=True, answers=True,
                          calls_tools=True, latency=1.0)
    registry.get("old").probed_at = _time.time() - (60 * 86_400)

    assert registry.known_good(endpoint=ENDPOINT) == []
    assert registry.known_good(endpoint=ENDPOINT, fresh_only=False) == ["old"]
    assert registry.get("old").probe_is_fresh is False


def test_known_good_excludes_text_only_models_when_tools_are_required(registry):
    registry.record_probe("tools", endpoint=ENDPOINT, responds=True,
                          answers=True, calls_tools=True, latency=1.0)
    registry.record_probe("prose", endpoint=ENDPOINT, responds=True,
                          answers=True, calls_tools=False, latency=1.0)

    assert registry.known_good(endpoint=ENDPOINT, require_tools=True) == ["tools"]
    assert set(registry.known_good(endpoint=ENDPOINT, require_tools=False)) == {
        "tools", "prose",
    }


def test_the_report_never_reads_tracked_as_checked(registry):
    registry.record("never-probed", ok=True, seconds=1.0)
    registry.record_probe("probed", endpoint=ENDPOINT, responds=True,
                          answers=True, calls_tools=True, latency=1.0)
    report = registry.report()
    assert report["tracked"] == 2
    assert report["probe"]["probed"] == 1
    assert report["probe"]["unprobed"] == 1


# --------------------------------------------------------------------------
# Bounding the run - this spends somebody's free tier
# --------------------------------------------------------------------------


def test_the_candidate_set_is_capped_however_much_is_asked_for(registry):
    result = probe_models([f"m{i}" for i in range(500)], base_url=ENDPOINT,
                          limit=10_000, registry=registry,
                          transport=working_transport)
    assert result["probed"] <= PROBE_MAX_LIMIT


def test_concurrency_is_capped(registry):
    result = probe_models(["a", "b"], base_url=ENDPOINT, concurrency=500,
                          registry=registry, transport=working_transport)
    assert result["ok"] is True
    assert PROBE_MAX_CONCURRENCY < 500


def test_a_model_named_twice_is_only_paid_for_once(registry):
    transport = counting(working_transport)
    result = probe_models(["a", "a", "a"], base_url=ENDPOINT, registry=registry,
                          transport=transport)
    assert result["probed"] == 1
    assert {c["model"] for c in transport.calls} == {"a"}


def test_a_run_reports_what_it_actually_spent(registry):
    result = probe_models(["a", "b"], base_url=ENDPOINT, registry=registry,
                          transport=working_transport)
    assert result["requests_sent"] == 4      # two models, two requests each


def test_the_default_run_does_not_probe_the_whole_catalogue(registry):
    """514 models would be 1028 requests to answer a question a dozen answers."""
    seen = []

    def catalogue(base_url, model, secret, prompt, tools, timeout):
        seen.append(model)
        return working_transport(base_url, model, secret, prompt, tools, timeout)

    probe_models(base_url=ENDPOINT, registry=registry, transport=catalogue)
    assert len(set(seen)) <= agents.PROBE_DEFAULT_LIMIT


def test_results_are_filed_and_saved(registry):
    probe_models(["a"], base_url=ENDPOINT, registry=registry,
                 transport=working_transport)
    assert registry.get("a").probe_verdict == PROBE_WORKING
    assert ModelRegistry(registry.path).get("a").probe_verdict == PROBE_WORKING


def test_a_run_separates_working_from_broken_from_merely_fluent(registry):
    def mixed(base_url, model, secret, prompt, tools, timeout):
        if model == "good":
            return working_transport(base_url, model, secret, prompt, tools, timeout)
        if model == "chatty":
            return text_only_transport(base_url, model, secret, prompt, tools, timeout)
        return _reply(responds=False, kind="http_401",
                      detail="API key expired", content="", status=401)

    result = probe_models(["good", "chatty", "dead"], base_url=ENDPOINT,
                          registry=registry, transport=mixed)
    assert result["working"] == ["good"]
    assert result["text_only"] == ["chatty"]
    assert result["broken"] == ["dead"]


# --------------------------------------------------------------------------
# The wire format. Getting either of these wrong looks like a dead gateway.
# --------------------------------------------------------------------------


def test_the_probe_never_streams():
    """An SSE body parsed as JSON fails as "Expecting value: line 1 column 1",
    which reads as an unreachable model rather than a protocol mismatch - and
    would retire the entire catalogue in a single run."""
    import inspect

    assert '"stream": False' in inspect.getsource(agents._probe_request)


def test_an_absent_key_means_no_authorization_header_at_all(monkeypatch):
    """An empty bearer token is an illegal header that httpx rejects before the
    request leaves, which surfaces as a transient fault and gets blamed on the
    model."""
    import httpx

    seen = {}

    class FakeResponse:
        status_code = 200
        text = '{"choices": [{"message": {"content": "ready"}}]}'

        @staticmethod
        def json():
            return {"choices": [{"message": {"content": "ready"},
                                 "finish_reason": "stop"}]}

    def fake_post(url, headers=None, json=None, timeout=None):
        seen["headers"] = headers
        seen["payload"] = json
        return FakeResponse()

    monkeypatch.setattr(httpx, "post", fake_post)
    agents._probe_request(ENDPOINT, "m", "", "hi", None, 5.0)

    assert "Authorization" not in seen["headers"]
    assert seen["payload"]["stream"] is False


def test_a_key_is_sent_when_there_is_one(monkeypatch):
    import httpx

    seen = {}

    class FakeResponse:
        status_code = 200
        text = "{}"

        @staticmethod
        def json():
            return {"choices": [{"message": {"content": "ready"}}]}

    monkeypatch.setattr(httpx, "post", lambda url, headers=None, json=None,
                        timeout=None: (seen.update(headers=headers), FakeResponse())[1])
    agents._probe_request(ENDPOINT, "m", "sk-secret", "hi", None, 5.0)
    assert seen["headers"]["Authorization"] == "Bearer sk-secret"


def test_an_sse_body_is_named_as_a_protocol_mismatch(monkeypatch):
    import httpx

    class SseResponse:
        status_code = 200
        text = 'data: {"choices": []}\n\n'

        @staticmethod
        def json():
            raise ValueError("Expecting value: line 1 column 1")

    monkeypatch.setattr(httpx, "post", lambda *a, **k: SseResponse())
    outcome = agents._probe_request(ENDPOINT, "m", "", "hi", None, 5.0)
    assert outcome["kind"] == "sse"
    assert outcome["responds"] is False


def test_a_rate_limit_is_not_reported_as_a_dead_model(monkeypatch, registry):
    import httpx

    class Limited:
        status_code = 429
        text = "slow down"

    monkeypatch.setattr(httpx, "post", lambda *a, **k: Limited())
    outcome = agents._probe_request(ENDPOINT, "m", "", "hi", None, 5.0)
    assert outcome["kind"] == "rate_limit"

    # And it must not trip the breaker: the provider is rationing us, the model
    # is not broken.
    for _ in range(6):
        registry.record_probe("m", endpoint=ENDPOINT, responds=False,
                              answers=False, calls_tools=False,
                              kind="rate_limit", detail="429")
    assert registry.get("m").available()[0] is True


def test_the_probe_tool_schema_is_trivial():
    """A model failing this is failing at tool calling, not at reading a
    complicated schema."""
    schema = PROBE_TOOL[0]["function"]
    assert schema["name"] == PROBE_TOOL_NAME
    assert list(schema["parameters"]["properties"]) == ["status"]


# --------------------------------------------------------------------------
# Failover in the pool
# --------------------------------------------------------------------------


@pytest.fixture
def pool(tmp_path, monkeypatch, registry):
    monkeypatch.setattr(agents, "KEYS_FILE", tmp_path / "keys.json")
    monkeypatch.setattr(agents, "DATA_DIR", tmp_path)
    monkeypatch.setattr(agents, "_MODELS", registry)
    p = AgentPool()
    p.add("groq", "gsk_test_aaaa")
    return p


def test_failover_does_not_re_pick_the_model_that_just_failed(pool, registry):
    """The breaker needs several consecutive faults before it opens, so without
    an explicit exclusion the best-ranked model after a failure is very often
    the one that just failed - and every attempt is spent on it."""
    key = pool.all()[0]
    key.candidates = ["first", "second", "third"]
    tried = []

    def fails_the_first_two(k, secret, messages, timeout, model=None):
        tried.append(model)
        if len(tried) < 3:
            raise agents._ModelFault("http_500", "upstream exploded")
        return "answer"

    result = pool.call([{"role": "user", "content": "x"}], max_attempts=4,
                       transport=fails_the_first_two)

    assert result["ok"] is True
    assert len(set(tried)) == 3, f"the same model was re-tried: {tried}"


def test_an_answer_reports_which_models_were_burned_getting_it(pool):
    key = pool.all()[0]
    key.candidates = ["a", "b"]
    calls = []

    def fails_once(k, secret, messages, timeout, model=None):
        calls.append(model)
        if len(calls) == 1:
            raise agents._ModelFault("http_400", "no")
        return "answer"

    result = pool.call([{"role": "user", "content": "x"}], max_attempts=3,
                       transport=fails_once)
    assert result["ok"] is True
    assert result["fell_back_from"] == [calls[0]]


def test_a_clean_answer_reports_no_fallback(pool):
    result = pool.call([{"role": "user", "content": "x"}], max_attempts=2,
                       transport=lambda *a, **k: "answer")
    assert result["fell_back_from"] == []


def test_probed_models_become_pool_candidates(pool, registry):
    key = pool.all()[0]
    registry.record_probe("probed-good", endpoint=key.base_url, responds=True,
                          answers=True, calls_tools=True, latency=1.0)
    assert "probed-good" in pool.model_candidates(key)


def test_the_operators_own_model_still_leads(pool, registry):
    key = pool.all()[0]
    registry.record_probe("probed-good", endpoint=key.base_url, responds=True,
                          answers=True, calls_tools=True, latency=0.1)
    assert pool.model_candidates(key)[0] == key.model


def test_pool_candidates_ignore_models_probed_at_another_endpoint(pool, registry):
    key = pool.all()[0]
    registry.record_probe("elsewhere", endpoint="https://other.example/v1",
                          responds=True, answers=True, calls_tools=True,
                          latency=1.0)
    assert "elsewhere" not in pool.model_candidates(key)


def test_a_prose_only_model_is_still_useful_to_the_pool(pool, registry):
    """Agent tasks ask for a small JSON object in the reply text, not for a tool
    call, so a model that answers in prose does that job perfectly well. The
    stricter filter belongs to the agent loop, which applies it itself."""
    key = pool.all()[0]
    registry.record_probe("prose", endpoint=key.base_url, responds=True,
                          answers=True, calls_tools=False, latency=1.0)
    assert "prose" in pool.model_candidates(key)


def test_running_out_of_models_reports_rather_than_looping(pool):
    key = pool.all()[0]
    key.candidates = ["only"]

    def always_fails(k, secret, messages, timeout, model=None):
        raise agents._ModelFault("http_500", "dead")

    result = pool.call([{"role": "user", "content": "x"}], max_attempts=5,
                       transport=always_fails)
    assert result["ok"] is False
    assert result["reason"] == "no_model"
    assert "probe" in result["detail"].lower()


# --------------------------------------------------------------------------
# Failover in the agent loop
# --------------------------------------------------------------------------


def run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


@pytest.fixture
def bridge(monkeypatch, registry):
    monkeypatch.setattr(llm_bridge, "_MODELS", registry)
    llm_bridge._config.update(
        provider="omniroute", model="auto/best-free",
        base_url="http://localhost:20128",
    )
    return llm_bridge._config


def test_the_probe_endpoint_and_the_bridge_agree_on_the_url(bridge):
    """If these disagreed by a /v1, every model probed through the gateway would
    look like it belonged to a different endpoint and the chain would always be
    empty."""
    assert llm_bridge._versioned_base(bridge) == ENDPOINT


def test_the_chain_leads_with_the_configured_model(bridge, registry):
    registry.record_probe("auto/fast", endpoint=ENDPOINT, responds=True,
                          answers=True, calls_tools=True, latency=0.1)
    chain = llm_bridge._failover_chain(bridge)
    assert chain[0] == "auto/best-free"
    assert "auto/fast" in chain


def test_the_chain_never_offers_a_model_that_ignores_tools(bridge, registry):
    """This is the agent loop. Promoting a model that answers without calling
    tools would turn an outage into confident invented numbers, which is worse
    than an outage."""
    registry.record_probe("prose", endpoint=ENDPOINT, responds=True,
                          answers=True, calls_tools=False, latency=0.1)
    assert "prose" not in llm_bridge._failover_chain(bridge)


def test_the_chain_is_bounded(bridge, registry):
    for i in range(20):
        registry.record_probe(f"auto/m{i}", endpoint=ENDPOINT, responds=True,
                              answers=True, calls_tools=True, latency=1.0)
    assert len(llm_bridge._failover_chain(bridge)) <= llm_bridge.MAX_FAILOVER_MODELS


def test_a_turn_survives_the_first_model_dying(bridge, registry, monkeypatch):
    """The live failure this fixes: auto/best-free timed out at 90s mid-turn and
    took the whole turn with it."""
    registry.record_probe("auto/fast", endpoint=ENDPOINT, responds=True,
                          answers=True, calls_tools=True, latency=1.0)
    seen = []

    async def attempt(config, model, messages, tools):
        seen.append(model)
        if model == "auto/best-free":
            raise llm_bridge.LLMError(
                "auto/best-free did not respond within 90s.", status=None)
        return {"role": "assistant", "content": "answered"}, {}

    monkeypatch.setattr(llm_bridge, "_one_attempt", attempt)
    reply = run(llm_bridge.chat([{"role": "user", "content": "hi"}]))

    assert reply["content"] == "answered"
    assert reply["_meta"]["model"] == "auto/fast"
    assert reply["_meta"]["configured_model"] == "auto/best-free"
    assert reply["_meta"]["failed_over_from"] == ["auto/best-free"]
    assert seen == ["auto/best-free", "auto/fast"]


def test_a_rate_limited_model_falls_through_rather_than_failing_the_turn(
    bridge, registry, monkeypatch,
):
    registry.record_probe("auto/fast", endpoint=ENDPOINT, responds=True,
                          answers=True, calls_tools=True, latency=1.0)

    async def attempt(config, model, messages, tools):
        if model == "auto/best-free":
            raise llm_bridge.LLMError("rate limiting this key (429).", status=429)
        return {"role": "assistant", "content": "ok"}, {}

    monkeypatch.setattr(llm_bridge, "_one_attempt", attempt)
    assert run(llm_bridge.chat([{"role": "user", "content": "hi"}]))["content"] == "ok"
    # A 429 is the provider rationing us, so it must not retire the model.
    assert registry.get("auto/best-free").available()[0] is True


def test_a_rejected_credential_stops_instead_of_walking_the_chain(
    bridge, registry, monkeypatch,
):
    """Every model on the endpoint authenticates the same way. Trying them all
    is a slower path to the same error, and it spends quota to get there."""
    registry.record_probe("auto/fast", endpoint=ENDPOINT, responds=True,
                          answers=True, calls_tools=True, latency=1.0)
    seen = []

    async def attempt(config, model, messages, tools):
        seen.append(model)
        raise llm_bridge._CredentialProblem(
            "The provider rejected the credentials (401).", status=401)

    monkeypatch.setattr(llm_bridge, "_one_attempt", attempt)
    with pytest.raises(llm_bridge.LLMError):
        run(llm_bridge.chat([{"role": "user", "content": "hi"}]))
    assert seen == ["auto/best-free"]


def test_an_empty_completion_falls_through_to_the_next_model(
    bridge, registry, monkeypatch,
):
    registry.record_probe("auto/fast", endpoint=ENDPOINT, responds=True,
                          answers=True, calls_tools=True, latency=1.0)

    async def attempt(config, model, messages, tools):
        if model == "auto/best-free":
            raise llm_bridge.LLMError(f"{model} returned an empty completion.")
        return {"role": "assistant", "content": "real answer"}, {}

    monkeypatch.setattr(llm_bridge, "_one_attempt", attempt)
    reply = run(llm_bridge.chat([{"role": "user", "content": "hi"}]))
    assert reply["content"] == "real answer"


def test_when_everything_fails_the_error_names_what_was_tried(
    bridge, registry, monkeypatch,
):
    registry.record_probe("auto/fast", endpoint=ENDPOINT, responds=True,
                          answers=True, calls_tools=True, latency=1.0)

    async def attempt(config, model, messages, tools):
        raise llm_bridge.LLMError(f"{model} is down.", status=500)

    monkeypatch.setattr(llm_bridge, "_one_attempt", attempt)
    with pytest.raises(llm_bridge.LLMError) as excinfo:
        run(llm_bridge.chat([{"role": "user", "content": "hi"}]))
    assert "Fell back through" in excinfo.value.message


def test_failover_does_not_rewrite_the_operators_saved_model(
    bridge, registry, monkeypatch,
):
    """Silently changing a Settings value the operator chose would make that
    screen a lie."""
    registry.record_probe("auto/fast", endpoint=ENDPOINT, responds=True,
                          answers=True, calls_tools=True, latency=1.0)

    async def attempt(config, model, messages, tools):
        if model == "auto/best-free":
            raise llm_bridge.LLMError("down", status=500)
        return {"role": "assistant", "content": "ok"}, {}

    monkeypatch.setattr(llm_bridge, "_one_attempt", attempt)
    run(llm_bridge.chat([{"role": "user", "content": "hi"}]))
    assert bridge.model == "auto/best-free"


def test_a_tool_call_reply_is_never_mistaken_for_an_empty_one(
    bridge, registry, monkeypatch,
):
    """A model calling a tool returns empty content by design. Treating that as
    an empty completion would break every tool-calling turn there is."""
    async def attempt(config, model, messages, tools):
        return {"role": "assistant", "content": "",
                "tool_calls": [{"id": "c1", "name": "list_assets",
                                "arguments": {}}]}, {}

    monkeypatch.setattr(llm_bridge, "_one_attempt", attempt)
    reply = run(llm_bridge.chat([{"role": "user", "content": "hi"}]))
    assert reply["tool_calls"][0]["name"] == "list_assets"


def test_a_credential_problem_is_told_apart_from_an_unavailable_model():
    """A gateway answers 401 for both. Getting it backwards either walks the
    whole chain to reach the same error, or lets one withdrawn free model take
    the entire endpoint down."""
    key_problem = llm_bridge.LLMError(
        "The provider rejected the credentials (401).", status=401)
    model_problem = llm_bridge.LLMError(
        "The provider rejected the credentials (401). model not available",
        status=401)

    assert llm_bridge._is_credential_problem(key_problem) is True
    assert llm_bridge._is_credential_problem(model_problem) is False
    assert llm_bridge._is_credential_problem(
        llm_bridge.LLMError("gateway timeout", status=504)) is False


@pytest.mark.parametrize("error,expected", [
    (llm_bridge.LLMError("rate limited", status=429), "rate_limit"),
    (llm_bridge.LLMError("boom", status=500), "http_500"),
    (llm_bridge.LLMError("m did not respond within 90s."), "timeout"),
    (llm_bridge.LLMError("m returned an empty completion."), "empty"),
])
def test_each_failure_is_filed_under_the_kind_it_actually_is(error, expected):
    assert llm_bridge._health_kind(error) == expected
