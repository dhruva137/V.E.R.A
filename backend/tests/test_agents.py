"""The agent pool and its tasks.

The safety property is the one under test: a model's answer must enter the
engine as weak, gradeable, outvotable evidence - never as a number, never as a
final answer. Everything else is scheduling.
"""

import pytest

from engine.core.agent_tasks import (
    AGENT_CONFIDENCE,
    AGENT_PROVENANCE,
    TASKS,
    _extract_json,
    adjudicate_conflict,
    infer_owner,
    resolve_algorithm,
)
from engine.core.agents import (
    PROVIDERS,
    AgentPool,
    _CredentialRejected,
    _RateLimited,
)
from engine.core.corroboration import Reading, corroborate
from engine.plugins import confidence_for


@pytest.fixture
def pool(tmp_path, monkeypatch):
    monkeypatch.setattr("engine.core.agents.KEYS_FILE", tmp_path / "keys.json")
    monkeypatch.setattr("engine.core.agents.DATA_DIR", tmp_path)
    p = AgentPool()
    p.add("groq", "gsk_test_aaaa")
    p.add("openrouter", "sk-or-test-bbbb")
    return p


def replies(text):
    return lambda key, secret, messages, timeout, model=None: text


# --------------------------------------------------------------------------
# Providers
# --------------------------------------------------------------------------


def test_every_provider_preset_is_usable():
    for name, preset in PROVIDERS.items():
        assert preset["label"] and preset["note"]
        assert preset["rpm"] > 0 and preset["rpd"] > 0
        if name != "custom":
            assert preset["base_url"].startswith("http")


def test_a_local_provider_is_offered_and_has_no_meaningful_quota():
    """Where a local model exists it is strictly better: no quota, no egress."""
    assert PROVIDERS["local"]["rpd"] > 100_000


# --------------------------------------------------------------------------
# Pool budget and selection
# --------------------------------------------------------------------------


def test_capacity_sums_across_keys(pool):
    capacity = pool.capacity()
    assert capacity["keys"] == 2
    assert capacity["requests_per_minute"] == (
        PROVIDERS["groq"]["rpm"] + PROVIDERS["openrouter"]["rpm"]
    )


def test_selection_prefers_the_key_with_the_most_headroom(pool):
    groq = next(k for k in pool.all() if k.provider == "groq")
    for _ in range(groq.rpm - 1):
        groq.record_call()
    assert pool.pick().provider == "openrouter"


def test_a_key_at_its_per_minute_limit_is_not_offered(pool):
    for key in pool.all():
        for _ in range(key.rpm):
            key.record_call()
    assert pool.pick() is None


def test_a_key_at_its_daily_limit_is_not_offered(pool):
    key = pool.all()[0]
    key.calls_today = key.rpd
    ok, reason = key.available
    assert ok is False and "daily" in reason


def test_secrets_are_never_returned(pool):
    """The plaintext key is memory-only, exactly like the model API key."""
    for key in pool.all():
        blob = str(key.to_dict())
        assert "gsk_test_aaaa" not in blob
        assert "sk-or-test-bbbb" not in blob
        hint = key.to_dict()["hint"]
        # Enough to tell two keys apart, never enough to use one. A keyless
        # provider says so rather than emitting a stray glyph.
        assert hint == "no key" or (hint.startswith("...") and len(hint) == 7)


def test_the_manifest_never_persists_a_secret(pool, tmp_path):
    written = (tmp_path / "keys.json").read_text(encoding="utf-8")
    assert "gsk_test_aaaa" not in written
    assert "sk-or-test-bbbb" not in written


def test_keys_return_disabled_after_a_restart(tmp_path, monkeypatch):
    """A pool that silently came back empty would look like a config bug; one
    that persisted secrets would be a worse product."""
    monkeypatch.setattr("engine.core.agents.KEYS_FILE", tmp_path / "k.json")
    monkeypatch.setattr("engine.core.agents.DATA_DIR", tmp_path)
    first = AgentPool()
    first.add("groq", "gsk_secret")

    second = AgentPool()
    restored = second.all()[0]
    assert restored.available[0] is False
    assert "re-enter" in restored.available[1]


# --------------------------------------------------------------------------
# Failure handling, by kind
# --------------------------------------------------------------------------


def test_a_credential_failure_takes_the_key_out_immediately(pool):
    """Retrying a revoked key is pure latency."""
    def reject(key, secret, messages, timeout, model=None):
        raise _CredentialRejected("invalid api key")

    pool.call([{"role": "user", "content": "x"}], max_attempts=2, transport=reject)
    assert all(not k.available[0] for k in pool.all())
    assert "credential rejected" in pool.all()[0].available[1]


def test_a_rate_limit_cools_the_key_rather_than_disabling_it(pool):
    """Quotas are usually account-wide: back off, do not rotate-and-hammer."""
    def limited(key, secret, messages, timeout, model=None):
        raise _RateLimited(retry_after=45)

    pool.call([{"role": "user", "content": "x"}], max_attempts=2, transport=limited)
    key = pool.all()[0]
    assert key.disabled_reason == ""
    assert "cooling" in key.available[1]


def test_a_transient_failure_is_retried_and_can_succeed(pool):
    calls = {"n": 0}

    def flaky(key, secret, messages, timeout, model=None):
        calls["n"] += 1
        if calls["n"] < 2:
            raise TimeoutError("network blip")
        return '{"algorithm": "RSA", "reason": "explicit call"}'

    result = pool.call([{"role": "user", "content": "x"}], max_attempts=3, transport=flaky)
    assert result["ok"] is True


def test_an_exhausted_pool_reports_rather_than_raising(pool):
    """An agent task that cannot run is a normal outcome the engine carries on
    through, not an exception that aborts a scan."""
    for key in pool.all():
        for _ in range(key.rpm):
            key.record_call()
    result = pool.call([{"role": "user", "content": "x"}], transport=replies("{}"))
    assert result["ok"] is False
    assert result["reason"] == "no_capacity"
    assert "continues without agent assistance" in result["detail"]


def test_an_empty_pool_is_not_an_error(tmp_path, monkeypatch):
    # Redirect the keys file so a restored OmniRoute gateway key on disk
    # cannot make this look like a live pool and hit the network.
    monkeypatch.setattr("engine.core.agents.KEYS_FILE", tmp_path / "empty-keys.json")
    monkeypatch.setattr("engine.core.agents.DATA_DIR", tmp_path)
    assert AgentPool().call([{"role": "user", "content": "x"}])["ok"] is False


# --------------------------------------------------------------------------
# The safety property: model output is weak, graded, outvotable evidence
# --------------------------------------------------------------------------


def test_a_model_answer_carries_the_weakest_grade(pool, monkeypatch):
    monkeypatch.setattr(
        pool, "call",
        lambda *a, **k: {"ok": True, "text": '{"algorithm": "RSA", "reason": "explicit call"}',
                         "model": "m", "provider": "p"})
    verdict = resolve_algorithm(
        pool, "cipher = Cipher.getInstance(alg)", "Foo.java:12")
    assert verdict.provenance == AGENT_PROVENANCE
    assert verdict.confidence == AGENT_CONFIDENCE
    assert verdict.requires_review is True


def test_a_model_claim_is_outweighed_by_a_runtime_observation():
    """The whole reason this is safe on a free tier. No special case required -
    the grades do it: the handshake leads, the model's contrary claim adds no
    confidence, and the disagreement is surfaced as a flag."""
    result = corroborate([
        Reading("tls", "observed", "runtime_observed",
                confidence_for("runtime_observed"), "vulnerable"),
        Reading("agent", "declared", AGENT_PROVENANCE, AGENT_CONFIDENCE, "safe"),
    ])
    assert result["claim"] == "vulnerable"
    assert result["confidence"] == confidence_for("runtime_observed")
    assert result["disagreement"] is True
    assert result["flagged"] is True


def test_the_model_never_returns_a_score_or_a_rank(pool, monkeypatch):
    monkeypatch.setattr(
        pool, "call",
        lambda *a, **k: {"ok": True, "text": '{"algorithm": "RSA", "reason": "r"}',
                         "model": "m", "provider": "p"})
    verdict = resolve_algorithm(pool, "x", "y")
    payload = verdict.to_dict()
    for forbidden in ("qirs", "score", "rank", "h_score", "t_score"):
        assert forbidden not in payload


def test_an_invented_algorithm_name_is_rejected(pool, monkeypatch):
    """Letting a model invent an algorithm name would poison the taxonomy."""
    monkeypatch.setattr(
        pool, "call",
        lambda *a, **k: {"ok": True, "text": '{"algorithm": "SuperCrypt9000", "reason": "made up"}',
                         "model": "m", "provider": "p"})
    assert resolve_algorithm(pool, "x", "y").answer == "unknown"


def test_a_known_algorithm_is_accepted_case_insensitively(pool, monkeypatch):
    monkeypatch.setattr(
        pool, "call",
        lambda *a, **k: {"ok": True, "text": '{"algorithm": "rsa", "reason": "explicit"}',
                         "model": "m", "provider": "p"})
    assert resolve_algorithm(pool, "x", "y").answer == "RSA"


def test_an_adjudication_naming_an_absent_sensor_is_discarded(pool, monkeypatch):
    """A verdict about a sensor that did not report is useless."""
    monkeypatch.setattr(
        pool, "call",
        lambda *a, **k: {"ok": True, "text": '{"favours": "ghost", "reason": "x", "confident": true}',
                         "model": "m", "provider": "p"})
    observations = [Reading("tls", "observed", "runtime_observed", 0.9, "safe"), Reading("source", "built", "static_analysis", 0.5, "vulnerable")]
    assert adjudicate_conflict(pool, "asset", observations) is None


def test_an_unconfident_adjudication_is_worth_even_less(pool, monkeypatch):
    monkeypatch.setattr(
        pool, "call",
        lambda *a, **k: {"ok": True, "text": '{"favours": "tls", "reason": "x", "confident": false}',
                         "model": "m", "provider": "p"})
    observations = [Reading("tls", "observed", "runtime_observed", 0.9, "safe"), Reading("source", "built", "static_analysis", 0.5, "vulnerable")]
    assert adjudicate_conflict(pool, "a", observations).confidence < AGENT_CONFIDENCE


def test_an_unknown_owner_produces_nothing_rather_than_a_guess(pool, monkeypatch):
    monkeypatch.setattr(
        pool, "call",
        lambda *a, **k: {"ok": True, "text": '{"team": "unknown", "reason": "no signal"}',
                         "model": "m", "provider": "p"})
    assert infer_owner(pool, "host-01", "/etc/x") is None


def test_a_task_returns_nothing_when_the_pool_is_dry(pool):
    for key in pool.all():
        key.disabled_reason = "test"
    assert resolve_algorithm(pool, "x", "y") is None


# --------------------------------------------------------------------------
# Parsing what small models actually emit
# --------------------------------------------------------------------------


@pytest.mark.parametrize("text", [
    '{"algorithm": "RSA"}',
    'Sure! ```json\n{"algorithm": "RSA"}\n```',
    'Here you go: {"algorithm": "RSA"} hope that helps',
])
def test_json_is_recovered_from_the_prose_small_models_wrap_it_in(text):
    assert _extract_json(text)["algorithm"] == "RSA"


@pytest.mark.parametrize("text", ["", "no json here", "{broken", None])
def test_unparseable_output_returns_none_rather_than_raising(text):
    assert _extract_json(text) is None


def test_every_task_states_why_it_exists_and_what_it_targets():
    for name, meta in TASKS.items():
        assert meta["label"] and meta["why"] and meta["target"]


# --------------------------------------------------------------------------
# Thinking models
# --------------------------------------------------------------------------


def test_an_empty_completion_is_a_failure_not_a_success(pool, monkeypatch):
    """A 200 with no content would otherwise hand the caller an empty string to
    parse. The usual cause is a thinking model spending its whole budget on
    internal reasoning: finish_reason 'length', completion_tokens 0."""
    import httpx

    class FakeResponse:
        status_code = 200
        headers: dict = {}

        @staticmethod
        def raise_for_status():
            return None

        @staticmethod
        def json():
            return {
                "choices": [{
                    "finish_reason": "length",
                    "message": {"role": "assistant"},   # no content key at all
                }],
                "usage": {"completion_tokens": 0},
            }

    monkeypatch.setattr(httpx, "post", lambda *a, **k: FakeResponse())
    key = pool.all()[0]

    from engine.core.agents import _ModelFault

    with pytest.raises(_ModelFault) as excinfo:
        pool._http_call(key, "secret", [{"role": "user", "content": "x"}], 5.0, "m")
    assert "empty completion" in str(excinfo.value)
    assert "thinking model" in str(excinfo.value)


def test_the_real_call_path_leaves_room_for_a_thinking_model():
    """Stated as a test so the budget is not quietly trimmed: agent tasks return
    small JSON, but a thinking model must be able to reason before emitting it."""
    import inspect
    from engine.core.agents import AgentPool
    source = inspect.getsource(AgentPool._http_call)
    assert '"max_tokens": 1024' in source
