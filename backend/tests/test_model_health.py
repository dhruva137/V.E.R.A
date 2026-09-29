"""Model health: learning which models actually work.

Measured against a live gateway, direct free model IDs answered 2 times out of
8 while the gateway's own auto/* routes answered 10 out of 10. These tests fix
the behaviour that gap demands.
"""

import pytest

from engine.core.model_health import (
    BREAKER_THRESHOLD,
    ModelRecord,
    ModelRegistry,
)


@pytest.fixture
def registry(tmp_path):
    return ModelRegistry(tmp_path / "health.json")


# --------------------------------------------------------------------------
# Reliability
# --------------------------------------------------------------------------


def test_an_unproven_model_sits_in_the_middle_not_at_either_extreme():
    """Smoothing exists so one call cannot crown or condemn a model."""
    assert ModelRecord(model="new").reliability == 0.5


def test_one_success_does_not_make_a_model_perfect(registry):
    registry.record("m", ok=True, seconds=1.0)
    assert registry.get("m").reliability < 1.0


def test_one_failure_does_not_condemn_a_model(registry):
    registry.record("m", ok=False, kind="timeout")
    assert registry.get("m").reliability > 0.0


def test_reliability_tracks_the_real_ratio(registry):
    for _ in range(9):
        registry.record("good", ok=True, seconds=1.0)
    registry.record("good", ok=False, kind="http_500")
    assert registry.get("good").reliability > 0.75


def test_a_model_is_unproven_until_it_has_a_few_attempts(registry):
    registry.record("m", ok=True, seconds=1.0)
    assert registry.get("m").proven is False
    for _ in range(3):
        registry.record("m", ok=True, seconds=1.0)
    assert registry.get("m").proven is True


def test_latency_uses_the_median_not_the_mean(registry):
    """One 30-second timeout must not drag the estimate for a fast model."""
    for _ in range(9):
        registry.record("m", ok=True, seconds=1.0)
    registry.record("m", ok=True, seconds=30.0)
    assert registry.get("m").median_latency == 1.0


def test_the_latency_window_is_bounded(registry):
    for i in range(60):
        registry.record("m", ok=True, seconds=float(i))
    assert len(registry.get("m").latencies) <= 20


# --------------------------------------------------------------------------
# The circuit breaker
# --------------------------------------------------------------------------


def test_repeated_model_faults_open_the_circuit(registry):
    for _ in range(BREAKER_THRESHOLD):
        registry.record("bad", ok=False, kind="http_401", detail="model unavailable")
    available, reason = registry.get("bad").available()
    assert available is False
    assert "circuit open" in reason


def test_a_rate_limit_does_not_retire_a_working_model(registry):
    """A 429 is the provider rationing us, not the model being broken.
    Counting it against the model would retire something perfectly good."""
    for _ in range(BREAKER_THRESHOLD + 2):
        registry.record("m", ok=False, kind="rate_limit")
    assert registry.get("m").available()[0] is True


def test_a_success_closes_the_circuit(registry):
    for _ in range(BREAKER_THRESHOLD):
        registry.record("m", ok=False, kind="http_500")
    assert registry.get("m").available()[0] is False
    registry.record("m", ok=True, seconds=1.0)
    assert registry.get("m").available()[0] is True


def test_the_failure_reason_is_kept_for_the_operator(registry):
    registry.record("m", ok=False, kind="http_401", detail="Model not available")
    assert "Model not available" in registry.get("m").last_error


# --------------------------------------------------------------------------
# Selection
# --------------------------------------------------------------------------


def test_reliability_beats_speed(registry):
    """A fast model that fails is worthless."""
    for _ in range(10):
        registry.record("fast_flaky", ok=False, kind="http_500")
        registry.record("slow_solid", ok=True, seconds=20.0)
    assert registry.best(["fast_flaky", "slow_solid"]) == "slow_solid"


def test_speed_breaks_a_tie_on_reliability(registry):
    """This is the real measured case: auto/pro-* and auto/best-* both answer
    every time, and one is three times faster."""
    for _ in range(10):
        registry.record("auto/best", ok=True, seconds=16.0)
        registry.record("auto/pro", ok=True, seconds=5.5)
    assert registry.best(["auto/best", "auto/pro"]) == "auto/pro"


def test_an_unproven_model_is_explored_before_a_known_bad_one(registry):
    """Explore, but do not gamble: try something new before something watched
    to fail, and after something watched to work."""
    for _ in range(10):
        registry.record("known_bad", ok=False, kind="http_400")
        registry.record("known_good", ok=True, seconds=2.0)
    ranked = registry.rank(["known_bad", "unseen", "known_good"])
    assert ranked == ["known_good", "unseen", "known_bad"]


def test_broken_models_are_excluded_from_usable(registry):
    for _ in range(BREAKER_THRESHOLD):
        registry.record("bad", ok=False, kind="http_500")
    assert "bad" not in registry.usable(["bad", "fine"])


def test_best_returns_none_when_everything_is_broken(registry):
    for _ in range(BREAKER_THRESHOLD):
        registry.record("a", ok=False, kind="http_500")
        registry.record("b", ok=False, kind="http_400")
    assert registry.best(["a", "b"]) is None


def test_ranking_an_empty_candidate_list_is_safe(registry):
    assert registry.rank([]) == []
    assert registry.best([]) is None


# --------------------------------------------------------------------------
# Persistence
# --------------------------------------------------------------------------


def test_health_survives_a_restart(tmp_path):
    """Relearning which of 500 models work is expensive; the data is not
    secret, so it is kept."""
    path = tmp_path / "h.json"
    first = ModelRegistry(path)
    for _ in range(5):
        first.record("m", ok=True, seconds=2.0)
    first.save()

    second = ModelRegistry(path)
    assert second.get("m").successes == 5
    assert second.get("m").reliability > 0.7


def test_a_tripped_breaker_does_not_survive_a_restart(tmp_path):
    """The deadline is on a monotonic clock that resets, and a model cooling an
    hour ago deserves another try now."""
    path = tmp_path / "h.json"
    first = ModelRegistry(path)
    for _ in range(BREAKER_THRESHOLD):
        first.record("m", ok=False, kind="http_500")
    assert first.get("m").available()[0] is False
    first.save()

    assert ModelRegistry(path).get("m").available()[0] is True


def test_a_corrupt_health_file_is_ignored_rather_than_fatal(tmp_path):
    path = tmp_path / "h.json"
    path.write_text("{not json at all")
    assert ModelRegistry(path).report()["tracked"] == 0


def test_the_report_states_that_reliability_is_measured(registry):
    registry.record("m", ok=True, seconds=1.0)
    report = registry.report()
    assert report["tracked"] == 1
    assert "measured from real outcomes" in report["note"]


def test_a_timeout_under_load_does_not_retire_a_working_model(registry):
    """Measured against a live gateway: calling in a tight loop produced
    repeated failures from a model that answered in six seconds on its own.
    Counting those against the model retires something that works."""
    for _ in range(BREAKER_THRESHOLD + 3):
        registry.record("good_under_load", ok=False, kind="transient")
    assert registry.get("good_under_load").available()[0] is True


def test_only_definite_upstream_refusals_trip_the_breaker(registry):
    for kind in ("http_400", "http_401", "http_404", "http_500", "empty", "sse"):
        name = f"m_{kind}"
        for _ in range(BREAKER_THRESHOLD):
            registry.record(name, ok=False, kind=kind)
        assert registry.get(name).available()[0] is False, kind

    for kind in ("rate_limit", "transient", "timeout", "credential"):
        name = f"ok_{kind}"
        for _ in range(BREAKER_THRESHOLD + 2):
            registry.record(name, ok=False, kind=kind)
        assert registry.get(name).available()[0] is True, kind


def test_an_untried_model_beats_one_that_keeps_failing(registry):
    """A model with a poor record must not outrank an untried one merely
    because it has a record. Without this the pool never falls through to a
    working alternative."""
    for _ in range(6):
        registry.record("failing", ok=False, kind="transient")   # never breaks the circuit
    assert registry.get("failing").available()[0] is True
    assert registry.get("failing").reliability < 0.5
    assert registry.best(["failing", "untried"]) == "untried"
