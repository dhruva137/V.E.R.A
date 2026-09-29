"""Mosca's inequality per asset: categories, axes, and ordering."""

from __future__ import annotations

import pytest

from engine import mosca


class _A:
    def __init__(self, x_c=0.0, x_i=0.0, y=0.0, h=0.0, t=0.0, vulnerable=True):
        self.x_c, self.x_i, self.y = x_c, x_i, y
        self.h_score, self.t_score = h, t
        self.quantum_vulnerable = vulnerable


@pytest.fixture(scope="module")
def z():
    return mosca.arrival_years()


def test_arrivals_are_ordered_pessimistic_first(z):
    """Pessimistic means CRQC soonest; optimistic latest."""
    assert 0 < z["pessimistic"] <= z["median"] <= z["optimistic"]


def test_categories_follow_the_readings(z):
    far = z["optimistic"] + 5
    between_med_and_opt = (z["median"] + z["optimistic"]) / 2
    between_pes_and_med = (z["pessimistic"] + z["median"]) / 2
    near = max(z["pessimistic"] - 5, 0.1)

    def category(horizon):
        return mosca.assess(_A(x_c=horizon, y=0.0, h=0.5, t=0.1), arrivals=z)["category"]

    assert category(far) == "certain"
    # Horizons are compared strictly against each reading's arrival.
    if between_med_and_opt > z["median"]:
        assert category(between_med_and_opt) == "likely"
    if z["pessimistic"] < between_pes_and_med < z["median"]:
        assert category(between_pes_and_med) == "possible"
    assert category(near) == "clear"


def test_integrity_axis_uses_min_of_trust_life_and_migration(z):
    """A signing key retiring before CRQC is clear no matter how long migration takes."""
    retiring = _A(x_i=1.0, y=40.0, h=0.0, t=0.5)
    reading = mosca.assess(retiring, arrivals=z)
    assert reading["axis"] == "integrity"
    assert reading["integrity"]["plan"]["horizon_years"] == pytest.approx(1.0)
    assert reading["category"] == "clear"

    long_lived = _A(x_i=40.0, y=40.0, h=0.0, t=0.5)
    assert mosca.assess(long_lived, arrivals=z)["category"] == "certain"


def test_confidentiality_is_additive(z):
    # Pinned to the report date so the clock term is zero and the arithmetic is exact.
    reading = mosca.assess(_A(x_c=5.0, y=3.0, h=0.4, t=0.1), arrivals=z, now_year=mosca.clock(0)["report_year"])
    assert reading["axis"] == "confidentiality"
    assert reading["confidentiality"]["plan"]["horizon_years"] == pytest.approx(8.0)
    assert reading["margin_years"]["median"] == pytest.approx(8.0 - z["median"], abs=1e-3)


def test_not_vulnerable_is_not_applicable(z):
    reading = mosca.assess(_A(vulnerable=False), arrivals=z)
    assert reading["applicable"] is False
    assert reading["category"] == "not_applicable"


def test_raising_x_or_y_never_improves_the_category(z):
    base = mosca.assess(_A(x_c=4.0, y=2.0, h=0.4), arrivals=z)["category"]
    worse_x = mosca.assess(_A(x_c=20.0, y=2.0, h=0.4), arrivals=z)["category"]
    worse_y = mosca.assess(_A(x_c=4.0, y=20.0, h=0.4), arrivals=z)["category"]
    rank = mosca.category_rank
    assert rank(worse_x) <= rank(base)
    assert rank(worse_y) <= rank(base)


class _Scheduled(_A):
    def __init__(self, deadline, blocked=False, **kw):
        super().__init__(**kw)
        self.statutory_deadline_year = deadline
        self.raw_details = {"change_blocked": True} if blocked else {}


def test_y_on_the_statutory_schedule_is_time_until_the_deadline(z):
    """Migrating on the regulator's date means Y is the years left, not the effort."""
    asset = _Scheduled(deadline=2033, x_c=10.0, y=0.5, h=0.5)
    reading = mosca.assess(asset, arrivals=z, now_year=2026.0)
    assert reading["y_effort"] == pytest.approx(0.5)
    assert reading["y_plan"] == pytest.approx(7.0)
    assert reading["horizon_years"] == pytest.approx(17.0)
    assert reading["category"] == "certain"  # 17 yr beats even the latest Z (~15)
    # Starting today shrinks the window to 10.5 yr - the argument for acting now.
    assert reading["starting_now_helps"] is True
    assert mosca.category_rank(reading["category_if_started_now"]) > mosca.category_rank("certain")


def test_vendor_gating_adds_lead_time(z):
    free = mosca.assess(_Scheduled(deadline=2027, x_c=9.0, y=0.5, h=0.5), arrivals=z, now_year=2026.0)
    gated = mosca.assess(_Scheduled(deadline=2027, x_c=9.0, y=0.5, h=0.5, blocked=True),
                         arrivals=z, now_year=2026.0)
    assert gated["vendor_gated"] is True and free["vendor_gated"] is False
    assert gated["y_effort"] == pytest.approx(free["y_effort"] + mosca.DEFAULT_VENDOR_LEAD_YEARS)
    assert gated["y_plan"] >= free["y_plan"]


def test_effort_longer_than_the_deadline_is_not_hidden(z):
    """A migration that cannot finish by the deadline is scheduled by its effort."""
    reading = mosca.assess(_Scheduled(deadline=2027, x_c=2.0, y=6.0, h=0.5), arrivals=z, now_year=2026.0)
    assert reading["y_plan"] == pytest.approx(6.0)


def test_category_rank_order():
    assert [mosca.category_rank(c) for c in mosca.CATEGORIES] == [0, 1, 2, 3]
    assert mosca.category_rank("unknown") == len(mosca.CATEGORIES)
