"""Expiry and agility: the two operational signals that are not risk scores.

These cover the parts most likely to break silently - date parsing across the
formats certificate tooling actually emits, band boundaries, and the mapping
from asset class to changeability. A wrong band here is not a crash, it is a
dashboard confidently reporting that nothing expires this month.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from engine.agility import BANDS, agility_for
from engine.agility import summarise as agility_summary
from engine.expiry import (
    CRITICAL_DAYS,
    WARNING_DAYS,
    band_for,
    days_remaining,
    parse_expiry,
)
from engine.expiry import summarise as expiry_summary
from models.schemas import CryptoAsset

NOW = datetime(2026, 8, 24, 12, 0, 0, tzinfo=timezone.utc)


def asset(**kwargs) -> CryptoAsset:
    base = dict(
        id=kwargs.pop("id", "a1"),
        source_type="tls",
        source_location="host.example:443",
        name=kwargs.pop("name", "test asset"),
    )
    base.update(kwargs)
    return CryptoAsset(**base)


# --- date parsing --------------------------------------------------------


@pytest.mark.parametrize("value", [
    "2027-01-01T00:00:00Z",          # the Z form certificates use
    "2027-01-01T00:00:00+00:00",     # explicit offset
    "2027-01-01T00:00:00",           # naive, treated as UTC
])
def test_parse_expiry_accepts_the_forms_real_tooling_emits(value):
    parsed = parse_expiry(value)
    assert parsed is not None
    assert parsed.year == 2027
    # Every form must come back timezone-aware, or comparing against now() raises.
    assert parsed.tzinfo is not None


@pytest.mark.parametrize("value", [None, "", "   ", "not a date", "2027-13-45"])
def test_parse_expiry_returns_none_rather_than_raising(value):
    """A bad date is missing data, not a reason to fail a whole scan."""
    assert parse_expiry(value) is None


# --- bands ---------------------------------------------------------------


def test_band_boundaries_are_inclusive_on_the_urgent_side():
    assert band_for(None) == "none"
    assert band_for(-1) == "expired"
    assert band_for(0) == "critical"
    assert band_for(CRITICAL_DAYS) == "critical"
    assert band_for(CRITICAL_DAYS + 1) == "warning"
    assert band_for(WARNING_DAYS) == "warning"
    assert band_for(WARNING_DAYS + 1) == "ok"


def test_days_remaining_is_negative_once_lapsed():
    lapsed = asset(cert_validity_end=(NOW - timedelta(days=10)).isoformat())
    assert days_remaining(lapsed, NOW) == -10


def test_asset_without_a_certificate_has_no_expiry():
    assert days_remaining(asset(), NOW) is None
    assert band_for(days_remaining(asset(), NOW)) == "none"


# --- estate summary ------------------------------------------------------


def test_summary_counts_every_asset_exactly_once():
    assets = [
        asset(id="expired", cert_validity_end=(NOW - timedelta(days=5)).isoformat()),
        asset(id="critical", cert_validity_end=(NOW + timedelta(days=9)).isoformat()),
        asset(id="warning", cert_validity_end=(NOW + timedelta(days=60)).isoformat()),
        asset(id="ok", cert_validity_end=(NOW + timedelta(days=300)).isoformat()),
        asset(id="none"),
    ]
    result = expiry_summary(assets, now=NOW)

    assert result["counts"] == {
        "expired": 1, "critical": 1, "warning": 1, "ok": 1, "none": 1,
    }
    assert sum(result["counts"].values()) == len(assets)
    # Only dated assets are "tracked"; the undated one is not a silent pass.
    assert result["tracked"] == 4
    assert result["at_risk"] == 2  # expired + critical


def test_worst_list_is_soonest_first_then_widest_blast_radius():
    """Two certificates expiring the same day are not the same incident."""
    assets = [
        asset(id="leaf", name="leaf", cert_validity_end=(NOW + timedelta(days=5)).isoformat()),
        asset(id="anchor", name="anchor", cert_validity_end=(NOW + timedelta(days=5)).isoformat()),
        asset(id="later", name="later", cert_validity_end=(NOW + timedelta(days=40)).isoformat()),
    ]
    result = expiry_summary(assets, dependents={"anchor": 120, "leaf": 2}, now=NOW)

    order = [row["asset_id"] for row in result["worst"]]
    assert order == ["anchor", "leaf", "later"]


def test_summary_never_returns_the_whole_estate():
    """The dashboard needs numbers. An endpoint that can return every asset is
    the one that falls over first at scale."""
    assets = [
        asset(id=f"a{i}", cert_validity_end=(NOW + timedelta(days=i)).isoformat())
        for i in range(200)
    ]
    result = expiry_summary(assets, now=NOW, worst_limit=10)
    assert len(result["worst"]) == 10
    assert result["tracked"] == 200


def test_undated_assets_never_appear_in_the_worst_list():
    assets = [asset(id="x"), asset(id="y")]
    result = expiry_summary(assets, now=NOW)
    assert result["worst"] == []
    assert result["at_risk"] == 0


# --- agility -------------------------------------------------------------


def test_a_cipher_suite_is_a_config_change_and_firmware_is_not():
    """The whole point of the axis: same risk score, different feasibility."""
    suite = agility_for(asset(asset_class="tls_cipher_suite"))
    firmware = agility_for(asset(asset_class="firmware_signing"))

    assert suite["key"] == "config"
    assert suite["actionable_now"] is True
    assert firmware["key"] == "hardware_bound"
    assert firmware["actionable_now"] is False
    assert firmware["rank"] > suite["rank"]


def test_hsm_keys_are_reported_as_blocked_on_a_vendor():
    band = agility_for(asset(asset_class="payment_hsm"))
    assert band["key"] == "vendor_blocked"
    assert band["actionable_now"] is False


def test_unknown_asset_class_falls_back_to_the_middle_of_the_range():
    """Neither waved through as trivial nor written off as impossible."""
    band = agility_for(asset(asset_class="something_new"))
    assert band["key"] == "coordinated"


def test_profile_label_resolves_when_asset_class_is_missing():
    band = agility_for(asset(profile_label="Root certificate authority"))
    assert band["key"] == "programme"


def test_root_ca_label_does_not_fall_through_to_plain_certificate():
    """Ordering in the label hints is load-bearing: 'root certificate authority'
    contains 'certificate', and matching that first would call a root CA an
    automatable re-issue."""
    root = agility_for(asset(profile_label="Root certificate authority"))
    leaf = agility_for(asset(profile_label="TLS server certificate"))
    assert root["key"] == "programme"
    assert leaf["key"] == "automatable"


def test_agility_summary_splits_actionable_from_blocked():
    assets = [
        asset(id="1", asset_class="tls_cipher_suite"),
        asset(id="2", asset_class="tls_certificate"),
        asset(id="3", asset_class="firmware_signing"),
        asset(id="4", asset_class="payment_hsm"),
    ]
    result = agility_summary(assets)

    assert result["total"] == 4
    assert result["actionable_now"] == 2
    assert result["blocked"] == 2
    assert result["actionable_pct"] == 50.0
    assert sum(result["counts"].values()) == 4


def test_every_band_is_reachable_from_some_profile():
    """A band nothing maps to is dead weight in the UI legend."""
    from engine.agility import AGILITY_BY_PROFILE

    mapped = set(AGILITY_BY_PROFILE.values())
    for band in BANDS:
        assert band["key"] in mapped, f"no asset class maps to {band['key']}"


def test_summary_of_an_empty_estate_does_not_divide_by_zero():
    assert agility_summary([])["actionable_pct"] == 0.0
    assert expiry_summary([])["at_risk"] == 0
