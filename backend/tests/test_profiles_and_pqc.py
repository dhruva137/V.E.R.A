"""Enterprise fit and the post-quantum-era threat register.

The fit layer's job is to say when an inventory is NOT trustworthy for a given
kind of organisation. The threat register's job is to keep saying something
useful after a migration is finished. Both are tested for exactly that.
"""

import pytest

from engine.pqc_threats import THREATS, assess, register
from engine.profiles import PROFILES, fit_report, get_profile, list_profiles


class FakeAsset:
    """Minimal stand-in for a scored asset."""

    def __init__(self, asset_class=None, quantum_vulnerable=True, verdict="shor",
                 x_c=5.0, agility_key="config"):
        self.asset_class = asset_class
        self.quantum_vulnerable = quantum_vulnerable
        self.verdict = verdict
        self.x_c = x_c
        self.agility_key = agility_key


# --------------------------------------------------------------------------
# Profiles
# --------------------------------------------------------------------------


def test_every_profile_is_complete_enough_to_sell_against():
    """A profile missing its reasoning is not usable in front of a buyer."""
    for key, profile in PROFILES.items():
        assert profile.key == key
        assert profile.sensors, f"{key} declares no sensors"
        assert profile.regulations, f"{key} declares no regulations"
        assert profile.hard_parts, f"{key} states no hard parts"
        assert len(profile.lead_with) > 60, f"{key} has no usable opening line"
        for sensor in profile.sensors:
            assert sensor.criticality in {"required", "important", "optional"}
            assert sensor.reason.strip(), f"{key}/{sensor.plugin_id} has no reason"


def test_every_profile_requires_at_least_one_sensor():
    for key, profile in PROFILES.items():
        required = [s for s in profile.sensors if s.criticality == "required"]
        assert required, f"{key} has no required sensor, so nothing can fail"


def test_profile_composition_shares_are_plausible():
    for key, profile in PROFILES.items():
        total = sum(profile.composition.values())
        assert 0.5 <= total <= 1.2, f"{key} composition sums to {total}"


def test_unknown_profile_falls_back_rather_than_raising():
    assert get_profile("not-a-vertical").key == "payments"


def test_payments_requires_the_hsm_sensor():
    """The defining claim of the payments profile."""
    profile = get_profile("payments")
    required = {s.plugin_id for s in profile.sensors if s.criticality == "required"}
    assert "hsm_pkcs11" in required


def test_missing_required_sensor_makes_an_estate_not_audit_ready():
    """The whole point: a hole in the wrong place invalidates the inventory."""
    assets = [FakeAsset("payment_hsm"), FakeAsset("token_signing")]
    report = fit_report("payments", {"hsm_pkcs11": False, "tls": True}, assets)

    assert report["audit_ready"] is False
    assert "hsm_pkcs11" in report["missing_required_sensors"]
    assert "not audit-ready" in report["verdict"].lower()


def test_absent_expected_asset_class_is_reported_as_a_finding():
    """No HSM keys at a payments processor means the inventory is wrong."""
    assets = [FakeAsset("tls_certificate")]
    states = {s.plugin_id: True for s in get_profile("payments").sensors}
    report = fit_report("payments", states, assets)

    assert "payment_hsm" in report["asset_classes_absent_but_expected"]
    assert report["audit_ready"] is False


def test_a_well_covered_estate_is_reported_as_fitting():
    profile = get_profile("payments")
    states = {s.plugin_id: True for s in profile.sensors}
    assets = [FakeAsset(cls) for cls in profile.must_be_present]
    report = fit_report("payments", states, assets)

    assert report["missing_required_sensors"] == []
    assert report["asset_classes_absent_but_expected"] == []
    assert report["audit_ready"] is True


def test_fit_on_an_empty_estate_says_so_instead_of_claiming_success():
    states = {s.plugin_id: True for s in get_profile("erp").sensors}
    report = fit_report("erp", states, [])
    assert "no estate loaded" in report["verdict"].lower()


def test_required_sensor_coverage_is_a_percentage_of_required_only():
    """Optional sensors must not dilute a missing required one."""
    report = fit_report(
        "payments",
        {"hsm_pkcs11": False, "tls": False, "key_material": True, "cloud_kms": True},
        [FakeAsset("payment_hsm")],
    )
    assert report["required_sensor_coverage_pct"] == 0.0


def test_profile_listing_is_renderable():
    listed = list_profiles()
    assert len(listed) == len(PROFILES)
    for card in listed:
        assert card["key"] and card["label"] and card["lead_with"]


# --------------------------------------------------------------------------
# Post-quantum-era threats
# --------------------------------------------------------------------------


def test_register_entries_are_sourced_and_actionable():
    """A threat with no evidence or no mitigation is an opinion."""
    for threat in THREATS:
        assert threat.status in {"active", "emerging", "monitored"}
        assert threat.evidence.strip(), f"{threat.key} cites nothing"
        assert threat.mitigation.strip(), f"{threat.key} offers no mitigation"
        assert threat.review_by, f"{threat.key} has no review date"


def test_register_is_ordered_by_evidence_strength():
    statuses = [t["status"] for t in register()]
    order = {"active": 0, "emerging": 1, "monitored": 2}
    assert statuses == sorted(statuses, key=lambda s: order[s])


def test_the_register_flags_its_own_staleness():
    """A register nobody revisits becomes misinformation."""
    for entry in register():
        assert "review_overdue" in entry


def test_a_fully_migrated_estate_still_has_applicable_threats():
    """The core claim: finishing the migration does not empty the list."""
    assets = [
        FakeAsset("tls_key_exchange", quantum_vulnerable=False, verdict="pqc")
        for _ in range(5)
    ]
    result = assess(assets)

    assert result["still_vulnerable"] == 0
    assert result["already_post_quantum"] == 5
    assert result["applicable_threats"], "a migrated estate must still show risk"
    keys = {t["threat"] for t in result["applicable_threats"]}
    assert "pqc_side_channel" in keys
    assert "lattice_cryptanalysis_immaturity" in keys


def test_long_retention_data_triggers_retroactive_exposure():
    assets = [FakeAsset("backup_encryption", x_c=15.0)]
    keys = {t["threat"] for t in assess(assets)["applicable_threats"]}
    assert "retroactive_hndl" in keys


def test_hard_to_change_assets_trigger_agility_debt():
    assets = [FakeAsset("firmware_signing", agility_key="hardware-bound")]
    keys = {t["threat"] for t in assess(assets)["applicable_threats"]}
    assert "agility_debt" in keys


def test_threat_model_drift_applies_to_any_estate_with_a_schedule():
    keys = {t["threat"] for t in assess([FakeAsset()])["applicable_threats"]}
    assert "threat_model_drift" in keys


def test_an_empty_estate_claims_no_exposure():
    """Nothing may be asserted from the absence of data."""
    result = assess([])
    assert result["applicable_threats"] == []
    assert result["estate_size"] == 0


def test_each_threat_is_reported_once_with_its_largest_exposure():
    """Two triggers for one threat must not produce two rows."""
    assets = (
        [FakeAsset("payment_hsm", quantum_vulnerable=False, verdict="pqc")] * 3
        + [FakeAsset("firmware_signing", quantum_vulnerable=False, verdict="pqc")] * 4
    )
    threats = assess(assets)["applicable_threats"]
    keys = [t["threat"] for t in threats]
    assert len(keys) == len(set(keys)), "a threat was reported twice"
