"""WP7: per-primitive horizon, explicit Mosca with data-class X, versioned threat model.

Property tests: more qubits never mean an earlier Z; D = 0 or an
unverified row reproduces the reference; raising X or Y never lowers risk; the
ordering is deterministic; the calendar moves scores only through the clock.
"""

from __future__ import annotations

import pytest
from hypothesis import given, settings, strategies as st

from engine import classification, mosca
from engine import quantum_resources as qr
from engine.qirs import order_assets, score_assets
from engine.threat_model import ThreatModel
from models.schemas import CryptoAsset


@pytest.fixture(scope="module")
def z():
    return mosca.arrival_years()


def report_year() -> float:
    return mosca.clock(0)["report_year"]


def asset(algorithm="RSA", key_size=2048, *, x_c=5.0, y=1.0, h=0.4, t=0.1, curve=None, **details):
    a = CryptoAsset(id=f"{algorithm}-{key_size}-{curve}-{x_c}-{y}", name="a", source_type="config",
                    source_location="x", algorithm=algorithm, key_size=key_size, curve=curve,
                    raw_details=details)
    a.quantum_vulnerable, a.verdict = True, "shor"
    a.x_c, a.y, a.h_score, a.t_score = x_c, y, h, t
    return a


# --------------------------------------------------------------------------
# Per-primitive horizon
# --------------------------------------------------------------------------


@settings(max_examples=60, deadline=None)
@given(st.floats(100, 20000), st.floats(100, 20000), st.floats(0.1, 5.0))
def test_more_qubits_never_arrive_earlier(a, b, d):
    low, high = sorted((a, b))
    assert qr.shift_years(low, 1409, d) <= qr.shift_years(high, 1409, d)


def test_p256_arrives_earlier_than_rsa_2048_with_a_citation():
    p256 = qr.shift_for("ECDSA", 256, "P-256", doubling=2.0)
    rsa = qr.shift_for("RSA", 2048, doubling=2.0)
    assert rsa["delta_years"] == 0.0
    assert p256["delta_years"] == pytest.approx(2.0 * -0.2400, abs=2e-3)
    assert "eprint.iacr.org/2026/280" in p256["row"]["url"]
    assert "1,193" in p256["basis"]


@pytest.mark.parametrize("algorithm,key_size,curve", [
    ("RSA", 3072, None), ("RSA", 4096, None), ("ECDSA", 384, None), ("X25519", None, None), ("DH", 2048, None),
])
def test_unverified_rows_fall_back_to_the_reference_and_say_so(algorithm, key_size, curve):
    shift = qr.shift_for(algorithm, key_size, curve, doubling=2.0)
    assert shift["delta_years"] == 0.0
    assert shift["row"]["status"] == "not_established"
    assert shift["basis"]


def test_zero_doubling_time_reproduces_the_reference():
    for row in qr.resources()["rows"]:
        shift = qr.shift_for(row["algorithms"][0], (row.get("key_sizes") or [None])[0],
                             (row.get("curves") or [None])[0], doubling=0.0)
        assert shift["delta_years"] == 0.0


def test_mosca_z_is_shifted_per_primitive(z):
    now = report_year()
    ec = mosca.assess(asset("ECDSA", 256, curve="P-256"), arrivals=z, now_year=now)
    rsa = mosca.assess(asset("RSA", 2048), arrivals=z, now_year=now)
    for reading in mosca.READINGS:
        assert ec["z"][reading] < rsa["z"][reading]
        assert rsa["z"][reading] == pytest.approx(z[reading])
    assert ec["z_shift"]["row"]["id"] == "ecdlp-p256"


# --------------------------------------------------------------------------
# Clock and versions
# --------------------------------------------------------------------------


def test_the_calendar_moves_z_only_through_the_clock(z):
    start = report_year()
    before = mosca.assess(asset(), arrivals=z, now_year=start + 1.0)
    after = mosca.assess(asset(), arrivals=z, now_year=start + 3.5)
    for reading in mosca.READINGS:
        assert before["z"][reading] - after["z"][reading] == pytest.approx(2.5, abs=1e-3)
    assert after["clock"]["elapsed_years"] - before["clock"]["elapsed_years"] == pytest.approx(2.5, abs=1e-3)
    assert before["z_shift"] == after["z_shift"]


def test_before_the_report_date_the_clock_is_zero(z):
    assert mosca.assess(asset(), arrivals=z, now_year=2020.0)["clock"]["elapsed_years"] == 0.0


def test_resources_table_matches_the_current_version():
    """Change quantum_resources.yaml and this fails until a new version with a changelog is added."""
    version = qr.current_version()
    assert qr.table_hash() == version["resources_table_hash"], (
        "The resources table changed. Add a version to kb/threat_model_versions.json with the new hash "
        f"({qr.table_hash()}) and a changelog entry.")


def test_every_version_has_a_changelog_and_is_unique():
    versions = qr.versions()
    assert len({v["version"] for v in versions}) == len(versions)
    for v in versions:
        assert v["changelog"].strip() and v["gri_edition"] and v["report_date"] and v["D"] > 0


def test_pinning_an_unknown_version_is_refused(monkeypatch):
    monkeypatch.setenv("VERA_THREAT_MODEL", "1999.01.1")
    with pytest.raises(ValueError, match="not a known threat-model version"):
        qr.current_version()


def test_manifest_records_the_threat_model_version():
    from engine.core import scan_pipeline

    run = scan_pipeline.run([asset()])
    assert run.manifest["threat_model_version"] == qr.current_version()["version"]
    assert run.manifest["resources_table_hash"] == qr.table_hash()


# --------------------------------------------------------------------------
# X from data classification, monotonicity, ordering
# --------------------------------------------------------------------------


def test_x_comes_from_the_longest_lived_data_class():
    a = asset(data_classes=["payment_card", "customer_pii", "made_up"], criticality="critical")
    a.s = 0.5
    record = classification.apply(a)
    assert a.x_c == 20.0 and record["lifetime"]["driving_class"] == "customer_pii"
    assert record["unknown_data_classes"] == ["made_up"]
    assert a.s == pytest.approx(0.95) and record["criticality"]["s_before"] == 0.5


def test_operator_override_wins_over_the_class_default():
    a = asset(data_classes=["financial_records"], x_years_override=3)
    classification.apply(a)
    assert a.x_c == 3.0 and a.raw_details["classification"]["lifetime"]["source"] == "operator override"


def test_without_classes_the_profile_default_stays_and_is_labelled():
    a = asset(x_c=7.0)
    classification.apply(a)
    assert a.x_c == 7.0 and a.raw_details["classification"]["lifetime"]["source"] == "asset-class default"


@settings(max_examples=40, deadline=None)
@given(st.floats(0, 30), st.floats(0, 30), st.floats(0, 10), st.floats(0, 10))
def test_raising_x_or_y_never_lowers_exposure(x1, x2, y1, y2):
    z = mosca.arrival_years()
    now = report_year()
    lo = mosca.assess(asset(x_c=min(x1, x2), y=min(y1, y2)), arrivals=z, now_year=now)
    hi = mosca.assess(asset(x_c=max(x1, x2), y=max(y1, y2)), arrivals=z, now_year=now)
    assert mosca.category_rank(hi["category"]) <= mosca.category_rank(lo["category"])
    for reading in mosca.READINGS:
        assert hi["margin_years"][reading] >= lo["margin_years"][reading]
        low_p = lo["probability_crqc_within_horizon"][reading]
        assert hi["probability_crqc_within_horizon"][reading] >= low_p - 1e-9


def test_ordering_is_deterministic():
    model = ThreatModel()
    estate = [asset(alg, size, x_c=x, y=y) for alg, size, x, y in
              [("RSA", 2048, 20, 2), ("ECDSA", 256, 10, 1), ("RSA", 3072, 5, 3), ("RSA", 2048, 1, 0.5)]]
    first = [a.id for a in order_assets(score_assets([a.model_copy(deep=True) for a in estate], model), model)]
    second = [a.id for a in order_assets(score_assets([a.model_copy(deep=True) for a in estate], model), model)]
    assert first == second


def test_mosca_endpoint_shows_the_source_of_every_number():
    from fastapi.testclient import TestClient

    from main import app

    client = TestClient(app)
    client.post("/api/scan/demo")
    target = next(a for a in client.get("/api/assets").json() if a["quantum_vulnerable"])
    reading = client.get(f"/api/mosca/{target['id']}").json()
    assert {"z", "z_reference", "z_shift", "clock", "x_basis", "probability_crqc_within_horizon",
            "classification", "y_basis"} <= set(reading)
    model = client.get("/api/threat-model").json()
    assert model["versioned"]["table_matches_version"] is True
    assert any(row["id"] == "ecdlp-p256" and row["shift"] < 0 for row in model["versioned"]["rows"])
