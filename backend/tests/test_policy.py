"""Engine policy as code — load, presets, pipeline threading, preview API."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from engine.core import scan_pipeline
from engine.core import policy as policy_mod
from engine.core.policy import (
    balanced_policy,
    list_presets,
    preset,
    sector_defaults,
    validate_policy,
)


@pytest.fixture(autouse=True)
def _reset_policy(tmp_path, monkeypatch):
    """Isolate each test from a persisted policy file on disk."""
    monkeypatch.setattr(policy_mod, "DATA_DIR", tmp_path)
    monkeypatch.setattr(policy_mod, "POLICY_FILE", tmp_path / "engine_policy.json")
    policy_mod._current = None
    yield
    policy_mod._current = None


class FakeAsset:
    def __init__(self, id, *, source_type="tls", quantum_vulnerable=True,
                 verdict="shor", qirs=0.1, slack_months=5.0, cert_serial=None,
                 raw_details=None, name=None, h_score=None, t_score=None):
        self.id = id
        self.name = name or id
        self.source_type = source_type
        self.quantum_vulnerable = quantum_vulnerable
        self.verdict = verdict
        self.qirs = qirs
        self.h_score = qirs if h_score is None else h_score
        self.t_score = qirs if t_score is None else t_score
        self.slack_months = slack_months
        self.cert_serial = cert_serial
        self.asset_class = "tls_certificate"
        self.risk_level = "high"
        self.raw_details = raw_details or {}


def test_default_load_matches_balanced_constants():
    pol = balanced_policy()
    assert pol.name == "balanced"
    assert pol.w_H == 0.5 and pol.w_T == 0.5
    assert pol.flag_threshold == 0.50
    assert pol.survival_curve_reading == "median"
    assert pol.provenance_confidences["runtime_observed"] == 0.98
    assert pol.risk_bands[0]["level"] == "high"
    assert "x_c" in pol.input_defaults
    # Per-class overrides come from qirs.PROFILES when available.
    assert "tls_certificate" in pol.asset_class_inputs


def test_preset_shapes():
    presets = list_presets()
    ids = {p["id"] for p in presets}
    assert ids == {"conservative", "balanced", "aggressive"}
    for entry in presets:
        body = entry["policy"]
        for key in (
            "version", "name", "description", "w_H", "w_T", "risk_bands",
            "flag_threshold",
            "provenance_confidences", "survival_curve_reading",
            "input_defaults", "asset_class_inputs",
        ):
            assert key in body
        assert body["survival_curve_reading"] in (
            "optimistic", "median", "pessimistic",
        )
        assert abs(body["w_H"] + body["w_T"] - 1.0) < 1e-9 or (
            0 <= body["w_H"] <= 1 and 0 <= body["w_T"] <= 1
        )

    cons = preset("conservative")
    aggr = preset("aggressive")
    assert cons.survival_curve_reading == "pessimistic"
    assert aggr.survival_curve_reading == "optimistic"
    # Conservative flags weak evidence sooner; aggressive only very weak evidence.
    assert cons.flag_threshold > balanced_policy().flag_threshold
    assert aggr.flag_threshold < balanced_policy().flag_threshold


def test_sector_defaults_from_packs():
    healthcare = sector_defaults("healthcare")
    assert "healthcare" in healthcare.name or "pack" in healthcare.description.lower()
    assert healthcare.w_H >= balanced_policy().w_H
    unknown = sector_defaults("no-such-sector-xyz")
    assert unknown.w_H == 0.5


def test_validate_rejects_bad_weights():
    with pytest.raises(ValueError):
        validate_policy({"w_H": -1, "w_T": 0.5})
    with pytest.raises(ValueError):
        validate_policy({"survival_curve_reading": "maybe"})


def test_pipeline_accepts_policy():
    assets = [
        FakeAsset("a", qirs=0.2, h_score=0.3, t_score=0.1),
        FakeAsset("b", qirs=0.2, h_score=0.1, t_score=0.3),
    ]
    balanced = scan_pipeline.run(assets)
    assert balanced.policy is not None
    assert balanced.policy["name"] == "balanced"

    # Heavier H weight should prefer asset a (higher h_score).
    h_heavy = preset("conservative")
    h_heavy.w_H, h_heavy.w_T = 0.9, 0.1
    h_run = scan_pipeline.run(assets, policy=h_heavy)
    assert h_run.ranked[0]["id"] == "a"

    t_heavy = preset("aggressive")
    t_heavy.w_H, t_heavy.w_T = 0.1, 0.9
    t_run = scan_pipeline.run(assets, policy=t_heavy)
    assert t_run.ranked[0]["id"] == "b"

    # Omitted policy must match an explicit balanced run (existing call sites).
    plain = scan_pipeline.run(assets)
    explicit = scan_pipeline.run(assets, policy=balanced_policy())
    assert [r["id"] for r in plain.ranked] == [r["id"] for r in explicit.ranked]


def test_preview_endpoint_shape():
    import main
    from api import routes

    client = TestClient(main.app)
    # Load a tiny estate so preview has something to rank.
    demo = client.post("/api/scan/demo", params={"org_persona": "Banking"})
    assert demo.status_code == 200

    presets = client.get("/api/engine/policy/presets")
    assert presets.status_code == 200
    body = presets.json()
    assert "presets" in body
    assert {p["id"] for p in body["presets"]} >= {"conservative", "balanced", "aggressive"}

    current = client.get("/api/engine/policy")
    assert current.status_code == 200
    assert "policy" in current.json()
    assert current.json()["policy"]["w_H"] == 0.5

    proposed = preset("conservative").to_dict()
    preview = client.post("/api/engine/policy/preview", json={"policy": proposed})
    assert preview.status_code == 200
    data = preview.json()
    for key in (
        "proposed", "current", "rank_moves", "moved_count",
        "flagged", "checks", "stats",
    ):
        assert key in data
    assert "current" in data["flagged"] and "proposed" in data["flagged"]
    assert "current" in data["checks"] and "proposed" in data["checks"]
    assert "checks_passed" in data["checks"]["proposed"]
    assert isinstance(data["rank_moves"], list)
    assert isinstance(data["moved_count"], int)

    # Save after preview.
    saved = client.put("/api/engine/policy", json={"policy": proposed})
    assert saved.status_code == 200
    assert saved.json()["saved"] is True
    assert saved.json()["policy"]["name"] == "conservative"

    # Clean up module estate so other API tests are not polluted.
    routes.state.assets = []
    routes._engine_run["run"] = None
