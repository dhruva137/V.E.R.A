"""The one-call Overview, the declared-assumption cost model, and what "behind" means."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from engine import cost_model
from engine.recommendations import behind
from main import app
from models.schemas import CryptoAsset

ESTATE = Path(__file__).resolve().parents[2] / "demo" / "estate" / "estate.yaml"


def _item(asset_id: str, need: str, system: str = "pay", owner: str = "self_managed") -> dict:
    return {"asset_id": asset_id, "asset": asset_id, "need": need, "system": system,
            "who_can_fix": {"key": owner}}


def test_one_change_per_need_system_and_file():
    items = [_item("a", "replace_now"), _item("b", "replace_now"), _item("c", "replace_now"),
             _item("d", "key_exchange", owner="vendor_firmware_gated")]
    locations = {"a": "/etc/nginx.conf:4", "b": "/etc/nginx.conf:9", "c": "/etc/other.conf:1", "d": "hsm://x"}
    result = cost_model.estimate(items, locations)
    assert result["changes"] == 3  # a and b are one edit to nginx.conf
    assert result["person_days"] == 3 + 3 + 2 and result["gated_person_days"] == 2
    assert result["per_asset"]["a"] == {"person_days": 1.5, "change_person_days": 3.0, "shared_with": 1, "cost": None}
    # No declared day rate: person-days only, never an invented currency figure.
    assert result["cost"] is None and result["assumptions"]["currency"] is None


def test_register_declares_rate_and_overrides_effort():
    declared = {"currency": "INR", "day_rate": 20000, "effort_days": {"replace_now": 5}}
    result = cost_model.estimate([_item("a", "replace_now")], {"a": "x:1"}, declared, "estate.yaml")
    assert result["person_days"] == 5 and result["cost"] == 100000
    assert result["assumptions"]["effort_source"]["replace_now"] == "estate register (estate.yaml)"
    assert result["assumptions"]["effort_source"]["hash"] == "VERA planning default"
    with pytest.raises(ValueError):
        cost_model.estimate([], {}, {"day_rate": -1})


def test_a_safe_asset_with_negative_slack_is_not_behind():
    safe = CryptoAsset(id="k", name="k", source_type="keystore", asset_class="payment_hsm",
                       source_location="hsm://k", algorithm="AES-256", verdict="pqc", slack_months=-14.8)
    weak = safe.model_copy(update={"algorithm": "3DES", "verdict": "classical", "classically_broken": True})
    assert not behind(safe)
    assert behind(weak)


@pytest.fixture(scope="module")
def overview():
    client = TestClient(app)
    assert client.post("/api/scan/full", json={"estate": str(ESTATE), "wait": True}).json()["status"] == "done"
    return client, client.get("/api/overview").json()


def test_overview_numbers_agree_with_their_sources(overview):
    client, body = overview
    risk = client.get("/api/risk").json()
    dashboard = client.get("/api/dashboard").json()
    assert body["verdict"]["vulnerable"] == dashboard["quantum_vulnerable"]
    assert body["verdict"]["exposed"] == risk["totals"]["certain"] + risk["totals"]["likely"]
    assert [f["key"] for f in body["figures"]] == ["inventoried", "vulnerable", "exposed", "gated"]
    assert all(f["source"] for f in body["figures"])
    # "Behind" is one definition everywhere: the milestone track and the dashboard agree.
    assert sum(m["behind"] for m in body["milestones"]) == dashboard["negative_slack_count"]
    assert sum(s["behind"] for s in body["systems"]) == dashboard["negative_slack_count"]


def test_overview_track_do_next_coverage_and_evidence(overview):
    _, body = overview
    assert [(m["phase"], m["year"]) for m in body["milestones"]] == [
        ("foundation", 2027), ("high_priority", 2028), ("full", 2029)]  # the bank is on the CII track
    assert 0 < len(body["do_next"]) <= 5
    ranks = [row["priority_rank"] for row in body["do_next"]]
    assert ranks == sorted(ranks)
    assert all(row["owner"]["key"] and row["fix"] for row in body["do_next"])
    assert {s["collector"] for s in body["coverage"]["not_run"]} >= {"tls", "ssh"}  # the demo reads captures
    assert body["evidence"]["cbom"]["valid"] is True
    assert body["evidence"]["manifest"]["alg"] in ("ML-DSA-65", "Ed25519")
    assert body["cost"]["currency"] == "INR" and body["cost"]["day_rate"] == 18000
    assert body["systems"][-1]["in_register"] is False  # what the register does not declare comes last
