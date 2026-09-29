"""The demo estate (demo/estate) exercises every PS surface and every drift rule.

This pins the demo's story so a rule or collector change that silently breaks
it fails here, not in front of the judges.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from main import app

ESTATE = Path(__file__).resolve().parents[2] / "demo" / "estate" / "estate.yaml"


@pytest.fixture(scope="module")
def scanned():
    client = TestClient(app)
    body = client.post("/api/scan/full", json={"estate": str(ESTATE), "wait": True}).json()
    assert body["status"] == "done", body
    return client, body


def test_every_drift_rule_fires_on_the_demo(scanned):
    client, _ = scanned
    fired = {r["rule"] for r in client.get("/api/drift").json()["records"]}
    assert fired == {f"D{i}" for i in range(1, 9)}


def test_every_surface_contributes(scanned):
    client, body = scanned
    log = client.get(f"/api/scan/jobs/{body['job_id']}").json()["event_log"]
    produced = {e["collector"] for e in log if e["type"] == "collector_finished" and e["findings"]}
    assert produced >= {"source", "dependency", "container", "config", "capture", "vault"}
    assert not [e for e in log if e["type"] == "collector_failed"]


def test_cross_plane_assets_and_systems(scanned):
    client, body = scanned
    assert body["result"]["cross_plane_assets"] >= 4
    assets = client.get("/api/assets").json()
    assert len(assets) > 200
    systems = {a["raw_details"].get("system") for a in assets} - {None}
    assert {"payments-gateway", "core-ledger", "mobile-api", "customer-portal", "ops-bastion"} <= systems
