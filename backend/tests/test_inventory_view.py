"""The inventory rows, their filter counts, and the asset panel (engine/inventory_view.py)."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from main import app

ESTATE = Path(__file__).resolve().parents[2] / "demo" / "estate" / "estate.yaml"


@pytest.fixture(scope="module")
def client():
    client = TestClient(app)
    assert client.post("/api/scan/full", json={"estate": str(ESTATE), "wait": True}).json()["status"] == "done"
    return client


def test_rows_and_facets_agree_with_the_dashboard(client):
    body = client.get("/api/inventory").json()
    dashboard = client.get("/api/dashboard").json()
    rows = body["rows"]
    assert len(rows) == dashboard["total_assets"]
    status = {f["value"]: f["count"] for f in body["facets"]["status"]}
    assert sum(status.values()) == len(rows)
    assert status["broken"] == dashboard["classically_broken"]
    flags = {f["value"]: f["count"] for f in body["facets"]["flags"]}
    assert flags["behind"] == dashboard["negative_slack_count"]
    # A row is small: no scoring inputs, no raw details.
    assert "raw_details" not in rows[0] and "h_score" not in rows[0]


def test_panel_has_every_section_with_evidence_and_the_fix(client):
    rows = client.get("/api/inventory").json()["rows"]
    row = next(r for r in rows if r["drift"] and r["need"])
    panel = client.get(f"/api/assets/{row['id']}/panel").json()
    assert set(panel) >= {"summary", "evidence", "risk", "fix", "dependencies", "history"}
    assert panel["summary"]["owner"]  # from the estate register's system owner
    assert panel["evidence"]["refs"] and panel["evidence"]["drift"]
    assert panel["fix"]["recommended"] and panel["fix"]["cost_estimate"]["person_days"] > 0
    assert panel["risk"]["mosca"]["asset"]["id"] == row["id"] and panel["risk"]["derivation"]["hndl"]["formula"]
    assert panel["history"] and panel["history"][0]["verdict"] == row["verdict"]


def test_panel_for_a_trust_anchor_lists_its_dependents(client):
    graph = client.get("/api/dependencies").json()
    anchor = max(graph["nodes"], key=lambda n: n["dependents"])
    panel = client.get(f"/api/assets/{anchor['id']}/panel").json()
    assert panel["dependencies"]["transitive_dependents"] == anchor["dependents"] > 0
    assert panel["dependencies"]["dependents"]


def test_safe_asset_says_why_nothing_is_needed(client):
    rows = client.get("/api/inventory").json()["rows"]
    safe = next(r for r in rows if r["status"] == "safe" and not r["need"])
    fix = client.get(f"/api/assets/{safe['id']}/panel").json()["fix"]
    assert fix["need"] is None and fix["why"]
