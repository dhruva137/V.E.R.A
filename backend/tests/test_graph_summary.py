"""The dependency summary must agree with the graph it projects.

If these two ever disagreed one of them would be wrong, and the Inventory's
"Breaks" column would quietly contradict the blast-radius page. They come from
the same `build_graph` call precisely so that cannot happen — this asserts it
stays that way.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from main import app


@pytest.fixture(scope="module")
def client():
    c = TestClient(app)
    c.post("/api/scan/demo?org_persona=Banking")
    return c


def test_summary_matches_the_full_graph_exactly(client):
    full = {n["id"]: n for n in client.get("/api/dependencies").json()["nodes"]}
    summary = client.get("/api/dependencies/summary").json()["assets"]

    assert set(summary) == set(full)
    for asset_id, row in summary.items():
        node = full[asset_id]
        assert row["dependents"] == node["dependents"]
        assert row["direct_dependents"] == node["direct_dependents"]
        assert row["confidence"] == node["confidence"]
        assert row["planes"] == node["planes"]
        assert row["flagged"] == node["flagged"]


def test_summary_is_substantially_smaller(client):
    """The whole reason it exists. At 10,000 assets the full projection is
    ~10 MB, downloaded to fill in four table columns."""
    full = len(client.get("/api/dependencies").content)
    summary = len(client.get("/api/dependencies/summary").content)
    assert summary * 3 < full


def test_summary_carries_the_aggregates_a_table_header_needs(client):
    stats = client.get("/api/dependencies/summary").json()["stats"]
    assert {"max_dependents", "flagged_nodes", "disagreement_nodes"} <= set(stats)


def test_summary_refuses_without_a_scan():
    """A zero where a number belongs would be believed. Say there is no scan."""
    from api.routes import state

    saved = list(state.assets)
    state.assets = []
    try:
        assert TestClient(app).get("/api/dependencies/summary").status_code == 409
    finally:
        state.assets = saved
