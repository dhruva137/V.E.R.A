"""The Risk screen's data (engine.risk_view) agrees with the engine, and its what-if stays a what-if."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from api.routes import state
from main import app

ESTATE = Path(__file__).resolve().parents[2] / "demo" / "estate" / "estate.yaml"


@pytest.fixture(scope="module")
def client():
    client = TestClient(app)
    assert client.post("/api/scan/full", json={"estate": str(ESTATE), "wait": True}).json()["status"] == "done"
    return client


def test_default_doubling_reproduces_the_engines_categories(client):
    view = client.get("/api/risk").json()
    assert view["what_if"] is False
    by_id = {a.id: a for a in state.assets}
    assert view["assets"], "the demo estate has quantum-vulnerable assets"
    for row in view["assets"]:
        assert row["category"] == by_id[row["id"]].mosca_category, row["name"]
    assert sum(view["totals"].values()) == len(state.assets)


def test_primitive_rows_carry_their_citation_and_shift(client):
    view = client.get("/api/risk").json()
    rsa = next(p for p in view["primitives"] if p["id"] == "rsa-2048")
    p256 = next(p for p in view["primitives"] if p["id"] == "ecdlp-p256")
    assert rsa["shift_years"] == 0.0 and rsa["url"].startswith("https://")
    assert p256["shift_years"] < 0  # fewer logical qubits: arrives earlier
    assert p256["z_years"]["median"] < rsa["z_years"]["median"]


def test_what_if_moves_the_band_but_never_the_stored_scores(client):
    before = {a.id: (a.mosca_category, a.qirs) for a in state.assets}
    slow = client.get("/api/risk", params={"doubling": 6.0}).json()
    fast = client.get("/api/risk", params={"doubling": 0.5}).json()
    assert slow["what_if"] and fast["what_if"]
    p256_slow = next(p for p in slow["primitives"] if p["id"] == "ecdlp-p256")["shift_years"]
    p256_fast = next(p for p in fast["primitives"] if p["id"] == "ecdlp-p256")["shift_years"]
    assert p256_slow < p256_fast < 0  # delta = D * log2(L_p / L_ref) scales with D
    assert {a.id: (a.mosca_category, a.qirs) for a in state.assets} == before


def test_doubling_outside_the_stated_range_is_rejected(client):
    assert client.get("/api/risk", params={"doubling": 0}).status_code == 422
