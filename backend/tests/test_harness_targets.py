"""The migration harness names the same target as the recommendation (engine.hybrid.replacement_for)."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from main import app

ESTATE = Path(__file__).resolve().parents[2] / "demo" / "estate" / "estate.yaml"


def test_signing_keys_become_signatures_and_non_swaps_are_reported():
    client = TestClient(app)
    assert client.post("/api/scan/full", json={"estate": str(ESTATE), "wait": True}).json()["status"] == "done"
    recs = {r["asset_id"]: r for r in client.get("/api/recommendations").json()["items"]}
    result = client.post("/api/harness/migrate", json={"target": "payments-gateway", "strategy": "hybrid"}).json()
    assert result["changes"] and result["migrated"] == len(result["changes"])
    for change in result["changes"]:
        rec = recs[change["asset_id"]]
        assert change["to"] == rec["recommended"]
        if rec["need"].startswith("signature"):
            assert "MLKEM" not in change["to"].upper().replace("-", "")
    # A leaked key or a library below its PQC release is not an algorithm swap.
    reasons = {s["need"] for s in result["skipped"]}
    assert "secret_exposure" in reasons and "library_upgrade" in reasons


def test_pqc_only_drops_the_classical_half_of_a_hybrid_group():
    from engine.hybrid import _pqc_only

    assert _pqc_only("X25519MLKEM768") == "ML-KEM-768"
    assert _pqc_only("SecP384r1MLKEM1024") == "ML-KEM-1024"
    assert _pqc_only("ML-DSA-65") == "ML-DSA-65"
