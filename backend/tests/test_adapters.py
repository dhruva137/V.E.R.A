"""Adapter catalog — honest capability surface, no fabricated counts."""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from adapters import describe_adapters, list_adapter_ids
from engine.discovery import surface


EXPECTED_ADAPTER_IDS = {"pkcs11", "kmip", "cloud_kms", "tls", "keystore"}


@pytest.fixture
def client():
    import main
    return TestClient(main.app)


def test_adapter_catalog_lists_the_five():
    assert set(list_adapter_ids()) == EXPECTED_ADAPTER_IDS
    cards = describe_adapters()
    assert {c["id"] for c in cards} == EXPECTED_ADAPTER_IDS


def test_every_adapter_states_cannot_prove():
    for card in describe_adapters():
        contract = card["coverage_contract"]
        assert contract["cannot_prove"], f"{card['id']} must state what it cannot prove"
        assert contract["proves"], f"{card['id']} must state what it proves"
        assert contract["requires"], f"{card['id']} must state what it requires"
        assert "asset_count" not in card
        assert "assets" not in card.get("measurement", {})


def test_vault_files_are_file_dump_not_live_active(tmp_path):
    """A dump on disk is measurable via file dump — not live Active connectivity."""
    (tmp_path / "hsm_pkcs11.json").write_text(json.dumps({"slots": []}))
    (tmp_path / "kmip.json").write_text(json.dumps({"objects": []}))
    (tmp_path / "cloud_kms.json").write_text(json.dumps({"keys": []}))
    cards = {c["id"]: c for c in describe_adapters(tmp_path)}
    for aid in ("pkcs11", "kmip", "cloud_kms"):
        m = cards[aid]["measurement"]
        assert m["mode"] == "file_dump"
        assert m["label"] == "Measurable via file dump"
        assert m["live_configured"] is False
        assert m["vault_files_present"]


def test_missing_vault_files_stay_unmeasured(tmp_path):
    cards = {c["id"]: c for c in describe_adapters(tmp_path)}
    for aid in ("pkcs11", "kmip", "cloud_kms", "tls", "keystore"):
        assert cards[aid]["measurement"]["mode"] == "unavailable"
        assert cards[aid]["measurement"]["live_configured"] is False


def test_discovery_surface_includes_adapters_with_coverage():
    data = surface()
    assert "adapters" in data
    ids = {a["id"] for a in data["adapters"]}
    assert ids == EXPECTED_ADAPTER_IDS
    for adapter in data["adapters"]:
        assert "cannot_prove" in adapter["coverage_contract"]
        assert adapter["measurement"]["live_configured"] is False


def test_adapter_backed_plugins_expose_coverage_contract():
    """hsm_pkcs11 / kmip / cloud_kms / keystore / tls carry the adapter contract."""
    plugins = {p["id"]: p for p in surface()["plugins"]}
    for plugin_id, adapter_id in (
        ("hsm_pkcs11", "pkcs11"),
        ("kmip", "kmip"),
        ("cloud_kms", "cloud_kms"),
        ("keystore", "keystore"),
        ("tls", "tls"),
    ):
        card = plugins[plugin_id]
        assert "coverage_contract" in card
        assert card["coverage_contract"]["cannot_prove"]
        assert card["coverage_contract"].get("adapter_id", adapter_id) == adapter_id


def test_live_connectors_remain_blind_spots_even_with_demo_vault():
    """File dump ≠ live credentials. Blind spots stay for PKCS#11 / KMIP / cloud."""
    data = surface()
    blind_ids = {b["id"] for b in data["coverage"]["blind_spots"]}
    assert "hsm_pkcs11" in blind_ids
    assert "kmip" in blind_ids
    assert "cloud_kms" in blind_ids
    # Demo vault present → status says file dump, not Active.
    plugins = {p["id"]: p for p in data["plugins"]}
    for pid in ("hsm_pkcs11", "kmip", "cloud_kms"):
        assert plugins[pid]["available"] is False
        if plugins[pid].get("measurement", {}).get("mode") == "file_dump":
            assert plugins[pid].get("status_label") == "Measurable via file dump"


def test_adapters_api_endpoint(client):
    response = client.get("/api/adapters")
    assert response.status_code == 200
    body = response.json()
    assert set(body["ids"]) == EXPECTED_ADAPTER_IDS
    assert len(body["adapters"]) == 5
    for card in body["adapters"]:
        assert card["coverage_contract"]["cannot_prove"]
        # Never fabricate live inventory size on the capability surface.
        serialised = str(card).lower()
        assert "2341" not in serialised
        assert "asset_count" not in card
