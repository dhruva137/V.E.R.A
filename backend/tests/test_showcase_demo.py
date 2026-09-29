"""Offline showcase demo — vault in, ranked estate out, no network.

Imports demo/showcase/run_demo so CI fails when the synthetic vault stops
supporting the CISO script (asset count, firmware QIRS-top blocked, no key
material, sane correlation).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

SHOWCASE = Path(__file__).resolve().parents[2] / "demo" / "showcase"
if str(SHOWCASE) not in sys.path:
    sys.path.insert(0, str(SHOWCASE))

import run_demo  # noqa: E402


@pytest.fixture(scope="module")
def report():
    return run_demo.build_report()


def test_run_demo_main_exits_zero():
    assert run_demo.main(["--quiet"]) == 0


def test_expected_json_matches_measured_counts(report):
    expected = run_demo.load_expected()
    assert report["raw_count"] == expected["raw_objects"]
    assert report["asset_count"] == expected["assets"]
    assert report["correlated_away"] == expected["correlated_away"]
    assert report["blocked_count"] == expected["change_blocked"]
    assert run_demo.check_invariants(report, expected) == []


def test_no_key_material_in_findings(report):
    blob = report["findings_blob"]
    assert "BEGIN PRIVATE KEY" not in blob
    assert "BEGIN RSA PRIVATE KEY" not in blob
    from engine.intake.scrub import FORBIDDEN
    for field in FORBIDDEN:
        assert f'"{field}"' not in blob


def test_correlation_count_is_sane(report):
    """Raw → assets drops by exactly the dual-observed certs, not by a collapse
    of the HSM. Counts come from expected.json so the vault has one source of
    truth for its size."""
    expected = run_demo.load_expected()
    low, high = expected["assets_range"]
    assert report["raw_count"] - report["asset_count"] == expected["correlated_away"]
    assert low <= report["asset_count"] <= high
    assert report["by_source"]["vault_pkcs11"] == expected["by_source"]["vault_pkcs11"]
    assert report["max_corroboration"] == expected["max_corroboration"]


def test_five_adapter_contracts_printed(report):
    from adapters import list_adapter_ids

    ids = [c["id"] for c in report["adapter_cards"]]
    assert ids == list_adapter_ids()
    assert len(ids) == 5
    for card in report["adapter_cards"]:
        contract = card["coverage_contract"]
        assert contract["proves"]
        assert contract["cannot_prove"]
        assert contract["adapter_id"] == card["id"]


def test_firmware_is_qirs_top_and_blocked(report):
    top = report["qirs_top"]
    assert top["asset_class"] == "firmware_signing"
    assert "atm-firmware-sign" in top["name"]
    assert top["change_blocked"] is True
    assert 0.18 <= top["qirs"] <= 0.21


def test_rank1_is_the_most_exposed_asset(report):
    """The backlog leads with the widest Mosca margin in the most urgent category (WP7)."""
    assert report["rank1_most_exposed"] is True


def test_hndl_is_not_tnfl(report):
    assert report["top_hndl"]["id"] != report["top_tnfl"]["id"]
    assert report["top_tnfl"]["asset_class"] in {
        "root_ca", "firmware_signing", "issuing_ca",
    }


def test_invariants_fail_when_pem_leaks(report):
    expected = run_demo.load_expected()
    poisoned = dict(report)
    poisoned["findings_blob"] = json.dumps({
        "CKA_VALUE": "-----BEGIN PRIVATE KEY-----\nMIIE\n",
    })
    failures = run_demo.check_invariants(poisoned, expected)
    assert any("key material" in f or "CKA_VALUE" in f for f in failures)


def test_make_vault_is_importable():
    """showcase/make_all.py must keep loading the generator."""
    import importlib.util

    path = SHOWCASE.parent / "vault" / "make_vault.py"
    spec = importlib.util.spec_from_file_location("make_vault_probe", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert callable(module.main)
    payload = module.hsm_pkcs11()
    assert payload["slots"]
    for slot in payload["slots"]:
        for obj in slot["objects"]:
            assert obj["CKA_EXTRACTABLE"] is False
