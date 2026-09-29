"""WP8: recommendations, measured cost, upgrade paths, who-can-fix, procurement clauses.

Acceptance: every quantum-vulnerable asset gets at least one
recommendation; profile switching changes targets as tabulated; classically
broken assets never get a quantum rationale; no latency without a measurement.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from engine import recommendations as rec
from engine.kb import libraries as kb
from engine.qirs import score_assets
from engine.threat_model import ThreatModel
from main import app
from models.schemas import CryptoAsset

ESTATE = Path(__file__).resolve().parents[2] / "demo" / "estate" / "estate.yaml"


def scored(**fields) -> CryptoAsset:
    fields.setdefault("id", "a")
    fields.setdefault("source_type", "config")
    asset = CryptoAsset(name="a", source_location="x", **fields)
    return score_assets([asset], ThreatModel())[0]


@pytest.fixture(scope="module")
def estate_client():
    client = TestClient(app)
    body = client.post("/api/scan/full", json={"estate": str(ESTATE), "wait": True}).json()
    assert body["status"] == "done"
    return client


# --------------------------------------------------------------------------
# Needs and targets
# --------------------------------------------------------------------------


@pytest.mark.parametrize("fields,need", [
    ({"asset_class": "tls_key_exchange", "key_exchange": "X25519", "usage": "key_exchange"}, "key_exchange"),
    ({"asset_class": "tls_certificate", "algorithm": "RSA", "key_size": 2048, "usage": "signing"},
     "signature_high_volume"),
    ({"asset_class": "root_ca", "algorithm": "RSA", "key_size": 4096, "usage": "signing"}, "signature_long_lived"),
    ({"asset_class": "firmware_signing", "algorithm": "ECDSA", "key_size": 256, "usage": "signing"},
     "signature_long_lived"),
    ({"asset_class": "generic_key", "algorithm": "RSA", "key_size": 2048, "usage": "encryption"}, "kem_at_rest"),
    ({"asset_class": "config", "algorithm": "3DES", "usage": "encryption"}, "replace_now"),
    ({"asset_class": "config", "algorithm": "AES-128", "usage": "encryption"}, "symmetric"),
    ({"asset_class": "source", "algorithm": None, "usage": "hashing"}, "resolve_first"),
    ({"asset_class": "embedded_private_key", "algorithm": "RSA", "usage": "signing"}, "secret_exposure"),
])
def test_need_for_each_kind_of_asset(fields, need):
    assert rec.need_for(scored(**fields), "commercial")[0] == need


def test_already_safe_assets_need_nothing():
    assert rec.recommend(scored(asset_class="config", algorithm="AES-256", usage="encryption"), "commercial") is None
    assert rec.recommend(scored(asset_class="tls_key_exchange", key_exchange="X25519MLKEM768",
                                usage="key_exchange"), "commercial") is None


@pytest.mark.parametrize("fields,commercial,cnsa", [
    ({"asset_class": "tls_key_exchange", "key_exchange": "X25519", "usage": "key_exchange"},
     "X25519MLKEM768", "ML-KEM-1024"),
    ({"asset_class": "tls_certificate", "algorithm": "ECDSA", "key_size": 256, "usage": "signing"},
     "ML-DSA-65", "ML-DSA-87"),
    ({"asset_class": "firmware_signing", "algorithm": "RSA", "key_size": 3072, "usage": "signing"},
     "SLH-DSA-SHA2-128s", "LMS / XMSS (firmware and software signing)"),
])
def test_profile_switch_changes_targets_as_tabulated(fields, commercial, cnsa):
    asset = scored(**fields)
    assert rec.recommend(asset, "commercial")["recommended"] == commercial
    assert rec.recommend(asset, "cnsa")["recommended"] == cnsa


def test_cnsa_upgrades_aes128_and_sha256_that_commercial_leaves_alone():
    sha = scored(asset_class="source", algorithm="SHA-256", usage="hashing")
    assert rec.recommend(sha, "commercial") is None
    assert rec.recommend(sha, "cnsa")["recommended"] == "SHA-384"
    aes = scored(asset_class="config", algorithm="AES-128", usage="encryption")
    assert rec.recommend(aes, "cnsa")["recommended"] == "AES-256"


def test_classically_broken_never_gets_a_quantum_rationale():
    for algorithm in ("DES", "3DES", "RC4", "MD5", "SHA-1"):
        item = rec.recommend(scored(asset_class="config", algorithm=algorithm, usage="encryption"), "commercial")
        assert item["need"] == "replace_now"
        text = (item["rationale"] + " " + item["why"]).lower()
        assert "independent of quantum" in text
        assert "crqc" not in text and "shor" not in text and "harvest" not in text


def test_draft_standards_are_never_recommended():
    targets = set()
    for need in rec.rules()["needs"].values():
        for profile in rec.PROFILES:
            targets.add(str(need[profile]["recommended"]))
            targets.update(map(str, need[profile].get("alternatives", [])))
    assert not any(t.startswith(("FN-DSA", "Falcon", "HQC")) for t in targets)


def test_every_citation_id_resolves():
    for need in rec.rules()["needs"].values():
        for cid in need.get("citations", []):
            assert cid in rec.rules()["citations"], cid


def test_unknown_profile_is_refused(monkeypatch):
    monkeypatch.setenv("VERA_PROFILE", "military")
    monkeypatch.setattr(rec, "_profile_override", {})
    with pytest.raises(ValueError):
        rec.active_profile()


# --------------------------------------------------------------------------
# Upgrade paths and ownership
# --------------------------------------------------------------------------


def test_library_below_threshold_becomes_an_upgrade_step():
    details = kb.details_for(kb.get("openssl"), "3.0.11")
    asset = scored(asset_class="crypto_library", raw_details=details)
    item = rec.recommend(asset, "commercial")
    assert item["need"] == "library_upgrade"
    assert item["recommended"] == "OpenSSL 3.5 LTS"
    assert item["upgrade_path"]["to_at_least"] == "3.5.0" and item["upgrade_path"]["from"] == "3.0.11"


@pytest.mark.parametrize("details,expected", [
    ({"change_blocked": True, "hsm_model": "payShield 10K", "hsm_pqc_ready": False}, "vendor_firmware_gated"),
    ({"discovered_by": "vault_cloud_kms", "key_ops": ["sign", "verify"], "kid": "https://kv.vault.azure.net/k"},
     "provider_gated"),
    ({"discovered_by": "vault_cloud_kms", "KeyUsage": "SIGN_VERIFY", "Arn": "arn:aws:kms:ap-south-1:1:key/x"},
     "self_managed"),
    ({"discovered_by": "tls_capture"}, "third_party"),
    ({"discovered_by": "tls_capture", "system": "payments"}, "self_managed"),
    ({}, "self_managed"),
])
def test_who_can_fix_it(details, expected):
    asset = scored(asset_class="tls_certificate", algorithm="RSA", key_size=2048, usage="signing",
                   source_type="tls" if "tls" in str(details) else "config", raw_details=details)
    assert rec.ownership(asset)["key"] == expected


# --------------------------------------------------------------------------
# Measured cost: never fabricated
# --------------------------------------------------------------------------


def test_no_latency_without_a_measurement(tmp_path, monkeypatch):
    monkeypatch.setattr(rec, "BENCH_PATH", tmp_path / "missing.json")
    cost = rec.cost_of("ML-DSA-65")
    assert cost["latency"] == [] and "Not measured" in cost["latency_note"]
    assert cost["sizes"] and cost["sizes"][0]["name"] == "ML-DSA-65"


def test_latency_is_quoted_with_host_date_and_method(tmp_path, monkeypatch):
    record = {"measured": True, "measured_at": "2026-09-24T05:00:00+00:00",
              "host": {"processor": "Test CPU", "machine": "x86_64"}, "tool": {"version": "3.5.4"},
              "results": [{"algorithm": "ML-KEM-768", "operation": "encapsulate", "microseconds": 29.0,
                           "per_second": 34484.6, "method": "openssl speed"},
                          {"algorithm": "X25519", "operation": "derive", "microseconds": 48.9,
                           "per_second": 20466.8, "method": "openssl speed"}]}
    path = tmp_path / "bench.json"
    path.write_text(json.dumps(record))
    monkeypatch.setattr(rec, "BENCH_PATH", path)
    cost = rec.cost_of("X25519MLKEM768")
    assert {r["algorithm"] for r in cost["latency"]} == {"ML-KEM-768", "X25519"}
    assert "Test CPU" in cost["latency_note"] and "2026-09-24" in cost["latency_note"]
    assert all(r["method"] for r in cost["latency"])


def test_committed_bench_record_is_honest():
    """The benchmark file in the repo either holds measurements with provenance or says it holds none."""
    record = json.loads(rec.BENCH_PATH.read_text(encoding="utf-8")) if rec.BENCH_PATH.is_file() else None
    if record is None:
        pytest.skip("no benchmark run committed")
    if not record["measured"]:
        assert record["results"] == []
        return
    assert record["measured_at"] and record["host"] and record["tool"]["version"]
    for r in record["results"]:
        assert r["method"] and r["per_second"] > 0 and r["microseconds"] > 0


# --------------------------------------------------------------------------
# Estate level
# --------------------------------------------------------------------------


def test_every_vulnerable_asset_in_the_demo_is_covered(estate_client):
    body = estate_client.get("/api/recommendations").json()
    assert body["uncovered_vulnerable"] == []
    assets = estate_client.get("/api/assets").json()
    vulnerable = {a["id"] for a in assets if a["quantum_vulnerable"]}
    assert vulnerable <= {i["asset_id"] for i in body["items"]}


def test_library_prerequisites_attach_by_system_and_stack(estate_client):
    body = estate_client.get("/api/recommendations").json()
    steps = {key: [s["step"] for s in value] for key, value in body["prerequisites"].items()}
    assert "OpenSSL 3.5 LTS" in steps["core-ledger|native"]
    assert "bcprov 1.79 or later" in steps["payments-gateway|java"]
    java = [i for i in body["items"] if i["system"] == "payments-gateway" and "CardVault.java" in i["asset"]
            and i["need"] in rec._MIGRATION_NEEDS]
    assert java and all("bcprov 1.79 or later" in [s["step"] for s in i["prerequisites"]] for i in java)
    rust = [i for i in body["items"] if "lib.rs" in i["asset"]]
    assert rust and all("prerequisites" not in i for i in rust)       # no Rust library is blocked


def test_gated_registers_and_clauses(estate_client):
    register = estate_client.get("/api/vendor-gated").json()["register"]
    kinds = {g["kind"] for g in register}
    assert kinds == {"vendor_firmware_gated", "provider_gated"}
    assert {"nShield Connect XC", "payShield 10K"} <= {g["who"] for g in register}
    clauses = estate_client.get("/api/procurement-clauses", params={"organisation": "Tejomaya Bank"}).json()["clauses"]
    assert len(clauses) == len(register)
    for clause in clauses:
        assert clause["status"] == "DRAFT FOR LEGAL REVIEW"
        assert "Tejomaya Bank" in clause["clause"] and "FIPS 203" in clause["clause"]
        assert any(c["id"] == "dst2026" for c in clause["citations"])


def test_profile_endpoint_round_trip(estate_client):
    assert estate_client.put("/api/profile", json={"profile": "cnsa"}).json() == {"profile": "cnsa"}
    kex = [i for i in estate_client.get("/api/recommendations").json()["items"] if i["need"] == "key_exchange"]
    assert kex and all(i["recommended"] == "ML-KEM-1024" for i in kex)
    estate_client.put("/api/profile", json={"profile": "commercial"})
    assert estate_client.put("/api/profile", json={"profile": "military"}).status_code == 400


def test_bench_endpoint(estate_client):
    body = estate_client.get("/api/bench").json()
    assert body["sizes"]
    assert body["measured"] is False or (body["results"] and body["measured_at"])
