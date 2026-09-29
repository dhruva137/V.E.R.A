"""CBOM fields CERT-In requires (BOM guidelines v2.0, Table 9), and the conformance report.

The conformance check reads the exported document, so these tests build small
estates, export them, and check both the CBOM fields and what the report says.
"""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from engine import certin
from engine.cbom import generate_cbom
from engine.cbom_import import cbom_to_findings
from engine.cbom_validate import validate_cbom
from engine.schema_validation import validate_cyclonedx
from main import app
from models.schemas import CryptoAsset

STAMP = "2026-09-25T00:00:00Z"
ESTATE = Path(__file__).resolve().parents[2] / "demo" / "estate" / "estate.yaml"


def _asset(**fields) -> CryptoAsset:
    base = {"name": "asset", "source_type": "keystore", "asset_class": "generic_key",
            "source_location": "vault://demo"}
    return CryptoAsset(**{**base, **fields})


def _components(document, asset_type):
    return [c for c in document["components"] if c.get("cryptoProperties", {}).get("assetType") == asset_type]


def test_kmip_key_carries_id_state_and_dates():
    key = _asset(id="k1", algorithm="RSA", key_size=3072, usage="Sign,Decrypt", raw_details={
        "discovered_by": "vault_kmip", "Unique Identifier": "KMIP-0042", "State": "Active",
        "Initial Date": "2025-01-01T00:00:00Z", "Activation Date": "2025-01-05T00:00:00Z"})
    doc = generate_cbom([key], "t", timestamp=STAMP)
    props = _components(doc, "related-crypto-material")[0]["cryptoProperties"]["relatedCryptoMaterialProperties"]
    assert props["id"] == "KMIP-0042" and props["state"] == "active"
    assert props["creationDate"] == "2025-01-01T00:00:00Z" and props["activationDate"] == "2025-01-05T00:00:00Z"
    alg = _components(doc, "algorithm")[0]["cryptoProperties"]["algorithmProperties"]
    assert alg["cryptoFunctions"] == ["sign", "decrypt"]


def test_key_state_is_evidenced_never_assumed():
    expired = _asset(id="k2", algorithm="RSA", key_size=2048, cert_validity_start="2020-01-01",
                     cert_validity_end="2024-01-01", raw_details={"discovered_by": "vault_keystore"})
    unknown = _asset(id="k3", algorithm="RSA", key_size=2048, raw_details={"discovered_by": "vault_keystore"})
    doc = generate_cbom([expired, unknown], "t", timestamp=STAMP)
    states = [c["cryptoProperties"]["relatedCryptoMaterialProperties"].get("state")
              for c in _components(doc, "related-crypto-material")]
    assert len(states) == 2 and set(states) == {"deactivated", None}  # no evidence, no claim


def test_cipher_suite_splits_into_parts_with_mode():
    suite = _asset(id="s1", source_type="config", asset_class="tls_cipher_suite", source_location="nginx.conf:5",
                   algorithm="ECDHE-RSA-AES256-GCM-SHA384", cipher_suite="ECDHE-RSA-AES256-GCM-SHA384")
    doc = generate_cbom([suite], "t", timestamp=STAMP)
    names = {c["name"] for c in _components(doc, "algorithm")}
    assert {"ECDHE", "AES-256-GCM", "SHA-384"} <= names
    aes = next(c for c in _components(doc, "algorithm") if c["name"] == "AES-256-GCM")
    assert aes["cryptoProperties"]["algorithmProperties"]["mode"] == "gcm"
    protocol = _components(doc, "protocol")[0]["cryptoProperties"]["protocolProperties"]
    assert protocol["type"] == "tls" and len(protocol["cipherSuites"][0]["algorithms"]) >= 3
    # The parts fold back into one asset on import.
    assert len(cbom_to_findings(doc)) == 1


def test_libraries_are_library_components_with_purl_and_survive_import():
    lib = _asset(id="l1", source_type="dependency", asset_class="crypto_library", usage="library",
                 source_location="requirements.txt:1", raw_details={
                     "library": "pyca/cryptography", "package": "cryptography", "library_version": "41.0.7",
                     "ecosystem": "pypi", "pqc_native_from": "None"})
    doc = generate_cbom([lib], "t", timestamp=STAMP)
    component = next(c for c in doc["components"] if c["type"] == "library")
    assert component["name"] == "cryptography" and component["purl"] == "pkg:pypi/cryptography@41.0.7"
    assert validate_cyclonedx(doc, "1.7") == [] and validate_cbom(doc)["valid"]
    back = cbom_to_findings(doc)
    assert [f.asset_class for f in back] == ["crypto_library"]
    assert back[0].raw_details["library"] == "pyca/cryptography"


def test_conformance_counts_present_missing_and_not_applicable():
    key = _asset(id="k4", algorithm="RSA", key_size=2048, raw_details={"discovered_by": "vault_keystore"})
    hybrid = _asset(id="h1", source_type="tls", asset_class="tls_key_exchange", key_exchange="X25519MLKEM768",
                    source_location="a:443")
    report = certin.conformance(generate_cbom([key, hybrid], "t", timestamp=STAMP))
    keys = next(t for t in report["by_type"] if t["asset_type"] == "related-crypto-material")
    creation = next(e for e in keys["elements"] if e["element"] == "Creation date")
    assert creation["present"] == 0 and creation["missing_reasons"]
    algorithms = next(t for t in report["by_type"] if t["asset_type"] == "algorithm")
    oid = next(e for e in algorithms["elements"] if e["element"] == "OID")
    assert oid["not_applicable"] == 1 and "codepoints" in oid["na_reason"]
    assert 0 < report["percent"] < 100


def test_conformance_endpoint_on_the_demo_estate():
    client = TestClient(app)
    assert client.post("/api/scan/full", json={"estate": str(ESTATE), "wait": True}).json()["status"] == "done"
    report = client.get("/api/certin-conformance").json()
    certificates = next(t for t in report["by_type"] if t["asset_type"] == "certificate")
    assert all(e["percent"] == 100.0 for e in certificates["elements"])
    assert report["percent"] >= 90.0  # measured 91.1 on 2026-09-25; a regression shows here


def test_aes_with_a_named_mode_carries_its_registered_oid():
    gcm = _asset(id="b1", source_type="binary", asset_class="binary", source_location="img!/usr/sbin/nginx",
                 algorithm="AES-256", key_size=256, raw_details={"mode": "gcm"})
    ctr = _asset(id="b2", source_type="binary", asset_class="binary", source_location="img!/usr/sbin/nginx",
                 algorithm="AES-128", key_size=128, raw_details={"mode": "ctr"})
    doc = generate_cbom([gcm, ctr], "t", timestamp=STAMP)
    by_name = {c["name"]: c for c in _components(doc, "algorithm")}
    assert by_name["AES-256-GCM"]["cryptoProperties"]["oid"] == "2.16.840.1.101.3.4.1.46"   # id-aes256-GCM
    assert "oid" not in by_name["AES-128-CTR"]["cryptoProperties"]
    oid = next(e for t in certin.conformance(doc)["by_type"] for e in t["elements"] if e["element"] == "OID")
    assert oid["present"] == 1 and oid["not_applicable"] == 1
