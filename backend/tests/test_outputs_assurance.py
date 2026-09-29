"""WP9: CycloneDX 1.7/1.6 against the official schemas, reproducibility, SARIF,
the signed manifest, the tamper-evident audit chain, delta reports and the NTRO PDF.
"""

from __future__ import annotations

import copy
import hashlib
import json
import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from engine import audit_chain, delta, manifest as mf
from engine.cbom import algorithm_family, canonical_json, generate_cbom, registry_curve
from engine.cbom_validate import validate_cbom
from engine.qirs import score_assets
from engine.schema_validation import validate_cyclonedx, validate_sarif
from engine.threat_model import ThreatModel
from main import app
from models.schemas import CryptoAsset

ESTATE = Path(__file__).resolve().parents[2] / "demo" / "estate" / "estate.yaml"
STAMP = "2026-09-24T10:00:00Z"


@pytest.fixture(scope="module")
def estate():
    client = TestClient(app)
    body = client.post("/api/scan/full", json={"estate": str(ESTATE), "wait": True}).json()
    assert body["status"] == "done"
    from api.routes import state
    return client, list(state.assets)


# --------------------------------------------------------------------------
# CycloneDX
# --------------------------------------------------------------------------


@pytest.mark.parametrize("spec", ["1.7", "1.6"])
def test_demo_cbom_validates_against_the_official_schema(estate, spec):
    _, assets = estate
    document = generate_cbom(assets, "Tejomaya", spec=spec, timestamp=STAMP)
    assert validate_cyclonedx(document, spec) == []
    report = validate_cbom(document)
    assert report["valid"], [c for c in report["checks"] if not c["passed"]]
    assert report["xml_validity_claimed"] is False


def test_17_carries_registry_names_that_16_does_not(estate):
    _, assets = estate
    v17 = json.dumps(generate_cbom(assets, "M", spec="1.7", timestamp=STAMP))
    v16 = json.dumps(generate_cbom(assets, "M", spec="1.6", timestamp=STAMP))
    for key in ('"algorithmFamily"', '"ellipticCurve"', '"ikev2TransformTypes"'):
        assert key in v17 and key not in v16
    assert '"fingerprint"' in v17


@pytest.mark.parametrize("canonical,family", [
    ("ML-KEM-768", "ML-KEM"), ("ML-DSA-65", "ML-DSA"), ("SHA-256", "SHA-2"), ("SHA3-256", "SHA-3"),
    ("SHA-1", "SHA-1"), ("X25519", "ECDH"), ("Ed25519", "EdDSA"), ("3DES", "3DES"), ("Diffie-Hellman", "FFDH"),
    ("RSA-2048", None),
])
def test_registry_family_mapping(canonical, family):
    assert algorithm_family(canonical, None) == family


def test_registry_curves():
    assert registry_curve("prime256v1") == "nist/P-256"
    assert registry_curve("secp256k1") == "secg/secp256k1"
    assert registry_curve("banana") is None


def _base(assets) -> dict:
    return generate_cbom(assets[:30], "M", spec="1.7", timestamp=STAMP)


def _first(document, asset_type):
    return next(c for c in document["components"] if c["cryptoProperties"]["assetType"] == asset_type)


BROKEN = {
    "wrong bomFormat": lambda d: d.__setitem__("bomFormat", "SPDX"),
    "unknown specVersion": lambda d: d.__setitem__("specVersion", "9.9"),
    "serial not a URN": lambda d: d.__setitem__("serialNumber", "12345"),
    "assetType outside the enum": lambda d: _first(d, "algorithm")["cryptoProperties"].__setitem__("assetType", "key"),
    "primitive outside the enum": lambda d: _first(d, "algorithm")["cryptoProperties"]["algorithmProperties"].__setitem__("primitive", "magic"),
    "algorithmFamily not in the registry": lambda d: _first(d, "algorithm")["cryptoProperties"]["algorithmProperties"].__setitem__("algorithmFamily", "Enigma"),
    "ellipticCurve not in the registry": lambda d: _first(d, "algorithm")["cryptoProperties"]["algorithmProperties"].__setitem__("ellipticCurve", "nist/P-999"),
    "nistQuantumSecurityLevel out of range": lambda d: _first(d, "algorithm")["cryptoProperties"]["algorithmProperties"].__setitem__("nistQuantumSecurityLevel", 9),
    "dangling dependsOn": lambda d: d["dependencies"][0].__setitem__("dependsOn", ["crypto:does-not-exist"]),
    "duplicate bom-ref": lambda d: d["components"].append(copy.deepcopy(d["components"][0])),
    "unknown top-level property": lambda d: d.__setitem__("veraScore", 1),
}


@pytest.mark.parametrize("name", sorted(BROKEN))
def test_broken_cboms_are_rejected(estate, name):
    document = _base(estate[1])
    assert validate_cbom(document)["valid"]
    BROKEN[name](document)
    assert validate_cbom(document)["valid"] is False, name


def test_at_least_six_distinct_rejections():
    assert len(BROKEN) >= 6


def test_output_is_byte_identical_and_order_independent(estate):
    _, assets = estate
    first = canonical_json(generate_cbom(assets, "M", timestamp=STAMP))
    second = canonical_json(generate_cbom(list(reversed(assets)), "M", timestamp=STAMP))
    assert hashlib.sha256(first.encode()).hexdigest() == hashlib.sha256(second.encode()).hexdigest()


def test_api_cbom_is_byte_identical_and_serves_both_specs(estate):
    client, _ = estate
    a, b = client.get("/api/cbom").content, client.get("/api/cbom").content
    assert a == b and json.loads(a)["specVersion"] == "1.7"
    assert json.loads(client.get("/api/cbom", params={"spec": "1.6"}).content)["specVersion"] == "1.6"
    assert client.get("/api/cbom", params={"spec": "2.0"}).status_code == 400


# --------------------------------------------------------------------------
# SARIF
# --------------------------------------------------------------------------


def test_sarif_is_schema_valid_with_real_locations(estate):
    client, _ = estate
    document = json.loads(client.get("/api/sarif").content)
    assert validate_sarif(document) == []
    results = document["runs"][0]["results"]
    uris = [r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for r in results]
    assert any(u.startswith("file:///") for u in uris)
    assert any(u.startswith("tls://") for u in uris) and any(u.startswith("ssh://") for u in uris)
    source = [r for r in results if ".java" in r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]]
    assert source and all(r["locations"][0]["physicalLocation"]["region"]["startLine"] >= 1 for r in source)
    assert {r["level"] for r in results} <= {"error", "warning", "note"}
    assert any(r["ruleId"].startswith("VERA-DRIFT-") for r in results)
    rule_ids = {r["id"] for r in document["runs"][0]["tool"]["driver"]["rules"]}
    assert {r["ruleId"] for r in results} <= rule_ids


def test_classically_broken_and_secrets_are_errors(estate):
    client, _ = estate
    results = json.loads(client.get("/api/sarif").content)["runs"][0]["results"]
    for r in results:
        if r["ruleId"] in ("VERA-REPLACE-NOW", "VERA-SECRET-EXPOSURE"):
            assert r["level"] == "error"


def test_broken_sarif_is_rejected():
    assert validate_sarif({"version": "2.1.0", "runs": [{"tool": {}}]})
    assert validate_sarif({"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "x"}},
                                                         "results": [{"level": "fatal", "message": {"text": "m"}}]}]})


# --------------------------------------------------------------------------
# Signed manifest
# --------------------------------------------------------------------------


def _unsigned() -> dict:
    return mf.build(scan={"scan_id": "s1", "assets": 3}, inputs=[{"collector": "source", "target": "x",
                                                                  "output_sha256": "ab" * 32, "findings": 3}],
                    cbom_text="{}", sarif_text="{}",
                    threat_model={"version": "2026.09.1", "resources_table_hash": "f8" * 32},
                    profile="commercial", policy={"preset": "balanced"}, created_at="2026-09-24T10:00:00+00:00")


@pytest.fixture(params=["ml-dsa", "ed25519"])
def signed(request, tmp_path, monkeypatch):
    if request.param == "ed25519":
        monkeypatch.setenv("VERA_SIGNING", "ed25519")
    elif mf.find_openssl() is None:
        pytest.skip("no OpenSSL 3.5+ on this host for ML-DSA-65")
    return mf.sign(_unsigned(), tmp_path / "keys")


def test_signed_manifest_verifies(signed):
    result = mf.verify(signed, signed["signature"]["public_key_pem"])
    assert result["valid"] and result["key_trusted"]
    assert signed["signature"]["alg"] in (mf.ML_DSA, mf.ED25519)


def test_ml_dsa_signature_has_the_fips_204_size(signed):
    if signed["signature"]["alg"] != mf.ML_DSA:
        pytest.skip("Ed25519 fallback in use")
    import base64

    assert len(base64.b64decode(signed["signature"]["value"])) == 3309


@pytest.mark.parametrize("tamper", [
    lambda m: m["scan"].__setitem__("assets", 4),
    lambda m: m.__setitem__("cbom_sha256", "0" * 64),
    lambda m: m["inputs"][0].__setitem__("output_sha256", "cd" * 32),
    lambda m: m.__setitem__("profile", "cnsa"),
])
def test_tampering_any_signed_field_fails(signed, tamper):
    modified = copy.deepcopy(signed)
    tamper(modified)
    assert mf.verify(modified)["valid"] is False


def test_tampering_the_signature_or_key_fails(signed):
    import base64

    raw = bytearray(base64.b64decode(signed["signature"]["value"]))
    raw[10] ^= 0x01
    bad_sig = copy.deepcopy(signed)
    bad_sig["signature"]["value"] = base64.b64encode(bytes(raw)).decode()
    assert mf.verify(bad_sig)["valid"] is False
    bad_key = copy.deepcopy(signed)
    bad_key["signature"]["public_key_sha256"] = "0" * 64
    assert mf.verify(bad_key)["reason"] == "public key does not match its recorded hash"


def test_fallback_is_labelled_classical(tmp_path, monkeypatch):
    monkeypatch.setenv("VERA_SIGNING", "ed25519")
    assert mf.sign(_unsigned(), tmp_path)["signature"]["alg"] == "Ed25519 (classical fallback)"


def test_manifest_cli(tmp_path, monkeypatch, signed):
    path = tmp_path / "m.json"
    path.write_text(json.dumps(signed))
    pem = tmp_path / "pub.pem"
    pem.write_text(signed["signature"]["public_key_pem"])
    assert mf.main(["verify", str(path), "--public-key", str(pem)]) == 0
    tampered = copy.deepcopy(signed)
    tampered["created_at"] = "2030-01-01"
    path.write_text(json.dumps(tampered))
    assert mf.main(["verify", str(path), "--public-key", str(pem)]) == 1


def test_manifest_endpoint_covers_every_collector_input(estate, monkeypatch, tmp_path):
    client, _ = estate
    monkeypatch.setattr(mf, "KEY_DIR", tmp_path / "keys")
    from api.routes import state
    state.manifest_cache = {}
    manifest = client.get("/api/manifest").json()
    assert len(manifest["inputs"]) >= 20 and all(len(i["output_sha256"]) == 64 for i in manifest["inputs"])
    check = client.post("/api/manifest/verify", json=manifest).json()
    assert check["valid"] and check["cbom_matches_current_scan"]


# --------------------------------------------------------------------------
# Audit chain
# --------------------------------------------------------------------------


def test_audit_chain_detects_raw_sql_tampering(tmp_path):
    chain = audit_chain.AuditChain(tmp_path / "audit.db")
    for i in range(5):
        chain.append("scan", "demo", {"n": i})
    assert chain.verify() == {"valid": True, "entries": 5, "first_broken": None, "head": chain.entries()[-1]["entry_hash"]}

    db = sqlite3.connect(tmp_path / "audit.db")
    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        db.execute("UPDATE audit_chain SET action = 'x' WHERE idx = 2")
    # An attacker with file access drops the guard and rewrites a row directly.
    db.execute("DROP TRIGGER audit_chain_no_update")
    db.execute("UPDATE audit_chain SET detail = '{\"n\": 99}' WHERE idx = 2")
    db.commit()
    result = chain.verify()
    assert result["valid"] is False and result["first_broken"] == 2


def test_audit_chain_detects_deletion(tmp_path):
    chain = audit_chain.AuditChain(tmp_path / "audit.db")
    for i in range(4):
        chain.append("export", "cbom", {"n": i})
    db = sqlite3.connect(tmp_path / "audit.db")
    db.execute("DROP TRIGGER audit_chain_no_delete")
    db.execute("DELETE FROM audit_chain WHERE idx = 1")
    db.commit()
    assert chain.verify()["first_broken"] == 1


def test_scans_exports_and_settings_are_chained(estate):
    client, _ = estate
    client.post("/api/scan/full", json={"estate": str(ESTATE), "wait": True})
    client.get("/api/sarif")
    client.put("/api/profile", json={"profile": "commercial"})
    body = client.get("/api/audit/chain", params={"limit": 200}).json()
    kinds = {e["kind"] for e in body["entries"]}
    assert {"scan", "export", "setting"} <= kinds
    assert body["verify"]["valid"]


def test_llm_setting_changes_never_record_values():
    from engine import audit_chain as chain_module

    client = TestClient(app)
    client.post("/api/llm/config", json={"api_key": "sk-test-secret-value"})
    entries = chain_module.default().entries()
    assert entries and "sk-test-secret-value" not in json.dumps(entries)


# --------------------------------------------------------------------------
# Delta and report
# --------------------------------------------------------------------------


def _scan(sid, ts, version, assets):
    return {"scan_id": sid, "timestamp": ts, "label": sid, "summary": {"threat_model_version": version},
            "assets": assets}


def test_delta_counts_migration_and_explains_the_clock():
    before = _scan("a", "2026-09-01T00:00:00+00:00", "2026.09.1", [
        {"id": "1", "name": "gw", "algorithm": "RSA", "quantum_vulnerable": True},
        {"id": "2", "name": "vpn", "algorithm": "DH", "quantum_vulnerable": True},
        {"id": "3", "name": "old", "algorithm": "ECDSA", "quantum_vulnerable": True},
    ])
    after = _scan("b", "2026-09-11T00:00:00+00:00", "2026.09.1", [
        {"id": "1", "name": "gw", "algorithm": "ML-DSA-65", "quantum_vulnerable": False},
        {"id": "2", "name": "vpn", "algorithm": "DH", "quantum_vulnerable": True},
        {"id": "4", "name": "new", "algorithm": "RSA", "quantum_vulnerable": True},
    ])
    d = delta.compare(before, after)
    assert [a["id"] for a in d["added"]] == ["4"] and [a["id"] for a in d["removed"]] == ["3"]
    assert d["migration"] == {"vulnerable_before": 3, "migrated": 1, "removed": 1, "still_vulnerable": 1,
                              "newly_vulnerable": 1, "progress_percent": 66.7,
                              "progress_basis": "(migrated + removed) / vulnerable in the earlier scan"}
    assert d["changed"][0]["changes"]["algorithm"] == ["RSA", "ML-DSA-65"]
    assert d["why_scores_moved"]["reason"] == "clock" and d["why_scores_moved"]["elapsed_days"] == 10.0


def test_delta_explains_a_threat_model_change(monkeypatch):
    from engine import quantum_resources

    monkeypatch.setattr(quantum_resources, "versions", lambda: [
        {"version": "2026.09.1", "changelog": "first"}, {"version": "2026.12.1", "changelog": "new P-256 estimate"}])
    d = delta.compare(_scan("a", "2026-09-01T00:00:00+00:00", "2026.09.1", []),
                      _scan("b", "2026-12-02T00:00:00+00:00", "2026.12.1", []))
    assert d["why_scores_moved"]["reason"] == "evidence"
    assert d["why_scores_moved"]["changelog"] == [{"version": "2026.12.1", "changelog": "new P-256 estimate"}]


def test_delta_warns_when_scans_do_not_overlap():
    d = delta.compare(_scan("a", "2026-09-01", "v", [{"id": "1", "quantum_vulnerable": True}]),
                      _scan("b", "2026-09-02", "v", [{"id": "2", "quantum_vulnerable": True}]))
    assert d["warning"] and d["overlap"] == 0.0


def test_ntro_report_is_a_pdf(estate, monkeypatch, tmp_path):
    client, _ = estate
    monkeypatch.setattr(mf, "KEY_DIR", tmp_path / "keys")
    from api.routes import state
    state.manifest_cache = {}
    response = client.get("/api/report/ntro")
    assert response.status_code == 200 and response.content[:5] == b"%PDF-"
    assert len(response.content) > 5000


def test_audit_chain_reports_a_row_edited_to_non_json_instead_of_failing(tmp_path):
    chain = audit_chain.AuditChain(tmp_path / "audit.db")
    for i in range(3):
        chain.append("export", "cbom", {"n": i})
    db = sqlite3.connect(tmp_path / "audit.db")
    db.execute("DROP TRIGGER audit_chain_no_update")
    db.execute("UPDATE audit_chain SET detail = 'not json' WHERE idx = 1")
    db.commit()
    result = chain.verify()
    assert result["valid"] is False and result["first_broken"] == 1
    assert "not valid JSON" in result["reason"]
    assert chain.entries()[1]["malformed"] is True


def test_audit_chain_reads_are_safe_while_other_threads_append(tmp_path):
    """The chain's one connection is shared by request threads; reads must not see a half-used cursor."""
    import threading

    chain = audit_chain.AuditChain(tmp_path / "audit.db")
    errors: list[BaseException] = []

    def writer(n: int) -> None:
        try:
            for i in range(40):
                chain.append("agent", "tool", {"writer": n, "i": i})
        except BaseException as exc:  # noqa: BLE001 - collected and asserted below
            errors.append(exc)

    def reader() -> None:
        try:
            for _ in range(40):
                chain.verify()
                chain.entries(10)
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=writer, args=(n,)) for n in range(4)] + \
        [threading.Thread(target=reader) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    final = chain.verify()
    assert final["valid"] and final["entries"] == 160
