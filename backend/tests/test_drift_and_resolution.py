"""WP6: identity resolution across collectors, drift rules D1-D8, capture replay."""

from __future__ import annotations

import datetime as dt
import json

import pytest

from collectors.capture_collector import CaptureCollector
from engine import drift
from engine.core import corroboration
from engine.core.resolution import exposure_for, normalise_serial, resolve
from models.schemas import CryptoAsset, RawCryptoFinding

NOW = dt.datetime(2026, 9, 24, tzinfo=dt.timezone.utc)
ISSUER = "CN=Demo Issuing CA,O=Demo,C=IN"


def tls(host="pay.demo.example:443", *, cls="tls_cipher_suite", protocol="TLSv1.2", suite=None, peer_ip=None,
        serial=None, end=None, pk=None, algorithm=None, key_size=None, subject=None, **details):
    raw = {"discovered_by": "tls_scanner", "provenance": "runtime_observed", "confidence": 0.98, **details}
    if peer_ip:
        raw["peer_ip"] = peer_ip
    if pk:
        raw["public_key_sha256"] = pk
    return RawCryptoFinding(id=f"tls-{host}-{cls}-{suite or serial or protocol}", source_type="tls",
                            source_location=host, asset_class=cls, protocol=protocol, cipher_suite=suite,
                            cert_serial=serial, cert_issuer=ISSUER if serial else None,
                            cert_subject=subject or ("CN=pay.demo.example" if serial else None),
                            cert_validity_end=end, algorithm=algorithm, key_size=key_size, raw_details=raw)


def held_cert(serial, end, *, key_size=2048, source="vault_keystore", **extra):
    return RawCryptoFinding(id=f"held-{serial}", source_type="keystore", source_location=f"/opt/ks.p12#{serial}",
                            asset_class="tls_certificate", algorithm="RSA", key_size=key_size, cert_serial=serial,
                            cert_issuer=ISSUER, cert_subject="CN=pay.demo.example", cert_validity_end=end,
                            raw_details={"discovered_by": source, "provenance": "artifact_parsed",
                                         "confidence": 0.90, **extra})


def ssh_live(host, wires):
    return [RawCryptoFinding(id=f"ssh-{host}-{w}", source_type="ssh", source_location=f"ssh://{host}",
                             asset_class="ssh_key_exchange", algorithm="X25519",
                             raw_details={"discovered_by": "ssh_live", "name_list": "kex_algorithms",
                                          "wire_name": w, "provenance": "runtime_observed", "confidence": 0.95})
            for w in wires]


def lib(source, version, **details):
    return RawCryptoFinding(id=f"{source}-{version}", source_type="container", source_location=f"img!/{source}",
                            asset_class="crypto_library",
                            raw_details={"discovered_by": f"container_scanner/{source}", "library_id": "openssl",
                                         "library_version": version, "image_digest": "sha256:abc", "image": "img",
                                         "confidence": 0.8, "provenance": "static_analysis", **details})


def rules_fired(findings, declarations):
    return [r["rule"] for r in drift.evaluate(findings, declarations, now=NOW)]


POLICY = {"kind": "tls_policy", "hosts": ["pay.demo.example:443"], "protocols": ["TLSv1.2", "TLSv1.3"],
          "ciphers": "ECDHE+AESGCM:!3DES:!RC4", "weak_cipher_enabled": False, "location": "/etc/nginx/pay.conf:1"}


# --------------------------------------------------------------------------
# Drift rules: a matching and a non-matching case each
# --------------------------------------------------------------------------


def test_d1_deprecated_tls_on_the_wire():
    assert rules_fired([tls(protocol="TLSv1.0")], [POLICY]) == ["D1"]
    assert rules_fired([tls(protocol="TLSv1.2")], [POLICY]) == []
    assert rules_fired([tls("other.example:443", protocol="TLSv1.0")], [POLICY]) == []  # not the same host


def test_d2_weak_cipher_served():
    assert rules_fired([tls(suite="TLS_RSA_WITH_3DES_EDE_CBC_SHA")], [POLICY]) == ["D2"]
    assert rules_fired([tls(suite="TLS_AES_256_GCM_SHA384")], [POLICY]) == []
    permissive = {**POLICY, "weak_cipher_enabled": True}
    assert rules_fired([tls(suite="TLS_RSA_WITH_3DES_EDE_CBC_SHA")], [permissive]) == []


def test_d3_manifest_and_binary_disagree():
    fired = drift.evaluate([lib("dependency", "3.0.11"), lib("binary", "1.1.1w")], [], now=NOW)
    assert [r["rule"] for r in fired] == ["D3"]
    assert fired[0]["declared"]["value"] == "OpenSSL 3.0.11" and fired[0]["observed"]["value"] == "OpenSSL 1.1.1w"
    assert rules_fired([lib("dependency", "3.0.11"), lib("binary", "3.0.11")], []) == []
    other_image = lib("binary", "1.1.1w", image_digest="sha256:other", image="other")
    assert rules_fired([lib("dependency", "3.0.11"), other_image], []) == []


def test_d4_deployed_key_weaker_than_code():
    code = RawCryptoFinding(id="src", source_type="source", source_location="repo/keys.py:3", asset_class="source",
                            algorithm="RSA", key_size=3072,
                            raw_details={"discovered_by": "source_scanner", "system": "payments"})
    deployed = tls(cls="tls_certificate", serial="0A1B", algorithm="RSA", key_size=2048, end="2027-01-01T00:00:00+00:00")
    system = {"kind": "system", "name": "payments", "hosts": ["pay.demo.example:443"]}
    assert rules_fired([code, deployed], [system]) == ["D4"]
    strong = tls(cls="tls_certificate", serial="0A1C", algorithm="RSA", key_size=4096, end="2027-01-01T00:00:00+00:00")
    assert rules_fired([code, strong], [system]) == []


def test_d5_retired_key_still_served():
    key = RawCryptoFinding(id="kmip-7", source_type="config", source_location="kmip://km/KMIP-0007",
                           asset_class="generic_key", algorithm="RSA",
                           raw_details={"discovered_by": "vault_kmip", "lifecycle_state": "Deactivated",
                                        "public_key_sha256": "BD:33:D9:9A:C9:DA:EB:3D:9D:3D:DD:C3:AE:57:B1:88",
                                        "display_name": "legacy-signing (KMIP)"})
    served = tls(cls="tls_certificate", serial="77", pk="bd33d99ac9daeb3d9d3dddc3ae57b188" + "0" * 32,
                 end="2027-01-01T00:00:00+00:00")
    fired = drift.evaluate([key, served], [], now=NOW)
    assert [r["rule"] for r in fired] == ["D5"] and "legacy-signing" in fired[0]["explain"]
    active = key.model_copy(update={"raw_details": {**key.raw_details, "lifecycle_state": "Active"}})
    assert rules_fired([active, served], []) == []


def test_d6_expired_certificate_still_served():
    expired = held_cert("0A1B", "2026-01-01T00:00:00+00:00")
    served = tls(cls="tls_certificate", serial="2587", end="2026-01-01T00:00:00+00:00")   # 0x0A1B == 2587
    assert normalise_serial("0A:1B") == normalise_serial("2587")
    fired = drift.evaluate([expired, served], [], now=NOW)
    assert [r["rule"] for r in fired] == ["D6"] and fired[0]["severity"] == "critical"
    valid = held_cert("0A1B", "2027-06-01T00:00:00+00:00")
    assert rules_fired([valid, served], []) == []


def test_d7_hybrid_kex_configured_but_not_offered():
    decl = {"kind": "ssh_policy", "hosts": ["10.20.0.5:22"], "kex": ["mlkem768x25519-sha256", "curve25519-sha256"],
            "location": "/etc/ssh/sshd_config:4"}
    assert rules_fired(ssh_live("10.20.0.5:22", ["curve25519-sha256", "ecdh-sha2-nistp256"]), [decl]) == ["D7"]
    assert rules_fired(ssh_live("10.20.0.5:22", ["mlkem768x25519-sha256", "curve25519-sha256"]), [decl]) == []


def test_d8_internal_system_on_a_public_address():
    system = {"kind": "system", "name": "core-ledger", "hosts": ["ledger.demo.internal:443"], "exposure": "internal"}
    public = tls("ledger.demo.internal:443", peer_ip="203.0.113.10")
    private = tls("ledger.demo.internal:443", peer_ip="10.4.0.8")
    assert rules_fired([public], [system]) == ["D8"]
    assert rules_fired([private], [system]) == []


def test_drift_records_carry_both_evidence_refs_and_are_ordered_by_severity():
    findings = [tls(protocol="TLSv1.0"), held_cert("0A1B", "2026-01-01T00:00:00+00:00"),
                tls(cls="tls_certificate", serial="2587", end="2026-01-01T00:00:00+00:00")]
    records = drift.evaluate(findings, [POLICY], now=NOW)
    assert [r["severity"] for r in records] == ["critical", "high"]
    for r in records:
        assert len(r["evidence_refs"]) == 2 and r["kind"] == "drift"
        assert r["declared"]["summary"] and r["observed"]["summary"] and r["explain"]
    assert drift.summarise(records)["by_rule"] == {"D6": 1, "D1": 1}


def test_every_rule_has_text_in_the_rule_file():
    for rule in drift.rules()["rules"]:
        assert {"id", "title", "severity", "declared", "observed", "explain"} <= set(rule)
    assert sorted(drift.rules()["by_id"]) == [f"D{i}" for i in range(1, 9)]


# --------------------------------------------------------------------------
# Identity resolution
# --------------------------------------------------------------------------


def test_same_certificate_across_planes_merges_and_gains_confidence():
    held = held_cert("0A1B", "2027-01-01T00:00:00+00:00")
    served = tls(cls="tls_certificate", serial="2587", end="2027-01-01T00:00:00+00:00", algorithm="RSA", key_size=2048)
    assets, stats = resolve([held, served])
    assert len(assets) == 1 and stats["cross_plane_assets"] == 1
    merged = assets[0]
    assert merged.source_type == "tls"                      # the stronger (observed) view is the base
    assert merged.raw_details["identity"]["matched_on"] == ["serial_issuer"]
    asset = CryptoAsset(**merged.model_dump(), name="pay", quantum_vulnerable=True, verdict="shor")
    reading = corroboration.for_asset(asset)
    assert set(reading["planes"]) == {"observed", "held"}
    assert reading["confidence"] == pytest.approx(min(1 - (1 - 0.98) * (1 - 0.90), 0.99))


def test_same_plane_duplicates_do_not_add_confidence():
    a = lib("dependency", "3.0.11")
    b = a.model_copy(update={"id": "dup", "source_location": "img!/other/status"})
    assets, _ = resolve([a, b])
    assert len(assets) == 1
    asset = CryptoAsset(**assets[0].model_dump(), name="lib", quantum_vulnerable=True, verdict="shor")
    assert corroboration.for_asset(asset)["confidence"] == pytest.approx(0.8)


def test_same_subject_different_serial_is_linked_not_merged():
    one, two = held_cert("01", "2027-01-01T00:00:00+00:00"), held_cert("02", "2027-01-01T00:00:00+00:00")
    assets, stats = resolve([one, two])
    assert len(assets) == 2 and stats["possible_duplicates"] == 2
    assert assets[0].raw_details["possible_duplicates"] == [assets[1].id]


def test_one_endpoint_keeps_its_distinct_assets():
    assets, _ = resolve([tls(suite="TLS_AES_256_GCM_SHA384"), tls(cls="tls_key_exchange", protocol="TLSv1.3")])
    assert len(assets) == 2



def test_versionless_library_takes_the_one_known_version_in_its_image():
    assets, _ = resolve([lib("binary", "unknown"), lib("dependency", "3.3.7")])
    assert len(assets) == 1
    assert assets[0].raw_details["library_version"] == "3.3.7"
    named = lib("binary", "unknown", display_name="OpenSSL (version unknown) in libssl.so.3", confidence=0.95)
    assets, _ = resolve([named, lib("dependency", "3.3.7")])
    assert assets[0].raw_details["display_name"] == "OpenSSL 3.3.7 in libssl.so.3"   # the name states the version too
    stale = lib("binary", "unknown", confidence=0.95, pqc_reason="Version unknown; PQC is native from 3.5.0.")
    known = lib("dependency", "3.3.7", pqc_reason="3.3.7 predates native PQC (from 3.5.0).", pqc_capable=False)
    assets, _ = resolve([stale, known])
    assert assets[0].raw_details["pqc_reason"].startswith("3.3.7 predates")    # the verdict follows the version
    assets, _ = resolve([lib("binary", "unknown"), lib("dependency", "3.3.7"), lib("wheel", "1.1.1w")])
    assert len(assets) == 3                               # two known versions: the version-less binary is ambiguous

@pytest.mark.parametrize("peer,declared,expected", [
    ("203.0.113.10", None, "internet"), ("10.0.0.4", "internet", "internal"), (None, "internal", "internal"),
])
def test_exposure_prefers_the_observed_address(peer, declared, expected):
    finding = tls("svc.demo.example:443", peer_ip=peer, **({"declared_exposure": declared} if declared else {}))
    assert exposure_for(finding)[0] == expected


# --------------------------------------------------------------------------
# Capture replay
# --------------------------------------------------------------------------


def test_capture_replay_is_observed_and_labelled_as_recorded(tmp_path):
    tls_doc = {"source": "tls", "collected_at": "2026-09-20T10:00:00Z",
               "findings": [tls(protocol="TLSv1.0").model_dump()]}
    ssh_doc = {"source": "ssh", "collected_at": "2026-09-20T10:05:00Z", "probes": [{
        "target": "10.20.0.5:22", "banner": "SSH-2.0-OpenSSH_9.2p1",
        "kex_algorithms": ["curve25519-sha256"], "server_host_key_algorithms": ["ssh-ed25519"],
        "encryption_server_to_client": ["aes256-gcm@openssh.com"], "mac_server_to_client": ["hmac-sha2-256"]}]}
    (tmp_path / "tls.json").write_text(json.dumps(tls_doc))
    (tmp_path / "ssh.json").write_text(json.dumps(ssh_doc))
    (tmp_path / "bad.json").write_text(json.dumps({"source": "smtp"}))
    result = CaptureCollector().collect([str(tmp_path)])
    assert result.stats["captures"] == 2
    assert any("not a capture" in f["reason"] for f in result.failures)
    for f in result.findings:
        d = f.raw_details
        assert corroboration.plane_for(d["discovered_by"], f.source_type) == "observed"
        assert d["confidence"] == pytest.approx(0.90) and d["recorded_at"].startswith("2026-09-20")
