"""Tests for the key-vault collector.

The first class of test here is the one that matters most in a sales
conversation: **no key material can survive into a finding.** That is the claim
that lets a bank run this at all, so it is asserted directly and adversarially —
key material is injected into a synthetic vault and the collector is required to
drop it.

The rest cover the things that would silently corrupt an estate: double-counting
an asset seen by two sensors, a corroboration bonus that manufactures certainty,
and a missing source failing quietly instead of being reported as a gap.
"""

from __future__ import annotations

import json

import pytest

from collectors.vault_collector import (
    _correlate,
    _identity,
    _scrub,
    scan_vault,
    vault_summary,
)
from engine.plugins import PROVENANCE
from models.schemas import RawCryptoFinding


# ---------------------------------------------------------------------------
# The security invariant
# ---------------------------------------------------------------------------

# Every attribute name across PKCS#11, KMIP, JWK and PEM conventions that would
# carry a private or secret value.
SECRET_FIELDS = [
    "CKA_VALUE", "CKA_PRIVATE_EXPONENT", "CKA_PRIME_1", "CKA_PRIME_2",
    "CKA_EXPONENT_1", "CKA_EXPONENT_2", "CKA_COEFFICIENT",
    "private_key", "private_key_pem", "key_material", "secret", "d", "p", "q",
]

PEM_BODY = (
    "-----BEGIN PRIVATE KEY-----\n"
    "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQ\n"
    "-----END PRIVATE KEY-----"
)


@pytest.mark.parametrize("field", SECRET_FIELDS)
def test_scrub_removes_every_secret_bearing_field(field):
    """Each forbidden attribute is dropped, at the top level."""
    cleaned = _scrub({field: PEM_BODY, "CKA_LABEL": "keep-me"})
    assert field not in cleaned
    assert cleaned["CKA_LABEL"] == "keep-me"


def test_scrub_removes_secrets_nested_at_depth():
    """A secret hidden inside a nested object is dropped too."""
    cleaned = _scrub({
        "outer": {"inner": {"CKA_VALUE": PEM_BODY, "CKA_ID": "0A11"}},
        "CKA_LABEL": "x",
    })
    assert "CKA_VALUE" not in cleaned["outer"]["inner"]
    assert cleaned["outer"]["inner"]["CKA_ID"] == "0A11"


def test_no_pem_body_survives_into_any_finding(tmp_path):
    """Adversarial: a vault that *does* contain key material must still yield
    findings that carry none. This is the product's core safety claim."""
    vault = tmp_path / "vault"
    vault.mkdir()
    (vault / "hsm_pkcs11.json").write_text(json.dumps({
        "slots": [{
            "slot_id": 0,
            "token_label": "EVIL-HSM",
            "manufacturer": "Test",
            "pqc_ready": False,
            "objects": [{
                "CKA_LABEL": "leaky-key",
                "CKA_KEY_TYPE": "CKK_RSA",
                "CKA_CLASS": "CKO_PRIVATE_KEY",
                "CKA_MODULUS_BITS": 2048,
                "CKA_SIGN": True,
                # Everything below must be stripped.
                "CKA_VALUE": PEM_BODY,
                "CKA_PRIVATE_EXPONENT": "00deadbeef",
                "private_key_pem": PEM_BODY,
            }],
        }],
    }), encoding="utf-8")

    findings, _ = scan_vault(vault)
    assert findings, "the collector should still produce the finding"

    blob = json.dumps([f.model_dump() for f in findings])
    assert "BEGIN PRIVATE KEY" not in blob
    assert "deadbeef" not in blob.lower()
    for field in SECRET_FIELDS:
        assert f'"{field}"' not in blob


def test_bundled_vault_carries_no_key_material():
    """The shipped demo vault is clean, and reports itself as clean."""
    findings, errors = scan_vault()
    assert not errors
    blob = json.dumps([f.model_dump() for f in findings])
    assert "BEGIN PRIVATE KEY" not in blob
    assert "BEGIN RSA PRIVATE KEY" not in blob
    assert vault_summary()["key_material_present"] is False


def test_every_hsm_private_object_is_non_extractable():
    """The reason no key material appears is structural, not incidental."""
    findings, _ = scan_vault()
    hsm = [f for f in findings
           if f.raw_details.get("discovered_by") == "vault_pkcs11"]
    assert hsm
    for finding in hsm:
        assert finding.raw_details.get("CKA_EXTRACTABLE") is False


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def test_all_five_sources_parse_without_error():
    findings, errors = scan_vault()
    assert errors == []
    sensors = {f.raw_details.get("discovered_by") for f in findings}
    assert sensors == {
        "vault_pkcs11", "vault_kmip", "vault_cloud_kms",
        "vault_keystore", "vault_certificate",
    }


def test_findings_carry_a_graded_provenance():
    """Confidence must come from the provenance table, never be invented."""
    findings, _ = scan_vault()
    valid = {PROVENANCE[p]["confidence"] for p in PROVENANCE}
    for finding in findings:
        provenance = finding.raw_details.get("provenance")
        assert provenance in PROVENANCE
        confidence = finding.raw_details.get("confidence")
        # Either the base grade, or a corroborated value above it.
        assert confidence >= min(valid)
        assert confidence <= 0.95


def test_hsm_without_pqc_mechanisms_marks_assets_change_blocked():
    """The operational fact that outranks a rank: an asset on a token whose
    firmware advertises no PQC mechanism cannot be migrated in place.

    The vault also holds a token that does advertise ML-DSA / ML-KEM. It is the
    control: if its keys were blocked too, "blocked" would be a constant rather
    than a reading of the firmware, and this test would prove nothing."""
    findings, _ = scan_vault()
    hsm = [f for f in findings
           if f.raw_details.get("discovered_by") == "vault_pkcs11"]
    assert hsm
    no_pqc = [f for f in hsm if not f.raw_details["hsm_pqc_ready"]]
    pqc_ready = [f for f in hsm if f.raw_details["hsm_pqc_ready"]]
    assert no_pqc and pqc_ready, "demo vault must hold a blocked and a PQC-ready token"

    assert all(f.raw_details["change_blocked"] for f in no_pqc)
    assert all("pqc-firmware-blocked" in f.tags for f in no_pqc)
    assert not any(f.raw_details["change_blocked"] for f in pqc_ready)
    assert not any("pqc-firmware-blocked" in f.tags for f in pqc_ready)


def test_pqc_ready_token_is_not_change_blocked(tmp_path):
    """The inverse: a token advertising ML-DSA is not blocked."""
    vault = tmp_path / "vault"
    vault.mkdir()
    (vault / "hsm_pkcs11.json").write_text(json.dumps({
        "slots": [{
            "slot_id": 0, "token_label": "NEW-HSM", "manufacturer": "Test",
            "mechanisms": ["CKM_ML_DSA", "CKM_ML_KEM"],
            "pqc_mechanisms_present": ["CKM_ML_DSA"],
            "pqc_ready": True,
            "objects": [{
                "CKA_LABEL": "modern-sign", "CKA_KEY_TYPE": "CKK_RSA",
                "CKA_CLASS": "CKO_PRIVATE_KEY", "CKA_MODULUS_BITS": 3072,
                "CKA_SIGN": True,
            }],
        }],
    }), encoding="utf-8")
    findings, _ = scan_vault(vault)
    assert findings[0].raw_details["change_blocked"] is False
    assert "pqc-firmware-blocked" not in findings[0].tags


def test_3des_key_length_converted_from_bytes_to_bits():
    """CKA_VALUE_LEN is bytes; the engine scores bits. Getting this wrong
    understates a 168-bit key as 21."""
    findings, _ = scan_vault()
    des = [f for f in findings if f.algorithm == "3DES"]
    assert des, "the demo vault contains a legacy 3DES PIN key"
    assert des[0].key_size == 192  # 24 bytes * 8


# ---------------------------------------------------------------------------
# Correlation
# ---------------------------------------------------------------------------

def _finding(fid, subject=None, location="loc", provenance="declared",
             confidence=0.85, sensor="s"):
    return RawCryptoFinding(
        id=fid, source_type="keystore", source_location=location,
        asset_class="tls_certificate", algorithm="RSA", key_size=2048,
        cert_subject=subject,
        raw_details={"provenance": provenance, "confidence": confidence,
                     "discovered_by": sensor},
    )


def test_same_certificate_from_two_sensors_becomes_one_asset():
    """Double-counting is the failure that makes every downstream total wrong."""
    merged = _correlate([
        _finding("a", subject="CN=root,O=X", sensor="vault_keystore",
                 provenance="artifact_parsed", confidence=0.90),
        _finding("b", subject="CN=root,O=X", sensor="vault_certificate",
                 provenance="artifact_parsed", confidence=0.90),
    ])
    assert len(merged) == 1
    assert merged[0].raw_details["corroboration_count"] == 2
    assert merged[0].raw_details["corroborated_by"] == [
        "vault_certificate", "vault_keystore",
    ]


def test_corroboration_never_exceeds_the_ceiling():
    """Agreement between weak sensors must not manufacture an observation."""
    merged = _correlate([
        _finding("a", subject="CN=x", sensor="s1",
                 provenance="static_analysis", confidence=0.55),
        _finding("b", subject="CN=x", sensor="s2",
                 provenance="heuristic", confidence=0.35),
    ])
    confidence = merged[0].raw_details["confidence"]
    assert confidence <= 0.95
    # Above the strongest single grade, but nowhere near "observed".
    assert 0.55 <= confidence < 0.70


def test_correlation_keeps_the_stronger_sensors_record():
    strong = _finding("strong", subject="CN=x", provenance="artifact_parsed",
                      confidence=0.90, sensor="parsed")
    weak = _finding("weak", subject="CN=x", provenance="heuristic",
                    confidence=0.35, sensor="guess")
    for order in ([strong, weak], [weak, strong]):
        merged = _correlate(list(order))
        assert len(merged) == 1
        assert merged[0].id == "strong"


def test_correlation_fills_gaps_but_never_overwrites():
    strong = _finding("strong", subject="CN=x", provenance="artifact_parsed",
                      confidence=0.90)
    strong.cert_issuer = None
    weak = _finding("weak", subject="CN=x", provenance="declared",
                    confidence=0.85)
    weak.cert_issuer = "CN=issuer"
    weak.algorithm = "ECDSA"          # must NOT overwrite the strong record
    merged = _correlate([strong, weak])[0]
    assert merged.cert_issuer == "CN=issuer"   # gap filled
    assert merged.algorithm == "RSA"           # existing value preserved


def test_distinct_assets_are_not_merged():
    merged = _correlate([
        _finding("a", subject="CN=one"),
        _finding("b", subject="CN=two"),
        _finding("c", location="pkcs11://t/slot0/k1"),
        _finding("d", location="pkcs11://t/slot0/k2"),
    ])
    assert len(merged) == 4


def test_identity_is_case_insensitive_on_subject():
    assert (_identity(_finding("a", subject="CN=Root CA,O=X"))
            == _identity(_finding("b", subject="cn=root ca,O=Y")))


def test_correlation_reduces_the_bundled_vault():
    raw, _ = scan_vault(correlate_sources=False)
    correlated, _ = scan_vault()
    assert len(correlated) < len(raw)
    assert len({f.id for f in correlated}) == len(correlated)


# ---------------------------------------------------------------------------
# Failure handling — a gap must be reported, never silent
# ---------------------------------------------------------------------------

def test_missing_vault_directory_reports_rather_than_raises(tmp_path):
    findings, errors = scan_vault(tmp_path / "does-not-exist")
    assert findings == []
    assert errors and "not found" in errors[0].lower()


def test_missing_source_file_is_reported_as_an_unmeasured_gap(tmp_path):
    vault = tmp_path / "vault"
    vault.mkdir()
    (vault / "kmip.json").write_text(json.dumps({"objects": []}), encoding="utf-8")
    _, errors = scan_vault(vault)
    # With no manifest every source is expected, so each absent one must say
    # so. Derived from the source table rather than hardcoded: adding a sensor
    # should not require editing an arithmetic constant here.
    from collectors.vault_collector import _adapter_sources

    assert len(errors) == len(_adapter_sources()) - 1
    assert all("not measured" in e for e in errors)
    assert not any("kmip.json" in e for e in errors)


def test_manifest_declared_sources_bound_what_counts_as_a_gap(tmp_path):
    """A key-manager export is not "missing TLS" — it is a different vault.

    When the manifest names the sources it contains, only those are expected.
    """
    vault = tmp_path / "vault"
    vault.mkdir()
    (vault / "kmip.json").write_text(json.dumps({"objects": []}), encoding="utf-8")
    (vault / "manifest.json").write_text(json.dumps({
        "sources": [{"file": "kmip.json"}],
    }), encoding="utf-8")
    _, errors = scan_vault(vault)
    assert errors == []


def test_malformed_json_does_not_lose_the_other_sources(tmp_path):
    vault = tmp_path / "vault"
    vault.mkdir()
    (vault / "hsm_pkcs11.json").write_text("{ this is not json", encoding="utf-8")
    (vault / "kmip.json").write_text(json.dumps({
        "endpoint": "kmip://t", "objects": [{
            "Unique Identifier": "K1", "Name": "good-key",
            "Object Type": "Symmetric Key", "Cryptographic Algorithm": "AES",
            "Cryptographic Length": 256, "State": "Active",
            "Cryptographic Usage Mask": ["Encrypt"],
        }],
    }), encoding="utf-8")
    findings, errors = scan_vault(vault)
    assert len(findings) == 1                      # the good source survived
    assert any("hsm_pkcs11" in e for e in errors)  # the bad one was reported


def test_scan_is_deterministic():
    first, _ = scan_vault()
    second, _ = scan_vault()
    assert [f.id for f in first] == [f.id for f in second]


# ---------------------------------------------------------------------------
# End to end
# ---------------------------------------------------------------------------

def test_vault_assets_score_through_the_engine():
    """The whole point: vault metadata reaches a defensible rank."""
    from engine.qirs import assign_risk_level, order_assets, score_assets
    from engine.regulatory import map_regulatory
    from engine.threat_model import ThreatModel
    from models.schemas import CryptoAsset

    findings, _ = scan_vault()
    assets = [CryptoAsset(**f.model_dump(), name=f.id) for f in findings]
    model = ThreatModel()
    assets = score_assets(assets, model)
    assets = map_regulatory(assets, org_persona="Banking")
    for asset in assets:
        asset.risk_level = assign_risk_level(asset)
    assets = order_assets(assets, model)

    assert all(0.0 <= a.qirs <= 1.0 for a in assets)
    assert all(0.0 <= a.h_score <= 1.0 for a in assets)
    assert all(0.0 <= a.t_score <= 1.0 for a in assets)
    # A signing trust anchor must out-rank a leaf TLS certificate on TNFL,
    # which is the two-axis model's whole claim.
    firmware = next(a for a in assets if a.asset_class == "firmware_signing")
    leaf = next(a for a in assets if a.asset_class == "tls_certificate")
    assert firmware.t_score > leaf.t_score


def test_vault_summary_reports_blind_spots():
    summary = vault_summary()
    assert summary["available"] is True
    assert summary["objects"] > 0
    assert summary["blind_spots"], "the vault must state what it cannot see"


def test_cloud_certificate_services_parse_from_their_own_api_shapes():
    import datetime as _dt

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    from collectors.vault_collector import _from_cloud

    key = ec.generate_private_key(ec.SECP384R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "api.demo.example")])
    now = _dt.datetime(2026, 1, 1, tzinfo=_dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(7).not_valid_before(now).not_valid_after(now + _dt.timedelta(days=90))
            .sign(key, hashes.SHA384()))
    pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    doc = {
        "aws_acm": {"certificates": [{"Certificate": {
            "CertificateArn": "arn:aws:acm:ap-south-1:111122223333:certificate/0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0",
            "DomainName": "pay.demo.example", "KeyAlgorithm": "RSA_2048", "SignatureAlgorithm": "SHA256WITHRSA",
            "Serial": "0a:1b", "Subject": "CN=pay.demo.example", "Issuer": "Amazon RSA 2048 M02",
            "NotBefore": "2026-01-01T00:00:00Z", "NotAfter": "2027-01-31T23:59:59Z", "Type": "AMAZON_ISSUED",
            "Status": "ISSUED", "InUseBy": ["arn:aws:elasticloadbalancing:ap-south-1:111122223333:loadbalancer/app/pay"]}}]},
        "azure_key_vault": {"certificates": [{
            "id": "https://demo-kv.vault.azure.net/certificates/portal-tls/5d1c", "x5t": "abc",
            "attributes": {"enabled": True, "nbf": "2026-02-01T00:00:00Z", "exp": "2027-02-01T00:00:00Z"},
            "policy": {"key_props": {"kty": "EC", "crv": "P-256", "exportable": False},
                       "x509_props": {"subject": "CN=portal.demo.example"}, "issuer": {"name": "Self"}}}]},
        "gcp_certificate_manager": {"certificates": [{
            "name": "projects/demo/locations/global/certificates/api-cert", "sanDnsnames": ["api.demo.example"],
            "expireTime": "2026-04-01T00:00:00Z", "pemCertificate": pem}]},
    }
    found = {f.tags[1]: f for f in _from_cloud(doc) if "cloud-certificate" in f.tags}
    assert (found["aws"].algorithm, found["aws"].key_size) == ("RSA", 2048)
    assert found["aws"].raw_details["in_use_by"]
    assert (found["azure"].algorithm, found["azure"].key_size) == ("ECDSA", 256)
    assert (found["gcp"].algorithm, found["gcp"].key_size) == ("ECDSA", 384)
    assert all(f.asset_class == "tls_certificate" for f in found.values())
    assert "BEGIN CERTIFICATE" not in repr([f.model_dump() for f in found.values()])   # the PEM is read, not kept
