"""Tests for the intake plane — scrub, identity, correlate, custody stamp.

These are the invariants the inlet must keep before the engine ever sees an
asset: no key material survives, the same CN merges, and custody is stamped
from sensor signals rather than source_type.
"""

from __future__ import annotations

from engine.intake import (
    correlate_findings,
    identity_key,
    scrub,
    stamp_finding_custody,
)
from models.schemas import RawCryptoFinding

PEM_BODY = (
    "-----BEGIN PRIVATE KEY-----\n"
    "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQ\n"
    "-----END PRIVATE KEY-----"
)


def test_scrub_drops_cka_value_and_private_key():
    cleaned = scrub({
        "CKA_VALUE": PEM_BODY,
        "private_key": PEM_BODY,
        "CKA_LABEL": "keep-me",
    })
    assert "CKA_VALUE" not in cleaned
    assert "private_key" not in cleaned
    assert cleaned["CKA_LABEL"] == "keep-me"


def test_identity_matches_same_cn_from_two_findings():
    a = RawCryptoFinding(
        id="a", source_type="keystore", source_location="store#alias",
        cert_subject="CN=Root CA,O=Bank",
        raw_details={"discovered_by": "vault_keystore"},
    )
    b = RawCryptoFinding(
        id="b", source_type="tls", source_location="Root CA",
        cert_subject="CN=Root CA,O=Other",
        raw_details={"discovered_by": "vault_certificate"},
    )
    assert identity_key(a) == identity_key(b)
    assert identity_key(a) == ("cert", "root ca")


def test_correlate_merges_same_cn_with_corroboration_count():
    a = RawCryptoFinding(
        id="a", source_type="keystore", source_location="a.jks#root",
        asset_class="root_ca", algorithm="RSA",
        cert_subject="CN=Root CA,O=X",
        raw_details={
            "provenance": "artifact_parsed", "confidence": 0.90,
            "discovered_by": "vault_keystore",
        },
    )
    b = RawCryptoFinding(
        id="b", source_type="tls", source_location="Root CA",
        asset_class="root_ca", algorithm="RSA",
        cert_subject="CN=Root CA,O=X",
        raw_details={
            "provenance": "artifact_parsed", "confidence": 0.90,
            "discovered_by": "vault_certificate",
        },
    )
    merged = correlate_findings([a, b])
    assert len(merged) == 1
    assert merged[0].raw_details["corroboration_count"] == 2


def test_stamp_finding_custody_sets_hsm_for_vault_pkcs11():
    finding = RawCryptoFinding(
        id="hsm-1", source_type="keystore",
        source_location="pkcs11://token/slot0/k",
        tags=["hsm", "token"],
        raw_details={"discovered_by": "vault_pkcs11", "confidence": 0.85},
    )
    stamp_finding_custody(finding)
    assert finding.raw_details["custody"] == "hsm"
