"""Offline production-like scenarios against the demo vault (and optional live out).

These are not a second product surface. They lock the claims a design-partner
demo has to survive with no network and no SoftHSM install: payment HSM objects
are change-blocked, TLS key-exchange can outrank the cert, correlation collapses
duplicate certificates, no key material survives a findings dump, unplugging
pack.payments does not move Bel/K or QIRS inputs, vault scan is a write tool,
a run issues a certificate, and every adapter states proves / cannot_prove.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from adapters.cloud_kms import CloudKmsAdapter
from adapters.keystore import KeystoreAdapter
from adapters.kmip import KmipAdapter
from adapters.pkcs11 import Pkcs11Adapter
from adapters.tls import TlsAdapter, parse as parse_tls
from collectors.vault_collector import DEFAULT_VAULT, scan_vault
from engine.agent_control import WRITE_TOOLS
from engine.core.scan_pipeline import run as pipeline_run
from engine.packs import PACKS, PackRegistry
from engine.qirs import score_assets
from engine.threat_model import ThreatModel
from models.schemas import CryptoAsset

REPO = Path(__file__).resolve().parents[2]
LIVE_OUT = REPO / "demo" / "live" / "out"
VAULT_TLS = DEFAULT_VAULT / "tls.json"

# Handshake-shaped document matching demo/live/out/tls.json (findings[]).
_SYNTHETIC_TLS = {
    "source": "tls",
    "collected_at": "2026-08-29T09:00:00Z",
    "note": "Synthetic. Same shape as a live handshake dump.",
    "findings": [
        {
            "id": "syn-tls-cert",
            "source_type": "tls",
            "source_location": "api.example.test:443",
            "asset_class": "tls_certificate",
            "algorithm": "RSA",
            "key_size": 2048,
            "protocol": "TLSv1.3",
            "cert_subject": "CN=api.example.test",
            "usage": "signing",
            "raw_details": {
                "type": "certificate",
                "provenance": "runtime_observed",
                "confidence": 0.98,
                "discovered_by": "vault_tls",
            },
        },
        {
            "id": "syn-tls-kx",
            "source_type": "tls",
            "source_location": "api.example.test:443",
            "asset_class": "tls_key_exchange",
            "key_exchange": "X25519",
            "protocol": "TLSv1.3",
            "usage": "key_exchange",
            "raw_details": {
                "type": "key_exchange",
                "provenance": "runtime_observed",
                "confidence": 0.98,
                "discovered_by": "vault_tls",
            },
        },
        {
            "id": "syn-tls-suite",
            "source_type": "tls",
            "source_location": "api.example.test:443",
            "asset_class": "tls_cipher_suite",
            "cipher_suite": "TLS_AES_256_GCM_SHA384",
            "protocol": "TLSv1.3",
            "usage": "encryption",
            "raw_details": {
                "type": "cipher_suite",
                "provenance": "runtime_observed",
                "confidence": 0.98,
                "discovered_by": "vault_tls",
            },
        },
    ],
}

_PEM_MARKERS = (
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
    "-----BEGIN OPENSSH PRIVATE KEY-----",
    "-----BEGIN ENCRYPTED PRIVATE KEY-----",
    "-----BEGIN CERTIFICATE-----",
)

_FIVE_ADAPTERS = (
    Pkcs11Adapter,
    KmipAdapter,
    CloudKmsAdapter,
    TlsAdapter,
    KeystoreAdapter,
)


@pytest.fixture(scope="module")
def threat_model():
    return ThreatModel()


def _assets_from(findings) -> list[CryptoAsset]:
    return [CryptoAsset(**f.model_dump(), name=f.id) for f in findings]


def _is_kx(item) -> bool:
    return (
        getattr(item, "asset_class", None) == "tls_key_exchange"
        or getattr(item, "usage", None) == "key_exchange"
    )


def _is_tls_cert(item) -> bool:
    return getattr(item, "asset_class", None) == "tls_certificate"


def _handshake_findings():
    """Live out-dir if present and complete; else vault tls.json; else synthetic."""
    if LIVE_OUT.is_dir() and (LIVE_OUT / "tls.json").is_file():
        findings, _ = scan_vault(LIVE_OUT)
        if any(_is_kx(f) for f in findings) and any(_is_tls_cert(f) for f in findings):
            return findings
    if VAULT_TLS.is_file():
        return parse_tls(json.loads(VAULT_TLS.read_text(encoding="utf-8")))
    return parse_tls(_SYNTHETIC_TLS)


def test_scenario_payments_hsm_change_blocked():
    """Vault load → at least one change-blocked payment or firmware asset."""
    findings, errors = scan_vault()
    assert not errors
    blocked = [
        f for f in findings
        if f.raw_details.get("change_blocked")
        and f.asset_class in {"payment_hsm", "firmware_signing"}
    ]
    assert blocked, "expected a firmware- or payment-HSM object marked change_blocked"
    assert any(f.asset_class == "payment_hsm" for f in blocked) or any(
        f.asset_class == "firmware_signing" for f in blocked
    )


def test_scenario_tls_live_shape_key_exchange_outranks_cert(threat_model):
    """Key exchange can outrank the certificate on QIRS when both are present."""
    findings = _handshake_findings()
    scored = score_assets(_assets_from(findings), threat_model)

    by_loc: dict[str, list[CryptoAsset]] = {}
    for asset in scored:
        by_loc.setdefault(asset.source_location, []).append(asset)

    pairs = 0
    for group in by_loc.values():
        kx = [a for a in group if _is_kx(a)]
        certs = [a for a in group if _is_tls_cert(a)]
        if not (kx and certs):
            continue
        pairs += 1
        assert max(a.qirs for a in kx) > max(a.qirs for a in certs)

    if pairs == 0:
        kx = [a for a in scored if _is_kx(a)]
        certs = [a for a in scored if _is_tls_cert(a)]
        assert kx and certs, "need a key_exchange and a tls_certificate"
        assert max(a.qirs for a in kx) > max(a.qirs for a in certs)
    else:
        assert pairs >= 1


def test_scenario_correlation_keystore_and_certificates_merge():
    """Same cert in keystore + certificates.json: raw objects → fewer assets.
    The raw count is read from the showcase expectations, the vault's single
    record of its own size."""
    expected = json.loads(
        (Path(__file__).resolve().parents[2] / "demo" / "showcase" / "expected.json")
        .read_text(encoding="utf-8")
    )
    raw, _ = scan_vault(correlate_sources=False)
    correlated, _ = scan_vault()
    assert len(raw) == expected["raw_objects"]
    assert len(correlated) < len(raw)
    assert len({f.id for f in correlated}) == len(correlated)

    ks_subjects = {
        f.cert_subject.lower()
        for f in raw
        if f.raw_details.get("discovered_by") == "vault_keystore" and f.cert_subject
    }
    cert_subjects = {
        f.cert_subject.lower()
        for f in raw
        if f.raw_details.get("discovered_by") == "vault_certificate" and f.cert_subject
    }
    overlap = ks_subjects & cert_subjects
    assert overlap, "demo vault must share at least one subject across the two sensors"


def test_scenario_no_key_material_in_findings_dump():
    """Entire findings JSON dump: no PEM headers, no CKA_VALUE field."""
    findings, errors = scan_vault()
    assert not errors
    blob = json.dumps([f.model_dump() for f in findings])
    for marker in _PEM_MARKERS:
        assert marker not in blob
    assert '"CKA_VALUE"' not in blob
    assert "CKA_PRIVATE_EXPONENT" not in blob


def test_scenario_pack_unplug_evidence_and_score_inputs_stable(threat_model):
    """Enable/disable pack.payments: evidence and QIRS inputs from asset_class stay.

    Language from the pack registry changes; corroboration and score inputs do not.
    """
    findings, _ = scan_vault()
    scored = score_assets(_assets_from(findings), threat_model)
    inputs_before = {
        a.id: (a.x_c, a.x_i, a.y, a.s, a.e, a.c, a.h_score, a.t_score, a.qirs)
        for a in scored
    }
    run_before = pipeline_run(scored)
    evidence_before = {
        aid: (e["confidence"], tuple(sorted(e["planes"].items())))
        for aid, e in run_before.corroboration.items()
    }

    registry = PackRegistry()
    for pack_id in PACKS:
        registry.enable(pack_id)
    language_on = registry.resolved("payments")
    assert registry.disable("pack.payments") is True
    language_off = registry.resolved("payments")

    scored_after = score_assets(_assets_from(findings), threat_model)
    inputs_after = {
        a.id: (a.x_c, a.x_i, a.y, a.s, a.e, a.c, a.h_score, a.t_score, a.qirs)
        for a in scored_after
    }
    run_after = pipeline_run(scored_after)
    evidence_after = {
        aid: (e["confidence"], tuple(sorted(e["planes"].items())))
        for aid, e in run_after.corroboration.items()
    }

    assert inputs_before == inputs_after
    assert evidence_before == evidence_after
    assert language_on["board_framing"] != language_off["board_framing"]
    assert language_on["controls"] != language_off["controls"]
    assert "pack.payments" in language_on["packs_applied"]
    assert "pack.payments" not in language_off["packs_applied"]


def test_scenario_write_tools_includes_scan_key_vault():
    assert "scan_key_vault" in WRITE_TOOLS


def test_scenario_manifest_digest_is_reproducible(threat_model):
    """The same estate, policy and threat model always produce the same digest,
    and the manifest names what it was computed from."""
    findings, _ = scan_vault()
    first = pipeline_run(score_assets(_assets_from(findings), threat_model))
    second = pipeline_run(score_assets(_assets_from(findings), threat_model))
    assert first.manifest["digest_sha256"] == second.manifest["digest_sha256"]
    assert len(first.manifest["digest_sha256"]) == 64
    assert first.manifest["run_id"] != second.manifest["run_id"]
    assert first.manifest["threat_model"]
    assert first.manifest["assets"] == len(first.ranked) >= 1
    assert first.checks_passed is True


def test_scenario_adapters_coverage_contract():
    assert len(_FIVE_ADAPTERS) == 5
    seen = set()
    for cls in _FIVE_ADAPTERS:
        adapter = cls()
        contract = adapter.coverage_contract()
        assert contract.get("proves"), f"{cls.__name__} proves is empty"
        assert contract.get("cannot_prove"), f"{cls.__name__} cannot_prove is empty"
        assert isinstance(contract["proves"], list)
        assert isinstance(contract["cannot_prove"], list)
        adapter_id = contract.get("adapter_id") or adapter.id
        assert adapter_id
        seen.add(adapter_id)
    assert seen == {"pkcs11", "kmip", "cloud_kms", "tls", "keystore"}
