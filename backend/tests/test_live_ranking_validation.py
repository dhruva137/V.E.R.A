"""Structural validation of QIRS ranking against real live TLS out-dir.

Skips when ``demo/live/out`` has no ``tls.json`` (gitignored / not collected).
When present, asserts the invariants the two-axis model claims on public
handshakes: key exchange is present, scores are deterministic, no PEM leaks,
and X25519 KX outranks the leaf certificate on every endpoint that has both.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from collectors.vault_collector import scan_vault
from engine.qirs import score_assets
from engine.threat_model import ThreatModel
from models.schemas import CryptoAsset

REPO = Path(__file__).resolve().parents[2]
LIVE_OUT = REPO / "demo" / "live" / "out"
LIVE_TLS = LIVE_OUT / "tls.json"

_PEM_MARKERS = (
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
    "-----BEGIN OPENSSH PRIVATE KEY-----",
    "-----BEGIN ENCRYPTED PRIVATE KEY-----",
    "-----BEGIN CERTIFICATE-----",
)


pytestmark = pytest.mark.skipif(
    not LIVE_TLS.is_file(),
    reason="demo/live/out/tls.json absent — run demo/live/collect.py first",
)


@pytest.fixture(scope="module")
def live_findings():
    findings, _errors = scan_vault(LIVE_OUT)
    assert findings, "live out present but scan_vault returned no findings"
    return findings


@pytest.fixture(scope="module")
def threat_model():
    return ThreatModel()


def _assets_from(findings) -> list[CryptoAsset]:
    return [CryptoAsset(**f.model_dump(), name=f.id) for f in findings]


def _is_kx(asset) -> bool:
    return (
        getattr(asset, "asset_class", None) == "tls_key_exchange"
        or getattr(asset, "usage", None) == "key_exchange"
    )


def _is_tls_cert(asset) -> bool:
    return getattr(asset, "asset_class", None) == "tls_certificate"


def test_live_out_manifest_not_synthetic():
    manifest = LIVE_OUT / "manifest.json"
    assert manifest.is_file()
    data = json.loads(manifest.read_text(encoding="utf-8"))
    assert data.get("synthetic") is False
    assert data.get("key_material_present") is False


def test_live_key_exchange_present(live_findings):
    kx = [f for f in live_findings if _is_kx(f)]
    assert kx, "expected at least one tls_key_exchange from live handshakes"
    assert any(
        (f.key_exchange or "").upper().startswith("X25519")
        or (f.key_exchange or "").upper() == "X25519"
        for f in kx
    ), "expected X25519 among live key-exchange findings"


def test_live_scores_deterministic(live_findings, threat_model):
    first = score_assets(_assets_from(live_findings), threat_model)
    second = score_assets(_assets_from(live_findings), threat_model)
    assert sorted((a.id, round(a.qirs, 6)) for a in first) == sorted(
        (a.id, round(a.qirs, 6)) for a in second
    )
    assert sorted((a.id, round(a.h_score, 6), round(a.t_score, 6)) for a in first) == sorted(
        (a.id, round(a.h_score, 6), round(a.t_score, 6)) for a in second
    )


def test_live_no_pem_in_findings(live_findings):
    blob = json.dumps([f.model_dump() for f in live_findings])
    for marker in _PEM_MARKERS:
        assert marker not in blob
    assert '"CKA_VALUE"' not in blob
    assert "CKA_PRIVATE_EXPONENT" not in blob


def test_live_kx_outranks_certificate_per_endpoint(live_findings, threat_model):
    scored = score_assets(_assets_from(live_findings), threat_model)
    by_loc: dict[str, list[CryptoAsset]] = {}
    for asset in scored:
        by_loc.setdefault(asset.source_location or "", []).append(asset)

    pairs = 0
    for loc, group in by_loc.items():
        kx = [a for a in group if _is_kx(a)]
        certs = [a for a in group if _is_tls_cert(a)]
        if not (kx and certs):
            continue
        pairs += 1
        assert max(a.qirs for a in kx) > max(a.qirs for a in certs), (
            f"{loc}: expected key_exchange QIRS > certificate QIRS"
        )

    assert pairs >= 1, "need at least one endpoint with both KX and certificate"


def test_live_no_classically_broken_on_modern_public_tls(live_findings, threat_model):
    scored = score_assets(_assets_from(live_findings), threat_model)
    broken = [a for a in scored if a.classically_broken]
    assert not broken, (
        "public TLS 1.3 endpoints in the sample should not be classically broken; "
        f"got {[a.source_location for a in broken]}"
    )


def test_live_tls_not_change_blocked(live_findings):
    """change_blocked is an HSM/firmware signal; live TLS leaves must not carry it."""
    blocked = [
        f
        for f in live_findings
        if (f.raw_details or {}).get("change_blocked")
        and f.asset_class
        in {"tls_key_exchange", "tls_certificate", "tls_cipher_suite"}
    ]
    assert not blocked
