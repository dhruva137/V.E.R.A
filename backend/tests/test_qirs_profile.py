"""QIRS profile resolution must not branch on source_type in qirs.py.

asset_class and TLS shape signals select the profile; legacy source_type
mapping lives in engine.packs as DATA.
"""

from __future__ import annotations

from models.schemas import CryptoAsset
from engine.qirs import PROFILES, resolve_profile


def _asset(**kw) -> CryptoAsset:
    defaults = dict(
        id="a1",
        source_type="",
        source_location="/x",
        name="test",
    )
    defaults.update(kw)
    return CryptoAsset(**defaults)


def test_asset_class_wins_without_source_type():
    asset = _asset(asset_class="root_ca", source_type="")
    assert resolve_profile(asset) is PROFILES["root_ca"]


def test_tls_key_exchange_shape_with_empty_source_type():
    asset = _asset(usage="key_exchange", source_type="")
    assert resolve_profile(asset) is PROFILES["tls_key_exchange"]


def test_tls_key_exchange_from_field_with_empty_source_type():
    asset = _asset(key_exchange="X25519", source_type="")
    assert resolve_profile(asset) is PROFILES["tls_key_exchange"]


def test_tls_cipher_suite_shape_with_empty_source_type():
    asset = _asset(cipher_suite="TLS_AES_128_GCM_SHA256", source_type="")
    assert resolve_profile(asset) is PROFILES["tls_cipher_suite"]


def test_tls_certificate_shape_with_empty_source_type():
    asset = _asset(cert_subject="CN=example", source_type="")
    assert resolve_profile(asset) is PROFILES["tls_certificate"]


def test_legacy_source_type_still_resolves_via_packs_data():
    """source_type=config with no asset_class: packs LEGACY table, not qirs ifs."""
    asset = _asset(source_type="config")
    assert resolve_profile(asset) is PROFILES["config"]

    asset = _asset(source_type="source")
    assert resolve_profile(asset) is PROFILES["source"]


def test_explicit_qirs_profile_in_raw_details():
    asset = _asset(raw_details={"qirs_profile": "backup_encryption"})
    assert resolve_profile(asset) is PROFILES["backup_encryption"]


def test_unclassified_falls_back_to_generic_key():
    asset = _asset(source_type="keystore")
    assert resolve_profile(asset) is PROFILES["generic_key"]
