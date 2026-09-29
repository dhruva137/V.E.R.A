"""WP1: the binary collector, the library KB it consults, and the collector registry.

Fixtures are built in-test or taken from the Python runtime itself, so no
binaries are committed: (a) the runtime's own OpenSSL, (b) synthetic blobs with
constant tables at known offsets, (c) a tiny JAR with a crafted constant pool.
"""

from __future__ import annotations

import datetime
import glob
import io
import json
import os
import ssl
import struct
import sys
import zipfile
from pathlib import Path

import pytest

from collectors import binary_scanner as bs
from collectors.base import CollectResult, Collector, Limits, PLANES
from collectors.registry import REGISTRY, describe
from engine.kb import libraries as kb
from engine.qirs import classify_asset
from models.schemas import CryptoAsset


def _by(findings, **match):
    out = []
    for f in findings:
        d = f.raw_details
        if all((getattr(f, k, None) if hasattr(f, k) else d.get(k)) == v for k, v in match.items()):
            out.append(f)
    return out


# --------------------------------------------------------------------------
# (a) The Python runtime's own OpenSSL
# --------------------------------------------------------------------------


def _runtime_libcrypto() -> Path | None:
    roots = {sys.base_prefix, sys.prefix, os.path.dirname(sys.executable)}
    patterns = []
    for root in roots:
        patterns += [os.path.join(root, "DLLs", "libcrypto-3*.dll"),
                     os.path.join(root, "Library", "bin", "libcrypto-3*.dll"),
                     os.path.join(root, "lib", "libcrypto.so*"),
                     os.path.join(root, "lib", "libcrypto*.dylib")]
    patterns += ["/usr/lib/**/libcrypto.so.*", "/lib/**/libcrypto.so.*", "/usr/lib64/libcrypto.so.*"]
    for pattern in patterns:
        hits = sorted(p for p in glob.glob(pattern, recursive=True) if not p.endswith((".pdb", ".hmac")))
        if hits:
            return Path(hits[0])
    return None


def test_finds_openssl_in_the_python_runtime_libcrypto():
    path = _runtime_libcrypto()
    if path is None:
        pytest.skip("no libcrypto found next to this Python runtime")
    result = bs.BinaryCollector().collect([str(path)])
    libs = _by(result.findings, asset_class="crypto_library", library_id="openssl")
    assert libs, f"OpenSSL not found in {path}"
    lib = libs[0]
    details = lib.raw_details
    assert details["linkage"] == "self"
    assert details["library_version"] != "unknown"
    assert kb.parse_version(details["library_version"])
    expected = kb.version_at_least(details["library_version"], "3.5.0")
    assert details["pqc_capable"] is expected
    assert "version_banner" in details["layers"]
    # What the library implements is recorded on it, not emitted as "uses".
    assert "RSA" in details["implements"] or "ECDSA" in details["implements"]
    assert not _by(result.findings, asset_class="binary", source_location=str(path))


def test_ssl_extension_links_openssl():
    import _ssl

    result = bs.BinaryCollector().collect([_ssl.__file__])
    libs = _by(result.findings, asset_class="crypto_library", library_id="openssl")
    assert libs, "the _ssl extension should link or bundle OpenSSL"
    assert {"linked_library", "version_banner", "symbol"} & set(libs[0].raw_details["layers"])


def test_runtime_openssl_version_matches_ssl_module_when_same_build():
    path = _runtime_libcrypto()
    if path is None:
        pytest.skip("no libcrypto found")
    found = _by(bs.BinaryCollector().collect([str(path)]).findings, library_id="openssl")[0]
    runtime = ssl.OPENSSL_VERSION.split()[1]
    if found.raw_details["library_version"] != runtime:
        pytest.skip(f"scanned {path} is a different build from the ssl module ({runtime})")
    assert found.raw_details["library_version"] == runtime


# --------------------------------------------------------------------------
# (b) Synthetic blobs
# --------------------------------------------------------------------------


def _rules_constant(const_id: str, variant: int = 0) -> bytes:
    return next(c for c in bs.rules().constants if c[0] == const_id)[3][variant]


def _blob(tmp_path: Path, name: str, parts: dict[int, bytes], size: int = 16384) -> Path:
    data = bytearray(b"\x7fELF" + b"\x00" * (size - 4))
    for offset, payload in parts.items():
        data[offset:offset + len(payload)] = payload
    path = tmp_path / name
    path.write_bytes(bytes(data))
    return path


def test_aes_sbox_found_at_known_offset(tmp_path):
    path = _blob(tmp_path, "app.bin", {4096: _rules_constant("aes_sbox")})
    result = bs.BinaryCollector().collect([str(path)])
    aes = _by(result.findings, asset_class="binary", algorithm="AES")
    assert len(aes) == 1
    details = aes[0].raw_details
    assert 4096 in details["offsets"]
    assert details["layers"] == ["constant"]
    assert details["confidence"] == pytest.approx(0.60)
    assert "aes_sbox" in details["constants"]
    # The structure could not be parsed; that is reported, not hidden.
    assert result.failures or details["parser"] in {"lief", "pyelftools"}


def test_constants_found_in_both_byte_orders(tmp_path):
    parts = {
        1024: _rules_constant("sha256_k", 1),     # little-endian
        4096: _rules_constant("p256_prime", 0),   # big-endian
        8192: _rules_constant("md5_t", 1),
    }
    findings = bs.BinaryCollector().collect([str(_blob(tmp_path, "mixed.bin", parts))]).findings
    algorithms = {f.algorithm for f in findings if f.asset_class == "binary"}
    assert {"SHA-256", "ECDSA", "MD5"} <= algorithms


def test_go_binary_version_and_packages(tmp_path):
    parts = {64: bs.GO_BUILDINFO, 128: b"go1.22.5\x00", 512: b"crypto/rsa.GenerateKey\x00crypto/ecdh.X25519"}
    findings = bs.BinaryCollector().collect([str(_blob(tmp_path, "server", parts))]).findings
    go = _by(findings, library_id="go-stdlib")
    assert go and go[0].raw_details["library_version"] == "1.22.5"
    assert go[0].raw_details["pqc_capable"] is False
    assert {"RSA", "ECDH"} <= {f.algorithm for f in findings if f.asset_class == "binary"}


def test_go_banner_ignored_outside_go_binaries(tmp_path):
    findings = bs.BinaryCollector().collect([str(_blob(tmp_path, "c.bin", {128: b"algo1.22 go1.22.5"}))]).findings
    assert not _by(findings, library_id="go-stdlib")


def test_private_key_marker_recorded_but_body_never_read(tmp_path):
    body = b"MIIEpAIBAAKCAQEAsecretbodysecretbodysecretbody"
    pem = b"-----BEGIN RSA PRIVATE KEY-----\n" + body + b"\n-----END RSA PRIVATE KEY-----\n"
    findings = bs.BinaryCollector().collect([str(_blob(tmp_path, "leaky.bin", {2048: pem}))]).findings
    keys = _by(findings, asset_class="embedded_private_key")
    assert len(keys) == 1
    details = keys[0].raw_details
    assert details["private_key_embedded"] is True
    assert details["offset"] == 2048
    assert len(details["marker_digest"]) == 64
    assert keys[0].algorithm == "RSA"
    assert b"secretbody".decode() not in json.dumps(keys[0].model_dump())


def _self_signed_pem() -> bytes:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "pinned.example")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(7)
            .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=30))
            .sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.PEM)


def test_embedded_certificate_is_parsed(tmp_path):
    findings = bs.BinaryCollector().collect([str(_blob(tmp_path, "pin.bin", {1024: _self_signed_pem()}))]).findings
    certs = _by(findings, asset_class="embedded_certificate")
    assert len(certs) == 1
    assert certs[0].algorithm in {"ECDSA", "EC"}
    assert certs[0].cert_subject == "CN=pinned.example"
    assert len(certs[0].raw_details["fingerprint_sha256"]) == 64


def test_oversize_file_is_a_reported_skip(tmp_path):
    path = _blob(tmp_path, "big.bin", {}, size=8192)
    result = bs.BinaryCollector().collect([str(path)], limits=Limits(max_binary_bytes=4096))
    assert not result.findings
    assert any("exceeds limit" in f["reason"] for f in result.failures)


def test_non_binaries_are_ignored(tmp_path):
    (tmp_path / "notes.txt").write_text("RSA_sign EVP_md5 OpenSSL 1.0.2k")
    result = bs.BinaryCollector().collect([str(tmp_path)])
    assert result.findings == []
    assert result.stats["files_seen"] == 1 and result.stats["binaries"] == 0


def test_missing_target_is_a_failure(tmp_path):
    result = bs.BinaryCollector().collect([str(tmp_path / "nope")])
    assert result.failures and result.failures[0]["reason"] == "not found"


def test_symlinks_are_not_followed(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    _blob(outside, "secret.bin", {4096: _rules_constant("aes_sbox")})
    root = tmp_path / "root"
    root.mkdir()
    try:
        os.symlink(outside, root / "link", target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not permitted on this host")
    assert bs.BinaryCollector().collect([str(root)]).findings == []


# --------------------------------------------------------------------------
# (c) A tiny JAR with a crafted constant pool
# --------------------------------------------------------------------------


def _class_file(class_refs: list[str], strings: list[str]) -> bytes:
    pool: list[bytes] = []

    def utf8(text: str) -> int:
        raw = text.encode()
        pool.append(b"\x01" + struct.pack(">H", len(raw)) + raw)
        return len(pool)

    for name in class_refs:
        pool.append(b"\x07" + struct.pack(">H", utf8(name) ))
    for text in strings:
        pool.append(b"\x08" + struct.pack(">H", utf8(text)))
    pool.append(b"\x05" + struct.pack(">q", 42))  # a long takes two slots
    count = len(pool) + 2
    body = b"".join(pool)
    tail = struct.pack(">HHHHHHH", 0x21, 1, 1, 0, 0, 0, 0)
    return b"\xca\xfe\xba\xbe" + struct.pack(">HHH", 0, 52, count) + body + tail


def _jar(path: Path) -> Path:
    inner = io.BytesIO()
    with zipfile.ZipFile(inner, "w") as z:
        z.writestr("META-INF/maven/org.bouncycastle/bcprov-jdk18on/pom.properties",
                   "groupId=org.bouncycastle\nartifactId=bcprov-jdk18on\nversion=1.78\n")
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("com/bank/Payments.class", _class_file(
            ["com/bank/Payments", "javax/crypto/Cipher", "java/security/Signature"],
            ["AES/ECB/PKCS5Padding", "SHA1withRSA", "hello"],
        ))
        z.writestr("com/bank/Util.class", _class_file(["com/bank/Util"], ["RSA", "DES"]))
        z.writestr("BOOT-INF/lib/bcprov-jdk18on-1.78.jar", inner.getvalue())
    return path


def test_jar_constant_pool_algorithms_and_modes(tmp_path):
    findings = bs.BinaryCollector().collect([str(_jar(tmp_path / "payments.jar"))]).findings
    aes = _by(findings, asset_class="binary", algorithm="AES")
    assert len(aes) == 1
    assert aes[0].raw_details["mode"] == "ECB"
    assert aes[0].raw_details["padding"] == "PKCS5Padding"
    assert aes[0].raw_details["confidence"] == pytest.approx(0.75)
    rsa = _by(findings, asset_class="binary", algorithm="RSA")
    assert rsa and rsa[0].raw_details["digest"] == "SHA1"
    # Util.class has "RSA" and "DES" literals but references no JCA API class.
    assert not _by(findings, asset_class="binary", algorithm="DES")


def test_jar_bundled_library_version_from_pom_properties(tmp_path):
    findings = bs.BinaryCollector().collect([str(_jar(tmp_path / "payments.jar"))]).findings
    bc = _by(findings, asset_class="crypto_library", library_id="bouncycastle")
    assert len(bc) == 1
    details = bc[0].raw_details
    assert details["library_version"] == "1.78"
    assert details["linkage"] == "bundled"
    assert details["pqc_capable"] is False
    assert "1.79" in details["upgrade_path"]


def test_malformed_class_is_reported(tmp_path):
    path = tmp_path / "Broken.class"
    path.write_bytes(b"\xca\xfe\xba\xbe\x00\x00\x00\x34\x00\x05\x63")
    result = bs.BinaryCollector().collect([str(path)])
    assert any("class parse failed" in f["reason"] for f in result.failures)


# --------------------------------------------------------------------------
# Library findings through the engine
# --------------------------------------------------------------------------


def _library_asset(version: str, library_id: str = "openssl") -> CryptoAsset:
    lib = kb.get(library_id)
    return CryptoAsset(id="x", name="lib", source_type="binary", source_location="/usr/lib/libcrypto.so.3",
                       asset_class="crypto_library", raw_details=kb.details_for(lib, version))


def test_library_below_pqc_threshold_is_quantum_vulnerable():
    asset = classify_asset(_library_asset("3.0.18"))
    assert asset.verdict == "shor" and asset.quantum_vulnerable
    assert asset.pqc_replacement == "OpenSSL 3.5 LTS"


def test_library_at_threshold_is_not_a_blocker():
    asset = classify_asset(_library_asset("3.5.0"))
    assert asset.verdict == "pqc" and not asset.quantum_vulnerable


def test_library_with_unknown_version_is_unknown_not_guessed():
    asset = classify_asset(_library_asset(None))
    assert asset.verdict == "unknown"
    assert "Version unknown" in asset.vulnerability_reason


def test_binary_findings_run_through_the_scan_pipeline():
    from engine.core import scan_pipeline
    from engine.qirs import score_assets
    from engine.threat_model import ThreatModel

    path = _runtime_libcrypto()
    if path is None:
        pytest.skip("no libcrypto found")
    findings = bs.BinaryCollector().collect([str(path)]).findings
    assets = [CryptoAsset(**f.model_dump(), name=f.raw_details["display_name"]) for f in findings]
    score_assets(assets, ThreatModel())
    run = scan_pipeline.run(assets)
    assert run.checks_passed
    ranked = {row["id"]: row for row in run.ranked}
    lib = next(a for a in assets if a.raw_details.get("library_id") == "openssl")
    assert ranked[lib.id]["planes"] == {"built": pytest.approx(0.85)}


# --------------------------------------------------------------------------
# Knowledge base integrity
# --------------------------------------------------------------------------


def test_kb_entries_are_well_formed():
    data = kb.load()
    assert data["as_of"]
    for lib in data["libraries"].values():
        assert lib.status in {"verified", "VERIFY"}, lib.id
        values = lib.pqc_native_from.values() if isinstance(lib.pqc_native_from, dict) else [lib.pqc_native_from]
        for value in values:
            assert value is None or value in {"any", "never"} or kb.parse_version(value), lib.id


@pytest.mark.parametrize("text,expected", [
    ("3.0.18", (3, 0, 18)), ("1.1.1w", (1, 1, 1)), ("go1.22.5", (1, 22, 5)), ("24", (24,)),
    ("", None), (None, None), ("unknown", None),
])
def test_parse_version(text, expected):
    assert kb.parse_version(text) == expected


def test_version_comparison_never_guesses():
    assert kb.version_at_least("3.5", "3.5.0") is True
    assert kb.version_at_least("3.4.9", "3.5.0") is False
    assert kb.version_at_least(None, "3.5.0") is None
    assert kb.version_at_least("unknown", "3.5.0") is None


def test_native_library_names_resolve():
    assert kb.for_native("libssl.so.3").id == "openssl"
    assert kb.for_native("libcrypto-3-x64.dll").id == "openssl"
    assert kb.for_native("libmbedcrypto.so.7").id == "mbedtls"
    assert kb.for_native("kernel32.dll") is None


# --------------------------------------------------------------------------
# Registry
# --------------------------------------------------------------------------


def test_registry_collectors_satisfy_the_contract():
    assert "binary" in REGISTRY
    for name, collector in REGISTRY.items():
        assert isinstance(collector, Collector), name
        assert collector.name == name
        assert collector.plane in PLANES
    assert {row["name"] for row in describe()} == set(REGISTRY)


def test_wrapped_collectors_report_failures(tmp_path):
    result = REGISTRY["keystore"].collect([str(tmp_path / "missing")])
    assert isinstance(result, CollectResult)
    assert result.failures and "does not exist" in result.failures[0]["reason"]


def test_one_cipher_in_two_modes_is_two_assets_named_by_mode():
    from collectors.binary_scanner import _symbols_by_mode
    assert _symbols_by_mode(["EVP_aes_256_gcm", "EVP_aes_256_cbc_hmac_sha1", "EVP_aes_256_cfb128", "EVP_aes_256_xts",
                             "EVP_aes_256_gcm_siv", "AES_set_encrypt_key"]) == {
        "gcm": ["EVP_aes_256_gcm"], "cbc": ["EVP_aes_256_cbc_hmac_sha1"], "cfb": ["EVP_aes_256_cfb128"],
        "other": ["EVP_aes_256_xts"], "gcm-siv": ["EVP_aes_256_gcm_siv"]}
    assert _symbols_by_mode(["AES_set_encrypt_key"]) == {}
