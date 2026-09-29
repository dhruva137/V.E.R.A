"""M1 - Keystore collector.

Parses PEM directories and PKCS#12 files for keys and certificates. The
previous version only returned five hard-coded findings and ignored the paths
it was given, so `scan_keystores(["/some/real/path"])` silently returned demo
data - which would be a very bad surprise on a real estate.

JKS is deliberately not parsed: it needs a Java toolchain or a
permissively-licensed pure-Python parser, and the blueprint's dependency rule
plus the schedule make that a poor trade. Unparsed files are reported as
unreadable rather than skipped, so nothing goes missing without saying so.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs12

from collectors.base import stable_id
from collectors.tls_scanner import get_algorithm_details
from models.schemas import RawCryptoFinding

_PEM_SUFFIXES = {".pem", ".crt", ".cer", ".key"}
_PKCS12_SUFFIXES = {".p12", ".pfx"}
_UNSUPPORTED_SUFFIXES = {".jks", ".keystore"}


def _finding_from_certificate(certificate, path: Path, asset_class: str) -> RawCryptoFinding:
    algorithm, key_size, curve = get_algorithm_details(certificate.public_key())
    try:
        signature_algorithm = certificate.signature_algorithm_oid._name
    except AttributeError:
        signature_algorithm = "Unknown"

    return RawCryptoFinding(
        id=stable_id("keystore", str(path), certificate.serial_number, certificate.subject.rfc4514_string()),
        source_type="keystore",
        source_location=str(path),
        asset_class=asset_class,
        algorithm=algorithm,
        key_size=key_size,
        signature_algorithm=signature_algorithm,
        cert_subject=certificate.subject.rfc4514_string(),
        cert_issuer=certificate.issuer.rfc4514_string(),
        cert_validity_start=certificate.not_valid_before_utc.isoformat(),
        cert_validity_end=certificate.not_valid_after_utc.isoformat(),
        cert_serial=str(certificate.serial_number),
        usage="signing",
        tags=["keystore-scan"],
        raw_details={
            "type": "certificate", "format": path.suffix.lstrip("."), "curve": curve,
            # Public data: the strongest identity key for cross-collector resolution.
            "fingerprint_sha256": certificate.fingerprint(hashes.SHA256()).hex(),
            "public_key_sha256": hashlib.sha256(certificate.public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest(),
        },
    )


def _classify_certificate(certificate) -> str:
    """Infer an asset class from the certificate's own extensions."""
    try:
        constraints = certificate.extensions.get_extension_for_class(x509.BasicConstraints).value
        if constraints.ca:
            is_root = certificate.subject == certificate.issuer
            return "root_ca" if is_root else "issuing_ca"
    except x509.ExtensionNotFound:
        pass

    try:
        usage = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        oids = {oid.dotted_string for oid in usage}
        if "1.3.6.1.5.5.7.3.3" in oids:  # id-kp-codeSigning
            return "code_signing"
        if "1.3.6.1.5.5.7.3.1" in oids:  # id-kp-serverAuth
            return "tls_certificate"
        if "1.3.6.1.5.5.7.3.2" in oids:  # id-kp-clientAuth
            return "device_identity"
    except x509.ExtensionNotFound:
        pass

    return "generic_key"


def _scan_pem(path: Path) -> list[RawCryptoFinding]:
    data = path.read_bytes()
    findings: list[RawCryptoFinding] = []

    for certificate in x509.load_pem_x509_certificates(data):
        findings.append(
            _finding_from_certificate(certificate, path, _classify_certificate(certificate))
        )

    if not findings and b"PRIVATE KEY" in data:
        private_key = serialization.load_pem_private_key(data, password=None)
        algorithm, key_size, curve = get_algorithm_details(private_key.public_key())
        findings.append(RawCryptoFinding(
            id=stable_id("keystore", str(path), "private_key", "pem"),
            source_type="keystore",
            source_location=str(path),
            asset_class="generic_key",
            algorithm=algorithm,
            key_size=key_size,
            usage="signing",
            tags=["keystore-scan"],
            raw_details={"type": "private_key", "format": "PEM", "curve": curve},
        ))

    return findings


def _scan_pkcs12(path: Path, password: bytes | None) -> list[RawCryptoFinding]:
    private_key, certificate, additional = pkcs12.load_key_and_certificates(
        path.read_bytes(), password
    )
    findings: list[RawCryptoFinding] = []

    if certificate is not None:
        findings.append(
            _finding_from_certificate(certificate, path, _classify_certificate(certificate))
        )
    for extra in additional or []:
        findings.append(_finding_from_certificate(extra, path, _classify_certificate(extra)))

    if private_key is not None and certificate is None:
        algorithm, key_size, curve = get_algorithm_details(private_key.public_key())
        findings.append(RawCryptoFinding(
            id=stable_id("keystore", str(path), "private_key", "pkcs12"),
            source_type="keystore",
            source_location=str(path),
            asset_class="generic_key",
            algorithm=algorithm,
            key_size=key_size,
            usage="signing",
            tags=["keystore-scan"],
            raw_details={"type": "private_key", "format": "PKCS12", "curve": curve},
        ))

    return findings


def scan_keystores(
    paths: list[str], password: str | None = None
) -> tuple[list[RawCryptoFinding], list[dict]]:
    """Scan real keystore paths. Returns (findings, unreadable)."""
    findings: list[RawCryptoFinding] = []
    unreadable: list[dict] = []
    secret = password.encode() if password else None

    for raw_path in paths:
        path = Path(raw_path)
        if not path.exists():
            unreadable.append({"path": raw_path, "reason": "path does not exist"})
            continue

        candidates = (
            [p for p in path.rglob("*") if p.is_file()] if path.is_dir() else [path]
        )

        for candidate in candidates:
            suffix = candidate.suffix.lower()
            try:
                if suffix in _PEM_SUFFIXES:
                    findings.extend(_scan_pem(candidate))
                elif suffix in _PKCS12_SUFFIXES:
                    findings.extend(_scan_pkcs12(candidate, secret))
                elif suffix in _UNSUPPORTED_SUFFIXES:
                    unreadable.append({
                        "path": str(candidate),
                        "reason": (
                            "JKS parsing is not implemented. Convert with "
                            "'keytool -importkeystore -deststoretype PKCS12' and rescan."
                        ),
                    })
            except Exception as exc:
                unreadable.append({"path": str(candidate), "reason": f"{type(exc).__name__}: {exc}"})

    return findings, unreadable
