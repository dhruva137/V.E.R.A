"""M1 - TLS collector.

Performs a passive TLS handshake against an endpoint list and records what was
negotiated: protocol version, cipher suite, key exchange, and the leaf
certificate's key algorithm, size, signature algorithm and validity window.

This is exactly what a browser or SSL Labs does. No authentication is
attempted, no payload is sent beyond the handshake, and nothing is written. It
is the same traffic the endpoint serves to any visitor.

Changes from the previous version:

  - Failures were swallowed into an empty list, so an unreachable host was
    indistinguishable from a host with no crypto. Unreachable targets are now
    reported back with the reason, which matters on stage when a scan comes
    back short.
  - The key exchange was inferred from the cipher suite name, which is wrong
    for TLS 1.3 - the suite name carries no key exchange at all. The negotiated
    group is read directly where the runtime exposes it.
  - Certificates were parsed with verification disabled and no note of it. It
    still is (an expired or self-signed certificate is a finding, not a reason
    to abort), but the verification result is now recorded as a finding of its
    own.
"""

from __future__ import annotations

import concurrent.futures
import datetime
import hashlib
import socket
import ssl

from collectors.base import stable_id
from engine import offline
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import (
    dh, dsa, ec, ed448, ed25519, rsa, x448, x25519,
)

from models.schemas import RawCryptoFinding

DEFAULT_TIMEOUT = 6.0


def get_algorithm_details(public_key) -> tuple[str, int | None, str | None]:
    """(algorithm, key size in bits, curve name)."""
    if isinstance(public_key, rsa.RSAPublicKey):
        return "RSA", public_key.key_size, None
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return "ECDSA", public_key.curve.key_size, public_key.curve.name
    if isinstance(public_key, dsa.DSAPublicKey):
        return "DSA", public_key.key_size, None
    if isinstance(public_key, dh.DHPublicKey):
        return "DH", public_key.key_size, None
    if isinstance(public_key, ed25519.Ed25519PublicKey):
        return "Ed25519", 256, "Curve25519"
    if isinstance(public_key, ed448.Ed448PublicKey):
        return "Ed448", 448, "Curve448"
    if isinstance(public_key, x25519.X25519PublicKey):
        return "X25519", 256, "Curve25519"
    if isinstance(public_key, x448.X448PublicKey):
        return "X448", 448, "Curve448"
    return "Unknown", None, None


def _parse_target(target: str) -> tuple[str, int]:
    text = target.strip()
    for prefix in ("https://", "http://"):
        if text.startswith(prefix):
            text = text[len(prefix):]
    text = text.split("/")[0]
    if ":" in text:
        host, _, port = text.rpartition(":")
        try:
            return host, int(port)
        except ValueError:
            return text, 443
    return text, 443


def _negotiated_group(tls_socket) -> str | None:
    """The negotiated key-exchange group, where the runtime exposes it.

    Python's ssl module only gained group_name() in 3.13 with a new enough
    OpenSSL. Where it is unavailable we return None rather than guessing from
    the cipher suite, because for TLS 1.3 that guess is always wrong.
    """
    getter = getattr(tls_socket, "group_name", None)
    if callable(getter):
        try:
            return getter()
        except (ssl.SSLError, OSError, NotImplementedError):
            return None
    return None


def _key_exchange_for(protocol: str | None, cipher_name: str, group: str | None) -> str | None:
    if group:
        return group
    if protocol == "TLSv1.3":
        # TLS 1.3 always uses an ephemeral (EC)DHE group, but the suite name
        # does not identify it. Guessing X25519 here would be recording an
        # assumption as a measurement; the group probe resolves it properly.
        return None
    upper = cipher_name.upper()
    if "ECDHE" in upper:
        return "ECDHE"
    if "DHE" in upper:
        return "DHE"
    if upper.startswith("AES") or "RSA" in upper:
        return "RSA"
    return None


# Candidate groups, weakest first. Each is probed by restricting the handshake
# to that group alone and seeing whether the server completes it - the same
# technique SSL Labs uses, and a real measurement rather than an inference.
#
# The hybrid entries need OpenSSL 3.5+. On an older library OpenSSL rejects the
# name outright, which we report as "not testable here" rather than as "not
# supported by the server" - those are very different findings.
_CANDIDATE_GROUPS = [
    ("prime256v1", "P-256", False),
    ("secp384r1", "P-384", False),
    ("secp521r1", "P-521", False),
    ("X25519", "X25519", False),
    ("X448", "X448", False),
    ("X25519MLKEM768", "X25519MLKEM768", True),
    ("SecP256r1MLKEM768", "SecP256r1MLKEM768", True),
]


def probe_key_exchange_groups(host: str, port: int = 443) -> dict:
    """Determine which key-exchange groups an endpoint actually accepts.

    Returns the supported list, whether any post-quantum hybrid group is
    offered, and which candidates could not be tested by the local library.
    """
    offline.allow(host)
    supported: list[str] = []
    untestable: list[str] = []
    hybrid_confirmed = False

    for openssl_name, label, is_hybrid in _CANDIDATE_GROUPS:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        try:
            context.set_ecdh_curve(openssl_name)
        except (ValueError, ssl.SSLError):
            # The local OpenSSL does not know this group. This says nothing
            # about the server and must not be recorded as a server result.
            untestable.append(label)
            continue

        try:
            with socket.create_connection((host, port), timeout=DEFAULT_TIMEOUT) as raw:
                with context.wrap_socket(raw, server_hostname=host):
                    supported.append(label)
                    if is_hybrid:
                        hybrid_confirmed = True
        except (OSError, ssl.SSLError):
            # Handshake refused: the server does not accept this group.
            continue

    # Tri-state, because "we could not test it" is not "the server said no".
    # Every hybrid candidate needs OpenSSL 3.5+; on an older library the honest
    # answer is unknown, and reporting False there would understate PQC
    # readiness across the whole scan.
    hybrid_untested = any(
        label in untestable for _, label, is_hybrid in _CANDIDATE_GROUPS if is_hybrid
    )
    if hybrid_confirmed:
        hybrid_status = "supported"
    elif hybrid_untested:
        hybrid_status = "unknown"
    else:
        hybrid_status = "not_supported"

    return {
        "supported": supported,
        "untestable_locally": untestable,
        "hybrid_status": hybrid_status,
        "hybrid_note": (
            "Hybrid groups could not be tested: the local OpenSSL "
            f"({ssl.OPENSSL_VERSION}) predates ML-KEM support, which landed in 3.5. "
            "This is a limitation of the scanning host, not a finding about the server."
            if hybrid_status == "unknown"
            else None
        ),
        # The strongest group we could negotiate, not the server's stated
        # preference - TLS does not expose that to a client that offers one
        # group at a time. For risk purposes every classical group here is
        # equally Shor-breakable, so the choice does not affect scoring.
        "strongest_supported": supported[-1] if supported else None,
    }


def _verify_chain(host: str, port: int) -> tuple[bool, str | None]:
    """Second connection with verification on, so trust failures are findings."""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=DEFAULT_TIMEOUT) as raw:
            with context.wrap_socket(raw, server_hostname=host):
                return True, None
    except ssl.SSLCertVerificationError as exc:
        return False, exc.verify_message or str(exc)
    except (OSError, ssl.SSLError) as exc:
        return False, f"{type(exc).__name__}: {exc}"


def _scan_single_endpoint(
    target: str, probe_groups: bool = True
) -> tuple[list[RawCryptoFinding], dict | None]:
    """Scan one endpoint. Returns (findings, failure) - failure is None on success."""
    host, port = _parse_target(target)
    offline.allow(host)  # an operator-named target stays reachable under VERA_OFFLINE=1
    location = f"{host}:{port}"
    findings: list[RawCryptoFinding] = []

    # Verification is disabled for the inspection handshake on purpose: an
    # expired or untrusted certificate is a finding we want to record, not a
    # reason to abort the scan. The trust result is captured separately.
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((host, port), timeout=DEFAULT_TIMEOUT) as raw:
            with context.wrap_socket(raw, server_hostname=host) as tls:
                der_certificate = tls.getpeercert(binary_form=True)
                cipher = tls.cipher()
                protocol = tls.version()
                group = _negotiated_group(tls)
                peer_ip = raw.getpeername()[0]
    except (OSError, ssl.SSLError) as exc:
        return [], {"target": location, "reason": f"{type(exc).__name__}: {exc}"}

    chain_trusted, trust_error = _verify_chain(host, port)

    if der_certificate:
        certificate = x509.load_der_x509_certificate(der_certificate, default_backend())
        algorithm, key_size, curve = get_algorithm_details(certificate.public_key())

        try:
            signature_algorithm = certificate.signature_algorithm_oid._name
        except AttributeError:
            signature_algorithm = "Unknown"

        not_before = certificate.not_valid_before_utc
        not_after = certificate.not_valid_after_utc
        days_remaining = (not_after - datetime.datetime.now(datetime.timezone.utc)).days

        findings.append(RawCryptoFinding(
            id=stable_id("tls", location, "certificate", certificate.serial_number),
            source_type="tls",
            source_location=location,
            asset_class="tls_certificate",
            algorithm=algorithm,
            key_size=key_size,
            protocol=protocol,
            signature_algorithm=signature_algorithm,
            cert_subject=certificate.subject.rfc4514_string(),
            cert_issuer=certificate.issuer.rfc4514_string(),
            cert_validity_start=not_before.isoformat(),
            cert_validity_end=not_after.isoformat(),
            cert_serial=str(certificate.serial_number),
            usage="signing",
            tags=["live-scan"],
            environment="production",
            raw_details={
                "type": "certificate",
                "curve": curve,
                "chain_trusted": chain_trusted,
                "trust_error": trust_error,
                "days_until_expiry": days_remaining,
                "peer_ip": peer_ip,
                # Links the served certificate to the key-manager object that holds its key.
                "public_key_sha256": hashlib.sha256(certificate.public_key().public_bytes(
                    serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest(),
                "fingerprint_sha256": hashlib.sha256(der_certificate).hexdigest(),
            },
        ))

    if cipher:
        cipher_name = cipher[0]

        findings.append(RawCryptoFinding(
            id=stable_id("tls", location, "cipher", cipher_name),
            source_type="tls",
            source_location=location,
            asset_class="tls_cipher_suite",
            cipher_suite=cipher_name,
            protocol=protocol,
            usage="encryption",
            tags=["live-scan"],
            environment="production",
            raw_details={"type": "cipher_suite", "bits": cipher[2] if len(cipher) > 2 else None,
                         "peer_ip": peer_ip},
        ))

        key_exchange = _key_exchange_for(protocol, cipher_name, group)
        group_probe: dict = {}

        # For TLS 1.3 the suite name carries no key exchange, so without a probe
        # there is simply no key-exchange asset - and that is the highest-HNDL
        # class in the model. Probing recovers it as a measurement.
        if not key_exchange and probe_groups:
            group_probe = probe_key_exchange_groups(host, port)
            key_exchange = group_probe.get("strongest_supported")

        if key_exchange:
            findings.append(RawCryptoFinding(
                id=stable_id("tls", location, "kex", key_exchange),
                source_type="tls",
                source_location=location,
                asset_class="tls_key_exchange",
                key_exchange=key_exchange,
                protocol=protocol,
                usage="key_exchange",
                tags=["live-scan"],
                environment="production",
                raw_details={
                    "type": "key_exchange",
                    "negotiated_group": group,
                    "source": (
                        "negotiated group reported by the TLS library" if group
                        else "single-group handshake probe" if group_probe
                        else "inferred from cipher suite name"
                    ),
                    **({
                        "groups_supported": group_probe.get("supported"),
                        "hybrid_status": group_probe.get("hybrid_status"),
                        "hybrid_note": group_probe.get("hybrid_note"),
                        "untestable_locally": group_probe.get("untestable_locally"),
                    } if group_probe else {}),
                },
            ))

    return findings, None


def scan_tls_endpoints(
    targets: list[str], max_workers: int = 12, probe_groups: bool = True
) -> tuple[list[RawCryptoFinding], list[dict]]:
    """Scan every target concurrently.

    Returns (findings, unreachable). Reporting the unreachable list is the
    point: a scan that silently returns fewer assets than it was given targets
    is a scan nobody can trust.

    `probe_groups` costs up to five extra handshakes per endpoint. It is worth
    it - it is the only way to recover the key-exchange asset on TLS 1.3, and
    it answers "does anything in this estate already support a hybrid group",
    which is the question the whole migration turns on.
    """
    findings: list[RawCryptoFinding] = []
    unreachable: list[dict] = []

    if not targets:
        return findings, unreachable

    def scan(target: str):
        return _scan_single_endpoint(target, probe_groups=probe_groups)

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        for result, failure in pool.map(scan, targets):
            findings.extend(result)
            if failure:
                unreachable.append(failure)

    return findings, unreachable
