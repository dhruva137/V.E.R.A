"""Key-vault collector — reads enterprise key-manager metadata into findings.

WHY THIS EXISTS
---------------
Every other collector in this package reaches out and looks at something: a TLS
endpoint, a file on disk, a line of source. None of them can see the place a
bank actually keeps the keys that matter — the HSM, the KMIP key manager, the
cloud KMS. Those are the assets with the worst timelines in any real estate, and
until now they could only enter VERA as a hand-written CSV row.

This collector reads the *native response shapes* of those systems:

    PKCS#11   C_FindObjects + C_GetAttributeValue, per slot
    KMIP 2.1  Locate + GetAttributes
    Cloud KMS AWS DescribeKey / Azure Key Vault / GCP CryptoKeyVersion
    Keystore  keytool -list -v
    X.509     parsed chain metadata

`demo/vault/` holds a synthetic estate in exactly those shapes, so the demo path
and the production path are the same code. Pointing this at a real dump of the
same shape works without modification; only the transport differs.

WHAT IT REFUSES TO DO
---------------------
It never records key material, and it cannot, because none of these sources
return any. Private objects report `CKA_EXTRACTABLE: false`; cloud KMS never
exports a managed key; keystore parsing stops at the certificate. The only
key-derived value carried through is a SHA-256 fingerprint of the public half.
`test_vault_collector.py` asserts that no PEM body or private-key value can
survive into a finding.

PROVENANCE
----------
Findings are stamped `declared` (0.85) for the systems of record that own the
object, and `artifact_parsed` (0.90) for things read out of a file. That grade
is what the engine uses to decide how much to believe them, so it matters that
an HSM's word about its own key outranks a regex, and that neither outranks an
observed handshake.
"""

from __future__ import annotations

import json
from datetime import date, datetime
from pathlib import Path
from typing import Any

from engine.intake.contract import stamp_finding_custody
from engine.intake.identity import correlate_findings as _correlate
from engine.intake.identity import identity_key as _identity
from engine.intake.scrub import scrub as _scrub
from models.schemas import RawCryptoFinding

# Repository-root-relative default. Overridden by VERA_VAULT_DIR.
DEFAULT_VAULT = Path(__file__).resolve().parents[2] / "demo" / "vault"

# PKCS#11 key types -> (algorithm, asset_class fallback)
_CKK = {
    "CKK_RSA": "RSA",
    "CKK_EC": "ECDSA",
    "CKK_ECDSA": "ECDSA",
    "CKK_AES": "AES",
    "CKK_DES3": "3DES",
    "CKK_GENERIC_SECRET": "HMAC",
}

# Cloud KMS key specs -> (algorithm, key size)
_KEY_SPEC = {
    "SYMMETRIC_DEFAULT": ("AES", 256),
    "RSA_2048": ("RSA", 2048),
    "RSA_3072": ("RSA", 3072),
    "RSA_4096": ("RSA", 4096),
    "ECC_NIST_P256": ("ECDSA", 256),
    "ECC_NIST_P384": ("ECDSA", 384),
    "EC_SIGN_P256_SHA256": ("ECDSA", 256),
    "EC_SIGN_P384_SHA384": ("ECDSA", 384),
    "RSA_SIGN_PKCS1_2048_SHA256": ("RSA", 2048),
    "RSA_SIGN_PKCS1_4096_SHA256": ("RSA", 4096),
    "GOOGLE_SYMMETRIC_ENCRYPTION": ("AES", 256),
}


def _days_until(iso: str | None) -> int | None:
    if not iso:
        return None
    try:
        stamp = iso.replace("Z", "")
        parsed = (datetime.fromisoformat(stamp).date()
                  if "T" in stamp else date.fromisoformat(stamp))
    except ValueError:
        return None
    return (parsed - date.today()).days


def _resolve(root: str | Path | None) -> Path:
    """Resolve a vault directory the way the operator meant it.

    The API server runs with `backend/` as its working directory, so a relative
    path typed by a human — `demo/live/out`, straight out of the collector's own
    "load it" line — resolved against the wrong place and the vault was reported
    missing. Relative paths are therefore tried against the repository root as
    well as the process CWD before being called absent.
    """
    if not root:
        return DEFAULT_VAULT
    candidate = Path(root)
    if candidate.is_absolute() or candidate.is_dir():
        return candidate
    repo_relative = Path(__file__).resolve().parents[2] / candidate
    return repo_relative if repo_relative.is_dir() else candidate


def _load(directory: Path, name: str) -> dict | None:
    path = directory / name
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        # A malformed source is a reported gap, never a crash. The caller sees
        # it as a missing source rather than a partial estate that looks whole.
        return None


# ---------------------------------------------------------------------------
# PKCS#11
# ---------------------------------------------------------------------------

def _pkcs11_class(label: str, usage_sign: bool, key_type: str) -> str:
    """Map an HSM object to a QIRS policy profile.

    Label-driven, because that is the only intent signal an HSM object carries.
    A firmware-signing key and a PIN-verification key have completely different
    horizons, and CKA_KEY_TYPE cannot tell them apart.
    """
    lowered = label.lower()
    if "firmware" in lowered:
        return "firmware_signing"
    if "code" in lowered or "release" in lowered:
        return "code_signing"
    if "device" in lowered or "-ca" in lowered or "issuing" in lowered:
        return "issuing_ca"
    if any(w in lowered for w in ("pin", "card", "cvk", "issuer-master", "emv")):
        return "payment_hsm"
    if "token" in lowered or "jwt" in lowered:
        return "token_signing"
    if key_type in {"CKK_AES", "CKK_DES3"}:
        return "backup_encryption"
    return "code_signing" if usage_sign else "generic_key"


def _from_pkcs11(doc: dict) -> list[RawCryptoFinding]:
    findings: list[RawCryptoFinding] = []
    for slot in doc.get("slots", []):
        token = slot.get("token_label", "unknown-token")
        pqc_ready = bool(slot.get("pqc_ready"))
        for obj in slot.get("objects", []):
            label = obj.get("CKA_LABEL", "")
            key_type = obj.get("CKA_KEY_TYPE", "")
            algorithm = _CKK.get(key_type, key_type.replace("CKK_", ""))
            bits = obj.get("CKA_MODULUS_BITS") or obj.get("CKA_VALUE_LEN")
            if bits and obj.get("CKA_VALUE_LEN"):
                bits *= 8  # CKA_VALUE_LEN is bytes
            if obj.get("CKA_EC_CURVE_NAME") == "secp256r1":
                bits = 256

            location = f"pkcs11://{token}/slot{slot.get('slot_id')}/{label}"
            findings.append(RawCryptoFinding(
                id=f"vault-hsm-{token}-{label}".lower().replace(" ", "-"),
                source_type="keystore",
                source_location=location,
                asset_class=_pkcs11_class(label, obj.get("CKA_SIGN", False), key_type),
                algorithm=algorithm,
                key_size=bits,
                cert_validity_start=obj.get("CKA_START_DATE") or None,
                cert_validity_end=obj.get("CKA_END_DATE") or None,
                usage="sign" if obj.get("CKA_SIGN") else "encrypt",
                owner=obj.get("owner"),
                environment="production",
                tags=["hsm", token.lower(), slot.get("manufacturer", "").lower()]
                     + (["pci-scope"] if obj.get("pci_scope") else [])
                     + ([] if pqc_ready else ["pqc-firmware-blocked"]),
                raw_details=_scrub({
                    **obj,
                    "provenance": "declared",
                    "confidence": 0.85,
                    "discovered_by": "vault_pkcs11",
                    "display_name": f"{label} ({token})",
                    "hsm_token": token,
                    "hsm_model": slot.get("model"),
                    "hsm_firmware": slot.get("firmware_version"),
                    "hsm_fips_mode": slot.get("fips_mode"),
                    "hsm_pqc_ready": pqc_ready,
                    "hsm_pqc_note": slot.get("pqc_readiness_note"),
                    # The operational fact that outranks the risk score: an
                    # asset on a token with no PQC mechanism cannot be migrated
                    # in place at any priority.
                    "change_blocked": not pqc_ready,
                    "expiry_days": _days_until(obj.get("CKA_END_DATE")),
                }),
            ))
    return findings


# ---------------------------------------------------------------------------
# KMIP
# ---------------------------------------------------------------------------

def _from_kmip(doc: dict) -> list[RawCryptoFinding]:
    findings = []
    for obj in doc.get("objects", []):
        name = obj.get("Name", obj.get("Unique Identifier", ""))
        algorithm = obj.get("Cryptographic Algorithm", "")
        lowered = name.lower()
        if "tde" in lowered or "archive" in lowered or "backup" in lowered:
            asset_class = "backup_encryption"
        elif "jwt" in lowered or "signing" in lowered:
            asset_class = "token_signing"
        elif "tls" in lowered:
            asset_class = "tls_certificate"
        else:
            asset_class = "generic_key"

        findings.append(RawCryptoFinding(
            id=f"vault-kmip-{obj.get('Unique Identifier','')}".lower(),
            source_type="keystore",
            source_location=f"{doc.get('endpoint','kmip://')}/{obj.get('Unique Identifier','')}",
            asset_class=asset_class,
            algorithm=algorithm,
            key_size=obj.get("Cryptographic Length"),
            usage=",".join(obj.get("Cryptographic Usage Mask", [])) or None,
            cert_validity_start=obj.get("Activation Date"),
            cert_validity_end=obj.get("Deactivation Date"),
            environment="production",
            tags=["kmip", "key-manager",
                  f"state-{str(obj.get('State','')).lower()}"]
                 + ([obj["Object Group"]] if obj.get("Object Group") else []),
            raw_details=_scrub({
                **obj,
                "provenance": "declared",
                "confidence": 0.85,
                "discovered_by": "vault_kmip",
                "display_name": f"{name} (KMIP)",
                # A Deactivated key still present is its own finding: it is not
                # in use, but it is still required to read anything it wrapped.
                "lifecycle_state": obj.get("State"),
            }),
        ))
    return findings


# ---------------------------------------------------------------------------
# Cloud KMS
# ---------------------------------------------------------------------------

def _from_cloud(doc: dict) -> list[RawCryptoFinding]:
    findings: list[RawCryptoFinding] = []

    def add(fid, location, spec, tags, extra, usage=None, expires=None, label=""):
        algorithm, bits = _KEY_SPEC.get(spec, (spec, None))
        findings.append(RawCryptoFinding(
            id=fid, source_type="config", source_location=location,
            asset_class="generic_key" if algorithm == "AES" else "token_signing",
            algorithm=algorithm, key_size=bits, usage=usage,
            cert_validity_end=expires, environment="production",
            tags=tags,
            raw_details=_scrub({
                **extra, "provenance": "declared", "confidence": 0.85,
                "discovered_by": "vault_cloud_kms", "key_spec": spec,
                "display_name": label or location,
            }),
        ))

    aws = doc.get("aws_kms", {})
    for k in aws.get("keys", []):
        add(f"vault-aws-{k['KeyId'][:8]}", k["Arn"], k.get("KeySpec", ""),
            ["cloud-kms", "aws", aws.get("region", "")],
            {**k, "rotation_enabled": k.get("RotationEnabled")},
            usage=k.get("KeyUsage"),
            label=f"{k.get('Description') or k['KeyId'][:8]} (AWS KMS)")

    azure = doc.get("azure_key_vault", {})
    for k in azure.get("keys", []):
        spec = (f"RSA_{k.get('key_size')}" if k.get("kty") == "RSA"
                else f"ECC_NIST_{str(k.get('crv','')).replace('-','')}")
        add(f"vault-azure-{k['kid'].rsplit('/',1)[-1]}", k["kid"], spec,
            ["cloud-kms", "azure"], k,
            label=f"{k['kid'].rsplit('/', 2)[-2]} (Azure Key Vault)",
            usage=",".join(k.get("key_ops", [])),
            expires=(k.get("attributes") or {}).get("exp"))

    gcp = doc.get("gcp_kms", {})
    for k in gcp.get("crypto_key_versions", []):
        add(f"vault-gcp-{k['name'].rsplit('/',3)[-3]}-{k['name'].rsplit('/',1)[-1]}",
            k["name"], k.get("algorithm", ""),
            ["cloud-kms", "gcp",
             f"protection-{str(k.get('protectionLevel','')).lower()}"], k,
            label=f"{k['name'].rsplit('/', 3)[-3]} v{k['name'].rsplit('/', 1)[-1]} (GCP KMS)")

    return findings + _from_cloud_certificates(doc)


# ---------------------------------------------------------------------------
# Cloud certificate services: AWS ACM, Azure Key Vault certificates, GCP Certificate Manager
# ---------------------------------------------------------------------------

# ACM's KeyAlgorithm enum -> (algorithm, bits, curve).
_ACM_KEY = {"RSA_1024": ("RSA", 1024, None), "RSA_2048": ("RSA", 2048, None), "RSA_3072": ("RSA", 3072, None),
            "RSA_4096": ("RSA", 4096, None), "EC_prime256v1": ("ECDSA", 256, "P-256"),
            "EC_secp384r1": ("ECDSA", 384, "P-384"), "EC_secp521r1": ("ECDSA", 521, "P-521")}
_CURVE_BITS = {"P-256": 256, "P-384": 384, "P-521": 521}


def _cloud_cert(fid, location, provider, algorithm, bits, *, subject=None, issuer=None, serial=None, not_before=None,
                not_after=None, signature=None, extra=None, label="") -> RawCryptoFinding:
    return RawCryptoFinding(
        id=fid, source_type="config", source_location=location, asset_class="tls_certificate",
        algorithm=algorithm, key_size=bits, signature_algorithm=signature, cert_subject=subject, cert_issuer=issuer,
        cert_serial=serial, cert_validity_start=not_before, cert_validity_end=not_after, usage="signing",
        environment="production", tags=["cloud-certificate", provider],
        raw_details=_scrub({
            **(extra or {}), "provenance": "declared", "confidence": 0.85,
            "discovered_by": f"vault_cloud_certificate/{provider}", "display_name": label or location,
            "expiry_days": _days_until(not_after),
        }),
    )


def _from_cloud_certificates(doc: dict) -> list[RawCryptoFinding]:
    """Certificates held by a cloud certificate service, from each provider's own read-only API response.

    AWS ACM DescribeCertificate states the key algorithm and names what uses the certificate (InUseBy). Azure Key
    Vault returns the certificate's key policy. GCP Certificate Manager returns only the public certificate, so its
    key is read from that PEM, and the PEM itself is not kept. No provider returns a private key from these calls.
    """
    findings: list[RawCryptoFinding] = []
    for item in (doc.get("aws_acm") or {}).get("certificates", []):
        c = item.get("Certificate", item)
        algorithm, bits, curve = _ACM_KEY.get(c.get("KeyAlgorithm", ""), (c.get("KeyAlgorithm"), None, None))
        findings.append(_cloud_cert(
            f"vault-acm-{c['CertificateArn'].rsplit('/', 1)[-1][:12]}", c["CertificateArn"], "aws", algorithm, bits,
            subject=c.get("Subject"), issuer=c.get("Issuer"), serial=c.get("Serial"), not_before=c.get("NotBefore"),
            not_after=c.get("NotAfter"), signature=c.get("SignatureAlgorithm"),
            extra={"curve": curve, "certificate_type": c.get("Type"), "status": c.get("Status"),
                   "in_use_by": c.get("InUseBy", []), "domain": c.get("DomainName")},
            label=f"{c.get('DomainName') or c['CertificateArn']} (AWS ACM)"))
    for c in (doc.get("azure_key_vault") or {}).get("certificates", []):
        policy = c.get("policy") or {}
        props = policy.get("key_props") or {}
        kty = str(props.get("kty", ""))
        algorithm = "RSA" if kty.startswith("RSA") else "ECDSA" if kty.startswith("EC") else (kty or None)
        attrs = c.get("attributes") or {}
        name = c["id"].rstrip("/").rsplit("/", 2)[-2]
        findings.append(_cloud_cert(
            f"vault-azcert-{name}", c["id"], "azure", algorithm, props.get("key_size") or _CURVE_BITS.get(props.get("crv")),
            subject=(policy.get("x509_props") or {}).get("subject"), issuer=(policy.get("issuer") or {}).get("name"),
            not_before=attrs.get("nbf"), not_after=attrs.get("exp"),
            extra={"curve": props.get("crv"), "exportable": props.get("exportable"), "thumbprint": c.get("x5t")},
            label=f"{name} (Azure Key Vault)"))
    for c in (doc.get("gcp_certificate_manager") or {}).get("certificates", []):
        parsed = _public_pem(c.get("pemCertificate"))
        extra = {k: v for k, v in c.items() if not k.lower().startswith("pem")}
        name = c["name"].rsplit("/", 1)[-1]
        findings.append(_cloud_cert(
            f"vault-gcpcert-{name}", c["name"], "gcp", parsed.get("algorithm"), parsed.get("bits"),
            subject=parsed.get("subject"), issuer=parsed.get("issuer"), serial=parsed.get("serial"),
            not_before=parsed.get("not_before"), not_after=parsed.get("not_after") or c.get("expireTime"),
            signature=parsed.get("signature"), extra={**extra, "curve": parsed.get("curve")},
            label=f"{name} (GCP Certificate Manager)"))
    return findings


def _public_pem(pem: str | None) -> dict:
    """Key and validity facts of a public certificate; empty when there is none or it does not parse."""
    if not pem:
        return {}
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    try:
        cert = x509.load_pem_x509_certificate(pem.encode())
    except ValueError:
        return {}
    key = cert.public_key()
    out = {"subject": cert.subject.rfc4514_string(), "issuer": cert.issuer.rfc4514_string(),
           "serial": format(cert.serial_number, "x"), "not_before": cert.not_valid_before_utc.isoformat(),
           "not_after": cert.not_valid_after_utc.isoformat(), "signature": cert.signature_algorithm_oid._name}
    if isinstance(key, rsa.RSAPublicKey):
        out.update(algorithm="RSA", bits=key.key_size)
    elif isinstance(key, ec.EllipticCurvePublicKey):
        out.update(algorithm="ECDSA", bits=key.curve.key_size, curve=key.curve.name)
    return out


# ---------------------------------------------------------------------------
# Keystores and certificates
# ---------------------------------------------------------------------------

def _from_keystores(doc: dict) -> list[RawCryptoFinding]:
    findings = []
    for store in doc.get("stores", []):
        for entry in store.get("entries", []):
            subject = entry.get("subject_dn", "")
            is_ca = "Root CA" in subject or "Issuing CA" in subject
            findings.append(RawCryptoFinding(
                id=f"vault-ks-{store['path']}-{entry['alias']}".lower()
                   .replace("/", "-").replace(".", "-"),
                source_type="keystore",
                source_location=f"{store['path']}#{entry['alias']}",
                asset_class=("root_ca" if "Root CA" in subject
                             else "issuing_ca" if "Issuing CA" in subject
                             else "tls_certificate"),
                algorithm=entry.get("key_algorithm"),
                key_size=entry.get("key_size"),
                signature_algorithm=entry.get("signature_algorithm"),
                cert_subject=subject,
                cert_issuer=entry.get("issuer_dn"),
                cert_validity_start=entry.get("valid_from"),
                cert_validity_end=entry.get("valid_until"),
                environment="production",
                tags=["keystore", store.get("type", "").lower()]
                     + (["trust-anchor"] if is_ca else []),
                raw_details=_scrub({
                    **entry, "provenance": "artifact_parsed",
                    "confidence": 0.90, "discovered_by": "vault_keystore",
                    "display_name": f"{entry['alias']} ({store.get('type','')})",
                    "store_path": store.get("path"),
                    "store_type": store.get("type"),
                    "expiry_days": _days_until(entry.get("valid_until")),
                }),
            ))
    return findings


def _from_certificates(doc: dict) -> list[RawCryptoFinding]:
    findings = []
    for cert in doc.get("certificates", []):
        subject = cert.get("subject", "")
        is_ca = cert.get("basic_constraints_ca", False)
        self_signed = cert.get("self_signed", False)
        findings.append(RawCryptoFinding(
            id=f"vault-cert-{cert.get('sha256_fingerprint','')[:17]}".lower()
               .replace(":", ""),
            source_type="tls",
            source_location=subject.split(",")[0].replace("CN=", ""),
            asset_class=("root_ca" if is_ca and self_signed
                         else "issuing_ca" if is_ca else "tls_certificate"),
            algorithm=cert.get("public_key_algorithm"),
            key_size=cert.get("public_key_size"),
            signature_algorithm=cert.get("signature_algorithm"),
            cert_subject=subject,
            cert_issuer=cert.get("issuer"),
            cert_validity_start=cert.get("not_before"),
            cert_validity_end=cert.get("not_after"),
            cert_serial=cert.get("serial_number"),
            environment="production",
            tags=["certificate"] + (["trust-anchor"] if is_ca else []),
            raw_details=_scrub({
                **cert, "provenance": "artifact_parsed", "confidence": 0.90,
                "discovered_by": "vault_certificate",
                "expiry_days": _days_until(cert.get("not_after")),
            }),
        ))
    return findings


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def _from_tls(doc: dict) -> list[RawCryptoFinding]:
    """Findings a live TLS handshake produced, passed through as-is.

    An endpoint yields three assets - the certificate, the key-exchange group
    and the cipher suite - and only the first has a subject. Writing just the
    certificates threw away the other two, which are precisely the
    confidentiality-bearing ones: the key exchange is the harvest-now surface.
    """
    findings = []
    for record in doc.get("findings", []):
        try:
            finding = RawCryptoFinding(**record)
        except Exception:  # noqa: BLE001 - one bad record must not lose the rest
            continue
        finding.raw_details.setdefault("provenance", "runtime_observed")
        finding.raw_details.setdefault("confidence", 0.98)
        finding.raw_details.setdefault("discovered_by", "vault_tls")
        findings.append(finding)
    return findings


def _adapter_sources() -> tuple[tuple[str, Any], ...]:
    """File → adapter.parse. Lazy to avoid a circular import with adapters.*

    Parsers still live in this module; adapters are the public seam so the
    engine and discovery surface never import `_from_*` directly.
    """
    from adapters import cloud_kms, kmip, keystore, pkcs11, tls

    return (
        ("tls.json", tls.parse),
        ("hsm_pkcs11.json", pkcs11.parse),
        ("kmip.json", kmip.parse),
        ("cloud_kms.json", cloud_kms.parse),
        ("keystores.json", keystore.parse),
        ("certificates.json", keystore.parse),
    )


# Back-compat for tests/callers that still iterate the old table name.
_SOURCES = None  # resolved on first scan_vault via _adapter_sources()


def scan_vault(
    root: str | Path | None = None,
    correlate_sources: bool = True,
) -> tuple[list[RawCryptoFinding], list[str]]:
    """Read every vault source present under `root`.

    Returns (findings, errors). A missing source is an error entry, not an
    exception: an inventory that silently skips the HSM is the failure this
    whole module exists to prevent.
    """
    directory = _resolve(root)
    findings: list[RawCryptoFinding] = []
    errors: list[str] = []

    if not directory.is_dir():
        return [], [f"Vault directory not found: {directory}"]

    # A vault's manifest declares which sources it contains. Only those are
    # expected, so a key-manager export is not reported as "missing TLS" - that
    # is not a gap in its coverage, it is a different kind of vault. When there
    # is no manifest, every source is expected and every absence is a gap.
    manifest = _load(directory, "manifest.json") or {}
    declared = {entry.get("file") for entry in manifest.get("sources", [])
                if isinstance(entry, dict)}

    for name, parser in _adapter_sources():
        doc = _load(directory, name)
        if doc is None:
            if declared and name not in declared:
                continue
            errors.append(f"{name}: missing or unreadable — that source was not measured.")
            continue
        try:
            findings.extend(parser(doc))
        except Exception as exc:  # noqa: BLE001 - one bad source must not lose the rest
            errors.append(f"{name}: {type(exc).__name__}: {exc}")

    # Custody is an intake fact (hsm|kms|keystore|network), not a QIRS input.
    # Stamp it here so every parser path — including TLS rehydration — carries it
    # without each _from_* needing to know the custody map.
    for finding in findings:
        stamp_finding_custody(finding)

    if correlate_sources:
        findings = _correlate(findings)

    return findings, errors


def vault_summary(root: str | Path | None = None) -> dict:
    """What the vault holds, for the discovery surface."""
    directory = _resolve(root)
    findings, errors = scan_vault(directory)
    manifest = _load(directory, "manifest.json") or {}
    by_source: dict[str, int] = {}
    for f in findings:
        key = f.raw_details.get("discovered_by", "unknown")
        by_source[key] = by_source.get(key, 0) + 1
    return {
        "directory": str(directory),
        "available": directory.is_dir(),
        "objects": len(findings),
        "by_source": by_source,
        "errors": errors,
        "synthetic": manifest.get("synthetic", True),
        "key_material_present": False,
        "blind_spots": manifest.get("blind_spots", []),
    }
