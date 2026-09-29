"""Read a CycloneDX CBOM back into raw findings.

The inverse of `engine.cbom`. Discovery is commoditised - IBM's CBOMkit is a
Linux Foundation project now - so the useful position is to consume what those
scanners emit rather than rebuild them. Anything producing CycloneDX 1.6
cryptographic-asset components can be ranked here without rescanning.

Deliberately lenient about everything except the crypto itself. Other tools
populate different subsets of the schema, and refusing a document because it
omits an optional field would defeat the point. Fields we cannot read are left
unset, and the scoring engine applies its class defaults exactly as it does for
a native scan.
"""

from __future__ import annotations

import hashlib
import re

from models.schemas import RawCryptoFinding

# CycloneDX cryptoFunctions -> the usage vocabulary the scoring engine expects.
_FUNCTION_TO_USAGE = {
    "sign": "signing", "verify": "signing",
    "encrypt": "encryption", "decrypt": "encryption",
    "keygen": "key_exchange", "encapsulate": "key_exchange", "decapsulate": "key_exchange",
    "keyderive": "key_derivation",
    "digest": "hashing",
}

# Primitive -> asset class, used only when nothing better is available.
_PRIMITIVE_TO_CLASS = {
    "kem": "tls_key_exchange",
    "key-agree": "tls_key_exchange",
    "signature": "generic_key",
    "pke": "generic_key",
    "block-cipher": "backup_encryption",
    "stream-cipher": "backup_encryption",
    "hash": "source",
    "mac": "source",
}


def _stable_id(*parts: str) -> str:
    digest = hashlib.sha256("|".join(("cbom-import", *parts)).encode()).hexdigest()
    return f"{digest[:8]}-{digest[8:12]}-{digest[12:16]}-{digest[16:20]}-{digest[20:32]}"


def _key_size(algorithm_properties: dict, name: str) -> int | None:
    raw = algorithm_properties.get("parameterSetIdentifier")
    if raw and str(raw).isdigit():
        return int(raw)
    # Fall back to a size embedded in the name, e.g. "RSA-2048".
    match = re.search(r"(\d{3,5})", name or "")
    return int(match.group(1)) if match else None


def _classify_asset_class(name: str, primitive: str, subject: str | None) -> str:
    """Infer a policy profile from whatever the document reveals.

    A CBOM from another tool has no notion of blast radius or trust horizon, so
    the class is what decides which defaults apply. Named CAs and signing keys
    are worth detecting because they are the assets the two-axis model exists
    to rank correctly.
    """
    haystack = f"{name} {subject or ''}".lower()

    if "root" in haystack and ("ca" in haystack or "authority" in haystack):
        return "root_ca"
    if any(k in haystack for k in ("issuing ca", "intermediate", "sub ca", "subca")):
        return "issuing_ca"
    if "firmware" in haystack:
        return "firmware_signing"
    if any(k in haystack for k in ("code sign", "code-sign", "release sign")):
        return "code_signing"
    if any(k in haystack for k in ("hsm", "pkcs#11", "pkcs11")):
        return "payment_hsm"
    if any(k in haystack for k in ("jwt", "saml", "oidc", "token")):
        return "token_signing"
    if "ssh" in haystack:
        return "ssh_key"
    if any(k in haystack for k in ("vpn", "ipsec", "ike")):
        return "vpn_ipsec"

    return _PRIMITIVE_TO_CLASS.get(primitive, "generic_key")


def _vera_prop(component: dict, name: str) -> str:
    """One `vera:` namespaced property, or "" if this CBOM is not VERA's."""
    for prop in component.get("properties") or []:
        if prop.get("name") == f"vera:{name}":
            return str(prop.get("value") or "").strip()
    return ""


def _vera_tags(component: dict) -> list[str]:
    """Tags VERA recorded on export, if this document came from VERA.

    A CBOM from another scanner carries no such property and returns nothing,
    which is the honest outcome: that document really does not know whether a
    host is a payment switch, and the operator's chosen sector baseline is then
    the only signal there is.
    """
    return [t.strip() for t in _vera_prop(component, "tags").split(",") if t.strip()]


def _library_finding(component: dict) -> RawCryptoFinding | None:
    """A crypto library component back into a library finding.

    Only libraries VERA recorded as crypto libraries: an ordinary SBOM library
    in a third-party document is not a cryptographic asset.
    """
    if _vera_prop(component, "asset-class") != "crypto_library":
        return None
    location = _vera_prop(component, "source-location") or component.get("name") or ""
    details = {"type": "imported", "source": "CycloneDX import", "bom_ref": component.get("bom-ref"),
               "package": component.get("name"), "library_version": component.get("version"),
               "purl": component.get("purl")}
    for key, field in (("pqc-native-from", "pqc_native_from"), ("pqc-capable", "pqc_capable"),
                       ("library-family", "library"), ("ecosystem", "ecosystem")):
        value = _vera_prop(component, key)
        if value:
            details[field] = value
    return RawCryptoFinding(
        id=_stable_id(component.get("bom-ref") or location, location),
        source_type="dependency",
        asset_class="crypto_library",
        source_location=location,
        algorithm=_vera_prop(component, "algorithm") or None,
        usage="library",
        tags=["imported", *_vera_tags(component)],
        environment="production",
        raw_details=details,
    )


def cbom_to_findings(document: dict) -> list[RawCryptoFinding]:
    """Extract findings from a CycloneDX document.

    Certificates and protocols are folded onto the algorithm they reference
    rather than becoming separate findings, so an imported document produces
    one asset per real cryptographic object instead of three rows describing
    the same key.
    """
    components = document.get("components") or []

    # Index certificates and protocols by the algorithm they point at, so their
    # detail can enrich that algorithm's finding.
    certificates: dict[str, dict] = {}
    protocols: dict[str, dict] = {}

    for component in components:
        crypto = component.get("cryptoProperties") or {}
        asset_type = crypto.get("assetType")

        if asset_type == "certificate":
            props = crypto.get("certificateProperties") or {}
            ref = props.get("signatureAlgorithmRef") or props.get("subjectPublicKeyRef")
            if ref:
                certificates[ref] = {**props, "_name": component.get("name")}

        elif asset_type == "protocol":
            props = crypto.get("protocolProperties") or {}
            refs = list(props.get("cryptoRefArray") or [])
            for suite in props.get("cipherSuites") or []:
                refs.extend(suite.get("algorithms") or [])
                props.setdefault("_suite", suite.get("name"))
            for ref in refs:
                protocols[ref] = props

    findings: list[RawCryptoFinding] = []

    for component in components:
        if component.get("type") == "library":
            library = _library_finding(component)
            if library is not None:
                findings.append(library)
            continue
        crypto = component.get("cryptoProperties") or {}
        if crypto.get("assetType") != "algorithm":
            continue
        # One part of a cipher suite whose asset is another component: folded into that asset.
        if _vera_prop(component, "suite-part-of"):
            continue

        bom_ref = component.get("bom-ref") or ""
        name = component.get("name") or "Unknown"
        algorithm_properties = crypto.get("algorithmProperties") or {}
        primitive = algorithm_properties.get("primitive") or "unknown"

        functions = algorithm_properties.get("cryptoFunctions") or []
        usage = next(
            (_FUNCTION_TO_USAGE[f] for f in functions if f in _FUNCTION_TO_USAGE), None
        )

        certificate = certificates.get(bom_ref) or {}
        protocol = protocols.get(bom_ref) or {}

        subject = certificate.get("subjectName")
        protocol_version = protocol.get("version")
        location = (
            _vera_prop(component, "source-location")
            or subject
            or certificate.get("_name")
            or (f"protocol:{protocol.get('type')}" if protocol else None)
            or name
        )

        findings.append(RawCryptoFinding(
            id=_stable_id(bom_ref or name, location),
            source_type="keystore" if subject else ("tls" if protocol else "source"),
            # VERA's own record where the document carries one, inference
            # otherwise - so a third-party CBOM behaves exactly as before.
            asset_class=(
                _vera_prop(component, "asset-class")
                or _classify_asset_class(name, primitive, subject)
            ),
            source_location=location,
            # A VERA document always carries vera:asset-class, so the absence
            # of vera:algorithm on one is information rather than a gap: this
            # asset genuinely had no primitive in that field - a TLS group lives
            # in key_exchange, a config line naming none has all three empty.
            # Falling back to the component name relabelled both cases.
            algorithm=(
                _vera_prop(component, "algorithm")
                or (None if _vera_prop(component, "asset-class") else name)
            ),
            key_exchange=_vera_prop(component, "key-exchange") or None,
            key_size=_key_size(algorithm_properties, name),
            # An IKE version is a connection setting, kept in raw_details as the collector records it.
            protocol=(
                f"TLSv{protocol_version}" if protocol_version and protocol.get("type") == "tls"
                else None if protocol.get("type") == "ike" else protocol_version
            ),
            cipher_suite=_vera_prop(component, "cipher-suite") or protocol.get("_suite"),
            signature_algorithm=name if usage == "signing" else None,
            cert_subject=subject,
            cert_issuer=certificate.get("issuerName"),
            cert_validity_start=certificate.get("notValidBefore"),
            cert_validity_end=certificate.get("notValidAfter"),
            usage=usage,
            # "imported" marks provenance; the rest is what the estate knew
            # about this asset, and is what classify_persona reads.
            tags=["imported", *_vera_tags(component)],
            environment="production",
            raw_details={
                "type": "imported",
                "source": "CycloneDX import",
                "bom_ref": bom_ref,
                "primitive": primitive,
                "curve": algorithm_properties.get("curve"),
                **({"ike_version": protocol_version,
                    "ike_version_source": _vera_prop(component, "ike-version-source") or "CycloneDX import"}
                   if protocol_version and protocol.get("type") == "ike" else {}),
            },
        ))

    return findings
