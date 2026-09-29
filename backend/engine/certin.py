"""Conformance of a CBOM to CERT-In's minimum elements for cryptographic assets.

CERT-In, *Technical Guidelines on SBOM, QBOM & CBOM, AIBOM and HBOM*, version
2.0 (9 July 2025), Table 9 lists the minimum elements a CBOM must carry for
each cryptographic asset type: algorithms, keys, protocols and certificates.
This module checks an exported CycloneDX document against that table, element
by element, and reports what is present, what is missing and why.

It reads the document itself, not the scan, so the answer describes exactly the
file an organisation would hand over. Three outcomes per element per component:

* present: the field is in the CBOM;
* missing: the field could exist but the source did not record it, or the asset
  is unresolved. Each has a stated reason, so the gap can be closed;
* not applicable: no value can exist. No OID is registered for a TLS version or
  an SSH method name, and a mode only applies to block ciphers and AEADs.
  These are excluded from the percentage and listed with the reason.
"""

from __future__ import annotations

from collections import Counter

STANDARD = ("CERT-In, Technical Guidelines on SBOM, QBOM & CBOM, AIBOM and HBOM, version 2.0 "
            "(9 July 2025), Table 9: Minimum Elements pertaining to Cryptographic Asset")
URL = "https://www.cert-in.org.in/PDF/TechnicalGuidelines-on-SBOM,QBOM&CBOM,AIBOM_and_HBOM_ver2.0.pdf"

# Names with no registered OID: hybrid TLS groups and SSH methods are registered
# as codepoints and names; plain "AES" needs a key size and mode to name an OID.
_NO_OID_NAMES = ("MLKEM", "SNTRUP", "X25519KYBER")
_MODAL_PRIMITIVES = {"block-cipher", "ae"}


def _get(component: dict, path: str):
    value = component
    for part in path.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return value


def _present(value) -> bool:
    if value in (None, "", [], {}):
        return False
    if value == "unknown" or value == ["unknown"]:
        return False
    return True


def _algorithm_elements(c: dict) -> list[tuple[str, str, bool | None, str]]:
    """(element, path, present-or-None-if-n/a, reason) for one algorithm component."""
    props = _get(c, "cryptoProperties.algorithmProperties") or {}
    name = str(c.get("name", ""))
    unresolved = name.lower().startswith("unknown")
    primitive = props.get("primitive")
    upper = name.upper().replace("-", "")
    out = [
        ("Name", "name", not unresolved, "The algorithm could not be resolved from the source; review the finding."),
        ("Asset type", "cryptoProperties.assetType", True, ""),
        ("Primitive", "cryptoProperties.algorithmProperties.primitive", _present(primitive),
         "The primitive could not be determined."),
    ]
    if primitive in _MODAL_PRIMITIVES:
        out.append(("Mode", "cryptoProperties.algorithmProperties.mode", _present(props.get("mode")),
                    "The source does not state the mode (for example AES.new without MODE_*)."))
    else:
        out.append(("Mode", "cryptoProperties.algorithmProperties.mode", None,
                    "A mode applies only to block ciphers and AEADs."))
    out.append(("Crypto functions", "cryptoProperties.algorithmProperties.cryptoFunctions",
                _present(props.get("cryptoFunctions")), "The use (sign, encrypt, ...) is not known."))
    out.append(("Classical security level", "cryptoProperties.algorithmProperties.classicalSecurityLevel",
                "classicalSecurityLevel" in props,
                "Depends on a key size the source did not record." if not unresolved else
                "The algorithm is unresolved."))
    if any(marker in upper for marker in _NO_OID_NAMES):
        out.append(("OID", "cryptoProperties.oid", None,
                    "Hybrid groups and SSH methods are registered as codepoints and names, not OIDs."))
    elif upper == "AES" or (primitive in _MODAL_PRIMITIVES and not props.get("mode") and "AES" in upper):
        out.append(("OID", "cryptoProperties.oid", False,
                    "An AES OID names the key size and mode; record the mode to resolve it."))
    elif "AES" in upper and props.get("mode") == "ctr":
        out.append(("OID", "cryptoProperties.oid", None, "NIST registers no OID for AES in CTR mode."))
    elif upper == "HMAC":
        out.append(("OID", "cryptoProperties.oid", False,
                    "An HMAC OID names its hash (HMAC-SHA256, ...); the source did not record the hash."))
    else:
        out.append(("OID", "cryptoProperties.oid", _present(_get(c, "cryptoProperties.oid")),
                    "No registered OID is mapped for this name yet." if not unresolved else "The algorithm is unresolved."))
    return out


def _key_elements(c: dict) -> list[tuple[str, str, bool | None, str]]:
    base = "cryptoProperties.relatedCryptoMaterialProperties."
    props = _get(c, "cryptoProperties.relatedCryptoMaterialProperties") or {}
    return [
        ("Name", "name", _present(c.get("name")), ""),
        ("Asset type", "cryptoProperties.assetType", True, ""),
        ("Id", base + "id", _present(props.get("id")), "The source recorded no key identifier."),
        ("State", base + "state", _present(props.get("state")),
         "The source recorded no state and the validity dates do not settle it."),
        ("Size", base + "size", _present(props.get("size")), "The source recorded no key size."),
        ("Creation date", base + "creationDate", _present(props.get("creationDate")),
         "Certificates and many keystores do not record when the key was created."),
        ("Activation date", base + "activationDate", _present(props.get("activationDate")),
         "The source recorded no activation or validity-start date."),
    ]


def _protocol_elements(c: dict) -> list[tuple[str, str, bool | None, str]]:
    base = "cryptoProperties.protocolProperties."
    props = _get(c, "cryptoProperties.protocolProperties") or {}
    kind = props.get("type")
    suites = props.get("cipherSuites") or props.get("ikev2TransformTypes") or props.get("cryptoRefArray")
    return [
        ("Name", "name", _present(c.get("name")), ""),
        ("Asset type", "cryptoProperties.assetType", True, ""),
        ("Version", base + "version", _present(props.get("version")),
         "The configuration line lists algorithms but does not state the protocol version." if kind != "ike" else
         "The configuration does not state the IKE version and its implementation (and so its default) is not recognisable."),
        ("Cipher suites", base + "cipherSuites", _present(suites),
         "No cipher suite or transform was recorded."),
        ("OID", "cryptoProperties.oid", None,
         "No OID is registered for TLS, SSH or IKE versions; the version identifies the protocol."),
    ]


def _certificate_elements(c: dict) -> list[tuple[str, str, bool | None, str]]:
    base = "cryptoProperties.certificateProperties."
    props = _get(c, "cryptoProperties.certificateProperties") or {}
    fields = [("Subject name", "subjectName"), ("Issuer name", "issuerName"), ("Not valid before", "notValidBefore"),
              ("Not valid after", "notValidAfter"), ("Signature algorithm reference", "signatureAlgorithmRef"),
              ("Subject public key reference", "subjectPublicKeyRef"), ("Certificate format", "certificateFormat"),
              ("Certificate extension", "certificateExtension")]
    return [("Name", "name", _present(c.get("name")), ""), ("Asset type", "cryptoProperties.assetType", True, "")] + [
        (label, base + field, _present(props.get(field)), "The certificate source did not record this field.")
        for label, field in fields]


_CHECKS = {
    "algorithm": ("Algorithms", _algorithm_elements),
    "related-crypto-material": ("Keys", _key_elements),
    "protocol": ("Protocols", _protocol_elements),
    "certificate": ("Certificates", _certificate_elements),
}


def conformance(cbom: dict, examples: int = 5) -> dict:
    """Element-by-element conformance of a CycloneDX CBOM to CERT-In Table 9."""
    components = [c for c in cbom.get("components", []) if c.get("type") == "cryptographic-asset"]
    by_type: list[dict] = []
    total_required = total_present = 0
    for asset_type, (label, check) in _CHECKS.items():
        items = [c for c in components if _get(c, "cryptoProperties.assetType") == asset_type]
        elements: dict[str, dict] = {}
        for c in items:
            for element, path, present, reason in check(c):
                e = elements.setdefault(element, {"element": element, "path": path, "applicable": 0,
                                                  "present": 0, "not_applicable": 0, "missing_examples": [],
                                                  "reasons": Counter(), "na_reason": ""})
                if present is None:
                    e["not_applicable"] += 1
                    e["na_reason"] = reason
                    continue
                e["applicable"] += 1
                if present:
                    e["present"] += 1
                else:
                    e["reasons"][reason] += 1
                    if len(e["missing_examples"]) < examples:
                        e["missing_examples"].append(c.get("name"))
        rows = []
        for e in elements.values():
            total_required += e["applicable"]
            total_present += e["present"]
            rows.append({**{k: v for k, v in e.items() if k != "reasons"},
                         "percent": round(100.0 * e["present"] / e["applicable"], 1) if e["applicable"] else None,
                         "missing_reasons": [{"reason": r, "count": n} for r, n in e["reasons"].most_common()]})
        by_type.append({"asset_type": asset_type, "label": label, "components": len(items), "elements": rows})
    return {
        "standard": STANDARD,
        "url": URL,
        "cbom_spec": cbom.get("specVersion"),
        "components": len(components),
        "required": total_required,
        "present": total_present,
        "percent": round(100.0 * total_present / total_required, 1) if total_required else None,
        "by_type": by_type,
    }
