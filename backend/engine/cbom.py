"""CycloneDX 1.7 CBOM emitter (1.6 kept as an export).

`generate_cbom(assets, spec="1.7")` emits a Cryptography Bill of Materials
that validates against the official schema for that version (vendored under
`engine/schemas/`, checked by `engine.cbom_validate`). 1.7 adds the
Cryptography Registry names: `algorithmFamily` and `ellipticCurve` come from
the registry's enumerations, certificates carry `serialNumber` and a SHA-256
`fingerprint`, and IKE proposals are emitted as `ikev2TransformTypes`. 1.6
keeps its `curve` string and none of the 1.7-only fields.

REPRODUCIBLE
------------
Components and dependencies are sorted by bom-ref, bom-refs are SHA-256 of a
stable identity, the serial number is derived from the content, and the
timestamp is taken from the scan (pass `timestamp`). Identical inputs give
byte-identical JSON through `canonical_json`.

Emits a Cryptography Bill of Materials that actually validates. The previous
implementation would have failed on several counts, each of which matters
because the CBOM is the artefact handed to a regulator:

  - ``cryptoFunctions`` carried values like ``"signing"`` and ``"key_exchange"``.
    The 1.6 enum is ``sign``, ``verify``, ``encapsulate``, ``keygen`` and so on.
  - ``primitive`` was ``"pke"`` for anything asymmetric and ``"unknown"``
    otherwise, so signatures, KEMs and key agreement all collapsed together.
  - Protocol assets were given ``algorithmProperties``. Protocols take
    ``protocolProperties``.
  - Private keys were emitted as algorithms rather than
    ``related-crypto-material``.
  - Nothing linked a certificate to the key it certifies, which is most of what
    makes a CBOM more useful than a list.

Enums here follow the CycloneDX 1.6 cryptographic-asset schema (ECMA-424).
"""

from __future__ import annotations

import datetime
import hashlib
import json
import re
import uuid

from engine import taxonomy
from engine.version import TOOL_VERSION
from models.schemas import CryptoAsset

SPEC_VERSION = "1.7"
SUPPORTED_SPECS = ("1.7", "1.6")

# Cryptography Registry (CycloneDX 1.7 cryptography-defs) names. Only
# unambiguous mappings: an RSA key without a known scheme gets no family.
_FAMILY_PREFIXES = (
    ("ML-KEM", "ML-KEM"), ("ML-DSA", "ML-DSA"), ("SLH-DSA", "SLH-DSA"), ("AES", "AES"), ("3DES", "3DES"),
    ("DES", "DES"), ("RC4", "RC4"), ("BLOWFISH", "Blowfish"), ("CHACHA20", "ChaCha20"), ("MD5", "MD5"),
    ("SHA-1", "SHA-1"), ("SHA3", "SHA-3"), ("SHA-", "SHA-2"),
    ("ECDSA", "ECDSA"), ("ECDHE", "ECDH"), ("ECDH", "ECDH"), ("X25519", "ECDH"), ("X448", "ECDH"),
    ("ED25519", "EdDSA"), ("ED448", "EdDSA"), ("DHE", "FFDH"), ("DIFFIE-HELLMAN", "FFDH"), ("DSA", "DSA"),
    ("HMAC", "HMAC"), ("HKDF", "HKDF"), ("LMS", "LMS"), ("XMSS", "XMSS"), ("CAST-128", "CAST5"),
)
_CURVES = {
    "p-256": "nist/P-256", "secp256r1": "nist/P-256", "prime256v1": "nist/P-256",
    "p-384": "nist/P-384", "secp384r1": "nist/P-384", "p-521": "nist/P-521", "secp521r1": "nist/P-521",
    "secp256k1": "secg/secp256k1", "curve25519": "other/Curve25519", "x25519": "other/Curve25519",
    "ed25519": "other/Ed25519", "curve448": "other/Curve448", "x448": "other/Curve448", "ed448": "other/Ed448",
}
# IANA IKEv2 Transform Type 4 group numbers (RFC 3526, RFC 5903, RFC 8031).
_IKE_GROUPS = {("DH", 1024): 2, ("DH", 1536): 5, ("DH", 2048): 14, ("DH", 3072): 15, ("DH", 4096): 16,
               ("DH", 6144): 17, ("DH", 8192): 18, ("ECDH", 256): 19, ("ECDH", 384): 20, ("ECDH", 521): 21,
               ("X25519", None): 31, ("X448", None): 32}

# --- CycloneDX 1.6 enumerations, used by both the emitter and the validator ---

ASSET_TYPES = {"algorithm", "certificate", "protocol", "related-crypto-material"}

PRIMITIVES = {
    "drbg", "mac", "block-cipher", "stream-cipher", "signature", "hash", "pke",
    "xof", "kdf", "key-agree", "kem", "ae", "combiner", "other", "unknown",
}

CRYPTO_FUNCTIONS = {
    "generate", "keygen", "encrypt", "decrypt", "digest", "tag", "keyderive",
    "sign", "verify", "encapsulate", "decapsulate", "other", "unknown",
}

EXECUTION_ENVIRONMENTS = {
    "software-plain-ram", "software-encrypted-ram", "software-tee", "hardware",
    "other", "unknown",
}

IMPLEMENTATION_PLATFORMS = {
    "generic", "x86_32", "x86_64", "armv7-a", "armv7-m", "armv8-a", "armv8-m",
    "armv9-a", "armv9-m", "s390x", "ppc64", "ppc64le", "other", "unknown",
}

MODES = {"cbc", "ecb", "ccm", "gcm", "cfb", "ofb", "ctr", "gcm-siv", "other", "unknown"}

PADDINGS = {"pkcs5", "pkcs7", "pkcs1v15", "oaep", "raw", "other", "unknown"}

RELATED_MATERIAL_TYPES = {
    "private-key", "public-key", "secret-key", "key", "ciphertext", "signature",
    "digest", "initialization-vector", "nonce", "seed", "salt", "shared-secret",
    "tag", "additional-data", "password", "credential", "token", "other", "unknown",
}

PROTOCOL_TYPES = {"tls", "ssh", "ipsec", "ike", "sstp", "wpa", "other", "unknown"}

CERTIFICATE_STATES = {
    "pre-activation", "active", "suspended", "deactivated", "compromised", "destroyed",
}

# Map the taxonomy's usage strings onto the 1.6 cryptoFunctions enum. This is
# the mapping whose absence made the old output invalid.
_USAGE_TO_FUNCTIONS = {
    "signing": ["sign", "verify"],
    "encryption": ["encrypt", "decrypt"],
    "key_exchange": ["keygen", "encapsulate", "decapsulate"],
    "key_wrapping": ["encrypt", "decrypt"],
    "hashing": ["digest"],
    "key_derivation": ["keyderive"],
}


def _bom_ref(*parts: str) -> str:
    digest = hashlib.sha256("|".join(parts).encode()).hexdigest()[:24]
    return f"crypto:{digest}"


def _rfc3339(value: str | None) -> str | None:
    """Normalise a timestamp to RFC 3339, which the schema requires."""
    if not value:
        return None
    text = value.strip()
    try:
        parsed = datetime.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=datetime.timezone.utc)
    return parsed.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# Sources spell usage their own way: KMIP "Sign,Decrypt", AWS "ENCRYPT_DECRYPT",
# JCA-style "sign". Each word maps to the CycloneDX function it names.
_USAGE_WORDS = {
    "sign": ["sign"], "verify": ["verify"], "encrypt": ["encrypt"], "decrypt": ["decrypt"],
    "wrap": ["encrypt"], "unwrap": ["decrypt"], "wrapkey": ["encrypt"], "unwrapkey": ["decrypt"],
    "derive": ["keyderive"], "digest": ["digest"], "hash": ["digest"], "mac": ["tag"], "tag": ["tag"],
    "authentication": ["sign", "verify"], "generatemac": ["tag"], "verifymac": ["tag"],
}
# What a primitive does, when the source says nothing about use (CERT-In Table 9:
# "the cryptographic functions supported by the asset").
_PRIMITIVE_FUNCTIONS = {
    "signature": ["sign", "verify"], "kem": ["keygen", "encapsulate", "decapsulate"],
    "key-agree": ["keygen", "keyderive"], "block-cipher": ["encrypt", "decrypt"],
    "stream-cipher": ["encrypt", "decrypt"], "ae": ["encrypt", "decrypt", "tag"], "hash": ["digest"],
    "mac": ["tag"], "kdf": ["keyderive"], "drbg": ["generate"], "pke": ["encrypt", "decrypt"],
}


def _crypto_functions(asset: CryptoAsset | None, primitive: str) -> list[str]:
    usage = str(getattr(asset, "usage", None) or "")
    functions = list(_USAGE_TO_FUNCTIONS.get(usage, []))
    if not functions and usage:
        for word in re.split(r"[\s,;/|_]+", usage.lower()):
            functions.extend(_USAGE_WORDS.get(word, []))
    if not functions:
        functions = _PRIMITIVE_FUNCTIONS.get(primitive, [])
    ordered = sorted({f for f in functions if f in CRYPTO_FUNCTIONS}, key=functions.index)
    return ordered or ["unknown"]


_MODE_IN_TEXT = re.compile(r"(?:^|[/_\-])(GCM-SIV|GCM|CCM|CBC|CTR|ECB|CFB|OFB)(?:$|[/_\-\d])", re.I)


def _mode_from_text(*texts) -> str | None:
    """A block-cipher mode named in a literal such as "AES/GCM/NoPadding" or "aes-256-cbc"."""
    for text in texts:
        m = _MODE_IN_TEXT.search(str(text or ""))
        if m:
            return m.group(1).lower()
    return None


def _execution_environment(asset: CryptoAsset) -> str:
    location = (asset.source_location or "").lower()
    if location.startswith("hsm://") or asset.asset_class == "payment_hsm":
        return "hardware"
    return "software-plain-ram"


def algorithm_family(canonical: str, asset: CryptoAsset | None = None) -> str | None:
    """Cryptography Registry family for a canonical algorithm name, or None if ambiguous."""
    name = canonical.upper()
    if name.startswith("RSA"):
        # Only evidence about this key's own scheme counts. A certificate's
        # signature_algorithm is how the *issuer* signed it, not what the
        # subject key does, so an RSA certificate key gets no family.
        details = (asset.raw_details or {}) if asset is not None else {}
        literal = str(details.get("argument_literal", "")).upper()
        padding = str(details.get("padding", "")).upper()
        if "PSS" in literal:
            return "RSASSA-PSS"
        if details.get("digest") and asset is not None and asset.usage == "signing":
            return "RSASSA-PKCS1"          # JCA "SHA256withRSA" is PKCS#1 v1.5
        if "OAEP" in padding:
            return "RSAES-OAEP"
        if "PKCS1" in padding:
            return "RSAES-PKCS1"
        return None
    for prefix, family in _FAMILY_PREFIXES:
        if name.startswith(prefix):
            return family
    return None


def registry_curve(*names: str | None) -> str | None:
    for name in names:
        if name and name.lower() in _CURVES:
            return _CURVES[name.lower()]
    return None


_PADDINGS = {"pkcs5padding": "pkcs5", "pkcs7padding": "pkcs7", "pkcs1padding": "pkcs1v15",
             "oaeppadding": "oaep", "nopadding": "raw"}


def _algorithm_component(asset: CryptoAsset, spec: str = SPEC_VERSION, part: tuple | None = None) -> dict:
    """The algorithm itself, as a `cryptographic-asset` of assetType algorithm.

    `part` is (role, facts, key_bits, mode) for one piece of a cipher suite; the
    asset's own algorithm is used otherwise.
    """
    details = asset.raw_details or {}
    if part:
        role, facts, key_bits, part_mode = part
    else:
        role, part_mode = None, None
        facts = taxonomy.classify_algorithm(asset.algorithm or asset.key_exchange, asset.key_size)
        key_bits = asset.key_size
    primitive = facts.primitive if facts.primitive in PRIMITIVES else "unknown"
    own = not role or role == "primary"

    algorithm_properties: dict = {
        "primitive": primitive,
        "executionEnvironment": _execution_environment(asset),
        "implementationPlatform": "generic",
        "certificationLevel": ["none"],
        # A suite's other parts each do their own job; only the asset's own algorithm takes its recorded usage.
        "cryptoFunctions": _crypto_functions(asset if own else None, primitive),
    }

    parameter_set = facts.canonical.rsplit("-", 1)[-1] if facts.canonical.startswith(("ML-KEM-", "ML-DSA-")) \
        else (str(key_bits) if key_bits else None)
    if parameter_set:
        algorithm_properties["parameterSetIdentifier"] = parameter_set
    curve = facts.curve or asset.curve or details.get("curve")
    if spec == "1.7":
        family = algorithm_family(facts.canonical, asset)
        if family:
            algorithm_properties["algorithmFamily"] = family
        registry = registry_curve(curve, facts.canonical)
        if registry:
            algorithm_properties["ellipticCurve"] = registry
    elif curve:
        algorithm_properties["curve"] = curve
    if facts.classical_bits is not None:
        algorithm_properties["classicalSecurityLevel"] = facts.classical_bits
    # 0 is a meaningful value here: "provides no post-quantum security".
    algorithm_properties["nistQuantumSecurityLevel"] = facts.nist_quantum_level

    named_mode = None
    if primitive in ("block-cipher", "ae"):
        mode = str(part_mode or (asset.suite_breakdown or {}).get("mode") or details.get("mode")
                   or _mode_from_text(details.get("argument_literal"), asset.algorithm, asset.cipher_suite)
                   or "").lower()
        if mode in MODES:
            algorithm_properties["mode"] = mode
            named_mode = mode if mode not in ("other", "unknown") else None
    padding = _PADDINGS.get(str(details.get("padding", "")).lower())
    if padding in PADDINGS:
        algorithm_properties["padding"] = padding

    component = {
        "type": "cryptographic-asset",
        "bom-ref": _bom_ref("algorithm", asset.id) if own else _bom_ref("algorithm", asset.id, role, facts.canonical),
        # AES-256-GCM and AES-256-CBC are different assets; the name says which, as CycloneDX's examples do.
        "name": f"{facts.canonical}-{named_mode.upper()}" if named_mode and named_mode.upper() not in facts.canonical.upper() else facts.canonical,
        "cryptoProperties": {
            "assetType": "algorithm",
            "algorithmProperties": algorithm_properties,
        },
    }
    oid = facts.oid
    if not oid and named_mode and facts.canonical.upper().startswith("AES"):
        bits = key_bits or asset.key_size or _bits_in_name(facts.canonical)
        oid = taxonomy.AES_MODE_OIDS.get((bits, named_mode)) if bits else None
    if oid:
        component["cryptoProperties"]["oid"] = oid
    return component


def _bits_in_name(name: str) -> int | None:
    m = re.search(r"(128|192|256)", name)
    return int(m.group(1)) if m else None


# Where each source records a key's identity and creation date (CERT-In BOM
# guidelines v2.0, Table 9: key id, state, size, creation and activation dates).
_KEY_ID_FIELDS = ("Unique Identifier", "KeyId", "kid", "CKA_ID", "alias", "CKA_LABEL", "sha256_fingerprint",
                  "public_key_sha256")
_KEY_CREATED_FIELDS = ("Initial Date", "CreationDate", "createTime", "creation_date")
_KMIP_STATE = {"pre-active": "pre-activation", "active": "active", "deactivated": "deactivated",
               "compromised": "compromised", "destroyed": "destroyed", "destroyed compromised": "destroyed"}
_KMS_STATE = {"enabled": "active", "disabled": "suspended", "pendingdeletion": "deactivated",
              "pendingimport": "pre-activation", "unavailable": "suspended"}


def _first(details: dict, fields: tuple[str, ...]):
    for field in fields:
        value = details.get(field)
        if value not in (None, "", "None"):
            return value
    return None


def _key_state(asset: CryptoAsset, details: dict, as_of: str) -> str | None:
    """The NIST SP 800-57 state the source recorded, or one its validity dates prove at the scan time.

    None when neither says: a key is never reported active by default.
    """
    recorded = str(details.get("State") or details.get("lifecycle_state") or "").strip().lower()
    if recorded in _KMIP_STATE:
        return _KMIP_STATE[recorded]
    kms = str(details.get("KeyState") or "").replace("_", "").strip().lower()
    if kms in _KMS_STATE:
        return _KMS_STATE[kms]
    start = _rfc3339(_first(details, ("Activation Date", "CKA_START_DATE")) or asset.cert_validity_start)
    end = _rfc3339(_first(details, ("Deactivation Date", "CKA_END_DATE")) or asset.cert_validity_end)
    if end and end < as_of:
        return "deactivated"
    if start and start > as_of:
        return "pre-activation"
    if start and end:
        return "active"
    return None


def _material_component(asset: CryptoAsset, algorithm_ref: str, as_of: str) -> dict:
    """The key material, as `related-crypto-material`."""
    raw_type = (asset.raw_details or {}).get("type", "")
    if raw_type == "private_key" or asset.usage in {"signing", "key_wrapping"}:
        material_type = "private-key"
    elif asset.usage == "encryption":
        material_type = "secret-key"
    elif asset.usage == "key_exchange":
        material_type = "shared-secret"
    else:
        material_type = "key"
    if material_type not in RELATED_MATERIAL_TYPES:
        material_type = "key"

    details = asset.raw_details or {}
    properties: dict = {
        "type": material_type,
        "algorithmRef": algorithm_ref,
    }
    key_id = _first(details, _KEY_ID_FIELDS)
    if key_id:
        properties["id"] = str(key_id)
    state = _key_state(asset, details, as_of)
    if state:
        properties["state"] = state
    if asset.key_size:
        properties["size"] = asset.key_size
    created = _rfc3339(_first(details, _KEY_CREATED_FIELDS))
    if created:
        properties["creationDate"] = created
    activation = _rfc3339(_first(details, ("Activation Date", "CKA_START_DATE")) or asset.cert_validity_start)
    if activation:
        properties["activationDate"] = activation
    if asset.cert_validity_end:
        expiration = _rfc3339(asset.cert_validity_end)
        if expiration:
            properties["expirationDate"] = expiration

    return {
        "type": "cryptographic-asset",
        "bom-ref": _bom_ref("material", asset.id),
        "name": f"{asset.name} (key material)",
        "cryptoProperties": {
            "assetType": "related-crypto-material",
            "relatedCryptoMaterialProperties": properties,
        },
    }


def _sha256_hex(value) -> str | None:
    text = "".join(ch for ch in str(value or "").lower() if ch in "0123456789abcdef")
    return text if len(text) == 64 else None


def _certificate_component(asset: CryptoAsset, algorithm_ref: str, material_ref: str,
                           spec: str = SPEC_VERSION) -> dict:
    properties: dict = {
        "subjectName": asset.cert_subject or asset.name,
        "certificateFormat": "X.509",
        "certificateExtension": "crt",
        "signatureAlgorithmRef": algorithm_ref,
        "subjectPublicKeyRef": material_ref,
    }
    if spec == "1.7":
        details = asset.raw_details or {}
        if asset.cert_serial:
            properties["serialNumber"] = str(asset.cert_serial)
        fingerprint = _sha256_hex(details.get("fingerprint_sha256") or details.get("sha256_fingerprint"))
        if fingerprint:
            properties["fingerprint"] = {"alg": "SHA-256", "content": fingerprint}
    if asset.cert_issuer:
        properties["issuerName"] = asset.cert_issuer
    not_before = _rfc3339(asset.cert_validity_start)
    not_after = _rfc3339(asset.cert_validity_end)
    if not_before:
        properties["notValidBefore"] = not_before
    if not_after:
        properties["notValidAfter"] = not_after

    return {
        "type": "cryptographic-asset",
        "bom-ref": _bom_ref("certificate", asset.id),
        "name": asset.cert_subject or asset.name,
        "cryptoProperties": {
            "assetType": "certificate",
            "certificateProperties": properties,
        },
    }


def _ikev2_transforms(asset: CryptoAsset, algorithm_ref: str) -> dict | None:
    """One IKE proposal token as a 1.7 `ikev2TransformTypes` entry."""
    details = asset.raw_details or {}
    role, wire = details.get("role"), str(details.get("wire_name") or asset.algorithm or "")
    if role == "group":
        entry: dict = {"algorithm": algorithm_ref}
        group = _IKE_GROUPS.get((asset.algorithm, asset.key_size)) or _IKE_GROUPS.get((asset.algorithm, None))
        if group:
            entry["group"] = group
        return {"ke": [entry]}
    if role == "cipher":
        entry = {"name": wire, "algorithm": algorithm_ref}
        if asset.key_size:
            entry["keyLength"] = asset.key_size
        return {"encr": [entry]}
    if role == "integrity":
        return {"integ": [{"name": wire, "algorithm": algorithm_ref}]}
    if role == "prf":
        return {"prf": [{"name": wire, "algorithm": algorithm_ref}]}
    return None


# purl types (package-url spec) for ecosystems where name and version are
# enough. Distribution packages (deb, apk) need a vendor namespace the scan does
# not know, so they carry no purl rather than a guessed one.
_PURL_TYPES = {"pypi": "pypi", "npm": "npm", "maven": "maven", "go": "golang", "cargo": "cargo",
               "nuget": "nuget", "composer": "composer", "gem": "gem", "conan": "conan"}


def _purl(ecosystem: str | None, package: str | None, version: str | None) -> str | None:
    kind = _PURL_TYPES.get(str(ecosystem or "").lower())
    if not kind or not package:
        return None
    name = str(package)
    if kind == "pypi":
        name = re.sub(r"[-_.]+", "-", name).lower()
    elif kind == "maven" and ":" in name:
        name = name.replace(":", "/", 1)
    elif kind == "npm" and name.startswith("@"):
        name = "%40" + name[1:]
    suffix = ""
    if version:
        suffix = "@" + (f"v{version}" if kind == "golang" and not str(version).startswith("v") else str(version))
    return f"pkg:{kind}/{name}{suffix}"


def _library_component(asset: CryptoAsset) -> dict:
    """A crypto library as a CycloneDX `library` component, not an algorithm.

    Carries the VERA properties (so an import rebuilds the same asset) plus the
    library's post-quantum status from the knowledge base.
    """
    details = asset.raw_details or {}
    version = details.get("library_version") or details.get("version")
    component = {
        "type": "library",
        "bom-ref": _bom_ref("library", asset.id),
        # The package as the ecosystem names it; the knowledge-base family goes in a property.
        "name": str(details.get("package") or details.get("library") or asset.name),
    }
    if version:
        component["version"] = str(version)
    purl = _purl(details.get("ecosystem"), details.get("package"), version)
    if purl:
        component["purl"] = purl
    extra = [{"name": f"vera:{key}", "value": str(details[field])}
             for key, field in (("pqc-native-from", "pqc_native_from"), ("pqc-capable", "pqc_capable"),
                                ("library-family", "library"), ("ecosystem", "ecosystem"))
             if details.get(field) not in (None, "", "None")]
    component["properties"] = _vera_properties(asset) + extra
    return component


def _suite_parts(asset: CryptoAsset) -> list[tuple[str, list[tuple]]]:
    """Each cipher suite the asset names, split into (role, facts, key bits, mode) parts.

    Reads `cipher_suite`, or the algorithm field when it holds a suite list such as
    "DES-CBC3-SHA:ECDHE-RSA-AES256-GCM-SHA384".
    """
    text = asset.cipher_suite
    if not text and asset.algorithm and taxonomy.classify_algorithm(asset.algorithm).canonical.lower() == "unknown":
        text = asset.algorithm
    out = []
    for suite in (t.strip() for t in re.split(r"[:,\s]+", text or "") if t.strip()):
        breakdown = taxonomy.decompose_cipher_suite(suite)
        parts = []
        if breakdown.key_exchange:
            parts.append(("key_exchange", taxonomy.classify_algorithm(breakdown.key_exchange), None, None))
        if breakdown.authentication:
            parts.append(("authentication", taxonomy.classify_algorithm(breakdown.authentication), None, None))
        if breakdown.bulk_cipher:
            parts.append(("cipher", taxonomy.classify_algorithm(breakdown.bulk_cipher, breakdown.bulk_key_bits),
                          breakdown.bulk_key_bits, breakdown.mode))
        if breakdown.mac:
            parts.append(("mac", taxonomy.classify_algorithm(breakdown.mac), None, None))
        if parts:
            out.append((suite, parts))
    return out


def _protocol_type(asset: CryptoAsset) -> str:
    location = (asset.source_location or "").lower()
    if asset.asset_class == "vpn_ipsec":
        return "ike"
    if asset.source_type == "ssh" or asset.asset_class == "ssh_key_exchange" or location.startswith("ssh://"):
        return "ssh"
    if asset.source_type == "tls" or "tls" in (asset.protocol or "").lower():
        return "tls"
    if "ipsec" in location:
        return "ipsec"
    if asset.cipher_suite:
        return "tls"  # a cipher-suite list from a server config (nginx ssl_ciphers, HAProxy) is TLS
    return "other"


def _protocol_component(asset: CryptoAsset, algorithm_refs: list[str], spec: str = SPEC_VERSION,
                        suites: list[tuple[str, list[str]]] | None = None) -> dict:
    protocol_type = _protocol_type(asset)
    properties: dict = {"type": protocol_type}

    version = (asset.protocol or "").upper().replace("TLSV", "").replace("SSH-", "").strip()
    # Multi-value directives such as "TLSv1.2 TLSv1.3" record the lowest
    # version, because that is what an attacker will negotiate down to.
    if version:
        properties["version"] = sorted(version.split())[0] if " " in version else version
    elif protocol_type == "ike" and (asset.raw_details or {}).get("ike_version"):
        # Resolved per connection by the config collector, already the lowest accepted.
        properties["version"] = str(asset.raw_details["ike_version"])
    if spec == "1.7" and protocol_type == "ike" and algorithm_refs:
        transforms = _ikev2_transforms(asset, algorithm_refs[0])
        if transforms:
            properties["ikev2TransformTypes"] = transforms

    if suites:
        properties["cipherSuites"] = [{"name": name, "algorithms": refs} for name, refs in suites if refs]
    elif asset.cipher_suite:
        properties["cipherSuites"] = [{"name": asset.cipher_suite, "algorithms": algorithm_refs}]
    if algorithm_refs:
        properties["cryptoRefArray"] = algorithm_refs

    return {
        "type": "cryptographic-asset",
        "bom-ref": _bom_ref("protocol", asset.id),
        "name": asset.name,
        "cryptoProperties": {
            "assetType": "protocol",
            "protocolProperties": properties,
        },
    }


def _vera_properties(asset: CryptoAsset) -> list[dict]:
    """VERA's own scoring, carried as namespaced `properties`.

    CycloneDX has no field for a risk score, and inventing one inside
    `cryptoProperties` would break validation. Namespaced properties are the
    documented extension point, so a consumer that does not know VERA simply
    ignores them and the BOM still validates.
    """
    values = {
        "verdict": asset.verdict,
        "quantum-vulnerable": str(asset.quantum_vulnerable).lower(),
        "classically-broken": str(asset.classically_broken).lower(),
        "hndl-score": f"{asset.h_score:.6f}",
        "tnfl-score": f"{asset.t_score:.6f}",
        "qirs": f"{asset.qirs:.6f}",
        "qirs-band-low": f"{asset.qirs_low:.6f}",
        "qirs-band-high": f"{asset.qirs_high:.6f}",
        "risk-level": asset.risk_level,
        "priority-rank": str(asset.priority_rank),
        "persona": asset.persona,
        "statutory-deadline-year": str(asset.statutory_deadline_year),
        "slack-months": f"{asset.slack_months:.1f}",
        "migration-effort-years": f"{asset.y:.2f}",
    }
    if asset.pqc_replacement:
        values["recommended-replacement"] = asset.pqc_replacement

    # Tags, because the regulatory mapper derives an asset's persona from its
    # location and its tags - and a location alone is not enough. Without this,
    # exporting an estate and importing it back re-derived a materially softer
    # picture than the scan it came from: the CII population fell from 55 assets
    # to 14 and the deadline band moved out by years, because "upi" and "atm"
    # live in the tags, not in the hostname. `vera:persona` above records what
    # was concluded; this records what it was concluded from, so the importer
    # can reach the same answer through the same code rather than trusting a
    # number in a file.
    if asset.tags:
        values["tags"] = ",".join(asset.tags)

    # The class and the algorithm as VERA recorded them, for the same reason.
    # The component's `name` is the canonical CycloneDX spelling - "ECDSA-P-256"
    # rather than "ECDSA" - which is right for the standard and wrong as an
    # input to the taxonomy: re-imported, twelve assets stopped being recognised
    # as Shor-breakable and silently became quantum-safe. The class drives the
    # migration-effort default and therefore the deadline, and inferring it from
    # a name put 131 of 195 assets in `generic_key`.
    values["asset-class"] = asset.asset_class

    # An asset carries its primitive in exactly one of three fields depending on
    # what it is - a key in `algorithm`, a TLS group in `key_exchange`, a
    # negotiated suite in `cipher_suite` - and a CycloneDX component name cannot
    # say which. Recording each one that is set, and only those, is what lets an
    # import rebuild the same asset rather than a differently-shaped one that
    # happens to score nearby.
    for field in ("algorithm", "key_exchange", "cipher_suite"):
        value = getattr(asset, field, None)
        if value:
            values[field.replace("_", "-")] = value

    # Where the asset actually lives. A CycloneDX component names the algorithm,
    # not the host running it, so a re-imported estate collapsed forty-two
    # distinct TLS endpoints into forty-two rows all called "protocol:tls" -
    # identical, unrankable, and useless to look at. This is also the other half
    # of what classify_persona reads.
    if asset.source_location:
        values["source-location"] = asset.source_location
    # Where an IKE version came from: stated in the file, or an implementation default.
    if (asset.raw_details or {}).get("ike_version_source"):
        values["ike-version-source"] = asset.raw_details["ike_version_source"]
    # A learned-detector finding carries its calibrated error: the q-value is the smallest FDR level at which
    # it would still be selected, calibrated per ISA (engine/binary_ml/detector.py).
    details = asset.raw_details or {}
    for key in ("detection_method", "detection_q_value", "detection_alpha", "detection_isa", "functions_selected"):
        if details.get(key) is not None:
            values[key.replace("_", "-")] = str(details[key])

    return [{"name": f"vera:{key}", "value": value} for key, value in values.items()]


def canonical_json(document: dict) -> str:
    """The byte-stable serialisation: sorted keys, fixed separators, UTF-8 text."""
    return json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _serial_for(components: list[dict], timestamp: str, org_name: str, spec: str) -> str:
    digest = hashlib.sha256(
        (spec + "|" + org_name + "|" + timestamp + "|" + "|".join(c["bom-ref"] for c in components)).encode()
    ).hexdigest()
    return f"urn:uuid:{uuid.UUID(digest[:32])}"


def generate_cbom(assets: list[CryptoAsset], org_name: str = "Scanned Estate", *, spec: str = SPEC_VERSION,
                  timestamp: str | None = None, threat_model_version: str | None = None) -> dict:
    """Build a CycloneDX CBOM (1.7 by default, 1.6 on request) with a dependency graph.

    Each asset expands into up to three components - the algorithm, the key
    material and either a certificate or a protocol - wired together with
    `dependencies`, which is what lets a consumer answer "what breaks if this
    algorithm is withdrawn". Pass the scan's `timestamp` for reproducible output.
    """
    if spec not in SUPPORTED_SPECS:
        raise ValueError(f"spec must be one of {SUPPORTED_SPECS}, got {spec!r}")
    components: list[dict] = []
    dependencies: dict[str, set[str]] = {}
    timestamp = _rfc3339(timestamp) if timestamp else \
        datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    as_of = timestamp  # key states are judged at the scan time, so the same scan exports the same CBOM

    for asset in assets:
        if asset.asset_class == "crypto_library":
            library = _library_component(asset)
            components.append(library)
            dependencies.setdefault(library["bom-ref"], set())
            continue

        suites = _suite_parts(asset)
        algorithm = _algorithm_component(asset, spec)
        if algorithm["name"].lower().startswith("unknown") and suites:
            # The asset's algorithm field held the suite string itself: the key
            # exchange (or the first part) stands for the asset.
            first = next((p for _, parts in suites for p in parts if p[0] == "key_exchange"), suites[0][1][0])
            algorithm = _algorithm_component(asset, spec, ("primary", *first[1:]))
        algorithm_ref = algorithm["bom-ref"]
        algorithm["properties"] = _vera_properties(asset)
        components.append(algorithm)
        # Every component must appear as a `ref` in dependencies, even leaves.
        dependencies.setdefault(algorithm_ref, set())

        suite_refs: list[tuple[str, list[str]]] = []
        for suite_name, parts in suites:
            refs = []
            for role, facts, bits, mode in parts:
                if facts.canonical == algorithm["name"]:
                    refs.append(algorithm_ref)
                    continue
                piece = _algorithm_component(asset, spec, (role, facts, bits, mode))
                piece["properties"] = [{"name": "vera:suite-part-of", "value": algorithm_ref}]
                if piece["bom-ref"] not in dependencies:
                    components.append(piece)
                    dependencies[piece["bom-ref"]] = set()
                refs.append(piece["bom-ref"])
            suite_refs.append((suite_name, refs))

        # Keys held in a keystore, HSM, KMIP server or cloud KMS, and certified keys, are key material.
        needs_material = (asset.source_type == "keystore" or bool(asset.cert_subject)
                          or str((asset.raw_details or {}).get("discovered_by", "")).startswith("vault_"))
        material_ref = None
        if needs_material:
            material = _material_component(asset, algorithm_ref, as_of)
            material_ref = material["bom-ref"]
            components.append(material)
            dependencies.setdefault(material_ref, set()).add(algorithm_ref)

        if asset.cert_subject:
            certificate = _certificate_component(asset, algorithm_ref, material_ref or algorithm_ref, spec)
            components.append(certificate)
            dependencies.setdefault(certificate["bom-ref"], set()).update(
                r for r in (algorithm_ref, material_ref) if r)

        if (asset.cipher_suite or suites or (asset.source_type == "tls" and asset.protocol)
                or _protocol_type(asset) in ("ike", "ssh")):
            all_refs = sorted({algorithm_ref, *(r for _, refs in suite_refs for r in refs)})
            protocol = _protocol_component(asset, all_refs, spec, suite_refs)
            components.append(protocol)
            dependencies.setdefault(protocol["bom-ref"], set()).update(all_refs)

    components.sort(key=lambda c: c["bom-ref"])
    metadata_properties = [{"name": "vera:tool-version", "value": TOOL_VERSION}]
    if threat_model_version:
        metadata_properties.append({"name": "vera:threat-model-version", "value": threat_model_version})

    return {
        "bomFormat": "CycloneDX",
        "specVersion": spec,
        "serialNumber": _serial_for(components, timestamp, org_name, spec),
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            # The legacy array-of-tools form is deprecated since 1.5.
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "VERA",
                        "version": TOOL_VERSION,
                        "description": "Cryptographic discovery, quantum-risk assessment and CBOM",
                    }
                ]
            },
            "component": {
                "type": "application",
                "bom-ref": "vera:target-estate",
                "name": org_name,
                "description": "Cryptographic estate under assessment",
            },
            "properties": metadata_properties,
        },
        "components": components,
        "dependencies": [{"ref": ref, "dependsOn": sorted(dependencies[ref])} for ref in sorted(dependencies)],
    }
