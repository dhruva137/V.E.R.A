"""Regex fallback for the source collector (Python and Java only).

`collectors.source_scanner` parses source with tree-sitter. When a grammar
cannot load, Python and Java files fall back to this regex ruleset and every
finding says so (`engine: "regex"`). Other languages have no fallback and are
reported as not scanned.

Stated limitations, which are why this is the fallback and not the default:

  - No dataflow analysis. `Cipher.getInstance(algorithm)` with a variable is an
    unresolved call site, not a guess.
  - Comments and strings are not excluded, so a commented-out `md5` is a
    finding. Over-reporting is the right failure direction for an inventory.
"""

from __future__ import annotations

import re

from collectors.base import stable_id
from models.schemas import RawCryptoFinding

# (pattern, algorithm, usage). Algorithm None means "call site found, algorithm
# not statically resolvable" - reported with the algorithm left unknown.
_RULES: list[tuple[re.Pattern, str | None, str]] = [
    # Python - hashlib
    (re.compile(r"\bhashlib\.md5\s*\("), "MD5", "hashing"),
    (re.compile(r"\bhashlib\.sha1\s*\("), "SHA-1", "hashing"),
    (re.compile(r"\bhashlib\.sha256\s*\("), "SHA-256", "hashing"),
    (re.compile(r"\bhashlib\.sha512\s*\("), "SHA-512", "hashing"),
    # Python - cryptography / PyCryptodome
    (re.compile(r"\brsa\.generate_private_key\s*\(|\bRSA\.generate\s*\("), "RSA", "signing"),
    (re.compile(r"\bec\.generate_private_key\s*\(|\bECC\.generate\s*\("), "ECDSA", "signing"),
    (re.compile(r"\bed25519\.Ed25519PrivateKey"), "Ed25519", "signing"),
    (re.compile(r"\bx25519\.X25519PrivateKey"), "X25519", "key_exchange"),
    (re.compile(r"\bdh\.generate_parameters\s*\("), "DH", "key_exchange"),
    (re.compile(r"\bAESGCM\s*\(|\bAES\.new\s*\("), "AES", "encryption"),
    (re.compile(r"\bChaCha20Poly1305\s*\("), "ChaCha20", "encryption"),
    (re.compile(r"\bDES\.new\s*\(|\bCipher\.DES\b"), "DES", "encryption"),
    (re.compile(r"\bDES3\.new\s*\("), "3DES", "encryption"),
    (re.compile(r"\bHKDF\s*\(|\bPBKDF2HMAC\s*\("), "HKDF", "key_derivation"),
    # Python - JWT
    (re.compile(r"""jwt\.encode\s*\([^)]*algorithm\s*=\s*["']RS256["']""", re.S), "RSA", "signing"),
    (re.compile(r"""jwt\.encode\s*\([^)]*algorithm\s*=\s*["']ES256["']""", re.S), "ECDSA", "signing"),
    (re.compile(r"""jwt\.encode\s*\([^)]*algorithm\s*=\s*["']HS256["']""", re.S), "HMAC", "signing"),
    # Java - JCA
    (re.compile(r"""Cipher\.getInstance\s*\(\s*["']AES"""), "AES", "encryption"),
    (re.compile(r"""Cipher\.getInstance\s*\(\s*["'](?:DESede|TripleDES)"""), "3DES", "encryption"),
    (re.compile(r"""Cipher\.getInstance\s*\(\s*["']DES[/"']"""), "DES", "encryption"),
    (re.compile(r"""Cipher\.getInstance\s*\(\s*["']RSA"""), "RSA", "encryption"),
    (re.compile(r"""MessageDigest\.getInstance\s*\(\s*["']MD5["']"""), "MD5", "hashing"),
    (re.compile(r"""MessageDigest\.getInstance\s*\(\s*["']SHA-?1["']"""), "SHA-1", "hashing"),
    (re.compile(r"""MessageDigest\.getInstance\s*\(\s*["']SHA-?256["']"""), "SHA-256", "hashing"),
    (re.compile(r"""Signature\.getInstance\s*\(\s*["'][^"']*withRSA["']"""), "RSA", "signing"),
    (re.compile(r"""Signature\.getInstance\s*\(\s*["'][^"']*withECDSA["']"""), "ECDSA", "signing"),
    (re.compile(r"""KeyPairGenerator\.getInstance\s*\(\s*["']RSA["']"""), "RSA", "signing"),
    (re.compile(r"""KeyPairGenerator\.getInstance\s*\(\s*["']EC["']"""), "ECDSA", "signing"),
    # Call sites where the algorithm is a variable - reported as unresolved.
    (re.compile(r"""Cipher\.getInstance\s*\(\s*(?!["'])\w+"""), None, "encryption"),
    (re.compile(r"""MessageDigest\.getInstance\s*\(\s*(?!["'])\w+"""), None, "hashing"),
]

# Java key sizes are usually a separate initialize() call; catch the common form.
_KEYSIZE = re.compile(r"(?:initialize|key_size\s*=|public_exponent[^)]*key_size\s*=)\s*\(?\s*(\d{3,5})")

SUFFIXES = {".py", ".java"}


def scan_text(text: str, location: str, language: str) -> list[RawCryptoFinding]:
    """Regex call sites in one file's text. Only the matched API text is kept."""
    findings: list[RawCryptoFinding] = []
    for pattern, algorithm, usage in _RULES:
        for match in pattern.finditer(text):
            line_number = text[: match.start()].count("\n") + 1
            size_match = _KEYSIZE.search(text, match.end(), match.end() + 400)
            key_size = int(size_match.group(1)) if size_match else None
            api = match.group(0).strip()
            findings.append(RawCryptoFinding(
                id=stable_id("source", location, line_number, api),
                source_type="source",
                source_location=f"{location}:{line_number}",
                asset_class="source",
                algorithm=algorithm,
                key_size=key_size,
                usage=usage,
                tags=["source-scan", f"lang:{language}", "engine:regex"],
                raw_details={
                    "type": "api_call",
                    "discovered_by": "source_scanner",
                    "plane": "built",
                    "provenance": "static_analysis",
                    "confidence": 0.50 if algorithm else 0.35,
                    "engine": "regex",
                    "language": language,
                    "api": api,
                    "line": line_number,
                    "resolved": algorithm is not None,
                    "unresolved": algorithm is None,
                    "note": None if algorithm else (
                        "Algorithm is supplied at runtime and cannot be resolved "
                        "statically. Reported as an unresolved call site rather than "
                        "guessed or dropped."
                    ),
                },
            ))
    return findings
