"""Cryptographic algorithm taxonomy.

Replaces substring matching on raw strings, which produced two systematic
errors:

  1. A cipher suite named ``TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`` contains the
     substring "RSA", so the whole suite - including its AES-256-GCM bulk cipher
     - was reported as breakable by Shor. The suite has to be decomposed into
     its key-exchange, authentication, bulk-cipher and MAC components, each
     classified on its own terms.
  2. SHA-1 and MD5 matched nothing in either list and fell through to "not
     quantum vulnerable", which is technically true and practically absurd.
     Classical breakage is a separate finding, not silence.

Four verdicts:

  ``shor``      - broken outright by Shor's algorithm. Requires migration.
  ``grover``    - security halved by Grover. AES-128 drops to 64-bit
                  quantum work; AES-256 stays comfortable. Parameter bump,
                  not an algorithm change.
  ``classical`` - already broken or deprecated classically (MD5, SHA-1, RC4,
                  3DES, DES). Nothing to do with quantum; still needs fixing.
  ``pqc``       - a NIST PQC standard, or symmetric crypto at a parameter size
                  that stays safe under Grover.

Sources: FIPS 203/204/205, NIST SP 800-57 Part 1 Rev 5 (security strengths),
NIST IR 8547 (deprecation timeline), RFC 8446 Appendix B.4 (TLS 1.3 suites),
IANA TLS Cipher Suite Registry.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, replace, field

# Verdict constants.
SHOR = "shor"
GROVER = "grover"
CLASSICAL = "classical"
PQC = "pqc"
UNKNOWN = "unknown"

# Primitive categories, aligned with the CycloneDX 1.6 `primitive` enum so the
# CBOM emitter can use them without a second mapping table.
PRIM_PKE = "pke"
PRIM_SIGNATURE = "signature"
PRIM_KEY_AGREE = "key-agree"
PRIM_KEM = "kem"
PRIM_BLOCK_CIPHER = "block-cipher"
PRIM_STREAM_CIPHER = "stream-cipher"
PRIM_HASH = "hash"
PRIM_MAC = "mac"
PRIM_AE = "ae"
PRIM_KDF = "kdf"
PRIM_UNKNOWN = "unknown"

# Verdicts ordered worst-first. A classical break outranks a Shor break because
# it is exploitable today rather than after a CRQC exists.
VERDICT_SEVERITY = [CLASSICAL, SHOR, GROVER, UNKNOWN, PQC]


@dataclass(frozen=True)
class AlgorithmFacts:
    """What we know about one named algorithm."""

    canonical: str
    primitive: str
    verdict: str
    rationale: str
    # Classical security strength in bits (NIST SP 800-57). None where the
    # notion does not apply cleanly.
    classical_bits: int | None = None
    # NIST PQC security category 1-5, or 0 for anything not PQC. Matches the
    # CycloneDX `nistQuantumSecurityLevel` field.
    nist_quantum_level: int = 0
    # PQC replacement, where one exists.
    pqc_replacement: str | None = None
    oid: str | None = None
    curve: str | None = None


def _rsa_facts(key_size: int | None) -> AlgorithmFacts:
    bits = {1024: 80, 2048: 112, 3072: 128, 4096: 152, 7680: 192}.get(key_size or 0)
    size_note = f"RSA-{key_size}" if key_size else "RSA"
    return AlgorithmFacts(
        canonical=size_note,
        primitive=PRIM_PKE,
        verdict=SHOR,
        rationale=(
            f"{size_note} rests on integer factorisation, which Shor's algorithm "
            "solves in polynomial time on a CRQC. Increasing the modulus does not "
            "help - it raises the qubit count required, not the asymptotic difficulty."
        ),
        classical_bits=bits,
        pqc_replacement="ML-KEM-768 (encryption) / ML-DSA-65 (signature)",
        oid="1.2.840.113549.1.1.1",
    )


def _ec_facts(name: str, key_size: int | None, curve: str | None) -> AlgorithmFacts:
    bits = {256: 128, 384: 192, 521: 256, 224: 112}.get(key_size or 0)
    label = f"{name}-{curve}" if curve else (f"{name}-{key_size}" if key_size else name)
    is_signature = name.upper() in {"ECDSA", "EDDSA", "ED25519", "ED448"}
    return AlgorithmFacts(
        canonical=label,
        primitive=PRIM_SIGNATURE if is_signature else PRIM_KEY_AGREE,
        verdict=SHOR,
        rationale=(
            f"{label} rests on the elliptic-curve discrete logarithm problem, which "
            "Shor's algorithm solves in polynomial time. Elliptic curves need fewer "
            "logical qubits to break than RSA at equivalent classical strength, so "
            "they fall earlier, not later."
        ),
        classical_bits=bits,
        pqc_replacement=(
            "ML-DSA-65 (signature)" if is_signature else "ML-KEM-768 (key establishment)"
        ),
        curve=curve,
        # id-ecPublicKey for ECDSA keys; id-ecDH (SEC 1) for elliptic-curve key agreement.
        oid="1.2.840.10045.2.1" if is_signature else "1.3.132.1.12",
    )


# Static table for everything that is not parameterised by key size.
_STATIC: dict[str, AlgorithmFacts] = {
    "DSA": AlgorithmFacts(
        "DSA", PRIM_SIGNATURE, SHOR,
        "DSA rests on the discrete logarithm problem in a finite field, solved by Shor.",
        classical_bits=112, pqc_replacement="ML-DSA-65", oid="1.2.840.10040.4.1",
    ),
    "DH": AlgorithmFacts(
        "Diffie-Hellman", PRIM_KEY_AGREE, SHOR,
        "Finite-field Diffie-Hellman rests on discrete log, solved by Shor.",
        classical_bits=112, pqc_replacement="ML-KEM-768",
    ),
    "DHE": AlgorithmFacts(
        "DHE", PRIM_KEY_AGREE, SHOR,
        "Ephemeral finite-field Diffie-Hellman. Forward secrecy protects against "
        "future key compromise, not against Shor: recorded traffic is still "
        "decryptable once the CRQC exists.",
        classical_bits=112, pqc_replacement="ML-KEM-768",
    ),
    "ECDHE": AlgorithmFacts(
        "ECDHE", PRIM_KEY_AGREE, SHOR,
        "Ephemeral elliptic-curve Diffie-Hellman. Forward secrecy does not defend "
        "against Shor - this is the primary harvest-now-decrypt-later surface.",
        classical_bits=128, pqc_replacement="X25519MLKEM768 (hybrid)",
    ),
    "X25519": AlgorithmFacts(
        "X25519", PRIM_KEY_AGREE, SHOR,
        "Curve25519 key agreement. ECDLP-based, so Shor-breakable.",
        classical_bits=128, pqc_replacement="X25519MLKEM768 (hybrid)",
        curve="Curve25519",
    ),
    "X448": AlgorithmFacts(
        "X448", PRIM_KEY_AGREE, SHOR,
        "Curve448 key agreement. ECDLP-based, so Shor-breakable.",
        classical_bits=224, pqc_replacement="ML-KEM-1024", curve="Curve448",
    ),
    "ED25519": AlgorithmFacts(
        "Ed25519", PRIM_SIGNATURE, SHOR,
        "EdDSA over Curve25519. ECDLP-based, so Shor-breakable.",
        classical_bits=128, pqc_replacement="ML-DSA-65", curve="Curve25519",
    ),
    "ED448": AlgorithmFacts(
        "Ed448", PRIM_SIGNATURE, SHOR,
        "EdDSA over Curve448. ECDLP-based, so Shor-breakable.",
        classical_bits=224, pqc_replacement="ML-DSA-87", curve="Curve448",
    ),
    # --- Symmetric: Grover halves the effective key length. ---
    "AES-128": AlgorithmFacts(
        "AES-128", PRIM_BLOCK_CIPHER, GROVER,
        "Grover's algorithm reduces a 128-bit key search to roughly 2^64 quantum "
        "operations. Not catastrophic given the cost of quantum memory, but below "
        "the 128-bit floor NIST IR 8547 expects after 2030. Rekey to AES-256.",
        classical_bits=128, pqc_replacement="AES-256",
    ),
    "AES-192": AlgorithmFacts(
        "AES-192", PRIM_BLOCK_CIPHER, PQC,
        "Grover leaves roughly 96-bit effective strength, above the post-2030 floor.",
        classical_bits=192, nist_quantum_level=3,
    ),
    "AES-256": AlgorithmFacts(
        "AES-256", PRIM_BLOCK_CIPHER, PQC,
        "Grover leaves roughly 128-bit effective strength. No migration required.",
        classical_bits=256, nist_quantum_level=5,
    ),
    "AES": AlgorithmFacts(
        "AES", PRIM_BLOCK_CIPHER, GROVER,
        "AES with an unrecorded key size. Grover halves whatever it is; confirm the "
        "key length before treating this as safe.",
        classical_bits=None,
    ),
    "CHACHA20": AlgorithmFacts(
        "ChaCha20", PRIM_STREAM_CIPHER, PQC,
        "256-bit stream cipher; Grover leaves roughly 128-bit strength.",
        classical_bits=256, nist_quantum_level=5,
    ),
    "3DES": AlgorithmFacts(
        "3DES", PRIM_BLOCK_CIPHER, CLASSICAL,
        "Triple DES has a 64-bit block, making it vulnerable to Sweet32 birthday "
        "attacks classically. Disallowed by NIST SP 800-131A since 2023. Quantum "
        "is not the reason to remove this.",
        classical_bits=112, pqc_replacement="AES-256",
    ),
    "DES": AlgorithmFacts(
        "DES", PRIM_BLOCK_CIPHER, CLASSICAL,
        "56-bit key, brute-forceable classically in hours. Withdrawn by NIST in 2005.",
        classical_bits=56, pqc_replacement="AES-256",
    ),
    "BLOWFISH": AlgorithmFacts(
        "Blowfish", PRIM_BLOCK_CIPHER, CLASSICAL,
        "64-bit block cipher: vulnerable to Sweet32 birthday attacks at scale, the "
        "same reason 3DES was withdrawn. Classically weak, independent of quantum.",
        classical_bits=64, pqc_replacement="AES-256",
    ),
    "RC4": AlgorithmFacts(
        "RC4", PRIM_STREAM_CIPHER, CLASSICAL,
        "Biased keystream; prohibited in TLS by RFC 7465. Classically broken.",
        classical_bits=None, pqc_replacement="AES-256-GCM",
    ),
    # --- Hashes. ---
    "MD5": AlgorithmFacts(
        "MD5", PRIM_HASH, CLASSICAL,
        "Practical chosen-prefix collisions since 2009. Unusable for any integrity "
        "or signature purpose. Classically broken, independent of quantum.",
        classical_bits=0, pqc_replacement="SHA-256",
    ),
    "SHA-1": AlgorithmFacts(
        "SHA-1", PRIM_HASH, CLASSICAL,
        "Chosen-prefix collision demonstrated in 2020 (SHA-1 is a Shambles) at "
        "roughly 2^63 work. Withdrawn by NIST in 2030 policy; unusable for "
        "signatures now. Classically broken, independent of quantum.",
        classical_bits=63, pqc_replacement="SHA-256",
    ),
    "SHA-224": AlgorithmFacts(
        "SHA-224", PRIM_HASH, GROVER,
        "112-bit collision resistance classically; Grover/BHT erodes the margin. "
        "Move to SHA-256 or better.",
        classical_bits=112, pqc_replacement="SHA-256",
    ),
    "SHA-256": AlgorithmFacts(
        "SHA-256", PRIM_HASH, PQC,
        "128-bit collision resistance; the best known quantum collision search "
        "offers no practical advantage. No migration required.",
        classical_bits=128, nist_quantum_level=2,
    ),
    "SHA-384": AlgorithmFacts(
        "SHA-384", PRIM_HASH, PQC, "192-bit collision resistance. Safe.",
        classical_bits=192, nist_quantum_level=4,
    ),
    "SHA-512": AlgorithmFacts(
        "SHA-512", PRIM_HASH, PQC, "256-bit collision resistance. Safe.",
        classical_bits=256, nist_quantum_level=5,
    ),
    "SHA3-256": AlgorithmFacts(
        "SHA3-256", PRIM_HASH, PQC, "128-bit collision resistance. Safe.",
        classical_bits=128, nist_quantum_level=2,
    ),
    "HMAC": AlgorithmFacts(
        "HMAC", PRIM_MAC, PQC,
        "HMAC security rests on the key, not on collision resistance; unaffected "
        "by quantum attack at 256-bit keys.",
        classical_bits=256,
    ),
    "HKDF": AlgorithmFacts(
        "HKDF", PRIM_KDF, PQC, "Key derivation over HMAC. Unaffected.",
        classical_bits=256,
    ),
    # --- NIST PQC standards. ---
    "ML-KEM-512": AlgorithmFacts(
        "ML-KEM-512", PRIM_KEM, PQC,
        "FIPS 203 module-lattice KEM, NIST security category 1.",
        classical_bits=128, nist_quantum_level=1,
    ),
    "ML-KEM-768": AlgorithmFacts(
        "ML-KEM-768", PRIM_KEM, PQC,
        "FIPS 203 module-lattice KEM, NIST security category 3. The default choice "
        "for TLS key establishment.",
        classical_bits=192, nist_quantum_level=3,
    ),
    "ML-KEM-1024": AlgorithmFacts(
        "ML-KEM-1024", PRIM_KEM, PQC,
        "FIPS 203 module-lattice KEM, NIST security category 5.",
        classical_bits=256, nist_quantum_level=5,
    ),
    "ML-DSA-44": AlgorithmFacts(
        "ML-DSA-44", PRIM_SIGNATURE, PQC,
        "FIPS 204 module-lattice signature, NIST security category 2.",
        classical_bits=128, nist_quantum_level=2,
    ),
    "ML-DSA-65": AlgorithmFacts(
        "ML-DSA-65", PRIM_SIGNATURE, PQC,
        "FIPS 204 module-lattice signature, NIST security category 3.",
        classical_bits=192, nist_quantum_level=3,
    ),
    "ML-DSA-87": AlgorithmFacts(
        "ML-DSA-87", PRIM_SIGNATURE, PQC,
        "FIPS 204 module-lattice signature, NIST security category 5.",
        classical_bits=256, nist_quantum_level=5,
    ),
    # Family names, for evidence that identifies the scheme but not its parameter set: the binary
    # collector's NTT-table layer (all ML-KEM sets share one twiddle table; so do all ML-DSA sets).
    # Facts are those of the weakest set in the family, so nothing is overstated.
    "ML-KEM": AlgorithmFacts(
        "ML-KEM", PRIM_KEM, PQC,
        "FIPS 203 module-lattice KEM; parameter set not identified (its NTT table is shared by all three), "
        "so the weakest set's category 1 is assumed.",
        classical_bits=128, nist_quantum_level=1,
    ),
    "ML-DSA": AlgorithmFacts(
        "ML-DSA", PRIM_SIGNATURE, PQC,
        "FIPS 204 module-lattice signature; parameter set not identified (its NTT table is shared by all "
        "three), so the weakest set's category 2 is assumed.",
        classical_bits=128, nist_quantum_level=2,
    ),
    "SLH-DSA": AlgorithmFacts(
        "SLH-DSA", PRIM_SIGNATURE, PQC,
        "FIPS 205 stateless hash-based signature. Large signatures, but its "
        "security rests only on the hash function - the conservative choice for "
        "long-lived roots and firmware signing.",
        classical_bits=128, nist_quantum_level=1,
    ),
    "X25519MLKEM768": AlgorithmFacts(
        "X25519MLKEM768", PRIM_KEM, PQC,
        "Hybrid key establishment combining X25519 with ML-KEM-768. Secure if "
        "either component holds, which is why it is the recommended transitional "
        "group (draft-ietf-tls-ecdhe-mlkem).",
        classical_bits=192, nist_quantum_level=3,
    ),
    "SECP256R1MLKEM768": AlgorithmFacts(
        "SecP256r1MLKEM768", PRIM_KEM, PQC,
        "Hybrid key establishment combining ECDH over P-256 with ML-KEM-768. Secure "
        "if either component holds; the hybrid for deployments that must keep a "
        "NIST curve (draft-ietf-tls-ecdhe-mlkem).",
        classical_bits=192, nist_quantum_level=3,
    ),
    "SECP384R1MLKEM1024": AlgorithmFacts(
        "SecP384r1MLKEM1024", PRIM_KEM, PQC,
        "Hybrid of ECDH over P-384 with ML-KEM-1024, the CNSA 2.0-aligned hybrid.",
        classical_bits=256, nist_quantum_level=5,
    ),
    "SNTRUP761X25519": AlgorithmFacts(
        "sntrup761x25519", PRIM_KEM, PQC,
        "OpenSSH's hybrid of Streamlined NTRU Prime with X25519. Post-quantum, but "
        "sntrup761 is not a NIST standard; OpenSSH now prefers mlkem768x25519.",
        classical_bits=128,
    ),
}

# Registered object identifiers, for the CBOM `oid` field (CERT-In BOM guidelines
# v2.0, Table 9). Only unambiguous registrations: plain "AES" has none (the OID
# names a key size and mode), and hybrid TLS groups and SSH method names are
# registered as protocol codepoints and names, not OIDs.
STANDARD_OIDS: dict[str, str] = {
    "DH": "1.2.840.10046.2.1",            # dhpublicnumber (ANSI X9.42)
    "DHE": "1.2.840.10046.2.1",
    "ECDH": "1.3.132.1.12",               # id-ecDH (SEC 1)
    "ECDHE": "1.3.132.1.12",
    "X25519": "1.3.101.110",              # RFC 8410
    "X448": "1.3.101.111",
    "ED25519": "1.3.101.112",
    "ED448": "1.3.101.113",
    "3DES": "1.2.840.113549.3.7",         # des-ede3-cbc (RFC 8018)
    "DES": "1.3.14.3.2.7",                # desCBC
    "RC4": "1.2.840.113549.3.4",
    "CHACHA20": "1.2.840.113549.1.9.16.3.18",  # id-alg-AEADChaCha20Poly1305 (RFC 8103)
    "MD5": "1.2.840.113549.2.5",
    "SHA-1": "1.3.14.3.2.26",
    "SHA-224": "2.16.840.1.101.3.4.2.4",
    "SHA-256": "2.16.840.1.101.3.4.2.1",
    "SHA-384": "2.16.840.1.101.3.4.2.2",
    "SHA-512": "2.16.840.1.101.3.4.2.3",
    "SHA3-256": "2.16.840.1.101.3.4.2.8",
    "ML-KEM-512": "2.16.840.1.101.3.4.4.1",   # NIST CSOR, FIPS 203
    "ML-KEM-768": "2.16.840.1.101.3.4.4.2",
    "ML-KEM-1024": "2.16.840.1.101.3.4.4.3",
    "ML-DSA-44": "2.16.840.1.101.3.4.3.17",   # NIST CSOR, FIPS 204
    "ML-DSA-65": "2.16.840.1.101.3.4.3.18",
    "ML-DSA-87": "2.16.840.1.101.3.4.3.19",
}
# AES OIDs name the key size and the mode (NIST CSOR, 2.16.840.1.101.3.4.1; RFC 3565, RFC 5084). There is no
# registered OID for AES in CTR mode, so CTR is absent here by design.
AES_MODE_OIDS: dict[tuple[int, str], str] = {
    (bits, mode): f"2.16.840.1.101.3.4.1.{base + arc}"
    for bits, base in ((128, 0), (192, 20), (256, 40))
    for mode, arc in (("ecb", 1), ("cbc", 2), ("ofb", 3), ("cfb", 4), ("gcm", 6), ("ccm", 7))
}
for _key, _oid in STANDARD_OIDS.items():
    if _key in _STATIC and _STATIC[_key].oid is None:
        _STATIC[_key] = replace(_STATIC[_key], oid=_oid)

# Alternate spellings seen in certificates, configs and source.
_ALIASES = {
    "ECC": "ECDSA", "EC": "ECDSA", "ECDSA": "ECDSA",
    "SECP256R1": "ECDSA", "PRIME256V1": "ECDSA", "P-256": "ECDSA",
    "SHA1": "SHA-1", "SHA256": "SHA-256", "SHA384": "SHA-384", "SHA512": "SHA-512",
    "SHA224": "SHA-224", "SHA-3": "SHA3-256", "SHA3": "SHA3-256",
    "DESEDE": "3DES", "TRIPLEDES": "3DES", "DES-EDE3": "3DES",
    "CHACHA20-POLY1305": "CHACHA20", "POLY1305": "CHACHA20",
    "CURVE25519": "X25519", "EDDSA": "ED25519",
    "KYBER": "ML-KEM-768", "KYBER768": "ML-KEM-768",
    "DILITHIUM": "ML-DSA-65", "DILITHIUM3": "ML-DSA-65",
    "SPHINCS+": "SLH-DSA", "SPHINCSPLUS": "SLH-DSA",
    "RSAENCRYPTION": "RSA", "RSASSA-PSS": "RSA",
    "MLKEM768X25519": "X25519MLKEM768", "MLKEM768NISTP256": "SECP256R1MLKEM768",
    "MLKEM1024NISTP384": "SECP384R1MLKEM1024",
}

_CURVE_BY_SIZE = {256: "P-256", 384: "P-384", 521: "P-521", 224: "P-224"}


def classify_algorithm(name: str | None, key_size: int | None = None) -> AlgorithmFacts:
    """Classify a single named algorithm."""
    if not name:
        return AlgorithmFacts(
            "Unknown", PRIM_UNKNOWN, UNKNOWN,
            "No algorithm recorded for this finding. Treated as unknown rather than "
            "safe - an uninventoried algorithm is a gap, not a pass.",
        )

    raw = name.strip()
    key = re.sub(r"[\s_]+", "-", raw).upper()

    # Signature-algorithm OID names, e.g. sha256WithRSAEncryption.
    m = re.match(r"^(SHA-?\d+|MD5)-?WITH-?(RSA|ECDSA|DSA)", key)
    if m:
        key = m.group(2)
    m = re.match(r"^(ECDSA|RSASSA-PSS|RSA)-WITH-(SHA-?\d+)$", key)
    if m:
        key = m.group(1)

    key = _ALIASES.get(key, key)

    if key.startswith("RSA"):
        embedded = re.search(r"(\d{3,5})", key)
        size = key_size or (int(embedded.group(1)) if embedded else None)
        return _rsa_facts(size)

    if key in {"ECDSA", "ECDH"}:
        curve = _CURVE_BY_SIZE.get(key_size or 0)
        return _ec_facts(key, key_size, curve)

    # AES-128 / AES-256 style, or bare AES plus a separate key_size.
    if key.startswith("AES"):
        embedded = re.search(r"(128|192|256)", key)
        size = int(embedded.group(1)) if embedded else key_size
        return _STATIC.get(f"AES-{size}", _STATIC["AES"])

    if key in _STATIC:
        return _STATIC[key]

    # Longest-prefix match handles things like "ML-KEM-768-X25519".
    for known in sorted(_STATIC, key=len, reverse=True):
        if key.startswith(known):
            return _STATIC[known]

    return AlgorithmFacts(
        raw, PRIM_UNKNOWN, UNKNOWN,
        f"'{raw}' is not in the VERA taxonomy. Flagged for manual review rather "
        "than assumed safe.",
    )


# --------------------------------------------------------------------------
# Cipher suite decomposition
# --------------------------------------------------------------------------


@dataclass
class SuiteBreakdown:
    """A TLS cipher suite split into the parts that get judged separately."""

    suite: str
    key_exchange: str | None = None
    authentication: str | None = None
    bulk_cipher: str | None = None
    bulk_key_bits: int | None = None
    mode: str | None = None
    mac: str | None = None
    # (role, facts) pairs, e.g. ("suite_bulk_cipher", <AES-256>).
    components: list[tuple[str, AlgorithmFacts]] = field(default_factory=list)

    @property
    def worst_verdict(self) -> str:
        """The verdict that governs the suite as a whole.

        Ordered by how much work the finding implies: an outright classical break
        outranks a Shor break because it is exploitable today.
        """
        present = {facts.verdict for _, facts in self.components}
        for verdict in VERDICT_SEVERITY:
            if verdict in present:
                return verdict
        return UNKNOWN


_BULK_PATTERNS = [
    (r"AES[-_]?256[-_]?GCM", "AES", 256, "gcm"),
    (r"AES[-_]?128[-_]?GCM", "AES", 128, "gcm"),
    (r"AES[-_]?256[-_]?CCM", "AES", 256, "ccm"),
    (r"AES[-_]?128[-_]?CCM", "AES", 128, "ccm"),
    (r"AES[-_]?256[-_]?CBC", "AES", 256, "cbc"),
    (r"AES[-_]?128[-_]?CBC", "AES", 128, "cbc"),
    (r"AES[-_]?256", "AES", 256, None),
    (r"AES[-_]?128", "AES", 128, None),
    (r"CHACHA20[-_]?POLY1305", "CHACHA20", 256, None),
    (r"3DES[-_]?EDE[-_]?CBC|DES[-_]?CBC3", "3DES", 112, "cbc"),
    (r"\bRC4\b", "RC4", 128, None),
]

_MAC_PATTERNS = [
    (r"SHA384", "SHA-384"), (r"SHA256", "SHA-256"),
    (r"SHA3_256|SHA3-256", "SHA3-256"),
    (r"POLY1305", "HMAC"), (r"\bSHA\b(?!\d)", "SHA-1"), (r"\bMD5\b", "MD5"),
]


def decompose_cipher_suite(suite: str) -> SuiteBreakdown:
    """Split a TLS cipher suite into key-exchange / auth / bulk / MAC.

    Handles both IANA names (``TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384``) and
    OpenSSL names (``ECDHE-RSA-AES256-GCM-SHA384``), plus TLS 1.3 suites, which
    carry no key-exchange or authentication in the suite name at all - those are
    negotiated separately, and pretending otherwise is where the old
    substring matcher went wrong.
    """
    out = SuiteBreakdown(suite=suite)
    if not suite:
        return out

    upper = suite.upper()

    # TLS 1.3 suites: TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256.
    # Key exchange and authentication are NOT part of the suite here.
    is_tls13 = bool(
        re.match(r"^TLS[-_](AES|CHACHA20)", upper)
        and "WITH" not in upper
    )

    if not is_tls13:
        if "ECDHE" in upper or "EECDH" in upper:
            out.key_exchange = "ECDHE"
        elif re.search(r"\bDHE\b|EDH", upper):
            out.key_exchange = "DHE"
        elif "ECDH" in upper:
            out.key_exchange = "ECDH"
        elif upper.startswith("TLS_RSA") or re.match(r"^(AES|DES|RC4)", upper):
            # Static RSA key transport: no forward secrecy at all.
            out.key_exchange = "RSA"
        elif "PSK" in upper:
            out.key_exchange = "PSK"

        if "ECDSA" in upper:
            out.authentication = "ECDSA"
        elif "RSA" in upper:
            out.authentication = "RSA"
        elif "DSS" in upper or "DSA" in upper:
            out.authentication = "DSA"

    for pattern, algo, bits, mode in _BULK_PATTERNS:
        if re.search(pattern, upper):
            out.bulk_cipher, out.bulk_key_bits, out.mode = algo, bits, mode
            break

    for pattern, mac in _MAC_PATTERNS:
        if re.search(pattern, upper):
            out.mac = mac
            break

    if out.key_exchange:
        out.components.append(("suite_key_exchange", classify_algorithm(out.key_exchange)))
    if out.authentication:
        out.components.append(("suite_authentication", classify_algorithm(out.authentication)))
    if out.bulk_cipher:
        out.components.append(
            ("suite_bulk_cipher", classify_algorithm(out.bulk_cipher, out.bulk_key_bits))
        )
    if out.mac:
        out.components.append(("suite_mac", classify_algorithm(out.mac)))

    return out


# --------------------------------------------------------------------------
# Protocol versions
# --------------------------------------------------------------------------

# A protocol version is judged on the version itself, NOT on the key-exchange
# group it happens to negotiate. TLS 1.2 and 1.3 are not Shor-breakable; the
# group is, and the group is a separate finding with its own score. Folding the
# group's weakness into the protocol row is how a scanner ends up reporting an
# AES-256-GCM record layer as "breakable by Shor".
_PROTOCOL_VERDICTS = {
    "SSLV2": (CLASSICAL, "SSLv2 is broken by DROWN and prohibited by RFC 6176."),
    "SSLV3": (CLASSICAL, "SSLv3 is broken by POODLE and prohibited by RFC 7568."),
    "TLSV1.0": (CLASSICAL, "TLS 1.0 is deprecated by RFC 8996: no AEAD, SHA-1 in the PRF."),
    "TLSV1.1": (CLASSICAL, "TLS 1.1 is deprecated by RFC 8996."),
    "TLSV1.2": (
        PQC,
        "TLS 1.2 as a protocol version needs no post-quantum change. What matters is "
        "the negotiated group, scored separately. TLS 1.2 has no standardised hybrid "
        "group, so reaching a quantum-safe handshake means moving to TLS 1.3 first.",
    ),
    "TLSV1.3": (
        PQC,
        "TLS 1.3 is the target protocol version and supports hybrid groups such as "
        "X25519MLKEM768. The version needs no change; the negotiated group is scored "
        "as its own asset.",
    ),
}

# Longest key first so "TLSV1.2" is not shadowed by a "TLSV1" prefix.
_PROTOCOL_KEYS = sorted(_PROTOCOL_VERDICTS, key=len, reverse=True)


def classify_protocol(version: str | None) -> tuple[str, str]:
    """Return (verdict, rationale) for a protocol version string."""
    if not version:
        return UNKNOWN, "No protocol version recorded."
    key = re.sub(r"[\s_]+", "", version).upper()
    # Normalise bare "TLSV1" to "TLSV1.0"; anything else keeps its explicit minor.
    if re.fullmatch(r"TLSV1", key):
        key = "TLSV1.0"
    for known in _PROTOCOL_KEYS:
        if known in key:
            return _PROTOCOL_VERDICTS[known]
    return UNKNOWN, f"Protocol '{version}' is not in the VERA taxonomy."


# --------------------------------------------------------------------------
# Top-level entry point used by the scoring pipeline
# --------------------------------------------------------------------------

# Verdicts that mean "this asset needs a post-quantum migration".
_REQUIRES_PQC_MIGRATION = {SHOR}


# --------------------------------------------------------------------------
# Grover-bounded residual security
#
# A boolean "grover_weakened" is too coarse to plan against: AES-128 and
# AES-256 are both weakened, and the difference between them is a factor of
# 2^64 in residual security. One needs replacing before 2030; the other is
# comfortable past 2040. Reporting them identically is the kind of averaging
# this engine exists to remove.
#
# Grover's algorithm searches an unstructured keyspace in ~2^(n/2) operations,
# so the conservative planning figure is half the classical strength. Two
# honest caveats travel with that number rather than being buried:
#
#   * NIST's own position is that Grover does not parallelise usefully - the
#     speedup requires a long *sequential* computation - so 2^(n/2) is an upper
#     bound on the adversary, not an expectation. Treating it as the planning
#     figure is deliberately conservative.
#   * It applies to symmetric key search and hash preimage resistance. Hash
#     *collision* resistance is already bits/2 classically by the birthday
#     bound, and quantum offers little further practical gain, so collision
#     strength is not halved a second time here.
# --------------------------------------------------------------------------

#: Residual-strength bands, in bits, after the Grover discount. Thresholds
#: follow NIST's categories: 128 bits is the long-term target, 112 is the
#: minimum acceptable through 2030, below 64 is not a security level.
GROVER_BANDS = [
    (128, "comfortable", "At or above the 128-bit post-quantum target. No action needed on Grover grounds."),
    (112, "adequate", "Meets the near-term minimum but sits below the 128-bit target. Replace on the normal refresh cycle."),
    (64, "weakened", "Materially reduced. Usable today, but this should be scheduled for replacement."),
    (0, "inadequate", "Below any accepted security level once Grover is assumed. Replace."),
]

#: Primitives to which the Grover discount applies: symmetric encryption,
#: authenticated encryption, hashing and MACs. Asymmetric primitives are
#: deliberately excluded - see the note in `grover_residual`.
_GROVER_APPLIES = {
    PRIM_BLOCK_CIPHER, PRIM_STREAM_CIPHER, PRIM_AE, PRIM_MAC, PRIM_KDF,
}

#: Hashes are handled separately and are NOT halved. The `classical_bits`
#: recorded for a hash is its *collision* resistance, which is already the
#: birthday bound (SHA-256 -> 128, not 256). Applying the Grover discount to a
#: figure that has already been halved once would double-count, and would
#: report SHA-256 as 64-bit - which is wrong by a factor of 2^64.
_GROVER_HASH_PRIMITIVES = {PRIM_HASH}


def grover_residual(classical_bits: int | None, primitive: str) -> dict:
    """Residual security in bits once Grover is assumed, with its band.

    Returns `applies=False` for asymmetric primitives: those are broken outright
    by Shor rather than weakened by Grover, and halving their key size would be
    a category error that understates the problem.
    """
    if primitive in _GROVER_HASH_PRIMITIVES:
        return {
            "applies": False,
            "residual_bits": classical_bits,
            "band": None,
            "note": (
                f"Collision resistance is already the birthday bound "
                f"({classical_bits} bits), not the digest length. Grover's "
                f"square-root speedup applies to preimage search, which is not "
                f"the binding property here, and the best known quantum "
                f"collision attack needs impractical quantum memory. The figure "
                f"is therefore reported unhalved rather than discounted twice."
            ) if classical_bits else "Digest strength unknown.",
        }

    if primitive not in _GROVER_APPLIES:
        return {
            "applies": False,
            "residual_bits": None,
            "band": None,
            "note": (
                "Grover does not govern this primitive. Asymmetric cryptography "
                "is broken outright by Shor, not weakened by a square-root "
                "speedup, so a residual-bits figure would understate it."
            ),
        }

    if not classical_bits or classical_bits <= 0:
        return {
            "applies": True,
            "residual_bits": None,
            "band": None,
            "note": "Key size unknown, so residual strength cannot be computed.",
        }

    residual = classical_bits // 2
    band, guidance = next(
        (name, why) for threshold, name, why in GROVER_BANDS if residual >= threshold
    )

    return {
        "applies": True,
        "classical_bits": classical_bits,
        "residual_bits": residual,
        "band": band,
        "guidance": guidance,
        "note": (
            f"{classical_bits}-bit classical strength becomes ~{residual} bits "
            f"against a Grover search (2^{residual} operations). NIST notes the "
            f"speedup does not parallelise usefully, so this is a conservative "
            f"upper bound on the adversary rather than an expectation."
        ),
    }


def classify_finding(
    algorithm: str | None,
    key_size: int | None,
    cipher_suite: str | None,
    key_exchange: str | None,
    protocol: str | None,
) -> dict:
    """Classify one raw finding across all the signals it carries.

    Returns a dict with the governing verdict, a human rationale, the primitive,
    and the per-component detail the asset detail view walks through.
    """
    components: list[tuple[str, AlgorithmFacts]] = []

    if algorithm:
        components.append(("algorithm", classify_algorithm(algorithm, key_size)))
    if key_exchange:
        components.append(("key_exchange", classify_algorithm(key_exchange, key_size)))

    suite_breakdown = None
    if cipher_suite:
        suite_breakdown = decompose_cipher_suite(cipher_suite)
        components.extend(suite_breakdown.components)

    protocol_verdict, protocol_why = classify_protocol(protocol)

    # Governing verdict: worst across the cryptographic material present.
    #
    # The protocol version only contributes when it is CLASSICAL - a deprecated
    # version (SSLv3, TLS 1.0) is a finding in its own right. A current version
    # contributes nothing, because "TLS 1.3" is not a weakness; whatever group it
    # negotiated is, and that group is scored as a separate asset.
    present = {facts.verdict for _, facts in components}
    if protocol_verdict == CLASSICAL:
        present.add(CLASSICAL)

    verdict = UNKNOWN
    for candidate in VERDICT_SEVERITY:
        if candidate in present:
            verdict = candidate
            break

    # Pick the rationale from the component that actually drove the verdict, so
    # the UI explains the specific reason rather than a generic sentence.
    rationale = None
    primitive = PRIM_UNKNOWN
    driver = None
    for _, facts in components:
        if facts.verdict == verdict:
            rationale, primitive, driver = facts.rationale, facts.primitive, facts.canonical
            break
    if rationale is None:
        if verdict == CLASSICAL and protocol_verdict == CLASSICAL:
            rationale, driver = protocol_why, protocol
        else:
            rationale = "No cryptographic material classified for this finding."

    primary = components[0][1] if components else None

    # A finding can be two things at once. `TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA`
    # has a classically broken bulk cipher AND a Shor-breakable key exchange; the
    # governing verdict reports the more urgent one, but these flags stay
    # independent so neither count is silently suppressed.
    quantum_vulnerable = any(f.verdict in _REQUIRES_PQC_MIGRATION for _, f in components)
    classically_broken = (
        any(f.verdict == CLASSICAL for _, f in components) or protocol_verdict == CLASSICAL
    )
    grover_weakened = any(f.verdict == GROVER for _, f in components)

    return {
        "verdict": verdict,
        "quantum_vulnerable": quantum_vulnerable,
        "classically_broken": classically_broken,
        "grover_weakened": grover_weakened,
        # Residual strength, not just a flag: AES-128 and AES-256 are both
        # "weakened" and are 2^64 apart, which is the difference between
        # replace-now and comfortable-past-2040.
        "grover": grover_residual(
            primary.classical_bits if primary else None,
            primary.primitive if primary else PRIM_UNKNOWN,
        ),
        "rationale": rationale,
        "driver": driver,
        "primitive": primitive,
        "classical_bits": primary.classical_bits if primary else None,
        "nist_quantum_level": primary.nist_quantum_level if primary else 0,
        "pqc_replacement": next(
            (f.pqc_replacement for _, f in components if f.verdict == verdict and f.pqc_replacement),
            None,
        ),
        "curve": primary.curve if primary else None,
        "oid": primary.oid if primary else None,
        "protocol_verdict": protocol_verdict,
        "protocol_rationale": protocol_why,
        "components": [
            {
                "role": role,
                "algorithm": f.canonical,
                "primitive": f.primitive,
                "verdict": f.verdict,
                "rationale": f.rationale,
                "classical_bits": f.classical_bits,
                "pqc_replacement": f.pqc_replacement,
            }
            for role, f in components
        ],
        "suite": (
            {
                "key_exchange": suite_breakdown.key_exchange,
                "authentication": suite_breakdown.authentication,
                "bulk_cipher": suite_breakdown.bulk_cipher,
                "bulk_key_bits": suite_breakdown.bulk_key_bits,
                "mode": suite_breakdown.mode,
                "mac": suite_breakdown.mac,
            }
            if suite_breakdown
            else None
        ),
    }
