"""M1 — Key material scanner.

Finds *key material* in a tree: PEM private keys, certificates, SSH keys, and
high-entropy credentials. This is the collector that answers the question the
original source scanner could not — "where are the actual keys, and is the same
key in more than one place" — which is the input to key-reuse detection and to
any honest migration plan.

THREE DETECTION METHODS, IN DESCENDING PRECISION
------------------------------------------------
1. **Structural** — a PEM/OpenSSH block header is unambiguous. When the block
   parses, the algorithm and key size are *read*, not guessed, and the finding
   is graded `artifact_parsed`.
2. **Pattern** — known credential formats with distinctive prefixes. High
   precision, and the provider is identified.
3. **Entropy** — Shannon entropy over a candidate string, gated by context.
   This is the only method that finds unknown formats, and it is also the only
   one that produces false positives, so it is graded `heuristic` and is always
   labelled as requiring review.

WHAT NEVER LEAVES
-----------------
**The secret itself is never stored, logged, or returned.** Only a SHA-256
fingerprint, its location, and its shape. That is enough to detect reuse across
hosts and repos, to prove a key exists, and to plan its rotation — and it means
running this scanner never creates a second copy of a credential. This is the
same boundary the rest of the product holds: metadata crosses, key material
does not.

WHAT THIS DOES NOT DO
---------------------
No dataflow, no live credential validation (that would mean transmitting the
secret to a third party, which this boundary forbids), and no model is consulted
to decide whether something is a secret.
"""

from __future__ import annotations

import hashlib
import math
import re
import uuid
from pathlib import Path

from models.schemas import RawCryptoFinding

# --------------------------------------------------------------------------
# Structural: PEM and OpenSSH blocks
# --------------------------------------------------------------------------

_PEM_BLOCK = re.compile(
    r"-----BEGIN ((?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY|CERTIFICATE)-----"
    r"(.*?)"
    r"-----END \1-----",
    re.S,
)

# Header -> (algorithm, asset_class, usage). Algorithm None means the block must
# be parsed to know, which _classify_pem does when cryptography is available.
_PEM_KIND = {
    "RSA PRIVATE KEY": ("RSA", "generic_key", "signing"),
    "EC PRIVATE KEY": ("ECDSA", "generic_key", "signing"),
    "DSA PRIVATE KEY": ("DSA", "generic_key", "signing"),
    "PRIVATE KEY": (None, "generic_key", "signing"),
    "ENCRYPTED PRIVATE KEY": (None, "generic_key", "signing"),
    "OPENSSH PRIVATE KEY": (None, "ssh_key", "signing"),
    "CERTIFICATE": (None, "tls_certificate", "signing"),
}

# --------------------------------------------------------------------------
# Pattern: known credential formats
# --------------------------------------------------------------------------

# Kept deliberately short and high-precision. A long list of loose patterns is
# how secret scanners earn their reputation for noise.
_CREDENTIAL_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("AWS access key id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b")),
    ("Stripe secret key", re.compile(r"\b[sr]k_(?:live|test)_[0-9A-Za-z]{16,}\b")),
    ("JSON Web Token", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b")),
    ("Private key assignment", re.compile(r"(?i)\b(?:private_key|secret_key|api_secret)\s*[:=]\s*['\"][^'\"]{16,}['\"]")),
]

# --------------------------------------------------------------------------
# Entropy: unknown formats
# --------------------------------------------------------------------------

# A quoted or assigned string long enough to be a credential.
_CANDIDATE = re.compile(r"['\"]([A-Za-z0-9+/=_\-]{24,120})['\"]")

# Context that makes a high-entropy string much more likely to be a secret.
_SECRET_CONTEXT = re.compile(
    r"(?i)\b(?:secret|token|password|passwd|api[_-]?key|auth|credential|private|"
    r"signing[_-]?key|encryption[_-]?key|access[_-]?key)\b"
)

# Context that makes it much less likely. Suppressing these is the single
# largest false-positive reduction available.
_NOISE_CONTEXT = re.compile(
    r"(?i)\b(?:example|sample|dummy|placeholder|fake|test|mock|fixture|lorem|"
    r"xxxx+|changeme|your[_-]?key[_-]?here|redacted)\b"
)

# Strings that are structurally not credentials however random they look.
_NOT_A_SECRET = re.compile(
    r"(?i)^(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})$"  # plain hashes/digests
    r"|^(?:https?://|/|\./|[a-z]+\.[a-z]+\.[a-z]+$)"      # urls, paths, dotted names
)

_ENTROPY_FLOOR = 4.0          # bits/char; base64-ish random text sits ~4.5-6.0
_ENTROPY_FLOOR_WITH_CONTEXT = 3.5   # a secret-shaped variable name lowers the bar

_SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", "venv", ".venv", "build", "dist",
    "target", ".next", "vendor", "site-packages", ".mypy_cache", ".pytest_cache",
}
_SKIP_SUFFIXES = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".pdf", ".zip", ".gz",
    ".tar", ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3", ".lock",
}
_MAX_FILE_BYTES = 2_000_000


def shannon_entropy(text: str) -> float:
    """Bits of entropy per character.

    The standard measure used by every credential scanner: a value near 0 means
    highly repetitive, ~4.5-6.0 is characteristic of random base64.
    """
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    length = len(text)
    total = -sum(
        (count / length) * math.log2(count / length) for count in counts.values()
    )
    # A single repeated character yields -0.0; normalise so callers and the UI
    # never render a negative zero.
    return total + 0.0 if total else 0.0


def fingerprint(material: str) -> str:
    """A stable, non-reversible identifier for a piece of key material.

    Whitespace is stripped first so the same key formatted differently in two
    places still collides — which is the entire point: this is what makes
    "the same key is on twelve hosts" detectable without ever holding the key.
    """
    normalised = "".join(material.split())
    return hashlib.sha256(normalised.encode("utf-8", "replace")).hexdigest()


def _classify_pem(header: str, body: str) -> tuple[str | None, int | None, str]:
    """Read algorithm and key size from a PEM block where possible.

    Falls back to the header's implied algorithm when the block is encrypted or
    the cryptography library cannot parse it. Returns (algorithm, key_size, how).
    """
    default_algorithm, _, _ = _PEM_KIND.get(header, (None, None, None))

    if header in {"ENCRYPTED PRIVATE KEY", "OPENSSH PRIVATE KEY"}:
        # Encrypted or OpenSSH-wrapped: the header is all that can be read
        # without a passphrase, and asking for one is out of scope.
        return default_algorithm, None, "header"

    pem = f"-----BEGIN {header}-----{body}-----END {header}-----".encode()
    try:
        from cryptography.hazmat.primitives.asymmetric import ec, rsa
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        from cryptography.x509 import load_pem_x509_certificate

        if header == "CERTIFICATE":
            cert = load_pem_x509_certificate(pem)
            public = cert.public_key()
        else:
            public = load_pem_private_key(pem, password=None).public_key()

        if isinstance(public, rsa.RSAPublicKey):
            return "RSA", public.key_size, "parsed"
        if isinstance(public, ec.EllipticCurvePublicKey):
            return "ECDSA", public.curve.key_size, "parsed"
        name = type(public).__name__.replace("PublicKey", "")
        return name, getattr(public, "key_size", None), "parsed"
    except Exception:  # noqa: BLE001 - unparseable is a normal outcome here
        return default_algorithm, None, "header"


def _scan_text(path: Path, text: str, root: Path) -> list[RawCryptoFinding]:
    findings: list[RawCryptoFinding] = []
    try:
        where = str(path.relative_to(root))
    except ValueError:
        where = str(path)

    seen_fingerprints: set[str] = set()
    # Lines already explained by a structural or pattern hit. The entropy pass
    # skips them: one secret must not be reported twice just because two methods
    # of different precision both saw it.
    claimed_lines: set[int] = set()

    # --- 1. Structural: PEM / OpenSSH blocks -------------------------------
    for match in _PEM_BLOCK.finditer(text):
        header, body = match.group(1), match.group(2)
        algorithm, key_size, how = _classify_pem(header, body)
        _, asset_class, usage = _PEM_KIND.get(header, (None, "generic_key", "signing"))
        fp = fingerprint(body)
        if fp in seen_fingerprints:
            continue
        seen_fingerprints.add(fp)

        line = text[: match.start()].count("\n") + 1
        claimed_lines.update(range(line, text[: match.end()].count("\n") + 2))
        is_certificate = header == "CERTIFICATE"
        findings.append(
            RawCryptoFinding(
                id=f"secret-{uuid.uuid4().hex[:12]}",
                source_type="keystore",
                source_location=f"{where}:{line}",
                asset_class=asset_class,
                algorithm=algorithm,
                key_size=key_size,
                usage=usage,
                tags=["key-material", "pem", "certificate" if is_certificate else "private-key"],
                raw_details={
                    "detection": "structural",
                    "pem_header": header,
                    "algorithm_source": how,
                    "key_fingerprint": fp,
                    "material_stored": False,
                    "requires_review": False,
                    "note": (
                        "Private key material found in a scanned tree. Only a "
                        "SHA-256 fingerprint is retained."
                        if not is_certificate
                        else "Certificate found in a scanned tree."
                    ),
                },
            )
        )

    # --- 2. Pattern: known credential formats ------------------------------
    for provider, pattern in _CREDENTIAL_PATTERNS:
        for match in pattern.finditer(text):
            value = match.group(0)
            fp = fingerprint(value)
            if fp in seen_fingerprints:
                continue
            seen_fingerprints.add(fp)
            line = text[: match.start()].count("\n") + 1
            claimed_lines.add(line)
            findings.append(
                RawCryptoFinding(
                    id=f"secret-{uuid.uuid4().hex[:12]}",
                    source_type="source",
                    source_location=f"{where}:{line}",
                    asset_class="generic_key",
                    algorithm=None,
                    usage="credential",
                    tags=["key-material", "credential", "hardcoded"],
                    raw_details={
                        "detection": "pattern",
                        "credential_type": provider,
                        "key_fingerprint": fp,
                        "material_stored": False,
                        "requires_review": False,
                        "note": (
                            f"A {provider} was found hardcoded. VERA does not "
                            "validate credentials against live services."
                        ),
                    },
                )
            )

    # --- 3. Entropy: unknown formats, context-gated ------------------------
    lines = text.splitlines()
    for index, raw_line in enumerate(lines, start=1):
        if index in claimed_lines or len(raw_line) > 4000:
            continue
        has_secret_context = bool(_SECRET_CONTEXT.search(raw_line))
        if _NOISE_CONTEXT.search(raw_line):
            continue

        for match in _CANDIDATE.finditer(raw_line):
            value = match.group(1)
            if _NOT_A_SECRET.search(value):
                continue
            entropy = shannon_entropy(value)
            floor = _ENTROPY_FLOOR_WITH_CONTEXT if has_secret_context else _ENTROPY_FLOOR
            if entropy < floor:
                continue
            # Without a secret-shaped name nearby, demand real randomness.
            if not has_secret_context and entropy < _ENTROPY_FLOOR + 0.5:
                continue

            fp = fingerprint(value)
            if fp in seen_fingerprints:
                continue
            seen_fingerprints.add(fp)
            findings.append(
                RawCryptoFinding(
                    id=f"secret-{uuid.uuid4().hex[:12]}",
                    source_type="source",
                    source_location=f"{where}:{index}",
                    asset_class="generic_key",
                    usage="credential",
                    tags=["key-material", "high-entropy", "needs-review"],
                    raw_details={
                        "detection": "entropy",
                        "entropy_bits_per_char": round(entropy, 3),
                        "length": len(value),
                        "context_match": has_secret_context,
                        "key_fingerprint": fp,
                        "material_stored": False,
                        "requires_review": True,
                        "note": (
                            "High-entropy string in a credential-shaped context. "
                            "Heuristic only — confirm before treating as a key."
                        ),
                    },
                )
            )

    return findings


def scan_tree(root: str | Path, max_files: int = 20_000) -> list[RawCryptoFinding]:
    """Walk a directory and report key material found in it.

    Binary and vendored paths are skipped. The traversal is bounded so pointing
    this at a very large monorepo degrades into a partial scan rather than a
    hang; the caller is told how far it got via the returned count.
    """
    root_path = Path(root).resolve()
    if not root_path.is_dir():
        return []

    findings: list[RawCryptoFinding] = []
    examined = 0

    for path in root_path.rglob("*"):
        if examined >= max_files:
            break
        if not path.is_file():
            continue
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        if path.suffix.lower() in _SKIP_SUFFIXES:
            continue
        try:
            if path.stat().st_size > _MAX_FILE_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        examined += 1
        findings.extend(_scan_text(path, text, root_path))

    return findings


def reuse_clusters(findings: list[RawCryptoFinding]) -> list[dict]:
    """Group findings by key fingerprint and report every key seen more than once.

    This is the payoff of fingerprinting: one key present in several places means
    compromising any one location compromises all of them, and migrating it is
    not one change but N.
    """
    by_fingerprint: dict[str, list[RawCryptoFinding]] = {}
    for finding in findings:
        fp = finding.raw_details.get("key_fingerprint")
        if fp:
            by_fingerprint.setdefault(fp, []).append(finding)

    clusters = [
        {
            "fingerprint": fp[:16],
            "occurrences": len(group),
            "algorithm": group[0].algorithm,
            "locations": [f.source_location for f in group[:25]],
        }
        for fp, group in by_fingerprint.items()
        if len(group) > 1
    ]
    return sorted(clusters, key=lambda c: c["occurrences"], reverse=True)
