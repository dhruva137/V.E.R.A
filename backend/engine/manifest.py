"""Signed scan manifest: the report protects itself.

A manifest pins one scan: the tool and threat-model versions, the profile and
policy, a SHA-256 of every collector's output, and SHA-256 of the CBOM and
SARIF exported from it. It is then signed:

    ML-DSA-65 (FIPS 204)         when an OpenSSL 3.5+ CLI is available (`VERA_OPENSSL`, PATH, or a well-known install)
    Ed25519 (classical fallback) otherwise, and labelled that way everywhere it appears

A scanner that tells an organisation to move to post-quantum signatures should
sign its own evidence with one, and say so plainly when it cannot.

Keys are generated on first use in `backend/data/signing/` (gitignored); only
the public key ever leaves the host. The signature covers the canonical JSON
of the manifest without its `signature` block, so changing any byte of the
manifest, or of the CBOM it names, makes verification fail.

CLI:
    python -m engine.manifest verify <manifest.json> [--public-key <pem>]
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from engine.version import TOOL_NAME, TOOL_VERSION

KEY_DIR = Path(os.environ.get("VERA_SIGNING_DIR", Path(__file__).resolve().parents[1] / "data" / "signing"))
ML_DSA = "ML-DSA-65"
ED25519 = "Ed25519 (classical fallback)"


def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).encode("utf-8")


def sha256_hex(data: bytes | str) -> str:
    return hashlib.sha256(data.encode("utf-8") if isinstance(data, str) else data).hexdigest()


# --------------------------------------------------------------------------
# Signing backends
# --------------------------------------------------------------------------


def _well_known_openssl() -> list[str]:
    """Where OpenSSL 3.5+ commonly ships when it is not on PATH.

    Git for Windows bundles a current OpenSSL CLI, but a server started from
    PowerShell or a service does not have Git's bin directory on PATH; without
    this the manifest would fall back to Ed25519 on a host that can sign ML-DSA.
    """
    program_files = os.environ.get("ProgramFiles", r"C:\Program Files")
    return [
        str(Path(program_files) / "Git" / "mingw64" / "bin" / "openssl.exe"),
        str(Path(program_files) / "Git" / "usr" / "bin" / "openssl.exe"),
        "/opt/homebrew/opt/openssl@3/bin/openssl",
        "/usr/local/opt/openssl@3/bin/openssl",
    ]


def find_openssl() -> str | None:
    """An OpenSSL CLI of 3.5 or later, or None: `VERA_OPENSSL`, then PATH, then well-known installs."""
    for candidate in (os.environ.get("VERA_OPENSSL"), shutil.which("openssl"),
                      *(p for p in _well_known_openssl() if Path(p).is_file())):
        if not candidate:
            continue
        try:
            out = subprocess.run([candidate, "version"], capture_output=True, text=True, timeout=10).stdout
        except (OSError, subprocess.TimeoutExpired):
            continue
        m = re.search(r"OpenSSL (\d+)\.(\d+)", out)
        if m and (int(m.group(1)), int(m.group(2))) >= (3, 5):
            return candidate
    return None


def _run(openssl: str, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run([openssl, *args], capture_output=True, text=True, timeout=60)


class _MLDSA:
    alg = ML_DSA

    def __init__(self, openssl: str, key_dir: Path):
        self.openssl, self.key, self.pub = openssl, key_dir / "ml-dsa-65.key.pem", key_dir / "ml-dsa-65.pub.pem"
        version = _run(openssl, "version").stdout.strip()
        self.provider = version.split("(")[0].strip() or "OpenSSL 3.5+"
        if not self.key.exists():
            key_dir.mkdir(parents=True, exist_ok=True)
            if _run(openssl, "genpkey", "-algorithm", ML_DSA, "-out", str(self.key)).returncode != 0:
                raise RuntimeError("ML-DSA-65 key generation failed")
            if _run(openssl, "pkey", "-in", str(self.key), "-pubout", "-out", str(self.pub)).returncode != 0:
                raise RuntimeError("ML-DSA-65 public key export failed")

    def public_pem(self) -> str:
        return self.pub.read_text(encoding="ascii")

    def sign(self, payload: bytes) -> bytes:
        with tempfile.TemporaryDirectory() as tmp:
            data, sig = Path(tmp) / "payload.bin", Path(tmp) / "sig.bin"
            data.write_bytes(payload)
            result = _run(self.openssl, "pkeyutl", "-sign", "-inkey", str(self.key), "-rawin",
                          "-in", str(data), "-out", str(sig))
            if result.returncode != 0:
                raise RuntimeError(f"ML-DSA-65 signing failed: {result.stderr.strip()[:200]}")
            return sig.read_bytes()


class _Ed25519:
    alg = ED25519
    provider = "pyca/cryptography"

    def __init__(self, key_dir: Path):
        self.key_path = key_dir / "ed25519.key.pem"
        if not self.key_path.exists():
            key_dir.mkdir(parents=True, exist_ok=True)
            key = Ed25519PrivateKey.generate()
            self.key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                        serialization.NoEncryption()))
        self._key = serialization.load_pem_private_key(self.key_path.read_bytes(), password=None)

    def public_pem(self) -> str:
        return self._key.public_key().public_bytes(serialization.Encoding.PEM,
                                                   serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii")

    def sign(self, payload: bytes) -> bytes:
        return self._key.sign(payload)


def signer(key_dir: Path | None = None):
    """ML-DSA-65 when possible; Ed25519 otherwise (or when `VERA_SIGNING=ed25519`)."""
    key_dir = key_dir or KEY_DIR
    openssl = None if os.environ.get("VERA_SIGNING", "").lower() == "ed25519" else find_openssl()
    if openssl:
        try:
            return _MLDSA(openssl, key_dir)
        except RuntimeError:
            pass  # the OpenSSL build lacks ML-DSA key generation; the fallback is labelled below
    return _Ed25519(key_dir)


def _der_of(pem: str) -> bytes:
    body = "".join(line for line in pem.strip().splitlines() if not line.startswith("-----"))
    return base64.b64decode(body)


# --------------------------------------------------------------------------
# Manifest
# --------------------------------------------------------------------------


def build(*, scan: dict, inputs: list[dict], cbom_text: str, sarif_text: str, threat_model: dict,
          profile: str, policy: dict, created_at: str) -> dict:
    """The unsigned manifest for one scan."""
    return {
        "manifest_version": 1,
        "tool": TOOL_NAME,
        "tool_version": TOOL_VERSION,
        "threat_model_version": threat_model["version"],
        "resources_table_hash": threat_model["resources_table_hash"],
        "profile": profile,
        "policy_sha256": sha256_hex(canonical(policy)),
        "scan": scan,
        "inputs": sorted(inputs, key=lambda i: (i.get("collector", ""), i.get("target", ""))),
        "cbom_sha256": sha256_hex(cbom_text),
        "sarif_sha256": sha256_hex(sarif_text),
        "created_at": created_at,
    }


def sign(manifest: dict, key_dir: Path | None = None) -> dict:
    unsigned = {k: v for k, v in manifest.items() if k != "signature"}
    backend = signer(key_dir)
    pem = backend.public_pem()
    signature = backend.sign(canonical(unsigned))
    return {**unsigned, "signature": {
        "alg": backend.alg, "provider": backend.provider,
        "public_key_sha256": sha256_hex(_der_of(pem)), "public_key_pem": pem,
        "value": base64.b64encode(signature).decode("ascii"),
    }}


def verify(manifest: dict, trusted_public_pem: str | None = None) -> dict:
    """{valid, alg, reason, key_trusted}. Tampering with any signed byte gives valid=False."""
    block = manifest.get("signature") or {}
    alg, pem, value = block.get("alg"), block.get("public_key_pem"), block.get("value")
    if not (alg and pem and value):
        return {"valid": False, "alg": alg, "reason": "manifest is not signed", "key_trusted": False}
    try:
        signature = base64.b64decode(value, validate=True)
        der = _der_of(pem)
    except (ValueError, TypeError):
        return {"valid": False, "alg": alg, "reason": "signature or public key is not valid base64",
                "key_trusted": False}
    if sha256_hex(der) != block.get("public_key_sha256"):
        return {"valid": False, "alg": alg, "reason": "public key does not match its recorded hash",
                "key_trusted": False}
    payload = canonical({k: v for k, v in manifest.items() if k != "signature"})
    trusted = trusted_public_pem is not None and _der_of(trusted_public_pem) == der

    if alg == ED25519:
        key = serialization.load_der_public_key(der)
        if not isinstance(key, Ed25519PublicKey):
            return {"valid": False, "alg": alg, "reason": "public key is not Ed25519", "key_trusted": False}
        try:
            key.verify(signature, payload)
        except InvalidSignature:
            return {"valid": False, "alg": alg, "reason": "signature does not match the manifest",
                    "key_trusted": trusted}
        return {"valid": True, "alg": alg, "reason": "signature verified", "key_trusted": trusted}

    if alg == ML_DSA:
        openssl = find_openssl()
        if openssl is None:
            return {"valid": False, "alg": alg, "reason": "cannot verify ML-DSA-65 here: no OpenSSL 3.5+ found",
                    "key_trusted": trusted, "verifiable_here": False}
        with tempfile.TemporaryDirectory() as tmp:
            data, sig, pub = Path(tmp) / "payload.bin", Path(tmp) / "sig.bin", Path(tmp) / "pub.pem"
            data.write_bytes(payload)
            sig.write_bytes(signature)
            pub.write_text(pem, encoding="ascii")
            result = _run(openssl, "pkeyutl", "-verify", "-pubin", "-inkey", str(pub), "-rawin",
                          "-in", str(data), "-sigfile", str(sig))
        if result.returncode == 0:
            return {"valid": True, "alg": alg, "reason": "signature verified", "key_trusted": trusted}
        return {"valid": False, "alg": alg, "reason": "signature does not match the manifest",
                "key_trusted": trusted}

    return {"valid": False, "alg": alg, "reason": f"unknown signature algorithm {alg!r}", "key_trusted": False}


def local_public_key(key_dir: Path | None = None) -> dict:
    backend = signer(key_dir)
    pem = backend.public_pem()
    return {"alg": backend.alg, "provider": backend.provider, "public_key_pem": pem,
            "public_key_sha256": sha256_hex(_der_of(pem))}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m engine.manifest")
    sub = parser.add_subparsers(dest="command", required=True)
    check = sub.add_parser("verify", help="verify a signed manifest")
    check.add_argument("manifest")
    check.add_argument("--public-key", help="PEM of the key you trust (defaults to this host's key)")
    args = parser.parse_args(argv)
    manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
    trusted = Path(args.public_key).read_text(encoding="ascii") if args.public_key else \
        local_public_key()["public_key_pem"]
    result = verify(manifest, trusted)
    print(json.dumps(result, indent=2))
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    sys.exit(main())
