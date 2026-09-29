"""Measure post-quantum and classical primitive latency on this machine.

    python bench/pqc_bench.py [--seconds 1.0] [--openssl PATH]  ->  bench/pqc_bench.json

WHAT IS MEASURED, AND HOW
-------------------------
Everything needs an OpenSSL of 3.5 or later (ML-KEM, ML-DSA, SLH-DSA). The
script looks for one at --openssl, then $VERA_OPENSSL, then on PATH, and
records which binary and library version it used.

    KEM + classical baselines   `openssl speed` (ML-KEM-512/768/1024, X25519, ECDH P-256,
                                ECDSA P-256, Ed25519, RSA-2048)
    ML-DSA, SLH-DSA             the same OpenSSL's libcrypto through ctypes, because
                                `openssl speed` in 3.5.x cannot initialise ML-DSA signing;
                                one keygen, then sign and verify in a timed loop

Every number carries its method, iteration count and wall time. If no OpenSSL
3.5+ is found, the output says "not measured on this host" and holds **no
timings at all**: a latency is never estimated, copied or defaulted.

Sizes are not measured: they are FIPS 203/204/205 constants and come from
backend/engine/hybrid.py.
"""

from __future__ import annotations

import argparse
import ctypes
import datetime as dt
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
OUT = HERE / "pqc_bench.json"
SPEED_ALGORITHMS = ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024", "ecdhx25519", "ecdhp256", "ecdsap256",
                    "ed25519", "rsa2048"]
SIGNATURE_ALGORITHMS = ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87", "SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128f"]


def find_openssl(explicit: str | None) -> tuple[str, tuple[int, ...]] | None:
    for candidate in (explicit, os.environ.get("VERA_OPENSSL"), shutil.which("openssl")):
        if not candidate:
            continue
        try:
            out = subprocess.run([candidate, "version"], capture_output=True, text=True, timeout=10).stdout
        except (OSError, subprocess.TimeoutExpired):
            continue
        m = re.search(r"OpenSSL (\d+)\.(\d+)\.(\d+)", out)
        if m:
            version = tuple(int(x) for x in m.groups())
            if version >= (3, 5, 0):
                return candidate, version
    return None


def _per_op(rate: float) -> float:
    return round(1_000_000.0 / rate, 2) if rate > 0 else 0.0


def run_speed(binary: str, seconds: float) -> list[dict]:
    """Parse `openssl speed` tables into per-operation rates."""
    cmd = [binary, "speed", "-seconds", str(max(int(seconds), 1)), *SPEED_ALGORITHMS]
    text = subprocess.run(cmd, capture_output=True, text=True, timeout=600).stdout
    results = []

    def add(algorithm, operation, rate):
        results.append({"algorithm": algorithm, "operation": operation, "per_second": round(float(rate), 1),
                        "microseconds": _per_op(float(rate)), "method": "openssl speed",
                        "command": " ".join(cmd[1:])})

    for line in text.splitlines():
        m = re.match(r"\s*(ML-KEM-\d+)\s+\S+s\s+\S+s\s+\S+s\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)", line)
        if m:
            add(m.group(1), "keygen", m.group(2))
            add(m.group(1), "encapsulate", m.group(3))
            add(m.group(1), "decapsulate", m.group(4))
            continue
        m = re.match(r"\s*rsa\s+2048 bits\s+\S+s\s+\S+s\s+\S+s\s+\S+s\s+([\d.]+)\s+([\d.]+)", line)
        if m:
            add("RSA-2048", "sign", m.group(1))
            add("RSA-2048", "verify", m.group(2))
            continue
        m = re.match(r"\s*256 bits ecdsa \(nistp256\)\s+\S+s\s+\S+s\s+([\d.]+)\s+([\d.]+)", line)
        if m:
            add("ECDSA P-256", "sign", m.group(1))
            add("ECDSA P-256", "verify", m.group(2))
            continue
        m = re.match(r"\s*\d+ bits ecdh \((nistp256|X25519)\)\s+\S+s\s+([\d.]+)", line)
        if m:
            add("X25519" if m.group(1) == "X25519" else "ECDH P-256", "derive", m.group(2))
            continue
        m = re.match(r"\s*253 bits EdDSA \(Ed25519\)\s+\S+s\s+\S+s\s+([\d.]+)\s+([\d.]+)", line)
        if m:
            add("Ed25519", "sign", m.group(1))
            add("Ed25519", "verify", m.group(2))
    return results


def _libcrypto_for(binary: str) -> ctypes.CDLL | None:
    """The libcrypto that ships next to the OpenSSL binary, if it is 3.5+."""
    bindir = Path(binary).resolve().parent
    names = sorted(bindir.glob("libcrypto-3*.dll")) + sorted(bindir.glob("libcrypto.so.3*")) + \
        sorted((bindir.parent / "lib").glob("libcrypto.so.3*")) + sorted((bindir.parent / "lib64").glob("libcrypto.so.3*"))
    for path in names:
        try:
            if sys.platform == "win32":
                os.add_dll_directory(str(path.parent))
            lib = ctypes.CDLL(str(path))
        except OSError:
            continue
        lib.OpenSSL_version.restype = ctypes.c_char_p
        lib.OpenSSL_version.argtypes = [ctypes.c_int]
        m = re.search(rb"OpenSSL (\d+)\.(\d+)", lib.OpenSSL_version(0))
        if m and (int(m.group(1)), int(m.group(2))) >= (3, 5):
            return lib
    return None


def run_signatures(binary: str, seconds: float) -> tuple[list[dict], list[str]]:
    lib = _libcrypto_for(binary)
    if lib is None:
        return [], [f"{a}: no OpenSSL 3.5+ libcrypto next to {binary}" for a in SIGNATURE_ALGORITHMS]
    vp, sz = ctypes.c_void_p, ctypes.c_size_t
    lib.EVP_PKEY_CTX_new_from_name.restype = vp
    lib.EVP_PKEY_CTX_new_from_name.argtypes = [vp, ctypes.c_char_p, ctypes.c_char_p]
    lib.EVP_PKEY_keygen_init.argtypes = [vp]
    lib.EVP_PKEY_generate.argtypes = [vp, ctypes.POINTER(vp)]
    lib.EVP_PKEY_CTX_free.argtypes = [vp]
    lib.EVP_PKEY_free.argtypes = [vp]
    lib.EVP_MD_CTX_new.restype = vp
    lib.EVP_MD_CTX_free.argtypes = [vp]
    lib.EVP_DigestSignInit_ex.argtypes = [vp, vp, ctypes.c_char_p, vp, ctypes.c_char_p, vp, vp]
    lib.EVP_DigestSign.argtypes = [vp, ctypes.c_char_p, ctypes.POINTER(sz), ctypes.c_char_p, sz]
    lib.EVP_DigestVerifyInit_ex.argtypes = [vp, vp, ctypes.c_char_p, vp, ctypes.c_char_p, vp, vp]
    lib.EVP_DigestVerify.argtypes = [vp, ctypes.c_char_p, sz, ctypes.c_char_p, sz]

    message = b"VERA benchmark message: 32 bytes."
    results, skipped = [], []
    for algorithm in SIGNATURE_ALGORITHMS:
        ctx = lib.EVP_PKEY_CTX_new_from_name(None, algorithm.encode(), None)
        pkey = vp()
        if not ctx or lib.EVP_PKEY_keygen_init(ctx) != 1 or lib.EVP_PKEY_generate(ctx, ctypes.byref(pkey)) != 1:
            skipped.append(f"{algorithm}: key generation unavailable in this OpenSSL")
            if ctx:
                lib.EVP_PKEY_CTX_free(ctx)
            continue
        lib.EVP_PKEY_CTX_free(ctx)

        def sign_once() -> bytes:
            md = lib.EVP_MD_CTX_new()
            try:
                if lib.EVP_DigestSignInit_ex(md, None, None, None, None, pkey, None) != 1:
                    raise RuntimeError("sign init failed")
                length = sz(0)
                lib.EVP_DigestSign(md, None, ctypes.byref(length), message, len(message))
                buf = ctypes.create_string_buffer(length.value)
                if lib.EVP_DigestSign(md, buf, ctypes.byref(length), message, len(message)) != 1:
                    raise RuntimeError("sign failed")
                return buf.raw[: length.value]
            finally:
                lib.EVP_MD_CTX_free(md)

        def verify_once(signature: bytes) -> None:
            md = lib.EVP_MD_CTX_new()
            try:
                if lib.EVP_DigestVerifyInit_ex(md, None, None, None, None, pkey, None) != 1:
                    raise RuntimeError("verify init failed")
                if lib.EVP_DigestVerify(md, signature, len(signature), message, len(message)) != 1:
                    raise RuntimeError("verify failed")
            finally:
                lib.EVP_MD_CTX_free(md)

        try:
            signature = sign_once()
            for operation, fn in (("sign", sign_once), ("verify", lambda: verify_once(signature))):
                count, start = 0, time.perf_counter()
                while time.perf_counter() - start < seconds:
                    fn()
                    count += 1
                elapsed = time.perf_counter() - start
                rate = count / elapsed
                results.append({"algorithm": algorithm, "operation": operation, "per_second": round(rate, 1),
                                "microseconds": _per_op(rate), "method": "libcrypto via ctypes (includes per-call context set-up)",
                                "iterations": count, "seconds": round(elapsed, 3),
                                "signature_bytes": len(signature)})
        except RuntimeError as exc:
            skipped.append(f"{algorithm}: {exc}")
        finally:
            lib.EVP_PKEY_free(pkey)
    return results, skipped


def host_record() -> dict:
    return {"platform": platform.platform(), "machine": platform.machine(), "processor": platform.processor(),
            "cpu_count": os.cpu_count(), "python": platform.python_version()}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--seconds", type=float, default=1.0)
    parser.add_argument("--openssl")
    parser.add_argument("--out", default=str(OUT))
    args = parser.parse_args(argv)

    record = {"measured_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
              "host": host_record(), "results": [], "not_measured": []}
    found = find_openssl(args.openssl)
    if found is None:
        record["measured"] = False
        record["note"] = "Not measured on this host: no OpenSSL 3.5 or later was found. No timings are reported."
    else:
        binary, version = found
        record["measured"] = True
        record["tool"] = {"openssl": binary, "version": ".".join(map(str, version))}
        record["results"].extend(run_speed(binary, args.seconds))
        signatures, skipped = run_signatures(binary, args.seconds)
        record["results"].extend(signatures)
        record["not_measured"].extend(skipped)
    Path(args.out).write_text(json.dumps(record, indent=2), encoding="utf-8")
    print(f"{len(record['results'])} measurements written to {args.out}"
          + (f"; not measured: {len(record['not_measured'])}" if record["not_measured"] else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
