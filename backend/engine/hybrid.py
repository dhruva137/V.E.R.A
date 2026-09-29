"""M8 - Hybrid harness and PQC benchmarks.

Two jobs.

**Migration harness.** Flip a service (or the whole estate) to hybrid or
PQC-only crypto, rescore, and report the before/after. This backs the 4:15 demo
beat - migrate, rescan, watch the score drop - without needing a live PQC
endpoint.

**Size benchmarks.** The operational story of this migration is not the word
"quantum-safe", it is that an X25519 key share is 32 bytes and an ML-KEM-768
encapsulation key is 1184. Certificate chains grow by kilobytes. That is what
breaks MTU assumptions, embedded flash budgets and smartcard buffers.

PROVENANCE
----------
Every size below is a **fixed constant defined by the standard**, not a
measurement: FIPS 203 Table 3 (ML-KEM), FIPS 204 Table 2 (ML-DSA), FIPS 205
(SLH-DSA), RFC 7748 (X25519), SEC 1 (P-256). They are exact and independently
checkable, which is why sizes carry the demo rather than latency.

Latency is deliberately NOT fabricated. The local OpenSSL is 3.0.x, which has
no ML-KEM, so a hybrid handshake cannot be measured on this machine. The
harness measures real classical handshake latency against a live endpoint where
one is reachable, and labels every PQC latency figure as a published reference
value with its source. `measurement_status` says which is which, so a reader is
never left guessing.
"""

from __future__ import annotations

import socket
import ssl
import statistics
import time
from dataclasses import asdict, dataclass

from engine.qirs import DEFAULT_W_H, DEFAULT_W_T, compute_hndl, compute_qirs, compute_qirs_band, compute_tnfl
from engine.regulatory import compute_slack
from engine.threat_model import ThreatModel
from models.schemas import CryptoAsset


@dataclass(frozen=True)
class AlgorithmSizes:
    name: str
    category: str  # kem | signature
    public_key_bytes: int
    private_key_bytes: int
    # KEM: ciphertext. Signature: signature length.
    payload_bytes: int
    payload_label: str
    nist_level: int | None
    standard: str
    quantum_safe: bool


# FIPS 203 Table 3; FIPS 204 Table 2; FIPS 205 Table 2; RFC 7748; SEC 1.
KEM_SIZES = [
    AlgorithmSizes("X25519", "kem", 32, 32, 32, "shared secret", None, "RFC 7748", False),
    AlgorithmSizes("P-256 ECDH", "kem", 65, 32, 32, "shared secret", None, "SEC 1 / FIPS 186-5", False),
    AlgorithmSizes("RSA-2048 transport", "kem", 256, 1190, 256, "ciphertext", None, "PKCS#1 v2.2", False),
    AlgorithmSizes("ML-KEM-512", "kem", 800, 1632, 768, "ciphertext", 1, "FIPS 203", True),
    AlgorithmSizes("ML-KEM-768", "kem", 1184, 2400, 1088, "ciphertext", 3, "FIPS 203", True),
    AlgorithmSizes("ML-KEM-1024", "kem", 1568, 3168, 1568, "ciphertext", 5, "FIPS 203", True),
    AlgorithmSizes(
        "X25519MLKEM768 (hybrid)", "kem", 1216, 2432, 1120, "ciphertext", 3,
        "draft-ietf-tls-ecdhe-mlkem (X25519 || ML-KEM-768)", True,
    ),
]

SIGNATURE_SIZES = [
    AlgorithmSizes("Ed25519", "signature", 32, 64, 64, "signature", None, "RFC 8032", False),
    AlgorithmSizes("ECDSA P-256", "signature", 65, 32, 72, "signature", None, "FIPS 186-5", False),
    AlgorithmSizes("RSA-2048", "signature", 256, 1190, 256, "signature", None, "FIPS 186-5", False),
    AlgorithmSizes("RSA-4096", "signature", 512, 2350, 512, "signature", None, "FIPS 186-5", False),
    AlgorithmSizes("ML-DSA-44", "signature", 1312, 2560, 2420, "signature", 2, "FIPS 204", True),
    AlgorithmSizes("ML-DSA-65", "signature", 1952, 4032, 3309, "signature", 3, "FIPS 204", True),
    AlgorithmSizes("ML-DSA-87", "signature", 2592, 4896, 4627, "signature", 5, "FIPS 204", True),
    AlgorithmSizes("SLH-DSA-SHA2-128s", "signature", 32, 64, 7856, "signature", 1, "FIPS 205", True),
    AlgorithmSizes("SLH-DSA-SHA2-128f", "signature", 32, 64, 17088, "signature", 1, "FIPS 205", True),
]

# Published reference latencies. These are NOT measured here and are labelled as
# such everywhere they surface. Order of magnitude only; the point is that
# lattice operations are cheap and the cost is bandwidth, not CPU.
REFERENCE_LATENCY_NOTE = (
    "Reference figures from the FIPS 203/204 reference implementations on a modern "
    "x86-64 core. Not measured on this machine: the local OpenSSL is 3.0.x, which "
    "does not implement ML-KEM, so a hybrid handshake cannot be benchmarked here. "
    "The operational cost of this migration is bytes on the wire, not CPU."
)

REFERENCE_LATENCY_US = [
    {"operation": "X25519 keygen + shared secret", "microseconds": 60, "quantum_safe": False},
    {"operation": "ML-KEM-768 keygen", "microseconds": 25, "quantum_safe": True},
    {"operation": "ML-KEM-768 encapsulate", "microseconds": 30, "quantum_safe": True},
    {"operation": "ML-KEM-768 decapsulate", "microseconds": 35, "quantum_safe": True},
    {"operation": "ECDSA P-256 sign", "microseconds": 40, "quantum_safe": False},
    {"operation": "ML-DSA-65 sign", "microseconds": 110, "quantum_safe": True},
    {"operation": "ML-DSA-65 verify", "microseconds": 45, "quantum_safe": True},
    {"operation": "RSA-2048 sign", "microseconds": 700, "quantum_safe": False},
]


def _size(name: str) -> AlgorithmSizes:
    for entry in KEM_SIZES + SIGNATURE_SIZES:
        if entry.name == name:
            return entry
    raise KeyError(name)


def handshake_size_comparison() -> dict:
    """Bytes on the wire for a classical versus a hybrid TLS 1.3 handshake.

    Counts the crypto-bearing fields only - key shares plus the certificate
    chain's public keys and signatures. It deliberately excludes the rest of the
    handshake, which does not change, so the delta is attributable.
    """
    classical_kex = _size("X25519")
    hybrid_kex = _size("X25519MLKEM768 (hybrid)")
    classical_sig = _size("RSA-2048")
    pqc_sig = _size("ML-DSA-65")

    # A typical chain: leaf + one intermediate, each carrying a public key and a
    # signature over it, plus the root's signature on the intermediate.
    chain_depth = 2

    def chain_bytes(sig: AlgorithmSizes) -> int:
        return chain_depth * (sig.public_key_bytes + sig.payload_bytes)

    classical = {
        "client_key_share": classical_kex.public_key_bytes,
        "server_key_share": classical_kex.payload_bytes,
        "certificate_chain": chain_bytes(classical_sig),
        "handshake_signature": classical_sig.payload_bytes,
    }
    hybrid = {
        "client_key_share": hybrid_kex.public_key_bytes,
        "server_key_share": hybrid_kex.payload_bytes,
        "certificate_chain": chain_bytes(pqc_sig),
        "handshake_signature": pqc_sig.payload_bytes,
    }

    classical_total = sum(classical.values())
    hybrid_total = sum(hybrid.values())

    rows = [
        {
            "field": label,
            "classical_bytes": classical[key],
            "pqc_bytes": hybrid[key],
            "delta_bytes": hybrid[key] - classical[key],
            "multiplier": round(hybrid[key] / classical[key], 1) if classical[key] else None,
        }
        for key, label in [
            ("client_key_share", "ClientHello key share"),
            ("server_key_share", "ServerHello key share"),
            ("certificate_chain", "Certificate chain (leaf + intermediate)"),
            ("handshake_signature", "CertificateVerify signature"),
        ]
    ]

    # 1500-byte Ethernet MTU less 40 bytes of IPv4 + TCP header.
    mtu_payload = 1460

    return {
        "classical_profile": "X25519 key exchange, RSA-2048 certificate chain",
        "pqc_profile": "X25519MLKEM768 hybrid key exchange, ML-DSA-65 certificate chain",
        "rows": rows,
        "classical_total_bytes": classical_total,
        "pqc_total_bytes": hybrid_total,
        "delta_bytes": hybrid_total - classical_total,
        "multiplier": round(hybrid_total / classical_total, 2),
        "mtu_note": (
            f"The classical handshake's crypto payload is {classical_total} bytes and fits "
            f"inside a single {mtu_payload}-byte TCP segment. The hybrid one is "
            f"{hybrid_total} bytes and spans {-(-hybrid_total // mtu_payload)} segments, "
            "so the handshake gains at least one extra round trip on a lossy link. This "
            "is the operational cost of the migration, and it is a network problem rather "
            "than a cryptography problem."
        ),
        "provenance": (
            "All sizes are constants fixed by FIPS 203, FIPS 204, RFC 7748 and SEC 1. "
            "Nothing here is estimated or measured."
        ),
    }


def benchmark_table() -> dict:
    """Full size table plus reference latencies, clearly separated."""
    return {
        "kem": [asdict(entry) for entry in KEM_SIZES],
        "signature": [asdict(entry) for entry in SIGNATURE_SIZES],
        "handshake": handshake_size_comparison(),
        "latency": {
            "measurement_status": "reference",
            "note": REFERENCE_LATENCY_NOTE,
            "openssl_version": ssl.OPENSSL_VERSION,
            "local_mlkem_support": _local_supports_mlkem(),
            "rows": REFERENCE_LATENCY_US,
        },
        "headline": (
            f"An X25519 key share is {_size('X25519').public_key_bytes} bytes. "
            f"An ML-KEM-768 encapsulation key is {_size('ML-KEM-768').public_key_bytes}. "
            f"That is {_size('ML-KEM-768').public_key_bytes // _size('X25519').public_key_bytes}x, "
            "and it is the part of this migration that actually breaks things."
        ),
    }


def _local_supports_mlkem() -> bool:
    """Whether the local OpenSSL can negotiate a hybrid group.

    ML-KEM landed in OpenSSL 3.5. Checking rather than assuming means the demo
    upgrades itself the moment it runs on a machine that has it.
    """
    try:
        context = ssl.create_default_context()
        context.set_ecdh_curve("X25519MLKEM768")
        return True
    except (ssl.SSLError, ValueError, AttributeError, NotImplementedError):
        return False


def measure_classical_handshake(host: str, port: int = 443, rounds: int = 3) -> dict:
    """Measure real TLS handshake latency against a live endpoint.

    This is a genuine measurement and is labelled as one. It exists so at least
    one number in the benchmark panel comes off the wire rather than out of a
    table.
    """
    from engine import offline

    offline.allow(host)  # the operator named this host for measurement
    samples: list[float] = []
    negotiated: dict = {}
    error: str | None = None

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    for _ in range(rounds):
        try:
            start = time.perf_counter()
            with socket.create_connection((host, port), timeout=6) as raw:
                with context.wrap_socket(raw, server_hostname=host) as tls:
                    samples.append((time.perf_counter() - start) * 1000.0)
                    if not negotiated:
                        cipher = tls.cipher()
                        negotiated = {
                            "protocol": tls.version(),
                            "cipher_suite": cipher[0] if cipher else None,
                        }
        except (OSError, ssl.SSLError) as exc:
            error = f"{type(exc).__name__}: {exc}"
            break

    if not samples:
        return {
            "measurement_status": "failed",
            "host": host,
            "error": error or "no samples collected",
        }

    return {
        "measurement_status": "measured",
        "host": host,
        "rounds": len(samples),
        "median_ms": round(statistics.median(samples), 2),
        "min_ms": round(min(samples), 2),
        "max_ms": round(max(samples), 2),
        "negotiated": negotiated,
        "note": (
            "Full TCP connect plus TLS handshake, measured now against a live public "
            "endpoint. Includes network round trips, so it is dominated by distance "
            "rather than by cryptography - which is the point: the CPU cost of the "
            "algorithms is not what a migration will notice."
        ),
    }


# --------------------------------------------------------------------------
# Migration harness
# --------------------------------------------------------------------------

# Needs whose fix is swapping one algorithm for another. The others (upgrade a
# library, rotate a leaked key, resolve an unknown call) are real work but not
# a swap, so the harness reports them instead of pretending to apply them.
_SWAP_NEEDS = {"key_exchange", "kem_at_rest", "signature_high_volume", "signature_long_lived", "symmetric",
               "hash", "replace_now"}
_TLS13_SUITE = "TLS_AES_256_GCM_SHA384"


def _pqc_only(target: str) -> str:
    """The post-quantum half of a hybrid group: X25519MLKEM768 -> ML-KEM-768."""
    compact = target.upper().replace("-", "")
    for size in ("512", "768", "1024"):
        if compact.endswith(f"MLKEM{size}") and not compact.startswith("MLKEM"):
            return f"ML-KEM-{size}"
    return target


def replacement_for(asset: CryptoAsset, strategy: str = "hybrid", profile: str | None = None) -> dict:
    """What this asset becomes, taken from its own recommendation.

    One source of truth: the target is the one `engine.recommendations`
    gives for the asset's need under the active profile (NIST or CNSA 2.0),
    so the simulation, the assistant's preview and the Plan screen name the
    same algorithm. An earlier class table turned an ECDSA signing key into
    ML-KEM-768, a key-exchange mechanism. Returns {replacement, field, need,
    reason}; replacement is None when the fix is not an algorithm swap.
    """
    from engine import recommendations

    rec = recommendations.recommend(asset, profile)
    if rec is None:
        return {"replacement": None, "field": "", "need": None, "reason": "Nothing to change under the active profile."}
    if rec["need"] not in _SWAP_NEEDS:
        return {"replacement": None, "field": "", "need": rec["need"],
                "reason": f"{rec['need_label']}: {rec['recommended']}. Not an algorithm swap, so it is not simulated."}
    target = str(rec["recommended"])
    if strategy == "pqc_only":
        target = _pqc_only(target)
    if asset.key_exchange or rec["need"] == "key_exchange" and not asset.algorithm:
        field = "key_exchange"
    elif asset.cipher_suite and asset.asset_class == "tls_cipher_suite":
        field = "cipher_suite"
    else:
        field = "algorithm"
    return {"replacement": target, "field": field, "need": rec["need"], "reason": rec["why"],
            "who_can_fix": rec["who_can_fix"]}


def _select(assets: list[CryptoAsset], target: str, asset_classes: list[str]) -> list[CryptoAsset]:
    selected = []
    for asset in assets:
        if not asset.quantum_vulnerable:
            continue
        if target and target.lower() not in asset.source_location.lower():
            continue
        if asset_classes and asset.asset_class not in asset_classes:
            continue
        selected.append(asset)
    return selected


def migrate(
    assets: list[CryptoAsset],
    threat_model: ThreatModel,
    target: str = "",
    asset_classes: list[str] | None = None,
    strategy: str = "hybrid",
) -> dict:
    """Migrate matching assets in place and report the before/after.

    Rescoring runs the same code path as the original scan - the assets are
    reclassified through the taxonomy after their algorithm is swapped, not
    given a hand-written lower score. If the swap did not genuinely change the
    classification, the score would not move.
    """
    from engine import recommendations  # local imports avoid cycles
    from engine.qirs import classify_asset

    selected = _select(assets, target, asset_classes or [])
    if not selected:
        return {
            "migrated": 0,
            "message": (
                f"No quantum-vulnerable assets matched target {target!r}."
                if target
                else "No quantum-vulnerable assets matched."
            ),
            "changes": [],
        }

    before = {
        "assets": len(selected),
        "avg_qirs": round(sum(a.qirs for a in selected) / len(selected), 6),
        "avg_hndl": round(sum(a.h_score for a in selected) / len(selected), 6),
        "avg_tnfl": round(sum(a.t_score for a in selected) / len(selected), 6),
        "max_qirs": round(max(a.qirs for a in selected), 6),
        "negative_slack": sum(1 for a in selected if recommendations.behind(a)),
        "quantum_vulnerable": sum(1 for a in selected if a.quantum_vulnerable),
    }

    changes = []
    skipped = []
    for asset in selected:
        # pqc_only drops the classical half of a hybrid: higher assurance against
        # Shor, but no fallback if the lattice assumption is ever weakened, which
        # is why hybrid is the transitional default.
        plan = replacement_for(asset, strategy)
        replacement, field = plan["replacement"], plan["field"]
        if replacement is None:
            skipped.append({"asset_id": asset.id, "name": asset.name, "need": plan["need"], "reason": plan["reason"]})
            continue

        original = asset.algorithm or asset.key_exchange or asset.cipher_suite
        asset.migrated = True
        asset.migrated_from = original

        if field == "key_exchange":
            asset.key_exchange = replacement
        elif field == "cipher_suite":
            asset.cipher_suite = _TLS13_SUITE
            asset.key_exchange = replacement
        else:
            asset.algorithm = replacement
            asset.key_size = None

        # Re-run the real classifier, then rescore.
        classify_asset(asset)
        asset.h_score = compute_hndl(asset, threat_model)
        asset.t_score = compute_tnfl(asset, threat_model)
        asset.qirs = compute_qirs(asset.h_score, asset.t_score, DEFAULT_W_H, DEFAULT_W_T)
        asset.qirs_low, asset.qirs_high = compute_qirs_band(asset, threat_model)
        asset.slack_months = compute_slack(asset.statutory_deadline_year, asset.y)

        changes.append(
            {
                "asset_id": asset.id,
                "name": asset.name,
                "from": original,
                "to": replacement,
                "qirs_after": asset.qirs,
                "still_vulnerable": asset.quantum_vulnerable,
            }
        )

    after = {
        "assets": len(selected),
        "avg_qirs": round(sum(a.qirs for a in selected) / len(selected), 6),
        "avg_hndl": round(sum(a.h_score for a in selected) / len(selected), 6),
        "avg_tnfl": round(sum(a.t_score for a in selected) / len(selected), 6),
        "max_qirs": round(max(a.qirs for a in selected), 6),
        "negative_slack": sum(1 for a in selected if recommendations.behind(a)),
        "quantum_vulnerable": sum(1 for a in selected if a.quantum_vulnerable),
    }

    return {
        "migrated": len(changes),
        "skipped": skipped,
        "target": target or "entire estate",
        "strategy": strategy,
        "before": before,
        "after": after,
        "qirs_reduction": round(before["avg_qirs"] - after["avg_qirs"], 6),
        "qirs_reduction_pct": (
            round((before["avg_qirs"] - after["avg_qirs"]) / before["avg_qirs"] * 100, 1)
            if before["avg_qirs"]
            else 0.0
        ),
        "wire_cost": handshake_size_comparison(),
        "changes": changes[:50],
        "message": (
            f"Migrated {len(changes)} of {len(selected)} selected assets to {strategy}"
            + (f"; {len(skipped)} need work that is not an algorithm swap" if skipped else "")
            + f". Average QIRS fell from {before['avg_qirs']:.4f} to {after['avg_qirs']:.4f}. Scores were "
            "recomputed by re-running the classifier over the new algorithms, not by applying a discount."
        ),
    }
