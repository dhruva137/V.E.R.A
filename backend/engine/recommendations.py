"""Recommendations: what to migrate each asset to, what it costs, who can fix it (PS clause iv).

For every asset the engine decides its *need* (key exchange in transit, key
transport at rest, high-volume signatures, long-lived signatures, symmetric,
hash, classically broken, library below its PQC release, key baked into an
artefact, or unresolved) and reads the target for the active profile from
`kb/recommendations.yaml`:

    commercial   NIST FIPS 203/204/205, hybrid first where it interoperates
    cnsa         CNSA 2.0 for sovereign / defence estates: ML-KEM-1024, ML-DSA-87,
                 LMS/XMSS for firmware; AES-128 and SHA-256 become upgrades

COST
----
Sizes are FIPS constants (engine/hybrid.py). Latency comes only from
`bench/pqc_bench.json`, which records the host, date and method of every
number; without it the recommendation says "not measured on this host".

WHO CAN FIX IT
--------------
    self_managed           the team migrates (code, configs, own keystores)
    vendor_firmware_gated  the HSM advertises no PQC mechanism: needs a firmware release
    provider_gated         the cloud KMS offers no PQC key for this usage
    third_party            a partner or SaaS endpoint outside the estate register
Gated items form registers, and each register gets a procurement clause
drafted for legal review.

A library below its PQC-capable release is a *prerequisite* for everything on
the same stack of the same system: Java code on a pre-1.79 Bouncy Castle, or a
TLS endpoint on OpenSSL 3.0, cannot use ML-KEM until the library is upgraded,
so those recommendations carry the upgrade as their first step.
"""

from __future__ import annotations

import json
import os
import re
from functools import lru_cache
from pathlib import Path

import yaml

from engine import hybrid

KB_PATH = Path(__file__).resolve().parent / "kb" / "recommendations.yaml"
BENCH_PATH = Path(__file__).resolve().parents[2] / "bench" / "pqc_bench.json"
PROFILES = ("commercial", "cnsa")
_LONG_LIVED = {"root_ca", "issuing_ca", "firmware_signing", "code_signing", "trust_store", "device_identity"}
_KEX_CLASSES = {"tls_key_exchange", "ssh_key_exchange", "vpn_ipsec"}
# Needs whose fix runs through a crypto library (and so can be blocked by one).
_MIGRATION_NEEDS = {"key_exchange", "kem_at_rest", "signature_high_volume", "signature_long_lived", "symmetric", "hash"}
_profile_override: dict[str, str] = {}


@lru_cache(maxsize=1)
def rules() -> dict:
    return yaml.safe_load(KB_PATH.read_text(encoding="utf-8"))


def active_profile() -> str:
    profile = _profile_override.get("profile") or os.environ.get("VERA_PROFILE", "commercial").strip().lower()
    if profile not in PROFILES:
        raise ValueError(f"VERA_PROFILE must be one of {PROFILES}, got {profile!r}")
    return profile


def set_profile(profile: str) -> str:
    if profile not in PROFILES:
        raise ValueError(f"profile must be one of {PROFILES}")
    _profile_override["profile"] = profile
    return profile


# --------------------------------------------------------------------------
# Need
# --------------------------------------------------------------------------


def behind(asset, profile: str | None = None) -> bool:
    """Needs a change, and that change cannot finish by the asset's DST milestone even if started today.

    Slack is computed for every asset, but it only means something for an asset
    that needs work. An AES-256 key in an HSM with negative slack has nothing
    to migrate, and counting it as behind overstated the estate.
    """
    return asset.slack_months < 0 and need_for(asset, profile or active_profile())[0] is not None


def need_for(asset, profile: str) -> tuple[str | None, str]:
    """(need, why) for one asset; need None means nothing to do."""
    d = asset.raw_details or {}
    if asset.asset_class == "embedded_private_key":
        return "secret_exposure", "A private-key marker was found inside a shipped artefact."
    if asset.asset_class == "crypto_library":
        if d.get("pqc_capable") is False:
            return "library_upgrade", d.get("pqc_reason", "Library predates native PQC.")
        if d.get("pqc_capable") is None:
            return "resolve_first", d.get("pqc_reason", "Library version or PQC support unknown.")
        return None, "Library already supports PQC natively."
    if asset.verdict == "unknown":
        return "resolve_first", asset.vulnerability_reason or "Algorithm not resolved."
    if asset.classically_broken:
        return "replace_now", asset.vulnerability_reason or "Classically broken."
    if asset.quantum_vulnerable:
        primitive = asset.primitive or ""
        suite = asset.suite_breakdown or {}
        if (asset.asset_class in _KEX_CLASSES or primitive in ("key-agree", "kem")
                or asset.usage == "key_exchange" or suite.get("key_exchange")):
            return "key_exchange", "Shor-exposed key establishment."
        if primitive == "pke" and asset.usage in ("encryption", "key_wrap"):
            return "kem_at_rest", "RSA key transport or encryption."
        if asset.asset_class in _LONG_LIVED:
            return "signature_long_lived", "Long-lived trust anchor or signing key."
        return "signature_high_volume", "Shor-exposed signature."
    canonical = (asset.algorithm or "").upper()
    if profile == "cnsa":
        for name, entry in rules().get("cnsa_upgrades", {}).items():
            if canonical == name.upper() or (name == "AES-128" and canonical == "AES" and asset.key_size == 128):
                return entry["need"], entry["reason"]
    if asset.grover_weakened and canonical.startswith("AES"):
        return "symmetric", "Grover-weakened key length."
    return None, "Already acceptable for the active profile."


# --------------------------------------------------------------------------
# Cost
# --------------------------------------------------------------------------


@lru_cache(maxsize=1)
def _bench_cached(mtime: float) -> dict | None:
    return json.loads(BENCH_PATH.read_text(encoding="utf-8"))


def bench() -> dict | None:
    if not BENCH_PATH.is_file():
        return None
    return _bench_cached(BENCH_PATH.stat().st_mtime)


_SIZE_NAMES = {"X25519MLKEM768": "X25519MLKEM768 (hybrid)"}


def cost_of(algorithm: str) -> dict:
    """FIPS sizes and measured latency for a target algorithm. Latency only if measured."""
    parts = ["ML-KEM-768", "X25519"] if algorithm == "X25519MLKEM768" else [algorithm]
    sizes = [vars(s) for s in hybrid.KEM_SIZES + hybrid.SIGNATURE_SIZES
             if s.name in (_SIZE_NAMES.get(algorithm, algorithm), algorithm)]
    record = bench()
    if not record or not record.get("measured"):
        return {"sizes": sizes, "latency": [], "latency_note": "Not measured on this host (run bench/pqc_bench.py)."}
    latency = [r for r in record["results"] if r["algorithm"] in parts]
    note = (f"Measured {record['measured_at']} on {record['host']['processor'] or record['host']['machine']} "
            f"with OpenSSL {record.get('tool', {}).get('version', '?')}.") if latency else \
        "This algorithm was not in the benchmark run."
    return {"sizes": sizes, "latency": latency, "latency_note": note}


# --------------------------------------------------------------------------
# Who can fix it
# --------------------------------------------------------------------------


def _provider_of(asset) -> str | None:
    d = asset.raw_details or {}
    text = " ".join(str(d.get(k, "")) for k in ("Arn", "kid", "name", "KeyId")) + " " + (asset.source_location or "")
    if "arn:aws:kms" in text:
        return "aws"
    if "vault.azure.net" in text or "azure" in text.lower():
        return "azure"
    if "cryptoKeys" in text or "gcp" in text.lower() or "googleapis" in text:
        return "gcp"
    return None


def _kms_usage(asset) -> str:
    """Usage from whichever field the provider uses: AWS KeyUsage, Azure key_ops, GCP algorithm."""
    d = asset.raw_details or {}
    usage = " ".join(str(v) for v in (d.get("KeyUsage"), d.get("key_ops"), d.get("algorithm"), d.get("purpose"),
                                       d.get("key_spec"), asset.usage) if v).upper()
    if "SIGN" in usage:
        return "signing"
    if "AGREE" in usage:
        return "key_agreement"
    return "encryption"


def _observed(asset) -> bool:
    from engine.core.corroboration import plane_for

    d = asset.raw_details or {}
    return plane_for(str(d.get("discovered_by") or asset.source_type), asset.source_type) == "observed"


def ownership(asset) -> dict:
    """{key, owner, action} for one asset. Recorded facts only; the default is the team itself."""
    d = asset.raw_details or {}
    if d.get("ownership") in ("self_managed", "vendor_firmware_gated", "provider_gated", "third_party"):
        return {"key": d["ownership"], "owner": d.get("owner_name", ""), "action": "As recorded on the asset."}
    if d.get("change_blocked") or d.get("hsm_pqc_ready") is False:
        vendor = d.get("hsm_model") or d.get("hsm_token") or "HSM vendor"
        return {"key": "vendor_firmware_gated", "owner": vendor,
                "action": f"Request a firmware release with ML-KEM / ML-DSA mechanisms from the vendor of {vendor}.",
                "evidence": d.get("hsm_pqc_note") or "Token advertises no PQC mechanism."}
    provider = _provider_of(asset) if "cloud_kms" in str(d.get("discovered_by", "")) else None
    if provider and asset.quantum_vulnerable:
        entry = rules()["providers"].get(provider, {})
        usage = _kms_usage(asset)
        if not entry.get(usage):
            return {"key": "provider_gated", "owner": entry.get("name", provider),
                    "action": f"Ask {entry.get('name', provider)} for a post-quantum {usage.replace('_', ' ')} "
                              "key type and a date; track it in the contract.",
                    "evidence": f"No PQC {usage.replace('_', ' ')} key type is recorded for {entry.get('name', provider)} "
                                f"(status {entry.get('status', 'VERIFY')})."}
        return {"key": "self_managed", "owner": d.get("owner") or "Key owner",
                "action": f"Create a replacement key: {entry[usage]}.", "evidence": f"status {entry.get('status')}"}
    if _observed(asset) and not d.get("system"):
        return {"key": "third_party", "owner": asset.source_location,
                "action": "Outside the estate register: raise it with the partner or add the host to a system."}
    return {"key": "self_managed", "owner": d.get("system") or asset.owner or "Owning team",
            "action": "The owning team migrates it."}


# --------------------------------------------------------------------------
# Recommendations
# --------------------------------------------------------------------------


def _effort(asset) -> dict:
    years = float(asset.y or 0.0)
    label = ("configuration change" if years <= 0.5 else "one release cycle" if years <= 1.5
             else "multi-release programme")
    return {"years": round(years, 2), "label": label}


def recommend(asset, profile: str | None = None, prerequisites: dict[str, list[dict]] | None = None) -> dict | None:
    """The recommendation for one asset, or None when nothing needs doing."""
    profile = profile or active_profile()
    need, why = need_for(asset, profile)
    if need is None:
        return None
    rule = rules()["needs"][need]
    target = rule[profile]
    d = asset.raw_details or {}
    item = {
        "asset_id": asset.id,
        "asset": asset.name,
        "algorithm": asset.algorithm or asset.key_exchange or asset.cipher_suite or asset.protocol,
        "system": d.get("system"),
        "need": need,
        "need_label": rule["label"],
        "why": why,
        "profile": profile,
        "recommended": target["recommended"],
        "alternatives": list(target.get("alternatives", [])),
        "rationale": " ".join(rule["rationale"].split()),
        "citations": [dict(rules()["citations"][c], id=c) for c in rule.get("citations", [])],
        "effort": _effort(asset),
        "who_can_fix": ownership(asset),
        "classically_broken": bool(asset.classically_broken),
        "quantum_vulnerable": bool(asset.quantum_vulnerable),
        "mosca_category": asset.mosca_category,
        "priority_rank": asset.priority_rank,
    }
    if need == "library_upgrade":
        item["recommended"] = d.get("upgrade_path") or f"Upgrade {d.get('library', 'the library')}"
        item["upgrade_path"] = {"library": d.get("library"), "from": d.get("library_version"),
                                "to_at_least": d.get("pqc_native_from"), "evidence": d.get("evidence_refs", [])[:2],
                                "kb_status": d.get("kb_status")}
    elif need in ("key_exchange", "kem_at_rest", "signature_high_volume", "signature_long_lived", "symmetric"):
        item["cost"] = cost_of(str(target["recommended"]))
    key = f"{d.get('system')}|{asset_stack(asset)}"
    if prerequisites and key in prerequisites and need in _MIGRATION_NEEDS:
        item["prerequisites"] = prerequisites[key]
    return item


_ECOSYSTEM_STACK = {"pypi": "python", "npm": "javascript", "maven": "java", "go": "go", "cargo": "rust",
                    "nuget": "csharp", "composer": "php", "gem": "ruby"}
_RUNTIME_STACK = {"openjdk": "java", "go-stdlib": "go", "dotnet": "csharp"}


def library_stack(details: dict) -> str:
    """Which code a blocked library gates: a language, or 'native' for OpenSSL-class libraries."""
    if details.get("runtime"):
        return _RUNTIME_STACK.get(details.get("library_id", ""), "native")
    if details.get("linkage") == "bundled":          # a JAR inside a JAR / image
        return "java"
    return _ECOSYSTEM_STACK.get(details.get("ecosystem", ""), "native")


def asset_stack(asset) -> str:
    """Which stack an asset's cryptography runs on: its source language, else native (TLS, configs, binaries)."""
    d = asset.raw_details or {}
    if d.get("language"):
        return {"c": "native"}.get(d["language"], d["language"])
    if d.get("binary_format") == "jar":
        return "java"
    return "native"


def recommend_all(assets, profile: str | None = None) -> dict:
    """Every recommendation for an estate, with library prerequisites per system and stack."""
    profile = profile or active_profile()
    blockers: dict[str, list[dict]] = {}
    for asset in assets:
        d = asset.raw_details or {}
        if asset.asset_class == "crypto_library" and d.get("pqc_capable") is False and d.get("system"):
            steps = blockers.setdefault(f"{d['system']}|{library_stack(d)}", [])
            step = d.get("upgrade_path") or f"Upgrade {d.get('library')}"
            if all(s["step"] != step for s in steps):
                steps.append({
                    "step": step, "library": d.get("library"), "version": d.get("library_version"),
                    "stack": library_stack(d),
                    "why": "Code on this stack cannot use ML-KEM / ML-DSA until the library under it is upgraded.",
                })
    items = [r for r in (recommend(a, profile, blockers) for a in assets) if r]
    by_need: dict[str, int] = {}
    by_owner: dict[str, int] = {}
    for r in items:
        by_need[r["need"]] = by_need.get(r["need"], 0) + 1
        by_owner[r["who_can_fix"]["key"]] = by_owner.get(r["who_can_fix"]["key"], 0) + 1
    uncovered = [a.id for a in assets if a.quantum_vulnerable and not any(r["asset_id"] == a.id for r in items)]
    record = bench()
    return {"profile": profile, "items": items, "by_need": by_need, "by_owner": by_owner,
            "uncovered_vulnerable": uncovered, "prerequisites": blockers,
            "drafts": rules().get("drafts", {}),
            "bench": {"measured": bool(record and record.get("measured")),
                      "measured_at": record.get("measured_at") if record else None,
                      "host": record.get("host") if record else None}}


# --------------------------------------------------------------------------
# Gated registers and procurement clauses
# --------------------------------------------------------------------------


def gated_register(assets, profile: str | None = None) -> list[dict]:
    """Vendor- and provider-gated items, grouped by who has to act."""
    profile = profile or active_profile()
    groups: dict[tuple[str, str], dict] = {}
    for asset in assets:
        if not asset.quantum_vulnerable:
            continue
        owner = ownership(asset)
        if owner["key"] not in ("vendor_firmware_gated", "provider_gated"):
            continue
        need, _ = need_for(asset, profile)
        target = rules()["needs"][need][profile]["recommended"] if need else "a post-quantum mechanism"
        group = groups.setdefault((owner["key"], owner["owner"]), {
            "kind": owner["key"], "who": owner["owner"], "action": owner["action"], "evidence": owner.get("evidence"),
            "assets": [], "capabilities": set(), "earliest_deadline": None,
        })
        group["assets"].append({"id": asset.id, "name": asset.name, "algorithm": asset.algorithm,
                                "deadline": asset.statutory_deadline_year, "priority_rank": asset.priority_rank})
        group["capabilities"].add(str(target))
        deadline = asset.statutory_deadline_year
        if deadline and (group["earliest_deadline"] is None or deadline < group["earliest_deadline"]):
            group["earliest_deadline"] = deadline
    out = []
    for group in sorted(groups.values(), key=lambda g: (g["kind"], g["who"])):
        group["capabilities"] = sorted(group["capabilities"])
        group["count"] = len(group["assets"])
        out.append(group)
    return out


def procurement_clauses(assets, organisation: str = "the Customer", profile: str | None = None) -> list[dict]:
    """Plain-language clause drafts per gated supplier. Drafts for legal review, not legal text."""
    clauses = []
    for group in gated_register(assets, profile):
        by_year = (group["earliest_deadline"] - 1) if group["earliest_deadline"] else None
        date = f"31 December {by_year}" if by_year else "a date agreed in writing"
        capabilities = ", ".join(c for c in group["capabilities"] if re.search(r"ML-|SLH|LMS|X25519MLKEM", c)) \
            or "NIST-standardised post-quantum algorithms (FIPS 203, 204, 205)"
        product = "the hardware security modules" if group["kind"] == "vendor_firmware_gated" else "the key management service"
        text = (f"{group['who']} (the Supplier) shall make available for {product} supplied to {organisation} "
                f"support for {capabilities}, as specified in NIST FIPS 203, FIPS 204 and FIPS 205, no later than "
                f"{date}. Until then the Supplier shall publish a dated roadmap for this support and notify "
                f"{organisation} within 30 days of any change to it. With each release the Supplier shall provide a "
                "Cryptographic Bill of Materials (CycloneDX 1.6 or later) listing the algorithms, key sizes and "
                "protocols the product uses.")
        clauses.append({
            "supplier": group["who"], "kind": group["kind"], "affects": group["count"],
            "capabilities": group["capabilities"], "deadline_basis": (
                f"One year before the earliest statutory milestone ({group['earliest_deadline']}) of the affected "
                "assets, to leave time to migrate after delivery." if by_year else "No statutory milestone recorded."),
            "clause": text, "status": "DRAFT FOR LEGAL REVIEW",
            "citations": [dict(rules()["citations"]["dst2026"], id="dst2026"),
                          dict(rules()["citations"]["fips203"], id="fips203")],
            "note": ("The DST task force report (Annexure C) asks organisations to start requesting CBOMs and a "
                     "quantum-resiliency roadmap from vendors in FY 2026-27, and to mandate CBOM submission through "
                     "procurement policy from FY 2027-28."),
        })
    return clauses
