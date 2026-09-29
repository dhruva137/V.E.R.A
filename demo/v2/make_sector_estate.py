"""Generate a realistic estate for one sector.

    python demo/v2/make_sector_estate.py payments 400

Writes demo/v2/<sector>_estate.csv, importable through Discovery -> CSV import.

The shape of each estate is taken from the sector profile's declared
composition (backend/engine/profiles.py), so a payments estate really is
HSM-heavy and an industrial one really is dominated by device identities. The
generator does not invent proportions; it reads the ones the product will be
judged against, which is what makes the demo honest rather than staged.

Everything produced is synthetic. No host, path, serial or key here is real.
"""

from __future__ import annotations

import csv
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "backend"))

from engine.profiles import PROFILES  # noqa: E402

# Algorithms a class realistically uses, with the legacy tail that always
# survives in a real estate. Post-quantum entries carry their FIPS parameter
# set (ML-KEM-768, not bare "ML-KEM"): the taxonomy treats an unqualified
# name as underspecified and refuses to call it quantum-safe, which is
# correct and which this generator must respect rather than work around.
ALGORITHMS = {
    "payment_hsm": [("RSA", 2048, 0.55), ("RSA", 4096, 0.2), ("3DES", 112, 0.15), ("ECDSA", 256, 0.1)],
    "root_ca": [("RSA", 4096, 0.6), ("ECDSA", 384, 0.4)],
    "issuing_ca": [("RSA", 2048, 0.6), ("ECDSA", 256, 0.4)],
    "code_signing": [("RSA", 3072, 0.5), ("ECDSA", 256, 0.5)],
    "firmware_signing": [("RSA", 2048, 0.6), ("ECDSA", 256, 0.4)],
    "device_identity": [("ECDSA", 256, 0.6), ("RSA", 2048, 0.4)],
    "token_signing": [("RSA", 2048, 0.7), ("ECDSA", 256, 0.3)],
    "tls_certificate": [("RSA", 2048, 0.55), ("ECDSA", 256, 0.35), ("ML-DSA-65", 0, 0.10)],
    "tls_key_exchange": [("ECDHE", 256, 0.7), ("X25519", 255, 0.2), ("ML-KEM-768", 0, 0.10)],
    "database_tls": [("RSA", 2048, 0.7), ("ECDSA", 256, 0.3)],
    "vpn_ipsec": [("DH", 2048, 0.5), ("ECDHE", 256, 0.5)],
    "backup_encryption": [("RSA", 2048, 0.6), ("AES", 256, 0.4)],
    "config": [("RSA", 2048, 0.5), ("ECDHE", 256, 0.5)],
    "source": [("SHA-256", 256, 0.6), ("MD5", 128, 0.2), ("SHA-1", 160, 0.2)],
    "ssh_key": [("RSA", 2048, 0.6), ("Ed25519", 255, 0.4)],
    "generic_key": [("RSA", 2048, 0.7), ("AES", 256, 0.3)],
}

HOSTS = {
    "payments": ["switch", "acquirer-gw", "tokenvault", "settlement", "issuer-api"],
    "banking": ["corebank", "netbanking", "swift-gw", "treasury", "archive"],
    "erp": ["s4hana", "bw", "solman", "pi-po", "fiori"],
    "saas": ["api", "web", "worker", "ingest", "billing"],
    "industrial": ["plc-gw", "scada", "historian", "mes", "edge"],
    "healthcare": ["ehr", "pacs", "lab-if", "hl7-gw", "portal"],
    "telecom": ["hss", "pcrf", "ims-core", "roaming-gw", "oss"],
    "energy": ["substation", "rtu-gw", "ems", "meter-hub", "scada"],
    "government": ["portal", "identity", "records", "interagency", "archive"],
}

ENVIRONMENTS = [("production", 0.7), ("staging", 0.2), ("dr", 0.1)]


def weighted(rng, options):
    total = sum(w for *_, w in options)
    roll = rng.uniform(0, total)
    upto = 0.0
    for *value, weight in options:
        upto += weight
        if roll <= upto:
            return value
    return list(options[-1][:-1])


def build(sector: str, count: int, seed: int = 20260828) -> list[dict]:
    profile = PROFILES[sector]
    rng = random.Random(seed + len(sector))
    hosts = HOSTS.get(sector, HOSTS["saas"])

    # Draw asset classes in the proportions the profile declares.
    classes = list(profile.composition.items())
    weights = [w for _, w in classes]
    names = [c for c, _ in classes]

    rows = []
    for index in range(count):
        asset_class = rng.choices(names, weights=weights, k=1)[0]
        algorithm, key_size = weighted(rng, ALGORITHMS.get(asset_class, ALGORITHMS["generic_key"]))
        host = rng.choice(hosts)
        env = weighted(rng, [(e, w) for e, w in ENVIRONMENTS])[0]

        # ~15% have no owner. That gap is deliberate: "nobody knows who owns
        # this key" is a real blocker and the product reports it.
        owner = "" if rng.random() < 0.15 else rng.choice([
            "Platform Engineering", "Payments Ops", "PKI Team", "Network Ops",
            "Application Security", "Infrastructure", "Data Platform",
        ])

        rows.append({
            "name": f"{host}-{index:04d}.{sector}.internal",
            "asset_class": asset_class,
            "algorithm": algorithm,
            "key_size": key_size or "",
            "source_type": {
                "config": "config", "source": "source",
            }.get(asset_class, "tls" if "tls" in asset_class else "keystore"),
            "hostname": f"{host}-{index:04d}.{sector}.internal",
            "environment": env,
            "owner": owner,
            "department": profile.label.split("/")[0].strip(),
        })
    return rows


def main() -> None:
    sector = sys.argv[1] if len(sys.argv) > 1 else "payments"
    count = int(sys.argv[2]) if len(sys.argv) > 2 else 400

    if sector not in PROFILES:
        raise SystemExit(f"Unknown sector {sector!r}. One of: {', '.join(PROFILES)}")

    rows = build(sector, count)
    out = Path(__file__).parent / f"{sector}_estate.csv"
    with out.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)

    classes: dict[str, int] = {}
    for row in rows:
        classes[row["asset_class"]] = classes.get(row["asset_class"], 0) + 1
    unowned = sum(1 for r in rows if not r["owner"])

    print(f"{out.name}: {len(rows)} assets, {unowned} unowned ({100*unowned//len(rows)}%)")
    for cls, n in sorted(classes.items(), key=lambda kv: -kv[1]):
        print(f"   {cls:20} {n:4}  {100*n/len(rows):5.1f}%")


if __name__ == "__main__":
    main()
