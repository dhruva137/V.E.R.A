"""Generate a large, realistically-shaped enterprise estate as CSV.

WHY A GENERATOR RATHER THAN A FIXTURE
-------------------------------------
A thousand hand-written rows would be a thousand rows of the same few patterns,
and the interesting property of a real estate is not its size - it is its
*shape*. Real inventories are dominated by a small number of repeated
configurations: a bank with 114,000 certificates does not have 114,000 distinct
cryptographic setups, it has a few dozen, deployed many thousands of times.

That shape is what this reproduces, and it is also what makes the estate cheap
to score: the six QIRS inputs come from ~17 policy templates, so a large estate
collapses to a few hundred distinct scoring problems regardless of row count.

COMPOSITION
-----------
Proportions follow reported enterprise practice rather than being invented:

  - TLS dominates. Most certificates are ordinary service endpoints.
  - A handful of CAs sit above thousands of leaf certificates - the trust
    concentration that makes forgery risk matter.
  - Long-lived signing keys (firmware, code) are rare but carry the worst
    migration timelines: HSM fleets run 10-20 year replacement cycles and no
    major vendor shipped GA post-quantum support as of mid-2025.
  - Roughly 15% of assets have no owner. Reported practice is worse - 53% of
    organisations cannot precisely quantify their inventory at all.
  - A small tail of already-broken primitives (3DES, SHA-1, MD5) survives in
    legacy paths, because it always does.

Usage:
    python demo/make_large_estate.py            # 1,200 rows, default
    python demo/make_large_estate.py 10000      # any size
"""

from __future__ import annotations

import csv
import datetime
import random
import sys
from pathlib import Path

SEED = 20260824  # fixed: the same estate every run, so numbers in a demo repeat

OUT = Path(__file__).parent / "enterprise_estate_1200.csv"

ORG = "tejomaya"

# (weight, type, algorithm, bits, protocol, class-of-service)
#
# Weights are relative frequencies, not percentages. TLS endpoints dominate
# because they always do; the rare rows are rare on purpose.
MIX = [
    (340, "tls_certificate", "RSA", 2048, "TLSv1.2"),
    (180, "tls_key_exchange", "ECDHE", 256, "TLSv1.3"),
    (150, "tls_certificate", "ECDSA", 256, "TLSv1.3"),
    (95, "tls_cipher_suite", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", 256, "TLSv1.2"),
    (70, "tls_key_exchange", "X25519", 256, "TLSv1.3"),
    (60, "database_tls", "AES", 256, None),
    (55, "ssh_key", "RSA", 2048, None),
    (40, "token_signing", "RSA", 2048, None),
    (34, "backup_encryption", "AES", 256, None),
    (28, "device_identity", "ECDSA", 256, None),
    (24, "vpn_ipsec", "DH", 2048, None),
    (22, "config", "TLS_RSA_WITH_AES_128_CBC_SHA256", 128, "TLSv1.2"),
    (18, "source", "RSA", 2048, None),
    (14, "payment_hsm", "RSA", 2048, None),
    (10, "code_signing", "RSA", 3072, None),
    (8, "issuing_ca", "RSA", 3072, None),
    (6, "firmware_signing", "RSA", 3072, None),
    # The legacy tail. Small, and always present in a real estate.
    (9, "config", "3DES", 168, "TLSv1.0"),
    (5, "source", "SHA-1", 160, None),
    (4, "source", "MD5", 128, None),
    (3, "backup_encryption", "3DES", 168, None),
    # Already migrated - proves the scorer zeroes them rather than assuming
    # everything is broken.
    (12, "tls_key_exchange", "X25519MLKEM768", 256, "TLSv1.3"),
    (6, "code_signing", "ML-DSA-65", 256, None),
    (3, "root_ca", "RSA", 4096, None),
]

SUBSYSTEMS = [
    ("upi", "Payments", "payments-platform@%s.example" % ORG),
    ("npci", "Payments", "payments-platform@%s.example" % ORG),
    ("cards", "Cards", "cards-engineering@%s.example" % ORG),
    ("atm", "ATM Estate", "atm-engineering@%s.example" % ORG),
    ("corebank", "Core Banking", "corebank-ops@%s.example" % ORG),
    ("channels", "Digital Channels", "identity-team@%s.example" % ORG),
    ("infra", "Infrastructure", "platform-team@%s.example" % ORG),
    ("pki", "PKI", "pki-team@%s.example" % ORG),
    ("treasury", "Treasury", "treasury-tech@%s.example" % ORG),
    ("lending", "Lending", "lending-eng@%s.example" % ORG),
]

ENVIRONMENTS = [("production", 68), ("staging", 20), ("dr", 12)]

HOST_ROLES = [
    "api", "gw", "svc", "web", "app", "edge", "int", "batch", "rpt", "auth",
    "mq", "cache", "db", "etl", "portal", "admin", "sso", "notify",
]


def weighted(rng: random.Random, options: list[tuple]) -> tuple:
    total = sum(row[0] for row in options)
    pick = rng.uniform(0, total)
    running = 0.0
    for row in options:
        running += row[0]
        if pick <= running:
            return row
    return options[-1]


def cert_dates(rng: random.Random, asset_type: str) -> tuple[str, str]:
    """Validity window anchored on remaining life, not issue date.

    Anchoring on the issue date puts short-lived certificates in the past, which
    reads as stale fixture data. Anchoring on remaining life produces the
    distribution a real estate has: mostly healthy, a renewal cycle's worth in
    the warning window, a small number genuinely overdue.
    """
    today = datetime.date.today()
    validity = {
        "tls_certificate": 398,      # CA/Browser Forum maximum
        "issuing_ca": 365 * 8,
        "root_ca": 365 * 20,
        "device_identity": 365 * 8,
        "code_signing": 365 * 3,
        "firmware_signing": 365 * 12,
    }.get(asset_type, 365 * 2)

    roll = rng.random()
    if roll < 0.02:
        remaining = -rng.randint(2, 60)          # lapsed
    elif roll < 0.06:
        remaining = rng.randint(1, 29)           # inside 30-day window
    elif roll < 0.12:
        remaining = rng.randint(31, 89)          # inside 90-day window
    else:
        remaining = rng.randint(120, max(150, validity))

    expires = today + datetime.timedelta(days=remaining)
    issued = expires - datetime.timedelta(days=validity)
    return issued.isoformat(), expires.isoformat()


def build(count: int) -> list[dict]:
    rng = random.Random(SEED)
    rows: list[dict] = []

    for index in range(count):
        _, asset_type, algorithm, bits, protocol = weighted(rng, MIX)
        tag, department, owner = rng.choice(SUBSYSTEMS)
        environment = weighted(rng, [(w, name) for name, w in ENVIRONMENTS])[1]

        role = rng.choice(HOST_ROLES)
        ordinal = rng.randint(1, 240)

        if asset_type in {"tls_certificate", "tls_key_exchange", "tls_cipher_suite",
                          "database_tls", "config"}:
            host = f"{role}-{tag}-{ordinal:03d}.{ORG}.internal:443"
            name = f"{role}-{tag}-{ordinal:03d} {asset_type.replace('_', ' ')}"
        elif asset_type == "payment_hsm":
            host = f"hsm://payment-hsm-{ordinal % 9:02d}/slot{ordinal % 4}/key"
            name = f"Payment HSM key {ordinal:03d}"
        elif asset_type == "firmware_signing":
            host = f"hsm://fw-hsm-{ordinal % 5:02d}/slot0/firmware-sign"
            name = f"{tag.upper()} firmware signing key {ordinal:02d}"
        elif asset_type == "code_signing":
            host = f"/opt/ci/{tag}-release-signing-{ordinal:02d}.pem"
            name = f"{department} release signing key {ordinal:02d}"
        elif asset_type == "issuing_ca":
            host = f"pki://{ORG}/issuing-ca-{tag}"
            name = f"Tejomaya Issuing CA - {department}"
        elif asset_type == "root_ca":
            host = f"pki://{ORG}/root-ca-g{ordinal % 3 + 1}"
            name = f"Tejomaya Root CA G{ordinal % 3 + 1}"
        elif asset_type == "ssh_key":
            host = f"/etc/ssh/ssh_host_key_{role}-{ordinal:03d}"
            name = f"SSH host key {role}-{ordinal:03d}"
        elif asset_type == "source":
            host = f"services/{tag}/{role}_handler.py:{rng.randint(20, 400)}"
            name = f"{department} source call site {ordinal:03d}"
        elif asset_type == "device_identity":
            host = f"{tag}-fleet-{ordinal:03d}.{ORG}.internal"
            name = f"{department} device identity {ordinal:03d}"
        elif asset_type == "vpn_ipsec":
            host = f"vpn-{tag}-{ordinal:02d}.{ORG}.internal"
            name = f"{department} IPsec tunnel {ordinal:02d}"
        elif asset_type == "token_signing":
            host = f"/opt/idp/{tag}-jwt-signing-{ordinal:02d}.pem"
            name = f"{department} token signing key {ordinal:02d}"
        else:  # backup_encryption
            host = f"/opt/backup/{tag}-archive-{ordinal:03d}.key"
            name = f"{department} backup key {ordinal:03d}"

        issued, expires = cert_dates(rng, asset_type)

        # ~15% of assets have nobody attached. An unowned asset cannot be
        # scheduled, which makes the gap an operational finding rather than
        # missing data.
        row_owner = "" if rng.random() < 0.15 else owner

        rows.append({
            "asset_name": name,
            "hostname": host,
            "type": asset_type,
            "algo": algorithm,
            "bits": bits or "",
            "protocol": protocol or "",
            "env": environment,
            "department": department,
            "owner": row_owner,
            "valid_from": issued,
            "valid_to": expires,
            "notes": f"{tag} subsystem",
        })

    return rows


def main() -> None:
    count = int(sys.argv[1]) if len(sys.argv) > 1 else 1200
    rows = build(count)

    out = OUT if count == 1200 else OUT.with_name(f"enterprise_estate_{count}.csv")
    with out.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    print(f"{len(rows)} assets -> {out}")

    # A quick shape report, so a change to the mix is visible without importing.
    from collections import Counter
    kinds = Counter(row["type"] for row in rows)
    unowned = sum(1 for row in rows if not row["owner"])
    print("top classes:", dict(kinds.most_common(6)))
    print(f"unowned: {unowned} ({100 * unowned / len(rows):.1f}%)")


if __name__ == "__main__":
    main()
