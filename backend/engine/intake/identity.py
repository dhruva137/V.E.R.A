"""Identity lattice and corroboration for intake findings.

WHY THIS EXISTS
---------------
Two sensors looking at the same certificate must become one object, not two
rows that double-count every downstream total. Identity is the subject CN where
there is one, and location|class|algorithm otherwise — never location alone,
because one TLS endpoint yields three distinct assets.

Corroboration raises confidence when independent methods agree, but never above
the ceiling of the stronger grade. Agreement between two weak sensors does not
manufacture an observation.
"""

from __future__ import annotations

from models.schemas import RawCryptoFinding


def identity_key(finding: RawCryptoFinding) -> tuple[str, str]:
    """What makes two findings the same underlying object.

    A certificate held in a keystore and the same certificate resolved from the
    chain are one certificate seen twice, not two certificates. Identity is the
    subject DN where there is one, and the location otherwise.
    """
    if finding.cert_subject:
        for part in finding.cert_subject.split(","):
            if part.strip().upper().startswith("CN="):
                return ("cert", part.split("=", 1)[1].strip().lower())
        return ("cert", finding.cert_subject.lower())
    # Location alone is not an identity. One TLS endpoint yields three distinct
    # assets - certificate, key exchange and cipher suite - all at the same
    # host:port, and keying on location merged them into one, silently losing
    # the key-exchange asset that carries the harvest-now-decrypt-later risk.
    algorithm = (finding.algorithm or finding.key_exchange
                 or finding.cipher_suite or "")
    return (
        "loc",
        f"{finding.source_location}|{finding.asset_class or ''}|{algorithm}".lower(),
    )


def correlate_findings(findings: list[RawCryptoFinding]) -> list[RawCryptoFinding]:
    """Fold findings that describe the same object into one, corroborated.

    This is the corroboration rule from `engine.plugins` applied at the point it
    actually matters. Two independent methods agreeing raises confidence, but
    never above the ceiling of the stronger one — agreement between two weak
    sensors does not manufacture an observation.

    Without this the estate double-counts: the root CA appears once from the
    keystore and once from the chain, and every total downstream is wrong.
    """
    from engine.plugins import corroborate

    merged: dict[tuple[str, str], RawCryptoFinding] = {}
    for finding in findings:
        key = identity_key(finding)
        existing = merged.get(key)
        if existing is None:
            merged[key] = finding
            continue

        # Keep whichever was learned by the stronger method as the base, so the
        # surviving record carries the better-evidenced parameters.
        strong, weak = existing, finding
        if (finding.raw_details.get("confidence", 0)
                > existing.raw_details.get("confidence", 0)):
            strong, weak = finding, existing

        provenances = [
            strong.raw_details.get("provenance", "inferred"),
            weak.raw_details.get("provenance", "inferred"),
        ]
        sensors = sorted({
            strong.raw_details.get("discovered_by", ""),
            weak.raw_details.get("discovered_by", ""),
        } - {""})

        strong.tags = sorted(set(strong.tags) | set(weak.tags))
        # The weaker view's fields fill gaps but never overwrite.
        for field_name in ("cert_issuer", "cert_serial", "cert_validity_end",
                           "cert_validity_start", "signature_algorithm", "owner"):
            if not getattr(strong, field_name, None):
                value = getattr(weak, field_name, None)
                if value:
                    setattr(strong, field_name, value)

        strong.raw_details["confidence"] = corroborate(provenances)
        strong.raw_details["corroborated_by"] = sensors
        strong.raw_details["corroboration_count"] = len(sensors)
        strong.raw_details["also_seen_at"] = sorted(
            set(strong.raw_details.get("also_seen_at", []))
            | {weak.source_location}
        )
        merged[key] = strong

    return list(merged.values())
