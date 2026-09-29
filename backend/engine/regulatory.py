"""M5 - Regulatory mapper.

Maps each asset to an adopter persona under the DST framework, resolves the
binding statutory milestone, and computes remaining slack.

DST, *Implementation of Quantum Safe Ecosystem in India* (Feb 2026), "Strategic
Roadmap for Quantum Safe Migration - Timelines" (report annexure, p. 101): two
tracks, each milestone a year. VERA plans against 1 January of that year
(`deadline_point`), the conservative reading.

  - "CII - Defence, Power, Telecoms, Other Critical Sectors": foundations 2027,
    high-priority 2028, full 2029. Banking and insurance (BFSI) and government
    are critical sectors under NCIIPC, so they are on this track.
  - "Regular Enterprises": foundations 2028, high-priority 2030, full 2033.
  - Separately, organisations request vendor CBOMs from FY 2026-27 and mandate
    them through procurement from FY 2027-28. That is a procurement rule, not a
    migration deadline, so it moves no date here.

Two rules from the report drive everything here.

**Highest-risk-persona-governs.** An entity that also operates critical
infrastructure follows the CII track *for that infrastructure*. The previous
implementation classified persona purely by matching substrings against a
source location, so every keystore, config and source finding - which have file
paths, not domains - fell through to General Enterprise. An organisation profile
now supplies the baseline persona and the per-asset heuristic can only escalate
from it, never dilute it.

**The binding milestone depends on the asset, not just the sector.** The
framework's phases are foundations (inventory and CBOM), high-priority
(migrate what matters), and full (everything else). Assigning one fixed phase
per persona - as the previous version did - meant a root CA and a marketing
site had the same deadline. The phase is now selected from the asset's own
criticality, which is what "high-priority" means in the source document.

slack = statutory_deadline - (today + Y), reported in months. Negative means
starting today still misses the milestone.
"""

from __future__ import annotations

import datetime
import re

from models.schemas import CryptoAsset

# Persona -> phase -> deadline year.
CII_TRACK = {"foundation": 2027, "high_priority": 2028, "full": 2029}
ENTERPRISE_TRACK = {"foundation": 2028, "high_priority": 2030, "full": 2033}
DEADLINES: dict[str, dict[str, int]] = {
    "CII": CII_TRACK,
    "Banking": CII_TRACK,
    "Insurance": CII_TRACK,
    "E-Governance": CII_TRACK,
    "Healthcare": ENTERPRISE_TRACK,
    "Education": ENTERPRISE_TRACK,
    "Technology Provider": ENTERPRISE_TRACK,
    "General Enterprise": ENTERPRISE_TRACK,
}
TRACK_SOURCE = ("DST, Implementation of Quantum Safe Ecosystem in India (Feb 2026), "
                "Strategic Roadmap for Quantum Safe Migration - Timelines")

# Ordering for highest-risk-persona-governs. Earlier in the list wins.
PERSONA_SEVERITY = [
    "CII",
    "Technology Provider",
    "Banking",
    "E-Governance",
    "Insurance",
    "Healthcare",
    "Education",
    "General Enterprise",
]

_SEVERITY_RANK = {p: i for i, p in enumerate(PERSONA_SEVERITY)}

# Substring signals per persona, checked against domain names, file paths and
# asset tags. Ordered so the more specific classification is tested first.
_PERSONA_SIGNALS: list[tuple[str, tuple[str, ...]]] = [
    (
        "CII",
        (
            "npci", "upi", "imps", "neft", "rtgs", "swift", "rbi", "sebi",
            "nse", "bse", "nsdl", "cdsl", "ccil", "irctc", "atm-switch",
            "card-switch", "payment-hsm", "settlement", "clearing", "grid",
            "scada", "powergrid",
        ),
    ),
    (
        "E-Governance",
        ("gov.in", "nic.in", "uidai", "aadhaar", "incometax", "gstn", "digilocker", "esign"),
    ),
    (
        "Banking",
        (
            "bank", "sbi", "hdfc", "icici", "axis", "kotak", "pnb", "baroda",
            "canara", "yesbank", "indusind", "core-banking", "corebank",
            "treasury", "loan", "deposit", "branch",
        ),
    ),
    ("Insurance", ("lic", "insur", "policyholder", "actuar", "hdfclife", "maxlife")),
    ("Healthcare", ("hospital", "health", "abdm", "ehr", "patient", "diagnost")),
    ("Education", ("edu.in", "ac.in", "university", "college", "school")),
    (
        "Technology Provider",
        ("tcs", "infosys", "wipro", "hcltech", "techm", "mindtree", "ltimindtree", "cognizant"),
    ),
]


def classify_persona(source_location: str, tags: list[str] | None = None) -> str | None:
    """Persona implied by an asset's own location and tags, or None.

    Returning None rather than a default matters: it lets `map_regulatory`
    distinguish "this asset tells us nothing" from "this asset is genuinely
    general enterprise", so the organisation baseline is applied instead of
    silently overriding it.
    """
    haystack = (source_location or "").lower()
    if tags:
        haystack += " " + " ".join(t.lower() for t in tags)

    for persona, signals in _PERSONA_SIGNALS:
        if any(signal in haystack for signal in signals):
            return persona
    return None


def governing_persona(*candidates: str | None) -> str:
    """Highest-risk-persona-governs: the most severe non-empty candidate."""
    present = [c for c in candidates if c]
    if not present:
        return "General Enterprise"
    return min(present, key=lambda p: _SEVERITY_RANK.get(p, len(PERSONA_SEVERITY)))


def binding_phase(asset: CryptoAsset) -> tuple[str, str]:
    """Select which DST milestone actually binds this asset.

    Returns (phase, reason).

    The framework's "high-priority" phase is defined by what the asset is, not
    by the sector it sits in. An asset qualifies when it is either a widely
    trusted anchor (large blast radius) or directly reachable by an attacker
    (internet-facing), which are the two properties the source document uses to
    describe high-priority systems.
    """
    if asset.c >= 0.7:
        return (
            "high_priority",
            f"Blast radius C = {asset.c:.2f}: a widely relied-upon trust anchor, so the "
            "high-priority milestone binds rather than the full-migration date.",
        )
    if asset.e >= 0.8:
        return (
            "high_priority",
            f"Exposure E = {asset.e:.2f}: internet-facing and interceptable, so the "
            "high-priority milestone binds.",
        )
    return (
        "full",
        f"Blast radius C = {asset.c:.2f} and exposure E = {asset.e:.2f} are both below the "
        "high-priority thresholds, so the full-migration milestone applies.",
    )


def get_deadline(persona: str, phase: str) -> int:
    """Statutory deadline year for a (persona, phase) pair."""
    table = DEADLINES.get(persona, DEADLINES["General Enterprise"])
    return table.get(phase, table["full"])


def _now_fractional(now: datetime.datetime | None = None) -> float:
    """Current time as a fractional year, e.g. 2026-08-06 -> 2026.596."""
    now = now or datetime.datetime.now()
    start = datetime.datetime(now.year, 1, 1)
    end = datetime.datetime(now.year + 1, 1, 1)
    return now.year + (now - start).total_seconds() / (end - start).total_seconds()


def deadline_point(deadline_year: int) -> float:
    """The moment VERA plans a milestone year against: 1 January of that year.

    The DST table gives a year per milestone. VERA plans to be done by the
    start of that year, the conservative reading, which leaves the year itself
    as margin (a 2028 milestone with a two-year
    migration shows -7 months as of August 2026). Every schedule computation
    uses this one function, and every screen says "planned against 1 Jan",
    so the date shown is the date computed.
    """
    return float(deadline_year)


def compute_slack(
    deadline_year: int,
    migration_effort_years: float,
    now: datetime.datetime | None = None,
) -> float:
    """Remaining slack in months.

    slack = (deadline - today) - Y, in months, with the deadline at
    `deadline_point` (1 January of the milestone year). Negative slack means
    that even starting migration today, the asset misses its milestone by that
    many months.
    """
    current = _now_fractional(now)
    return round((deadline_point(deadline_year) - current) * 12.0 - migration_effort_years * 12.0, 1)


def map_regulatory(
    assets: list[CryptoAsset],
    org_persona: str = "Banking",
    now: datetime.datetime | None = None,
) -> list[CryptoAsset]:
    """Assign persona, binding milestone, deadline and slack to each asset.

    `org_persona` is the organisation's own baseline classification, supplied by
    the operator. Per-asset signals can only escalate it - an organisation that
    declares itself a bank does not get General Enterprise deadlines just
    because a finding happened to live at `/etc/ssl/private/`.
    """
    for asset in assets:
        asset_persona = classify_persona(asset.source_location, asset.tags)
        asset.persona = governing_persona(org_persona, asset_persona)
        if asset_persona and asset.persona == asset_persona and asset_persona != org_persona:
            asset.persona_source = (
                f"escalated to '{asset_persona}' by the asset itself, above the "
                f"organisation baseline '{org_persona}' "
                "(highest-risk-persona-governs)"
            )
        else:
            asset.persona_source = f"organisation baseline '{org_persona}'"

        phase, reason = binding_phase(asset)
        asset.binding_phase = phase
        asset.binding_phase_reason = reason
        asset.statutory_deadline_year = get_deadline(asset.persona, phase)
        asset.slack_months = compute_slack(asset.statutory_deadline_year, asset.y, now)

    return assets


def deadline_table() -> dict:
    """The full deadline matrix, for display in the UI."""
    return {
        "deadlines": DEADLINES,
        "persona_severity": PERSONA_SEVERITY,
        "source": (
            "DST, Implementation of Quantum Safe Ecosystem in India, 5 Feb 2026. "
            "Technology-provider CBOM submission mandatory from FY 2027-28."
        ),
        "caveat": (
            "The DST document sets migration tracks; the RBI Q-SAFE committee "
            "(constituted 25 May 2026) has not yet reported and no Master Direction "
            "has been issued. These dates are the published roadmap, not an "
            "enforced circular."
        ),
    }
