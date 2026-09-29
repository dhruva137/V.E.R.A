"""M9 - Board memo generator.

One document a board can act on: what was found, what is already late, what it
costs, and what the honest limits of the analysis are.

The limitations section is not boilerplate. This memo is aimed at an audience
that will be asked to fund a multi-year programme off it, and a risk document
that does not state its own assumptions is not usable evidence.
"""

from __future__ import annotations

import datetime
import io

from reportlab.lib import colors
from reportlab.lib.enums import TA_JUSTIFY
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    KeepTogether, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
)

from engine.qirs import dominant_axis
from models.schemas import CryptoAsset, DashboardSummary

INK = colors.HexColor("#0F172A")
ACCENT = colors.HexColor("#0E7490")
DANGER = colors.HexColor("#B91C1C")
MUTED = colors.HexColor("#64748B")
RULE = colors.HexColor("#CBD5E1")
BAND = colors.HexColor("#F1F5F9")

RISK_COLOURS = {
    "critical": colors.HexColor("#B91C1C"),
    "high": colors.HexColor("#C2410C"),
    "medium": colors.HexColor("#A16207"),
    "low": colors.HexColor("#15803D"),
    "minimal": colors.HexColor("#15803D"),
    "informational": colors.HexColor("#6D28D9"),
    "safe": colors.HexColor("#15803D"),
}


def _styles() -> dict:
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "Title", parent=base["Heading1"], fontName="Helvetica-Bold",
            fontSize=22, leading=26, textColor=INK, spaceAfter=2,
        ),
        "subtitle": ParagraphStyle(
            "Subtitle", parent=base["Normal"], fontSize=10.5, leading=14,
            textColor=MUTED, spaceAfter=14,
        ),
        "h2": ParagraphStyle(
            "H2", parent=base["Heading2"], fontName="Helvetica-Bold", fontSize=12.5,
            leading=16, textColor=ACCENT, spaceBefore=16, spaceAfter=7,
        ),
        "body": ParagraphStyle(
            "Body", parent=base["Normal"], fontSize=9.8, leading=14.5,
            textColor=INK, alignment=TA_JUSTIFY, spaceAfter=7,
        ),
        "small": ParagraphStyle(
            "Small", parent=base["Normal"], fontSize=8.2, leading=11.5, textColor=MUTED,
        ),
        "cell": ParagraphStyle(
            "Cell", parent=base["Normal"], fontSize=8.2, leading=10.5, textColor=INK,
        ),
        "lead": ParagraphStyle(
            "Lead", parent=base["Normal"], fontSize=11, leading=16, textColor=INK,
            spaceAfter=10,
        ),
    }


def _table(data, widths, styles, align=None) -> Table:
    table = Table(data, colWidths=widths, repeatRows=1, hAlign="LEFT")
    commands = [
        ("BACKGROUND", (0, 0), (-1, 0), INK),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8.2),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("GRID", (0, 0), (-1, -1), 0.4, RULE),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, BAND]),
    ]
    if align:
        commands.extend(align)
    table.setStyle(TableStyle(commands))
    return table


def _metric_row(dashboard: DashboardSummary, styles) -> Table:
    cells = [
        ("Assets catalogued", f"{dashboard.total_assets}", INK),
        ("Quantum-vulnerable", f"{dashboard.quantum_vulnerable}", DANGER),
        ("Behind schedule", f"{dashboard.negative_slack_count}", DANGER),
        ("Already broken", f"{dashboard.classically_broken}", colors.HexColor("#6D28D9")),
    ]
    data = [
        [Paragraph(f'<font size="7" color="#64748B">{label.upper()}</font>', styles["small"])
         for label, _, _ in cells],
        # hexval() returns '0xrrggbb'; reportlab's colour parser needs '#rrggbb'.
        [Paragraph(f'<font size="19" color="#{colour.hexval()[2:]}"><b>{value}</b></font>',
                   styles["cell"])
         for _, value, colour in cells],
    ]
    table = Table(data, colWidths=[42 * mm] * 4, hAlign="LEFT")
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), BAND),
        ("BOX", (0, 0), (-1, -1), 0.4, RULE),
        ("INNERGRID", (0, 0), (-1, -1), 0.4, RULE),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
    ]))
    return table


def generate_board_memo(
    assets: list[CryptoAsset],
    dashboard: DashboardSummary,
    cbom_report: dict | None = None,
    threat_model=None,
) -> bytes:
    styles = _styles()
    buffer = io.BytesIO()
    document = SimpleDocTemplate(
        buffer, pagesize=A4,
        leftMargin=18 * mm, rightMargin=18 * mm, topMargin=16 * mm, bottomMargin=16 * mm,
        title="VERA - Post-Quantum Migration Readiness",
        author="VERA (Epoch Zero)",
    )

    today = datetime.date.today()
    flow = []

    # --- Header ---
    flow.append(Paragraph("Post-Quantum Migration Readiness", styles["title"]))
    flow.append(Paragraph(
        f"Cryptographic estate assessment &middot; {today:%d %B %Y} &middot; "
        f"Prepared by VERA &middot; Sector track: {dashboard.org_persona}",
        styles["subtitle"],
    ))
    flow.append(_metric_row(dashboard, styles))
    flow.append(Spacer(1, 12))

    # --- Position ---
    behind = [a for a in assets if a.quantum_vulnerable and a.slack_months < 0]
    worst = min(assets, key=lambda a: a.slack_months) if assets else None
    vulnerable_pct = (
        dashboard.quantum_vulnerable / dashboard.total_assets * 100
        if dashboard.total_assets else 0
    )

    flow.append(Paragraph("Position", styles["h2"]))
    if behind:
        flow.append(Paragraph(
            f"<b>{len(behind)} assets cannot meet their statutory migration milestone even if "
            f"work begins today.</b> The worst is {worst.name}, which overruns its "
            f"{worst.statutory_deadline_year} deadline by {abs(worst.slack_months):.0f} months. "
            "These are not assets that are merely risky - they are assets where the remaining "
            "calendar is already shorter than the migration itself.",
            styles["lead"],
        ))
    else:
        flow.append(Paragraph(
            "No asset is currently past the point where its statutory milestone can still be "
            "met. That position holds only while migration effort estimates hold; it is a "
            "reason to start, not a reason to wait.",
            styles["lead"],
        ))

    flow.append(Paragraph(
        f"Of {dashboard.total_assets} cryptographic assets catalogued, "
        f"{dashboard.quantum_vulnerable} ({vulnerable_pct:.0f}%) rely on RSA, elliptic-curve or "
        "finite-field cryptography, all of which Shor's algorithm breaks outright on a "
        f"cryptographically relevant quantum computer. A further {dashboard.classically_broken} "
        "use algorithms already broken by classical cryptanalysis and require attention "
        "regardless of any quantum timeline.",
        styles["body"],
    ))

    # --- Why the ordering is what it is ---
    flow.append(Paragraph("Why this ordering", styles["h2"]))
    flow.append(Paragraph(
        "Quantum risk splits into two exposures that behave differently, and ranking on either "
        "one alone mis-orders the other. <b>Confidentiality risk</b> applies to encrypted "
        "traffic an adversary can record today and decrypt later; its exposure window is the "
        "data's secrecy requirement <i>plus</i> the migration time, so delay makes it "
        "monotonically worse. <b>Integrity risk</b> applies to signing keys and trust anchors, "
        "which are not leaked but forged; the window closes when either the migration completes "
        "or the anchor retires, so it is capped rather than unbounded.",
        styles["body"],
    ))
    flow.append(Paragraph(
        "The consequence is that long-lived signing anchors - root CAs, firmware and code "
        "signing keys - are systematically under-ranked by tools that score confidentiality "
        "only, which is most of them.",
        styles["body"],
    ))

    # --- Priorities ---
    flow.append(Paragraph("Migration priorities", styles["h2"]))
    top = [a for a in assets if a.quantum_vulnerable][:12]
    rows = [["#", "Asset", "Class", "Axis", "QIRS", "Deadline", "Slack"]]
    for asset in top:
        axis, value = dominant_axis(asset)
        rows.append([
            str(asset.priority_rank),
            Paragraph(asset.name[:52], styles["cell"]),
            Paragraph(asset.profile_label[:26], styles["cell"]),
            f"{axis} {value:.2f}",
            f"{asset.qirs:.3f}",
            str(asset.statutory_deadline_year),
            f"{asset.slack_months:+.0f} mo",
        ])

    align = [("ALIGN", (3, 1), (-1, -1), "RIGHT"), ("ALIGN", (0, 0), (0, -1), "CENTER")]
    for index, asset in enumerate(top, start=1):
        if asset.slack_months < 0:
            align.append(("TEXTCOLOR", (6, index), (6, index), DANGER))
            align.append(("FONTNAME", (6, index), (6, index), "Helvetica-Bold"))
    flow.append(_table(
        rows, [8 * mm, 55 * mm, 30 * mm, 22 * mm, 14 * mm, 18 * mm, 17 * mm], styles, align
    ))
    flow.append(Spacer(1, 4))
    flow.append(Paragraph(
        "Ordering rule: assets that cannot meet their milestone are listed first, most overrun "
        "first; the rest by composite score descending. 'Axis' names the exposure driving each "
        "asset and its value.",
        styles["small"],
    ))

    # --- Risk profile ---
    flow.append(Paragraph("Distribution", styles["h2"]))
    risk_rows = [["Risk band", "Assets", "Meaning"]]
    meanings = {
        "critical": "Past the point of meeting its milestone, and high scoring",
        "high": "Past its milestone, or high exposure on its dominant axis",
        "medium": "Material exposure with schedule still available",
        "low": "Low exposure; migrate on the normal refresh cycle",
        "minimal": "Negligible exposure",
        "informational": "Classically broken - fix now, unrelated to quantum",
        "safe": "No migration required",
    }
    for level, count in dashboard.by_risk_level.items():
        risk_rows.append([level.capitalize(), str(count), meanings.get(level, "")])
    flow.append(_table(risk_rows, [26 * mm, 18 * mm, 110 * mm], styles))

    flow.append(PageBreak())

    # --- Cost ---
    flow.append(Paragraph("What the migration costs operationally", styles["h2"]))
    flow.append(Paragraph(
        "The difficulty of this migration is not computational. Post-quantum algorithms are "
        "fast. The difficulty is size: keys, ciphertexts and signatures grow by an order of "
        "magnitude, and that breaks MTU assumptions, embedded flash budgets, smartcard buffers "
        "and any protocol with a fixed-length field.",
        styles["body"],
    ))
    size_rows = [
        ["Element", "Today", "Post-quantum", "Growth"],
        ["TLS key share (X25519 to ML-KEM-768)", "32 B", "1,184 B", "37x"],
        ["Signature (ECDSA P-256 to ML-DSA-65)", "72 B", "3,309 B", "46x"],
        ["Signature (ECDSA P-256 to SLH-DSA-128s)", "72 B", "7,856 B", "109x"],
        ["TLS handshake crypto payload", "1,344 B", "16,167 B", "12x"],
    ]
    flow.append(_table(
        size_rows, [78 * mm, 24 * mm, 30 * mm, 20 * mm], styles,
        [("ALIGN", (1, 1), (-1, -1), "RIGHT")],
    ))
    flow.append(Spacer(1, 4))
    flow.append(Paragraph(
        "Sizes are constants fixed by FIPS 203, FIPS 204, FIPS 205 and RFC 7748 - not estimates. "
        "A classical TLS handshake's crypto payload fits in one TCP segment; the hybrid "
        "equivalent spans twelve.",
        styles["small"],
    ))

    # --- Regulatory ---
    flow.append(Paragraph("Regulatory position", styles["h2"]))
    flow.append(Paragraph(
        "Deadlines are taken from the DST framework <i>Implementation of Quantum Safe Ecosystem "
        "in India</i> (5 February 2026). Critical information infrastructure follows "
        "foundations 2027, high-priority 2028, full migration 2029. Banking, healthcare, "
        "insurance, education and e-governance follow 2028, 2030 and 2033. Where an entity "
        "operates critical infrastructure alongside its primary sector, the framework's "
        "highest-risk-persona-governs rule applies the stricter track to that infrastructure, "
        "which is why parts of this estate carry 2028 dates rather than 2030.",
        styles["body"],
    ))
    flow.append(Paragraph(
        "<b>This is a published roadmap, not an enforced circular.</b> The RBI Q-SAFE committee "
        "was constituted on 25 May 2026 and has not yet reported; no Master Direction has been "
        "issued. The case for starting now is not that a deadline lands in ninety days. It is "
        "that inventory is the first line item in every roadmap published so far, and building "
        "one takes years - organisations that begin after the circular will be running a crisis "
        "migration.",
        styles["body"],
    ))

    # --- Evidence ---
    flow.append(Paragraph("Evidence produced", styles["h2"]))
    if cbom_report:
        verdict = "passed" if cbom_report.get("valid") else "FAILED"
        flow.append(Paragraph(
            f"A CycloneDX {cbom_report.get('spec_version', '1.6')} Cryptography Bill of "
            f"Materials covering {cbom_report.get('components_checked', 0)} components "
            f"accompanies this memo. It {verdict} all "
            f"{cbom_report.get('rules_total', 0)} structural, enumeration and "
            "reference-integrity checks. This is the machine-readable artefact a regulator or "
            "counterparty can be handed directly; technology providers face mandatory CBOM "
            "submission from FY 2027-28.",
            styles["body"],
        ))

    # --- Limitations ---
    flow.append(Paragraph("Limitations of this analysis", styles["h2"]))
    limitations = [
        "<b>The threat timeline is a subjective prior, not a forecast.</b> It is fitted to an "
        "expert elicitation of roughly 26 respondents (Global Risk Institute, 2025). Every "
        "absolute score is therefore reported as a band across optimistic, median and "
        "pessimistic readings of that elicitation. No single number should be quoted from it.",

        "<b>Asset ordering is more robust than asset scores.</b> Within one axis, ranking "
        "assets of comparable sensitivity depends only on their time horizons, not on the "
        "threat curve - so the migration order stands without anyone knowing when a quantum "
        "computer arrives. Comparing across the two axes does depend on the curve and on the "
        "weighting chosen, and that sensitivity is measured and reported rather than hidden.",

        "<b>Migration effort estimates are class defaults.</b> Effort per asset class is a "
        "policy input, not a measurement from this estate. Slack figures move directly with "
        "these, and they should be replaced with the organisation's own estimates before this "
        "memo is used for budgeting.",

        "<b>Discovery is not exhaustive.</b> This assessment covers TLS endpoints, keystores, "
        "configuration and source. Hardware security module internals, mainframe cryptography "
        "and third-party components reached only through vendor APIs are out of scope and will "
        "add assets, almost certainly including high-consequence ones.",
    ]
    for text in limitations:
        flow.append(Paragraph(text, styles["body"]))

    # --- Recommendations ---
    flow.append(Paragraph("Recommended actions", styles["h2"]))
    actions = [
        (
            "Replace class-default effort estimates with real ones",
            "Everything in the slack column depends on migration effort per asset class. "
            "This is the cheapest action here and it determines whether the rest of the "
            "numbers can be trusted.",
        ),
        (
            f"Start the {len(behind)} overrunning assets now" if behind
            else "Begin with the long-lead trust anchors",
            "These are dominated by long-lead trust anchors - firmware signing, device "
            "identity and HSM-resident keys - where migration is gated by hardware refresh "
            "cycles and vendor firmware rather than by internal effort. Nothing accelerates "
            "them later.",
        ),
        (
            "Require crypto-agility in procurement from this quarter",
            "Every device and system bought without the ability to accept a new trust anchor "
            "extends the migration by its full service life. This costs nothing today and is "
            "irreversible if missed.",
        ),
        (
            "Enable hybrid key exchange on external endpoints",
            "X25519MLKEM768 is standardised, shipped in current TLS stacks, and closes the "
            "harvest-now-decrypt-later exposure on traffic being recorded today. It is "
            "backwards compatible: clients that do not support it negotiate the classical "
            "group.",
        ),
        (
            "Re-run this assessment quarterly",
            "The estate changes faster than the deadlines. The inventory is only useful if it "
            "is current, which is the argument for automating it rather than commissioning it.",
        ),
    ]
    for index, (headline, detail) in enumerate(actions, start=1):
        flow.append(KeepTogether([
            Paragraph(f"<b>{index}. {headline}</b>", styles["body"]),
            Paragraph(detail, styles["body"]),
        ]))

    flow.append(Spacer(1, 10))
    flow.append(Paragraph(
        f"Generated by VERA v1.0.0 on {today:%d %B %Y}. "
        f"Scan reference {dashboard.scan_id or 'n/a'}. "
        "Scoring model: QIRS, extending the Quantum-Adjusted Risk Score within the PAREK "
        "framework (MDPI Electronics 2025, 14(17), 3338). Threat timeline: Global Risk "
        "Institute Quantum Threat Timeline Report 2025.",
        styles["small"],
    ))

    document.build(flow)
    return buffer.getvalue()
