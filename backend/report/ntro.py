"""NTRO / CII assessment report (PDF).

Sections, in the order a reviewer reads them:

    1  Executive page        scope, what was found, the three things to do first
    2  Mosca by system       exposure category per system (X + Y against per-primitive Z)
    3  Vendor-gated register who must ship PQC before the estate can move, with clause status
    4  Top recommendations   target, measured cost on this host, prerequisite upgrades, owner
    5  Drift                 where declared and observed evidence disagree
    6  Methodology           every citation, the qubit table, D, data-class defaults, limits
    7  Evidence              manifest hash, signature algorithm and verification result

Every number comes from the scan, the benchmark file or a cited source; a
section with nothing to show says so rather than being dropped.
"""

from __future__ import annotations

import hashlib
import io
import json

from reportlab.graphics.shapes import Drawing, Rect, String
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from report.generator import BAND, DANGER, INK, MUTED, RULE, _styles, _table

MOSCA_COLOURS = {"certain": colors.HexColor("#B91C1C"), "likely": colors.HexColor("#C2410C"),
                 "possible": colors.HexColor("#A16207"), "clear": colors.HexColor("#15803D")}
MOSCA_ORDER = ("certain", "likely", "possible", "clear")


def _esc(text) -> str:
    return str(text if text is not None else "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _mosca_chart(by_system: dict[str, dict[str, int]]) -> Drawing:
    """Horizontal stacked bars: one row per system, segments by Mosca category."""
    rows = sorted(by_system.items(), key=lambda kv: (-kv[1].get("certain", 0), -sum(kv[1].values()), kv[0]))[:12]
    width, row_h, label_w = 170 * mm, 7 * mm, 42 * mm
    height = row_h * (len(rows) + 1) + 6 * mm
    drawing = Drawing(width, height)
    bar_w = width - label_w - 4 * mm
    peak = max((sum(c.get(k, 0) for k in MOSCA_ORDER) for _, c in rows), default=1) or 1
    for i, (system, counts) in enumerate(rows):
        y = height - (i + 1) * row_h - 2 * mm
        drawing.add(String(0, y + 2.2 * mm, system[:26], fontName="Helvetica", fontSize=7.5, fillColor=INK))
        x = label_w
        for category in MOSCA_ORDER:
            n = counts.get(category, 0)
            if not n:
                continue
            w = bar_w * n / peak
            drawing.add(Rect(x, y, w, row_h - 2 * mm, fillColor=MOSCA_COLOURS[category], strokeColor=None))
            if w > 7 * mm:
                drawing.add(String(x + 1.5 * mm, y + 1.6 * mm, str(n), fontName="Helvetica-Bold", fontSize=7,
                                   fillColor=colors.white))
            x += w
    lx = label_w
    for category in MOSCA_ORDER:
        drawing.add(Rect(lx, 1 * mm, 3 * mm, 3 * mm, fillColor=MOSCA_COLOURS[category], strokeColor=None))
        drawing.add(String(lx + 4 * mm, 1.4 * mm, category, fontName="Helvetica", fontSize=7, fillColor=MUTED))
        lx += 26 * mm
    return drawing


def _metric_table(cells: list[tuple[str, str, colors.Color]], styles) -> Table:
    data = [[Paragraph(f'<font size="7" color="#64748B">{_esc(label).upper()}</font>', styles["small"])
             for label, _, _ in cells],
            [Paragraph(f'<font size="18" color="#{colour.hexval()[2:]}"><b>{_esc(value)}</b></font>', styles["cell"])
             for _, value, colour in cells]]
    table = Table(data, colWidths=[170 * mm / len(cells)] * len(cells), hAlign="LEFT")
    table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), BAND), ("BOX", (0, 0), (-1, -1), 0.4, RULE),
                               ("INNERGRID", (0, 0), (-1, -1), 0.4, RULE), ("TOPPADDING", (0, 0), (-1, -1), 6),
                               ("BOTTOMPADDING", (0, 0), (-1, -1), 6)]))
    return table


def generate_ntro_report(*, assets, estate: dict | None, scan: dict, recommendations: dict, gated: list[dict],
                         clauses: list[dict], drift: list[dict], threat_model: dict, manifest: dict,
                         manifest_check: dict, citations: dict, data_classes: dict) -> bytes:
    styles = _styles()
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, leftMargin=20 * mm, rightMargin=20 * mm, topMargin=18 * mm,
                            bottomMargin=18 * mm, title="Cryptographic inventory and quantum-risk assessment",
                            author="VERA", subject="SIH26164 (NTRO) assessment report")
    flow: list = []
    name = (estate or {}).get("name") or scan.get("label") or "Scanned estate"
    vulnerable = [a for a in assets if a.quantum_vulnerable]
    broken = [a for a in assets if a.classically_broken]
    categories: dict[str, int] = {}
    by_system: dict[str, dict[str, int]] = {}
    for a in vulnerable:
        cat = a.mosca_category or "clear"
        categories[cat] = categories.get(cat, 0) + 1
        system = (a.raw_details or {}).get("system") or "not in register"
        by_system.setdefault(system, {})
        by_system[system][cat] = by_system[system].get(cat, 0) + 1

    # 1. Executive page ------------------------------------------------------
    flow.append(Paragraph("Cryptographic inventory and quantum-risk assessment", styles["title"]))
    flow.append(Paragraph(f"{_esc(name)} · scan {_esc(scan.get('scan_id', '')[:8])} · {_esc(scan.get('timestamp'))}"
                          f" · threat model {_esc(threat_model['version'])}", styles["subtitle"]))
    flow.append(_metric_table([
        ("Assets", str(len(assets)), INK), ("Quantum-vulnerable", str(len(vulnerable)), DANGER),
        ("Exposed under every reading", str(categories.get("certain", 0)), DANGER),
        ("Classically broken", str(len(broken)), colors.HexColor("#6D28D9")),
        ("Drift findings", str(len(drift)), colors.HexColor("#C2410C")),
    ], styles))
    flow.append(Spacer(1, 8))
    first_steps = []
    prereqs = recommendations.get("prerequisites") or {}
    if prereqs:
        steps = sorted({s["step"] for v in prereqs.values() for s in v})
        first_steps.append(f"Upgrade the libraries that block PQC: {_esc(', '.join(steps[:6]))}.")
    if categories.get("certain"):
        top = next((a for a in vulnerable if a.mosca_category == "certain"), None)
        if top is not None:
            first_steps.append(f"Start with the {categories['certain']} assets exposed under every CRQC reading; "
                               f"the first is <b>{_esc(top.name[:70])}</b>.")
    if gated:
        first_steps.append(f"Send the {len(clauses)} supplier clause drafts in section 3 to legal review: "
                           f"{_esc(', '.join(g['who'] for g in gated[:4]))} must ship PQC first.")
    if broken:
        first_steps.append(f"Replace the {len(broken)} classically broken items now; they are not a quantum question.")
    flow.append(Paragraph("What to do first", styles["h2"]))
    for i, step in enumerate(first_steps or ["No quantum-vulnerable assets were found in this scan."], 1):
        flow.append(Paragraph(f"{i}. {step}", styles["body"]))
    flow.append(Paragraph(
        "Scope: " + _esc(", ".join(sorted({(a.raw_details or {}).get("system") or "not in register" for a in assets}))) +
        ". Every figure in this report traces to a scan finding, the benchmark file, or a cited source "
        "(section 6).", styles["small"]))

    # 2. Mosca -------------------------------------------------------------
    flow.append(Paragraph("Mosca by system", styles["h2"]))
    flow.append(Paragraph(
        "Exposed when X + Y exceeds Z, where X is how long the data must stay secret (from the declared data "
        "classes), Y is when migration finishes (effort, vendor lead time, statutory deadline) and Z is when a "
        "cryptographically relevant quantum computer arrives: shifted per primitive by its logical-qubit "
        "requirement and measured from the report date. 'Certain' means exposed under every reading of the expert "
        "elicitation.", styles["body"]))
    if by_system:
        flow.append(_mosca_chart(by_system))
    else:
        flow.append(Paragraph("No quantum-vulnerable assets.", styles["small"]))

    # 3. Vendor-gated register --------------------------------------------
    flow.append(PageBreak())
    flow.append(Paragraph("Vendor- and provider-gated register", styles["h2"]))
    if gated:
        rows = [["Who must act", "Kind", "Assets", "Needs", "Earliest milestone"]]
        for g in gated:
            rows.append([Paragraph(_esc(g["who"]), styles["cell"]), g["kind"].replace("_", " "), str(g["count"]),
                         Paragraph(_esc(", ".join(g["capabilities"])), styles["cell"]),
                         str(g.get("earliest_deadline") or "")])
        flow.append(_table(rows, [42 * mm, 34 * mm, 14 * mm, 52 * mm, 28 * mm], styles))
        flow.append(Paragraph(f"{len(clauses)} procurement clause drafts are attached to the register in the "
                              "application, marked DRAFT FOR LEGAL REVIEW. They follow the DST task force's "
                              "recommendation to put quantum-safe requirements into procurement.", styles["small"]))
    else:
        flow.append(Paragraph("No asset is gated on a vendor or provider.", styles["small"]))

    # 4. Recommendations ---------------------------------------------------
    flow.append(Paragraph(f"Top recommendations ({_esc(recommendations.get('profile'))} profile)", styles["h2"]))
    items = [i for i in recommendations.get("items", []) if i["quantum_vulnerable"] or i["need"] in
             ("replace_now", "library_upgrade", "secret_exposure")]
    items.sort(key=lambda i: (i["priority_rank"] or 10**9))
    rows = [["#", "Asset", "Move to", "Measured cost on this host", "First"]]
    for item in items[:14]:
        latency = (item.get("cost") or {}).get("latency") or []
        cost = "; ".join(f"{r['algorithm']} {r['operation']} {r['microseconds']:.0f} µs" for r in latency[:2]) \
            or ((item.get("cost") or {}).get("latency_note") or "")
        first = "; ".join(s["step"] for s in item.get("prerequisites", [])[:2]) or item["who_can_fix"]["key"].replace("_", " ")
        rows.append([str(item["priority_rank"]), Paragraph(_esc(item["asset"][:60]), styles["cell"]),
                     Paragraph(_esc(item["recommended"]), styles["cell"]), Paragraph(_esc(cost[:90]), styles["cell"]),
                     Paragraph(_esc(first[:70]), styles["cell"])])
    flow.append(_table(rows, [9 * mm, 52 * mm, 33 * mm, 42 * mm, 34 * mm], styles))
    bench = recommendations.get("bench") or {}
    flow.append(Paragraph(
        (f"Latency measured {_esc(bench.get('measured_at'))} on {_esc((bench.get('host') or {}).get('processor'))}."
         if bench.get("measured") else "Latency not measured on this host; only FIPS sizes are shown."),
        styles["small"]))

    # 5. Drift -------------------------------------------------------------
    flow.append(Paragraph("Drift: declared versus observed", styles["h2"]))
    if drift:
        rows = [["Rule", "Severity", "Where", "Declared", "Observed"]]
        for d in drift[:14]:
            rows.append([d["rule"], d["severity"], Paragraph(_esc(d["subject"][:40]), styles["cell"]),
                         Paragraph(_esc(d["declared"]["value"][:50]), styles["cell"]),
                         Paragraph(_esc(d["observed"]["value"][:50]), styles["cell"])])
        flow.append(_table(rows, [12 * mm, 18 * mm, 44 * mm, 48 * mm, 48 * mm], styles))
    else:
        flow.append(Paragraph("No drift: declared configuration and observed behaviour agree where both exist.",
                              styles["small"]))

    # 6. Methodology --------------------------------------------------------
    flow.append(PageBreak())
    flow.append(Paragraph("Methodology and sources", styles["h2"]))
    flow.append(Paragraph(
        f"Threat model {_esc(threat_model['version'])}: {_esc(threat_model['gri_edition'])}. Per-primitive shift "
        f"delta = D x log2(L_p / L_ref) with D = {threat_model['doubling_years']:g} years (a stated assumption). "
        "Rows without a verified estimate use the reference curve.", styles["body"]))
    rows = [["Primitive", "Logical qubits", "Shift (yr)", "Source"]]
    for row in threat_model["rows"]:
        rows.append([Paragraph(_esc(row["label"]), styles["cell"]), str(row.get("logical_qubits") or "not established"),
                     f"{row['shift']:+.2f}", Paragraph(_esc((row.get("source") or row.get("note") or "")[:110]),
                                                        styles["cell"])])
    flow.append(_table(rows, [38 * mm, 22 * mm, 16 * mm, 94 * mm], styles))
    flow.append(Paragraph("Data shelf life (X) defaults, to be confirmed with each data owner: " + _esc("; ".join(
        f"{v['label']} {v['years']} yr" for v in data_classes.values())) + ".", styles["small"]))
    flow.append(Spacer(1, 6))
    for cid, c in sorted(citations.items()):
        flow.append(Paragraph(f"[{_esc(cid)}] {_esc(c['label'])} {_esc(c['url'])}", styles["small"]))
    flow.append(Paragraph(
        "Limits: static analysis finds call sites, not dataflow; library versions are reported only when a banner "
        "or lockfile states them; recorded observations say what was true when recorded; cloud-provider PQC "
        "availability and several library thresholds are marked VERIFY in the knowledge base.", styles["small"]))

    # 7. Evidence --------------------------------------------------------------
    flow.append(Paragraph("Evidence", styles["h2"]))
    manifest_hash = hashlib.sha256(json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    signature = manifest.get("signature") or {}
    rows = [["Item", "Value"],
            ["Manifest SHA-256", manifest_hash],
            ["CBOM SHA-256 (CycloneDX " + _esc(scan.get("cbom_spec", "1.7")) + ")", manifest.get("cbom_sha256", "")],
            ["SARIF SHA-256", manifest.get("sarif_sha256", "")],
            ["Signature", f"{signature.get('alg')} ({signature.get('provider')})"],
            ["Signing key SHA-256", signature.get("public_key_sha256", "")],
            ["Verification", f"{'valid' if manifest_check.get('valid') else 'NOT VALID'}: {manifest_check.get('reason')}"]]
    flow.append(_table([rows[0]] + [[Paragraph(_esc(a), styles["cell"]), Paragraph(_esc(b), styles["cell"])]
                                    for a, b in rows[1:]], [45 * mm, 125 * mm], styles))

    doc.build(flow)
    return buffer.getvalue()
