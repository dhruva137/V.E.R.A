"""What happened to one asset, stage by stage, with the formulas applied.

WHY THIS REPLACES A FLOWCHART
-----------------------------
A block diagram tells you the pipeline has six stages. It cannot tell you what
happened to *your* root CA, which is the only question an operator actually
has. This module answers that: pick an asset, and get the ordered record of every
transformation applied to it, each with the formula, the substituted values, and
the result.

The formulas live here rather than in the inventory for a reason. In a table of
four hundred rows a formula is noise; at the moment somebody asks "why is this
ranked third" it is the entire answer.
"""

from __future__ import annotations


def _fmt(value, places: int = 4) -> str:
    try:
        return f"{float(value):.{places}f}"
    except (TypeError, ValueError):
        return str(value)


def build(asset, evidence: dict, scored: dict, mosca_reading: dict | None = None) -> list[dict]:
    """The ordered journey of one asset through the scan pipeline.

    Every step carries formula, substitution and result, so a number on screen
    can always be checked by hand.
    """
    steps: list[dict] = []
    asset_id = str(getattr(asset, "id", "?"))
    readings = (evidence or {}).get("readings", [])
    planes = (evidence or {}).get("planes", {})

    steps.append({
        "stage": "intake",
        "title": "Admitted",
        "formula": "accept if id present and unique and 0 <= QIRS <= 1",
        "substitution": f"id={asset_id[:12]}  qirs={_fmt(getattr(asset, 'qirs', 0))}",
        "result": "accepted",
        "detail": "Malformed input is quarantined with a reason, never scored.",
    })

    steps.append({
        "stage": "corroborate",
        "title": f"{len(readings)} reading(s) across {len(planes)} evidence plane(s)",
        "formula": "c = 1 - prod_planes (1 - max confidence in plane)",
        "substitution": "  ".join(f"{plane}={_fmt(value, 2)}" for plane, value in planes.items()) or "none",
        "result": f"confidence = {_fmt((evidence or {}).get('confidence', 0), 2)}",
        "detail": (
            "Two readings from the same plane are one view of one artefact, so only "
            "the strongest counts. Confidence rises only when a different plane agrees."
        ),
    })

    x_c = float(getattr(asset, "x_c", 0.0) or 0.0)
    x_i = float(getattr(asset, "x_i", 0.0) or 0.0)
    y = float(getattr(asset, "y", 0.0) or 0.0)

    steps.append({
        "stage": "score",
        "title": "Confidentiality axis (HNDL)",
        "formula": "H = S * E * [1 - S_Z(X_c + Y)]",
        "substitution": (
            f"S={_fmt(getattr(asset, 's', 0), 2)}  E={_fmt(getattr(asset, 'e', 0), 2)}  "
            f"X_c+Y={_fmt(x_c, 2)}+{_fmt(y, 2)}={_fmt(x_c + y, 2)} yr"
        ),
        "result": f"H = {_fmt(getattr(asset, 'h_score', 0))}",
        "detail": (
            "Additive in migration time: every month of slip extends the window "
            "in which harvestable traffic is still being generated."
        ),
    })

    steps.append({
        "stage": "score",
        "title": "Integrity axis (TNFL)",
        "formula": "T = C * [1 - S_Z(min(X_i, Y))]",
        "substitution": (
            f"C={_fmt(getattr(asset, 'c', 0), 2)}  "
            f"min(X_i,Y)=min({_fmt(x_i, 2)},{_fmt(y, 2)})={_fmt(min(x_i, y), 2)} yr"
        ),
        "result": f"T = {_fmt(getattr(asset, 't_score', 0))}",
        "detail": (
            "Capped by migration time: once Y exceeds X_i the window stops "
            "growing, because the anchor retires before a forgery matters. This "
            "is why a root CA cannot be ranked on confidentiality alone."
        ),
    })

    band = (scored or {}).get("band", {})
    steps.append({
        "stage": "score",
        "title": "Composite and band",
        "formula": "QIRS = w_H*H + w_T*T;  band = QIRS under optimistic..pessimistic survival",
        "substitution": (
            f"H={_fmt(getattr(asset, 'h_score', 0))}  T={_fmt(getattr(asset, 't_score', 0))}"
        ),
        "result": (
            f"QIRS = {_fmt((scored or {}).get('qirs', getattr(asset, 'qirs', 0)))}  "
            f"[{_fmt(band.get('low', 0))}, {_fmt(band.get('high', 0))}]"
        ),
        "detail": "The band is the spread between readings of one expert survey, not a statistical interval.",
    })

    if mosca_reading and mosca_reading.get("applicable"):
        z = mosca_reading["z"]
        margins = mosca_reading["margin_years"]
        steps.append({
            "stage": "order",
            "title": f"Mosca ({mosca_reading['axis']} axis)",
            "formula": (
                ("exposed if X_c + Y > Z" if mosca_reading["axis"] == "confidentiality"
                 else "exposed if min(X_i, Y) > Z")
                + ";  Y = max(effort + lead, deadline - now)"
            ),
            "substitution": (
                f"Y_plan={_fmt(mosca_reading['y_plan'], 1)} yr  "
                f"Y_now={_fmt(mosca_reading['y_effort'], 1)} yr  "
                f"horizon={_fmt(mosca_reading['horizon_years'], 1)} yr  "
                f"Z={_fmt(z['pessimistic'], 1)}/{_fmt(z['median'], 1)}/{_fmt(z['optimistic'], 1)} yr"
            ),
            "result": (
                f"{mosca_reading['category']}  margin(median)={_fmt(margins['median'], 1)} yr"
                + (f"  ->  {mosca_reading['category_if_started_now']} if started today"
                   if mosca_reading.get("starting_now_helps") else "")
            ),
            "detail": mosca_reading["explanation"],
        })

    slack = float(getattr(asset, "slack_months", 0.0) or 0.0)
    steps.append({
        "stage": "order",
        "title": "Statutory slack (shown, not used for order)",
        "formula": "slack = deadline - (today + Y)",
        "substitution": (
            f"deadline={getattr(asset, 'statutory_deadline_year', '?')}  Y={_fmt(y, 2)} yr"
        ),
        "result": f"{_fmt(slack, 1)} months",
        "detail": (
            "Negative slack: this asset cannot meet its milestone even starting today."
            if slack < 0 else "Time remains against the statutory milestone."
        ),
    })

    flag = (scored or {}).get("flag_reason")
    steps.append({
        "stage": "order",
        "title": "Ranked" + (" (flagged)" if flag else ""),
        "formula": "Mosca category first, then QIRS descending",
        "substitution": f"category={(scored or {}).get('mosca_category', '-')}",
        "result": f"rank #{(scored or {}).get('rank', '-')}",
        "detail": flag or "Evidence is corroborated well enough to act on.",
    })

    return steps
