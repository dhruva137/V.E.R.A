"""Mosca's inequality, made explicit per asset.

    exposed  <=>  X + Y > Z

X is how long the protected thing must stay safe, Y how long until it is
actually migrated, Z when a cryptographically relevant quantum computer (CRQC)
arrives.

TWO AXES, TWO INEQUALITIES
--------------------------
The classic statement is about confidentiality: traffic recorded until migration
finishes must stay secret for X_c years after, so the window is X_c + Y.
Signatures fail differently. A forgery only matters while the key is still
trusted, and only if migration has not finished, so the window is min(X_i, Y):

    confidentiality (HNDL)   exposed <=> X_c + Y      > Z
    integrity       (TNFL)   exposed <=> min(X_i, Y)  > Z

Each asset is judged on the axis that dominates its risk score - a root CA is an
integrity problem, a TLS key exchange is a confidentiality problem.

Y IS WHEN, NOT HOW LONG
-----------------------
The per-asset profile says how much *effort* a migration takes once started. Y
in Mosca's sense is how long until the asset is *actually* migrated, which also
depends on when it starts and on whether it can start at all:

    Y_effort = profile effort + vendor lead time (if the HSM / provider has not
               shipped a post-quantum mechanism, nothing can happen until it does)
    Y_plan   = max(Y_effort, statutory deadline - now)

Y_plan is what an organisation that migrates on the regulator's schedule will
actually live with, so the category is reported on it. The category if work
started today (Y = Y_effort) is reported beside it, because the difference
between the two is the whole argument for starting now.

Z IS NOT A DATE
---------------
Z comes from the expert-elicited survival ensemble in engine/threat_model.py.
Each reading (optimistic / median / pessimistic) gives the year by which a CRQC
is more likely than not, counted from the report the experts answered in. Two
corrections make it per asset and per day:

    clock      years elapsed since the report date are subtracted, so Z shrinks
               as time passes (the only way a score moves without new evidence)
    primitive  a shift from engine/quantum_resources.py: P-256 needs fewer
               logical qubits than RSA-2048, so its Z is earlier

An asset exposed even under the *latest* reading is
"certain"; under the median, "likely"; only under the earliest, "possible";
otherwise "clear". That is the categorisation the problem statement asks for,
and it keeps the disagreement between readings visible instead of averaging it
away.
"""

from __future__ import annotations

from datetime import datetime, timezone
from functools import lru_cache

from engine.regulatory import deadline_point

READINGS = ("optimistic", "median", "pessimistic")

#: Ordered from most to least urgent. Used for sorting and for the UI legend.
CATEGORIES = ("certain", "likely", "possible", "clear")
CATEGORY_LABEL = {
    "certain": "Exposed under every reading",
    "likely": "Exposed under the median reading",
    "possible": "Exposed only if CRQC comes early",
    "clear": "Migration completes before CRQC",
    "not_applicable": "Not Shor-vulnerable",
}

#: Years added to Y when a vendor or provider must ship a PQC mechanism before
#: the asset can be touched. A stated assumption, overridable per call.
DEFAULT_VENDOR_LEAD_YEARS = 2.0

_SEARCH_MAX_YEARS = 80.0


@lru_cache(maxsize=1)
def _shared_model():
    from engine.threat_model import ThreatModel

    return ThreatModel()


def current_year() -> float:
    """Fractional calendar year now, e.g. 2026.67 in late August."""
    now = datetime.now(timezone.utc)
    return now.year + (now.timetuple().tm_yday - 1) / 365.25


def arrival_years(threat_model=None) -> dict[str, float]:
    """Years from now at which each reading puts P(CRQC) at 50%.

    Found by bisection on the survival curve, which is monotone decreasing.
    """
    model = threat_model or _shared_model()
    arrivals: dict[str, float] = {}
    for index, reading in enumerate(READINGS):
        low, high = 0.0, _SEARCH_MAX_YEARS
        if model.survival(high)[index] > 0.5:
            arrivals[reading] = high
            continue
        for _ in range(60):
            mid = (low + high) / 2.0
            if model.survival(mid)[index] > 0.5:
                low = mid
            else:
                high = mid
        arrivals[reading] = round((low + high) / 2.0, 3)
    return arrivals


def _category(margins: dict[str, float]) -> str:
    # The optimistic reading has the latest Z, so exposure under it holds under all.
    if margins["optimistic"] > 0:
        return "certain"
    if margins["median"] > 0:
        return "likely"
    if margins["pessimistic"] > 0:
        return "possible"
    return "clear"


def is_gated(asset) -> bool:
    """True when a vendor or provider must ship PQC support before migration can start."""
    details = getattr(asset, "raw_details", {}) or {}
    return bool(
        details.get("change_blocked")
        or details.get("ownership") in {"vendor_firmware_gated", "provider_gated"}
    )


def _axis_reading(horizon: float, z: dict[str, float]) -> dict:
    margins = {r: round(horizon - z[r], 3) for r in READINGS}
    return {"horizon_years": round(horizon, 3), "margin_years": margins, "category": _category(margins)}


def _report_year() -> float:
    """Fractional year of the elicitation the ensemble is anchored to."""
    from engine.quantum_resources import current_version

    y, m, d = (int(p) for p in current_version()["report_date"].split("-"))
    return y + (datetime(y, m, d).timetuple().tm_yday - 1) / 365.25


def clock(now_year: float) -> dict:
    """Years elapsed since the report the survival curve was elicited in.

    The experts said "within 10 years" on the report date; a year later the
    same answer means within 9. Before the report date the clock is zero.
    """
    report = _report_year()
    return {"report_year": round(report, 3), "now_year": round(now_year, 3),
            "elapsed_years": round(max(now_year - report, 0.0), 3)}


def primitive_of(asset) -> tuple[str | None, int | None, str | None]:
    """(algorithm, key size, curve) the quantum-resources table is keyed on."""
    algorithm = getattr(asset, "algorithm", None) or getattr(asset, "key_exchange", None)
    suite = getattr(asset, "suite_breakdown", None) or {}
    if not algorithm and suite:
        algorithm = suite.get("key_exchange") or suite.get("authentication")
    curve = getattr(asset, "curve", None) or (getattr(asset, "raw_details", None) or {}).get("curve")
    return algorithm, getattr(asset, "key_size", None), curve


def assess(
    asset,
    threat_model=None,
    arrivals: dict[str, float] | None = None,
    *,
    now_year: float | None = None,
    vendor_lead_years: float = DEFAULT_VENDOR_LEAD_YEARS,
) -> dict:
    """The full Mosca reading for one asset, with every input shown.

    Z per reading = (arrival from the report date) - (years elapsed since it)
                    + (this primitive's shift from the quantum-resources table).
    """
    from engine.quantum_resources import shift_for

    z_report = arrivals or arrival_years(threat_model)
    x_c = float(getattr(asset, "x_c", 0.0) or 0.0)
    x_i = float(getattr(asset, "x_i", 0.0) or 0.0)
    effort = float(getattr(asset, "y", 0.0) or 0.0)
    now = current_year() if now_year is None else float(now_year)
    tick = clock(now)
    shift = shift_for(*primitive_of(asset))
    z = {r: round(max(z_report[r] - tick["elapsed_years"], 0.0) + shift["delta_years"], 3) for r in READINGS}
    x_basis = ((getattr(asset, "raw_details", None) or {}).get("classification") or {}).get("lifetime")

    if not getattr(asset, "quantum_vulnerable", False):
        return {
            "applicable": False,
            "category": "not_applicable",
            "label": CATEGORY_LABEL["not_applicable"],
            "x_c": x_c, "x_i": x_i, "y_effort": effort, "z": z,
        }

    gated = is_gated(asset)
    y_effort = effort + (vendor_lead_years if gated else 0.0)
    deadline = getattr(asset, "statutory_deadline_year", None)
    y_plan = max(y_effort, deadline_point(deadline) - now) if deadline else y_effort

    plan_c = _axis_reading(x_c + y_plan, z)
    plan_i = _axis_reading(min(x_i, y_plan), z)
    now_c = _axis_reading(x_c + y_effort, z)
    now_i = _axis_reading(min(x_i, y_effort), z)

    t = float(getattr(asset, "t_score", 0.0) or 0.0)
    h = float(getattr(asset, "h_score", 0.0) or 0.0)
    axis = "integrity" if t > h else "confidentiality"
    plan = plan_i if axis == "integrity" else plan_c
    started_now = now_i if axis == "integrity" else now_c
    helps = category_rank(started_now["category"]) > category_rank(plan["category"])

    # P(CRQC before the horizon ends) per reading: 1 - S_p(elapsed + horizon).
    model = threat_model or _shared_model()
    survival = model.survival(max(tick["elapsed_years"] + plan["horizon_years"] - shift["delta_years"], 0.0))
    probability = {r: round(1.0 - float(s), 4) for r, s in zip(READINGS, survival)}

    return {
        "applicable": True,
        "axis": axis,
        "category": plan["category"],
        "label": CATEGORY_LABEL[plan["category"]],
        "category_if_started_now": started_now["category"],
        "starting_now_helps": helps,
        "x_c": x_c,
        "x_i": x_i,
        "y_effort": round(y_effort, 3),
        "y_plan": round(y_plan, 3),
        "vendor_gated": gated,
        "vendor_lead_years": vendor_lead_years if gated else 0.0,
        "deadline_year": deadline,
        "z": z,
        "z_reference": z_report,
        "z_shift": shift,
        "clock": tick,
        "x_basis": x_basis,
        "probability_crqc_within_horizon": probability,
        "horizon_years": plan["horizon_years"],
        "margin_years": plan["margin_years"],
        "confidentiality": {"formula": "X_c + Y > Z", "plan": plan_c, "if_started_now": now_c},
        "integrity": {"formula": "min(X_i, Y) > Z", "plan": plan_i, "if_started_now": now_i},
        "explanation": (
            f"{axis.capitalize()} axis. On the statutory schedule Y = {y_plan:.1f} yr, horizon "
            f"{plan['horizon_years']:.1f} yr vs CRQC {z['pessimistic']:.1f}-{z['optimistic']:.1f} yr: "
            f"{CATEGORY_LABEL[plan['category']].lower()}."
            + (f" Started today (Y = {y_effort:.1f} yr) it becomes "
               f"{CATEGORY_LABEL[started_now['category']].lower()}." if helps else "")
            + (f" Includes {vendor_lead_years:.0f} yr vendor lead time: the token or provider "
               "has no post-quantum mechanism yet." if gated else "")
        ),
    }


def category_rank(category: str) -> int:
    """Sort position of a category; unknown categories sort last."""
    try:
        return CATEGORIES.index(category)
    except ValueError:
        return len(CATEGORIES)
