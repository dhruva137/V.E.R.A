"""M3 - Threat model.

Builds a survival function S_Z(t) = P(no cryptographically relevant quantum
computer by year t) from the expert elicitation published in the Global Risk
Institute *Quantum Threat Timeline Report 2025* (Mosca & Piani).

WHAT THIS IS
------------
The GRI report is a subjective prior elicited from ~26 experts. It is not a
measurement. Anyone who reports a single number off it is overclaiming, so we
carry three curves - an optimistic, a median and a pessimistic reading of the
same elicitation - and report every downstream score as a band across them.

ANCHOR POINTS
-------------
The published figures the blueprint cites:

  - ~34% probability of a CRQC by 2030 (t = 5)
  - 28-49% within 10 years (t = 10), depending on how responses are pooled
  - 69% of respondents assign >= 50% at 15 years (t = 15)
  - 92% of respondents assign >= 50% at 20 years (t = 20)

The 15- and 20-year figures are *shares of respondents crossing a 50% threshold*,
not pooled probabilities. Reading them directly as P(CRQC) - as a naive
implementation does - inflates the tail badly. We use them as an ordering signal
and place the pooled probability between the 10-year band and the respondent
share.

FUNCTIONAL FORM
---------------
Shape-preserving monotone cubic (PCHIP) through the elicited anchors, so the
curve reproduces the elicitation exactly rather than smoothing over it, and is
monotone by construction. Beyond the last anchor it continues on a fitted
Weibull tail so horizons past 2055 stay well defined.

A Weibull is also fitted across all anchors and reported as a parametric summary
(`parametric_summary`), with its residuals, because reviewers ask for one. It is
not used for scoring. `survival_families()` exposes several unrelated monotone
families used by the sensitivity analysis to show the asset ordering does not
depend on any of this (blueprint Claim 2).

`_assert_monotone` runs at import so a future edit cannot silently reintroduce a
non-monotone curve.
"""

from __future__ import annotations

import numpy as np
from scipy.interpolate import PchipInterpolator
from scipy.optimize import curve_fit

# t is years from the 2025 elicitation baseline.
BASELINE_YEAR = 2025

# (t, P(CRQC by t)) per interpretation. Survival is 1 - P.
# t = 0 is pinned at P = 0: there is no CRQC today.
ANCHORS_T = np.array([0.0, 5.0, 10.0, 15.0, 20.0, 30.0])

# Optimistic reading: CRQC arrives late. Low end of the 10-year band; the
# 15/20-year respondent shares treated as upper bounds, not pooled probabilities.
P_OPTIMISTIC = np.array([0.0, 0.22, 0.28, 0.50, 0.70, 0.88])

# Median reading: the headline 2030 figure, midpoint of the 10-year band.
P_MEDIAN = np.array([0.0, 0.34, 0.385, 0.62, 0.82, 0.95])

# Pessimistic reading: high end of the 10-year band, respondent shares taken
# close to face value.
P_PESSIMISTIC = np.array([0.0, 0.45, 0.49, 0.70, 0.92, 0.99])

# Provenance surfaced through the API so the UI never shows a number without
# being able to say where it came from.
SOURCE = ("Global Risk Institute, Quantum Threat Timeline Report 2025 (7th edition, Mosca & Piani, "
          "published 9 March 2026)")
ELICITATION_N = 26
CAVEAT = (
    "Subjective prior elicited from approximately 26 experts. Not a measurement. "
    "Absolute risk levels are reported as a band across three readings of the same "
    "elicitation. Asset ordering within each axis does not depend on this curve at "
    "all - see /api/sensitivity."
)


def weibull_survival(t, lam, k):
    """S(t) = exp(-(t/lambda)^k)."""
    t = np.maximum(np.asarray(t, dtype=float), 0.0)
    return np.exp(-((t / lam) ** k))


def _assert_monotone(name: str, probs: np.ndarray) -> None:
    """A survival function cannot increase, so P(CRQC by t) cannot decrease."""
    if np.any(np.diff(probs) < 0):
        raise ValueError(
            f"{name} anchor points are non-monotone: {probs.tolist()}. "
            "P(CRQC by t) must be non-decreasing in t."
        )
    if np.any(probs < 0) or np.any(probs > 1):
        raise ValueError(f"{name} anchors must lie in [0, 1]: {probs.tolist()}")


_ENSEMBLE = (
    ("optimistic", P_OPTIMISTIC),
    ("median", P_MEDIAN),
    ("pessimistic", P_PESSIMISTIC),
)

for _name, _p in _ENSEMBLE:
    _assert_monotone(_name, _p)

# The three readings must also be ordered against each other at every anchor.
if not (np.all(P_OPTIMISTIC <= P_MEDIAN) and np.all(P_MEDIAN <= P_PESSIMISTIC)):
    raise ValueError("Ensemble is not ordered optimistic <= median <= pessimistic")


class ThreatModel:
    """Three-member survival ensemble over the GRI 2025 elicitation.

    `survival(t)` returns `(optimistic, median, pessimistic)` survival
    probabilities. Optimistic is the highest survival (CRQC latest, lowest
    risk); pessimistic is the lowest survival (CRQC soonest, highest risk).
    """

    def __init__(self):
        self._interp: dict[str, PchipInterpolator] = {}
        self._weibull: dict[str, tuple[float, float]] = {}
        self._weibull_resid: dict[str, dict[str, float]] = {}
        self._tail_scale: dict[str, float] = {}

        t_last = float(ANCHORS_T[-1])

        for name, probs in _ENSEMBLE:
            survival = 1.0 - probs
            self._interp[name] = PchipInterpolator(ANCHORS_T, survival, extrapolate=False)

            # Weibull over all anchors: reported as a parametric summary, and
            # reused as the tail beyond the last anchor.
            popt = self._fit_weibull(survival)
            self._weibull[name] = popt
            self._weibull_resid[name] = self._residual_stats(survival, popt)

            # Rescale the tail so it joins the interpolant continuously at the
            # last anchor instead of stepping.
            w_last = float(weibull_survival(t_last, *popt))
            self._tail_scale[name] = (float(survival[-1]) / w_last) if w_last > 0 else 1.0

    @staticmethod
    def _fit_weibull(survival_targets: np.ndarray) -> tuple[float, float]:
        # Bounds keep lambda positive and k in a range that stays a plausible
        # arrival shape; unbounded, curve_fit can wander to a degenerate fit.
        popt, _ = curve_fit(
            weibull_survival,
            ANCHORS_T,
            survival_targets,
            p0=[14.0, 1.6],
            bounds=([1.0, 0.5], [60.0, 6.0]),
            maxfev=20000,
        )
        return float(popt[0]), float(popt[1])

    @staticmethod
    def _residual_stats(survival_targets: np.ndarray, popt) -> dict[str, float]:
        predicted = weibull_survival(ANCHORS_T, *popt)
        resid = predicted - survival_targets
        return {
            "rmse": round(float(np.sqrt(np.mean(resid**2))), 6),
            "max_abs_error": round(float(np.max(np.abs(resid))), 6),
        }

    def _survival_one(self, name: str, t: float) -> float:
        t_max = float(ANCHORS_T[-1])
        if t <= t_max:
            value = float(self._interp[name](t))
        else:
            lam, k = self._weibull[name]
            value = float(weibull_survival(t, lam, k) * self._tail_scale[name])
        return min(max(value, 0.0), 1.0)

    def survival(self, t: float) -> tuple[float, float, float]:
        """(optimistic, median, pessimistic) survival at horizon t years."""
        if t is None or t < 0:
            return 1.0, 1.0, 1.0
        opt = self._survival_one("optimistic", t)
        med = self._survival_one("median", t)
        pes = self._survival_one("pessimistic", t)
        # Ordered by construction; clamp anyway so a pathological horizon can
        # never produce an inverted band downstream.
        lo, hi = min(opt, pes), max(opt, pes)
        return opt, min(max(med, lo), hi), pes

    def failure_prob(self, t: float) -> tuple[float, float, float]:
        """P(CRQC by t) under each member, ordered low risk to high risk."""
        opt, med, pes = self.survival(t)
        return 1.0 - opt, 1.0 - med, 1.0 - pes

    @property
    def parametric_summary(self) -> dict[str, dict[str, float]]:
        """Weibull fit reported alongside the interpolant. Not used for scoring."""
        return {
            name: {
                "lambda": round(lam, 4),
                "k": round(k, 4),
                **self._weibull_resid[name],
            }
            for name, (lam, k) in self._weibull.items()
        }

    def get_ensemble_data(self, max_years: int = 30, step: float = 0.5) -> dict:
        """Curve data for the front end, plus full provenance."""
        curves = []
        n_points = int(max_years / step) + 1
        for i in range(n_points):
            t = round(i * step, 4)
            opt, med, pes = self.survival(t)
            curves.append(
                {
                    "year": round(BASELINE_YEAR + t, 4),
                    "t": t,
                    "optimistic_sz": round(opt, 6),
                    "median_sz": round(med, 6),
                    "pessimistic_sz": round(pes, 6),
                    "optimistic_prob": round(1.0 - opt, 6),
                    "median_prob": round(1.0 - med, 6),
                    "pessimistic_prob": round(1.0 - pes, 6),
                    # Recharts renders a shaded band from a [low, high] pair.
                    "band": [round(1.0 - opt, 6), round(1.0 - pes, 6)],
                }
            )

        anchors = [
            {
                "t": float(t),
                "year": BASELINE_YEAR + int(t),
                "optimistic_prob": float(o),
                "median_prob": float(m),
                "pessimistic_prob": float(p),
            }
            for t, o, m, p in zip(ANCHORS_T, P_OPTIMISTIC, P_MEDIAN, P_PESSIMISTIC)
        ]

        return {
            "curves": curves,
            "anchors": anchors,
            "baseline_year": BASELINE_YEAR,
            "functional_form": (
                "Shape-preserving monotone cubic (PCHIP) through elicited anchors; "
                "fitted Weibull tail beyond t = 30"
            ),
            "parametric_summary": self.parametric_summary,
            "source": SOURCE,
            "elicitation_respondents": ELICITATION_N,
            "caveat": CAVEAT,
        }


# --------------------------------------------------------------------------
# Alternative monotone survival families.
#
# Used only by engine.sensitivity to demonstrate blueprint Claim 2: ranking
# within an axis is invariant to the choice of S_Z, because 1 - S_Z is monotone
# increasing and the ranking therefore depends only on the horizon argument.
# These are deliberately unrelated functional forms, not perturbations of the
# fitted curve, so agreement is a real result rather than an artefact.
# --------------------------------------------------------------------------


def survival_families() -> dict[str, dict]:
    """Monotone-decreasing S(t) with S(0) = 1, from unrelated functional forms.

    Each entry is `{"label": str, "fn": callable}`. The parameters are chosen so
    every family crosses S = 0.5 somewhere in the 2035-2045 range, i.e. they are
    all *plausible* readings - but their shapes differ substantially, which is
    the point: if the ranking survives all of them, it does not depend on the
    curve.
    """
    import math

    def exponential(rate: float):
        # Constant hazard. Memoryless - the least structured assumption possible.
        return lambda t: math.exp(-rate * max(t, 0.0))

    def weibull(lam: float, k: float):
        # Increasing hazard for k > 1: arrival gets more likely as effort compounds.
        return lambda t: math.exp(-((max(t, 0.0) / lam) ** k))

    def gompertz(a: float, b: float):
        # Exponentially increasing hazard - the aggressive-breakthrough reading.
        return lambda t: math.exp(-(a / b) * (math.exp(b * max(t, 0.0)) - 1.0))

    def log_logistic(alpha: float, beta: float):
        # Hazard rises then falls - "if it does not happen soon it stalls".
        return lambda t: 1.0 / (1.0 + (max(t, 0.0) / alpha) ** beta)

    gri = ThreatModel()

    return {
        "gri_median": {
            "label": "GRI 2025 median (PCHIP)",
            "fn": lambda t: gri.survival(t)[1],
        },
        "gri_optimistic": {
            "label": "GRI 2025 optimistic (PCHIP)",
            "fn": lambda t: gri.survival(t)[0],
        },
        "gri_pessimistic": {
            "label": "GRI 2025 pessimistic (PCHIP)",
            "fn": lambda t: gri.survival(t)[2],
        },
        "exponential": {
            "label": "Exponential, constant hazard (median 2043)",
            "fn": exponential(0.0385),
        },
        "weibull_steep": {
            "label": "Weibull, sharply increasing hazard (k = 3.5)",
            "fn": weibull(20.0, 3.5),
        },
        "gompertz": {
            "label": "Gompertz, exponentially increasing hazard",
            "fn": gompertz(0.012, 0.115),
        },
        "log_logistic": {
            "label": "Log-logistic, non-monotone hazard",
            "fn": log_logistic(16.0, 2.2),
        },
    }
