"""Ordering-invariance and sensitivity analysis - blueprint Claim 2.

The claim as the blueprint states it: *within the HNDL axis, ranking by H is
ranking by X_c + Y, identical for any monotone survival function.*

**That statement is too strong, and this module measures where it breaks.**

    H = S . E . [1 - S_Z(X_c + Y)]

is a product of an asset-specific constant (S.E) and a curve-dependent factor.
Ranking by H equals ranking by X_c + Y only when S.E is *equal across the assets
being compared*. When it varies, changing the curve changes how a fixed
multiplier trades off against the horizon term, and pairs genuinely swap. A
concrete case: asset A with S.E = 1.0 at a 5-year horizon versus asset B with
S.E = 0.5 at 20 years. Under a curve where 1 - S_Z is 0.34 and 0.82, B outranks
A. Under a flatter curve giving 0.50 and 0.60, A outranks B.

So the defensible theorem is *conditional*:

    For any two assets with equal S.E, ranking by H is ranking by X_c + Y, for
    every monotone S_Z. Identically, for equal C, ranking by T is ranking by
    min(X_i, Y).

This module measures both readings:

  - **Stratified** - Spearman's rank correlation computed within groups of
    equal S.E (for HNDL) and equal C (for TNFL). This is the theorem, and it
    comes out at exactly 1.0.
  - **Global** - the same across the whole estate, ignoring strata. Below 1.0,
    and that is the honest limit of the claim.
  - **Composite** - the same on QIRS, which reintroduces S_Z twice over at
    different horizons and moves the most. Reported with the exact number of
    asset pairs whose order flips, because a count is easier to argue about
    than a coefficient.

Survival families are drawn from unrelated functional forms - exponential,
Weibull, Gompertz, log-logistic - not perturbations of the fitted curve, so
agreement is a result rather than an artefact of how they were generated.
"""

from __future__ import annotations

from scipy.stats import spearmanr

from engine.qirs import DEFAULT_W_H, DEFAULT_W_T
from engine.threat_model import survival_families
from models.schemas import CryptoAsset


def _rank_values(assets: list[CryptoAsset], survival) -> tuple[list[float], list[float], list[float]]:
    """Recompute H, T and QIRS for every asset under one survival function."""
    h_values, t_values, q_values = [], [], []
    for asset in assets:
        if not asset.quantum_vulnerable:
            h_values.append(0.0)
            t_values.append(0.0)
            q_values.append(0.0)
            continue
        h = asset.s * asset.e * (1.0 - survival(asset.x_c + asset.y))
        t = asset.c * (1.0 - survival(min(asset.x_i, asset.y)))
        h_values.append(h)
        t_values.append(t)
        q_values.append(DEFAULT_W_H * h + DEFAULT_W_T * t)
    return h_values, t_values, q_values


def _rho(a: list[float], b: list[float]) -> float:
    """Spearman's rank correlation between two score vectors."""
    # A constant vector has no order to disagree with - every asset scoring
    # identically is trivially in agreement - and the coefficient is undefined.
    if len(a) < 2 or len(set(a)) < 2 or len(set(b)) < 2:
        return 1.0
    rho, _ = spearmanr(a, b)
    return 1.0 if rho != rho else float(rho)  # nan guard


def reordered_pairs(a: list[float], b: list[float]) -> int:
    """Exact count of pairs strictly ordered one way by `a` and the other by `b`.

    Sort by (a, b): pairs tied in `a` then sit in ascending `b` and can never
    count. Every remaining strict inversion in the `b` sequence is a pair with
    a_i < a_j and b_i > b_j - a genuine reordering. Counted by merge sort in
    O(n log n), so this stays fast on a ten-thousand-asset estate. Ties in `b`
    are not reorderings and are not counted.
    """
    order = sorted(range(len(a)), key=lambda i: (a[i], b[i]))
    seq = [b[i] for i in order]

    def sort_count(values: list[float]) -> tuple[list[float], int]:
        if len(values) <= 1:
            return values, 0
        mid = len(values) // 2
        left, left_count = sort_count(values[:mid])
        right, right_count = sort_count(values[mid:])
        merged: list[float] = []
        inversions = left_count + right_count
        i = j = 0
        while i < len(left) and j < len(right):
            if right[j] < left[i]:
                # left is sorted, so every remaining left value exceeds right[j]
                inversions += len(left) - i
                merged.append(right[j])
                j += 1
            else:
                merged.append(left[i])
                i += 1
        merged.extend(left[i:])
        merged.extend(right[j:])
        return merged, inversions

    return sort_count(seq)[1]


def _stratified_rho(
    assets: list[CryptoAsset],
    key,
    base_values: list[float],
    other_values: list[float],
) -> tuple[float, int, int]:
    """Spearman's rho within strata of equal `key`, pooled as a worst case.

    Returns (minimum rho over strata, strata compared, assets in those strata).
    Strata of size one carry no ordering information and are skipped.
    """
    strata: dict = {}
    for index, asset in enumerate(assets):
        strata.setdefault(round(key(asset), 9), []).append(index)

    worst = 1.0
    compared = 0
    covered = 0
    for indices in strata.values():
        if len(indices) < 2:
            continue
        compared += 1
        covered += len(indices)
        rho = _rho(
            [base_values[i] for i in indices],
            [other_values[i] for i in indices],
        )
        worst = min(worst, rho)
    return worst, compared, covered


def analyse_invariance(assets: list[CryptoAsset]) -> dict:
    """Measure how much the ranking moves across survival families.

    Reports the conditional theorem (stratified) and the unconditional reading
    (global) separately, because only the first one is actually true.
    """
    scored = [a for a in assets if a.quantum_vulnerable]
    if len(scored) < 2:
        return {
            "sufficient_data": False,
            "message": "At least two quantum-vulnerable assets are needed to compare rankings.",
        }

    families = survival_families()
    baseline_name = "gri_median"
    baseline = families[baseline_name]["fn"]
    base_h, base_t, base_q = _rank_values(scored, baseline)

    comparisons = []
    strata_h = strata_t = 0
    for name, family in families.items():
        if name == baseline_name:
            continue
        h_values, t_values, q_values = _rank_values(scored, family["fn"])

        # The theorem's condition: equal S.E for HNDL, equal C for TNFL.
        rho_h_strat, strata_h, _ = _stratified_rho(
            scored, lambda a: a.s * a.e, base_h, h_values
        )
        rho_t_strat, strata_t, _ = _stratified_rho(
            scored, lambda a: a.c, base_t, t_values
        )

        comparisons.append(
            {
                "family": name,
                "label": family["label"],
                "rho_hndl_stratified": round(rho_h_strat, 6),
                "rho_tnfl_stratified": round(rho_t_strat, 6),
                "rho_hndl_global": round(_rho(base_h, h_values), 6),
                "rho_tnfl_global": round(_rho(base_t, t_values), 6),
                "rho_composite": round(_rho(base_q, q_values), 6),
                "reordered_pairs_composite": reordered_pairs(base_q, q_values),
            }
        )

    def worst(key: str) -> float:
        return min(c[key] for c in comparisons)

    min_h_strat = worst("rho_hndl_stratified")
    min_t_strat = worst("rho_tnfl_stratified")
    min_h_global = worst("rho_hndl_global")
    min_t_global = worst("rho_tnfl_global")
    min_composite = worst("rho_composite")

    total_pairs = len(scored) * (len(scored) - 1) // 2
    discordant = max(c["reordered_pairs_composite"] for c in comparisons)

    return {
        "sufficient_data": True,
        "assets_compared": len(scored),
        "baseline": families[baseline_name]["label"],
        "families_tested": len(comparisons) + 1,
        "comparisons": comparisons,
        "summary": {
            "min_rho_hndl_stratified": round(min_h_strat, 6),
            "min_rho_tnfl_stratified": round(min_t_strat, 6),
            "min_rho_hndl_global": round(min_h_global, 6),
            "min_rho_tnfl_global": round(min_t_global, 6),
            "min_rho_composite": round(min_composite, 6),
            "hndl_strata": strata_h,
            "tnfl_strata": strata_t,
            "total_pairs": total_pairs,
            "worst_case_discordant_pairs": discordant,
            "conditional_invariance_holds": min_h_strat > 0.9999 and min_t_strat > 0.9999,
        },
        "interpretation": {
            "theorem": (
                "For assets with equal S.E, ranking by H is ranking by X_c + Y, because "
                "1 - S_Z is monotone increasing and applying a monotone map to a common "
                "argument cannot reorder. Identically for T with equal C. Measured "
                f"within strata across {len(comparisons) + 1} unrelated survival families: "
                f"rho = {min_h_strat:.4f} (HNDL) and {min_t_strat:.4f} (TNFL). "
                "Exactly 1.0 is the theorem holding, not evidence for it."
            ),
            "limit_of_the_theorem": (
                "Across the whole estate the invariance is weaker, at "
                f"rho = {min_h_global:.4f} for HNDL, because S.E varies between assets. "
                "H is a product of an asset constant and a curve-dependent factor, so "
                "changing the curve changes how those two trade off. A high-sensitivity "
                "asset at a short horizon and a low-sensitivity asset at a long horizon "
                "can swap places. The blueprint states this claim without the equal-S.E "
                "condition; that version is not true and we do not rely on it."
            ),
            "cross_axis": (
                "The composite moves the most, at "
                f"rho = {min_composite:.4f} - at most {discordant} reordered pairs out of "
                f"{total_pairs}. H and T are different functionals of S_Z evaluated at "
                "different horizons, so weighting them together reintroduces the curve "
                "twice. This is the sensitivity the absolute scores are reported with."
            ),
            "consequence": (
                "Ranking assets of comparable sensitivity within one axis needs no view "
                "on Q-day. Comparing across sensitivities, or across axes, is a "
                "judgement - and is presented as one rather than buried in a "
                "single number."
            ),
        },
    }


def weight_sensitivity(assets: list[CryptoAsset], steps: int = 11) -> dict:
    """How the top of the backlog changes as the composite weights change.

    w_H runs from 0 (pure integrity view) to 1 (pure confidentiality view). If
    the same assets sit at the top across that whole sweep, the weight choice is
    not load-bearing and the recommendation is robust. Where it is load-bearing,
    the operator should see that rather than be handed a single ordering.
    """
    scored = [a for a in assets if a.quantum_vulnerable]
    if not scored:
        return {"sufficient_data": False, "points": [], "always_top_10": []}

    points = []
    top_sets = []
    for index in range(steps):
        w_h = index / (steps - 1)
        w_t = 1.0 - w_h
        ranked = sorted(scored, key=lambda a: -(w_h * a.h_score + w_t * a.t_score))
        top_ten = [a.id for a in ranked[:10]]
        top_sets.append(set(top_ten))
        points.append(
            {
                "w_h": round(w_h, 3),
                "w_t": round(w_t, 3),
                "top_asset": ranked[0].name,
                "top_asset_id": ranked[0].id,
                "top_10_ids": top_ten,
            }
        )

    stable = set.intersection(*top_sets) if top_sets else set()
    by_id = {a.id: a for a in scored}

    # Overlap between the two extreme views, which is the sharpest statement of
    # how much the weighting matters.
    pure_integrity, pure_confidentiality = top_sets[0], top_sets[-1]
    extremes_overlap = len(pure_integrity & pure_confidentiality)

    if stable:
        interpretation = (
            f"{len(stable)} of 10 assets stay in the top ten across every weighting from "
            "pure integrity (w_H = 0) to pure confidentiality (w_H = 1). Those are the "
            "assets the recommendation does not depend on a weighting judgement."
        )
    else:
        interpretation = (
            "No asset stays in the top ten across the full weighting sweep, and the "
            f"two extreme views share {extremes_overlap} of 10 assets. That is not a "
            "defect in the model - it is the dual-axis argument stated numerically. "
            "A pure confidentiality view surfaces ephemeral key exchange; a pure "
            "integrity view surfaces long-lived signing anchors. They are disjoint "
            "populations, which is precisely why a single-axis score cannot rank both."
        )

    return {
        "sufficient_data": True,
        "points": points,
        "always_top_10": [
            {"id": asset_id, "name": by_id[asset_id].name, "qirs": by_id[asset_id].qirs}
            for asset_id in stable
        ],
        "stable_count": len(stable),
        "extremes_overlap": extremes_overlap,
        "pure_integrity_top": [
            {"id": i, "name": by_id[i].name, "t_score": by_id[i].t_score} for i in points[0]["top_10_ids"][:5]
        ],
        "pure_confidentiality_top": [
            {"id": i, "name": by_id[i].name, "h_score": by_id[i].h_score} for i in points[-1]["top_10_ids"][:5]
        ],
        "interpretation": interpretation,
    }
