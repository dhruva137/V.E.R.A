"""Fast numerical checks of research/THEORY.md (the large version is research/experiments/theory_sim.py).

Each check estimates FDR by Monte Carlo and passes when the mean FDP is within three standard errors of alpha.
"""
import numpy as np
import pytest

from engine.binary_ml.conformal import (bh, conformal_pvalues, default_thresholds, ebh, fused_evalues,
                                        mixture_calibrator)

ALPHA = 0.1


def _fdp(sel, null):
    return (sel & null).sum() / max(1, sel.sum())


def _ok(fdps, alpha=ALPHA):
    fdps = np.asarray(fdps)
    return fdps.mean() <= alpha + 3 * fdps.std() / np.sqrt(len(fdps))


def _strata(rng, n_cal=300, m_null=150, m_alt=15):
    """Three 'ISAs' whose null score distributions differ (location shifts), as x86/AArch64/ARM32 do."""
    shift = {0: 0.0, 1: 0.8, 2: 1.6}
    cal = {g: rng.normal(shift[g], 1, n_cal) for g in shift}
    s, g_of, null = [], [], []
    for g in shift:
        s += list(rng.normal(shift[g], 1, m_null)) + list(rng.normal(shift[g] + 3, 1, m_alt))
        g_of += [g] * (m_null + m_alt)
        null += [True] * m_null + [False] * m_alt
    return cal, np.array(s), np.array(g_of), np.array(null)


def test_prop1_per_isa_calibration_controls_fdr_and_pooled_x86_does_not():
    rng = np.random.default_rng(0)
    per_isa, wrong = [], []
    for _ in range(300):
        cal, s, g, null = _strata(rng)
        p = np.empty(len(s))
        for k in cal:
            p[g == k] = conformal_pvalues(s[g == k], cal[k])
        per_isa.append(_fdp(bh(p, ALPHA), null))
        wrong.append(_fdp(bh(conformal_pvalues(s, cal[0]), ALPHA), null))   # everything calibrated on stratum 0
    assert _ok(per_isa)
    assert np.mean(wrong) > 2 * ALPHA            # the documented failure mode must actually appear


def test_theorem2_fusion_controls_fdr_under_strong_dependence():
    rng = np.random.default_rng(1)
    fdps = []
    for _ in range(300):
        n_cal, m_null, m_alt = 2000, 400, 40
        z_cal, z_null, z_alt = rng.normal(size=n_cal), rng.normal(size=m_null), rng.normal(1.5, 1, m_alt)
        learned = [np.r_[z_null, z_alt], z_cal]
        # a second learned rung that is 0.9-correlated with the first (arbitrary dependence)
        eps = lambda n: rng.normal(size=n)
        second = [0.9 * learned[0] + 0.44 * eps(m_null + m_alt), 0.9 * z_cal + 0.44 * eps(n_cal)]
        # a 0/1 signature rung: fires on 30% of alternatives and 0.5% of nulls
        sig_test = np.r_[rng.random(m_null) < 0.005, rng.random(m_alt) < 0.3].astype(float)
        sig_cal = (rng.random(n_cal) < 0.005).astype(float)
        ps = [conformal_pvalues(t, c) for t, c in (learned, second, (sig_test, sig_cal))]
        e = fused_evalues(ps, [1 / 3] * 3, default_thresholds(n_cal, m_null + m_alt, ALPHA))
        null = np.r_[np.ones(m_null, bool), np.zeros(m_alt, bool)]
        fdps.append(_fdp(ebh(e, ALPHA), null))
    assert _ok(fdps)


def test_calibrator_outputs_are_e_values_for_uniform_p():
    rng = np.random.default_rng(2)
    u = rng.random(2_000_000)
    e = mixture_calibrator(u, default_thresholds(999, 100, ALPHA))
    assert e.mean() <= 1 + 4 * e.std() / np.sqrt(u.size)


def test_prop3_calibration_budget_floor():
    # n < m/alpha - 1: even a perfect score cannot be certified by BH
    m, n = 1000, 500
    cal = np.zeros(n)
    s = np.r_[np.full(10, 100.0), np.zeros(m - 10)]
    assert bh(conformal_pvalues(s, cal), ALPHA).sum() == 0
    # with enough calibration nulls the same scores are certified
    assert bh(conformal_pvalues(s, np.zeros(m * 10 + 1)), ALPHA).sum() == 10


@pytest.mark.parametrize("prevalence", [0.005, 0.05, 0.34])
def test_prop0_bh_holds_at_any_prevalence(prevalence):
    rng = np.random.default_rng(3)
    fdps = []
    for _ in range(200):
        m = 2000
        k = max(1, int(prevalence * m))
        cal = rng.normal(size=3000)
        s = np.r_[rng.normal(size=m - k), rng.normal(2.5, 1, k)]
        null = np.r_[np.ones(m - k, bool), np.zeros(k, bool)]
        fdps.append(_fdp(bh(conformal_pvalues(s, cal), ALPHA), null))
    assert _ok(fdps)
