"""Large Monte Carlo check of research/THEORY.md: every guarantee on a grid, with 99% confidence intervals.

For each cell, REPS independent draws; FDR is estimated as mean FDP; a cell PASSES when the upper end of the
99% normal interval is <= alpha. Cells that the theory says may fail (cross-ISA calibration, fixed threshold)
are reported, not asserted. Also records fused-vs-single-rung power, to show when fusion helps.

    python theory_sim.py            (single core, about ten minutes)
"""
from __future__ import annotations

import itertools
import json
import sys
import time
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend"))
from engine.binary_ml.conformal import (bh, conformal_evalues, conformal_pvalues, default_thresholds,  # noqa: E402
                                        ebh, fused_evalues)
from sklearn.linear_model import LogisticRegression  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent))
from v1_detector import _commit  # noqa: E402

REPS = 2000
SEED = 20260928
ALPHAS = (0.05, 0.1, 0.2)


def ci99(x):
    x = np.asarray(x, dtype=float)
    return float(x.mean()), float(x.mean() + 2.576 * x.std() / np.sqrt(len(x)))


def fdp_pow(sel, null):
    return (sel & null).sum() / max(1, sel.sum()), (sel & ~null).sum() / max(1, (~null).sum())


def prop1(rng, alpha, n_cal, prevalence):
    """Three strata with shifted null distributions; per-stratum vs wrong (stratum-0) calibration."""
    shifts = (0.0, 0.8, 1.6)
    per, wrong = [], []
    for _ in range(REPS):
        s, g, null, cal = [], [], [], {}
        for k, sh in enumerate(shifts):
            m = 300
            a = max(1, int(prevalence * m))
            cal[k] = rng.normal(sh, 1, n_cal)
            s += list(rng.normal(sh, 1, m - a)) + list(rng.normal(sh + 3, 1, a))
            g += [k] * m
            null += [True] * (m - a) + [False] * a
        s, g, null = np.array(s), np.array(g), np.array(null)
        p = np.empty(len(s))
        for k in cal:
            p[g == k] = conformal_pvalues(s[g == k], cal[k])
        per.append(fdp_pow(bh(p, alpha), null)[0])
        wrong.append(fdp_pow(bh(conformal_pvalues(s, cal[0]), alpha), null)[0])
    return {"per_isa": ci99(per), "wrong_isa": ci99(wrong)}


def _rungs(rng, rho, sig_fire_alt, n, a):
    """(learned, correlated learned, 0/1 signature) scores for n points of which the last a are crypto."""
    z = np.r_[rng.normal(size=n - a), rng.normal(2.0, 1, a)]
    second = rho * z + np.sqrt(1 - rho ** 2) * rng.normal(size=n)
    sig = np.r_[rng.random(n - a) < 0.002, rng.random(a) < sig_fire_alt].astype(float)
    return np.c_[z, second, sig]


def thm2(rng, alpha, rho, sig_fire_alt, n_cal=4000, m=500, prevalence=0.05):
    """Fusion procedures vs single rungs. The stacked combiner is fitted on an independent 'dev' draw."""
    procs = ("stacked_bh", "evalue_avg_ebh", "calibrator_fused_ebh", "learned_bh", "signature_bh", "bonferroni_by")
    out = {k: ([], []) for k in procs}
    a = max(1, int(prevalence * m))
    null = np.r_[np.ones(m - a, bool), np.zeros(a, bool)]
    th = default_thresholds(n_cal, m, alpha)
    dev = _rungs(rng, rho, sig_fire_alt, 20000, 2000)
    combiner = LogisticRegression(max_iter=1000).fit(dev, np.r_[np.zeros(18000), np.ones(2000)])
    for _ in range(REPS):
        cal = _rungs(rng, rho, sig_fire_alt, n_cal, 0)
        test = _rungs(rng, rho, sig_fire_alt, m, a)
        ps = [conformal_pvalues(test[:, k], cal[:, k]) for k in range(3)]
        es = [conformal_evalues(test[:, k], cal[:, k], alpha) for k in range(3)]
        g_test, g_cal = combiner.decision_function(test), combiner.decision_function(cal)
        sels = {
            "stacked_bh": bh(conformal_pvalues(g_test, g_cal), alpha),
            "evalue_avg_ebh": ebh(0.4 * es[0] + 0.2 * es[1] + 0.4 * es[2], alpha),
            "calibrator_fused_ebh": ebh(fused_evalues(ps, [0.4, 0.2, 0.4], th), alpha),
            "learned_bh": bh(ps[0], alpha),
            "signature_bh": bh(ps[2], alpha),
            "bonferroni_by": bh(np.minimum(1, 3 * np.min(ps, axis=0)), alpha / np.sum(1 / np.arange(1, m + 1))),
        }
        for k, sel in sels.items():
            f, pw = fdp_pow(sel, null)
            out[k][0].append(f)
            out[k][1].append(pw)
    return {k: {"fdr": ci99(v[0]), "power": float(np.mean(v[1]))} for k, v in out.items()}


def prevalence_sweep(rng, alpha, prevalence, auc_shift=1.3):
    """Conformal BH vs a fixed threshold as prevalence falls (Proposition 0)."""
    bhf, fixf, bhp = [], [], []
    m = 4000
    a = max(1, int(prevalence * m))
    null = np.r_[np.ones(m - a, bool), np.zeros(a, bool)]
    for _ in range(REPS // 4):
        cal = rng.normal(size=5000)
        s = np.r_[rng.normal(size=m - a), rng.normal(auc_shift, 1, a)]
        f, pw = fdp_pow(bh(conformal_pvalues(s, cal), alpha), null)
        bhf.append(f), bhp.append(pw)
        fixf.append(fdp_pow(s > 1.28, null)[0])          # threshold at the null's 90th percentile
    return {"bh": ci99(bhf), "bh_power": float(np.mean(bhp)), "fixed_threshold": ci99(fixf)}


def main():
    t0 = time.time()
    rng = np.random.default_rng(SEED)
    res = {"commit": _commit(), "seed": SEED, "reps": REPS, "prop1": {}, "thm2": {}, "prop0": {}, "violations": []}
    for alpha, n_cal, prev in itertools.product(ALPHAS, (200, 1000), (0.01, 0.05)):
        key = f"alpha={alpha},n_cal={n_cal},prev={prev}"
        r = prop1(rng, alpha, n_cal, prev)
        res["prop1"][key] = r
        if r["per_isa"][1] > alpha:
            res["violations"].append(("prop1", key, r["per_isa"]))
    for alpha, rho, fire in itertools.product((0.1,), (0.0, 0.5, 0.95), (0.0, 0.3, 0.8)):
        key = f"alpha={alpha},rho={rho},sig_fire={fire}"
        r = thm2(rng, alpha, rho, fire)
        res["thm2"][key] = r
        for proc in r:
            if r[proc]["fdr"][1] > alpha:
                res["violations"].append(("thm2", key, proc, r[proc]["fdr"]))
    for prev in (0.005, 0.01, 0.05, 0.1, 0.34):
        res["prop0"][f"prev={prev}"] = prevalence_sweep(rng, 0.1, prev)
    res["seconds"] = round(time.time() - t0, 1)
    out = ROOT / "research" / "results" / "theory_sim.json"
    out.write_text(json.dumps(res, indent=1))
    print("violations:", res["violations"])
    print(json.dumps(res["thm2"], indent=1)[:3000])
    print(json.dumps(res["prop0"], indent=1))


if __name__ == "__main__":
    main()
