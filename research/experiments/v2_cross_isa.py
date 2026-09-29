"""Phase B2: when does the guarantee transfer across instruction sets, and what does per-ISA calibration cost?

For the model selected on dev (results/v2_selection.json):
    train on {x86-64 only, all ISAs} x 5 seeds; score the sealed pool; for each test ISA, over 500 random
    calibration/test splits (by source function), at 5% crypto prevalence, alpha = 0.1:
        calibrate on x86-64 nulls  vs  calibrate on the test ISA's own nulls
    report mean FDP with a 95% interval (over splits and seeds) and mean power.
    Calibration budget: per-ISA calibration with n = 25, 50, 100, 200, 400, 800 nulls; FDP and power.
The selection of the model is not revisited here: this experiment characterises it.

    python v2_cross_isa.py
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import numpy as np
import torch
from sklearn.ensemble import HistGradientBoostingClassifier

sys.path.insert(0, str(Path(__file__).resolve().parent))
import v2_models as vm  # noqa: E402
from v1_detector import ROOT, SEED, _commit  # noqa: E402
from v2_data import load  # noqa: E402
from engine.binary_ml.conformal import bh, conformal_pvalues  # noqa: E402

RES = ROOT / "research" / "results"
ALPHA, PREV, SPLITS, SEEDS = 0.1, 0.05, 500, 5
ISAS = ("x86-64", "aarch64", "arm32")
BUDGET = (25, 50, 100, 200, 400, 800)


def train_score(kind, train_rows, eval_rows, seed, fmean, fstd):
    if kind.startswith("hgb"):
        clf = HistGradientBoostingClassifier(max_iter=400, learning_rate=0.05, max_leaf_nodes=31,
                                             class_weight="balanced", random_state=seed)
        clf.fit(np.stack([r["fvec"] for r in train_rows]), [r["y"] for r in train_rows])
        return clf.predict_proba(np.stack([r["fvec"] for r in eval_rows]))[:, 1]
    packs = {"train": vm.Pack(train_rows, fmean, fstd), "dev": vm.Pack(DEV_ROWS, fmean, fstd)}
    model, predict, _ = vm.run_neural(kind, packs, seed, 20, 256)
    s = predict(vm.Pack(eval_rows, fmean, fstd))
    del model
    torch.cuda.empty_cache()
    return s


def study(s, y, arch, groups, rng, test_isa, cal_isa, n_budget=None):
    uniq = np.unique(groups)
    fdp, pw = [], []
    for _ in range(SPLITS):
        cal_g = set(rng.choice(uniq, size=len(uniq) // 2, replace=False))
        in_cal = np.fromiter((g in cal_g for g in groups), bool, len(groups))
        cal = np.nonzero(in_cal & (y == 0) & (arch == cal_isa))[0]
        if n_budget is not None:
            if len(cal) < n_budget:
                continue
            cal = rng.choice(cal, size=n_budget, replace=False)
        t = np.nonzero(~in_cal & (arch == test_isa))[0]
        neg, pos = t[y[t] == 0], t[y[t] == 1]
        k = int(round(PREV * len(neg) / (1 - PREV)))
        t = np.r_[neg, rng.choice(pos, size=min(k, len(pos)), replace=False)]
        sel = bh(conformal_pvalues(s[t], s[cal]), ALPHA)
        fdp.append((sel & (y[t] == 0)).sum() / max(1, sel.sum()))
        pw.append((sel & (y[t] == 1)).sum() / max(1, (y[t] == 1).sum()))
    return fdp, pw


def summarise(fdps, pws):
    f = np.asarray(fdps)
    return {"mean_fdp": round(float(f.mean()), 4), "fdp_ci95": [round(float(f.mean() - 1.96 * f.std() / np.sqrt(len(f))), 4),
                                                                round(float(f.mean() + 1.96 * f.std() / np.sqrt(len(f))), 4)],
            "mean_power": round(float(np.mean(pws)), 4), "n": int(len(f))}


def main():
    global DEV_ROWS
    t0 = time.time()
    kind = json.loads((RES / "v2_selection.json").read_text())["selected"]
    meta, rows, _ = load()
    train = [r for r in rows if r["split"] == "train"]
    DEV_ROWS = [r for r in rows if r["split"] == "dev"]
    pool = [r for r in rows if r["split"] == "sealed"]
    F = np.stack([r["fvec"] for r in train])
    fmean, fstd = F.mean(0), np.maximum(F.std(0), 1e-3)
    y = np.array([r["y"] for r in pool])
    arch = np.array([r["arch"] for r in pool])
    groups = np.array([r["uid"] for r in pool])
    res = {"commit": _commit(), "model": kind, "alpha": ALPHA, "prevalence": PREV, "splits": SPLITS, "seeds": SEEDS,
           "matrix": {}, "budget": {}}
    rng = np.random.default_rng(SEED)
    acc = {}
    for train_set in ("x86-64", "all"):
        tr = train if train_set == "all" else [r for r in train if r["arch"] == "x86-64"]
        for sd in range(SEEDS):
            s = train_score(kind, tr, pool, SEED + sd, fmean, fstd)
            for test_isa in ISAS:
                for cal in ("x86-64", "per-isa"):
                    cal_isa = "x86-64" if cal == "x86-64" else test_isa
                    f, p = study(s, y, arch, groups, rng, test_isa, cal_isa)
                    a = acc.setdefault((train_set, test_isa, cal), ([], []))
                    a[0].extend(f)
                    a[1].extend(p)
                if train_set == "all" and sd == 0:
                    for n in BUDGET:
                        f, p = study(s, y, arch, groups, rng, test_isa, test_isa, n_budget=n)
                        res["budget"][f"{test_isa}/n={n}"] = summarise(f, p) if f else None
            print(train_set, "seed", sd, f"{(time.time() - t0) / 60:.1f} min", flush=True)
    for (train_set, test_isa, cal), (f, p) in acc.items():
        res["matrix"][f"train={train_set}/test={test_isa}/calibrate={cal}"] = summarise(f, p)
    res["minutes"] = round((time.time() - t0) / 60, 1)
    (RES / "v2_cross_isa.json").write_text(json.dumps(res, indent=2))
    for k, v in res["matrix"].items():
        print(k, v)


DEV_ROWS: list = []

if __name__ == "__main__":
    main()
