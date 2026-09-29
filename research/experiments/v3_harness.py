"""Phase 2 (v3): the breakthrough retry, on a frozen harness so every candidate is a config swap.

Data (cached once): indicrypt_bench/v2_all + v2_sealed_c, every toolchain and O0/O2/O3/Os.
Declared before any score: neural candidates are the mean of 3 seeds; selection is by DEV PR-AUC only and is
written to results/v3_selection.json before a sealed score exists; the ship rule is unchanged (sealed O0/O2 PR-AUC
>= v1 + 0.03 AND >= 5,000 functions/s on CPU).

Candidates
    v1_shipped        the artefact in backend/engine/binary_ml/model (reference)
    hgb_allopt        the same trees retrained on TRAIN at all four optimisation levels (4x the data)
    hgb_loops_allopt  + loop aggregates
    gnn_cfg_hybrid / sage_cfg_hybrid / gat_cfg_hybrid   GIN, GraphSAGE, GAT over the CFG + v1 features, all opts
    avg_hgb_<net>     plain average of hgb_allopt and each network (no fitting)
Certified power (the number the brief asks to lift): deployment protocol, library-disjoint. Calibration = SEALED
non-crypto functions per ISA (all opts); test binaries of m = 100 functions of one ISA from sealed_b + sealed_c,
5% and 1% crypto, 300 binaries each, BH at alpha = 0.1. Reported with a 99% interval on FDR.
Fusion retry: learned + loops + Findcrypt3 (crypto rules only; the self-audit showed its CRC rule sank fusion) + NTT,
stacked combiner fitted on DEV, and the e-value average; ELF toolchains only.

    python v3_harness.py [--seeds 3] [--epochs 20]
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import joblib
import numpy as np
import torch
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, roc_auc_score

sys.path.insert(0, str(Path(__file__).resolve().parent))
import v2_models as vm  # noqa: E402
from v1_detector import ROOT, SEED, _commit  # noqa: E402
from v2_data import load, loop_features  # noqa: E402
from v2_fusion import rung_flags  # noqa: E402
from engine.binary_ml.conformal import bh, conformal_evalues, conformal_pvalues, ebh  # noqa: E402

RES = ROOT / "research" / "results"
MODEL = ROOT / "backend" / "engine" / "binary_ml" / "model"
NETS = ("gnn_cfg_hybrid", "sage_cfg_hybrid", "gat_cfg_hybrid")


def hgb():
    return HistGradientBoostingClassifier(max_iter=400, learning_rate=0.05, max_leaf_nodes=31, class_weight="balanced",
                                          random_state=SEED)


def certified(scores: dict, y, arch, cal_mask, test_mask, rng, m=100, prev=0.05, reps=300, alpha=0.1, evalue_keys=()):
    out = {k: {"fdp": [], "tp": 0} for k in list(scores) + (["evalue_average"] if evalue_keys else [])}
    pos_total = 0
    for _ in range(reps):
        isa = rng.choice(["x86-64", "aarch64", "arm32"])
        neg = np.nonzero(test_mask & (arch == isa) & (y == 0))[0]
        pos = np.nonzero(test_mask & (arch == isa) & (y == 1))[0]
        k = max(1, int(round(prev * m)))
        if len(neg) < m - k or len(pos) < k:
            continue
        t = np.r_[rng.choice(neg, m - k, replace=False), rng.choice(pos, k, replace=False)]
        yt = y[t]
        pos_total += k
        cal = cal_mask & (arch == isa) & (y == 0)
        evs = []
        for name, s in scores.items():
            sel = bh(conformal_pvalues(s[t], s[cal]), alpha)
            out[name]["fdp"].append((sel & (yt == 0)).sum() / max(1, sel.sum()))
            out[name]["tp"] += int((sel & (yt == 1)).sum())
            if name in evalue_keys:
                evs.append(conformal_evalues(s[t], s[cal], alpha))
        if evalue_keys:
            sel = ebh(np.mean(evs, 0), alpha)
            out["evalue_average"]["fdp"].append((sel & (yt == 0)).sum() / max(1, sel.sum()))
            out["evalue_average"]["tp"] += int((sel & (yt == 1)).sum())
    res = {}
    for k, v in out.items():
        f = np.asarray(v["fdp"])
        res[k] = {"fdr": round(float(f.mean()), 4), "fdr_ci99": [round(float(f.mean() - 2.576 * f.std() / np.sqrt(len(f))), 4),
                                                                 round(float(f.mean() + 2.576 * f.std() / np.sqrt(len(f))), 4)],
                  "power": round(v["tp"] / max(1, pos_total), 4), "binaries": int(len(f))}
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, default=3)
    ap.add_argument("--epochs", type=int, default=20)
    args = ap.parse_args()
    t0 = time.time()
    rng = np.random.default_rng(SEED)
    meta, rows, counts = load(("v2_all", "v2_sealed_c"))
    y = meta.y.values
    split = meta.split.values
    F = np.stack([r["fvec"] for r in rows])
    L = np.stack([np.r_[r["fvec"], loop_features(r)] for r in rows])
    tr = split == "train"
    res = {"commit": _commit(), "seed": SEED, "rows": {s: int((split == s).sum()) for s in np.unique(split)},
           "declared": "neural = mean of seeds; select on dev PR-AUC; ship rule unchanged", "candidates": {}}
    S = {}
    S["v1_shipped"] = joblib.load(MODEL / "v1_model.joblib").predict_proba(F)[:, 1]
    m = hgb().fit(F[tr], y[tr])
    S["hgb_allopt"] = m.predict_proba(F)[:, 1]
    t = time.perf_counter()
    m.predict_proba(F[:20000])
    tput = {"v1_shipped": round(20000 / (time.perf_counter() - t)), "hgb_allopt": None}
    tput["hgb_allopt"] = tput["v1_shipped"]
    S["hgb_loops_allopt"] = hgb().fit(L[tr], y[tr]).predict_proba(L)[:, 1]
    t = time.perf_counter()
    hgb().fit(L[tr][:2000], y[tr][:2000]).predict_proba(L[:20000])
    tput["hgb_loops_allopt"] = round(20000 / (time.perf_counter() - t))
    print("trees done", f"{(time.time() - t0) / 60:.1f} min", flush=True)

    # neural candidates on the GPU, all opts
    F_tr = F[tr]
    fmean, fstd = F_tr.mean(0), np.maximum(F_tr.std(0), 1e-3)
    parts = {"train": [r for r, s in zip(rows, split) if s == "train"], "dev": [r for r, s in zip(rows, split) if s == "dev"]}
    packs = {k: vm.Pack(v, fmean, fstd) for k, v in parts.items()}
    all_pack = vm.Pack(rows, fmean, fstd)
    for kind in NETS:
        ss = []
        t1 = time.time()
        for sd in range(args.seeds):
            model, predict, hist = vm.run_neural(kind, packs, SEED + sd, args.epochs, 256)
            ss.append(predict(all_pack))
            if sd == 0:
                tput[kind] = vm.cpu_throughput(kind, model, packs["dev"])
                model.to(vm.DEV_)
            del model
            torch.cuda.empty_cache()
        S[kind] = np.mean(ss, 0)
        S[f"avg_hgb_{kind}"] = 0.5 * (S["hgb_allopt"] + S[kind])
        tput[f"avg_hgb_{kind}"] = round(1 / (1 / tput[kind] + 1 / tput["hgb_allopt"]))
        print(kind, f"{(time.time() - t1) / 60:.1f} min", flush=True)

    dev = split == "dev"
    for k, s in S.items():
        res["candidates"][k] = {"dev_pr_auc": round(average_precision_score(y[dev], s[dev]), 4),
                                "dev_roc_auc": round(roc_auc_score(y[dev], s[dev]), 4), "cpu_functions_per_s": tput.get(k)}
    selected = max((k for k in S if k != "v1_shipped"), key=lambda k: res["candidates"][k]["dev_pr_auc"])
    (RES / "v3_selection.json").write_text(json.dumps({"selected": selected, "dev": {k: v["dev_pr_auc"] for k, v in res["candidates"].items()},
                                                       "commit": res["commit"], "time": time.strftime("%Y-%m-%dT%H:%M:%S")}, indent=2))
    res["selected_on_dev"] = selected
    print("SELECTED", selected, {k: v["dev_pr_auc"] for k, v in res["candidates"].items()}, flush=True)

    # sealed scoring (selection already fixed)
    sealed_o02 = (split == "sealed") & meta.opt.isin(["O0", "O2"]).values
    all_sealed = np.isin(split, ["sealed", "sealed_b", "sealed_c"])
    for k, s in S.items():
        res["candidates"][k]["sealed_O0_O2_pr_auc"] = round(average_precision_score(y[sealed_o02], s[sealed_o02]), 4)
        res["candidates"][k]["all_sealed_pr_auc"] = round(average_precision_score(y[all_sealed], s[all_sealed]), 4)
        res["candidates"][k]["all_sealed_roc_auc"] = round(roc_auc_score(y[all_sealed], s[all_sealed]), 4)
    v1 = res["candidates"]["v1_shipped"]["sealed_O0_O2_pr_auc"]
    sc = res["candidates"][selected]
    res["ship_rule"] = {"v1_sealed_pr_auc": v1, "selected_sealed_pr_auc": sc["sealed_O0_O2_pr_auc"],
                        "gain": round(sc["sealed_O0_O2_pr_auc"] - v1, 4), "cpu_functions_per_s": sc["cpu_functions_per_s"],
                        "ship": bool(sc["sealed_O0_O2_pr_auc"] - v1 >= 0.03 and (sc["cpu_functions_per_s"] or 0) >= 5000)}
    print("SHIP RULE", res["ship_rule"], flush=True)

    # certified power, library-disjoint deployment protocol
    arch = meta.arch.values
    cal_mask = split == "sealed"
    test_mask = np.isin(split, ["sealed_b", "sealed_c"])
    res["certified"] = {f"prev={p}": certified(S, y, arch, cal_mask, test_mask, rng, prev=p) for p in (0.05, 0.01)}
    for p, r in res["certified"].items():
        print("certified", p, {k: (v["fdr"], v["power"]) for k, v in r.items()}, flush=True)

    # fusion retry (ELF only; Findcrypt3 crypto rules only)
    fl = rung_flags(meta.drop(columns=[c for c in ("findcrypt", "ntt") if c in meta]), crypto_rules_only=True)
    elf = (meta.toolchain != "gcc-x64").values
    lg = lambda p: np.log(np.clip(p, 1e-6, 1 - 1e-6) / (1 - np.clip(p, 1e-6, 1 - 1e-6)))
    X = np.c_[lg(S[selected]), lg(S["hgb_loops_allopt"]), fl.findcrypt.values, fl.ntt.values]
    comb = LogisticRegression(max_iter=2000, class_weight="balanced").fit(X[elf & dev], y[elf & dev])
    rungs = {"learned": S[selected], "loops": S["hgb_loops_allopt"], "findcrypt_crypto_rules": fl.findcrypt.values.astype(float),
             "ntt": fl.ntt.values.astype(float), "stacked_fusion": comb.decision_function(X)}
    res["fusion"] = {"combiner_coef": dict(zip(["learned", "loops", "findcrypt", "ntt"], np.round(comb.coef_[0], 3).tolist())),
                     "coverage_test": {"findcrypt_on_crypto": round(float(fl.findcrypt[test_mask & elf & (y == 1)].mean()), 4),
                                       "findcrypt_on_noncrypto": round(float(fl.findcrypt[test_mask & elf & (y == 0)].mean()), 4),
                                       "ntt_on_crypto": round(float(fl.ntt[test_mask & elf & (y == 1)].mean()), 4)}}
    for p in (0.05, 0.01):
        res["fusion"][f"prev={p}"] = certified(rungs, y, arch, cal_mask & elf, test_mask & elf, rng, prev=p,
                                                evalue_keys=("learned", "findcrypt_crypto_rules", "ntt"))
        print("fusion", p, {k: (v["fdr"], v["power"]) for k, v in res["fusion"][f"prev={p}"].items()}, flush=True)
    res["minutes"] = round((time.time() - t0) / 60, 1)
    (RES / "v3_harness.json").write_text(json.dumps(res, indent=2))
    np.save(RES / "v3_scores_selected.npy", S[selected])


if __name__ == "__main__":
    main()
