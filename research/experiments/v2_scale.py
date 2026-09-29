"""Phase A2 / B5 / B6, and B1 on sealed_b: does v1 hold on more compilers, optimisation levels and libraries?

Data: indicrypt_bench/v2_all (every object: 4 toolchains x O0/O2/O3/Os x train/dev/sealed/sealed_b libraries).
    B5   v1 as shipped (trained on TRAIN at O0/O2) scored on sealed at each opt level: O3/Os were never trained on
    A2   the same model on sealed_b (libsodium, wolfSSL incl. its ML-KEM/ML-DSA/LMS/XMSS; sqlite, libpng)
    B6   v1 retrained on TRAIN at all four opt levels: does compiler diversity in training help on sealed_b?
    B1   fusion on sealed_b: v1 + loops + Findcrypt3 + NTT rungs, stacked combiner fitted on DEV (O0/O2, as
         before), per-ISA conformal, pooled and deployment-shaped (synthetic binaries) protocols
Every number comes from this run; the combiner and the model never see sealed_b.

    python v2_scale.py
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, roc_auc_score

sys.path.insert(0, str(Path(__file__).resolve().parent))
from v1_detector import ROOT, SEED, _commit  # noqa: E402
from v2_data import load, loop_features  # noqa: E402
from v2_fusion import binary_study, mondrian_study, rung_flags  # noqa: E402

RES = ROOT / "research" / "results"


def hgb():
    return HistGradientBoostingClassifier(max_iter=400, learning_rate=0.05, max_leaf_nodes=31,
                                          class_weight="balanced", random_state=SEED)


def auc(y, s):
    return {"roc_auc": round(roc_auc_score(y, s), 4), "pr_auc": round(average_precision_score(y, s), 4), "n": int(len(y)),
            "crypto": int(np.sum(y))} if 0 < np.sum(y) < len(y) else None


def _lg(p):
    p = np.clip(p, 1e-6, 1 - 1e-6)
    return np.log(p / (1 - p))


def main():
    t0 = time.time()
    rng = np.random.default_rng(SEED)
    meta, rows, counts = load("v2_all")
    meta = meta.reset_index(drop=True)
    F = np.stack([r["fvec"] for r in rows])
    L = np.stack([np.r_[r["fvec"], loop_features(r)] for r in rows])
    y = meta.y.values
    tr_o02 = ((meta.split == "train") & meta.opt.isin(["O0", "O2"])).values
    tr_all = (meta.split == "train").values
    res = {"commit": _commit(), "seed": SEED, "label_counts": counts,
           "rows": {f"{sp}/{op}": int(n) for (sp, op), n in meta.groupby(["split", "opt"]).size().items()}}

    v1 = hgb().fit(F[tr_o02], y[tr_o02])
    v1_all = hgb().fit(F[tr_all], y[tr_all])
    loops = hgb().fit(L[tr_o02], y[tr_o02])
    s_v1, s_v1all, s_loops = v1.predict_proba(F)[:, 1], v1_all.predict_proba(F)[:, 1], loops.predict_proba(L)[:, 1]

    # B5: per optimisation level on sealed
    res["B5_sealed_by_opt"] = {}
    for opt in ("O0", "O2", "O3", "Os"):
        m = ((meta.split == "sealed") & (meta.opt == opt)).values
        res["B5_sealed_by_opt"][opt] = {"v1_trained_O0_O2": auc(y[m], s_v1[m]), "v1_trained_all_opts": auc(y[m], s_v1all[m])}
    # A2 / B6: sealed_b overall, per library, per opt, per ISA
    sb = (meta.split == "sealed_b").values
    res["A2_sealed_b"] = {"v1_trained_O0_O2": auc(y[sb], s_v1[sb]), "v1_trained_all_opts": auc(y[sb], s_v1all[sb]),
                          "loops": auc(y[sb], s_loops[sb])}
    res["A2_sealed_b_by_isa"] = {a: auc(y[sb & (meta.arch == a).values], s_v1[sb & (meta.arch == a).values])
                                 for a in ("x86-64", "aarch64", "arm32")}
    res["A2_sealed_b_by_opt"] = {o: auc(y[sb & (meta.opt == o).values], s_v1[sb & (meta.opt == o).values])
                                 for o in ("O0", "O2", "O3", "Os")}
    res["A2_sealed_b_by_library"] = {}
    for lib in sorted(set(meta.library[sb])):
        m = sb & (meta.library == lib).values
        res["A2_sealed_b_by_library"][lib] = {"n": int(m.sum()), "crypto": int(y[m].sum()),
                                              "mean_score_crypto": round(float(s_v1[m & (y == 1)].mean()), 3) if (y[m] == 1).any() else None,
                                              "mean_score_noncrypto": round(float(s_v1[m & (y == 0)].mean()), 3) if (y[m] == 0).any() else None}
    print(json.dumps({k: res[k] for k in ("B5_sealed_by_opt", "A2_sealed_b", "A2_sealed_b_by_isa")}, indent=1), flush=True)

    # B1 on sealed_b (ELF toolchains, where rung attribution exists)
    meta["s_v1"], meta["s_loops"] = s_v1, s_loops
    flags = rung_flags(meta.drop(columns=[c for c in ("findcrypt", "ntt") if c in meta]))
    meta["findcrypt"], meta["ntt"] = flags.findcrypt.values, flags.ntt.values
    elf = (meta.toolchain != "gcc-x64").values
    dev = meta[elf & (meta.split == "dev").values & meta.opt.isin(["O0", "O2"]).values]
    pool = meta[elf & sb].reset_index(drop=True)
    feats = lambda d: np.c_[_lg(d.s_v1), _lg(d.s_loops), d.findcrypt, d.ntt]
    comb = LogisticRegression(max_iter=2000, class_weight="balanced").fit(feats(dev), dev.y)
    scores = {"learned_v1": pool.s_v1.values, "loops": pool.s_loops.values, "findcrypt": pool.findcrypt.values.astype(float),
              "ntt": pool.ntt.values.astype(float), "stacked_fusion": comb.decision_function(feats(pool))}
    res["B1_sealed_b"] = {"combiner_coef": dict(zip(["learned", "loops", "findcrypt", "ntt"], np.round(comb.coef_[0], 3).tolist())),
                          "rung_coverage": {"findcrypt_on_crypto": round(float(pool.findcrypt[pool.y == 1].mean()), 4),
                                            "findcrypt_on_noncrypto": round(float(pool.findcrypt[pool.y == 0].mean()), 4),
                                            "ntt_on_crypto": round(float(pool.ntt[pool.y == 1].mean()), 4),
                                            "ntt_on_noncrypto": round(float(pool.ntt[pool.y == 0].mean()), 4)},
                          "pooled": {}, "binaries": {}}
    yy, arch, groups = pool.y.values, pool.arch.values, pool.uid.values
    for prev in (None, 0.05, 0.01):
        k = "natural" if prev is None else str(prev)
        res["B1_sealed_b"]["pooled"][k] = mondrian_study(scores, yy, arch, groups, rng, prev,
                                                         evalue_keys=("learned_v1", "findcrypt", "ntt"))
        print("pooled", k, {n: (v["mean_fdp"], v["mean_power"]) for n, v in res["B1_sealed_b"]["pooled"][k].items() if n.endswith("@0.1")}, flush=True)
    for m in (50, 100, 500):
        for prev in (0.05, 0.01):
            r = binary_study(scores, yy, arch, groups, rng, m, prev)
            res["B1_sealed_b"]["binaries"][f"m={m},prev={prev}"] = r
            print(f"binary m={m} prev={prev}", {n: (v["mean_fdp"], v["power"]) for n, v in r.items()}, flush=True)
    res["minutes"] = round((time.time() - t0) / 60, 1)
    (RES / "v2_scale.json").write_text(json.dumps(res, indent=2, default=str))


if __name__ == "__main__":
    main()
