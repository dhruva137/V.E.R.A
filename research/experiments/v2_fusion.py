"""Phase B1/B7: certified rung fusion on real functions (research/THEORY.md, Theorems 2a and 2b).

Rungs, per function (ELF toolchains only, where the Findcrypt3 / NTT attribution by relocation exists):
    learned     the v2 model selected on dev (scores saved by v2_models.py, seed ensemble)
    v1          the v1 model (for the "old vs new" row)
    loops       gradient-boosted trees with loop aggregates (A1)
    findcrypt   Findcrypt3 crypto-constant rules hit the function (0/1)
    ntt         an ML-KEM/ML-DSA twiddle table is referenced by the function (0/1)
Procedures, each with per-ISA (Mondrian) conformal calibration on a random half of the evaluation pool's
non-crypto functions, 200 splits by source function, at natural / 5% / 1% / 0.5% prevalence:
    single rungs + BH; stacked fusion (logistic combiner fitted on DEV) + BH; average of conformal e-values + e-BH.
The combiner never sees the evaluation pool; calibration never touches training.

    python v2_fusion.py [--pool sealed|sealed_b]
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression

sys.path.insert(0, str(Path(__file__).resolve().parent))
from v1_detector import ROOT, SEED, _commit  # noqa: E402
from v2_data import BENCH, load  # noqa: E402
from engine.binary_ml.conformal import bh, conformal_evalues, conformal_pvalues, ebh  # noqa: E402

RES = ROOT / "research" / "results"
ALPHAS = (0.05, 0.1, 0.2)
PREVALENCE = (None, 0.05, 0.01, 0.005)
SPLITS = 200


def _logit(p):
    p = np.clip(p, 1e-6, 1 - 1e-6)
    return np.log(p / (1 - p))


NON_CRYPTO_RULES = ("CRC", "BASE64", "Elf_Hash", "Delphi", "VC6_Random", "VC8_Random", "Unknown_Random", "WellRNG512")


def rung_flags(meta: pd.DataFrame, crypto_rules_only: bool = False) -> pd.DataFrame:
    """Findcrypt3 and NTT flags per function. ``crypto_rules_only`` drops Findcrypt3's checksum/encoding rules
    (the self-audit showed its CRC32 rule firing on zlib-family code); the default keeps v2 results reproducible."""
    fc = pd.read_csv(BENCH / "findcrypt_flags.csv")
    fc["name"] = fc.name.str.lstrip("_")
    key = ["toolchain", "opt", "library", "rel", "name"]
    ntt = fc[fc.rules.str.contains("NTT_")][key].drop_duplicates().assign(ntt=1)
    crypto_rules = fc.rules.str.split("|").apply(lambda rs: any(not r.startswith("NTT_") and not (crypto_rules_only and
                                                                                           r.startswith(NON_CRYPTO_RULES)) for r in rs))
    f3 = fc[crypto_rules][key].drop_duplicates().assign(findcrypt=1)
    out = meta.merge(f3, on=key, how="left").merge(ntt, on=key, how="left")
    return out.fillna({"findcrypt": 0, "ntt": 0})


def mondrian_study(scores: dict, y, arch, groups, rng, prevalence, evalue_keys=()):
    """scores: name -> array. Per-ISA conformal p-values; returns FDP/power per procedure and alpha."""
    uniq = np.unique(groups)
    rec = {}
    for _ in range(SPLITS):
        cal_g = set(rng.choice(uniq, size=len(uniq) // 2, replace=False))
        in_cal = np.fromiter((g in cal_g for g in groups), bool, len(groups))
        test_idx = np.nonzero(~in_cal)[0]
        if prevalence is not None:
            neg, pos = test_idx[y[test_idx] == 0], test_idx[y[test_idx] == 1]
            k = int(round(prevalence * len(neg) / (1 - prevalence)))
            test_idx = np.r_[neg, rng.choice(pos, size=min(k, len(pos)), replace=False)]
        yt = y[test_idx]
        pv, ev = {}, {a: {} for a in ALPHAS}
        for name, s in scores.items():
            p = np.ones(len(test_idx))
            for a_ in np.unique(arch):
                t_mask = arch[test_idx] == a_
                cal = s[in_cal & (y == 0) & (arch == a_)]
                if t_mask.any() and len(cal):
                    p[t_mask] = conformal_pvalues(s[test_idx][t_mask], cal)
                    if name in evalue_keys:
                        for al in ALPHAS:
                            ev[al].setdefault(name, np.zeros(len(test_idx)))
                            ev[al][name][t_mask] = conformal_evalues(s[test_idx][t_mask], cal, al)
            pv[name] = p
        for al in ALPHAS:
            sels = {name: bh(p, al) for name, p in pv.items()}
            if evalue_keys:
                sels["evalue_average"] = ebh(np.mean([ev[al][k] for k in evalue_keys], 0), al)
            for name, sel in sels.items():
                r = rec.setdefault(f"{name}@{al}", {"fdp": [], "power": []})
                r["fdp"].append((sel & (yt == 0)).sum() / max(1, sel.sum()))
                r["power"].append((sel & (yt == 1)).sum() / max(1, (yt == 1).sum()))
    return {k: {"mean_fdp": round(float(np.mean(v["fdp"])), 4),
                "fdp_ci99_upper": round(float(np.mean(v["fdp"]) + 2.576 * np.std(v["fdp"]) / np.sqrt(len(v["fdp"]))), 4),
                "mean_power": round(float(np.mean(v["power"])), 4)} for k, v in rec.items()}


def binary_study(scores: dict, y, arch, groups, rng, m: int, prevalence: float, reps: int = 300, alpha: float = 0.1):
    """Deployment-shaped protocol: a 'binary' is m functions of ONE ISA from the test half, with the given
    share of crypto; BH runs inside each binary (as the product does), calibration is the other half's nulls
    of that ISA. Returns mean FDP over binaries (an FDR estimate) and pooled power per procedure."""
    uniq = np.unique(groups)
    out = {k: {"fdp": [], "tp": 0, "pos": 0} for k in scores}
    for _ in range(reps):
        cal_g = set(rng.choice(uniq, size=len(uniq) // 2, replace=False))
        in_cal = np.fromiter((g in cal_g for g in groups), bool, len(groups))
        isa = rng.choice(np.unique(arch))
        neg = np.nonzero(~in_cal & (arch == isa) & (y == 0))[0]
        pos = np.nonzero(~in_cal & (arch == isa) & (y == 1))[0]
        k = max(1, int(round(prevalence * m)))
        if len(neg) < m - k or len(pos) < k:
            continue
        t = np.r_[rng.choice(neg, m - k, replace=False), rng.choice(pos, k, replace=False)]
        yt = y[t]
        for name, sc in scores.items():
            cal = sc[in_cal & (y == 0) & (arch == isa)]
            sel = bh(conformal_pvalues(sc[t], cal), alpha)
            out[name]["fdp"].append((sel & (yt == 0)).sum() / max(1, sel.sum()))
            out[name]["tp"] += int((sel & (yt == 1)).sum())
            out[name]["pos"] += int(k)
    return {n: {"mean_fdp": round(float(np.mean(v["fdp"])), 4),
                "fdp_ci99_upper": round(float(np.mean(v["fdp"]) + 2.576 * np.std(v["fdp"]) / np.sqrt(len(v["fdp"]))), 4),
                "power": round(v["tp"] / max(1, v["pos"]), 4), "binaries": len(v["fdp"])} for n, v in out.items()}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pool", default="sealed")
    ap.add_argument("--data", default="v2_o0o2")
    ap.add_argument("--learned", default=None, help="learned rung for the combiner (default: the dev selection)")
    args = ap.parse_args()
    t0 = time.time()
    rng = np.random.default_rng(SEED)
    sel = args.learned or json.loads((RES / "v2_selection.json").read_text())["selected"]
    meta, _, _ = load(args.data)
    for name in ("hgb_v1", "hgb_loops", sel):
        for split in ("dev", args.pool):
            f = RES / f"v2_scores_{name}_{split}.npy"
            if not f.exists():
                raise SystemExit(f"missing {f}: run v2_models.py (and v2_score_pool.py for sealed_b) first")
            meta.loc[meta.split == split, f"s_{name}"] = np.load(f)
    meta = rung_flags(meta)
    elf = meta.toolchain != "gcc-x64"
    dev, pool = meta[elf & (meta.split == "dev")], meta[elf & (meta.split == args.pool)].reset_index(drop=True)

    feats = lambda d: np.c_[_logit(d[f"s_{sel}"]), _logit(d["s_hgb_loops"]), d.findcrypt, d.ntt]
    comb = LogisticRegression(max_iter=2000, class_weight="balanced").fit(feats(dev), dev.y)
    scores = {"learned_v2": pool[f"s_{sel}"].values, "learned_v1": pool["s_hgb_v1"].values,
              "loops": pool["s_hgb_loops"].values, "findcrypt": pool.findcrypt.values.astype(float),
              "ntt": pool.ntt.values.astype(float), "stacked_fusion": comb.decision_function(feats(pool))}
    res = {"commit": _commit(), "seed": SEED, "pool": args.pool, "selected_learned": sel,
           "combiner_coef": dict(zip(["learned", "loops", "findcrypt", "ntt"], np.round(comb.coef_[0], 3).tolist())),
           "pool_rows": int(len(pool)), "pool_crypto": int(pool.y.sum()),
           "rung_coverage": {"findcrypt_on_crypto": round(float(pool.findcrypt[pool.y == 1].mean()), 4),
                             "findcrypt_on_noncrypto": round(float(pool.findcrypt[pool.y == 0].mean()), 4),
                             "ntt_on_crypto": round(float(pool.ntt[pool.y == 1].mean()), 4),
                             "ntt_on_noncrypto": round(float(pool.ntt[pool.y == 0].mean()), 4)},
           "prevalence": {}}
    y, arch, groups = pool.y.values, pool.arch.values, pool.uid.values
    for prev in PREVALENCE:
        key = "natural" if prev is None else str(prev)
        res["prevalence"][key] = mondrian_study(scores, y, arch, groups, rng, prev,
                                                evalue_keys=("learned_v2", "findcrypt", "ntt"))
        print(key, {k: (v["mean_fdp"], v["mean_power"]) for k, v in res["prevalence"][key].items() if k.endswith("@0.1")}, flush=True)
    res["binaries"] = {}
    for m in (100, 500, 2000):
        for prev in (0.05, 0.01):
            r = binary_study(scores, y, arch, groups, rng, m, prev)
            res["binaries"][f"m={m},prev={prev}"] = r
            print(f"binary m={m} prev={prev}", {k: (v["mean_fdp"], v["power"]) for k, v in r.items()}, flush=True)
    res["minutes"] = round((time.time() - t0) / 60, 1)
    (RES / f"v2_fusion_{args.pool}_{sel}.json").write_text(json.dumps(res, indent=2))


if __name__ == "__main__":
    main()
