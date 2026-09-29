"""Phase 0 self-audit: look for our own mistakes before claiming anything new.

0.1 leakage      byte-identical functions shared between TRAIN and an evaluation split (same toolchain, opt,
                 code bytes); how much do they inflate the metrics? (score with and without them)
0.2 validity     (a) the prevalence manipulation removes positives from the TEST side only; calibration is
                 nulls only, so test nulls stay a random subset exchangeable with calibration nulls: correct by
                 construction, stated here. (b) the harder, deployment-shaped question our pooled studies did
                 not ask: calibrate on OTHER libraries (exactly what the shipped artefact does: dev + sealed
                 nulls) and test on library-disjoint code (sealed_b, sealed_c). Does FDR <= alpha survive?
                 Which null libraries sit above the calibration distribution?
0.3 breadth      sealed metrics per library, across sealed + sealed_b + sealed_c (8 crypto libraries)
0.4 fairness     Findcrypt3 scored on what it is designed for: crypto rules only (not its CRC/base64 rules),
                 on programs whose primitive has a constant in its rule database
0.5 identity     the shipped model (backend/engine/binary_ml/model) is the evaluated model: same features,
                 same predictions as a refit with the evaluated configuration

    python self_audit.py      -> research/results/self_audit.json
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import joblib
import numpy as np
import yara
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import average_precision_score, roc_auc_score

sys.path.insert(0, str(Path(__file__).resolve().parent))
from v1_detector import ROOT, SEED, _commit  # noqa: E402
from v2_data import load  # noqa: E402
from v2_fusion import binary_study  # noqa: E402
from engine.binary_ml.conformal import bh, conformal_pvalues  # noqa: E402
from engine.binary_ml.features import FEATURES  # noqa: E402

RES = ROOT / "research" / "results"
MODEL = ROOT / "backend" / "engine" / "binary_ml" / "model"
NON_CRYPTO_RULES = ("CRC", "BASE64", "Elf_Hash", "Delphi", "VC6_Random", "VC8_Random", "Unknown_Random", "WellRNG512")


def metrics(y, s):
    if y.sum() == 0 or y.sum() == len(y):
        return None
    return {"roc_auc": round(roc_auc_score(y, s), 4), "pr_auc": round(average_precision_score(y, s), 4),
            "n": int(len(y)), "crypto": int(y.sum())}


def main():
    t0 = time.time()
    rng = np.random.default_rng(SEED)
    meta, rows, _ = load(("v2_all", "v2_sealed_c"))
    F = np.stack([r["fvec"] for r in rows])
    y = meta.y.values
    out = {"commit": _commit(), "seed": SEED}

    # ---- 0.5 identity
    shipped = joblib.load(MODEL / "v1_model.joblib")
    cal = json.loads((MODEL / "v1_calibration.json").read_text())
    tr = ((meta.split == "train") & meta.opt.isin(["O0", "O2"])).values
    refit = HistGradientBoostingClassifier(max_iter=400, learning_rate=0.05, max_leaf_nodes=31, class_weight="balanced",
                                           random_state=SEED).fit(F[tr], y[tr])
    s_ship = shipped.predict_proba(F)[:, 1]
    s_refit = refit.predict_proba(F)[:, 1]
    o02 = meta.opt.isin(["O0", "O2"]).values
    sealed_o02 = (meta.split == "sealed").values & o02
    out["0.5_identity"] = {
        "feature_list_equal": cal["meta"]["features"] == list(FEATURES),
        "exported_at_commit": cal["meta"]["commit"],
        "max_abs_prediction_difference_vs_refit": float(np.abs(s_ship - s_refit).max()),
        "sealed_O0_O2_shipped": metrics(y[sealed_o02], s_ship[sealed_o02]),
        "v1_1_reported_sealed": json.loads((RES / "v1_1_detector.json").read_text())["sealed"]["roc_auc"],
    }
    print("0.5", out["0.5_identity"], flush=True)

    # ---- 0.1 leakage
    meta["key"] = list(zip(meta.toolchain, meta.opt, meta.code_sha))
    train_keys = set(meta.key[meta.split == "train"])
    leak = meta.key.isin(train_keys).values
    out["0.1_leakage"] = {}
    for sp in ("dev", "sealed", "sealed_b", "sealed_c"):
        m = (meta.split == sp).values
        out["0.1_leakage"][sp] = {"rows": int(m.sum()), "byte_identical_to_train": int((m & leak).sum()),
                                  "share": round(float((m & leak).sum() / m.sum()), 4),
                                  "with": metrics(y[m], s_ship[m]), "without": metrics(y[m & ~leak], s_ship[m & ~leak])}
    lab = meta.groupby("key").y.nunique()
    out["0.1_leakage"]["byte_identical_keys_with_conflicting_labels"] = int((lab > 1).sum())
    print("0.1", {k: (v["share"], v["with"] and v["with"]["pr_auc"], v["without"] and v["without"]["pr_auc"])
                  for k, v in out["0.1_leakage"].items() if isinstance(v, dict)}, flush=True)

    # ---- 0.3 per library (all sealed splits, all opt levels, shipped model)
    ev = meta.split.isin(["sealed", "sealed_b", "sealed_c"]).values & ~leak
    null_dev = s_ship[(meta.split == "dev").values & (y == 0)]
    thr = float(np.quantile(null_dev, 0.95))           # a threshold fixed on DEV nulls: 5% dev false-positive rate
    per_lib = {}
    for lib in sorted(set(meta.library[ev])):
        m = ev & (meta.library == lib).values
        per_lib[lib] = {"split": meta.split[m].iloc[0], "n": int(m.sum()), "crypto": int(y[m].sum()),
                        "metrics": metrics(y[m], s_ship[m]),
                        "recall_at_dev_fpr_5pct": round(float((s_ship[m & (y == 1)] >= thr).mean()), 4) if (y[m] == 1).any() else None,
                        "false_positive_rate_at_dev_fpr_5pct": round(float((s_ship[m & (y == 0)] >= thr).mean()), 4) if (y[m] == 0).any() else None}
    out["0.3_per_library"] = {"threshold_from_dev_nulls": round(thr, 4), "libraries": per_lib,
                              "crypto_libraries_evaluated": sorted(l for l, v in per_lib.items() if v["crypto"] > 0),
                              "all_sealed": metrics(y[ev], s_ship[ev])}
    print("0.3 crypto libs:", out["0.3_per_library"]["crypto_libraries_evaluated"], out["0.3_per_library"]["all_sealed"], flush=True)

    # ---- 0.2 deployment-shaped validity: calibration = the SHIPPED nulls (dev + sealed), tests library-disjoint
    shipped_nulls = {a: np.asarray(v) for a, v in cal["null_scores"].items()}
    test_pool = meta.split.isin(["sealed_b", "sealed_c"]).values & o02
    arch = meta.arch.values
    res_bin = {}
    for m_size in (50, 100, 500):
        for prev in (0.05, 0.01):
            fdp, tp, pos = [], 0, 0
            for _ in range(300):
                isa = rng.choice(["x86-64", "aarch64", "arm32"])
                neg = np.nonzero(test_pool & (arch == isa) & (y == 0))[0]
                posi = np.nonzero(test_pool & (arch == isa) & (y == 1))[0]
                k = max(1, int(round(prev * m_size)))
                t = np.r_[rng.choice(neg, m_size - k, replace=False), rng.choice(posi, k, replace=False)]
                sel = bh(conformal_pvalues(s_ship[t], shipped_nulls[isa]), 0.1)
                fdp.append((sel & (y[t] == 0)).sum() / max(1, sel.sum()))
                tp += int((sel & (y[t] == 1)).sum())
                pos += k
            f = np.asarray(fdp)
            res_bin[f"m={m_size},prev={prev}"] = {"mean_fdp": round(float(f.mean()), 4),
                                                  "fdp_ci99_upper": round(float(f.mean() + 2.576 * f.std() / np.sqrt(len(f))), 4),
                                                  "power": round(tp / pos, 4)}
    # which null libraries sit above the calibration distribution? (the exchangeability check, per library)
    exceed = {}
    for lib in sorted(set(meta.library[test_pool & (y == 0)])):
        m = test_pool & (y == 0) & (meta.library == lib).values
        by_isa = {}
        for isa, nulls in shipped_nulls.items():
            mi = m & (arch == isa)
            if mi.any():
                q95 = np.quantile(nulls, 0.95)
                by_isa[isa] = round(float((s_ship[mi] > q95).mean()), 4)   # 0.05 expected if exchangeable
        exceed[lib] = by_isa
    out["0.2_validity"] = {
        "prevalence_manipulation": "positives are removed from the test side only; calibration is nulls only; test "
                                   "nulls remain a random subset (grouped by source function) of the same null "
                                   "population as calibration, so exchangeability is preserved by construction",
        "pooled_studies_caveat": "pooled studies split functions at random, so calibration and test share libraries; "
                                 "this is favourable to exchangeability and is why the library-disjoint test below exists",
        "library_disjoint_binaries": {"calibration": "shipped nulls (dev + sealed, per ISA)", "test": "sealed_b + sealed_c, O0/O2",
                                      "alpha": 0.1, "cells": res_bin},
        "null_share_above_calibration_q95": exceed,
    }
    print("0.2", {k: (v["mean_fdp"], v["fdp_ci99_upper"], v["power"]) for k, v in res_bin.items()}, flush=True)
    print("0.2 exceed", exceed, flush=True)

    # ---- 0.4 Findcrypt3, fairly
    rules = yara.compile(filepath=str(ROOT / "research/indicrypt_bench/src/findcrypt/findcrypt3.rules"))
    man = json.loads((ROOT / "research/e2e/manifest.json").read_text())
    e2e = json.loads((RES / "e2e.json").read_text())["programs"]
    fc = {}
    for k, v in man.items():
        data = (ROOT / "research/e2e/bin" / f"{k}.stripped").read_bytes()
        hits = sorted({m.rule for m in rules.match(data=data)})
        crypto_hits = [h for h in hits if not h.startswith(NON_CRYPTO_RULES)]
        fc[k] = {"all_rules": hits, "crypto_rules": crypto_hits, "contains_crypto": v["contains_crypto"],
                 "train_overlap": v["train_overlap"]}
    ind = {k: v for k, v in fc.items() if not v["train_overlap"]}
    pos = [k for k, v in ind.items() if v["contains_crypto"]]
    neg = [k for k, v in ind.items() if not v["contains_crypto"]]
    in_db = [k for k in pos if ind[k]["crypto_rules"]]      # its primitive has a constant Findcrypt knows
    out["0.4_findcrypt_fair"] = {
        "as_released_all_rules": {"tpr": round(sum(bool(ind[k]["all_rules"]) for k in pos) / len(pos), 3),
                                  "fpr": round(sum(bool(ind[k]["all_rules"]) for k in neg) / len(neg), 3)},
        "crypto_rules_only": {"tpr": round(sum(bool(ind[k]["crypto_rules"]) for k in pos) / len(pos), 3),
                              "fpr": round(sum(bool(ind[k]["crypto_rules"]) for k in neg) / len(neg), 3)},
        "false_alarm_rules": sorted({r for k in neg for r in ind[k]["all_rules"]}),
        "programs_whose_primitive_findcrypt_knows": in_db,
        "missed_by_findcrypt_found_by_vera": sorted(k for k in pos if not ind[k]["crypto_rules"] and
                                                     (e2e[k]["flags"]["vera_signatures"] or e2e[k]["flags"]["v1_certified"])),
        "note": "Findcrypt identifies known constants; its CRC32 rule fires on checksums by design, so those are "
                "not errors of the tool. It is complementary: it names algorithms, VERA certifies presence.",
    }
    print("0.4", out["0.4_findcrypt_fair"], flush=True)
    out["minutes"] = round((time.time() - t0) / 60, 1)
    (RES / "self_audit.json").write_text(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
