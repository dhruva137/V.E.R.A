"""Phase B4: robustness to instruction-level perturbations, for the detector and for the guarantee.

Perturbations are applied to decoded instructions before any view is built (simulated, like the black-box
attacks on neural binary function detectors; a real rewriter would also have to keep the program working):
    dead_code_10 / dead_code_30   insert 10% / 30% junk data moves and adds at random positions
    substitute                    rot -> shift, shift, or ; xor -> or, and, not   (what a rewriter emits)
    blind_constants               every large immediate becomes a small immediate plus an add
Two threat models, both on the sealed pool at 5% prevalence, alpha = 0.1, per-ISA calibration, 200 splits:
    crypto_only   only cryptographic functions are perturbed (an adversary hiding crypto): the nulls are
                  untouched, so FDR must stay <= alpha and only power can fall
    everything    every function is perturbed (an obfuscated binary) but calibration is clean: exchangeability
                  is broken on purpose, so FDR may exceed alpha; this measures by how much
Scored by v1 trees and by the v2 model selected on dev.

    python v2_robustness.py
"""
from __future__ import annotations

import json
import random
import sys
import time
from dataclasses import replace
from pathlib import Path

import numpy as np
import torch
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import average_precision_score, roc_auc_score

sys.path.insert(0, str(Path(__file__).resolve().parent))
import v2_models as vm  # noqa: E402
from v1_detector import ROOT, SEED, _commit  # noqa: E402
from v2_data import load  # noqa: E402
from engine.binary_ml.conformal import bh, conformal_pvalues  # noqa: E402
from engine.binary_ml.features import Insn, MIN_INSNS, decode, vector  # noqa: E402
from engine.binary_ml.functions import functions  # noqa: E402
from engine.binary_ml.graph import build, node_matrix, tokens  # noqa: E402

RES = ROOT / "research" / "results"
BENCH = ROOT / "research" / "indicrypt_bench"


def perturb(ins: list[Insn], how: str, rng: random.Random) -> list[Insn]:
    if how == "none":
        return ins
    fake = max(i.addr for i in ins) + 0x100000          # synthetic addresses: never a branch target
    out: list[Insn] = []

    def junk():
        nonlocal fake
        fake += 1
        return Insn(rng.choice(("mov", "add", "load")), (), None, None, False, False, fake, 4, None)

    for i in ins:
        if how.startswith("dead_code"):
            rate = 0.1 if how.endswith("10") else 0.3
            out.append(i)
            if rng.random() < rate and i.cls not in ("cbr", "jmp", "ret"):
                out.append(junk())
        elif how == "substitute":
            if i.cls == "rot" or i.folded == "rot":
                amt = i.shift_imm
                out += [replace(i, cls="shift", folded=None), replace(junk(), cls="shift", shift_imm=amt),
                        replace(junk(), cls="or")]
            elif i.cls == "xor":
                out += [replace(i, cls="or"), replace(junk(), cls="and"), replace(junk(), cls="not")]
            else:
                out.append(i)
        elif how == "blind_constants":
            big = [v for v in i.imms if 0xFFFF < v < 0xFFFFFFFFFFFF0000]
            if big:
                out += [replace(i, imms=tuple(v & 0xFFF for v in i.imms)), replace(junk(), cls="add", imms=(0x1000,))]
            else:
                out.append(i)
    return out


def views(ins, start, end):
    g = build(ins, start, end)
    return {"fvec": np.asarray(vector(ins, start, end), np.float32), "nodes": np.asarray(node_matrix(ins, g), np.float16),
            "cfg": np.asarray(g.cfg_edges, np.int16).reshape(-1, 2), "dfg": np.zeros((0, 2), np.int16),
            "tokens": np.asarray(tokens(ins), np.uint8)}


def main():
    t0 = time.time()
    kind = json.loads((RES / "v2_selection.json").read_text())["selected"]
    meta, rows, _ = load()
    train = [r for r in rows if r["split"] == "train"]
    pool = [r for r in rows if r["split"] == "sealed" and r["toolchain"] != "gcc-x64" and r["opt"] == "O2"]
    want = {(r["library"], r["toolchain"], r["opt"], r["rel"], r["name"]): r for r in pool}
    # re-decode the pool's functions from their objects so they can be perturbed
    idx = {}
    for j in map(json.loads, open(BENCH / "objects" / "index.jsonl", encoding="utf-8")):
        if j["ok"]:
            idx[j["obj"]] = j
    decoded = {}
    for obj, j in idx.items():
        if (j["library"], j["toolchain"], j["opt"]) not in {(k[0], k[1], k[2]) for k in list(want)[:0]} and j["opt"] == "O2" \
                and j["toolchain"] != "gcc-x64" and j["library"] in {r["library"] for r in pool}:
            for fn in functions(obj):
                key = (j["library"], j["toolchain"], j["opt"], j["rel"], fn.name.lstrip("_"))
                if key in want and key not in decoded:
                    decoded[key] = (decode(fn.code, fn.arch, fn.address), fn.address, fn.address + len(fn.code))
    keys = [k for k in want if k in decoded]
    y = np.array([want[k]["y"] for k in keys])
    arch = np.array([want[k]["arch"] for k in keys])
    groups = np.array([want[k]["uid"] for k in keys])
    F = np.stack([r["fvec"] for r in train])
    fmean, fstd = F.mean(0), np.maximum(F.std(0), 1e-3)
    v1 = HistGradientBoostingClassifier(max_iter=400, learning_rate=0.05, max_leaf_nodes=31, class_weight="balanced",
                                        random_state=SEED).fit(F, [r["y"] for r in train])
    net = None
    if "dfg" in kind or "both" in kind:
        # perturbed junk instructions carry no register sets, so a data-flow view of them would be invented
        res_note = f"{kind} uses data-flow edges; only v1 is scored under perturbation"
        kind = "hgb_v1"
    else:
        res_note = ""
    if not kind.startswith("hgb"):
        base = kind.replace("_hybrid", "")
        net = (vm.SeqModel(100, hybrid=kind.endswith("_hybrid")) if base.startswith("seq") else
               vm.GIN(41, 2 if base.split("_")[1] == "both" else 1, hybrid=kind.endswith("_hybrid")))
        net.load_state_dict(torch.load(ROOT / f"research/models/{kind}_seed0.pt", map_location="cpu"))
        net.eval()
    vm.DEV_ = "cpu"

    def score(vs):
        out = {"v1": v1.predict_proba(np.stack([v["fvec"] for v in vs]))[:, 1]}
        if net is not None:
            for v in vs:
                v["y"] = 0
            pack = vm.Pack(vs, fmean, fstd)
            s = []
            with torch.no_grad():
                for i in range(0, len(vs), 512):
                    b = np.arange(i, min(len(vs), i + 512))
                    f = torch.from_numpy(pack.f[b]) if kind.endswith("_hybrid") else None
                    if kind.startswith("seq"):
                        z = net(pack.token_batch(b), f)
                    else:
                        x, ei, ei2, gid, n = pack.graph_batch(b, "cfg")
                        z = net(x, ei, ei2, gid, n, f)
                    s.append(torch.sigmoid(z).numpy())
            out["v2"] = np.concatenate(s)
        return out

    clean = score([views(*decoded[k]) for k in keys])
    res = {"commit": _commit(), "model": kind, "note": res_note, "pool_rows": len(keys), "clean": {}, "attacks": {}}
    for m, s in clean.items():
        res["clean"][m] = {"roc_auc": round(roc_auc_score(y, s), 4), "pr_auc": round(average_precision_score(y, s), 4)}
    rng_np = np.random.default_rng(SEED)
    for how in ("dead_code_10", "dead_code_30", "substitute", "blind_constants"):
        rr = random.Random(SEED)
        pert = score([views(perturb(decoded[k][0], how, rr), decoded[k][1], decoded[k][2]) for k in keys])
        entry = {}
        for m in pert:
            for threat in ("crypto_only", "everything"):
                test_s = np.where(y == 1, pert[m], clean[m]) if threat == "crypto_only" else pert[m]
                fd, pw = [], []
                uniq = np.unique(groups)
                for _ in range(200):
                    cal_g = set(rng_np.choice(uniq, size=len(uniq) // 2, replace=False))
                    in_cal = np.fromiter((g in cal_g for g in groups), bool, len(groups))
                    t_all = np.nonzero(~in_cal)[0]
                    neg, pos = t_all[y[t_all] == 0], t_all[y[t_all] == 1]
                    k = int(round(0.05 * len(neg) / 0.95))
                    t = np.r_[neg, rng_np.choice(pos, size=min(k, len(pos)), replace=False)]
                    p = np.ones(len(t))
                    for a in np.unique(arch):
                        tm = arch[t] == a
                        cal = clean[m][in_cal & (y == 0) & (arch == a)]      # calibration is always clean code
                        if tm.any() and len(cal):
                            p[tm] = conformal_pvalues(test_s[t][tm], cal)
                    sel = bh(p, 0.1)
                    fd.append((sel & (y[t] == 0)).sum() / max(1, sel.sum()))
                    pw.append((sel & (y[t] == 1)).sum() / max(1, (y[t] == 1).sum()))
                f = np.asarray(fd)
                entry[f"{m}/{threat}"] = {"roc_auc": round(roc_auc_score(y, test_s), 4), "mean_fdp": round(float(f.mean()), 4),
                                          "fdp_ci99_upper": round(float(f.mean() + 2.576 * f.std() / np.sqrt(len(f))), 4),
                                          "mean_power": round(float(np.mean(pw)), 4)}
        res["attacks"][how] = entry
        print(how, {k: (v["roc_auc"], v["mean_fdp"], v["mean_power"]) for k, v in entry.items()}, flush=True)
    res["minutes"] = round((time.time() - t0) / 60, 1)
    (RES / "v2_robustness.json").write_text(json.dumps(res, indent=2))


if __name__ == "__main__":
    main()
