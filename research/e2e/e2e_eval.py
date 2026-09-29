"""Phase A7: end to end on stripped, statically linked programs (research/e2e/bin, built by build_cli.py).

Per program and ISA:
    boundaries   function starts recovered from call targets in the stripped image vs FUNC symbols of its
                 unstripped twin (same link, same addresses): precision and recall of starts
    detection    does the method say the program contains cryptography? compared with ground truth
                 (manifest.json). Methods:
        vera_signatures   VERA's existing binary layers (libraries, symbols, banners, constant tables)
        findcrypt3         any Findcrypt3 rule matches the image
        ntt                an ML-KEM / ML-DSA twiddle table is present
        v1_certified       v1 learned rung, BH at alpha over the program's functions, per-ISA calibration
        v2_certified       the v2 model selected on dev, same certification
        fusion_certified   stacked fusion (combiner fitted on dev) of v2 + loops + Findcrypt3 + NTT, same
Calibration: non-crypto functions of the held-out libraries (dev + sealed), per ISA, scored by the same model.
Programs whose library is in TRAIN are reported separately (train_overlap) and excluded from the headline.

    python e2e_eval.py [--alpha 0.1]
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

import lief
import numpy as np
import torch
import yara

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(ROOT / "research" / "experiments"))
from engine.binary_ml.conformal import bh, bh_qvalues, conformal_pvalues  # noqa: E402
from engine.binary_ml.features import MIN_INSNS, decode, vector  # noqa: E402
from engine.binary_ml.functions import _elf_functions, functions_in_bytes  # noqa: E402
from engine.binary_ml.graph import build, loop_instructions, node_matrix, tokens  # noqa: E402
from engine.binary_ml.signatures import fingerprints, references_table, scan as ntt_scan  # noqa: E402
from engine.binary_ml.xrefs import data_refs  # noqa: E402
from v1_detector import SEED, _commit  # noqa: E402
from v2_data import load, loop_features  # noqa: E402
import v2_models as vm  # noqa: E402

lief.logging.disable()
RULES = yara.compile(filepath=str(ROOT / "research/indicrypt_bench/src/findcrypt/findcrypt3.rules"))
ARCH = {"x86_64": "x86-64", "aarch64": "aarch64"}


def view(fn):
    """All per-function views, exactly as extract_v2.py builds them."""
    regs: list = []
    ins = decode(fn.code, fn.arch, fn.address, regs=regs)
    if len(ins) < MIN_INSNS:
        return None
    end = fn.address + len(fn.code)
    g = build(ins, fn.address, end, regs)
    loops = []
    for L in sorted(g.loops, key=lambda loop: -sum(g.blocks[b][1] - g.blocks[b][0] for b in loop))[:8]:
        li = loop_instructions(ins, g, L)
        if len(li) >= MIN_INSNS:
            loops.append(vector(li, li[0].addr, li[-1].addr + li[-1].size))
    return {"fvec": np.asarray(vector(ins, fn.address, end), np.float32),
            "loops": np.asarray(loops, np.float32).reshape(-1, 74),
            "nodes": np.asarray(node_matrix(ins, g), np.float16), "cfg": np.asarray(g.cfg_edges, np.int16).reshape(-1, 2),
            "dfg": np.asarray(g.dfg_edges, np.int16).reshape(-1, 2), "tokens": np.asarray(tokens(ins), np.uint8), "y": 0}


class Scorers:
    """v1 trees, loop trees, the selected v2 network (seed 0), and the stacked combiner, all fitted as in research."""

    def __init__(self):
        from sklearn.ensemble import HistGradientBoostingClassifier
        from sklearn.linear_model import LogisticRegression
        meta, rows, _ = load()
        self.sel = json.loads((ROOT / "research/results/v2_selection.json").read_text())["selected"]
        tr = [r for r in rows if r["split"] == "train"]
        mk = lambda: HistGradientBoostingClassifier(max_iter=400, learning_rate=0.05, max_leaf_nodes=31,
                                                    class_weight="balanced", random_state=SEED)
        self.v1 = mk().fit(np.stack([r["fvec"] for r in tr]), [r["y"] for r in tr])
        self.loops = mk().fit(np.stack([np.r_[r["fvec"], loop_features(r)] for r in tr]), [r["y"] for r in tr])
        F = np.stack([r["fvec"] for r in tr])
        self.fmean, self.fstd = F.mean(0), np.maximum(F.std(0), 1e-3)
        kind = self.sel
        self.kind = kind
        base = kind.replace("_hybrid", "")
        if base.startswith("gnn"):
            edges = base.split("_")[1]
            self.net = vm.GIN(41, 2 if edges == "both" else 1, hybrid=kind.endswith("_hybrid"))
        elif base.startswith("seq"):
            self.net = vm.SeqModel(100, hybrid=kind.endswith("_hybrid"))
        else:
            self.net = None
        if self.net is not None:
            self.net.load_state_dict(torch.load(ROOT / f"research/models/{kind}_seed0.pt", map_location="cpu"))
            self.net.eval()
        # calibration pool: non-crypto functions of held-out libraries, ELF toolchains, per ISA
        cal_rows = [r for r in rows if r["split"] in ("dev", "sealed") and r["y"] == 0 and r["toolchain"] != "gcc-x64"]
        self.cal = {}
        dev_rows = [r for r in rows if r["split"] == "dev" and r["toolchain"] != "gcc-x64"]
        # combiner (fitted on dev functions; signature flags come from findcrypt_flags.csv via v2_fusion)
        import pandas as pd
        from v2_fusion import rung_flags
        dmeta = rung_flags(meta[(meta.split == "dev") & (meta.toolchain != "gcc-x64")].reset_index(drop=True))
        dsc = self.score(dev_rows)
        Xd = np.c_[self._lg(dsc["v2"]), self._lg(dsc["loops"]), dmeta.findcrypt.values, dmeta.ntt.values]
        self.comb = LogisticRegression(max_iter=2000, class_weight="balanced").fit(Xd, dmeta.y.values)
        cmeta = rung_flags(pd.DataFrame([{k: r[k] for k in ("library", "rel", "label", "family", "toolchain", "opt", "arch",
                                                              "name", "uid", "n_insns", "y", "split")} for r in cal_rows]))
        csc = self.score(cal_rows)
        fused = self.comb.decision_function(np.c_[self._lg(csc["v2"]), self._lg(csc["loops"]), cmeta.findcrypt.values, cmeta.ntt.values])
        arch = np.array([r["arch"] for r in cal_rows])
        for a in ("x86-64", "aarch64"):
            m = arch == a
            self.cal[a] = {"v1": csc["v1"][m], "v2": csc["v2"][m], "fusion": fused[m], "n": int(m.sum())}

    @staticmethod
    def _lg(p):
        p = np.clip(p, 1e-6, 1 - 1e-6)
        return np.log(p / (1 - p))

    def score(self, rows):
        X = np.stack([r["fvec"] for r in rows])
        out = {"v1": self.v1.predict_proba(X)[:, 1],
               "loops": self.loops.predict_proba(np.stack([np.r_[r["fvec"], loop_features(r)] for r in rows]))[:, 1]}
        if self.net is None:
            out["v2"] = out["v1"] if self.kind == "hgb_v1" else out["loops"]
            return out
        pack = vm.Pack(rows, self.fmean, self.fstd)
        vm.DEV_ = "cpu"
        s = []
        with torch.no_grad():
            for i in range(0, len(rows), 512):
                idx = np.arange(i, min(len(rows), i + 512))
                f = torch.from_numpy(pack.f[idx]) if self.kind.endswith("_hybrid") else None
                if self.kind.startswith("seq"):
                    z = self.net(pack.token_batch(idx), f)
                else:
                    x, ei, ei2, gid, n = pack.graph_batch(idx, self.kind.replace("_hybrid", "").split("_")[1])
                    z = self.net(x, ei, ei2, gid, n, f)
                s.append(torch.sigmoid(z).numpy())
        out["v2"] = np.concatenate(s)
        return out


def vera_signatures(path: Path) -> bool:
    os.environ["VERA_BINARY_DETECTOR"] = "0"
    from collectors.binary_scanner import scan_blob
    res = scan_blob(path.read_bytes(), str(path))
    return any(f.algorithm or f.asset_class == "crypto_library" for f in res.findings)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--alpha", type=float, default=0.1)
    args = ap.parse_args()
    t0 = time.time()
    sc = Scorers()
    manifest = json.loads((HERE / "manifest.json").read_text())
    W = {k: v[0] for k, v in fingerprints().items()}
    out = {"commit": _commit(), "alpha": args.alpha, "selected_v2": sc.kind,
           "calibration_n": {a: v["n"] for a, v in sc.cal.items()}, "programs": {}}
    for key, info in sorted(manifest.items()):
        name, arch_s = key.rsplit("_", 1) if not key.endswith("x86_64") else (key[:-7], "x86_64")
        arch = ARCH[arch_s]
        full, stripped = HERE / "bin" / key, HERE / "bin" / (key + ".stripped")
        data = stripped.read_bytes()
        truth = {f.address for f in _elf_functions(lief.ELF.parse(str(full))) if f.code}
        recovered = functions_in_bytes(data, "elf")
        starts = {f.address for f in recovered}
        img = lief.ELF.parse(str(stripped))

        def va(off):
            for seg in img.segments:
                if seg.file_offset <= off < seg.file_offset + seg.physical_size:
                    return seg.virtual_address + off - seg.file_offset
            return -1
        tables = [(va(h.offset), va(h.offset) + h.length, W[h.scheme]) for h in ntt_scan(data)]
        fc_ranges = []
        for m in RULES.match(data=data):
            for s in m.strings:
                for inst in s.instances:
                    a = va(inst.offset)
                    fc_ranges.append((a, a + inst.matched_length, 1))
        views, fns = [], []
        for fn in recovered:
            v = view(fn)
            if v is not None:
                refs = data_refs(fn.code, fn.arch, fn.address)
                v["ntt"] = float(bool(tables) and references_table(refs, tables))
                v["findcrypt"] = float(any(a <= r < e for r in refs for a, e, _ in fc_ranges)
                                       or any(fn.address <= a < fn.address + len(fn.code) for a, _, _ in fc_ranges))
                views.append(v)
                fns.append(fn)
        s = sc.score(views)
        fused = sc.comb.decision_function(np.c_[sc._lg(s["v2"]), sc._lg(s["loops"]),
                                                [v["findcrypt"] for v in views], [v["ntt"] for v in views]])
        cal = sc.cal[arch]
        cert, min_q = {}, {}
        for rung, vals in (("v1", s["v1"]), ("v2", s["v2"]), ("fusion", fused)):
            p = conformal_pvalues(vals, cal[rung])
            sel = bh(p, args.alpha)
            cert[rung] = [hex(fns[i].address) for i in np.nonzero(sel)[0]]
            min_q[rung] = round(float(bh_qvalues(p).min()), 5)   # the program is flagged at any alpha >= this
        out["programs"][key] = {
            "contains_crypto": info["contains_crypto"], "train_overlap": info["train_overlap"], "arch": arch,
            "functions_recovered": len(recovered), "functions_scored": len(views), "functions_true": len(truth),
            "boundary_precision": round(len(starts & truth) / max(1, len(starts)), 4),
            "boundary_recall": round(len(starts & truth) / max(1, len(truth)), 4),
            "flags": {"vera_signatures": vera_signatures(stripped), "findcrypt3": bool(fc_ranges), "ntt": bool(tables),
                      "v1_certified": bool(cert["v1"]), "v2_certified": bool(cert["v2"]),
                      "fusion_certified": bool(cert["fusion"])},
            "certified": cert,
            "min_q": min_q,
        }
        print(key, out["programs"][key]["flags"], flush=True)
    # summary: binary-level TPR / FPR per method, independent programs only
    progs = [p for p in out["programs"].values() if not p["train_overlap"]]
    summary = {}
    for method in progs[0]["flags"]:
        tp = sum(p["flags"][method] and p["contains_crypto"] for p in progs)
        fp = sum(p["flags"][method] and not p["contains_crypto"] for p in progs)
        pos = sum(p["contains_crypto"] for p in progs)
        neg = len(progs) - pos
        summary[method] = {"tpr": round(tp / max(1, pos), 3), "fpr": round(fp / max(1, neg), 3), "tp": tp, "fp": fp,
                           "positives": pos, "negatives": neg}
    out["summary_independent"] = summary
    out["boundaries"] = {"precision_mean": round(float(np.mean([p["boundary_precision"] for p in out["programs"].values()])), 4),
                         "recall_mean": round(float(np.mean([p["boundary_recall"] for p in out["programs"].values()])), 4)}
    out["minutes"] = round((time.time() - t0) / 60, 1)
    (ROOT / "research/results/e2e.json").write_text(json.dumps(out, indent=2))
    print(json.dumps({"summary": summary, "boundaries": out["boundaries"]}, indent=2))


if __name__ == "__main__":
    main()
