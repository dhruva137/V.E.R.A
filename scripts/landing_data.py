"""Export the real numbers the landing page animates.

Everything on the landing page that looks like data is data: the calibration histogram is the shipped model's
x86-64 non-crypto calibration scores, and the per-function scores, p-values and Benjamini-Hochberg selection are
the shipped detector run on the stripped demo binaries in demo/detector/. The instruction stream is the real
disassembly of the function the detector ranks highest.

    python scripts/landing_data.py      # writes frontend/src/landing/data.json
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from engine.binary_ml.conformal import bh, bh_qvalues, conformal_pvalues  # noqa: E402
from engine.binary_ml.detector import _load  # noqa: E402
import capstone  # noqa: E402

from engine.binary_ml.features import MIN_INSNS, function_vector  # noqa: E402
from engine.binary_ml.functions import functions  # noqa: E402

ALPHA = 0.1
OUT = ROOT / "frontend" / "src" / "landing" / "data.json"


def run(binary: str) -> dict:
    model, nulls, _ = _load()
    funcs = functions(ROOT / "demo" / "detector" / f"{binary}.stripped")
    rows, kept = [], []
    for fn in funcs:
        vec, n = function_vector(fn.code, fn.arch, fn.address)
        if n >= MIN_INSNS:
            rows.append(vec)
            kept.append(fn)
    scores = model.predict_proba(np.asarray(rows))[:, 1]
    p = conformal_pvalues(scores, nulls[kept[0].arch])
    q = bh_qvalues(p)
    sel = bh(p, ALPHA)
    top = kept[int(np.argmax(scores))]
    modes = {"x86-64": (capstone.CS_ARCH_X86, capstone.CS_MODE_64), "aarch64": (capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)}
    md = capstone.Cs(*modes[top.arch])
    insns = list(md.disasm(top.code, top.address))[:48]
    return {
        "binary": binary,
        "arch": kept[0].arch,
        "functions": len(kept),
        "selected": int(sel.sum()),
        "scores": [round(float(s), 4) for s in scores],
        "p": [round(float(v), 6) for v in p],
        "q": [round(float(v), 6) for v in q],
        "sel": [bool(v) for v in sel],
        "top_function": {"address": hex(top.address),
                         "insns": [f"{i.mnemonic} {i.op_str}".strip() for i in insns]},
    }


def main() -> None:
    _, nulls, meta = _load()
    calibration = {}
    for arch in ("x86-64", "aarch64"):
        v = np.asarray(nulls[arch])
        counts, edges = np.histogram(v, bins=48, range=(0.0, 1.0))
        calibration[arch] = {"n": int(v.size), "counts": counts.tolist()}
    data = {
        "model": meta["model"],
        "calibration": calibration,
        "runs": [run(b) for b in ("siphash_x86_64", "siphash_aarch64", "xxhash_x86_64", "lz4_x86_64")],
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(data), encoding="utf-8")
    for r in data["runs"]:
        print(r["binary"], r["arch"], r["functions"], "functions,", r["selected"], "certified at alpha", ALPHA)


if __name__ == "__main__":
    main()
