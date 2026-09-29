"""End to end through the product itself: exactly what VERA reports for each stripped program.

e2e_eval.py compares research variants and refits v1; the self-audit (0.5) found a refit on reordered rows is
not bit-identical to the shipped artefact. This script removes that gap: it calls the binary collector
(collectors.binary_scanner.scan_blob) with the shipped model, shipped per-ISA calibration and every layer on,
and records what the product would put in the CBOM. It is the source of the "as shipped" numbers.

    python e2e_product.py      -> research/results/e2e_product.json
"""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(ROOT / "research" / "experiments"))
os.environ["VERA_BINARY_DETECTOR"] = "1"
from collectors.binary_scanner import scan_blob  # noqa: E402
from v1_detector import _commit  # noqa: E402


def main():
    t0 = time.time()
    manifest = json.loads((HERE / "manifest.json").read_text())
    out = {"commit": _commit(), "path": "collectors.binary_scanner.scan_blob (shipped model + calibration)", "programs": {}}
    for key, info in sorted(manifest.items()):
        p = HERE / "bin" / f"{key}.stripped"
        t = time.perf_counter()
        res = scan_blob(p.read_bytes(), str(p))
        seconds = time.perf_counter() - t
        layers = sorted({layer for f in res.findings for layer in f.raw_details.get("layers", [])})
        learned = [f for f in res.findings if "layer:learned_function" in f.tags]
        out["programs"][key] = {
            "contains_crypto": info["contains_crypto"], "train_overlap": info["train_overlap"],
            "flagged": bool(res.findings), "layers": layers,
            "algorithms": sorted({f.algorithm for f in res.findings if f.algorithm}),
            "learned_q": learned[0].raw_details["detection_q_value"] if learned else None,
            "functions_scored": res.stats.get("functions_scored", 0), "failures": [str(x) for x in res.failures][:3],
            "seconds": round(seconds, 2),
        }
        print(key, out["programs"][key]["flagged"], layers, out["programs"][key]["algorithms"], flush=True)
    for scope in ("independent", "all"):
        progs = [v for v in out["programs"].values() if scope == "all" or not v["train_overlap"]]
        pos = [v for v in progs if v["contains_crypto"]]
        neg = [v for v in progs if not v["contains_crypto"]]
        out[f"summary_{scope}"] = {"detected": sum(v["flagged"] for v in pos), "positives": len(pos),
                                   "false_alarms": sum(v["flagged"] for v in neg), "negatives": len(neg),
                                   "found_only_by_learned_layer": sum(v["layers"] == ["learned_function"] for v in pos),
                                   "median_seconds_per_binary": sorted(v["seconds"] for v in progs)[len(progs) // 2]}
    out["minutes"] = round((time.time() - t0) / 60, 1)
    (ROOT / "research" / "results" / "e2e_product.json").write_text(json.dumps(out, indent=2))
    print(json.dumps({k: v for k, v in out.items() if k.startswith("summary")}, indent=2))


if __name__ == "__main__":
    main()
