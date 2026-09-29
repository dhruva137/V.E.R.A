"""Export the v1 detector as the CPU artefact the product ships (backend/engine/binary_ml/model/).

What ships is exactly what was evaluated in v1_1_detector.py: gradient-boosted trees on the mnemonic +
operand features, trained on the TRAIN libraries only. Alongside it go the calibration null scores, per ISA,
taken from the non-crypto functions of the held-out libraries (dev and sealed). Those functions never
touched training, and per-ISA calibration is what v1.1 showed the guarantee needs.

    python export_v1.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import sklearn

sys.path.insert(0, str(Path(__file__).resolve().parent))
from v1_1_detector import DEV, SEALED, TRAIN, load, models  # noqa: E402
from v1_detector import ROOT, SEED, _commit  # noqa: E402
from engine.binary_ml.features import FEATURES  # noqa: E402

OUT = ROOT / "backend" / "engine" / "binary_ml" / "model"


def main() -> None:
    df, _ = load()
    tr = df[df.library.isin(TRAIN)]
    held_null = df[df.library.isin(DEV | SEALED) & (df.y == 0)]
    clf = models()["hgb"]().fit(tr[list(FEATURES)].values, tr.y.values)
    scores = clf.predict_proba(held_null[list(FEATURES)].values)[:, 1]
    calibration = {arch: sorted(round(float(s), 6) for s in scores[(held_null.arch == arch).values])
                   for arch in ("x86-64", "aarch64", "arm32")}
    OUT.mkdir(parents=True, exist_ok=True)
    joblib.dump(clf, OUT / "v1_model.joblib", compress=3)
    meta = {
        "model": "v1: HistGradientBoosting, mnemonic + operand features",
        "trained_on": sorted(TRAIN), "calibration_from": sorted(DEV | SEALED),
        "features": list(FEATURES), "commit": _commit(), "seed": SEED,
        "sklearn_version": sklearn.__version__,
        "calibration_nulls": {a: len(v) for a, v in calibration.items()},
        "evaluation": "research/results/v1_1_detector.json",
    }
    (OUT / "v1_calibration.json").write_text(json.dumps({"meta": meta, "null_scores": calibration}))
    size = (OUT / "v1_model.joblib").stat().st_size
    print(json.dumps({**meta, "model_bytes": size, "features": len(FEATURES)}, indent=2))


if __name__ == "__main__":
    np.random.seed(SEED)
    main()
