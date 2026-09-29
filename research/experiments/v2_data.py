"""Load v2 function views with protocol-v2 labels and the pre-registered splits.

Same labelling as v1.1 (core_labels.py, frozen) and the same splits:
    train   mbedtls libtomcrypt bcon tiny-aes | lua zstd cjson zlib
    dev     pqclean monocypher micro-ecc      | stb lz4 xxhash kissfft          (all choices are made here)
    sealed  bearssl tweetnacl siphash         | brotli libdeflate yyjson lodepng
    sealed_b libsodium wolfssl                | sqlite libpng                    (registered before v2 work)
"""
from __future__ import annotations

import pickle
from pathlib import Path

import numpy as np
import pandas as pd

BENCH = Path(__file__).resolve().parents[1] / "indicrypt_bench"
TRAIN = {"mbedtls", "libtomcrypt", "bcon", "tiny-aes", "lua", "zstd", "cjson", "zlib"}
DEV = {"pqclean", "monocypher", "micro-ecc", "stb", "lz4", "xxhash", "kissfft"}
SEALED = {"bearssl", "tweetnacl", "siphash", "brotli", "libdeflate", "yyjson", "lodepng"}
SEALED_B = {"libsodium", "wolfssl", "sqlite", "libpng"}
SEALED_C = {"blake3", "argon2", "tiny_sha3"}                                    # registered in the self-audit
SPLIT = {**{l: "train" for l in TRAIN}, **{l: "dev" for l in DEV}, **{l: "sealed" for l in SEALED},
         **{l: "sealed_b" for l in SEALED_B}, **{l: "sealed_c" for l in SEALED_C}}


def load(subdir: str | tuple[str, ...] = "v2_o0o2") -> tuple[pd.DataFrame, list[dict], dict]:
    """(meta frame, per-row dicts with arrays, label counts). Orchestration functions are dropped."""
    rows = []
    for d in ((subdir,) if isinstance(subdir, str) else subdir):
        for shard in sorted((BENCH / d).glob("shard_*.pkl")):
            rows += pickle.load(open(shard, "rb"))
    core = pd.read_csv(BENCH / "core_labels.csv")
    core = core[core.ops >= 0].drop_duplicates(["library", "rel", "name"])
    core_map = {(r.library, r.rel, r.name): int(r.core) for r in core.itertuples()}
    keep, counts = [], {"core": 0, "orchestration": 0, "unmatched": 0, "noncrypto": 0}
    for r in rows:
        if r["label"] == "noncrypto":
            status = "noncrypto"
        else:
            c = core_map.get((r["library"], r["rel"], r["name"].split(".")[0]))
            status = "core" if c == 1 else "orchestration" if c == 0 else "unmatched"
        counts[status] += 1
        if status in ("core", "noncrypto"):
            r["y"] = int(status == "core")
            r["split"] = SPLIT[r["library"]]
            keep.append(r)
    meta = pd.DataFrame([{k: r[k] for k in ("library", "rel", "label", "family", "toolchain", "opt", "arch",
                                              "name", "uid", "n_insns", "y", "split", "code_sha")} for r in keep])
    return meta, keep, counts


LOOP_AGG = ("loop_max", "loop_mean")


def loop_features(r: dict) -> np.ndarray:
    """Max and mean of the v1 feature vector over the function's loops (zeros when it has none), plus count."""
    L = r["loops"]
    if len(L) == 0:
        return np.zeros(2 * 74 + 1, dtype=np.float32)
    return np.r_[L.max(0), L.mean(0), [np.log1p(len(L))]].astype(np.float32)
