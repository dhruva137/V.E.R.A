"""v2 architecture decision (Phase A1, A3, A4 and B3): which representation carries the crypto signal?

Candidates, all trained on TRAIN and selected on DEV only (by mean dev PR-AUC over seeds):
    hgb_v1          v1 exactly: gradient-boosted trees on the 74 function features
    hgb_loops       + max/mean of the same features over the function's loops (A1 as a feature change)
    gnn_cfg         GIN over the CFG, basic blocks as nodes (41 operand-aware features each)      (A3)
    gnn_dfg         the same over block-level def-use edges                                          (B3)
    gnn_both        both edge types as two relations                                                 (B3)
    *_hybrid        the GNN/transformer embedding concatenated with the 74 function features
    seq             transformer over instruction-class tokens (<= 512)                               (A4)
The selection is written to results/v2_selection.json BEFORE any sealed score is computed. Then every
candidate is scored on sealed and sealed_b (for the paper's table), and the ship rule is applied to the
selected one: sealed PR-AUC >= v1 + 0.03 AND >= 5,000 functions/s on CPU.

    python v2_models.py [--seeds 3] [--epochs 25]
GPU: RTX 5050 8 GB, mixed precision; CPU fallback works but is slow.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import average_precision_score, roc_auc_score

sys.path.insert(0, str(Path(__file__).resolve().parent))
from v1_detector import ROOT, SEED, _commit  # noqa: E402
from v2_data import load, loop_features  # noqa: E402

OUT = ROOT / "research" / "results"
MODELS = ROOT / "research" / "models"
DEV_ = "cuda" if torch.cuda.is_available() else "cpu"


# ---------------------------------------------------------------- data tensors

class Pack:
    """Rows of one split turned into tensors once."""

    def __init__(self, rows, fmean, fstd):
        self.y = np.array([r["y"] for r in rows], dtype=np.float32)
        self.f = np.clip((np.stack([r["fvec"] for r in rows]) - fmean) / fstd, -10, 10).astype(np.float32)
        self.nodes = [r["nodes"].astype(np.float32) for r in rows]
        self.cfg = [r["cfg"].astype(np.int64) for r in rows]
        self.dfg = [r["dfg"].astype(np.int64) for r in rows]
        self.tok = [r["tokens"].astype(np.int64) for r in rows]

    def graph_batch(self, idx, edges: str):
        xs, eis, eis2, gid, off = [], [], [], [], 0
        for b, i in enumerate(idx):
            n = len(self.nodes[i])
            xs.append(self.nodes[i])
            e1 = self.cfg[i] if edges in ("cfg", "both") else self.dfg[i]
            eis.append(e1 + off)
            if edges == "both":
                eis2.append(self.dfg[i] + off)
            gid.append(np.full(n, b))
            off += n
        t = lambda a: torch.from_numpy(np.concatenate(a)).to(DEV_)
        ei = t(eis).reshape(-1, 2).T if sum(len(e) for e in eis) else torch.zeros(2, 0, dtype=torch.long, device=DEV_)
        ei2 = None
        if edges == "both":
            ei2 = t(eis2).reshape(-1, 2).T if sum(len(e) for e in eis2) else torch.zeros(2, 0, dtype=torch.long, device=DEV_)
        return t(xs), ei, ei2, t(gid), len(idx)

    def token_batch(self, idx):
        L = max(len(self.tok[i]) for i in idx)
        out = np.zeros((len(idx), L), dtype=np.int64)
        for b, i in enumerate(idx):
            out[b, :len(self.tok[i])] = self.tok[i]
        return torch.from_numpy(out).to(DEV_)


# ---------------------------------------------------------------- models

class GIN(nn.Module):
    def __init__(self, d_in, relations, hidden=96, layers=3, hybrid=False, d_f=74):
        super().__init__()
        self.relations = relations
        self.inp = nn.Linear(d_in, hidden)
        self.layers = nn.ModuleList()
        for _ in range(layers):
            self.layers.append(nn.ModuleDict({
                "mlp": nn.Sequential(nn.Linear(hidden * (1 + relations), hidden), nn.ReLU(), nn.Linear(hidden, hidden)),
                "norm": nn.LayerNorm(hidden)}))
        self.hybrid = hybrid
        head_in = 2 * hidden + (d_f if hybrid else 0)
        self.head = nn.Sequential(nn.Linear(head_in, hidden), nn.ReLU(), nn.Dropout(0.1), nn.Linear(hidden, 1))

    @staticmethod
    def _agg(h, ei):
        out = torch.zeros_like(h)
        if ei.shape[1]:
            src, dst = ei
            out.index_add_(0, dst, h[src])
            out.index_add_(0, src, h[dst])          # messages both ways: structure, not execution order
        return out

    def forward(self, x, ei, ei2, gid, n_graphs, f=None):
        h = torch.relu(self.inp(x))
        for layer in self.layers:
            parts = [h, self._agg(h, ei)]
            if self.relations == 2:
                parts.append(self._agg(h, ei2))
            h = layer["norm"](h + layer["mlp"](torch.cat(parts, 1)))
        return GIN._readout(self, h, gid, n_graphs, f)

    @staticmethod
    def _readout(self, h, gid, n_graphs, f):
        h = h.float()                                   # pool in fp32: sums over 512 blocks overflow fp16
        s = torch.zeros(n_graphs, h.shape[1], device=h.device).index_add_(0, gid, h)
        mx = torch.full((n_graphs, h.shape[1]), -1e4, device=h.device)
        mx = mx.scatter_reduce(0, gid[:, None].expand_as(h), h, reduce="amax", include_self=True)
        z = torch.cat([s / 10.0, mx], 1)
        if self.hybrid:
            z = torch.cat([z, f.float()], 1)
        return self.head(z).squeeze(1)


class SAGE(nn.Module):
    """GraphSAGE: mean of neighbours (both directions) concatenated with self, per layer."""

    def __init__(self, d_in, hidden=128, layers=3, hybrid=True, d_f=74):
        super().__init__()
        self.inp = nn.Linear(d_in, hidden)
        self.layers = nn.ModuleList([nn.Linear(2 * hidden, hidden) for _ in range(layers)])
        self.norms = nn.ModuleList([nn.LayerNorm(hidden) for _ in range(layers)])
        self.hybrid = hybrid
        self.head = nn.Sequential(nn.Linear(2 * hidden + (d_f if hybrid else 0), hidden), nn.ReLU(), nn.Dropout(0.1),
                                  nn.Linear(hidden, 1))

    def forward(self, x, ei, ei2, gid, n_graphs, f=None):
        h = torch.relu(self.inp(x))
        n = h.shape[0]
        if ei.shape[1]:
            src = torch.cat([ei[0], ei[1]])
            dst = torch.cat([ei[1], ei[0]])
        else:
            src = dst = torch.zeros(0, dtype=torch.long, device=h.device)
        deg = torch.zeros(n, device=h.device).index_add_(0, dst, torch.ones_like(dst, dtype=torch.float)).clamp(min=1)
        for lin, norm in zip(self.layers, self.norms):
            agg = torch.zeros_like(h).index_add_(0, dst, h[src]) / deg[:, None].to(h.dtype)
            h = norm(h + torch.relu(lin(torch.cat([h, agg], 1))))
        return GIN._readout(self, h, gid, n_graphs, f)


class GAT(nn.Module):
    """Single-head graph attention over CFG edges (both directions) plus self-loops."""

    def __init__(self, d_in, hidden=128, layers=3, hybrid=True, d_f=74):
        super().__init__()
        self.inp = nn.Linear(d_in, hidden)
        self.W = nn.ModuleList([nn.Linear(hidden, hidden, bias=False) for _ in range(layers)])
        self.a = nn.ParameterList([nn.Parameter(torch.randn(2 * hidden) * 0.05) for _ in range(layers)])
        self.norms = nn.ModuleList([nn.LayerNorm(hidden) for _ in range(layers)])
        self.hybrid = hybrid
        self.head = nn.Sequential(nn.Linear(2 * hidden + (d_f if hybrid else 0), hidden), nn.ReLU(), nn.Dropout(0.1),
                                  nn.Linear(hidden, 1))

    def forward(self, x, ei, ei2, gid, n_graphs, f=None):
        h = torch.relu(self.inp(x))
        n = h.shape[0]
        loop = torch.arange(n, device=h.device)
        src = torch.cat([ei[0], ei[1], loop]) if ei.shape[1] else loop
        dst = torch.cat([ei[1], ei[0], loop]) if ei.shape[1] else loop
        for W, a, norm in zip(self.W, self.a, self.norms):
            z = W(h).float()
            d = z.shape[1]
            e = torch.nn.functional.leaky_relu((z[src] * a[:d]).sum(1) + (z[dst] * a[d:]).sum(1), 0.2)
            mx = torch.full((n,), -1e9, device=h.device).scatter_reduce(0, dst, e, reduce="amax", include_self=True)
            w = torch.exp(e - mx[dst])
            den = torch.zeros(n, device=h.device).index_add_(0, dst, w).clamp(min=1e-9)
            msg = torch.zeros_like(z).index_add_(0, dst, z[src] * (w / den[dst])[:, None])
            h = norm(h.float() + torch.nn.functional.elu(msg)).to(h.dtype)
        return GIN._readout(self, h, gid, n_graphs, f)


class SeqModel(nn.Module):
    def __init__(self, vocab, d=64, layers=2, heads=4, hybrid=False, d_f=74, max_len=512):
        super().__init__()
        self.emb = nn.Embedding(vocab, d, padding_idx=0)
        self.pos = nn.Embedding(max_len, d)
        enc = nn.TransformerEncoderLayer(d, heads, 2 * d, dropout=0.1, batch_first=True, norm_first=True)
        self.enc = nn.TransformerEncoder(enc, layers)
        self.hybrid = hybrid
        self.head = nn.Sequential(nn.Linear(2 * d + (d_f if hybrid else 0), d), nn.ReLU(), nn.Linear(d, 1))

    def forward(self, tok, f=None):
        pad = tok == 0
        h = self.emb(tok) + self.pos(torch.arange(tok.shape[1], device=tok.device))[None]
        h = self.enc(h, src_key_padding_mask=pad)
        keep = (~pad).unsqueeze(-1).to(h.dtype)
        mean = (h * keep).sum(1) / keep.sum(1).clamp(min=1)
        z = torch.cat([h[:, 0], mean], 1)
        if self.hybrid:
            z = torch.cat([z, f], 1)
        return self.head(z).squeeze(1)


# ---------------------------------------------------------------- training

def run_neural(kind, packs, seed, epochs, batch):
    torch.manual_seed(seed)
    np.random.seed(seed)
    tr, dv = packs["train"], packs["dev"]
    hybrid = kind.endswith("_hybrid")
    base = kind.replace("_hybrid", "")
    if base == "seq":
        model = SeqModel(100, hybrid=hybrid)
    elif base.startswith("sage"):
        model = SAGE(tr.nodes[0].shape[1], hybrid=hybrid)
    elif base.startswith("gat"):
        model = GAT(tr.nodes[0].shape[1], hybrid=hybrid)
    else:
        edges = base.split("_")[1]
        model = GIN(tr.nodes[0].shape[1], 2 if edges == "both" else 1, hybrid=hybrid)
    model.to(DEV_)
    opt = torch.optim.AdamW(model.parameters(), lr=2e-3, weight_decay=1e-4)
    pos_w = torch.tensor((tr.y == 0).sum() / max(1, tr.y.sum()), device=DEV_)
    lossf = nn.BCEWithLogitsLoss(pos_weight=pos_w)
    scaler = torch.amp.GradScaler("cuda", enabled=DEV_ == "cuda")

    def predict(pack):
        model.eval()
        out = []
        with torch.no_grad(), torch.autocast(DEV_, dtype=torch.float16, enabled=DEV_ == "cuda"):
            for s in range(0, len(pack.y), 512):
                idx = np.arange(s, min(len(pack.y), s + 512))
                out.append(torch.sigmoid(forward(pack, idx).float()).cpu().numpy())
        return np.concatenate(out)

    def forward(pack, idx):
        f = torch.from_numpy(pack.f[idx]).to(DEV_) if hybrid else None
        if base == "seq":
            return model(pack.token_batch(idx), f)
        x, ei, ei2, gid, n = pack.graph_batch(idx, base.split("_")[1])
        return model(x, ei, ei2, gid, n, f)

    best, best_state, history = -1.0, None, []
    rng = np.random.default_rng(seed)
    for ep in range(epochs):
        model.train()
        order = rng.permutation(len(tr.y))
        for s in range(0, len(order), batch):
            idx = order[s:s + batch]
            yb = torch.from_numpy(tr.y[idx]).to(DEV_)
            with torch.autocast(DEV_, dtype=torch.float16, enabled=DEV_ == "cuda"):
                loss = lossf(forward(tr, idx).float(), yb)
            opt.zero_grad(set_to_none=True)
            scaler.scale(loss).backward()
            scaler.unscale_(opt)
            nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            scaler.step(opt)
            scaler.update()
        ap = average_precision_score(dv.y, predict(dv))
        history.append(round(float(ap), 4))
        if ap > best:
            best = ap
            best_state = {k: v.detach().clone() for k, v in model.state_dict().items()}
    model.load_state_dict(best_state)
    return model, predict, history


def cpu_throughput(kind, model, pack):
    """Functions/s for the model alone on CPU (features already built), batch 1024, 4 threads."""
    torch.set_num_threads(4)
    m = model.to("cpu").float().eval()
    global DEV_
    saved, DEV_ = DEV_, "cpu"
    idx = np.arange(min(2048, len(pack.y)))
    hybrid = kind.endswith("_hybrid")
    base = kind.replace("_hybrid", "")
    with torch.no_grad():
        t0 = time.perf_counter()
        for s in range(0, len(idx), 1024):
            b = idx[s:s + 1024]
            f = torch.from_numpy(pack.f[b]) if hybrid else None
            if base == "seq":
                m(pack.token_batch(b), f)
            else:
                x, ei, ei2, gid, n = pack.graph_batch(b, base.split("_")[1])
                m(x, ei, ei2, gid, n, f)
        dt = time.perf_counter() - t0
    DEV_ = saved
    return round(len(idx) / dt)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, default=3)
    ap.add_argument("--epochs", type=int, default=25)
    ap.add_argument("--batch", type=int, default=256)
    ap.add_argument("--kinds", nargs="*", default=["gnn_cfg", "gnn_dfg", "gnn_both", "gnn_cfg_hybrid",
                                                    "gnn_both_hybrid", "seq", "seq_hybrid"])
    args = ap.parse_args()
    t0 = time.time()
    meta, rows, counts = load()
    parts = {s: [r for r in rows if r["split"] == s] for s in ("train", "dev", "sealed")}
    F_tr = np.stack([r["fvec"] for r in parts["train"]])
    fmean, fstd = F_tr.mean(0), np.maximum(F_tr.std(0), 1e-3)
    res = {"commit": _commit(), "seed": SEED, "device": torch.cuda.get_device_name(0) if DEV_ == "cuda" else "cpu",
           "label_counts": counts, "rows": {k: len(v) for k, v in parts.items()}, "candidates": {}}

    # Tree baselines (deterministic, one fit each).
    trees = {}
    for name, feats in (("hgb_v1", lambda r: r["fvec"]), ("hgb_loops", lambda r: np.r_[r["fvec"], loop_features(r)])):
        X = {s: np.stack([feats(r) for r in parts[s]]) for s in parts}
        y = {s: np.array([r["y"] for r in parts[s]]) for s in parts}
        clf = HistGradientBoostingClassifier(max_iter=400, learning_rate=0.05, max_leaf_nodes=31,
                                             class_weight="balanced", random_state=SEED).fit(X["train"], y["train"])
        t = time.perf_counter()
        clf.predict_proba(X["dev"])
        thr = round(len(X["dev"]) / (time.perf_counter() - t))
        trees[name] = (clf, X, y)
        res["candidates"][name] = {"dev_pr_auc": [round(average_precision_score(y["dev"], clf.predict_proba(X["dev"])[:, 1]), 4)],
                                   "cpu_functions_per_s": thr}
        print(name, res["candidates"][name], flush=True)

    packs = {s: Pack(parts[s], fmean, fstd) for s in parts}
    neural = {}
    for kind in args.kinds:
        aps, hist, models = [], [], []
        t1 = time.time()
        for sd in range(args.seeds):
            model, predict, h = run_neural(kind, packs, SEED + sd, args.epochs, args.batch)
            aps.append(round(float(max(h)), 4))
            hist.append(h)
            models.append((model, predict))
        neural[kind] = models
        res["candidates"][kind] = {"dev_pr_auc": aps, "dev_curve_seed0": hist[0], "train_minutes": round((time.time() - t1) / 60, 1)}
        print(kind, aps, f"{(time.time() - t1) / 60:.1f} min", flush=True)
        torch.cuda.empty_cache()

    # ---- selection on dev, written before any sealed score exists
    mean_dev = {k: float(np.mean(v["dev_pr_auc"])) for k, v in res["candidates"].items()}
    selected = max(mean_dev, key=mean_dev.get)
    OUT.mkdir(exist_ok=True)
    (OUT / "v2_selection.json").write_text(json.dumps({"selected": selected, "mean_dev_pr_auc": mean_dev,
                                                       "commit": res["commit"], "time": time.strftime("%Y-%m-%dT%H:%M:%S")}, indent=2))
    res["selected_on_dev"] = selected
    print("SELECTED on dev:", selected, flush=True)

    # ---- sealed scores for every candidate (selection is already fixed)
    ys = packs["sealed"].y
    for name, (clf, X, y) in trees.items():
        s = clf.predict_proba(X["sealed"])[:, 1]
        res["candidates"][name]["sealed"] = {"pr_auc": round(average_precision_score(ys, s), 4), "roc_auc": round(roc_auc_score(ys, s), 4)}
        np.save(OUT / f"v2_scores_{name}_sealed.npy", s)
        np.save(OUT / f"v2_scores_{name}_dev.npy", clf.predict_proba(X["dev"])[:, 1])
    for kind, models in neural.items():
        prs, rocs, all_s = [], [], []
        for model, predict in models:
            s = predict(packs["sealed"])
            all_s.append(s)
            prs.append(round(average_precision_score(ys, s), 4))
            rocs.append(round(roc_auc_score(ys, s), 4))
        np.save(OUT / f"v2_scores_{kind}_sealed.npy", np.mean(all_s, 0))
        np.save(OUT / f"v2_scores_{kind}_dev.npy", np.mean([p(packs["dev"]) for _, p in models], 0))
        res["candidates"][kind]["sealed"] = {"pr_auc": prs, "roc_auc": rocs, "pr_auc_seed_mean_ensemble":
                                             round(average_precision_score(ys, np.mean(all_s, 0)), 4)}
        res["candidates"][kind]["cpu_functions_per_s"] = cpu_throughput(kind, models[0][0], packs["dev"])
        MODELS.mkdir(parents=True, exist_ok=True)
        torch.save(models[0][0].state_dict(), MODELS / f"{kind}_seed0.pt")
        models[0][0].to(DEV_)
    v1_pr = res["candidates"]["hgb_v1"]["sealed"]["pr_auc"]
    sel = res["candidates"][selected]
    sel_pr = np.mean(sel["sealed"]["pr_auc"]) if isinstance(sel["sealed"]["pr_auc"], list) else sel["sealed"]["pr_auc"]
    res["ship_rule"] = {"v1_sealed_pr_auc": v1_pr, "selected_sealed_pr_auc": round(float(sel_pr), 4),
                        "gain": round(float(sel_pr - v1_pr), 4), "cpu_functions_per_s": sel["cpu_functions_per_s"],
                        "ship": bool(sel_pr - v1_pr >= 0.03 and sel["cpu_functions_per_s"] >= 5000)}
    res["minutes"] = round((time.time() - t0) / 60, 1)
    (OUT / "v2_models.json").write_text(json.dumps(res, indent=2))
    print(json.dumps(res["ship_rule"], indent=2))


if __name__ == "__main__":
    main()
