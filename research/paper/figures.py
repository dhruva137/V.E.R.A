"""The paper's figures, drawn only from research/results/*.json (no number is typed in here).

Palette: slots 1-3 of the dataviz reference palette (blue, orange, aqua), which validate all-pairs for CVD in
light mode; the alpha bound is a neutral dashed rule, never a series colour. One y-axis per panel.

    python figures.py        -> research/paper/figures/*.png
"""
from __future__ import annotations

import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402

RES = Path(__file__).resolve().parents[1] / "results"
OUT = Path(__file__).resolve().parent / "figures"
BLUE, ORANGE, AQUA = "#2a78d6", "#eb6834", "#1baf7a"
INK, MUTED, GRID = "#0b0b0b", "#52514e", "#e6e4df"
plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 9, "axes.edgecolor": MUTED, "axes.labelcolor": INK,
                     "xtick.color": MUTED, "ytick.color": MUTED, "axes.spines.top": False, "axes.spines.right": False,
                     "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.6, "axes.axisbelow": True})


def J(name):
    return json.loads((RES / name).read_text())


def bars(ax, groups, series, colors, labels, err=None, fmt="{:.1%}"):
    n = len(series)
    w = 0.8 / n
    x = np.arange(len(groups))
    for i, (vals, c, lab) in enumerate(zip(series, colors, labels)):
        pos = x - 0.4 + w * (i + 0.5)
        yerr = None if err is None or err[i] is None else np.array(err[i]).T
        ax.bar(pos, vals, w * 0.92, color=c, label=lab, yerr=yerr, capsize=2, error_kw={"elinewidth": 0.8, "ecolor": INK})
        for j, (p, v) in enumerate(zip(pos, vals)):
            top = v + (err[i][j][1] if err is not None and err[i] is not None else 0)
            ax.text(p, top, fmt.format(v), ha="center", va="bottom", fontsize=7, color=INK)
    ax.set_xticks(x, groups)


def alpha_rule(ax, a):
    ax.axhline(a, color=MUTED, ls="--", lw=1)
    ax.text(ax.get_xlim()[1], a, f" α = {a}", va="bottom", ha="right", color=MUTED, fontsize=8)


def fig1():
    b2 = J("v2_cross_isa.json")["matrix"]
    v11 = J("v1_1_detector.json")["dev_arch_shift"]
    fig, (a1, a2) = plt.subplots(1, 2, figsize=(7.2, 2.8))
    isas = ["x86-64", "aarch64", "arm32"]
    s_x86 = [b2[f"train=all/test={i}/calibrate=x86-64"] for i in isas]
    s_per = [b2[f"train=all/test={i}/calibrate=per-isa"] for i in isas]
    ci = lambda s: [(v["mean_fdp"] - v["fdp_ci95"][0], v["fdp_ci95"][1] - v["mean_fdp"]) for v in s]
    bars(a1, isas, [[v["mean_fdp"] for v in s_x86], [v["mean_fdp"] for v in s_per]], [ORANGE, BLUE],
         ["calibrated on x86-64", "calibrated per ISA"], err=[ci(s_x86), ci(s_per)])
    a1.set_ylim(0, 0.14)
    alpha_rule(a1, 0.1)
    a1.set_title("(a) v2 GNN, trained on all ISAs, α = 0.1", fontsize=9, loc="left")
    a1.set_ylabel("false discovery rate (5% crypto)")
    a1.legend(frameon=False, fontsize=7, loc="upper left")
    x86 = [v11[i]["calibrated_on_x86"]["bh@0.2"]["mean_fdp"] for i in isas]
    per = [v11[i]["recalibrated_on_target"]["bh@0.2"]["mean_fdp"] for i in isas]
    bars(a2, isas, [x86, per], [ORANGE, BLUE], ["calibrated on x86-64", "calibrated per ISA"])
    a2.set_ylim(0, 0.42)
    alpha_rule(a2, 0.2)
    a2.set_title("(b) v1 trees, trained on x86-64 only, α = 0.2", fontsize=9, loc="left")
    fig.tight_layout()
    fig.savefig(OUT / "fig1_per_isa_fdr.png", dpi=220)


def fig2():
    v11 = J("v1_1_detector.json")["sealed"]["conformal"]
    fu = J("v2_fusion_sealed_hgb_v1.json")["prevalence"]
    prevs = [("prevalence=natural", "natural", "34%"), ("prevalence=0.05", "0.05", "5%"), ("prevalence=0.01", "0.01", "1%")]
    fig, (a1, a2) = plt.subplots(1, 2, figsize=(7.2, 2.8))
    fixed = [v11[p]["fixed@0.9"]["mean_fdp"] for p, _, _ in prevs]
    conf = [v11[p]["bh@0.1"]["mean_fdp"] for p, _, _ in prevs]
    bars(a1, [lab for *_, lab in prevs], [fixed, conf], [ORANGE, BLUE], ["fixed confidence ≥ 0.9", "conformal BH, α = 0.1"])
    alpha_rule(a1, 0.1)
    a1.set_ylim(0, 1.0)
    a1.set_ylabel("false share of flagged functions")
    a1.set_xlabel("crypto prevalence (sealed libraries)")
    a1.legend(frameon=False, fontsize=7, loc="upper left")
    a1.set_title("(a) a fixed threshold is not a guarantee", fontsize=9, loc="left")
    v1p = [fu[k]["learned_v1@0.1"]["mean_power"] for _, k, _ in prevs]
    fsp = [fu[k]["stacked_fusion@0.1"]["mean_power"] for _, k, _ in prevs]
    bars(a2, [lab for *_, lab in prevs], [v1p, fsp], [BLUE, AQUA], ["learned rung (v1)", "stacked fusion"])
    a2.set_ylabel("power (share of crypto certified)")
    a2.set_xlabel("crypto prevalence (sealed libraries)")
    a2.legend(frameon=False, fontsize=7, loc="upper right")
    a2.set_title("(b) power at FDR ≤ 0.1, pooled protocol", fontsize=9, loc="left")
    fig.tight_layout()
    fig.savefig(OUT / "fig2_prevalence.png", dpi=220)


def fig3():
    sim = J("theory_sim.json")["thm2"]
    e2e = J("e2e.json")["summary_independent"]
    fig, (a1, a2) = plt.subplots(1, 2, figsize=(7.2, 2.8))
    cells = [("alpha=0.1,rho=0.5,sig_fire=0.0", "0%"), ("alpha=0.1,rho=0.5,sig_fire=0.3", "30%"), ("alpha=0.1,rho=0.5,sig_fire=0.8", "80%")]
    bars(a1, [lab for _, lab in cells],
         [[sim[c]["learned_bh"]["power"] for c, _ in cells], [sim[c]["signature_bh"]["power"] for c, _ in cells],
          [sim[c]["stacked_bh"]["power"] for c, _ in cells]], [BLUE, ORANGE, AQUA],
         ["learned rung", "signature rung", "stacked fusion"])
    a1.set_ylabel("power at FDR ≤ 0.1")
    a1.set_xlabel("share of crypto the signature rung fires on")
    a1.set_title("(a) simulation, 2,000 reps per cell", fontsize=9, loc="left")
    a1.legend(frameon=False, fontsize=7, loc="upper left")
    methods = [("findcrypt3", "Findcrypt3"), ("vera_signatures", "signatures"), ("v1_certified", "certified\nlearned (v1)"),
               ("product", "VERA as\nshipped")]
    progs = [p for p in J("e2e.json")["programs"].values() if not p["train_overlap"]]
    shipped = lambda p: p["flags"]["vera_signatures"] or p["flags"]["v1_certified"]
    pos, neg = [p for p in progs if p["contains_crypto"]], [p for p in progs if not p["contains_crypto"]]
    e2e = dict(e2e, product={"tpr": sum(map(shipped, pos)) / len(pos), "fpr": sum(map(shipped, neg)) / len(neg)})
    tpr = [e2e[m]["tpr"] for m, _ in methods]
    fpr = [e2e[m]["fpr"] for m, _ in methods]
    bars(a2, [lab for _, lab in methods], [tpr, fpr], [BLUE, ORANGE], ["detection rate (crypto binaries)", "false-alarm rate"],
         fmt="{:.0%}")
    a2.set_ylim(0, 1.0)
    a2.set_title(f"(b) stripped static programs ({len(pos)} crypto, {len(neg)} not)",
                 fontsize=9, loc="left")
    a2.legend(frameon=False, fontsize=7, loc="upper left")
    fig.tight_layout()
    fig.savefig(OUT / "fig3_fusion_and_binaries.png", dpi=220)




def fig4():
    """B7: the deployment-shaped protocol on sealed_b (per-ISA calibration, BH inside each synthetic binary)."""
    b = J("v2_scale.json")["B1_sealed_b"]["binaries"]
    sizes = [50, 100, 500]
    fig, (a1, a2) = plt.subplots(1, 2, figsize=(7.2, 2.8))
    for prev, col, lab in ((0.05, BLUE, "5% crypto"), (0.01, ORANGE, "1% crypto")):
        cells = [b[f"m={m},prev={prev}"]["learned_v1"] for m in sizes]
        mean = np.array([c["mean_fdp"] for c in cells])
        up = np.array([c["fdp_ci99_upper"] for c in cells])
        a1.errorbar(sizes, mean, yerr=[mean - np.maximum(0, 2 * mean - up), up - mean], color=col, marker="o", ms=5,
                    lw=2, capsize=3, label=lab)
        a2.plot(sizes, [c["power"] for c in cells], color=col, marker="o", ms=5, lw=2, label=lab)
    a1.axhline(0.1, color=MUTED, ls="--", lw=1)
    a1.text(500, 0.1, " α = 0.1", va="bottom", ha="right", color=MUTED, fontsize=8)
    for a in (a1, a2):
        a.set_xscale("log")
        a.set_xticks(sizes, [str(s) for s in sizes])
        a.set_xlabel("functions in the binary")
        a.legend(frameon=False, fontsize=7)
    a1.set_ylabel("false discovery rate (99% CI)")
    a1.set_ylim(0, 0.2)
    a1.set_title("(a) FDR stays at α within error", fontsize=9, loc="left")
    a2.set_ylabel("power (share of crypto certified)")
    a2.set_title("(b) power falls with size and rarity", fontsize=9, loc="left")
    fig.tight_layout()
    fig.savefig(OUT / "fig4_binaries_sealed_b.png", dpi=220)


if __name__ == "__main__":
    OUT.mkdir(parents=True, exist_ok=True)
    for f in (fig1, fig2, fig3, fig4):
        f()
        print("wrote", f.__name__)
