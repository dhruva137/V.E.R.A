# Research: calibrated, signature-free crypto detection in binaries

This folder is the research loop behind V.E.R.A.'s binary detector: the benchmark (IndiCrypt-Bench), the
experiments, and their results. **Nothing here is needed to run V.E.R.A..** The product runs offline on a
plain CPU. It uses the feature and calibration code in `backend/engine/binary_ml/` and a small exported
model. Experiments here may use a GPU later (v2 onwards). Their output is always (a) a decision in one
line and (b) a CPU-servable artefact. None of them is a notebook.

## The question v1 answers

The existing binary collector finds cryptography by linked libraries, symbols, banners and constant
tables. It states its own gap: no disassembly, so it misses custom code, stripped static builds, and
tables computed at start-up. v1 asks three things:

1. Can a statistical detector over disassembly find crypto *functions* in libraries it has never seen,
   on x86-64, AArch64 and ARM32? Does adding operand features help, which Mnemocrypt (NDSS BAR 2025)
   names as its own gap?
2. Can the CBOM carry a **distribution-free false-discovery guarantee** on those findings?
3. Where does the guarantee break?

## IndiCrypt-Bench v0

The PS says open datasets such as GitHub repositories and OpenSSL may be used. v0 takes 23 open-source
libraries at pinned commits (`indicrypt_bench/manifest.py`) and compiles them with four toolchains:

- clang for x86-64, AArch64 and ARM32
- gcc (MinGW) for x86-64

Each is built at O0 and O2 (`build.py`: 7,056 compiles, 6,856 succeeded; failures stay listed in
`objects/index.jsonl`).

| Split | Crypto libraries | Non-crypto libraries (hard negatives) |
|---|---|---|
| train | mbedtls, libtomcrypt, bcon, tiny-AES | Lua, zstd, cJSON, zlib |
| dev | PQClean (ML-KEM, ML-DSA, HQC, Falcon, SPHINCS+), Monocypher, micro-ecc | stb (JPEG IDCT), lz4, xxHash, kissfft (fixed-point FFT) |
| **sealed** | BearSSL, TweetNaCl, SipHash | brotli, libdeflate, yyjson, lodepng |

Non-crypto files *inside* crypto libraries are negatives too: mbedtls X.509/TLS/base64 and libtomcrypt
DER/CRC/Adler.

**Labelling** (`core_labels.py`, protocol v2, frozen). A function is crypto if its source file implements
a primitive **and** its preprocessed source does primitive computation. That means at least 3 arithmetic
or bitwise operators, counting inlined static callees and ignoring loop headers and array indices.
Wrappers in crypto files are excluded rather than labelled negative. This matches Mnemocrypt's
function-level labelling (173 crypto functions out of 19,482 in its OpenSSL build). Labels come from
source, never from the binary, so they cannot leak detector features.

Result: 45,415 function instances (1,634 unique functions in sealed) after dropping, and counting,
6,587 tiny functions, 2,860 lifecycle functions, 6,245 byte-identical duplicates and 4,713 orchestration
wrappers.

## Results (all CPU; commit `872d5f6`; seed 20260928; 200 random calibration/test splits by source function)

`results/v1_1_detector.json`, produced by `experiments/v1_1_detector.py`.

**Detection on the sealed set.** Model chosen on dev (gradient-boosted trees, mnemonic + operand
features), trained on train only, scored once:

| | ROC-AUC | PR-AUC |
|---|---|---|
| all | 0.826 | 0.737 |
| x86-64 | 0.834 | 0.752 |
| AArch64 | 0.805 | 0.722 |
| ARM32 | 0.831 | 0.721 |

**Operand ablation** (dev, same model family). ROC-AUC 0.760 with mnemonic features only, 0.742 with
operand features only, **0.793 with both**. On ARM32: 0.757 → 0.782.

**The guarantee** (sealed; FDP is the false share among selected functions, averaged over splits):

| Crypto prevalence | Fixed threshold 0.9 (Mnemocrypt's mode) | Conformal BH α=0.05 | α=0.1 | α=0.2 |
|---|---|---|---|---|
| natural (34%) | FDP 14.5% | 3.6% | 6.7% | 13.4% |
| 5% | **60.8%** | 1.3% | 8.0% | 17.5% |
| 1% | **89.5%** | 0.7% | 3.7% | 13.6% |

A fixed confidence threshold does not control false discoveries when cryptography is rare, and in real
binaries it is rare. Conformal selection stays at or under α in every row.

**Where it breaks: ISA shift** (dev; trained and calibrated on x86-64 only; tested at 5% prevalence):

| Test ISA | Calibrated on x86-64, α=0.2 | Recalibrated on target ISA, α=0.2 |
|---|---|---|
| x86-64 | FDP 10.1% | 7.6% |
| AArch64 | 0.0% (over-conservative, power 0.4%) | 6.7% |
| ARM32 | **35.6%: the guarantee fails** | 3.9% |

Exchangeability is the real assumption, and a new ISA violates it. The fix that works is calibrating
per ISA, which the CBOM layer therefore does. A few hundred labelled non-crypto functions per ISA are
enough. They are cheap to produce from open-source builds.

**The weakness: power.** At 5% prevalence and α=0.1, conformal BH certifies only 2.8% of crypto functions
on sealed. At natural prevalence and α=0.2 it certifies 25.3%. The guarantee is sound, but a statistical
detector at AUC 0.83 is too weak to certify much. This is the measured reason for v2.

**e-value composition.** Averaging the e-values of the mnemonic-only and operand-only detectors is valid
under any dependence (FDP 0.3% at α=0.1) but has almost no power (0.4%). Composition only pays once the
rungs are individually strong. That is a v3 result, not a v1 one.

**Baselines** (v1 first run, file-level labels, dev set, `results/v1_detector.json`):

| Method | FDP | TPR | Note |
|---|---|---|---|
| Findcrypt3 | 0% | 1.8% | ELF only, relocation attribution |
| Caballero adjusted | 43.2% | 98.0% | |

Findcrypt misses:
- MD5 on AArch64: its constants are built from `movz/movk` halves
- mbedtls AES: its tables are computed at start-up
- the SHA-256 K table: the released rule lists only the IV

**CPU cost** (`results/v1_cpu_cost.json`): model 1.56 MB; trains in 9.9 s; scores 83k functions/s.
Disassembly is the bottleneck, at about 236 functions/s per core in Python.

## In the product: end to end on stripped static binaries

`research/experiments/export_v1.py` exports exactly the evaluated model (688 KB) with per-ISA calibration nulls
from held-out non-crypto functions: x86-64 5,194, AArch64 2,552, ARM32 2,538. The binary collector's
`learned_function` layer uses it only when no other layer found anything in an ELF/PE binary. It emits a CBOM
finding with its q-value (`vera:detection-q-value`). Fixtures are in `backend/tests/fixtures/learned/`, built with
`-static -s`: no symbols, and boundaries recovered from call targets.

| Binary | Result |
|---|---|
| SipHash-2-4 CLI, x86-64 | 1 of 36 functions certified at α=0.1, q = 0.083; it is the SipHash core (its 64-bit init constant is in the function) |
| SipHash-2-4 CLI, AArch64 | 1 of 44 certified, q = 0.052. The constant exists only as 16-bit `movk` halves, which byte signatures miss |
| Made-up ARX cipher, x86-64 | **Missed.** The compiler inlined the cipher into `main` next to argument parsing and `printf`. The recovered region scores 0.16, so nothing is certified |

The miss is the v1 limitation stated plainly: function-level scoring cannot see cryptography inlined into
orchestration code. Pre-registered for v2: score loop-level regions (strongly connected components of the CFG),
not whole functions, and measure recall on the same fixture.

## Decisions (one line each)

- **Gradient-boosted trees over random forest.** Dev PR-AUC 0.771 vs 0.739 on the same features.
- **Operand features stay in.** +0.033 dev ROC-AUC and +0.025 on ARM32; mnemonic-only is worse on every ISA.
- **Calibration is per ISA.** An x86-calibrated threshold gave FDP 35.6% on ARM32 at α=0.2.
- **v2 builds a graph model over the CFG/DFG** (trained on the GPU, exported to CPU). v1 cannot certify
  enough functions (power 2.8% at 5% prevalence).

## v2: theory, fusion, architectures, scale and end to end (2026-09-28)

Full write-up: `paper/paper.md` (short-paper draft) and `THEORY.md` (statements and proofs). Figures:
`paper/figures/` (regenerate with `python paper/figures.py`). Every number below is in the named file.

| Question | Answer | File |
|---|---|---|
| Do the guarantees hold? | Per-ISA BH and both fusion theorems: 0 violations over 21 settings × 2,000 reps; wrong-ISA calibration fails (FDR 0.19–0.96) | `theory_sim.json` |
| Graph or sequence model? (A3/A4/B3) | Selected on dev: GNN over CFG + v1 features. Sealed PR-AUC 0.725 vs v1 0.737 (−0.012 at the clean commit; +0.004 in the first run; < +0.03 either way): **not shipped**. CFG > DFG > sequence; transformer scores 32 functions/s on CPU | `v2_models.json` |
| Loops (A1) | Loop aggregates: no gain on sealed (0.739), best single rung on sealed-B (power 21.1% vs 19.5%); inlined-cipher region 0.16 → 0.83 in a pilot, still not certified | `v2_models.json`, `v2_scale.json` |
| New opt levels (B5) | v1 trained on O0/O2 holds on unseen O3 (ROC-AUC 0.856) and Os (0.845); retraining on all opts adds ≤ 0.02 | `v2_scale.json` |
| New libraries (A2) | Sealed-B (libsodium, wolfSSL, SQLite, libpng): ROC-AUC 0.797, PR-AUC 0.580 | `v2_scale.json` |
| Fusion (B1) | Simulation: stacked fusion 12% → 40% power when rungs are complementary. Real: sealed 12.1% → 14.8%; sealed-B 19.5% → **14.4% (worse)**: Findcrypt3 fires equally on crypto and CRC code there | `theory_sim.json`, `v2_fusion_*.json`, `v2_scale.json` |
| Per-ISA calibration (B2) | x86-calibrated FDR on AArch64/ARM32 6.0%/7.8% vs per-ISA 1.2%/1.9% (clean-commit rerun; first run 7.6%/7.9% vs 1.6%/2.4%) (5 seeds × 500 splits, 95% CIs) | `v2_cross_isa.json` |
| Deployment protocol (B7) | Sealed-B binaries of 50/100/500 functions at 5%: FDR 8.1/11.7/7.1% (every 99% CI contains 0.1), power 15.8/13.9/9.5% | `v2_scale.json` |
| Robustness (B4) | Dead code, substitution, constant blinding: ROC-AUC −0.024 at worst; FDR ≤ α in all 16 conditions | `v2_robustness.json` |
| End to end (A7) | Stripped static programs outside training libraries: shipped layers find 14/16 crypto binaries, 0/14 false alarms; Findcrypt3 4 false alarms; boundary recall 0.50 | `e2e.json` |
| Benchmark (B6) | 27 libraries (30 with sealed-C), 4 toolchains, O0/O2/O3/Os: 16,711 objects, 128,288 labelled functions | `indicrypt_bench/extract_v2_all_report.json` |

**Decisions.**

- **v1 stays.** It is the only detector that ships. No v2 model cleared the pre-registered bar.
- **The NTT table rung ships** as the binary collector's `pqc_table` layer: 8/8 recall and 0 false hits on 3,036
  objects.
- **Fusion does not ship yet.** It is valid, but it didn't transfer to sealed-B.
- **Next power lever: calibration size per ISA** (Proposition 3), then loop-level scoring (v3).

## Corrections to the research dossier

- The PS title is *Enterprise Cryptographic Discovery & **Analysis** Tool* (portal, 28 Sep 2026).
- NTRO does name data sources: "Standard Open source datasets for source code repositories (eg: Github),
  libraries (eg: Openssl) may be used." IndiCrypt-Bench builds on that; it does not fill a void.
- Mnemocrypt's 11.4% is the false share **among flagged functions** (an FDP), not a false-positive rate.
- "First cross-architecture crypto-identification benchmark" is not claimable. Li et al. (*Frontiers of
  Computer Science* 20(10), 2025/26) evaluate tools on 7 libraries × 6 ISAs × 4 opt levels. What is new
  here is a benchmark with a held-out *calibration* split and function-level labels, for certified-FDR
  CBOM findings.
- Kestrel (arXiv 2608.25122, Aug 2026) detects ML-KEM/ML-DSA in stripped binaries from NTT constant
  tables with 128/128 recall. It names runtime-generated tables as the evasion it cannot handle, and
  that is the case a signature-free detector covers. The two are complementary.

## Reproduce

```
pip install ziglang capstone yara-python lief scikit-learn pandas tree-sitter-language-pack
cd research/indicrypt_bench
python fetch_sources.py        # clones every library at the commit in manifest.py
python build.py                # ~10 min, 6 jobs
python extract.py && python core_labels.py && python findcrypt_baseline.py
cd ../experiments && python v1_detector.py && python v1_1_detector.py
```

## v3 and the re-stamp (28 Sep 2026)

- **v3 frozen harness** (`experiments/v3_harness.py`, `results/v3_harness.json`): GIN, GraphSAGE and GAT (3 seeds,
  all optimisation levels, dev-only selection). Clean-commit run: GAT selected (dev tie with GIN), +0.0277 sealed
  PR-AUC, below the +0.03 bar: **v1 stays**. Certified power under library shift at 5% crypto at most 8.6%.
  Findcrypt3's crypto rules: 77% false share under shift (signature evidence is not exchangeable across
  libraries); the e-value average inherits it (56%), stacked fusion stays below α. Fusion: theory and simulation only.
- **Re-stamp.** Every result that carried `+dirty` was rerun at a clean commit. CPU-only studies reproduced exactly;
  GPU-trained numbers moved within noise (GPU kernels are not bit-deterministic) and every decision held. The dirty
  check now covers code, rules and the shipped model only (`v1_detector._commit`).
- **Containers** (`e2e/container_e2e.py`): nginx:1.27-alpine and alpine:3.20 from Docker Hub, scanned through the
  product API: valid CycloneDX 1.7, library versions resolved, AES modes and OIDs recorded, CERT-In Table 9 96.2%
  on nginx (baseline before the fixes: `results/container_before_fix.json`).
