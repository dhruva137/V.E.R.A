# Certified, signature-free cryptographic function detection across instruction sets

*Draft short paper, 28 Sep 2026. Code, benchmark builder and every result file are in `research/`. Each number in
this draft names the file that produced it; commits are recorded inside those files.*

## Abstract

Cryptographic inventories (CBOMs) are now a procurement requirement. India's DST task force makes vendor CBOMs
mandatory from FY 2027–28. Yet binary scanners report crypto findings as if they were certain. We study the
detection of cryptographic functions in stripped binaries, on x86-64, AArch64 and ARM32, with a *certified*
false-discovery rate (FDR).

Our contributions:

1. A detector that is signature-free, operand-aware and architecture-neutral.
2. Per-ISA (Mondrian) conformal selection, which bounds the expected share of false findings at α without
   distributional assumptions, together with a *rung-fusion* result that unifies signature evidence and learned
   evidence under one guarantee.
3. IndiCrypt-Bench: 30 open-source libraries × 4 toolchains × 4 optimisation levels (128,288 labelled
   functions, plus 1,023 in a third sealed set), with sealed test sets and a calibration split.

Results:

- **The guarantee holds** in every measured setting within Monte Carlo error.
- **A fixed confidence threshold (as used by Mnemocrypt) does not.** At 5% and 1% crypto prevalence, 60.8% and
  89.5% of its flags are false.
- **Calibrating on a different ISA breaks or triples FDR.** Per-ISA calibration restores it.
- **On stripped, statically linked programs** outside the training libraries, signatures plus the certified
  learned layer detect 14/16 crypto binaries with 0/14 false alarms, re-measured on the shipped model through
  the product's own scan path.
- **A self-audit** (leakage, library-disjoint validity, a fair baseline, shipped = evaluated) moved no headline
  number and surfaced one measured exchangeability violation, reported below.
- **Negative results:** graph and sequence models did not beat gradient-boosted trees on sealed libraries, and
  stacked fusion did not transfer to a library population whose signature behaviour differs.

## 1. Problem

A CBOM line that says "this firmware uses cryptography" is used in audits and procurement. A false line costs
credibility, and a missing one hides quantum-vulnerable code.

Signature tools each have a stated blind spot:

- Findcrypt-style constant tables, and Kestrel (arXiv 2608.25122) for ML-KEM/ML-DSA twiddle tables, miss code
  whose tables are computed at run time.
- Library-version fingerprints (QED-Lite, IACR 2026/660) see only known libraries with version metadata.

The learned alternative, Mnemocrypt (NDSS BAR 2025), is a random forest on 43 mnemonic statistics. Its
limitations: 32-bit x86 only, operands ignored, and a fixed confidence threshold. LLM approaches (FoC, TOSEM
2025; CREBench, arXiv 2604.03750) name functions but offer no error guarantee.

We ask two questions. Can a detector over stripped code in three ISAs *certify* its findings? And can the evidence
from signature tools join the same guarantee?

## 2. IndiCrypt-Bench

**Libraries.** The PS permits open datasets, and IndiCrypt-Bench v1 is built from open-source libraries at pinned
commits (`research/indicrypt_bench/manifest.py`):

| Split | Crypto libraries | Non-crypto (hard negatives) |
|---|---|---|
| train | mbedtls, libtomcrypt, B-Con, tiny-AES | Lua, zstd, cJSON, zlib |
| dev | PQClean (ML-KEM, ML-DSA, HQC, Falcon, SPHINCS+), Monocypher, micro-ecc | stb, lz4, xxHash, kissfft (fixed point) |
| sealed | BearSSL, TweetNaCl, SipHash | brotli, libdeflate, yyjson, lodepng |
| sealed-B | libsodium, wolfSSL (incl. ML-KEM, ML-DSA, LMS, XMSS) | SQLite, libpng |
| sealed-C | BLAKE3, Argon2, tiny_sha3 | — |

The sealed and sealed-B splits were each registered before any model that could be tuned on them existed.
Sealed-C was added in the self-audit, registered before it was scored, and scored once.

**Builds.** Every source file is compiled to its own object with:

- clang for x86-64, AArch64 and ARM32
- gcc for x86-64

each at O0, O2, O3 and Os. That is 16,711 objects. Failures are kept in the index; most are wolfSSL's
architecture-specific files.

**Labels** are function-level and come from *source*, never from the binary (`core_labels.py`, frozen). A function
is cryptographic when:

- its file implements a primitive, and
- its preprocessed body, including inlined static callees, performs at least 3 arithmetic or bitwise operations.

Orchestration wrappers are excluded, which matches Mnemocrypt's function-level labelling. Non-crypto functions
inside crypto libraries (X.509, base64, DER, CRC) are negatives. SQLite's `chacha_block` is excluded by name,
because it really is ChaCha20.

The result: 128,288 labelled functions after dropping, and counting, tiny functions, lifecycle functions,
duplicates and wrappers (`v2_all/extract_report.json`).

What is new is not the number of ISAs; Li et al. (Frontiers of CS, 2025/26) cover six. What is new is the
**held-out calibration split and function-level labels** a certified detector needs.

## 3. Method

**Detector (v1).** Capstone disassembly is mapped to 24 architecture-neutral operation classes. Each function gets
74 features:

- mnemonic statistics, as in Mnemocrypt;
- operand statistics: immediates and their bit entropy, known crypto and non-crypto constants, shift and rotate
  amounts, rotates folded into ARM barrel-shifter operands, indexed table loads, byte extraction, and
  straight-line ALU runs.

Gradient-boosted trees score each function.

**Certification.** For each ISA *g*, non-crypto calibration functions give conformal p-values. Benjamini–Hochberg
runs inside each binary. Proposition 1 (`THEORY.md`): under within-ISA exchangeability, FDR ≤ α·m₀/m. The proof
uses PRDS of conformal p-values (Bates et al., Ann. Statist. 2023), preserved across independent ISA blocks, and
Benjamini–Yekutieli (2001).

**Rung fusion.** Theorem 2a: any combiner of rung scores fitted on data disjoint from calibration and test gives a
valid single rung. Theorem 2b: averaging calibrated conformal e-values and running e-BH (Wang & Ramdas 2022) is
valid under arbitrary dependence, but power-limited.

**Calibration budget.** Proposition 3: BH cannot reject anything among *m* functions unless the ISA has at least
*m/α − 1* calibration functions.

**Signature rungs.**

- *NTT rung.* ML-KEM/ML-DSA twiddle tables are derived from the FIPS 203/204 parameters in plain, centred and
  Montgomery forms, and matched with windowed multiset matching. It detected 8/8 PQClean NTT objects across the
  4 toolchains, with 0 hits on 3,036 non-PQC objects.
- *Findcrypt3.*
- *V.E.R.A.'s existing library, symbol, banner and constant layers.*

**Architectures tried (Phase A3/A4).**

- a GIN over the basic-block CFG with 41 operand-aware node features
- the same over block-level def-use edges (DFG) and over both
- hybrids that add the 74 function features
- a transformer over instruction-class tokens

Selection was on dev only, and the choice was written to disk before any sealed score existed
(`v2_selection.json`).

## 4. Results

**Detection.** v1 was trained on O0/O2 train libraries only.

| Test set | ROC-AUC | PR-AUC | Source |
|---|---|---|---|
| sealed (x86-64 / AArch64 / ARM32) | 0.834 / 0.805 / 0.831 | — | `v1_1_detector.json` |
| sealed, O3 (never trained on) | 0.856 | 0.789 | `v2_scale.json` |
| sealed, Os (never trained on) | 0.845 | 0.775 | `v2_scale.json` |
| sealed-B | 0.797 | 0.580 (17.7% crypto) | `v2_scale.json` |

Operand features raised dev ROC-AUC from 0.760 to 0.793 (ARM32: 0.757 → 0.782). Adding O3/Os builds to training
helps only a little (sealed O3: 0.856 → 0.867).

**Architectures** (`v2_models.json`, 3 seeds, RTX 5050; rerun at a clean commit):

| Model | Dev PR-AUC | Sealed PR-AUC | CPU functions/s |
|---|---|---|---|
| v1 trees | 0.771 | 0.737 | 61,840 |
| GNN over CFG | 0.821 | 0.750 | 13,538 |
| GNN over DFG | 0.804 | 0.744 | 15,856 |
| GNN over CFG, hybrid (selected on dev) | 0.825 | 0.725 | 16,890 |
| Transformer | 0.729 | 0.704 | 34 |

- The selected model changes sealed PR-AUC by **−0.012** (+0.004 in the first run; GPU training is not
  bit-deterministic), so the pre-registered ship rule (≥ +0.03) fails and v1 stays.
- Control flow carries more signal than data flow, and sequences carry less than either.
- The graph models' dev gains come from epoch selection on dev and do not survive the move to unseen libraries.

**The guarantee.** Figure 2 (sealed, pooled test). A fixed 0.9 threshold gives FDP 14.5%, 60.8% and 89.5% at 34%,
5% and 1% prevalence. Conformal BH at α = 0.1 gives 6.7%, 8.0% and 3.7%.

The simulation grid (`theory_sim.json`: 21 settings × 2,000 reps) shows 0 violations of Propositions 1 and 2. It
also shows that deliberately wrong-ISA calibration fails, with FDR from 0.19 to 0.96.

**Per-ISA calibration** (Figure 1; `v2_cross_isa.json`, 5 seeds × 500 splits):

- The GNN trained on all ISAs and calibrated on x86-64 gives FDR 6.0% on AArch64 and 7.8% on ARM32. Calibrated
  per ISA it gives 1.2% and 1.9% (clean-commit rerun; the first run gave 7.6% / 7.9% and 1.6% / 2.4%).
- The v1 trees trained on x86-64 only and calibrated on x86-64 exceed the bound on ARM32: 35.6% at α = 0.2
  (`v1_1_detector.json`). Per-ISA calibration gives 3.9%.

How badly foreign calibration inflates FDR depends on the model, so only per-ISA calibration is safe by
construction.

**Deployment protocol** (Figure 4; `v2_scale.json`). A binary is *m* functions of one ISA from sealed-B, and BH
runs inside it:

| m | Prevalence | FDR (99% CI) | Power |
|---|---|---|---|
| 50 | 5% | 8.1% (4.4–11.8) | 15.8% |
| 100 | 5% | 11.7% (7.7–15.7) | 13.9% |
| 500 | 5% | 7.1% (4.9–9.4) | 9.5% |

Every interval contains α. Power falls with binary size and rarity, as Proposition 3 predicts. On the sealed pool,
whose calibration is smaller, power is lower (`v2_fusion_sealed_hgb_v1.json`). **The number of calibration
functions per ISA is the main lever on power.**

**Fusion.**

- *Simulation, rungs complementary* (`theory_sim.json`): stacked fusion lifts power from 12.0% (learned rung) and
  9.9% (signature rung) to **39.9%** at the same certified FDR.
- *Sealed:* it lifts power modestly, from 12.1% to 14.8% at natural prevalence.
- *Sealed-B:* it **lowers** power, from 19.5% to 14.4%, while the loop-aggregate trees alone reach 21.1%, the
  best single rung there. Findcrypt3 fires on 2.8% of crypto and 2.4% of non-crypto
  functions there (CRC tables in SQLite and libpng), yet the dev-fitted combiner weights it at 2.0.

Fusion is valid in every case. It is not always better. A signature rung whose meaning changes between library
populations needs its combiner refitted on that population.

**Robustness** (`v2_robustness.json`). Dead-code insertion, instruction substitution and constant blinding were
simulated at instruction level.

- ROC-AUC moves by at most −0.025 (substitution against v1, perturbing crypto functions only).
- FDR stays ≤ α in all 16 attack × model × threat combinations. That includes perturbing every function, which
  deliberately breaks exchangeability.

**End to end** (Figure 3b; `e2e.json`). These are statically linked, stripped programs whose libraries are
outside the training split, on x86-64 and AArch64. Function boundaries are recovered from call targets, with
precision 0.81 and recall 0.50 against the unstripped twin.

| Method | Crypto binaries detected | Non-crypto binaries flagged |
|---|---|---|
| Findcrypt3 | 37.5% | 28.6% |
| Signature layers (incl. NTT) | 75.0% | 0% |
| Certified learned layer, α = 0.1 | 62.5% | 0% |
| Both, as shipped | **87.5% (14/16)** | **0% (0/14)** |

SipHash is found only by the learned layer, on both ISAs. The two misses are a made-up ARX cipher that the
compiler inlined into `main`. Scoring its loops separately raised the region's score from 0.16 to 0.83 in a pilot, but
the shipped layer scores whole functions, so it stays a miss.

The same 30 programs were re-scanned through the product's own path (`e2e_product.json`: `scan_blob` with the
shipped model and calibration, not a refit). The result is identical: 14/16 detected, 0/14 flagged, SipHash found
only by the learned layer.

**Self-audit** (`SELF_AUDIT.md`, `self_audit.json`):

- *Leakage.* Byte-identical functions crossing splits are 0.17% of sealed rows; removing them moves sealed PR-AUC
  from 0.7575 to 0.7577.
- *Library-disjoint validity.* The shipped calibration against binaries from sealed-B and sealed-C libraries: FDR
  ≤ 1.5% in all 6 cells (α = 0.1), power 1.2–8.7%. But non-crypto helpers *inside* Argon2 and libsodium exceed the
  calibration 95th percentile 17.5–22.2% of the time, where 5% is expected: a measured violation of Assumption E.
  The bound held because most nulls (SQLite, libpng) score below calibration.
- *More libraries.* With sealed-C, 8 sealed crypto libraries; pooled ROC-AUC 0.820 over 59,868 functions.
- *Fair baseline.* All of Findcrypt3's false alarms came from its CRC32 rule; with crypto rules only its FPR is 0%.

**Retry on a frozen harness (v3)** (`v3_harness.json`). GIN, GraphSAGE and GAT over the CFG (3 seeds each, all
optimisation levels, selection on dev written before any sealed score). The selected model gains +0.0277
sealed PR-AUC: below the +0.03 bar, so v1 stays. Certified power under library shift at 5% crypto reached at most
8.6% for any candidate. Findcrypt3's crypto rules have a 77% false share under shift,
because signature evidence is not exchangeable across libraries; the e-value average inherits it, while stacked
fusion stays below α. Fusion therefore remains validated in theory and simulation, not shipped.

**Real container images** (`container_e2e.json`). nginx:1.27-alpine and alpine:3.20, pulled from Docker Hub with
digest verification and scanned through the product API, give valid CycloneDX 1.7 CBOMs (0 violations) with
resolved library versions (OpenSSL 3.3.3 / 3.3.7) and block-cipher modes (20/20 AES components; 0/6 before). CERT-In
Table 9 conformance on the nginx CBOM: 96.2% (85.4% before recording modes and their OIDs).

## 5. Limitations

- **Exchangeability is the assumption.** It fails across ISAs (measured), for non-crypto helpers inside crypto
  libraries (measured: Argon2, libsodium), and plausibly under unseen compilers or obfuscators. Our robustness study is simulated, not a working binary rewriter.
- **Power is modest.** It is 9–16% of crypto functions in 50–500-function binaries at 5% prevalence. The guarantee
  prefers silence to error. A larger calibration set per ISA is the cheapest improvement.
- **FDR is an average over repeated use**, not a promise per finding (Gao, Roquain & Xiang, arXiv 2601.02610). We
  report each finding's q-value so boundary cases are visible.
- **Coverage.** Function boundaries in stripped code are recovered with 50% recall. Labels come from a fixed source
  rule, not manual review. The end-to-end set is small (30 independent binaries), so its 0% false-alarm rate is an
  observation, not a bound.
- **Comparability.** Mnemocrypt's 11.4% was measured by hand on malware and is not directly comparable to our
  numbers.

## 6. Related work

- **Classical and signature detection:** Gröbert et al. (RAID 2011); Where's Crypto? (USENIX Security 2021);
  Findcrypt3; Kestrel (arXiv 2608.25122); QED-Lite (IACR ePrint 2026/660).
- **Learned detection:** Mnemocrypt (NDSS BAR 2025); FoC (TOSEM 2025); CREBench (arXiv 2604.03750).
- **Benchmarks:** Li et al. (Frontiers of CS, 2025/26).
- **Conformal selection:** Bates et al. (2023); Jin & Candès (JMLR 2023); Bashari et al. (NeurIPS 2023);
  Wang & Ramdas (JRSS-B 2022); Zhu & Simeone (arXiv 2604.11305); Gao, Roquain & Xiang (arXiv 2601.02610).
  Conformal prediction has been applied to offensive security (Cherubin, arXiv 2609.05165), not, as far as we
  found, to cryptographic inventories.

## Reproduce

See `research/README.md`.

All v2 GPU work fits on one RTX 5050 (8 GB): the architecture comparison takes 32–38 minutes, the cross-ISA matrix
14 minutes. The shipped detector is CPU-only: a 688 KB model that scores 83k functions/s.
