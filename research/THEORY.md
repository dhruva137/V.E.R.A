# Theory: certified crypto findings, per-ISA calibration and rung fusion

This note states the guarantees V.E.R.A.'s binary detector relies on, and proves each one from published
results. Every statement is also checked numerically:

- fast: `backend/tests/test_binary_ml_theory.py` (runs in the normal suite)
- large: `research/experiments/theory_sim.py` → `research/results/theory_sim.json`

Nothing here is new mathematics. What is new is assembling these results into a detector that fuses
signature evidence and learned evidence under one false-discovery guarantee, and measuring where the
assumption fails.

## Setting

A binary under test has functions *j = 1..m*. Hypothesis *H_j*: "function *j* is not cryptographic". *H_0* is
the set of true nulls, and *m_0 = |H_0|*. A *rung* is any procedure that gives a function a score; higher means
more cryptographic. Examples:

- the learned model
- an indicator "an NTT constant table is referenced here"
- an indicator "this code belongs to a library whose version banner we recognise"

Each rung *k* has calibration functions *C_g* that are known to be non-cryptographic, for each instruction set
*g* (x86-64, AArch64, ARM32).

**Assumption E (within-ISA exchangeability).** For each ISA *g*, the calibration scores in *C_g* and the scores
of the null test functions of ISA *g* are exchangeable. Non-null test scores may be arbitrary but are fixed,
i.e. we condition on them. Calibration sets of different ISAs are independent.

Assumption E is the only assumption. It is about how the calibration code relates to the code under test, and
Section 5 measures when it fails.

Conformal p-value of test function *j* (ISA *g*, rung *k*):

    p_j^k = (1 + #{i in C_g : S_i^k >= S_j^k}) / (|C_g| + 1)

## 0. Why a fixed confidence threshold is not a guarantee

For a fixed threshold *t*, with crypto prevalence *π*, false-positive rate FPR(t) and true-positive rate TPR(t),
the expected false share among flagged functions is, to first order,

    FDP(t) ≈ (1 - π)·FPR(t) / ((1 - π)·FPR(t) + π·TPR(t))

This tends to 1 as *π* → 0, for any fixed *t* with FPR(t) > 0. A detector that is excellent on a balanced
test set therefore produces mostly false flags on real binaries, where cryptography is rare.

Measured (sealed set, threshold 0.9):

| Prevalence | FDP |
|---|---|
| 34% | 14.5% |
| 5% | 60.8% |
| 1% | 89.5% |

`research/results/v1_1_detector.json`. This motivates selecting with an error guarantee instead of a
confidence cut-off.

## 1. Per-ISA (Mondrian) conformal BH

**Proposition 1.** Under Assumption E, Benjamini–Hochberg at level *α*, applied jointly to the per-ISA conformal
p-values of all *m* test functions (any mix of ISAs), satisfies FDR ≤ *α·m_0/m* ≤ *α*.

*Proof.*

1. Within one ISA, conformal p-values that share a calibration set are PRDS on the nulls when test nulls are
   exchangeable with the calibration set and non-null scores are held fixed (Bates, Candès, Lei, Romano,
   Sesia, Ann. Statist. 2023, Thm 2.4).
2. Blocks for different ISAs use disjoint, independent calibration sets, so the full vector is a concatenation
   of independent PRDS blocks. PRDS survives this. For an increasing set *D* and a null *j* in block *g*,
   P(D | p_j = t) = E_q[P((p_g, q) ∈ D | p_j = t)]. Here *q* stands for the other blocks and is independent
   of block *g*. Each section {p_g : (p_g, q) ∈ D} is increasing, so every inner term is non-decreasing in
   *t*, and so is their average.
3. BH on PRDS p-values controls FDR at *α·m_0/m* (Benjamini & Yekutieli, Ann. Statist. 2001, Thm 1.2). ∎

*What it does not cover.* Calibrating one ISA with another's calibration set violates Assumption E. The p-values
then need not be super-uniform, and the bound can fail. Measured: an x86-64-calibrated detector on ARM32 gave
FDP 35.6% at *α* = 0.2. Per-ISA calibration gave 3.9%.

## 2. Certified rung fusion

Two constructions are valid. The measured power decides which one V.E.R.A. uses.

**Theorem 2a (stacked fusion; the one V.E.R.A. uses).** Let *g* : ℝ^K → ℝ be any function of the rung scores, fitted
on data disjoint from the calibration and test sets. In V.E.R.A. that data is the dev libraries. Treat
*S_j = g(S_j^1, …, S_j^K)* as a single rung, with per-ISA conformal p-values from the calibration functions'
fused scores. Then BH at level *α* has FDR ≤ *α·m_0/m* under Assumption E.

*Proof.* *g* is fixed before the calibration and test data are used. Hence the fused calibration and null test
scores are measurable functions, applied identically, of exchangeable objects, and remain exchangeable.
Proposition 1 applies unchanged. ∎

Validity costs nothing here: any combiner is allowed, including one that ignores a useless rung. Power is best
when *g* orders functions like the likelihood ratio of crypto against non-crypto. That is the Neyman–Pearson
view of conformal selection (arXiv 2502.16513). A logistic combiner fitted on dev is a direct estimate of it.

Measured by simulation (`theory_sim.json`; *α* = 0.1, 5% prevalence, 500 functions, 4,000 calibration functions;
signature false-hit rate 0.2%):

| Signature fires on | Learned rung, BH | Signature rung, BH | **Stacked, BH** | Avg. e-values, e-BH | Calibrator e-fusion |
|---|---|---|---|---|---|
| 0% of crypto | 11.1% | 0% | **11.1%** | 0.5% | 0.4% |
| 30% of crypto | 12.0% | 9.9% | **39.9%** | 1.3% | 0.4% |
| 80% of crypto | 11.5% | 78.9% | **84.3%** | 23.2% | 0.9% |

Every procedure's FDR has a 99% upper bound ≤ 0.1 in every cell. Stacked fusion beats every single rung when
the rungs are complementary, and loses nothing when one rung is useless.

**Theorem 2b (e-value fusion; robust to any dependence, but weaker).** The construction below needs no fitted
combiner and no dev data, which is its only advantage. The table above shows its cost: e-values are capped by
the calibration size (Proposition 3), and averaging divides the cap.

A *p-to-e calibrator* is a non-increasing *f* : [0,1] → [0,∞] with ∫₀¹ f(u) du ≤ 1. Two examples:

- the *hard* calibrator f_t(u) = 1{u ≤ t}/t
- a *mixture* of hard calibrators, f(u) = Σ_l π_l · f_{t_l}(u), with π_l ≥ 0 and Σ π_l = 1

Let rungs *k = 1..K* give per-ISA conformal p-values *p_j^k* under Assumption E. The rungs
may be arbitrarily dependent: they may score the same calibration functions, reuse features, or be the same
model at different thresholds. Fix, before seeing the calibration or test data, calibrators *f_k* and weights
*w_k* ≥ 0 with Σ w_k = 1. Define

    e_j = Σ_k w_k · f_k(p_j^k)

Then e-BH at level *α* (reject the *k̂* largest e-values, *k̂* = max{k : e_(k) ≥ m/(α·k)}) satisfies
FDR ≤ *α·m_0/m*, with no condition on the dependence between rungs or between functions.

*Proof.*

1. A conformal p-value is super-uniform for a null under exchangeability: P(p_j^k ≤ u) ≤ u for all *u*
   (Vovk, Gammerman, Shafer 2005). Ties make it more conservative, never less, which matters for 0/1
   signature rungs.
2. For super-uniform *p* and non-increasing *f* with ∫f ≤ 1: E f(p) = ∫₀^∞ P(f(p) > s) ds. The set
   {f(p) > s} = {p < f⁻(s)} for the generalised inverse, so P(f(p) > s) ≤ P(U < f⁻(s)) = P(f(U) > s) for
   uniform *U*. Hence E f(p) ≤ E f(U) = ∫₀¹ f ≤ 1. So each f_k(p_j^k) is an e-value for *H_j*.
3. A convex combination of e-values for the same hypothesis is an e-value, whatever their dependence,
   because expectation is linear.
4. e-BH controls FDR at *α·m_0/m* under arbitrary dependence of the e-values (Wang & Ramdas, JRSS-B 2022,
   Thm 5.1). ∎

**On power (Theorem 2b).** A signature rung that fires on no calibration function gives its hits the
smallest possible p-value, 1/(n+1). With the hard calibrator at *t* = 1/(n+1) that becomes the e-value *n+1*.
The learned rung gives large e-values where signatures are silent. With equal weights, a function certified by
either rung alone keeps half its e-value, so fusion helps when rungs are *complementary*: they fire on
different functions. When one rung dominates everywhere, fusion costs at most a factor 1/*w_k* in e-value.
In simulation the cap dominates. Theorem 2b is therefore kept as the robust fallback, not the default.

**Calibrators are chosen on dev.** The calibrators and weights must not depend on the calibration or test data
they certify. We fix them on the dev libraries and apply them unchanged to the sealed sets. That keeps
Theorem 2's premise intact.

## 3. The calibration budget

**Proposition 3.** With *n_g* calibration functions for ISA *g*, the smallest conformal p-value is 1/(n_g+1).
Two consequences:

- For BH to reject anything among *m* functions of that ISA, it is necessary that
  1/(n_g+1) ≤ *α/m*, that is **n_g ≥ m/α − 1**.
- For the fused e-BH with hard calibrators, the largest possible e-value is max_k w_k·(n_g+1)/c_k, where
  *c_k* is the calibrator's threshold multiplier. It must reach *m/α*.

*Proof.* Immediate from the definitions. BH rejects only p ≤ α·k/m, which is at most α. e-BH rejects only
e ≥ m/α. ∎

So "how few labelled negatives per ISA suffice" has an exact floor. Certifying anything in a 1,000-function
binary at *α* = 0.1 needs at least 9,999 null calibration functions for that ISA. We have 5,194 for x86-64,
2,552 for AArch64 and 2,538 for ARM32. The floor, not the model, limits power on large binaries. This is a
concrete, cheap lever: build more non-crypto code per ISA.

## 4. What the guarantee is not

- **FDR is an average over repeated use**, not a promise about one finding. Gao, Roquain & Xiang
  (arXiv 2601.02610, 2026) show BH-based novelty detection can be unreliable exactly at the decision
  boundary. We report each finding's q-value, so a finding selected only at the boundary is visible as such.
- **Exchangeability is a property of code, not of the method.** Assumption E fails when the code under test
  comes from a population the calibration set does not represent: a new ISA, obfuscation, a new compiler.
  Section 1 measures one failure. Phase B2 and B4 measure more.
- **It certifies "cryptographic", not "which algorithm".** Naming the primitive is a separate, uncertified
  step.

## 5. Numerical checks

`theory_sim.py` estimates FDR by Monte Carlo over repeated draws. Each check below passes when the upper
end of the 99% interval is ≤ α:

1. Proposition 1 with three strata whose null distributions differ, calibrated per stratum. The same
   setting with cross-stratum calibration must be allowed to fail, and does.
2. Theorems 2a and 2b with three rungs:
   - a noisy learned score
   - a 0/1 signature that fires on 30% of alternatives and on 0.5% of nulls
   - a second learned score correlated 0.9 with the first
   These are fused with mixture calibrators, under strong dependence between rungs.
3. Proposition 3: no rejection when n < m/α − 1.
4. Prevalence sweep 0.5%–34%: conformal BH stays ≤ α while a fixed threshold drifts upward.
