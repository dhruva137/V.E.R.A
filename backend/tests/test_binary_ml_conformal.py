"""The conformal layer must control FDR on exchangeable data, whatever the score quality."""
import numpy as np
import pytest

from engine.binary_ml.conformal import bh, bh_qvalues, conformal_evalues, conformal_pvalues, ebh


def _trial(rng, n_cal=400, n_null=900, n_alt=100, shift=2.0):
    cal = rng.normal(size=n_cal)
    test = np.concatenate([rng.normal(size=n_null), rng.normal(loc=shift, size=n_alt)])
    truth = np.r_[np.zeros(n_null, bool), np.ones(n_alt, bool)]
    return cal, test, truth


@pytest.mark.parametrize("alpha", [0.05, 0.1, 0.2])
def test_bh_and_ebh_control_fdr(alpha):
    rng = np.random.default_rng(0)
    fdp_bh, fdp_ebh = [], []
    for _ in range(300):
        cal, test, truth = _trial(rng)
        p = conformal_pvalues(test, cal)
        for sel, acc in ((bh(p, alpha), fdp_bh), (ebh(conformal_evalues(test, cal, alpha), alpha), fdp_ebh)):
            acc.append((sel & ~truth).sum() / max(1, sel.sum()))
    # Mean FDP estimates FDR; allow Monte-Carlo slack of three standard errors.
    for fdps in (fdp_bh, fdp_ebh):
        se = np.std(fdps) / np.sqrt(len(fdps))
        assert np.mean(fdps) <= alpha + 3 * se


def test_useless_score_selects_almost_nothing():
    rng = np.random.default_rng(1)
    cal, test, _ = _trial(rng, shift=0.0)     # alternatives look exactly like nulls
    assert bh(conformal_pvalues(test, cal), 0.1).sum() <= 5


def test_qvalue_is_smallest_alpha_selecting_it():
    rng = np.random.default_rng(2)
    cal, test, _ = _trial(rng)
    p = conformal_pvalues(test, cal)
    q = bh_qvalues(p)
    for alpha in (0.05, 0.1, 0.3):
        assert np.array_equal(q <= alpha, bh(p, alpha))


def test_pvalue_bounds():
    p = conformal_pvalues(np.array([-10.0, 1000.0]), np.arange(99.0))
    assert p[0] == 1.0 and p[1] == pytest.approx(1 / 100)
