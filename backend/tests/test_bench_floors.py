"""Detection floors on the labelled corpus (bench/corpus, scored by bench/score.py).

Each floor is the measured value minus 0.02, so a change that costs precision
or recall on either split fails here instead of surfacing as a quieter number
in bench/results.json. Raise a floor when a measured value rises; never lower
one to make a change pass.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

BENCH = Path(__file__).resolve().parents[2] / "bench"

# Measured 2026-09-24 (bench/results.json): tune P 0.982 R 0.949; held-out P 0.964 R 1.0.
FLOORS = {
    "tune": {"precision": 0.962, "recall": 0.929},
    "holdout": {"precision": 0.944, "recall": 0.980},
}


@pytest.fixture(scope="module")
def scored():
    spec = importlib.util.spec_from_file_location("bench_score", BENCH / "score.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.score()


@pytest.mark.parametrize("split", ["tune", "holdout"])
def test_detection_does_not_fall_below_its_floor(scored, split):
    overall = scored["splits"][split]["overall"]
    assert overall["precision"] >= FLOORS[split]["precision"], overall
    assert overall["recall"] >= FLOORS[split]["recall"], overall


def test_every_decoy_stays_clean(scored):
    """Crypto words in comments and strings are not cryptography."""
    noisy = [c["id"] for c in scored["cases"] if c["decoy"] and c["false_positives"]]
    assert noisy == []


def test_no_collector_fails_on_the_corpus(scored):
    assert [c["id"] for c in scored["cases"] if c["collector_failures"]] == []
