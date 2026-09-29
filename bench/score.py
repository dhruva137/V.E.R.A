"""Score the collectors against the labelled corpus: precision, recall and F1.

    python bench/make_corpus.py && python bench/score.py   ->  bench/results.json

Each case in bench/corpus/<surface>/truth.yaml is run through the collector that
owns that surface, exactly as a scan would run it. Findings are matched to the
case's expectations one to one:

* **Names** match at algorithm-family level. Both sides are normalised (case,
  punctuation, TLS version spelling, 3DES aliases, JOSE names such as RS256 to
  their family), and one must contain the
  other: "AES" matches "AES-256-GCM", "RSA" matches "SHA1withRSA".
* **Source** findings must also be in the expected file, within 2 lines.
* **Dependencies** match on the library or package name.

An unmatched finding is a false positive; an unmatched expectation is a false
negative. Numbers are reported per surface, per source language, and for the
tune and held-out splits separately. Every miss and every false positive is
listed in the output, so the numbers can be checked case by case.
"""

from __future__ import annotations

import datetime as dt
import json
import re
import subprocess
import sys
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
CORPUS = HERE / "corpus"
sys.path.insert(0, str(ROOT / "backend"))

from collectors.registry import REGISTRY  # noqa: E402

COLLECTOR_FOR = {"source": "source", "dependency": "dependency", "config": "config", "ssh": "capture",
                 "binary": "binary", "container": "container"}
ALIASES = {"TRIPLEDES": "3DES", "DESEDE": "3DES", "DES3": "3DES", "DESEDE3": "3DES", "TDEA": "3DES"}
# JOSE algorithm names are their family at the level this benchmark matches.
ALIASES |= {f"{p}{n}": fam for p, fam in (("RS", "RSA"), ("PS", "RSA"), ("ES", "ECDSA"), ("HS", "HMAC"))
            for n in (256, 384, 512)}
LINE_TOLERANCE = 2

# The first measurement, before any correction, kept so the corrections below
# can be judged: tune tp 52 / fp 4 / fn 7, held-out tp 24 / fp 3 / fn 3.
FIRST_RUN = {
    "tune": {"tp": 52, "fp": 4, "fn": 7, "precision": 0.929, "recall": 0.881, "f1": 0.904},
    "holdout": {"tp": 24, "fp": 3, "fn": 3, "precision": 0.889, "recall": 0.889, "f1": 0.889},
}
CORRECTIONS = [
    {"kind": "rule", "split_seen": "tune", "what": "Python: Cipher(algorithms.AES(...)) detected (py-crypto-cipher-aes)."},
    {"kind": "rule", "split_seen": "tune", "what": "Go: a crypto/des import is not reported when the file calls 3DES."},
    {"kind": "knowledge base", "split_seen": "tune", "what": "Ruby openssl gem added (PQC status: not established)."},
    {"kind": "label", "split_seen": "tune", "what": "go.mod `go 1.22` is a Go standard-library runtime; now expected."},
    {"kind": "label", "split_seen": "tune", "what": "AESGCM.generate_key + AESGCM(key) is one AES use, not two."},
    {"kind": "label", "split_seen": "tune", "what": "IKE `sha1` is HMAC integrity (HMAC-SHA-1), labelled HMAC, not SHA-1."},
    {"kind": "scorer", "split_seen": "holdout", "what": "JOSE names (RS256, ES256, HS256) normalised to their family; "
                                                        "the tool already reported RSA / HMAC for them."},
    {"kind": "fixture", "split_seen": "holdout", "what": "AES S-box fixture now embeds the full 256-byte table; the first "
                                                         "one held only a 32-byte prefix, which no real binary contains."},
]


def canon(name: str | None) -> str:
    text = re.sub(r"[^A-Z0-9]", "", str(name or "").upper())
    text = re.sub(r"^(TLS|SSL)V?(\d)$", r"\g<1>\g<2>0", text)       # TLSv1 -> TLS10
    text = re.sub(r"^(TLS|SSL)V?(\d)(\d)$", r"\g<1>\g<2>\g<3>", text)  # TLSv1.2 -> TLS12
    return ALIASES.get(text, text)


def names_of(finding) -> list[str]:
    d = finding.raw_details or {}
    return [canon(v) for v in (finding.algorithm, finding.protocol, finding.cipher_suite, finding.key_exchange,
                               d.get("library"), d.get("package")) if v]


def _same_name(expected: str, found: list[str]) -> bool:
    return any(expected and f and (expected in f or f in expected) for f in found)


def _file_and_line(finding) -> tuple[str, int | None]:
    location = str(finding.source_location).replace("\\", "/").split("!")[-1]
    match = re.match(r"^(.*?):(\d+)$", location)
    path, line = (match.group(1), int(match.group(2))) if match else (location, None)
    line = (finding.raw_details or {}).get("line") or line
    return path.rsplit("/", 1)[-1], line


def match_case(surface: str, case: dict, findings: list) -> tuple[int, list, list]:
    """(true positives, misses, false positives) for one case."""
    unmatched = list(range(len(findings)))
    misses = []
    tp = 0
    for expect in case["expect"]:
        wanted = canon(expect.get("name") or expect.get("library"))
        best, best_distance = None, None
        for i in unmatched:
            f = findings[i]
            if not _same_name(wanted, names_of(f)):
                continue
            if surface == "source":
                file, line = _file_and_line(f)
                if file != expect["file"] or line is None or abs(line - expect["line"]) > LINE_TOLERANCE:
                    continue
                distance = abs(line - expect["line"])
            else:
                distance = 0
            if best is None or distance < best_distance:
                best, best_distance = i, distance
        if best is None:
            misses.append(expect)
        else:
            unmatched.remove(best)
            tp += 1
    false_positives = [{"location": str(findings[i].source_location).replace("\\", "/").split("bench/corpus/")[-1],
                        "names": names_of(findings[i])} for i in unmatched]
    return tp, misses, false_positives


def _rates(tp: int, fp: int, fn: int) -> dict:
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    f1 = (2 * precision * recall / (precision + recall)) if precision and recall else (0.0 if tp == 0 and (fp or fn) else None)
    r = lambda v: None if v is None else round(v, 3)  # noqa: E731
    return {"tp": tp, "fp": fp, "fn": fn, "precision": r(precision), "recall": r(recall), "f1": r(f1)}


def score() -> dict:
    per_case = []
    for truth_file in sorted(CORPUS.glob("*/truth.yaml")):
        truth = yaml.safe_load(truth_file.read_text(encoding="utf-8"))
        surface = truth["surface"]
        collector = REGISTRY[COLLECTOR_FOR[surface]]
        for case in truth["cases"]:
            result = collector.collect([str(CORPUS.parent / "corpus" / case["path"])])
            tp, misses, fps = match_case(surface, case, result.findings)
            per_case.append({"id": case["id"], "surface": surface, "language": case.get("language"),
                             "split": case["split"], "decoy": not case["expect"], "tp": tp,
                             "misses": misses, "false_positives": fps, "collector_failures": result.failures})

    def aggregate(rows):
        return _rates(sum(r["tp"] for r in rows), sum(len(r["false_positives"]) for r in rows),
                      sum(len(r["misses"]) for r in rows)) | {"cases": len(rows)}

    splits = {"all": per_case, "tune": [r for r in per_case if r["split"] == "tune"],
              "holdout": [r for r in per_case if r["split"] == "holdout"]}
    out = {}
    for split, rows in splits.items():
        surfaces = sorted({r["surface"] for r in rows})
        languages = sorted({r["language"] for r in rows if r["language"]})
        out[split] = {
            "overall": aggregate(rows),
            "by_surface": {s: aggregate([r for r in rows if r["surface"] == s]) for s in surfaces},
            "by_language": {lang: aggregate([r for r in rows if r["language"] == lang]) for lang in languages},
        }
    return {"splits": out, "cases": per_case}


def _git_commit() -> str | None:
    try:
        return subprocess.run(["git", "-C", str(ROOT), "rev-parse", "HEAD"], capture_output=True, text=True,
                              check=True, timeout=10).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return None


def main() -> int:
    result = score()
    document = {
        "measured_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "git_commit": _git_commit(),
        "corpus": "bench/corpus (written by bench/make_corpus.py; licence-clean, authored for this benchmark)",
        "matching": ("One-to-one. Names at algorithm-family level after normalisation; source findings must be "
                     f"in the expected file within {LINE_TOLERANCE} lines; dependencies by library or package."),
        "first_run": FIRST_RUN,
        "corrections_after_first_run": CORRECTIONS,
        "caveats": [
            "The corpus is small (tens of cases per surface) and written by the same team that wrote the rules; "
            "the held-out 30% was chosen by hash and not used to tune rules, but it is not an independent corpus.",
            "Binary and container cases are synthetic byte patterns (banners, constants, certificates, package "
            "databases), not compiled third-party software.",
            "Symmetric ciphers on SSH (aes128-cbc, chacha20-poly1305) are not labelled or scored; key exchange and "
            "host keys are.",
        ],
        **result,
    }
    (HERE / "results.json").write_text(json.dumps(document, indent=2, default=str) + "\n", encoding="utf-8")
    for split in ("tune", "holdout"):
        o = document["splits"][split]["overall"]
        print(f"{split:8} P={o['precision']} R={o['recall']} F1={o['f1']}  (tp {o['tp']}, fp {o['fp']}, "
              f"fn {o['fn']}, {o['cases']} cases)")
        for surface, s in document["splits"][split]["by_surface"].items():
            print(f"   {surface:11} P={s['precision']} R={s['recall']} F1={s['f1']}  ({s['cases']} cases)")
    print(f"wrote {HERE / 'results.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
