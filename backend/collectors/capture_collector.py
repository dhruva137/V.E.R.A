"""Recorded observations (plane: observed): replay a TLS or SSH capture file.

A live probe is the strongest evidence there is, but a scan often has to run
where the endpoints are not reachable: an air-gapped review laptop, a judge's
demo, an audit of last month's state. The TLS and SSH collectors can write what
they observed to a file; this collector reads it back.

Formats:
    {"source": "tls", "collected_at": "...", "findings": [<RawCryptoFinding>, ...]}
    {"source": "ssh", "collected_at": "...", "probes": [{"target": "host:22", "banner": "...",
                                                         "kex_algorithms": [...], ...}]}

Every finding keeps the observed plane (it *was* observed) and gains
`recorded_at` and `replayed_from`, and its confidence is the recorded grade
(0.90), below a live handshake (0.98): a record says what was true then, not
what is true now.
"""

from __future__ import annotations

import json
from pathlib import Path

from collectors.base import DEFAULT_LIMITS, CollectResult, Limits, Timer, evidence, read_capped, stable_id, walk
from collectors.ssh_scanner import findings_from_probe
from models.schemas import RawCryptoFinding

RECORDED_CONFIDENCE = 0.90


def _stamp(finding: RawCryptoFinding, sensor: str, path: Path, recorded_at: str) -> RawCryptoFinding:
    details = dict(finding.raw_details or {})
    details.update({
        "discovered_by": sensor,
        "plane": "observed",
        "provenance": "runtime_observed",
        "confidence": RECORDED_CONFIDENCE,
        "recorded_at": recorded_at,
        "replayed_from": str(path),
    })
    details.setdefault("evidence_refs", [evidence(sensor, finding.source_location)])
    details["evidence_refs"] = list(details["evidence_refs"]) + [evidence("capture", str(path))]
    return finding.model_copy(update={
        "id": stable_id("capture", sensor, finding.id),
        "raw_details": details,
        "tags": sorted(set(finding.tags) | {"recorded-observation"}),
    })


def read_capture(path: Path, data: bytes) -> list[RawCryptoFinding]:
    doc = json.loads(data)
    source = doc.get("source")
    recorded_at = str(doc.get("collected_at", "unknown"))
    if source == "tls":
        return [_stamp(RawCryptoFinding(**item), "tls_capture", path, recorded_at)
                for item in doc.get("findings", [])]
    if source == "ssh":
        out = []
        for probe in doc.get("probes", []):
            out.extend(_stamp(f, "ssh_live_capture", path, recorded_at)
                       for f in findings_from_probe(probe["target"], probe))
        return out
    raise ValueError(f"unknown capture source {source!r}; expected 'tls' or 'ssh'")


class CaptureCollector:
    """Collector-contract implementation; see `collectors.base.Collector`."""

    name = "capture"
    plane = "observed"
    label = "Recorded observations"
    description = "Replays TLS / SSH observations recorded earlier, labelled with when they were recorded."
    target_kinds = ("capture", "path")

    def collect(self, targets: list[str], *, limits: Limits = DEFAULT_LIMITS) -> CollectResult:
        result = CollectResult(stats={"captures": 0})
        timer = Timer(limits)
        for target in targets:
            for path in walk(Path(target), limits, result):
                if path.suffix.lower() != ".json":
                    continue
                data = read_capped(path, limits.max_text_bytes * 8, result)
                if data is None:
                    continue
                try:
                    result.findings.extend(read_capture(path, data))
                    result.stats["captures"] += 1
                except (ValueError, KeyError, TypeError) as exc:
                    result.fail(path, f"not a capture: {type(exc).__name__}: {exc}")
        result.stats["duration_ms"] = timer.elapsed_ms
        return result
