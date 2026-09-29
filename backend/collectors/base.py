"""The collector contract every discovery source implements.

WHY A CONTRACT
--------------
The PS asks for one tool that scans source repositories, binaries, libraries,
container images, configurations and live endpoints. Seven scanners with seven
calling conventions make that a pile of scripts; one contract makes it a tool.
Each collector declares its name and its evidence plane (see
`engine.core.corroboration`), takes a list of targets, and returns findings,
failures and stats. Nothing a collector could not read is dropped silently: it
goes into `failures` with the reason.

SAFETY RULES (enforced here, not left to each collector)
--------------------------------------------------------
- Collectors never execute target content. They read bytes.
- `walk` never follows a symlink, so a scan cannot escape the root it was given.
- Reads are capped by `Limits`; an oversize file is a reported skip, not a crash.
- No key material is stored. Collectors record fingerprints and positions only
  (see `engine/intake/scrub.py`).
"""

from __future__ import annotations

import hashlib
import os
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator, Protocol, runtime_checkable

from models.schemas import RawCryptoFinding

PLANES = ("declared", "built", "held", "observed")

MB = 1024 * 1024


@dataclass(frozen=True)
class Limits:
    """Resource caps for one collector run."""

    max_binary_bytes: int = 256 * MB
    max_text_bytes: int = 2 * MB
    max_section_bytes: int = 16 * MB
    max_files: int = 200_000
    timeout_s: float = 300.0


DEFAULT_LIMITS = Limits()


@dataclass
class CollectResult:
    """What one collector run produced, including what it could not read."""

    findings: list[RawCryptoFinding] = field(default_factory=list)
    failures: list[dict] = field(default_factory=list)
    stats: dict = field(default_factory=dict)
    # Posture facts (not assets) that drift rules compare with observations:
    # e.g. {"kind": "tls_policy", "hosts": [...], "protocols": [...]}.
    declarations: list[dict] = field(default_factory=list)

    def fail(self, target: str | Path, reason: str) -> None:
        self.failures.append({"target": str(target), "reason": reason})

    def extend(self, other: "CollectResult") -> None:
        self.findings.extend(other.findings)
        self.failures.extend(other.failures)
        self.declarations.extend(other.declarations)
        for key, value in other.stats.items():
            if isinstance(value, (int, float)) and isinstance(self.stats.get(key, 0), (int, float)):
                self.stats[key] = self.stats.get(key, 0) + value

    def to_summary(self) -> dict:
        return {
            "findings": len(self.findings),
            "failures": self.failures[:50],
            "failure_count": len(self.failures),
            "declarations": len(self.declarations),
            "stats": self.stats,
        }


@runtime_checkable
class Collector(Protocol):
    """A discovery source. `plane` is where its evidence sits."""

    name: str
    plane: str
    label: str
    description: str
    target_kinds: tuple[str, ...]

    def collect(self, targets: list[str], *, limits: Limits = DEFAULT_LIMITS) -> CollectResult: ...


class Timer:
    """Wall-clock budget for one collector run."""

    def __init__(self, limits: Limits):
        self.start = time.monotonic()
        self.budget = limits.timeout_s

    @property
    def expired(self) -> bool:
        return (time.monotonic() - self.start) > self.budget

    @property
    def elapsed_ms(self) -> int:
        return int((time.monotonic() - self.start) * 1000)


def walk(root: Path, limits: Limits, result: CollectResult,
         skip_dirs: frozenset[str] = frozenset({".git", "node_modules", "__pycache__", ".venv", "venv"}),
         ) -> Iterator[Path]:
    """Yield regular files under `root`, never following symlinks.

    A single file is yielded as-is. Stops at `limits.max_files` and records the
    truncation as a failure so a partial walk is never mistaken for a full one.
    """
    root = Path(root)
    if root.is_symlink():
        result.fail(root, "symlink target not followed")
        return
    if root.is_file():
        yield root
        return
    if not root.is_dir():
        result.fail(root, "not found")
        return

    seen = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d not in skip_dirs)
        for name in sorted(filenames):
            path = Path(dirpath) / name
            if path.is_symlink():
                continue
            seen += 1
            if seen > limits.max_files:
                result.fail(root, f"stopped after {limits.max_files} files (limit)")
                return
            yield path


def read_capped(path: Path, cap: int, result: CollectResult) -> bytes | None:
    """Read a file if it is within `cap` bytes; otherwise record a skip."""
    try:
        size = path.stat().st_size
    except OSError as exc:
        result.fail(path, f"stat failed: {exc.strerror or exc}")
        return None
    if size > cap:
        result.fail(path, f"skipped: {size} bytes exceeds limit of {cap}")
        result.stats["skipped"] = result.stats.get("skipped", 0) + 1
        return None
    try:
        data = path.read_bytes()
    except OSError as exc:
        result.fail(path, f"read failed: {exc.strerror or exc}")
        return None
    result.stats["bytes_read"] = result.stats.get("bytes_read", 0) + len(data)
    return data


def new_id() -> str:
    return str(uuid.uuid4())


def stable_id(*parts: object) -> str:
    """Deterministic id from the finding's identity, so rescans are reproducible."""
    digest = hashlib.sha256("\x1f".join(str(p) for p in parts).encode("utf-8")).hexdigest()
    return str(uuid.UUID(digest[:32]))


def evidence(collector: str, location: str, *, line: int | None = None,
             digest: str | None = None, layer: str | None = None) -> dict:
    """One `evidence_refs` entry, as described in docs/ARCHITECTURE.md."""
    ref: dict = {"collector": collector, "location": location}
    if line is not None:
        ref["line"] = line
    if digest:
        ref["digest"] = digest
    if layer:
        ref["layer"] = layer
    return ref
