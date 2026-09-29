"""Decision traces — the engine's own record of what it did and why.

Modelled on the Decision Trace Schema (arXiv 2604.09296), which names the
"Fragmented Trace Problem": automated decision systems spread their reasoning
across logs that no single record ties together, so nobody can reconstruct why a
particular decision came out the way it did.

The engine solves that by construction rather than by logging. Every stage emits
an immutable record of its inputs, the operation applied, the rule that governed
it, and what came out. The consequence is that the same mechanism serves two
purposes that are usually built twice:

  * the UI can render the engine running, because the trace *is* the run; and
  * an auditor can be handed the derivation of any number on the screen.

Design constraints taken from the schema: completeness without unbounded
storage, immutability once written, and low enough overhead to leave on in
production. Traces are held in memory for the current run and are deliberately
not persisted - they describe a computation, not an estate, and a stale trace is
worse than none.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass(frozen=True)
class TraceEvent:
    """One recorded step. Immutable once created."""

    stage: str
    operation: str
    #: What this step was about - an asset id, or "*" for estate-wide work.
    subject: str
    #: The rule or formula applied, stated so it can be checked by hand.
    rule: str
    inputs: dict[str, Any] = field(default_factory=dict)
    output: dict[str, Any] = field(default_factory=dict)
    duration_us: int = 0
    timestamp: str = ""
    event_id: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


class Trace:
    """An append-only record of one engine run."""

    def __init__(self, run_id: str | None = None):
        self.run_id = run_id or uuid.uuid4().hex[:12]
        self.started_at = datetime.now(timezone.utc).isoformat()
        self._events: list[TraceEvent] = []
        self._stage_started: dict[str, float] = {}
        self.stage_timings: dict[str, int] = {}

    # -- Recording ---------------------------------------------------------

    def record(
        self,
        stage: str,
        operation: str,
        subject: str,
        rule: str,
        inputs: dict | None = None,
        output: dict | None = None,
        duration_us: int = 0,
    ) -> TraceEvent:
        event = TraceEvent(
            stage=stage,
            operation=operation,
            subject=subject,
            rule=rule,
            inputs=inputs or {},
            output=output or {},
            duration_us=duration_us,
            timestamp=datetime.now(timezone.utc).isoformat(),
            event_id=uuid.uuid4().hex[:10],
        )
        self._events.append(event)
        return event

    def begin_stage(self, stage: str) -> None:
        self._stage_started[stage] = time.perf_counter()

    def end_stage(self, stage: str) -> int:
        started = self._stage_started.pop(stage, None)
        elapsed = int((time.perf_counter() - started) * 1_000_000) if started else 0
        self.stage_timings[stage] = elapsed
        return elapsed

    # -- Reading -----------------------------------------------------------

    @property
    def events(self) -> list[TraceEvent]:
        return list(self._events)

    def for_subject(self, subject: str) -> list[dict]:
        """Every step that touched one asset, in order.

        This is the drill-down: given an id, walk its whole journey through the
        engine and see each number with the rule that produced it.
        """
        return [e.to_dict() for e in self._events if e.subject == subject]

    def by_stage(self) -> dict[str, list[dict]]:
        grouped: dict[str, list[dict]] = {}
        for event in self._events:
            grouped.setdefault(event.stage, []).append(event.to_dict())
        return grouped

    def summary(self) -> dict:
        counts: dict[str, int] = {}
        for event in self._events:
            counts[event.stage] = counts.get(event.stage, 0) + 1
        return {
            "run_id": self.run_id,
            "started_at": self.started_at,
            "event_count": len(self._events),
            "events_per_stage": counts,
            "microseconds_per_stage": dict(self.stage_timings),
            "total_microseconds": sum(self.stage_timings.values()),
        }
