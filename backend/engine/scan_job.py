"""The unified scan job behind `/api/scan/full`.

One job runs every collector a target needs, then resolves identities across
collectors, evaluates drift, and hands the resolved assets to the scoring
pipeline. Each step appends an event, and `/api/scan/jobs/{id}/events` streams
them as server-sent events, so the Scan screen shows each surface being
read as it happens rather than a spinner.

    started -> collector_started / collector_finished (per target x collector)
            -> resolved -> drift -> done | failed

A collector that raises is recorded as `collector_failed` with the error and
the job continues: one unreadable image must not lose the rest of the estate,
and it must not disappear silently either.
"""

from __future__ import annotations

import contextvars
import hashlib
import json
import threading
import time
import traceback
import uuid
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Callable

from collectors.base import CollectResult
from collectors.registry import REGISTRY
from engine import drift as drift_engine
from engine.core.corroboration import plane_for
from engine.core.resolution import resolve
from engine.estate import Target

KIND_COLLECTORS = {
    "path": ("source", "dependency", "binary", "config", "keystore", "secret"),
    "repo": ("source", "dependency", "config", "secret"),
    "image": ("container",),
    "capture": ("capture",),
    "vault": ("vault",),
    "host": ("tls",),
}
MAX_JOBS = 20


def output_digest(findings) -> str:
    """SHA-256 of a collector's findings, order-independent, for the signed manifest."""
    rows = sorted(json.dumps(f.model_dump(), sort_keys=True, default=str) for f in findings)
    return hashlib.sha256("\n".join(rows).encode("utf-8")).hexdigest()


def collectors_for(target: Target) -> tuple[str, ...]:
    if target.collectors:
        return tuple(c for c in target.collectors if c in REGISTRY)
    if target.kind == "host" and str(target.value).rsplit(":", 1)[-1] == "22":
        return ("ssh",)
    return tuple(c for c in KIND_COLLECTORS.get(target.kind, ()) if c in REGISTRY)


@dataclass
class Job:
    id: str
    targets: list[Target]
    status: str = "queued"                  # queued | running | done | failed
    created_at: float = field(default_factory=time.time)
    events: list[dict] = field(default_factory=list)
    result: dict | None = None
    error: str | None = None
    # One entry per collector run, for the signed manifest: {collector, target, findings, output_sha256}.
    inputs: list[dict] = field(default_factory=list)
    cond: threading.Condition = field(default_factory=threading.Condition)

    def emit(self, kind: str, **data) -> None:
        with self.cond:
            self.events.append({"seq": len(self.events), "type": kind,
                                "at": round(time.time() - self.created_at, 3), **data})
            self.cond.notify_all()

    def finish(self, status: str) -> None:
        with self.cond:
            self.status = status
            self.cond.notify_all()

    def summary(self) -> dict:
        return {"job_id": self.id, "status": self.status, "targets": [t.to_dict() for t in self.targets],
                "events": len(self.events), "result": self.result, "error": self.error}


JOBS: "OrderedDict[str, Job]" = OrderedDict()
_LOCK = threading.Lock()


def get(job_id: str) -> Job | None:
    return JOBS.get(job_id)


def _bind(result: CollectResult, target: Target) -> None:
    """Stamp a target's declared system facts on everything collected from it."""
    stamp = {k: v for k, v in {
        "system": target.system, "declared_exposure": target.exposure, "criticality": target.criticality,
        "data_classes": target.data_classes or None, "bound_host": target.host,
    }.items() if v}
    if not stamp:
        return
    for finding in result.findings:
        details = finding.raw_details
        for key, value in stamp.items():
            details.setdefault(key, value)
    for decl in result.declarations:
        decl.setdefault("system", target.system)
        if target.host and not decl.get("hosts"):
            decl["bound_host"] = target.host


def _run(job: Job, declarations: list[dict], finish: Callable) -> None:
    job.finish("running")
    plan = [{"target": t.value, "kind": t.kind, "system": t.system, "exposure": t.exposure,
             "collectors": list(collectors_for(t))} for t in job.targets]
    job.emit("started", plan=plan, targets=len(job.targets))
    findings, decls = [], list(declarations)
    try:
        for target in job.targets:
            for name in collectors_for(target):
                collector = REGISTRY[name]
                job.emit("collector_started", collector=name, label=collector.label, plane=collector.plane,
                         target=target.value, system=target.system)
                started = time.monotonic()
                try:
                    result = collector.collect([target.value])
                except Exception as exc:  # a collector bug must not lose the rest of the estate
                    job.emit("collector_failed", collector=name, target=target.value,
                             error=f"{type(exc).__name__}: {exc}", trace=traceback.format_exc(limit=3))
                    continue
                _bind(result, target)
                findings.extend(result.findings)
                decls.extend(result.declarations)
                job.inputs.append({"collector": name, "target": target.value, "findings": len(result.findings),
                                   "output_sha256": output_digest(result.findings)})
                by_plane: dict[str, int] = {}
                for f in result.findings:
                    plane = plane_for(str(f.raw_details.get("discovered_by") or f.source_type), f.source_type)
                    by_plane[plane] = by_plane.get(plane, 0) + 1
                job.emit("collector_finished", collector=name, plane=collector.plane, target=target.value,
                         system=target.system, findings=len(result.findings), by_plane=by_plane,
                         failures=len(result.failures), failure_sample=result.failures[:5],
                         declarations=len(result.declarations),
                         duration_ms=int((time.monotonic() - started) * 1000))
        attached = _attach_systems(findings, decls)
        assets, resolution = resolve(findings)
        job.emit("resolved", **resolution, systems_attached_by_host=attached)
        drift = drift_engine.evaluate(findings, decls)
        _mark_drift(assets, drift)
        job.emit("drift", **{k: v for k, v in drift_engine.summarise(drift).items() if k != "rules"})
        job.result = finish(job, assets, decls, drift, resolution)
        job.emit("done", **job.result)
        job.finish("done")
    except Exception as exc:
        job.error = f"{type(exc).__name__}: {exc}"
        job.emit("failed", error=job.error, trace=traceback.format_exc(limit=5))
        job.finish("failed")


def _attach_systems(findings, declarations: list[dict]) -> int:
    """Give an endpoint finding the system the register declares for its host.

    Estate-wide sources (recorded captures, shared key managers) are not bound
    to one system when collected; the host they answered on is what ties them.
    """
    from engine.core.resolution import endpoint_of

    by_host = {h.lower(): d for d in declarations if d.get("kind") == "system" for h in d.get("hosts", [])}
    attached = 0
    for finding in findings:
        details = finding.raw_details
        system = by_host.get(endpoint_of(finding) or "")
        if system is None or details.get("system"):
            continue
        details.update({k: v for k, v in {
            "system": system["name"], "declared_exposure": system.get("exposure"),
            "criticality": system.get("criticality"), "data_classes": system.get("data_classes") or None,
        }.items() if v})
        attached += 1
    return attached


def _mark_drift(assets, drift: list[dict]) -> None:
    """Point each asset at the drift records that name it (or any finding merged into it)."""
    by_id: dict[str, list[str]] = {}
    for record in drift:
        for asset_id in record["asset_ids"]:
            by_id.setdefault(asset_id, []).append(record["id"])
    for asset in assets:
        ids = [asset.id, *asset.raw_details.get("merged_ids", [])]
        linked = sorted({d for i in ids for d in by_id.get(i, [])})
        if linked:
            asset.raw_details["drift_ids"] = linked


def start(targets: list[Target], declarations: list[dict], finish: Callable, *, run_async: bool = True) -> Job:
    job = Job(id=str(uuid.uuid4()), targets=targets)
    with _LOCK:
        JOBS[job.id] = job
        while len(JOBS) > MAX_JOBS:
            JOBS.popitem(last=False)
    if run_async:
        # The request's context goes with the scan, so its audit entries name who started it.
        context = contextvars.copy_context()
        threading.Thread(target=context.run, args=(_run, job, declarations, finish), daemon=True,
                         name=f"scan-{job.id[:8]}").start()
    else:
        _run(job, declarations, finish)
    return job


def stream(job: Job, since: int = 0, keepalive_s: float = 15.0):
    """Server-sent events for a job, from event `since`, until it finishes."""
    index = since
    while True:
        with job.cond:
            if index >= len(job.events) and job.status in ("queued", "running"):
                job.cond.wait(timeout=keepalive_s)
            pending = job.events[index:]
            finished = job.status in ("done", "failed")
        if not pending and not finished:
            yield ": keepalive\n\n"
            continue
        for event in pending:
            yield f"id: {event['seq']}\nevent: {event['type']}\ndata: {json.dumps(event, default=str)}\n\n"
            index += 1
        if finished and index >= len(job.events):
            return
