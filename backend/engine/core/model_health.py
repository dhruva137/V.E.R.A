"""Model health - learning which models actually work, from what actually happened.

WHY THIS EXISTS
---------------
A gateway advertising 500 models is not offering 500 usable models. Measured
against a live OmniRoute instance, direct free model IDs answered 2 times out of
8 - the rest returned 400, 401 or 500 from the upstream provider - while the
gateway's own `auto/*` routes answered 10 times out of 10, because the gateway
falls through to another provider on failure.

That gap is not a bug to route around once. It is a property of free capacity:
providers rotate, quotas trip, models are withdrawn, and a list that was correct
yesterday is wrong today. So the engine treats model reliability the same way it
treats every other input - as something measured and decayed, never assumed.

WHAT IT DOES
------------
Every call outcome is recorded against the model that served it. From those
outcomes the registry derives:

  * **reliability** - a Laplace-smoothed success rate, so one lucky call does not
    make a model look perfect and one unlucky call does not condemn it;
  * **latency** - the median, because a mean is dragged around by one 30-second
    timeout;
  * **a circuit breaker** - a model that fails repeatedly is taken out of
    rotation for a cooling period rather than retried into the ground.

Selection then prefers reliability first and speed second, which is the right
order: a fast model that fails is worthless, and the tasks here are small.

Nothing here is a guess. A model with no history is *unproven*, not *good* and
not *bad*, and it is tried ahead of a model with a known bad record but behind
one with a known good record.

PROBING, AND WHY A TOOL CALL IS PART OF IT
------------------------------------------
Waiting for organic traffic to reveal a broken model means discovering it during
the turn that needed it. A probe pays that cost up front: a tiny real request to
each candidate, recorded here alongside everything learned passively.

A probe asks three separate questions, because a model can pass one and fail the
next:

  * does it **respond** at all - is there an HTTP 200 with a body we can parse;
  * does it **answer** - is the completion non-empty, which a thinking model
    given a small token budget will fail while still returning 200;
  * does it **call a tool** when handed one.

The third question is the one that matters most for this product. A model that
advertises tool support and never emits a tool call does not fail visibly. It
answers a migration question out of its own head - confident prose with invented
key sizes and invented deadlines, attributed to an estate it never read. That is
the worst failure mode VERA has, and it is indistinguishable from a good answer
unless somebody checks. So it is checked, per model, and recorded.

A model that was never probed is `unknown` here. It is never `working`.
"""

from __future__ import annotations

import json
import statistics
import time
from dataclasses import dataclass, field
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parents[2] / "data"
HEALTH_FILE = DATA_DIR / "model_health.json"

#: Consecutive failures before a model is taken out of rotation.
BREAKER_THRESHOLD = 3
#: How long a tripped model stays out, in seconds.
BREAKER_COOLDOWN = 300.0
#: Laplace smoothing. Two pseudo-observations, one success one failure, so an
#: unproven model starts at 0.5 rather than at 0.0 or 1.0.
_PRIOR_SUCCESS = 1.0
_PRIOR_TOTAL = 2.0

#: Outcomes that mean "this model is unusable", as distinct from "we were
#: rate-limited" or "the network hiccuped". Only these trip the breaker.
#:
#: A definite refusal from the upstream - 400, 401, 404, 500, an empty
#: completion, an SSE body - is about the model. A 429 is the provider
#: rationing us. A timeout or connection error under load is usually about us:
#: measured against a live gateway, calling in a tight loop produced repeated
#: failures from a model that answered in 6 seconds when called on its own.
#: Counting those against the model retired something that worked, which is the
#: opposite of what this registry is for.
_MODEL_FAULTS = {"http_400", "http_401", "http_404", "http_500", "empty", "sse"}

#: Recorded against reliability - they did fail - but never allowed to trip the
#: breaker, because the model is not the thing that went wrong.
#:
#: ``credential`` is here for the same reason as ``rate_limit``: a rejected
#: API key authenticates every model on that endpoint identically. Counting it
#: against the model opens the circuit for 300s on every other key that shares
#: the same model id, which is the opposite of isolating a bad credential.
_NOT_THE_MODELS_FAULT = {"rate_limit", "transient", "timeout", "credential"}

#: The verdicts a probe can reach. Ordered worst to best so a caller can compare
#: them, and deliberately including `unknown`: a model nobody probed has no
#: verdict, and the absence of evidence is reported as exactly that rather than
#: being rounded up to "probably fine".
PROBE_UNKNOWN = "unknown"
PROBE_UNREACHABLE = "unreachable"
PROBE_EMPTY = "empty"
PROBE_TEXT_ONLY = "text-only"
PROBE_WORKING = "working"

#: How long a probe result is treated as current. Free capacity rotates - a
#: provider withdraws a model, a quota resets, a pool is re-pointed - so a
#: fortnight-old verdict is history, not status. Nothing is deleted when it goes
#: stale; it is reported as stale, which is a different claim.
PROBE_FRESH_FOR = 14 * 86_400.0


@dataclass
class ModelRecord:
    """What has actually happened when this model was called."""

    model: str
    successes: int = 0
    failures: int = 0
    consecutive_failures: int = 0
    latencies: list[float] = field(default_factory=list)
    last_error: str = ""
    last_seen: float = 0.0
    breaker_until: float = 0.0

    # -- What a probe measured -------------------------------------------
    #
    # Separate from the fields above, because they answer a different question.
    # Reliability is "how have calls to this model gone"; a probe verdict is
    # "what did this model do when we deliberately tested it, and when". They
    # can disagree - a model that probed clean this morning can be rate-limited
    # now - and collapsing them would lose that.
    #
    # `probed_at` is wall clock, not the monotonic clock the breaker uses,
    # because it has to mean something after a restart: "probed on Tuesday" is
    # a fact, "probed 400 seconds into some previous process" is not.
    probed_at: float = 0.0
    #: The base URL the probe was sent to. A verdict is only about the endpoint
    #: that produced it - the same model id behind a different gateway is a
    #: different thing, and treating them as one is how failover ends up calling
    #: a model that was never there.
    probe_endpoint: str = ""
    probe_responds: bool = False
    probe_answers: bool = False
    probe_calls_tools: bool = False
    probe_latency_s: float | None = None
    #: What the gateway said actually served the request. An `auto/*` route is a
    #: policy, not a model, and knowing it resolved to claude-haiku-4.5 today is
    #: the difference between a measurement and a rumour.
    probe_served_by: str = ""
    probe_detail: str = ""

    @property
    def attempts(self) -> int:
        return self.successes + self.failures

    @property
    def probe_verdict(self) -> str:
        """What the probe concluded, or `unknown` if there was no probe.

        Never infer a verdict from call history. A model can have answered a
        hundred prose requests and still never have been handed a tool, and
        reporting that as `working` would be the exact fabrication this registry
        exists to prevent.
        """
        if not self.probed_at:
            return PROBE_UNKNOWN
        if not self.probe_responds:
            return PROBE_UNREACHABLE
        if not self.probe_answers:
            return PROBE_EMPTY
        return PROBE_WORKING if self.probe_calls_tools else PROBE_TEXT_ONLY

    @property
    def probe_is_fresh(self) -> bool:
        return bool(self.probed_at) and (time.time() - self.probed_at) < PROBE_FRESH_FOR

    def probe_age_days(self) -> float | None:
        if not self.probed_at:
            return None
        return round(max(0.0, time.time() - self.probed_at) / 86_400.0, 2)

    @property
    def reliability(self) -> float:
        """Laplace-smoothed success rate.

        One lucky call must not make a model look perfect, and one unlucky call
        must not condemn it. An unproven model sits at 0.5.
        """
        return round(
            (self.successes + _PRIOR_SUCCESS) / (self.attempts + _PRIOR_TOTAL), 4
        )

    @property
    def median_latency(self) -> float | None:
        return round(statistics.median(self.latencies), 2) if self.latencies else None

    @property
    def proven(self) -> bool:
        return self.attempts >= 3

    def available(self, now: float | None = None) -> tuple[bool, str]:
        now = now if now is not None else time.monotonic()
        if now < self.breaker_until:
            return False, (
                f"circuit open for {self.breaker_until - now:.0f}s after "
                f"{self.consecutive_failures} consecutive failures "
                f"({self.last_error})"
            )
        return True, ""

    def record_success(self, seconds: float | None = None) -> None:
        self.successes += 1
        self.consecutive_failures = 0
        self.breaker_until = 0.0
        self.last_seen = time.monotonic()
        # An unmeasured call contributes to the success count and nothing else.
        # Filing it as zero seconds would make the median latency a claim about
        # a request nobody timed, and a model would look faster the more often
        # we failed to time it.
        if seconds:
            self.latencies.append(seconds)
        # Keep the window short so the median tracks current behaviour rather
        # than how the model performed a thousand calls ago.
        if len(self.latencies) > 20:
            self.latencies = self.latencies[-20:]

    def record_failure(self, kind: str, detail: str = "") -> None:
        self.failures += 1
        self.last_error = f"{kind}: {detail}"[:120] if detail else kind
        self.last_seen = time.monotonic()
        if kind in _MODEL_FAULTS:
            self.consecutive_failures += 1
            if self.consecutive_failures >= BREAKER_THRESHOLD:
                self.breaker_until = time.monotonic() + BREAKER_COOLDOWN
        else:
            # Quota, timeout and network faults are not the model's fault.
            # Recording them keeps the reliability figure honest while leaving
            # a working model in rotation.
            self.consecutive_failures = 0

    def record_probe(self, *, endpoint: str, responds: bool, answers: bool,
                     calls_tools: bool, latency: float | None = None,
                     served_by: str = "", detail: str = "") -> None:
        """Store what a deliberate test of this model found.

        Only what was actually observed is stored. A probe that never got past
        the transport records `responds=False` and keeps no latency figure -
        the time spent failing is not this model's response time, and putting a
        number there would make an unreachable model look merely slow.
        """
        self.probed_at = time.time()
        # Normalised on the way in so a trailing slash cannot split one endpoint
        # into two. Failover matches on this string, and "…/v1" failing to equal
        # "…/v1/" would silently produce an empty fallback chain.
        self.probe_endpoint = (endpoint or "").rstrip("/")
        self.probe_responds = responds
        self.probe_answers = answers
        self.probe_calls_tools = calls_tools
        self.probe_latency_s = round(latency, 2) if (responds and latency) else None
        self.probe_served_by = served_by[:80]
        self.probe_detail = detail[:200]

    def to_dict(self) -> dict:
        ok, reason = self.available()
        return {
            "model": self.model,
            "reliability": self.reliability,
            "attempts": self.attempts,
            "successes": self.successes,
            "failures": self.failures,
            "median_latency_s": self.median_latency,
            "proven": self.proven,
            "available": ok,
            "unavailable_reason": reason,
            "last_error": self.last_error,
            # A model nobody probed reports `unknown`, never `working`.
            "probe_verdict": self.probe_verdict,
            "probe_responds": self.probe_responds if self.probed_at else None,
            "probe_answers": self.probe_answers if self.probed_at else None,
            "probe_calls_tools": self.probe_calls_tools if self.probed_at else None,
            "probe_latency_s": self.probe_latency_s,
            "probe_served_by": self.probe_served_by or None,
            "probe_endpoint": self.probe_endpoint or None,
            "probe_detail": self.probe_detail or None,
            "probe_age_days": self.probe_age_days(),
            "probe_fresh": self.probe_is_fresh if self.probed_at else None,
        }


class ModelRegistry:
    """Which models to try, in what order, based on what has happened."""

    def __init__(self, path: Path | None = None):
        self.path = path or HEALTH_FILE
        self._records: dict[str, ModelRecord] = {}
        self.load()

    # -- Recording -------------------------------------------------------

    def record(self, model: str, *, ok: bool, seconds: float = 0.0,
               kind: str = "", detail: str = "") -> ModelRecord:
        record = self._records.setdefault(model, ModelRecord(model=model))
        if ok:
            record.record_success(seconds)
        else:
            record.record_failure(kind or "unknown", detail)
        return record

    def get(self, model: str) -> ModelRecord:
        return self._records.setdefault(model, ModelRecord(model=model))

    def record_probe(self, model: str, *, endpoint: str, responds: bool,
                     answers: bool, calls_tools: bool,
                     latency: float | None = None, served_by: str = "",
                     detail: str = "", kind: str = "") -> ModelRecord:
        """File a probe result, and let it count as the real call it was.

        A probe is not a simulation - it is a genuine request to a genuine
        endpoint, so its outcome belongs in the reliability figure like any
        other. What deliberately does *not* count against reliability is a model
        that answered in prose but ignored the tool: the call succeeded, and the
        thing it failed at is a capability, recorded as `text-only` rather than
        smuggled in as unreliability. Conflating the two would retire a model
        that is perfectly good for narrative work.
        """
        record = self._records.setdefault(model, ModelRecord(model=model))
        record.record_probe(
            endpoint=endpoint, responds=responds, answers=answers,
            calls_tools=calls_tools, latency=latency, served_by=served_by,
            detail=detail,
        )
        if responds and answers:
            record.record_success(latency)
        else:
            record.record_failure(kind or ("empty" if responds else "transient"),
                                  detail)
        return record

    # -- Selection -------------------------------------------------------

    def rank(self, candidates: list[str], exclude: set[str] | None = None) -> list[str]:
        """Order candidates best-first.

        Reliability dominates, latency breaks ties. That order is deliberate:
        a fast model that fails is worthless, and these tasks are small enough
        that a few seconds either way does not matter.

        An unproven model sorts between the known-good and the known-bad, so
        the registry explores without gambling: it will try something new
        before falling back to something it has watched fail.

        `exclude` drops models already tried in the current turn. Failover needs
        it: the breaker only opens after several consecutive faults, so without
        it the "next" model after a failure is very often the one that just
        failed, and a fallback chain that keeps re-picking its own first link is
        not a fallback chain.
        """
        now = time.monotonic()
        skip = exclude or set()

        def key(model: str):
            record = self._records.get(model)
            if record is None:
                # Unproven sits at the 0.5 prior and competes on reliability
                # like everything else. Giving it its own tier meant a model
                # that had been failing all morning still outranked something
                # untried, purely because it had a history.
                return (0, -0.5, 15.0)
            usable, _ = record.available(now)
            return (
                0 if usable else 1,            # broken models go last
                -record.reliability,
                record.median_latency or 15.0,
            )

        return sorted((c for c in candidates if c not in skip), key=key)

    def usable(self, candidates: list[str], exclude: set[str] | None = None) -> list[str]:
        """Candidates whose circuit is not open."""
        now = time.monotonic()
        return [
            m for m in self.rank(candidates, exclude)
            if m not in self._records or self._records[m].available(now)[0]
        ]

    def best(self, candidates: list[str], exclude: set[str] | None = None) -> str | None:
        ranked = self.usable(candidates, exclude)
        return ranked[0] if ranked else None

    def known_good(self, *, endpoint: str = "", require_tools: bool = True,
                   fresh_only: bool = True, limit: int = 8) -> list[str]:
        """Models a probe actually watched work, best-first.

        This is the material failover is built from, and every word of the
        filter is load-bearing:

          * `endpoint` - a verdict earned against one gateway says nothing about
            the same model id behind another. Falling back to a model that was
            never on this endpoint is a 404 dressed up as resilience.
          * `require_tools` - the agent loop is a tool-calling loop. A model that
            answers beautifully in prose and never calls a tool will invent the
            estate it was asked about, so for that path it is not a fallback,
            it is a hazard. Narrative work can pass `False`.
          * `fresh_only` - free capacity rotates. A verdict from last month is
            history; it is reported, but it is not treated as current status.

        Returns nothing when nothing qualifies. An empty list is the honest
        answer to "which models are known to work", and the caller must be able
        to carry on without one.
        """
        acceptable = (
            {PROBE_WORKING} if require_tools
            else {PROBE_WORKING, PROBE_TEXT_ONLY}
        )
        matches = [
            r for r in self._records.values() if r.probe_verdict in acceptable
        ]
        if endpoint:
            wanted = endpoint.rstrip("/")
            matches = [r for r in matches if r.probe_endpoint == wanted]
        if fresh_only:
            matches = [r for r in matches if r.probe_is_fresh]
        matches = [r for r in matches if r.available()[0]]
        return self.rank([r.model for r in matches])[:limit]

    # -- Reporting -------------------------------------------------------

    def report(self, limit: int = 25) -> dict:
        records = sorted(
            self._records.values(),
            key=lambda r: (-r.reliability, r.median_latency or 99.0),
        )
        proven_good = [r for r in records if r.proven and r.reliability >= 0.7]
        broken = [r for r in records if not r.available()[0]]
        probed = [r for r in records if r.probed_at]

        return {
            "tracked": len(records),
            "proven_reliable": len(proven_good),
            "circuit_open": len(broken),
            "models": [r.to_dict() for r in records[:limit]],
            # Probe coverage is reported next to the counts so nobody reads
            # "40 tracked" as "40 checked". Most of what is tracked here was
            # never deliberately tested.
            "probe": {
                "probed": len(probed),
                "working": sum(1 for r in probed if r.probe_verdict == PROBE_WORKING),
                "text_only": sum(1 for r in probed if r.probe_verdict == PROBE_TEXT_ONLY),
                "empty": sum(1 for r in probed if r.probe_verdict == PROBE_EMPTY),
                "unreachable": sum(
                    1 for r in probed if r.probe_verdict == PROBE_UNREACHABLE
                ),
                "unprobed": len(records) - len(probed),
                "stale": sum(1 for r in probed if not r.probe_is_fresh),
                "last_probe_age_days": min(
                    (r.probe_age_days() for r in probed
                     if r.probe_age_days() is not None),
                    default=None,
                ),
            },
            "note": (
                "Reliability is measured from real outcomes, not advertised. A "
                "gateway offering 500 models is not offering 500 usable ones, "
                "and which ones work changes as providers rotate and quotas "
                "trip."
            ),
        }

    def probe_report(self, endpoint: str = "") -> dict:
        """Everything a probe has established, worst first.

        Ordered by verdict rather than by name because the list exists to be
        acted on: what is broken and what lies about tool support are the rows
        somebody has to do something about.
        """
        rank = {
            PROBE_UNREACHABLE: 0, PROBE_EMPTY: 1, PROBE_TEXT_ONLY: 2,
            PROBE_WORKING: 3, PROBE_UNKNOWN: 4,
        }
        rows = [r for r in self._records.values() if r.probed_at]
        if endpoint:
            wanted = endpoint.rstrip("/")
            rows = [r for r in rows if r.probe_endpoint == wanted]
        rows.sort(key=lambda r: (rank.get(r.probe_verdict, 5),
                                 r.probe_latency_s if r.probe_latency_s else 999.0))
        return {
            "endpoint": endpoint or None,
            "probed": len(rows),
            "working": [r.model for r in rows if r.probe_verdict == PROBE_WORKING],
            "results": [r.to_dict() for r in rows],
            "note": (
                "A model is only listed here because it was actually called. "
                "Anything absent is unknown, not working. `text-only` means the "
                "model answered but ignored a tool it was handed - it will "
                "answer an estate question from its own head rather than from "
                "the estate."
            ),
        }

    # -- Persistence -----------------------------------------------------
    #
    # Health is not secret and is expensive to relearn, so it survives a
    # restart. The circuit-breaker deadline deliberately does not: it is
    # measured on a monotonic clock that resets, and a model that was cooling
    # an hour ago deserves another try now.

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps([
            {
                "model": r.model, "successes": r.successes, "failures": r.failures,
                "latencies": r.latencies[-20:], "last_error": r.last_error,
                # Probe results are the expensive part - each one cost a real
                # request against a real quota - so they survive alongside the
                # counters. `probed_at` is wall clock precisely so that it still
                # means something on the other side of a restart.
                "probed_at": r.probed_at,
                "probe_endpoint": r.probe_endpoint,
                "probe_responds": r.probe_responds,
                "probe_answers": r.probe_answers,
                "probe_calls_tools": r.probe_calls_tools,
                "probe_latency_s": r.probe_latency_s,
                "probe_served_by": r.probe_served_by,
                "probe_detail": r.probe_detail,
            }
            for r in self._records.values()
        ], indent=2), encoding="utf-8")

    def load(self) -> None:
        try:
            rows = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        for row in rows:
            try:
                latency = row.get("probe_latency_s")
                self._records[row["model"]] = ModelRecord(
                    model=row["model"],
                    successes=int(row.get("successes", 0)),
                    failures=int(row.get("failures", 0)),
                    latencies=[float(x) for x in row.get("latencies", [])],
                    last_error=str(row.get("last_error", "")),
                    # Absent probe fields load as "never probed", which is the
                    # correct reading of a file written before probing existed.
                    # Defaulting them to True would turn every historical record
                    # into a working model nobody ever tested.
                    probed_at=float(row.get("probed_at", 0.0) or 0.0),
                    probe_endpoint=str(row.get("probe_endpoint", "") or ""),
                    probe_responds=bool(row.get("probe_responds", False)),
                    probe_answers=bool(row.get("probe_answers", False)),
                    probe_calls_tools=bool(row.get("probe_calls_tools", False)),
                    probe_latency_s=float(latency) if latency else None,
                    probe_served_by=str(row.get("probe_served_by", "") or ""),
                    probe_detail=str(row.get("probe_detail", "") or ""),
                )
            except (KeyError, TypeError, ValueError):
                continue


REGISTRY = ModelRegistry()
