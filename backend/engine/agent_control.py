"""Control plane for the AI agent.

WHY THIS MODULE EXISTS
----------------------
The agent can change the estate. `migrate_asset` rewrites an asset's algorithm
and rescores it, which moves the migration backlog every executive downstream is
reading. An agent that can do that on the strength of a sentence typed into a
chat box is not a feature - it is an unlogged, unbounded, unreviewed write path
into the system of record.

So the agent does not call tools. It calls *through* this module, which decides
whether the call is allowed, and records that it happened either way. Four
independent limits, because they fail differently:

**Autonomy mode** - the posture. `read_only` (the default, NTRO mode) removes
the write tools from the schema entirely, so the model is never even told they
exist. `approval` lets the model propose a write and requires a human to
confirm it. `autonomous` executes writes directly, and is opt-in. The starting
mode can be set with VERA_AGENT_MODE.

**Rate limit** - a token bucket over tool calls. Bounds a model stuck in a loop,
which small local models genuinely do, and bounds the cost of a runaway turn on
a metered API.

**Blast-radius cap** - a ceiling on how many assets one action may mutate. Rate
limiting does not help here: a single `migrate_asset` call with an empty target
matches the entire estate, and that is one call.

**Iteration budget** - a ceiling on tool round trips inside one turn, so a model
that keeps calling tools without ever answering terminates.

Every decision, allowed or refused, lands in the audit log with its arguments
and outcome. "The agent did something to production and nobody can say what" is
the failure this module exists to make impossible.

State is in memory, alongside the scan it describes. Restarting clears the log
with the estate it refers to, which is the honest scope for a tool whose
inventory is also in memory.
"""

from __future__ import annotations

import datetime
import os
import time
import uuid
from collections import deque
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field

AutonomyMode = Literal["read_only", "approval", "autonomous"]

# Tools that mutate state. Estate mutation (migrate, vault rescan) is a write. Everything else is a read, and
# reads are never gated — an agent that cannot look things up is useless, and
# looking things up harms nothing.
WRITE_TOOLS = {"migrate_asset", "scan_key_vault"}

MODE_NOTES = {
    "read_only": (
        "The agent can read and explain the estate but cannot change it. Write "
        "tools are removed from the schema, so the model is not told they exist."
    ),
    "approval": (
        "The agent may propose a change. Nothing is applied until a human "
        "approves the specific proposal."
    ),
    "autonomous": (
        "The agent applies changes directly, still bounded by the rate limit, "
        "the blast-radius cap and the audit log."
    ),
}


def _default_mode() -> str:
    """VERA_AGENT_MODE if it names a mode, else read-only (NTRO mode, engine.ntro_mode)."""
    mode = os.environ.get("VERA_AGENT_MODE", "").strip()
    return mode if mode in MODE_NOTES else "read_only"


class ControlSettings(BaseModel):
    """Operator-facing limits. Every field is enforced, not advisory."""

    # Read-only unless the operator says otherwise: an assessment tool that can
    # change the inventory by default is a harder thing to approve for use.
    mode: AutonomyMode = Field(default_factory=_default_mode)

    # Token bucket over tool calls.
    max_tool_calls_per_minute: int = Field(default=20, ge=1, le=240)
    # Tool round trips inside one chat turn.
    max_iterations_per_turn: int = Field(default=6, ge=1, le=20)
    # Assets a single write action may mutate.
    max_assets_per_action: int = Field(default=25, ge=1, le=1000)
    # Wall-clock ceiling for one turn, so a slow local model cannot hold a
    # request open indefinitely.
    turn_timeout_seconds: float = Field(default=180.0, ge=10.0, le=900.0)
    # Proposals expire, so an approval card left open for an hour cannot be
    # clicked against an estate that has since been rescanned.
    approval_ttl_seconds: float = Field(default=900.0, ge=30.0, le=86400.0)


class AuditEntry(BaseModel):
    """One thing the agent did, or was stopped from doing."""

    id: str
    timestamp: str
    tool: str
    arguments: dict = Field(default_factory=dict)
    # allowed | refused | proposed | approved | rejected | expired | error
    outcome: str
    detail: str = ""
    mutating: bool = False
    duration_ms: Optional[int] = None
    assets_affected: int = 0
    mode: str = ""


class Proposal(BaseModel):
    """A write the agent wants to make, waiting on a human.

    Carries the preview the operator is approving, so the card they click shows
    the consequence rather than the request.
    """

    id: str
    tool: str
    arguments: dict
    created_at: str
    expires_at: str
    summary: str
    preview: dict = Field(default_factory=dict)
    status: str = "pending"  # pending | approved | rejected | expired
    resolved_at: Optional[str] = None
    result: Optional[dict] = None


class RateLimited(Exception):
    """The token bucket is empty. Carries when it will not be."""

    def __init__(self, retry_after: float, limit: int):
        super().__init__(
            f"Rate limit reached ({limit} tool calls/minute). "
            f"Retry in {retry_after:.0f}s."
        )
        self.retry_after = retry_after
        self.limit = limit


class ControlRefusal(Exception):
    """The control plane refused the call outright.

    Distinct from RateLimited: waiting will not help. The message is written to
    be shown to the model, so it can explain the refusal instead of retrying.
    """

    def __init__(self, message: str, *, remedy: str = ""):
        super().__init__(message)
        self.message = message
        self.remedy = remedy


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _iso(moment: datetime.datetime) -> str:
    return moment.isoformat()


class AgentControl:
    """Singleton control plane. One per process, like the scan it guards."""

    def __init__(self):
        self.settings = ControlSettings()
        # Bounded: an audit log that grows without limit is a memory leak with a
        # compliance story attached. 500 entries is far more than one demo or
        # one working session produces, and the count of everything ever seen is
        # kept separately so the total is never silently wrong.
        self.audit: deque[AuditEntry] = deque(maxlen=500)
        self.total_calls = 0
        self.total_refusals = 0
        self.proposals: dict[str, Proposal] = {}
        # Monotonic timestamps of recent tool calls, for the token bucket.
        self._call_times: deque[float] = deque()

    # -- settings ---------------------------------------------------------

    def update_settings(self, **kwargs) -> ControlSettings:
        merged = self.settings.model_dump()
        for key, value in kwargs.items():
            if key in merged and value is not None:
                merged[key] = value
        # Validated rather than assigned, so an out-of-range limit is rejected
        # here instead of quietly disabling the protection it describes.
        self.settings = ControlSettings(**merged)
        return self.settings

    # -- rate limiting ----------------------------------------------------

    def _prune(self, now: float) -> None:
        while self._call_times and now - self._call_times[0] > 60.0:
            self._call_times.popleft()

    def rate_state(self) -> dict:
        now = time.monotonic()
        self._prune(now)
        used = len(self._call_times)
        limit = self.settings.max_tool_calls_per_minute
        return {
            "used": used,
            "limit": limit,
            "remaining": max(limit - used, 0),
            "window_seconds": 60,
            "retry_after": (
                round(max(0.0, 60.0 - (now - self._call_times[0])), 1)
                if used >= limit and self._call_times
                else 0.0
            ),
        }

    def _consume_rate(self) -> None:
        now = time.monotonic()
        self._prune(now)
        limit = self.settings.max_tool_calls_per_minute
        if len(self._call_times) >= limit:
            raise RateLimited(max(0.0, 60.0 - (now - self._call_times[0])), limit)
        self._call_times.append(now)

    # -- audit ------------------------------------------------------------

    def record(
        self,
        tool: str,
        outcome: str,
        *,
        arguments: dict | None = None,
        detail: str = "",
        mutating: bool = False,
        duration_ms: int | None = None,
        assets_affected: int = 0,
    ) -> AuditEntry:
        entry = AuditEntry(
            id=f"audit_{uuid.uuid4().hex[:10]}",
            timestamp=_iso(_now()),
            tool=tool,
            arguments=_redact(arguments or {}),
            outcome=outcome,
            detail=detail,
            mutating=mutating,
            duration_ms=duration_ms,
            assets_affected=assets_affected,
            mode=self.settings.mode,
        )
        self.audit.append(entry)
        # The in-memory log feeds the UI; the hash chain is the tamper-evident record.
        from engine import audit_chain

        audit_chain.append("agent", tool, {"outcome": outcome, "mutating": mutating, "mode": self.settings.mode,
                                           "assets_affected": assets_affected, "arguments": entry.arguments},
                           actor="agent")
        self.total_calls += 1
        if outcome in {"refused", "error"}:
            self.total_refusals += 1
        return entry

    def audit_log(self, limit: int = 100) -> list[dict]:
        """Newest first, which is the order anyone reading it wants."""
        entries = list(self.audit)[-limit:]
        return [e.model_dump() for e in reversed(entries)]

    # -- authorisation ----------------------------------------------------

    def tool_is_allowed(self, tool: str) -> bool:
        """Whether this tool is offered to the model at all."""
        if tool in WRITE_TOOLS and self.settings.mode == "read_only":
            return False
        return True

    def authorise(self, tool: str, arguments: dict, *, assets_affected: int = 0) -> str:
        """Decide what happens to a tool call. Returns "execute" or "propose".

        Raises ControlRefusal or RateLimited instead of returning them, so a
        caller cannot forget to check.
        """
        mutating = tool in WRITE_TOOLS

        if mutating and self.settings.mode == "read_only":
            self.record(
                tool, "refused", arguments=arguments, mutating=True,
                detail="Agent is in read-only mode.",
            )
            raise ControlRefusal(
                "This agent is in read-only mode and cannot change the estate.",
                remedy="An operator can switch to approval mode in Settings.",
            )

        if mutating and assets_affected > self.settings.max_assets_per_action:
            self.record(
                tool, "refused", arguments=arguments, mutating=True,
                assets_affected=assets_affected,
                detail=(
                    f"{assets_affected} assets exceeds the "
                    f"{self.settings.max_assets_per_action}-asset cap."
                ),
            )
            raise ControlRefusal(
                f"That action would change {assets_affected} assets, above the "
                f"{self.settings.max_assets_per_action}-asset limit for a single "
                f"agent action.",
                remedy="Narrow the target, or raise the cap in Settings.",
            )

        try:
            self._consume_rate()
        except RateLimited as limited:
            self.record(
                tool, "refused", arguments=arguments, mutating=mutating,
                detail=str(limited),
            )
            raise

        if mutating and self.settings.mode == "approval":
            return "propose"
        return "execute"

    # -- proposals --------------------------------------------------------

    def propose(self, tool: str, arguments: dict, summary: str, preview: dict) -> Proposal:
        created = _now()
        expires = created + datetime.timedelta(seconds=self.settings.approval_ttl_seconds)
        proposal = Proposal(
            id=f"prop_{uuid.uuid4().hex[:10]}",
            tool=tool,
            arguments=arguments,
            created_at=_iso(created),
            expires_at=_iso(expires),
            summary=summary,
            preview=preview,
        )
        self.proposals[proposal.id] = proposal
        self.record(
            tool, "proposed", arguments=arguments, mutating=True,
            detail=summary, assets_affected=preview.get("assets_affected", 0),
        )
        return proposal

    def get_proposal(self, proposal_id: str) -> Proposal | None:
        proposal = self.proposals.get(proposal_id)
        if proposal and proposal.status == "pending" and self._expired(proposal):
            proposal.status = "expired"
            proposal.resolved_at = _iso(_now())
            self.record(
                proposal.tool, "expired", arguments=proposal.arguments, mutating=True,
                detail="Proposal expired before approval.",
            )
        return proposal

    def _expired(self, proposal: Proposal) -> bool:
        return datetime.datetime.fromisoformat(proposal.expires_at) < _now()

    def pending_proposals(self) -> list[dict]:
        # Reading expires stale ones as a side effect, so the UI never shows an
        # approve button that would fail.
        for proposal_id in list(self.proposals):
            self.get_proposal(proposal_id)
        return [
            p.model_dump() for p in self.proposals.values() if p.status == "pending"
        ]

    def resolve(self, proposal_id: str, status: str, result: dict | None = None) -> None:
        proposal = self.proposals.get(proposal_id)
        if not proposal:
            return
        proposal.status = status
        proposal.resolved_at = _iso(_now())
        proposal.result = result
        self.record(
            proposal.tool,
            "approved" if status == "approved" else "rejected",
            arguments=proposal.arguments,
            mutating=True,
            detail=proposal.summary,
            assets_affected=(result or {}).get("migrated", 0),
        )

    # -- reporting --------------------------------------------------------

    def status(self) -> dict:
        return {
            "settings": self.settings.model_dump(),
            "mode_note": MODE_NOTES[self.settings.mode],
            "modes": [
                {"key": key, "note": note} for key, note in MODE_NOTES.items()
            ],
            "rate": self.rate_state(),
            "write_tools": sorted(WRITE_TOOLS),
            "totals": {
                "calls": self.total_calls,
                "refusals": self.total_refusals,
                "pending_approvals": len(
                    [p for p in self.proposals.values() if p.status == "pending"]
                ),
                "audit_retained": len(self.audit),
            },
        }

    def reset(self) -> None:
        """Used by tests, and by the operator's "clear log" action."""
        self.audit.clear()
        self.proposals.clear()
        self._call_times.clear()
        self.total_calls = 0
        self.total_refusals = 0


# Keys whose values must never reach the audit log. The agent's tools do not
# take secrets today, but an audit log is exactly the kind of thing that ends up
# holding one after a later change.
_SENSITIVE = {"api_key", "key", "token", "secret", "password", "authorization"}


def _redact(arguments: dict) -> dict:
    return {
        k: ("[redacted]" if k.lower() in _SENSITIVE else v)
        for k, v in arguments.items()
    }


_control = AgentControl()


def get_control() -> AgentControl:
    return _control
