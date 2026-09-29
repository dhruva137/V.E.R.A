"""The agent pool - language models as fuel for the engine, not as an oracle.

WHAT THIS IS FOR
----------------
The engine has questions only a reader can answer: a source file that chooses
its algorithm at runtime, two sensors that flatly disagree, a key whose owner
nobody recorded. Static analysis reports these as unresolved and stops, which is
honest but leaves work on the table.

A model can read the surrounding context and form a view. So models are wired in
as **another sensor**, subject to every rule the other sensors obey:

  * A model's answer enters the engine as a **reading with a provenance
    grade**, not as a number. It is graded `heuristic` - the weakest grade
    that exists - because a model reading code is exactly that.
  * It can therefore be **outweighed**. A runtime observation at 0.98 always
    counts for more than a model claim at 0.35.
  * It never writes a score, never sets a rank, and never changes a check.
    The founding rule stands: the model contributes language, never numbers.

That framing is what makes this safe to run on free-tier models. A wrong answer
from a small model becomes a weak, reviewable reading, not a confident number
nobody can trace.

WHY A POOL
----------
Free tiers are generous per-account and tight per-key. Running the engine's
agent work across several keys - and several providers - turns a per-key ceiling
into a pool budget. Nearly every provider is OpenAI-compatible, so one adapter
covers OpenRouter, Groq, Cerebras, Mistral and local servers; Gemini is reached
through its OpenAI-compatible endpoint.

Failure handling follows the gateway pattern rather than a naive retry:

  * a **credential** failure rotates to another key immediately - retrying a
    revoked key is pure latency;
  * a **rate-limit** failure backs the key off for a cooling period, because
    quotas are usually account-wide and hammering it hurts every other task;
  * a **transient** failure retries the same key with exponential backoff and
    jitter, because the key is fine and the network was not.

PROBING BEFORE THE TURN THAT NEEDS IT
-------------------------------------
The pool learns which models work by using them, which means the first thing it
learns about a dead model is learned during a task that wanted one. A probe
front-loads that: a tiny real request to each candidate, graded on three
separate questions - does it respond, does it return anything, and does it call
a tool when handed one - and filed in the health registry alongside everything
learned passively.

Two requests per model, not one, because those questions genuinely cannot be
answered by a single call. Measured against the live gateway, a model given a
tool answers with `content: ""` and a tool call; a model given no tool answers
with text and no tool call. One request can only ever establish one of the two.

The candidate set is bounded and configurable and defaults to a dozen. The
gateway advertises 514 models; probing all of them would be 1028 requests
against free quota to answer a question a dozen requests answer well enough.
"""

from __future__ import annotations

import json
import os
import random
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from engine.core.model_health import REGISTRY as _MODELS

DATA_DIR = Path(__file__).resolve().parents[2] / "data"
KEYS_FILE = DATA_DIR / "agent_keys.json"

# Provider presets. Every one of these speaks the OpenAI chat-completions shape,
# which is why a single adapter reaches all of them. Limits are the published
# free-tier figures at time of writing and are treated as hints for scheduling,
# never as guarantees - the provider's own 429 is the authority.
PROVIDERS: dict[str, dict] = {
    # Listed first because it dominates the others: a self-hosted MIT gateway
    # fronting 290+ providers and 500+ models, 90+ of them free, with
    # quota-aware fallback handled inside the gateway rather than here. One
    # entry reaches more free capacity than every direct provider below it, and
    # nothing leaves the host, because the gateway *is* the host.
    #
    # Its published free-tier catalogue is on the order of 1.5 billion tokens a
    # month across 40+ pools, so the per-minute figure below is a scheduling
    # hint for our side, not a limit the gateway imposes.
    "omniroute": {
        "label": "OmniRoute (self-hosted gateway)",
        "base_url": "http://localhost:20128/v1",
        # OmniRoute addresses models as provider/model. There is no "auto",
        # so this must be set to something the running gateway actually has -
        # `omniroute models` lists them.
        "default_model": "",
        "rpm": 120,
        "rpd": 100_000,
        "needs_key": False,
        "note": (
            "One local endpoint, 290+ providers, 90+ free. Does its own "
            "provider fallback and quota tracking. Preferred over direct keys "
            "wherever it is running."
        ),
    },
    "openrouter": {
        "label": "OpenRouter",
        "base_url": "https://openrouter.ai/api/v1",
        "default_model": "deepseek/deepseek-r1:free",
        "rpm": 20,
        "rpd": 50,
        "needs_key": True,
        "note": (
            "One key, many free models. Daily ceiling rises to 1000 once any "
            "credit has been purchased. Model roster changes often."
        ),
    },
    "groq": {
        "label": "Groq",
        "base_url": "https://api.groq.com/openai/v1",
        "default_model": "llama-3.3-70b-versatile",
        "rpm": 30,
        "rpd": 14_400,
        "needs_key": True,
        "note": "Fastest free inference; deepest free model list.",
    },
    "gemini": {
        "label": "Google AI Studio (Gemini)",
        "base_url": "https://generativelanguage.googleapis.com/v1beta/openai",
        "default_model": "gemini-2.5-flash",
        "rpm": 15,
        "rpd": 1_500,
        "needs_key": True,
        "note": "Generous daily ceiling; reached through the OpenAI-compatible endpoint.",
    },
    "cerebras": {
        "label": "Cerebras",
        "base_url": "https://api.cerebras.ai/v1",
        "default_model": "llama-3.3-70b",
        "rpm": 30,
        "rpd": 1_000,
        "needs_key": True,
        "note": "Roughly 1M tokens/day free.",
    },
    "mistral": {
        "label": "Mistral",
        "base_url": "https://api.mistral.ai/v1",
        "default_model": "mistral-small-latest",
        "rpm": 30,
        "rpd": 1_000,
        "needs_key": True,
        "note": "Free experimentation tier.",
    },
    "local": {
        "label": "Local (Ollama / vLLM / LM Studio)",
        "base_url": "http://127.0.0.1:11434/v1",
        "default_model": "qwen3:1.7b",
        "rpm": 600,
        "rpd": 1_000_000,
        "needs_key": False,
        "note": "No quota and no data leaves the host. Preferred where available.",
    },
    "custom": {
        "label": "Custom OpenAI-compatible endpoint",
        "base_url": "",
        "default_model": "",
        "rpm": 30,
        "rpd": 1_000,
        "needs_key": False,
        "note": "Any gateway exposing /chat/completions.",
    },
}


def _now() -> float:
    return time.monotonic()


# --------------------------------------------------------------------------
# Probe configuration
#
# Every number here is a spending limit on somebody else's free tier, so each
# one is named and each one has a ceiling a caller cannot argue past.
# --------------------------------------------------------------------------

#: How many models a probe run will touch unless told otherwise. Twelve, not
#: 514: the point is to find a handful that work, not to audit a catalogue.
PROBE_DEFAULT_LIMIT = 12
#: The most a caller may ask for, however insistent the request. A run at this
#: ceiling is already 128 requests.
PROBE_MAX_LIMIT = 64
#: Requests in flight. Kept low deliberately - measured against the live
#: gateway, calling in a tight loop produced failures from models that answered
#: fine when called with a little space, so an aggressive probe would report
#: working models as broken and retire them.
PROBE_DEFAULT_CONCURRENCY = 3
PROBE_MAX_CONCURRENCY = 8
#: A cold `auto/*` route took 12s on first call against a live gateway, and a
#: free provider under load is slower still. Too tight a timeout does not save
#: money, it just manufactures failures.
PROBE_TIMEOUT = 45.0
#: The same ceiling the real call path uses, for the same reason: a thinking
#: model that spends its whole budget reasoning returns HTTP 200 with an empty
#: completion, and a probe that squeezed this would report working models as
#: broken. It is a ceiling, not a target - the expected answer is one word.
PROBE_MAX_TOKENS = 1024

#: The prompts. Deliberately minute - a probe that costs real tokens should cost
#: as few as possible, and nothing here needs the model to be clever.
PROBE_TEXT_PROMPT = "Reply with the single word: ready"
PROBE_TOOL_PROMPT = "Call the report_status tool with status set to ok."

#: One trivial tool, whose only job is to be callable. The schema is as small as
#: a valid one can be, so a model that fails to call it is failing at tool
#: calling rather than at reading a complicated schema.
PROBE_TOOL_NAME = "report_status"
PROBE_TOOL = [{
    "type": "function",
    "function": {
        "name": PROBE_TOOL_NAME,
        "description": "Report a one-word status back to the caller.",
        "parameters": {
            "type": "object",
            "properties": {
                "status": {"type": "string", "description": "One word."},
            },
            "required": ["status"],
        },
    },
}]

#: Probed alongside whatever the gateway advertises. These are the routes worth
#: knowing about by name: the gateway's own fallback policies, which survive an
#: upstream provider dying because falling through is what they are for.
#:
#: Deliberately a starting point rather than a catalogue. Anything absent is
#: still probeable by naming it - it is just not spent on by default.
EXPLICIT_PROBE_MODELS = (
    "auto/best-free",
    "auto/fast",
    "auto/chat",
    "auto/best-reasoning",
    "auto/cheap",
)


@dataclass
class PooledKey:
    """One credential, with its own budget and health.

    The plaintext key is held in memory only and is never returned by any API,
    exactly like the model key elsewhere in this product. What is persisted is
    the provider, the model and a four-character hint, which is enough to tell
    two keys apart and not enough to use one.
    """

    id: str
    provider: str
    label: str
    model: str
    base_url: str
    hint: str
    rpm: int
    rpd: int
    #: Models to try on this key, best-first. A gateway offers many and not all
    #: of them work; the health registry decides the order at call time.
    candidates: list[str] = field(default_factory=list)
    #: Runtime state, never persisted.
    calls_this_minute: list[float] = field(default_factory=list)
    calls_today: int = 0
    day_started: float = field(default_factory=_now)
    cooling_until: float = 0.0
    consecutive_failures: int = 0
    disabled_reason: str = ""
    total_calls: int = 0
    total_failures: int = 0

    def _prune(self) -> None:
        cutoff = _now() - 60.0
        self.calls_this_minute = [t for t in self.calls_this_minute if t > cutoff]
        if _now() - self.day_started > 86_400:
            self.calls_today = 0
            self.day_started = _now()

    @property
    def available(self) -> tuple[bool, str]:
        if self.disabled_reason:
            return False, self.disabled_reason
        self._prune()
        if _now() < self.cooling_until:
            return False, f"cooling for {self.cooling_until - _now():.0f}s after a rate limit"
        if len(self.calls_this_minute) >= self.rpm:
            return False, "per-minute budget spent"
        if self.calls_today >= self.rpd:
            return False, "daily budget spent"
        return True, ""

    @property
    def headroom(self) -> float:
        """Share of this key's per-minute budget still free. Drives selection so
        load spreads instead of hammering whichever key is first."""
        self._prune()
        return max(0.0, 1.0 - len(self.calls_this_minute) / max(self.rpm, 1))

    def record_call(self) -> None:
        self.calls_this_minute.append(_now())
        self.calls_today += 1
        self.total_calls += 1
        self.consecutive_failures = 0

    def record_rate_limit(self, cooldown: float = 60.0) -> None:
        # Quotas are usually account-wide, so a 429 means back off rather than
        # rotate-and-hammer: another key on the same account would fail too.
        self.cooling_until = _now() + cooldown
        self.total_failures += 1

    def record_credential_failure(self, detail: str) -> None:
        # Retrying a revoked key is pure latency. Take it out of the pool and
        # say why, rather than letting it fail silently forever.
        self.disabled_reason = f"credential rejected: {detail}"[:160]
        self.total_failures += 1

    def record_transient(self) -> None:
        self.consecutive_failures += 1
        self.total_failures += 1
        if self.consecutive_failures >= 5:
            self.disabled_reason = "five consecutive transient failures"

    def to_dict(self) -> dict:
        ok, reason = self.available
        return {
            "id": self.id,
            "provider": self.provider,
            "label": self.label,
            "model": self.model,
            "hint": self.hint,
            "available": ok,
            "unavailable_reason": reason,
            "rpm": self.rpm,
            "rpd": self.rpd,
            "used_this_minute": len(self.calls_this_minute),
            "used_today": self.calls_today,
            "headroom": round(self.headroom, 3),
            "total_calls": self.total_calls,
            "total_failures": self.total_failures,
        }


class AgentPool:
    """Every credential the engine may burn, and the scheduler over them."""

    def __init__(self):
        self._keys: dict[str, PooledKey] = {}
        self._secrets: dict[str, str] = {}   # id -> plaintext, memory only
        self._load_manifest()

    # -- Registration ----------------------------------------------------

    def add(self, provider: str, api_key: str, *, model: str = "",
            base_url: str = "", label: str = "") -> PooledKey:
        preset = PROVIDERS.get(provider, PROVIDERS["custom"])
        resolved_model = model or preset["default_model"]
        # Identity is provider + model, not a counter. A counter meant every
        # restart appended another copy of the same gateway to the manifest -
        # after a dozen runs the pool reported eleven OmniRoute entries that
        # were all the same endpoint, and its advertised capacity was nonsense.
        key_id = f"{provider}:{resolved_model or 'default'}"
        pooled = PooledKey(
            id=key_id,
            provider=provider,
            label=label or preset["label"],
            model=resolved_model,
            base_url=base_url or preset["base_url"],
            hint=f"...{api_key[-4:]}" if len(api_key) >= 4 else "no key",
            rpm=preset["rpm"],
            rpd=preset["rpd"],
        )
        self._keys[key_id] = pooled
        self._secrets[key_id] = api_key or ""
        self._save_manifest()
        return pooled

    def remove(self, key_id: str) -> bool:
        if key_id not in self._keys:
            return False
        del self._keys[key_id]
        self._secrets.pop(key_id, None)
        self._save_manifest()
        return True

    def all(self) -> list[PooledKey]:
        return list(self._keys.values())

    def _save_manifest(self) -> None:
        """Persist everything except the secret."""
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        KEYS_FILE.write_text(json.dumps([
            {
                "id": k.id, "provider": k.provider, "label": k.label,
                "model": k.model, "base_url": k.base_url, "hint": k.hint,
            }
            for k in self._keys.values()
        ], indent=2), encoding="utf-8")

    def _load_manifest(self) -> None:
        """Restore the shape of the pool, but never a usable credential.

        Keys reappear disabled with a stated reason after a restart. That is
        deliberate: a pool that silently came back empty would look like a
        configuration bug, and one that persisted secrets to disk would be a
        worse product than one that asks for them again.
        """
        try:
            rows = json.loads(KEYS_FILE.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        for row in rows:
            try:
                preset = PROVIDERS.get(row["provider"], PROVIDERS["custom"])
                pooled = PooledKey(
                    id=row["id"], provider=row["provider"], label=row["label"],
                    model=row["model"], base_url=row["base_url"], hint=row["hint"],
                    rpm=preset["rpm"], rpd=preset["rpd"],
                )
                if preset.get("needs_key", True):
                    pooled.disabled_reason = (
                        "secret not loaded since restart; re-enter it"
                    )
                self._keys[pooled.id] = pooled
            except KeyError:
                continue
            # Older manifests used a counter for the id, so the same provider
            # could appear many times. Keyed by provider+model on load, those
            # collapse back into one entry.

    # -- Scheduling ------------------------------------------------------

    def _has_credential(self, key: PooledKey) -> bool:
        """Whether this key is usable.

        A self-hosted gateway and a local model need no credential, and
        requiring one would make the best option in the pool permanently
        unavailable. Only providers that actually authenticate are gated.
        """
        preset = PROVIDERS.get(key.provider, PROVIDERS["custom"])
        if not preset.get("needs_key", True):
            return True
        return bool(self._secrets.get(key.id))


    def secret_for(self, base_url: str) -> str:
        """The credential registered for this endpoint, or an empty string.

        Exists so callers outside the pool never have to reach into `_secrets`.
        An empty string is a real answer, not a failure: a self-hosted gateway
        needs no credential, and the caller must omit the Authorization header
        entirely rather than send an empty bearer token.
        """
        wanted = (base_url or "").rstrip("/")
        for key in self._keys.values():
            if key.base_url.rstrip("/") == wanted:
                return self._secrets.get(key.id, "")
        return ""

    def model_candidates(self, key: PooledKey) -> list[str]:
        """Every model worth trying on this key, in the order to try them.

        The key's own model leads, because an operator who named one meant it.
        Behind it come models a probe watched work *at this key's endpoint* -
        and only at this endpoint, because a verdict earned against one gateway
        says nothing about the same identifier behind another.

        Tool calling is not required here. Agent tasks ask for a small JSON
        object in the reply text, not for a tool call, so a model that answers
        in prose does this job perfectly well. The agent loop in llm_bridge is
        the path that needs the stricter filter, and it applies it itself.
        """
        ordered = [m for m in key.candidates if m]
        if key.model and key.model not in ordered:
            ordered.insert(0, key.model)
        if key.base_url:
            for model in _MODELS.known_good(
                endpoint=key.base_url, require_tools=False,
            ):
                if model not in ordered:
                    ordered.append(model)
        return ordered

    def pick(self) -> PooledKey | None:
        """The healthiest available key, by remaining per-minute headroom.

        Spreading by headroom rather than round-robin keeps one slow provider
        from throttling the whole pool.
        """
        candidates = [
            k for k in self._keys.values()
            if k.available[0] and self._has_credential(k)
        ]
        if not candidates:
            return None
        return max(candidates, key=lambda k: (k.headroom, -k.total_failures))

    def capacity(self) -> dict:
        """What the pool can do right now, honestly."""
        keys = self.all()
        usable = [k for k in keys if k.available[0] and self._has_credential(k)]
        return {
            "keys": len(keys),
            "usable_now": len(usable),
            "requests_per_minute": sum(k.rpm for k in usable),
            "requests_per_day": sum(k.rpd for k in usable),
            "providers": sorted({k.provider for k in usable}),
            "blocked": [
                {"id": k.id, "provider": k.provider, "reason": k.available[1]}
                for k in keys if not k.available[0]
            ],
        }

    # -- Invocation ------------------------------------------------------

    def call(self, messages: list[dict], *, max_attempts: int = 4,
             timeout: float = 30.0, transport: Callable | None = None) -> dict:
        """Run one completion across the pool, handling each failure by kind.

        `transport` is injectable so the failure paths can be tested without a
        network. Returns a result dict rather than raising: an agent task that
        cannot run is a normal outcome the engine must carry on through, not an
        exception that aborts a scan.
        """
        send = transport or self._http_call
        attempts: list[dict] = []
        # Models already burned in *this* call. Without it, failover does not
        # fail over: the breaker needs several consecutive faults before it
        # opens, so the best-ranked model after a failure is very often the one
        # that just failed, and the pool spends every attempt on it.
        tried: set[str] = set()

        for attempt in range(max_attempts):
            key = self.pick()
            if key is None:
                return {
                    "ok": False, "reason": "no_capacity", "attempts": attempts,
                    "detail": (
                        "No key in the pool has budget right now. The engine "
                        "continues without agent assistance; findings that "
                        "needed it stay unresolved rather than being guessed."
                    ),
                }

            # Which model on this key? The registry ranks by what has actually
            # worked, so a model that has been returning 401 all morning is not
            # tried again ahead of one that answers.
            candidates = self.model_candidates(key)
            model = _MODELS.best(candidates, exclude=tried)
            if model is None:
                # Nothing healthy is left. An untried model with an open circuit
                # is still worth one attempt - the cooldown is short and a
                # stale verdict beats no answer - but re-calling something that
                # already failed this turn is not a fallback, it is a loop.
                remaining = [m for m in candidates if m not in tried]
                model = remaining[0] if remaining else None
            if model is None:
                return {
                    "ok": False, "reason": "no_model", "attempts": attempts,
                    "detail": (
                        f"Every model on {key.id} has been tried this turn or "
                        f"has an open circuit. Probe the endpoint to find "
                        f"working models: POST /api/agents/probe."
                        if tried else
                        f"No model is configured for {key.id} and none has "
                        f"been probed at {key.base_url}. Probe the endpoint "
                        f"first: POST /api/agents/probe."
                    ),
                }
            tried.add(model)
            started = time.perf_counter()

            try:
                text = send(key, self._secrets[key.id], messages, timeout, model)
                elapsed = time.perf_counter() - started
                key.record_call()
                _MODELS.record(model, ok=True, seconds=elapsed)
                _MODELS.save()
                return {"ok": True, "text": text, "key_id": key.id,
                        "provider": key.provider, "model": model,
                        "seconds": round(elapsed, 2), "attempts": attempts,
                        # Which models were burned getting here. An answer that
                        # took three models to obtain is still an answer, but it
                        # is not the same event as one that took a single call,
                        # and hiding the difference hides a degrading pool.
                        "fell_back_from": [
                            m for m in tried if m != model
                        ]}
            except _RateLimited as exc:
                # The provider rationing us is not the model failing. Recorded,
                # but it must not retire a model that works.
                key.record_rate_limit(exc.retry_after)
                _MODELS.record(model, ok=False, kind="rate_limit", detail=str(exc))
                attempts.append({"key": key.id, "model": model,
                                 "kind": "rate_limit", "detail": str(exc)})
            except _CredentialRejected as exc:
                key.record_credential_failure(str(exc))
                # The key is wrong, not the model. Recording this as http_401
                # would open the model circuit for every other key that shares
                # the id; ``credential`` counts against reliability without
                # retiring a model that works behind a different key.
                _MODELS.record(model, ok=False, kind="credential", detail=str(exc))
                attempts.append({"key": key.id, "model": model,
                                 "kind": "credential", "detail": str(exc)})
            except _ModelFault as exc:
                # The key is fine; this model is not. Try the next-best model
                # on the same key rather than burning another key's budget.
                _MODELS.record(model, ok=False, kind=exc.kind, detail=str(exc))
                _MODELS.save()
                attempts.append({"key": key.id, "model": model,
                                 "kind": exc.kind, "detail": str(exc)})
            except Exception as exc:  # noqa: BLE001 - transient
                key.record_transient()
                _MODELS.record(model, ok=False, kind="transient",
                               detail=f"{type(exc).__name__}")
                attempts.append({"key": key.id, "model": model,
                                 "kind": "transient",
                                 "detail": f"{type(exc).__name__}: {exc}"})
                # Same key, backed off with jitter: the key is fine, the
                # network was not.
                # Start at a full second, not a quarter. Measured against a
                # live gateway, four calls a second apart all succeeded while
                # the same calls back-to-back mostly failed: the retry storm
                # was causing the failures it was retrying.
                time.sleep(min(2 ** attempt * 1.0 + random.uniform(0, 0.5), 8.0))

        return {"ok": False, "reason": "exhausted", "attempts": attempts,
                "detail": f"All {max_attempts} attempts failed."}

    @staticmethod
    def _http_call(key: PooledKey, secret: str, messages: list[dict],
                   timeout: float, model: str | None = None) -> str:
        import httpx

        # Omit the header entirely when there is no secret. A self-hosted
        # gateway needs none, and sending "Bearer " with an empty value is an
        # illegal header that httpx rejects before the request leaves - which
        # surfaces as a transient network fault and gets blamed on the model.
        headers: dict[str, str] = {}
        if secret:
            headers["Authorization"] = f"Bearer {secret}"
        if key.provider == "openrouter":
            # OpenRouter asks callers to identify themselves; it also improves
            # free-tier standing.
            headers["HTTP-Referer"] = "https://vera.local"
            headers["X-Title"] = "VERA"

        response = httpx.post(
            f"{key.base_url.rstrip('/')}/chat/completions",
            headers=headers,
            json={
                "model": model or key.model,
                "messages": messages,
                "temperature": 0.0,
                # Explicit, never left to the server default. Some gateways
                # (OmniRoute among them) stream unless told otherwise, and an
                # SSE body parsed as JSON fails in a way that looks like the
                # provider is broken rather than like a protocol mismatch.
                "stream": False,
                # Enough for a thinking model to reason AND answer. Agent
                # tasks return small JSON objects, so this is a ceiling
                # against runaway cost, not a target.
                "max_tokens": 1024,
            },
            timeout=timeout,
        )

        if response.status_code == 429:
            retry = response.headers.get("retry-after")
            raise _RateLimited(retry_after=float(retry) if retry else 60.0)
        if response.status_code in (401, 403):
            # A gateway returns 401 both for a bad key and for a model the
            # upstream will not serve. The body distinguishes them, and getting
            # this wrong retires a working key over one unavailable model.
            body = response.text[:200]
            if "model" in body.lower():
                raise _ModelFault("http_401", body[:120])
            raise _CredentialRejected(body[:120])
        if response.status_code in (400, 404, 500, 502, 503):
            raise _ModelFault(f"http_{response.status_code}", response.text[:120])
        response.raise_for_status()

        payload = response.json()
        choice = payload["choices"][0]
        content = (choice.get("message", {}).get("content") or "").strip()

        if not content:
            # A 200 with no content is a failure, and treating it as success
            # would hand the caller an empty string to parse. The common cause
            # is a thinking model (Gemini 2.5, DeepSeek R1) spending its whole
            # budget on internal reasoning: finish_reason is "length" and
            # completion_tokens is zero. Raising here routes it through the
            # transient path, which retries with backoff rather than silently
            # returning nothing.
            raise _ModelFault(
                "empty",
                f"empty completion from {model or key.model} "
                f"(finish_reason={choice.get('finish_reason')}); "
                "a thinking model may need a larger token budget",
            )

        return content


class _ModelFault(Exception):
    """This model is unusable; the key is fine.

    Separated from a credential failure because the remedies are opposite: a
    credential failure means stop using the key, a model fault means keep the
    key and try a different model on it.
    """

    def __init__(self, kind: str, detail: str = ""):
        super().__init__(detail or kind)
        self.kind = kind


class _RateLimited(Exception):
    def __init__(self, retry_after: float = 60.0):
        super().__init__(f"rate limited, retry after {retry_after:.0f}s")
        self.retry_after = retry_after


class _CredentialRejected(Exception):
    pass


# --------------------------------------------------------------------------
# The probe
#
# Nothing below infers anything. Every field it files was observed on a request
# that was actually sent; a model it did not reach is recorded as unreached, and
# a model it never touched is not recorded at all.
# --------------------------------------------------------------------------


def _probe_request(base_url: str, model: str, secret: str, prompt: str,
                   tools: list[dict] | None, timeout: float) -> dict:
    """One tiny completion, reported as an outcome rather than an exception.

    A probe that raised would make the caller's job pattern-matching on
    exception types across a thread pool; the whole point here is a flat record
    of what happened, including the failures, so failures come back as data.
    """
    import httpx

    # No header at all when there is no secret. `Authorization: Bearer ` with an
    # empty value is an illegal header that httpx rejects before the request
    # leaves the process - which arrives looking like an unreachable endpoint
    # and gets blamed on the model.
    headers: dict[str, str] = {}
    if secret:
        headers["Authorization"] = f"Bearer {secret}"

    payload: dict[str, Any] = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.0,
        # Explicit, always. OmniRoute streams unless told otherwise, and an SSE
        # body parsed as JSON fails as "Expecting value: line 1 column 1" -
        # which reads as an unreachable model rather than as a protocol
        # mismatch, and would retire the entire catalogue in one run.
        "stream": False,
        "max_tokens": PROBE_MAX_TOKENS,
    }
    if tools:
        payload["tools"] = tools
        payload["tool_choice"] = "auto"

    started = time.perf_counter()
    try:
        response = httpx.post(
            f"{base_url.rstrip('/')}/chat/completions",
            headers=headers, json=payload, timeout=timeout,
        )
    except Exception as exc:  # noqa: BLE001 - every transport fault is a result
        kind = "timeout" if "Timeout" in type(exc).__name__ else "transient"
        return {
            "responds": False, "kind": kind, "status": None,
            "detail": f"{type(exc).__name__}: {exc}"[:200],
            "seconds": round(time.perf_counter() - started, 2),
            "content": "", "tool_calls": [], "served_by": "", "finish_reason": "",
        }

    elapsed = round(time.perf_counter() - started, 2)
    base = {
        "responds": False, "status": response.status_code, "seconds": elapsed,
        "content": "", "tool_calls": [], "served_by": "", "finish_reason": "",
    }

    if response.status_code == 429:
        # Rationing, not breakage. Named as its own kind so it never trips the
        # breaker and never gets reported to the operator as a dead model.
        return {**base, "kind": "rate_limit",
                "detail": f"rate limited: {response.text[:120]}"}
    if response.status_code != 200:
        return {**base, "kind": f"http_{response.status_code}",
                "detail": response.text[:200]}

    body = response.text
    if body.lstrip().startswith("data:"):
        return {**base, "kind": "sse",
                "detail": "server-sent events despite stream=false"}
    try:
        data = response.json()
    except Exception:
        return {**base, "kind": "sse",
                "detail": f"200 with an unparseable body: {body[:120]}"}

    choices = data.get("choices") or []
    if not choices:
        return {**base, "kind": "empty", "detail": "200 with no choices"}

    message = choices[0].get("message") or {}
    calls = [
        (call.get("function") or {}).get("name", "")
        for call in (message.get("tool_calls") or [])
    ]
    return {
        **base,
        "responds": True,
        "kind": "",
        "detail": "",
        "content": (message.get("content") or "").strip(),
        "tool_calls": [c for c in calls if c],
        # An `auto/*` route is a routing policy, not a model. Recording what it
        # resolved to turns "auto/best-free works" into something checkable.
        "served_by": str(data.get("model") or ""),
        "finish_reason": str(choices[0].get("finish_reason") or ""),
    }


def probe_model(model: str, *, base_url: str, secret: str = "",
                timeout: float = PROBE_TIMEOUT,
                transport: Callable | None = None) -> dict:
    """Test one model and return what was measured, never what was assumed.

    Two requests, and the second only when the first earned it. A model that
    cannot return a sentence is not going to be asked whether it can call a
    tool - that request would tell us nothing we do not already know and would
    still be charged against the quota.
    """
    send = transport or _probe_request

    text = send(base_url, model, secret, PROBE_TEXT_PROMPT, None, timeout)
    responds = bool(text["responds"])
    # An HTTP 200 carrying an empty completion is a failure, full stop. It is
    # what a thinking model does when it spends its budget reasoning, and
    # calling it a success hands the caller an empty string to parse.
    answers = responds and bool(text["content"])

    result = {
        "model": model,
        "endpoint": base_url,
        "responds": responds,
        "answers": answers,
        "calls_tools": False,
        "latency_s": text["seconds"] if responds else None,
        "served_by": text["served_by"],
        "kind": text["kind"],
        "detail": text["detail"],
        "requests": 1,
    }

    if not answers:
        if responds and not text["content"]:
            result["kind"] = "empty"
            result["detail"] = (
                f"HTTP 200 with an empty completion "
                f"(finish_reason={text['finish_reason'] or 'unset'}); a thinking "
                f"model may have spent the whole token budget reasoning"
            )
        return result

    tool = send(base_url, model, secret, PROBE_TOOL_PROMPT, PROBE_TOOL, timeout)
    result["requests"] = 2
    result["calls_tools"] = bool(
        tool["responds"] and PROBE_TOOL_NAME in tool["tool_calls"]
    )
    # Latency is the mean of the two measured calls, which is a fairer figure
    # than either alone: the plain completion is the cheapest thing this model
    # will ever do, and the tool turn is closer to what the agent asks of it.
    if tool["responds"]:
        result["latency_s"] = round((text["seconds"] + tool["seconds"]) / 2, 2)

    if not result["calls_tools"]:
        # The failure this product cares about most, so it is spelled out
        # rather than left as a false flag. A model in this state answers a
        # migration question with invented numbers and sounds certain doing it.
        result["detail"] = (
            "answered in prose but emitted no tool call when handed one"
            if tool["responds"]
            else f"tool turn failed: {tool['kind']} {tool['detail']}".strip()
        )
        if not tool["responds"]:
            result["kind"] = tool["kind"]

    return result


def discover_probe_candidates(base_url: str, *, secret: str = "",
                              limit: int = PROBE_DEFAULT_LIMIT,
                              timeout: float = 15.0) -> tuple[list[str], str]:
    """What to probe, bounded, with a sentence saying where the list came from.

    Prefers the gateway's own `auto/*` routes over individual free model ids,
    which is not laziness: those routes carry the gateway's provider fallback,
    so one of them survives an upstream outage that takes a named free model
    down. The explicit list rides along so a run is never empty just because the
    catalogue could not be read.
    """
    import httpx

    headers = {"Authorization": f"Bearer {secret}"} if secret else {}
    advertised: list[str] = []
    note = ""
    try:
        response = httpx.get(
            f"{base_url.rstrip('/')}/models", headers=headers, timeout=timeout,
        )
        response.raise_for_status()
        advertised = [
            str(entry.get("id", ""))
            for entry in (response.json().get("data") or [])
            if entry.get("id")
        ]
    except Exception as exc:  # noqa: BLE001
        note = (
            f"Could not read the catalogue at {base_url} "
            f"({type(exc).__name__}); falling back to the explicit list."
        )

    autos = [m for m in advertised if m.startswith("auto/")]
    ordered: list[str] = []
    for model in list(EXPLICIT_PROBE_MODELS) + autos:
        # An explicit model the gateway does not advertise is still probed. The
        # catalogue is a claim, and a model missing from it that answers anyway
        # is a more useful discovery than a tidy list.
        if model not in ordered:
            ordered.append(model)

    if not note:
        note = (
            f"{len(advertised)} models advertised, {len(autos)} of them auto/* "
            f"routes. Probing {min(len(ordered), limit)} of them - the routes "
            f"carry the gateway's own provider fallback, so they survive an "
            f"upstream outage a named free model does not."
        )
    return ordered[:limit], note


def probe_models(models: list[str] | None = None, *, base_url: str = "",
                 secret: str = "", limit: int = PROBE_DEFAULT_LIMIT,
                 concurrency: int = PROBE_DEFAULT_CONCURRENCY,
                 registry=None, transport: Callable | None = None,
                 timeout: float = PROBE_TIMEOUT) -> dict:
    """Probe a bounded set of models and file every result in the registry.

    Caps are enforced here rather than trusted to the caller, because the caller
    is an HTTP endpoint and the cost is somebody's free tier.
    """
    from concurrent.futures import ThreadPoolExecutor

    registry = registry if registry is not None else _MODELS
    base_url = base_url or PROVIDERS["omniroute"]["base_url"]
    limit = max(1, min(int(limit or PROBE_DEFAULT_LIMIT), PROBE_MAX_LIMIT))
    concurrency = max(1, min(int(concurrency or PROBE_DEFAULT_CONCURRENCY),
                             PROBE_MAX_CONCURRENCY))

    if models:
        # Order preserved and duplicates dropped, so asking for the same model
        # twice does not spend the quota twice.
        candidates, note = [], "Explicit model list supplied by the caller."
        for model in models:
            if model and model not in candidates:
                candidates.append(model)
        candidates = candidates[:limit]
    else:
        candidates, note = discover_probe_candidates(
            base_url, secret=secret, limit=limit,
        )

    if not candidates:
        return {
            "ok": False, "endpoint": base_url, "probed": 0, "results": [],
            "note": note, "requests_sent": 0,
            "detail": "Nothing to probe. Name models explicitly to run anyway.",
        }

    started = time.perf_counter()
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        results = list(pool.map(
            lambda model: probe_model(
                model, base_url=base_url, secret=secret, timeout=timeout,
                transport=transport,
            ),
            candidates,
        ))

    for result in results:
        registry.record_probe(
            result["model"],
            endpoint=result["endpoint"],
            responds=result["responds"],
            answers=result["answers"],
            calls_tools=result["calls_tools"],
            latency=result["latency_s"],
            served_by=result["served_by"],
            detail=result["detail"],
            kind=result["kind"],
        )
    registry.save()

    working = [r["model"] for r in results if r["answers"] and r["calls_tools"]]
    text_only = [r["model"] for r in results if r["answers"] and not r["calls_tools"]]
    return {
        "ok": True,
        "endpoint": base_url,
        "probed": len(results),
        "requests_sent": sum(r["requests"] for r in results),
        "seconds": round(time.perf_counter() - started, 2),
        "working": working,
        "text_only": text_only,
        "broken": [r["model"] for r in results if not r["answers"]],
        "results": results,
        "note": note,
        "detail": (
            f"{len(working)} of {len(results)} answered and called a tool. "
            f"{len(text_only)} answered but ignored the tool - those will "
            f"invent an answer rather than read the estate, so they are not "
            f"offered to the agent loop."
        ),
    }


POOL = AgentPool()


# --------------------------------------------------------------------------
# Seeding from the environment
# --------------------------------------------------------------------------

#: Environment variable per provider. A key pasted into .env should just work;
#: making an operator re-enter it in the UI as well would be a second place for
#: the same secret to be wrong.
_ENV_KEYS = {
    "omniroute": ("VERA_OMNIROUTE_API_KEY", "VERA_OMNIROUTE_MODEL", "VERA_OMNIROUTE_BASE_URL"),
    "groq": ("VERA_GROQ_API_KEY", "VERA_GROQ_MODEL", ""),
    "gemini": ("VERA_GEMINI_API_KEY", "VERA_GEMINI_MODEL", ""),
    "openrouter": ("VERA_OPENROUTER_API_KEY", "VERA_OPENROUTER_MODEL", ""),
    "cerebras": ("VERA_CEREBRAS_API_KEY", "VERA_CEREBRAS_MODEL", ""),
    "mistral": ("VERA_MISTRAL_API_KEY", "VERA_MISTRAL_MODEL", ""),
    "local": ("", "VERA_LOCAL_MODEL", "VERA_LOCAL_BASE_URL"),
}


def seed_from_environment(pool: AgentPool | None = None) -> list[str]:
    """Load every provider configured in the environment into the pool.

    A keyless provider (a self-hosted gateway, a local model) is seeded when it
    has a base URL and a model, because those are what make it usable; a keyed
    provider is seeded only when its key is present. Returns the provider names
    actually added, so startup can say what it found rather than claiming
    capacity it does not have.
    """
    pool = pool or POOL
    added: list[str] = []
    existing = {k.provider for k in pool.all()}

    for provider, (key_var, model_var, url_var) in _ENV_KEYS.items():
        if provider in existing:
            continue

        api_key = os.environ.get(key_var, "").strip() if key_var else ""
        model = os.environ.get(model_var, "").strip() if model_var else ""
        base_url = os.environ.get(url_var, "").strip() if url_var else ""

        needs_key = PROVIDERS.get(provider, {}).get("needs_key", True)
        if needs_key and not api_key:
            continue
        if not needs_key and not (base_url or model):
            # Nothing configured for this keyless provider; seeding it would
            # add an entry that can never answer.
            continue

        pool.add(provider, api_key, model=model, base_url=base_url)
        added.append(provider)

    return added
