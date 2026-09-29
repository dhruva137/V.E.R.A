"""LLM integration bridge - bring your own model.

VERA ships no model and no API key. An operator points this bridge at a model
they already control - a local Ollama daemon, an OpenAI-compatible endpoint, an
Anthropic key, or a self-hosted vLLM/LM Studio server - and the agent and the
narrative generators start using it. Nothing is called until they do.

WHY A BRIDGE RATHER THAN AN SDK
-------------------------------
Four providers behind one normalised call. The agent loop (engine.agent) is
written once against the canonical message format below and does not know or
care which provider answered, so swapping a cloud key for a local Llama changes
a dropdown, not the code.

CANONICAL MESSAGE FORMAT
------------------------
Internally, and over the wire to the dashboard, messages are OpenAI-shaped with
tool arguments already parsed:

    {"role": "system"|"user"|"assistant", "content": str}
    {"role": "assistant", "content": str,
     "tool_calls": [{"id": str, "name": str, "arguments": dict}]}
    {"role": "tool", "tool_call_id": str, "name": str, "content": str}

`arguments` is always a dict here - never a JSON string. Ollama returns objects
and OpenAI returns strings; normalising at the boundary means the agent never
has to guess which it got. Each adapter converts to and from its provider's
shape, so a conversation started on one provider can be continued on another.

The API key lives in memory only. It is never written to disk, never logged and
never returned by the API - `to_dict` reports whether one is set, not what it is.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import time
import uuid
from typing import Any, Optional

import httpx

from engine.core.model_health import REGISTRY as _MODELS

# Providers. `custom` is `openai` with a base URL the operator supplies, kept
# separate only so the UI can label it honestly - anything speaking the OpenAI
# chat-completions schema (vLLM, LM Studio, llama.cpp, Together, OpenRouter,
# Groq, Gemini, Azure) works through it.
#
# `api_prefix` is the version segment between the base URL and the resource.
# Empty for Ollama, whose paths are absolute. See _endpoint: it exists because
# operators paste base URLs that already contain the version and some that do
# not, and both have to reach the same endpoint.
PROVIDERS = {
    "ollama": {
        "label": "Ollama (local)",
        "default_base_url": "http://localhost:11434",
        "needs_key": False,
        "api_prefix": "",
        "note": "Runs entirely on this machine. No data leaves the host.",
    },
    "openai": {
        "label": "OpenAI",
        "default_base_url": "https://api.openai.com",
        "needs_key": True,
        "api_prefix": "v1",
        "note": "Also covers Azure OpenAI and any OpenAI-compatible gateway.",
    },
    "anthropic": {
        "label": "Anthropic",
        "default_base_url": "https://api.anthropic.com",
        "needs_key": True,
        "api_prefix": "v1",
        "note": "Claude models through the native Messages API.",
    },
    # OmniRoute is listed ahead of the direct providers deliberately. It is a
    # self-hosted MIT gateway that fronts 290+ providers (90+ of them free) on
    # one OpenAI-compatible endpoint and does quota-aware fallback itself, so a
    # single entry here reaches more free capacity than every direct provider
    # below it combined - and no key leaves the host, because the gateway is
    # the host.
    "omniroute": {
        "label": "OmniRoute (self-hosted gateway)",
        "default_base_url": "http://localhost:20128",
        "needs_key": False,
        "api_prefix": "v1",
        "note": (
            "One local endpoint in front of 290+ providers and 500+ models, "
            "90+ free. Handles provider fallback and quota tracking itself. "
            "Default port 20128. Models use a provider/model form, e.g. "
            "'cc/claude-opus-4-7'."
        ),
    },
    "groq": {
        "label": "Groq",
        "default_base_url": "https://api.groq.com",
        "needs_key": True,
        "api_prefix": "openai/v1",
        "note": "Best direct free tier: 30 req/min, 14,400 req/day. Fastest inference.",
    },
    "gemini": {
        "label": "Google AI Studio (Gemini)",
        "default_base_url": "https://generativelanguage.googleapis.com",
        "needs_key": True,
        "api_prefix": "v1beta/openai",
        "note": (
            "Reached through Google's OpenAI-compatible endpoint, so it needs no "
            "separate adapter. Free tier is 1,500 requests/day."
        ),
    },
    "custom": {
        "label": "Custom OpenAI-compatible endpoint",
        "default_base_url": "http://localhost:8080",
        "needs_key": False,
        "api_prefix": "v1",
        "note": "vLLM, LM Studio, llama.cpp, OpenRouter, Cerebras, Together.",
    },
}

# Gateways identifiable from the shape of their API key.
#
# Every one of these speaks the OpenAI chat-completions schema, so none of them
# is a new provider - they are the documented `openai` provider pointed at a
# different host. What the table buys is that an operator does not have to know
# that: an API key already says which service issued it, so asking someone to
# also paste an endpoint and a model identifier is asking them to repeat
# themselves, and getting either one wrong is the single most common way this
# feature fails in a hurry.
#
# `model` is a starting point, not a claim about what a given key can reach.
# Load models in Settings still reports the truth.
KEY_SHAPES = (
    ("sk-ant-", {
        "provider": "anthropic",
        "base_url": "https://api.anthropic.com",
        "model": "",
        "label": "Anthropic",
    }),
    ("sk-or-", {
        "provider": "openai",
        "base_url": "https://openrouter.ai/api/v1",
        "model": "",
        "label": "OpenRouter",
    }),
    ("gsk_", {
        "provider": "openai",
        "base_url": "https://api.groq.com/openai/v1",
        "model": "openai/gpt-oss-20b",
        "label": "Groq",
    }),
    # Google issues two shapes: the long-standing AIza... AI Studio key, and a
    # newer AQ.... one. Both authenticate against the same OpenAI-compatible
    # endpoint, so both map here.
    ("AIza", {
        "provider": "openai",
        "base_url": "https://generativelanguage.googleapis.com/v1beta/openai",
        "model": "gemini-2.5-flash",
        "label": "Google Gemini",
    }),
    ("AQ.", {
        "provider": "openai",
        "base_url": "https://generativelanguage.googleapis.com/v1beta/openai",
        "model": "gemini-2.5-flash",
        "label": "Google Gemini",
    }),
    ("sk-", {
        "provider": "openai",
        "base_url": "https://api.openai.com",
        "model": "gpt-4o-mini",
        "label": "OpenAI",
    }),
)


def identify_key(api_key: str) -> dict | None:
    """Which gateway issued this key, if its shape says so.

    Order matters: sk-ant- and sk-or- are both sk- keys, so the specific
    prefixes are tested before the general one.
    """
    key = (api_key or "").strip()
    for prefix, gateway in KEY_SHAPES:
        if key.startswith(prefix):
            return gateway
    return None


def _is_a_default_base_url(url: str) -> bool:
    """Whether this URL is one nobody chose - a provider default or a blank.

    Used to decide if auto-configuration may overwrite it. A base URL an
    operator actually typed is never touched.
    """
    if not url:
        return True
    candidates = {p["default_base_url"] for p in PROVIDERS.values()}
    candidates |= {g["base_url"] for _, g in KEY_SHAPES}
    return url.rstrip("/") in {c.rstrip("/") for c in candidates}


# A path segment that is itself a version: v1, v2, v1beta.
_VERSION_SEGMENT = re.compile(r"v\d+[a-z0-9]*")

ANTHROPIC_VERSION = "2023-06-01"

# Requests are bounded so a wedged endpoint cannot hang a dashboard request
# forever. Tool-calling turns on a local 8B model are genuinely slow, hence 90s
# rather than something tighter.
DEFAULT_TIMEOUT = 90.0
DISCOVERY_TIMEOUT = 12.0


class LLMError(Exception):
    """A provider call failed in a way the operator needs to see.

    Carries a remedy where one is knowable: "model not found" is only useful
    next to `ollama pull llama3.1`.
    """

    def __init__(self, message: str, *, remedy: str = "", status: int | None = None):
        super().__init__(message)
        self.message = message
        self.remedy = remedy
        self.status = status

    def to_dict(self) -> dict:
        return {"error": self.message, "remedy": self.remedy, "status": self.status}


class LLMConfig:
    """Runtime LLM configuration, mutable through the API.

    Seeded from the environment so a deployment can be configured without
    touching the UI, then overridable at runtime so a demo can switch model
    without a restart.
    """

    def __init__(self):
        self.provider: str = os.environ.get("VERA_LLM_PROVIDER", "").strip().lower()
        self.api_key: str = os.environ.get("VERA_LLM_API_KEY", "").strip()
        configured_base = os.environ.get("VERA_LLM_BASE_URL", "").strip()
        self.base_url: str = configured_base or self.default_base_url()
        self.model: str = os.environ.get("VERA_LLM_MODEL", "").strip()

        # One variable is enough to bring a deployment up already configured.
        #
        # The same reasoning as pasting a key into Settings: the key names the
        # service that issued it, so VERA_LLM_API_KEY on its own is a complete
        # configuration. An operator who does set the endpoint explicitly keeps
        # it - this only fills what was left blank.
        if self.api_key and not configured_base:
            gateway = identify_key(self.api_key)
            if gateway:
                self.provider = self.provider or gateway["provider"]
                self.base_url = gateway["base_url"]
                self.model = self.model or gateway["model"]
        self.temperature: float = float(os.environ.get("VERA_LLM_TEMPERATURE", "0.2"))
        self.max_tokens: int = int(os.environ.get("VERA_LLM_MAX_TOKENS", "1200"))
        self.timeout: float = DEFAULT_TIMEOUT
        # Ollama only. 4096 (its default) is not enough for the system prompt,
        # fifteen tool schemas and a couple of tool results together.
        self.num_ctx: int = int(os.environ.get("VERA_LLM_NUM_CTX", "16384"))
        # Surface a reasoning model's scratchpad to the operator.
        self.show_thinking: bool = os.environ.get("VERA_LLM_THINKING", "1") != "0"
        # Set by a successful call, cleared by any config change, so the UI can
        # distinguish "configured" from "known to work".
        self.verified: bool = False
        self.last_error: str = ""

    def default_base_url(self) -> str:
        return PROVIDERS.get(self.provider, {}).get("default_base_url", "")

    @property
    def enabled(self) -> bool:
        return bool(self.provider)

    @property
    def is_configured(self) -> bool:
        """Whether a call can be attempted at all.

        Deliberately not "whether it will work" - only a round trip proves that,
        which is what test_connection is for.
        """
        if self.provider not in PROVIDERS:
            return False
        if not self.model:
            return False
        if PROVIDERS[self.provider]["needs_key"] and not self.api_key:
            return False
        return bool(self.base_url)

    def missing(self) -> list[str]:
        """What is still needed, so the UI can say so precisely."""
        gaps = []
        if self.provider not in PROVIDERS:
            return ["provider"]
        if not self.base_url:
            gaps.append("base_url")
        if not self.model:
            gaps.append("model")
        if PROVIDERS[self.provider]["needs_key"] and not self.api_key:
            gaps.append("api_key")
        return gaps

    def update(self, **kwargs) -> None:
        previous_provider = self.provider
        for key in ("provider", "api_key", "base_url", "model"):
            if key in kwargs and kwargs[key] is not None:
                setattr(self, key, str(kwargs[key]).strip())
        for key, cast in (
            ("temperature", float), ("max_tokens", int), ("timeout", float),
            ("num_ctx", int), ("show_thinking", bool),
        ):
            if kwargs.get(key) is not None:
                try:
                    setattr(self, key, cast(kwargs[key]))
                except (TypeError, ValueError):
                    pass

        # Switching provider without also naming a base URL should land on that
        # provider's default rather than silently keeping the old one - pointing
        # an OpenAI key at localhost:11434 is a confusing way to fail.
        if self.provider != previous_provider and "base_url" not in kwargs:
            self.base_url = self.default_base_url()

        # A pasted key configures the rest of itself.
        #
        # The key already identifies the service that issued it, so an endpoint
        # and a model typed alongside it are duplicated information and two more
        # chances to get it wrong. Only fields nobody chose are filled: a base
        # URL an operator actually typed survives this untouched, and so does a
        # model they picked.
        if kwargs.get("api_key"):
            gateway = identify_key(self.api_key)
            if gateway and _is_a_default_base_url(self.base_url):
                self.provider = gateway["provider"]
                self.base_url = gateway["base_url"]
                if not self.model and gateway["model"]:
                    self.model = gateway["model"]

        # Any change invalidates a previous successful test.
        self.verified = False
        self.last_error = ""

    def clear_key(self) -> None:
        self.api_key = ""
        self.verified = False

    def to_dict(self) -> dict:
        return {
            "provider": self.provider,
            "provider_label": PROVIDERS.get(self.provider, {}).get("label", ""),
            "base_url": self.base_url,
            "model": self.model,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            "num_ctx": self.num_ctx,
            "show_thinking": self.show_thinking,
            "enabled": self.enabled,
            "is_configured": self.is_configured,
            "missing": self.missing(),
            "needs_key": PROVIDERS.get(self.provider, {}).get("needs_key", False),
            "verified": self.verified,
            "last_error": self.last_error,
            # The key itself is never returned. The last four characters are
            # enough to confirm which key is loaded without disclosing it.
            "has_api_key": bool(self.api_key),
            "api_key_hint": f"...{self.api_key[-4:]}" if len(self.api_key) >= 4 else "",
            "providers": [{"key": k, **v} for k, v in PROVIDERS.items()],
        }


_config = LLMConfig()


def get_config() -> LLMConfig:
    return _config


# --------------------------------------------------------------------------
# HTTP plumbing
# --------------------------------------------------------------------------


def _headers(config: LLMConfig) -> dict:
    headers = {"Content-Type": "application/json"}
    if config.provider == "anthropic":
        if config.api_key:
            headers["x-api-key"] = config.api_key
        headers["anthropic-version"] = ANTHROPIC_VERSION
    elif config.api_key:
        headers["Authorization"] = f"Bearer {config.api_key}"
    return headers


def _versioned_base(config: LLMConfig) -> str:
    """The base URL with the version segment present exactly once.

    Split out from `_endpoint` because two things need it and they must agree:
    the endpoint builder, and the failover chain, which keys probe results by
    the URL they were measured against. If those two disagreed by a `/v1`, every
    model probed through this bridge would look like it belonged to a different
    endpoint and failover would never find a single candidate.
    """
    base = config.base_url.rstrip("/")
    prefix = PROVIDERS.get(config.provider, {}).get("api_prefix", "")
    tail = base.rsplit("/", 1)[-1].lower()

    already_versioned = (
        tail == prefix
        or bool(_VERSION_SEGMENT.fullmatch(tail))
        # A compatibility root such as Gemini's /v1beta/openai: the version sits
        # one segment up, so the URL is complete despite ending in a word. Groq
        # publishes a bare /openai with no version anywhere, and still needs one.
        or (
            tail == "openai"
            and any(_VERSION_SEGMENT.fullmatch(s) for s in base.lower().split("/"))
        )
    )
    if prefix and not already_versioned:
        base = f"{base}/{prefix}"
    return base


def _endpoint(config: LLMConfig, resource: str) -> str:
    """Join the base URL to a resource, inserting the version segment once.

    Base URLs arrive in whatever shape the provider's own documentation shows,
    and they do not agree on how much of the path they include:

        https://api.openai.com                       needs /v1 appended
        https://api.x.ai                             needs /v1 appended
        https://api.x.ai/v1                          already carries it
        https://api.groq.com/openai                  needs /v1 appended
        https://api.groq.com/openai/v1               already carries it
        https://generativelanguage.googleapis.com/v1beta/openai
                                                     versioned one segment up,
                                                     and 404s on a second /v1

    Appending blindly produced /v1/v1/chat/completions. Every provider answers
    that with a 404 whose message names the model, so it read as a bad model
    identifier and sent operators to change the wrong setting.
    """
    return f"{_versioned_base(config)}/{resource.lstrip('/')}"


def _error_detail(response: httpx.Response) -> str:
    """The provider's own explanation, in whichever shape it sent it.

    Every provider nests this differently, and Gemini wraps the object in a
    list. Without the list case the parse failed and the operator was shown the
    raw response body - the message they needed, buried in braces.
    """
    try:
        body = response.json()
    except Exception:
        return (response.text or "")[:300]

    if isinstance(body, list):
        body = body[0] if body else {}
    if not isinstance(body, dict):
        return str(body)[:300]

    raw = body.get("error")
    if isinstance(raw, dict):
        return str(raw.get("message") or raw.get("type") or "")[:300]
    return str(raw or body.get("detail") or body.get("message") or "")[:300]


def _translate_http_error(config: LLMConfig, exc: Exception) -> LLMError:
    """Turn a transport or status failure into something actionable.

    A bare "request failed" sends an operator hunting through logs; naming the
    fix is the difference between a demo that recovers and one that stops.
    """
    if isinstance(exc, httpx.ConnectError):
        if config.provider == "ollama":
            return LLMError(
                f"Cannot reach Ollama at {config.base_url}.",
                remedy="Start it with `ollama serve`, then load the model list again.",
            )
        return LLMError(
            f"Cannot reach {config.base_url}.",
            remedy="Check the base URL is correct and the endpoint is running.",
        )
    if isinstance(exc, (httpx.ReadTimeout, httpx.ConnectTimeout, asyncio.TimeoutError)):
        return LLMError(
            f"{config.model or 'The model'} did not respond within {config.timeout:.0f}s.",
            remedy="A large model on CPU can exceed this. Try a smaller model.",
        )
    if isinstance(exc, httpx.HTTPStatusError):
        status = exc.response.status_code
        detail = _error_detail(exc.response)

        # A rejected key is not reported consistently: OpenAI and Anthropic use
        # 401, Gemini answers 400 with the reason in the message. Keying only on
        # the status code left the most common mistake of all - a wrong or
        # unpasted key - showing as a bare "Provider returned 400."
        looks_like_a_key_problem = "api key" in detail.lower() or "api_key" in detail.lower()
        if status in (401, 403) or (status == 400 and looks_like_a_key_problem):
            return LLMError(
                f"The provider rejected the credentials ({status}). {detail}".strip(),
                remedy="Check the API key, and that it has access to this model.",
                status=status,
            )
        if status == 404:
            if config.provider == "ollama":
                return LLMError(
                    f"Ollama has no model named {config.model!r}.",
                    remedy=f"Pull it first: `ollama pull {config.model}`",
                    status=status,
                )
            return LLMError(
                f"Endpoint or model not found ({status}). {detail}".strip(),
                remedy="Check the base URL path and the model identifier.",
                status=status,
            )
        if status == 429:
            return LLMError(
                "The provider is rate limiting this key (429).",
                remedy="Wait and retry, or switch to a local Ollama model.",
                status=status,
            )
        return LLMError(f"Provider returned {status}. {detail}".strip(), status=status)
    return LLMError(str(exc) or exc.__class__.__name__)


# --------------------------------------------------------------------------
# Message adapters
#
# Canonical (documented at the top of this module) in, provider-shaped out, and
# back again. Kept in named functions rather than inlined so each provider's
# quirks are readable and testable on their own.
# --------------------------------------------------------------------------


def _to_openai_messages(messages: list[dict]) -> list[dict]:
    out = []
    for msg in messages:
        role = msg.get("role")
        if role == "tool":
            out.append({
                "role": "tool",
                "tool_call_id": msg.get("tool_call_id", ""),
                "content": msg.get("content", ""),
            })
        elif role == "assistant" and msg.get("tool_calls"):
            out.append({
                "role": "assistant",
                "content": msg.get("content") or None,
                "tool_calls": [
                    _openai_tool_call(call) for call in msg["tool_calls"]
                ],
            })
        else:
            out.append({"role": role, "content": msg.get("content", "")})
    return out


def _openai_tool_call(call: dict) -> dict:
    out = {
        "id": call["id"],
        "type": "function",
        "function": {
            "name": call["name"],
            # OpenAI wants a JSON *string* here, which is the single most common
            # source of tool-calling bugs when talking to more than one provider.
            "arguments": json.dumps(call.get("arguments") or {}),
        },
    }
    # Returned exactly as it arrived; see _from_openai_message.
    if call.get("extra_content"):
        out["extra_content"] = call["extra_content"]
    return out


def _from_openai_message(message: dict) -> dict:
    calls = []
    for call in message.get("tool_calls") or []:
        function = call.get("function", {})
        parsed = {
            "id": call.get("id") or f"call_{uuid.uuid4().hex[:12]}",
            "name": function.get("name", ""),
            "arguments": _coerce_arguments(function.get("arguments")),
        }
        # Opaque provider state travelling with the call.
        #
        # Gemini 3.x returns a thought_signature here and rejects the follow-up
        # turn with a 400 if it does not come back - "Function call is missing a
        # thought_signature in functionCall parts". Nothing here interprets it;
        # it is carried through the canonical form and handed back untouched, so
        # a provider that does not use the field is unaffected.
        if call.get("extra_content"):
            parsed["extra_content"] = call["extra_content"]
        calls.append(parsed)
    result = {"role": "assistant", "content": message.get("content") or ""}
    if calls:
        result["tool_calls"] = calls
    return result


def _to_ollama_messages(messages: list[dict]) -> list[dict]:
    out = []
    for msg in messages:
        role = msg.get("role")
        if role == "tool":
            # Ollama pairs tool results positionally and ignores an id.
            out.append({"role": "tool", "content": msg.get("content", "")})
        elif role == "assistant" and msg.get("tool_calls"):
            out.append({
                "role": "assistant",
                "content": msg.get("content") or "",
                "tool_calls": [
                    {"function": {"name": c["name"], "arguments": c.get("arguments") or {}}}
                    for c in msg["tool_calls"]
                ],
            })
        else:
            out.append({"role": role, "content": msg.get("content", "")})
    return out


def _from_ollama_message(message: dict) -> dict:
    calls = []
    for call in message.get("tool_calls") or []:
        function = call.get("function", {})
        calls.append({
            # Ollama does not issue ids; the loop needs one to pair results.
            "id": f"call_{uuid.uuid4().hex[:12]}",
            "name": function.get("name", ""),
            "arguments": _coerce_arguments(function.get("arguments")),
        })
    result = {"role": "assistant", "content": message.get("content") or ""}
    if calls:
        result["tool_calls"] = calls
    # Reasoning models (deepseek-r1, qwen3) return their scratchpad in a separate
    # `thinking` field rather than inside content. It is not context for the next
    # turn - it is shown to the operator and then dropped - so it rides along on
    # the message rather than being folded into the answer.
    if message.get("thinking"):
        result["thinking"] = message["thinking"]
    return result


def _to_anthropic(messages: list[dict]) -> tuple[str, list[dict]]:
    """Split the system prompt out and rebuild the turn as content blocks.

    Anthropic takes `system` as a top-level parameter, expects an assistant tool
    call as a `tool_use` block, and expects the result as a `tool_result` block
    on a *user* turn rather than under a `tool` role.
    """
    system_parts = [m.get("content", "") for m in messages if m.get("role") == "system"]
    out: list[dict] = []

    for msg in messages:
        role = msg.get("role")
        if role == "system":
            continue
        if role == "tool":
            block = {
                "type": "tool_result",
                "tool_use_id": msg.get("tool_call_id", ""),
                "content": msg.get("content", ""),
            }
            # Consecutive tool results belong on a single user turn.
            if out and out[-1]["role"] == "user" and isinstance(out[-1]["content"], list):
                out[-1]["content"].append(block)
            else:
                out.append({"role": "user", "content": [block]})
        elif role == "assistant" and msg.get("tool_calls"):
            blocks: list[dict] = []
            if msg.get("content"):
                blocks.append({"type": "text", "text": msg["content"]})
            for call in msg["tool_calls"]:
                blocks.append({
                    "type": "tool_use",
                    "id": call["id"],
                    "name": call["name"],
                    "input": call.get("arguments") or {},
                })
            out.append({"role": "assistant", "content": blocks})
        else:
            out.append({"role": role, "content": msg.get("content", "")})

    return "\n\n".join(p for p in system_parts if p), out


def _from_anthropic_response(data: dict) -> dict:
    text_parts, calls = [], []
    for block in data.get("content") or []:
        if block.get("type") == "text":
            text_parts.append(block.get("text", ""))
        elif block.get("type") == "tool_use":
            calls.append({
                "id": block.get("id") or f"call_{uuid.uuid4().hex[:12]}",
                "name": block.get("name", ""),
                "arguments": block.get("input") or {},
            })
    result = {"role": "assistant", "content": "".join(text_parts)}
    if calls:
        result["tool_calls"] = calls
    return result


def _coerce_arguments(raw: Any) -> dict:
    """Always hand the agent a dict.

    OpenAI sends a JSON string, Ollama sends an object, and small local models
    sometimes send a string that is not valid JSON at all. The last case is
    reported as an empty argument set rather than crashing the turn.
    """
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str) and raw.strip():
        try:
            parsed = json.loads(raw)
            return parsed if isinstance(parsed, dict) else {}
        except json.JSONDecodeError:
            return {}
    return {}


def _tools_for_provider(provider: str, tools: list[dict] | None) -> Any:
    """Tool schemas in each provider's shape.

    Tools are declared once in engine.agent using the OpenAI function shape;
    Anthropic's differs only in nesting and the `input_schema` key.
    """
    if not tools:
        return None
    if provider == "anthropic":
        return [
            {
                "name": t["function"]["name"],
                "description": t["function"].get("description", ""),
                "input_schema": t["function"].get(
                    "parameters", {"type": "object", "properties": {}}
                ),
            }
            for t in tools
        ]
    return tools


# --------------------------------------------------------------------------
# Public calls
# --------------------------------------------------------------------------


#: A failure that means "stop, the credentials are wrong". Distinguished from
#: every other failure because the remedies are opposite: a model fault means
#: try the next model, a credential fault means every model on this endpoint
#: will fail the same way and trying them all is just a slower error message.
class _CredentialProblem(LLMError):
    pass


#: How many models one turn may burn before giving up. Three, because the turn
#: has its own wall-clock budget upstream and a chain long enough to exhaust it
#: fails the turn just as surely as no chain at all - only slower, and after
#: spending more quota.
MAX_FAILOVER_MODELS = 3


def _is_credential_problem(error: LLMError) -> bool:
    """Whether this failure is about the key rather than about the model.

    A gateway answers 401 both for a rejected key and for a model the upstream
    will not serve, and the difference decides whether to stop or to fall
    through. Getting it backwards is expensive in both directions: treat a bad
    key as a model fault and the turn walks the whole chain to reach the same
    error; treat an unavailable model as a bad key and one withdrawn free model
    takes the entire endpoint down with it.
    """
    if error.status not in (400, 401, 403):
        return False
    lowered = (error.message or "").lower()
    if "model" in lowered:
        return False
    return any(
        marker in lowered
        for marker in ("credential", "api key", "api_key", "unauthorized")
    )


def _health_kind(error: LLMError) -> str:
    """Which bucket in the health registry this failure belongs in.

    The distinction that matters is whether the model is at fault. A 429 is the
    provider rationing us and a timeout is usually load on our side; recording
    either as a model fault retires something that works.
    """
    if error.status == 429:
        return "rate_limit"
    if error.status:
        return f"http_{error.status}"
    lowered = str(error.message).lower()
    if "did not respond" in lowered or "timeout" in lowered:
        return "timeout"
    if "empty completion" in lowered:
        return "empty"
    return "transient"


def _failover_chain(config: LLMConfig) -> list[str]:
    """The configured model, then models a probe watched work on this endpoint.

    The operator's choice always leads - they named it, and silently preferring
    something else would make the Settings screen a lie. What follows it is only
    ever a model that was actually probed, at this exact endpoint, and that
    actually emitted a tool call when handed one.

    That last condition is not fussiness. This is the agent loop: a model that
    answers fluently and never calls a tool does not fail, it *confabulates* -
    it answers a question about the estate without reading the estate, in
    complete sentences, with numbers it made up. Promoting one of those to
    fallback would turn an outage into something worse than an outage.
    """
    chain = [config.model] if config.model else []
    for model in _MODELS.known_good(
        endpoint=_versioned_base(config), require_tools=True,
    ):
        if model not in chain:
            chain.append(model)
    return chain[:MAX_FAILOVER_MODELS]


async def chat(messages: list[dict], tools: list[dict] | None = None) -> dict:
    """One turn, across as many models as it takes to get an answer.

    Returns a canonical assistant message with a `_meta` block carrying the
    model that actually answered, latency, token usage, and - when the first
    choice failed - what it fell back from. Raises LLMError only when every
    model in the chain failed, so callers still get a typed error rather than a
    silent None.

    The chain exists because a free-tier model going down mid-turn used to end
    the turn. It is not a retry: the same model is never called twice, because
    the thing that just refused is the least likely thing to answer next.
    """
    config = _config
    if not config.is_configured:
        raise LLMError(
            "No language model is configured.",
            remedy="Open Settings, choose a provider, load a model and save.",
        )

    chain = _failover_chain(config)
    attempts: list[dict] = []
    last: LLMError | None = None

    for model in chain:
        started = time.perf_counter()
        try:
            message, usage = await _one_attempt(config, model, messages, tools)
        except _CredentialProblem as exc:
            # Every model on this endpoint authenticates the same way, so the
            # next one down the chain would fail identically. Stop here and say
            # what is actually wrong. Counted as ``credential``, not http_401:
            # the key is wrong, and opening the model circuit would punish every
            # other key that happens to share the same model id.
            config.last_error = exc.message
            _MODELS.record(model, ok=False, kind="credential", detail=exc.message)
            _MODELS.save()
            raise
        except LLMError as exc:
            kind = _health_kind(exc)
            _MODELS.record(model, ok=False, kind=kind, detail=exc.message)
            _MODELS.save()
            attempts.append({"model": model, "kind": kind, "detail": exc.message})
            last = exc
            continue

        elapsed = time.perf_counter() - started
        _MODELS.record(model, ok=True, seconds=elapsed)
        _MODELS.save()

        config.verified = True
        config.last_error = ""
        message["_meta"] = {
            # The model that answered, which is not always the model that was
            # configured. Reporting config.model here would attribute an answer
            # to a model that never produced it.
            "model": model,
            "configured_model": config.model,
            "provider": config.provider,
            "latency_ms": round(elapsed * 1000),
            "usage": {k: v for k, v in usage.items() if v is not None},
            "failed_over_from": [a["model"] for a in attempts],
        }
        return message

    # Everything in the chain failed. Report the last real failure rather than a
    # summary, because the last failure is the one with the provider's own words
    # in it, and add what else was tried so it does not look like one bad call.
    detail = last or LLMError(
        f"No model is available. {config.model or 'None'} is configured and "
        f"nothing has been probed at {_versioned_base(config)}.",
        remedy="Probe the endpoint from the Agent pool screen.",
    )
    if len(attempts) > 1:
        others = ", ".join(f"{a['model']} ({a['kind']})" for a in attempts[:-1])
        detail = LLMError(
            f"{detail.message} Fell back through {others} first.",
            remedy=detail.remedy, status=detail.status,
        )
    config.last_error = detail.message
    raise detail


async def _one_attempt(config: LLMConfig, model: str, messages: list[dict],
                       tools: list[dict] | None) -> tuple[dict, dict]:
    """One provider round trip with one named model.

    Split out of `chat` so the failover loop has something to call per model.
    Takes the model explicitly rather than reading `config.model`, which is what
    lets a fallback run without mutating the operator's saved configuration.
    """
    provider = config.provider

    if provider == "ollama":
        url = _endpoint(config, "api/chat")
        payload: dict[str, Any] = {
            "model": model,
            "messages": _to_ollama_messages(messages),
            "stream": False,
            "options": {
                "temperature": config.temperature,
                "num_predict": config.max_tokens,
                # The estate preamble plus fifteen tool schemas plus a few tool
                # results runs past Ollama's 4096 default, and an overflowed
                # context silently drops the *oldest* tokens - which is the
                # system prompt telling it to call tools at all. That failure
                # looks like a dumb model rather than a truncated one.
                "num_ctx": config.num_ctx,
            },
        }
        # Ask reasoning models to expose their scratchpad separately instead of
        # burying it in the answer. Ollama ignores this on models without the
        # capability, so it costs nothing to send unconditionally.
        payload["think"] = config.show_thinking
    elif provider == "anthropic":
        url = _endpoint(config, "messages")
        system, converted = _to_anthropic(messages)
        payload = {
            "model": model,
            "messages": converted,
            "max_tokens": config.max_tokens,
            "temperature": config.temperature,
        }
        if system:
            payload["system"] = system
    else:  # openai | custom | omniroute | groq | gemini
        url = _endpoint(config, "chat/completions")
        payload = {
            "model": model,
            "messages": _to_openai_messages(messages),
            "temperature": config.temperature,
            "max_tokens": config.max_tokens,
            # Explicit, never left to the server default. A self-hosted gateway
            # streams unless told otherwise, and an SSE body parsed as JSON
            # fails as "Expecting value: line 1 column 1", which reads like the
            # model is unreachable rather than like a protocol mismatch.
            "stream": False,
        }

    provider_tools = _tools_for_provider(provider, tools)
    if provider_tools:
        payload["tools"] = provider_tools

    try:
        async with httpx.AsyncClient(timeout=config.timeout) as client:
            response = await client.post(url, json=payload, headers=_headers(config))
            response.raise_for_status()
            data = response.json()
    except Exception as exc:
        error = _translate_http_error(config, exc)
        config.last_error = error.message
        # A rejected credential is re-raised as its own type so the failover
        # loop stops instead of walking the whole chain. Every model on this
        # endpoint authenticates identically, so the rest would fail the same
        # way - slower, and with a less useful message at the end of it.
        if _is_credential_problem(error):
            raise _CredentialProblem(
                error.message, remedy=error.remedy, status=error.status,
            ) from exc
        raise error from exc

    if provider == "ollama":
        message = _from_ollama_message(data.get("message") or {})
        usage = {
            "prompt_tokens": data.get("prompt_eval_count"),
            "completion_tokens": data.get("eval_count"),
        }
    elif provider == "anthropic":
        message = _from_anthropic_response(data)
        usage = {
            "prompt_tokens": (data.get("usage") or {}).get("input_tokens"),
            "completion_tokens": (data.get("usage") or {}).get("output_tokens"),
        }
    else:
        choices = data.get("choices") or [{}]
        message = _from_openai_message(choices[0].get("message") or {})
        raw_usage = data.get("usage") or {}
        usage = {
            "prompt_tokens": raw_usage.get("prompt_tokens"),
            "completion_tokens": raw_usage.get("completion_tokens"),
        }

    # An HTTP 200 carrying neither content nor a tool call is a failure, and
    # returning it as a success is how a broken model reaches the operator as an
    # empty chat bubble. The usual cause is a thinking model spending its whole
    # budget on internal reasoning: finish_reason "length", completion_tokens 0.
    # Raised as an LLMError so it falls through to the next model in the chain
    # rather than ending the turn.
    if not (message.get("content") or "").strip() and not message.get("tool_calls"):
        raise LLMError(
            f"{model} returned an empty completion.",
            remedy="A thinking model may need a larger token budget.",
        )

    return message, usage


# Families known to support tool calling. Used only to mark a model in the
# picker - the agent still attempts the call, because this list ages.
_TOOL_CAPABLE_HINTS = (
    "llama3.1", "llama3.2", "llama3.3", "llama4", "qwen2.5", "qwen3", "mistral",
    "mixtral", "command-r", "firefunction", "hermes3", "gpt-4", "gpt-5", "gpt-oss",
    "o1", "o3", "o4", "claude", "gemma3", "granite3", "devstral", "magistral",
    "gemini", "grok",
)


def _likely_supports_tools(name: str) -> bool:
    lowered = (name or "").lower()
    return any(hint in lowered for hint in _TOOL_CAPABLE_HINTS)


async def list_models() -> dict:
    """Models the configured endpoint actually offers.

    This is what the Load model button calls. Typing a model name blind is how
    an operator ends up debugging a 404 mid-demo; listing what is present
    removes the guess.
    """
    config = _config
    if config.provider not in PROVIDERS:
        raise LLMError(
            "Choose a provider first.",
            remedy="Pick Ollama for a local model, or OpenAI/Anthropic with a key.",
        )
    if not config.base_url:
        raise LLMError("No base URL is set.", remedy="Enter the endpoint URL.")
    if PROVIDERS[config.provider]["needs_key"] and not config.api_key:
        raise LLMError(
            f"{PROVIDERS[config.provider]['label']} needs an API key before it will "
            f"list models.",
            remedy="Paste the key, save, then load the model list.",
        )

    url = _endpoint(config, "api/tags" if config.provider == "ollama" else "models")

    try:
        async with httpx.AsyncClient(timeout=DISCOVERY_TIMEOUT) as client:
            response = await client.get(url, headers=_headers(config))
            response.raise_for_status()
            data = response.json()
    except Exception as exc:
        error = _translate_http_error(config, exc)
        config.last_error = error.message
        raise error from exc

    models = []
    if config.provider == "ollama":
        for entry in data.get("models") or []:
            details = entry.get("details") or {}
            size_gb = (entry.get("size") or 0) / 1e9
            models.append({
                "id": entry.get("name", ""),
                "label": entry.get("name", ""),
                "detail": " · ".join(filter(None, [
                    details.get("parameter_size"),
                    details.get("quantization_level"),
                    f"{size_gb:.1f} GB" if size_gb else "",
                ])),
                # Tool calling is what the agent needs; a model without it can
                # still write narratives, so this is a hint, not a filter.
                "supports_tools": _likely_supports_tools(entry.get("name", "")),
            })
    else:
        for entry in data.get("data") or []:
            identifier = entry.get("id", "")
            models.append({
                "id": identifier,
                "label": entry.get("display_name") or identifier,
                "detail": entry.get("owned_by", "") or "",
                "supports_tools": _likely_supports_tools(identifier),
            })

    models.sort(key=lambda m: m["id"])
    if not models:
        raise LLMError(
            "The endpoint responded but offers no models.",
            remedy=(
                "Pull one first: `ollama pull llama3.1`"
                if config.provider == "ollama"
                else "Check that the key has model access."
            ),
        )
    return {"models": models, "count": len(models), "provider": config.provider}


async def test_connection() -> dict:
    """Prove the whole path works before an operator relies on it.

    Sends a real minimal completion rather than pinging the host, because a
    reachable endpoint with a missing model or a rejected key looks identical at
    the socket level and different everywhere that matters.
    """
    config = _config
    started = time.perf_counter()
    reply = await chat([
        {"role": "system", "content": "Reply with exactly: ready"},
        {"role": "user", "content": "Connection test."},
    ])
    return {
        "ok": True,
        "provider": config.provider,
        "model": config.model,
        "latency_ms": round((time.perf_counter() - started) * 1000),
        "reply": (reply.get("content") or "").strip()[:200],
        "usage": reply.get("_meta", {}).get("usage", {}),
        "supports_tools": _likely_supports_tools(config.model),
    }


# --------------------------------------------------------------------------
# Narrative and remediation
#
# Both degrade to a deterministic template when no model is configured, so every
# asset always has an explanation and the feature is never a dead end.
# --------------------------------------------------------------------------


async def _complete(prompt: str, system: str) -> Optional[str]:
    try:
        message = await chat([
            {"role": "system", "content": system},
            {"role": "user", "content": prompt},
        ])
        return (message.get("content") or "").strip() or None
    except LLMError:
        return None


async def generate_threat_narrative(asset_data: dict, regulatory_context: dict) -> dict:
    """Executive threat narrative for one asset."""
    template = _template_narrative(asset_data, regulatory_context)

    if not _config.is_configured:
        return {"narrative": template, "source": "template", "model": None}

    system = (
        "You are a cybersecurity analyst specialising in post-quantum cryptography "
        "migration. Write concise, factual executive briefings. No speculation. Cite "
        "the numbers you are given and invent none. Third person. Two paragraphs maximum."
    )
    prompt = (
        f"Write a brief executive risk narrative for this cryptographic asset:\n"
        f"Asset: {asset_data.get('name', 'Unknown')}\n"
        f"Asset class: {asset_data.get('profile_label') or asset_data.get('asset_class', 'Unknown')}\n"
        f"Algorithm: {asset_data.get('algorithm') or asset_data.get('key_exchange', 'Unknown')}\n"
        f"Verdict: {asset_data.get('verdict', 'unknown')} "
        f"({asset_data.get('vulnerability_reason', '')})\n"
        f"HNDL (confidentiality) score: {asset_data.get('h_score', 0):.3f}\n"
        f"TNFL (integrity) score: {asset_data.get('t_score', 0):.3f}\n"
        f"QIRS composite: {asset_data.get('qirs', 0):.3f}\n"
        f"Migration effort: {asset_data.get('y', 0):.1f} years\n"
        f"Slack against deadline: {asset_data.get('slack_months', 0):.0f} months\n"
        f"Sector track: {regulatory_context.get('persona', 'Unknown')}\n"
        f"Statutory deadline: {regulatory_context.get('deadline_year', 2033)}\n"
    )

    result = await _complete(prompt, system)
    if result:
        return {"narrative": result, "source": "llm", "model": _config.model}
    return {
        "narrative": template,
        "source": "template",
        "model": None,
        "note": _config.last_error or None,
    }


def _template_narrative(asset_data: dict, regulatory_context: dict) -> str:
    """Deterministic fallback. Always available, never wrong about the numbers."""
    name = asset_data.get("name", "This asset")
    algo = (
        asset_data.get("algorithm")
        or asset_data.get("key_exchange")
        or "an unspecified algorithm"
    )
    h = asset_data.get("h_score", 0)
    t = asset_data.get("t_score", 0)
    qirs = asset_data.get("qirs", 0)
    slack = asset_data.get("slack_months", 0)
    persona = regulatory_context.get("persona", "General Enterprise")
    deadline = regulatory_context.get("deadline_year", 2033)
    y = asset_data.get("y", 0)

    dominant = "confidentiality (HNDL)" if h > t else "integrity (TNFL)"
    risk_level = (
        "critical" if qirs > 0.2 else "high" if qirs > 0.1
        else "moderate" if qirs > 0.05 else "low"
    )

    parts = [
        f"{name} uses {algo}, which is vulnerable to Shor's algorithm.",
        f"Its primary exposure is on the {dominant} axis, with a composite QIRS of "
        f"{qirs:.3f} ({risk_level} risk).",
    ]
    if slack < 0:
        parts.append(
            f"Under the {persona} track this asset faces a {deadline} statutory deadline "
            f"but needs an estimated {y:.1f} years to migrate, leaving a deficit of "
            f"{abs(slack):.0f} months. Migration should already have begun."
        )
    else:
        parts.append(
            f"Under the {persona} track with a {deadline} deadline, {slack:.0f} months of "
            f"slack remain if migration begins promptly."
        )
    return " ".join(parts)


async def generate_remediation_steps(asset_data: dict) -> dict:
    """Migration guidance for one asset."""
    template = _template_remediation(asset_data)

    if not _config.is_configured:
        return {"steps": template, "source": "template", "model": None}

    system = (
        "You are a cryptographic engineering consultant. Give specific, actionable "
        "migration steps with exact commands or configuration directives where they "
        "exist. Numbered steps. No preamble."
    )
    prompt = (
        f"Provide step-by-step remediation to migrate this asset to post-quantum "
        f"cryptography:\n"
        f"Asset class: {asset_data.get('asset_class', '')}\n"
        f"Current algorithm: {asset_data.get('algorithm', '')}\n"
        f"Key size: {asset_data.get('key_size', 'unknown')}\n"
        f"Protocol: {asset_data.get('protocol', 'unknown')}\n"
        f"Source: {asset_data.get('source_location', 'unknown')}\n"
        f"Recommended replacement: "
        f"{asset_data.get('pqc_replacement') or 'ML-KEM-768 / ML-DSA-65'}\n"
    )

    result = await _complete(prompt, system)
    if result:
        return {"steps": result, "source": "llm", "model": _config.model}
    return {
        "steps": template,
        "source": "template",
        "model": None,
        "note": _config.last_error or None,
    }


def _template_remediation(asset_data: dict) -> str:
    """Template-based remediation guidance, keyed by asset class."""
    asset_class = asset_data.get("asset_class") or ""
    algo = asset_data.get("algorithm") or "the current algorithm"

    guides = {
        "tls-server": (
            "1. Verify OpenSSL is 3.5 or later (ships ML-KEM and ML-DSA natively).\n"
            "2. Add a hybrid key-exchange group: X25519MLKEM768.\n"
            "3. Nginx: ssl_ecdh_curve X25519MLKEM768:X25519:prime256v1;\n"
            "4. Apache: SSLOpenSSLConfCmd Groups X25519MLKEM768:x25519\n"
            "5. Test: openssl s_client -groups X25519MLKEM768 -connect <host>:443\n"
            "6. Watch handshake failure rates for older clients.\n"
            "7. Rescan with VERA to confirm the score drop."
        ),
        "tls-kex": (
            "1. This is a key-exchange component; it migrates with its server.\n"
            "2. Enable X25519MLKEM768 on the server.\n"
            "3. Confirm client libraries negotiate ML-KEM.\n"
            "4. Test interoperability before rolling out widely."
        ),
        "root-ca": (
            "1. Treat this as a multi-year CA re-issuance programme, not a config change.\n"
            "2. Generate a new root using ML-DSA-65 (FIPS 204).\n"
            "3. Cross-sign an intermediate to keep existing chains valid.\n"
            "4. Distribute the new root to every trust store.\n"
            "5. Re-issue all subordinate CAs under the new root.\n"
            "6. Publish a sunset date for the classical root."
        ),
        "code-signing": (
            "1. Generate a new code-signing key pair using ML-DSA-65.\n"
            "2. Dual-sign during the transition (classical + PQC).\n"
            "3. Update every verifier to accept ML-DSA signatures.\n"
            "4. Distribute the new public key to all verifying parties.\n"
            "5. Only then retire the classical key."
        ),
        "firmware": (
            "1. Firmware verification keys are often burned in; confirm what is updatable.\n"
            "2. Where a key can be rotated, move to ML-DSA-65 or SLH-DSA.\n"
            "3. Where it cannot, plan hardware replacement against the device's service life.\n"
            "4. Dual-sign images during the fleet transition."
        ),
    }

    default = (
        f"1. Confirm the algorithm in use ({algo}) and where it is configured.\n"
        "2. Select the NIST replacement: ML-KEM for key establishment, ML-DSA for signatures.\n"
        "3. Check library and framework support for that algorithm.\n"
        "4. Deploy hybrid first, so a failure falls back to a working classical path.\n"
        "5. Test in staging, including interoperability with older peers.\n"
        "6. Rescan with VERA to confirm the score drop."
    )

    for key, guide in guides.items():
        if asset_class.startswith(key.split("-")[0]):
            return guide
    return default
