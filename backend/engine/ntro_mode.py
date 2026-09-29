"""NTRO mode: the defaults for an air-gapped CII assessment, and the status line that states them.

Three facts, shown together on Settings and in the agent panel:

1. **Read-only agent.** Write tools are removed from the model's schema, so it
   is never told it could migrate anything.
2. **Local model.** Ollama `qwen3:1.7b` on this machine, so no estate data is
   sent to a model provider. Cloud providers stay selectable in Settings, and
   are labelled as sending data off the machine.
3. **Offline.** `VERA_OFFLINE=1` limits outbound connections to this machine
   and to scan targets an operator named.

`apply_defaults` fills these only where the operator left a variable unset: a
value from the shell, run.ps1 or `.env` always wins. A cloud API key on its own
already names its provider (engine.llm_bridge.identify_key), so the local model
default is not applied over one.

`status` reports what is actually in force, not what was requested. The offline
fact reads the socket guard's own state, so the line cannot say "offline" while
nothing is enforcing it.
"""

from __future__ import annotations

import os
from typing import MutableMapping
from urllib.parse import urlparse

LOCAL_MODEL = {"VERA_LLM_PROVIDER": "ollama", "VERA_LLM_MODEL": "qwen3:1.7b"}
ALWAYS = {"VERA_AGENT_MODE": "read_only", "VERA_LLM_THINKING": "0", "VERA_OFFLINE": "1"}
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}


def apply_defaults(environ: MutableMapping[str, str] | None = None) -> list[str]:
    """Set every NTRO default the operator left unset. Returns the variables it set."""
    env = os.environ if environ is None else environ
    filled = []
    defaults = dict(ALWAYS)
    if not env.get("VERA_LLM_PROVIDER") and not env.get("VERA_LLM_API_KEY"):
        defaults.update(LOCAL_MODEL)
    for key, value in defaults.items():
        if not env.get(key):
            env[key] = value
            filled.append(key)
    return filled


def _is_local(provider: str, base_url: str) -> bool:
    if provider == "ollama":
        host = urlparse(base_url or "http://localhost:11434").hostname or ""
        return host in LOCAL_HOSTS
    return (urlparse(base_url or "").hostname or "") in LOCAL_HOSTS


def status() -> dict:
    """The three NTRO facts as they stand right now, and whether all three hold."""
    from engine import offline
    from engine.agent_control import get_control
    from engine.llm_bridge import get_config

    mode = get_control().settings.mode
    config = get_config()
    local = bool(config.provider) and _is_local(config.provider, config.base_url)
    guard = offline.status()
    facts = [
        {"key": "agent", "ok": mode == "read_only", "label": f"Agent: {mode.replace('_', '-')}",
         "detail": "Write tools are not in the model's schema." if mode == "read_only"
         else "The agent can propose or apply changes."},
        {"key": "model", "ok": local,
         "label": f"Model: {config.model or 'none'} ({'local' if local else 'leaves this machine' if config.provider else 'not configured'})",
         "detail": "Prompts and tool results stay on this machine." if local
         else "Estate data in prompts is sent to the provider." if config.provider else "No model is configured."},
        {"key": "offline", "ok": guard["enforced"],
         "label": "Offline: enforced" if guard["enforced"] else "Offline: off",
         "detail": guard["detail"]},
    ]
    return {"ntro_mode": all(f["ok"] for f in facts), "facts": facts,
            "line": " · ".join(f["label"] for f in facts)}
