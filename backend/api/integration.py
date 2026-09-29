"""The integration surface: VERA as a tool another AI can call.

WHY THIS EXISTS
---------------
The agent page proves the estate can be reasoned about in natural language, but
it only proves it for *our* agent. An enterprise already running an assistant
does not want a fourteenth dashboard - it wants its own assistant to be able to
answer "what should we migrate first" without a human opening this app.

So the same fifteen tools the built-in agent uses are exposed as a plain HTTP
surface any model can call. Nothing here is a second implementation: these
endpoints dispatch into `engine.agent.execute_tool`, which routes through the
same control plane, honours the same four limits and writes the same audit log.
A tool invoked from outside is indistinguishable, downstream, from one the
built-in agent invoked - which is the only way the governance claim stays true.

WHY IT IS VERSIONED AND SEPARATE FROM /api
------------------------------------------
`/api/*` is this dashboard's private backend; its shapes change whenever the UI
needs them to. `/api/v1/*` is a contract someone else's code depends on. Mixing
the two would mean a UI refactor silently breaking an integration.

AUTHENTICATION
--------------
`/api/*` is unauthenticated by design - the demo says so on its own login page.
This surface is not, because it carries a write path. Every route here requires
a key issued in Settings, and the write tool additionally requires a key that
was issued with the `write` scope.
"""

from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, Body, Depends, Header, HTTPException, Request

from engine.api_keys import APIKey, get_store

router = APIRouter(prefix="/v1", tags=["integration"])


# --------------------------------------------------------------------------
# Auth
# --------------------------------------------------------------------------


def _presented_key(
    authorization: Optional[str] = Header(default=None),
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
) -> Optional[str]:
    """Accept either `Authorization: Bearer …` or `X-API-Key: …`.

    Both are common enough that supporting only one guarantees a support
    conversation on the first integration.
    """
    if authorization and authorization.lower().startswith("bearer "):
        return authorization[7:].strip()
    return x_api_key.strip() if x_api_key else None


def require_key(raw: Optional[str] = Depends(_presented_key)) -> APIKey:
    record = get_store().verify(raw)
    if record is None:
        # 401 with a WWW-Authenticate hint, not 403: the caller may simply not
        # have presented anything yet.
        raise HTTPException(
            status_code=401,
            detail=(
                "A valid API key is required. Create one in Settings → API access, "
                "then send it as 'Authorization: Bearer <key>'."
            ),
            headers={"WWW-Authenticate": "Bearer"},
        )
    return record


def require_write(key: APIKey = Depends(require_key)) -> APIKey:
    if "write" not in key.scopes:
        raise HTTPException(
            status_code=403,
            detail=(
                f"Key '{key.name}' is read-only. Issue a key with the write scope to "
                "propose changes to the estate."
            ),
        )
    return key


# --------------------------------------------------------------------------
# Discovery
# --------------------------------------------------------------------------


@router.get("/manifest")
def manifest(request: Request) -> dict:
    """What this service is and how to drive it.

    Deliberately unauthenticated: a caller needs to be able to discover how to
    authenticate before it has authenticated. Nothing here is estate data.
    """
    from engine.agent import tool_catalogue

    base = str(request.base_url).rstrip("/")
    catalogue = tool_catalogue()

    return {
        "name": "VERA",
        "version": "1.0",
        "description": (
            "Post-quantum cryptographic risk scoring and migration planning. Scores an "
            "estate on two independent axes - harvest-now-decrypt-later confidentiality "
            "risk and trust-now-forge-later integrity risk - and reports what to migrate "
            "first, whether each asset can meet its statutory deadline, what expires "
            "before that deadline arrives, and what is actually changeable today."
        ),
        "auth": {
            "type": "bearer",
            "header": "Authorization: Bearer <key>",
            "alternative_header": "X-API-Key: <key>",
            "issue_keys_at": "Settings → API access",
        },
        "endpoints": {
            "tools": f"{base}/api/v1/tools",
            "invoke": f"{base}/api/v1/tools/{{tool_name}}",
            "openapi": f"{base}/openapi.json",
            "docs": f"{base}/docs",
        },
        "tool_count": len(catalogue),
        "write_tools": [t["name"] for t in catalogue if t["mutating"]],
        "governance": (
            "Every call is routed through the same control plane as the built-in agent: "
            "approval mode, a token-bucket rate limit, a blast-radius cap, and an "
            "immutable audit log. A refusal is recorded as explicitly as an allow."
        ),
        "grounding": (
            "Every figure returned is computed by the scoring engine. No endpoint here "
            "invokes a language model, so no returned number was generated by one."
        ),
    }


@router.get("/tools")
def list_tools(key: APIKey = Depends(require_key)) -> dict:
    """The full tool schemas, in the shape function-calling models expect.

    Returned verbatim from the same TOOLS_SCHEMA the built-in agent is given, so
    an external model sees exactly the tools ours does - no drift between the
    two, because there is only one definition.
    """
    from engine.agent import TOOLS_SCHEMA, tool_catalogue

    availability = {t["name"]: t for t in tool_catalogue()}

    tools = []
    for schema in TOOLS_SCHEMA:
        name = schema["function"]["name"]
        meta = availability.get(name, {})
        tools.append({
            **schema,
            "vera": {
                "mutating": meta.get("mutating", False),
                "available_in_current_mode": meta.get("available", True),
                # A read-only key cannot reach a write tool regardless of the
                # control plane's mode, so say which of the two would stop it.
                "permitted_by_this_key": (
                    "write" in key.scopes if meta.get("mutating") else True
                ),
            },
        })

    return {
        "tools": tools,
        "count": len(tools),
        "format": "openai.function",
        "note": (
            "Pass these straight to a function-calling model. Invoke a chosen tool at "
            "POST /api/v1/tools/{name} with the arguments object as the request body."
        ),
    }


# --------------------------------------------------------------------------
# Invocation
# --------------------------------------------------------------------------


@router.post("/tools/{tool_name}")
def invoke_tool(
    tool_name: str,
    arguments: dict[str, Any] = Body(default_factory=dict),
    key: APIKey = Depends(require_key),
) -> dict:
    """Run one tool and return its result.

    Dispatches into the same `execute_tool` the built-in agent calls, so the
    control plane, the limits and the audit trail all apply identically. The
    write scope is enforced here rather than inside the engine because scope is
    a property of the caller, not of the estate.
    """
    from engine.agent import TOOL_IMPLEMENTATIONS, execute_tool
    from engine.agent_control import WRITE_TOOLS

    if tool_name not in TOOL_IMPLEMENTATIONS:
        raise HTTPException(
            status_code=404,
            detail=(
                f"No tool named '{tool_name}'. "
                f"Available: {', '.join(sorted(TOOL_IMPLEMENTATIONS))}"
            ),
        )

    if tool_name in WRITE_TOOLS and "write" not in key.scopes:
        raise HTTPException(
            status_code=403,
            detail=(
                f"'{tool_name}' changes the estate and key '{key.name}' is read-only. "
                "Issue a key with the write scope."
            ),
        )

    result = execute_tool(tool_name, arguments or {})

    # A refusal is a successful HTTP call that returns a refusal - not a 500.
    # The caller asked a legitimate question and got a governed answer, and
    # flattening that into an error would lose the reason.
    return {
        "tool": tool_name,
        "result": result,
        "refused": bool(result.get("refused_by")),
        "key": {"name": key.name, "scopes": key.scopes},
    }


@router.get("/status")
def integration_status(key: APIKey = Depends(require_key)) -> dict:
    """Whether there is anything to talk about yet, and under what limits."""
    from api.routes import state
    from engine.agent_control import get_control

    control = get_control()
    assets = state.assets or []

    return {
        "estate_loaded": bool(assets),
        "asset_count": len(assets),
        "control": {
            "mode": control.settings.mode,
            "max_tool_calls_per_minute": control.settings.max_tool_calls_per_minute,
            "max_assets_per_action": control.settings.max_assets_per_action,
        },
        "key": {"name": key.name, "scopes": key.scopes, "call_count": key.call_count},
    }
