"""Streaming agent turns over Server-Sent Events.

WHY THIS EXISTS
---------------
`POST /api/chat` returns nothing until the whole turn is finished. Against a
gateway routing to a rate-limited free model that can be most of the 180s turn
budget, and during that time the dashboard shows a spinner — even though the
agent may have called three tools and asked to navigate somewhere twenty
seconds ago. The operator cannot tell a working agent from a hung one, and the
navigation the agent requested arrives long after it was useful.

`POST /api/chat/stream` emits the same turn as it happens:

    event: tool_call     the agent is about to run a tool
    event: tool_result   what the tool returned  (the UI acts on this NOW)
    event: message       assistant prose or reasoning
    event: done          the full payload `/api/chat` would have returned
    event: error         the turn could not continue

Both endpoints drive `engine.agent.process_chat_events`, so streaming and
non-streaming execute identical logic. This is a *transport*, not a second
implementation — there is no path here for the two to disagree.

This lives in its own module rather than in `api/routes.py` purely to keep a
very large file from growing another concern.
"""

from __future__ import annotations

import asyncio
import json
import logging

from fastapi import APIRouter
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter()


class StreamChatRequest(BaseModel):
    """A full transcript, exactly as `/api/chat` takes it.

    The dashboard owns the conversation and replays it each turn, so the server
    holds no session and a reload cannot desynchronise the two.
    """

    messages: list[dict] = Field(default_factory=list)


def _sse(event: str, data: dict) -> str:
    """One SSE frame.

    `default=str` because tool results carry engine objects that are not all
    JSON-native, and losing a frame to a serialisation error would strand the
    client mid-turn with no way to know why.
    """
    return f"event: {event}\ndata: {json.dumps(data, default=str)}\n\n"


@router.post("/chat/stream")
async def chat_stream(request: StreamChatRequest):
    """Run one agent turn, emitting each step as it happens."""
    from engine.agent import process_chat_events

    async def events():
        # Tells any intermediary not to buffer, and gives the client something
        # immediately so a slow first model call still looks alive.
        yield _sse("open", {"status": "running"})
        try:
            async for event in process_chat_events(request.messages):
                kind = event.get("type", "message")
                payload = {k: v for k, v in event.items() if k != "type"}
                yield _sse(kind, payload)
        except asyncio.CancelledError:
            # The operator navigated away or pressed Stop. Not an error, and
            # nothing the agent had started is applied - writes go through the
            # control plane's approval gate, not through this stream.
            logger.info("Agent stream cancelled by the client.")
            raise
        except Exception as exc:  # noqa: BLE001 - a dead stream must say why
            logger.exception("Agent stream failed")
            yield _sse("error", {
                "error": f"{type(exc).__name__}: {exc}",
                "remedy": "The turn stopped. Nothing it had started was applied.",
            })

    return StreamingResponse(
        events(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "Connection": "keep-alive",
            # nginx and friends buffer SSE by default, which reintroduces
            # exactly the delay this endpoint exists to remove.
            "X-Accel-Buffering": "no",
        },
    )
