"""Streaming agent turns, and the agent's ability to drive the dashboard.

Two things are asserted here that matter more than they look:

* The streaming and non-streaming endpoints must run the SAME logic. They share
  `process_chat_events`, and a regression that forked them would let the two
  disagree about what the agent did — which is the one thing this product
  cannot afford, since the whole argument is that the chat and the dashboard
  cannot contradict each other.
* `open_page` must refuse an unknown page rather than inventing one. The agent
  drives the operator's screen with it; a silent no-op or a guessed page is a
  worse failure than a stated refusal.
"""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from engine import agent, llm_bridge
from main import app


@pytest.fixture(autouse=True)
def no_model_configured():
    """Pin the turn to its deterministic, model-free path.

    These tests assert the SHAPE of a turn — that it opens, that it always
    terminates, that streaming and blocking agree. None of that should depend
    on whether some earlier test in the session happened to leave a provider
    configured, and a real network call here would make the suite slow and
    flaky for no added coverage.
    """
    saved = dict(llm_bridge._config.__dict__)
    llm_bridge._config.update(provider="", model="", base_url="", api_key="")
    yield
    llm_bridge._config.__dict__.update(saved)


@pytest.fixture
def client():
    return TestClient(app)


def _frames(raw: str) -> list[tuple[str, dict]]:
    """Parse an SSE body into (event, data) pairs."""
    out = []
    for block in raw.split("\n\n"):
        event, data = None, None
        for line in block.split("\n"):
            if line.startswith("event:"):
                event = line[6:].strip()
            elif line.startswith("data:"):
                try:
                    data = json.loads(line[5:].strip())
                except json.JSONDecodeError:
                    data = None
        if event:
            out.append((event, data))
    return out


# ---------------------------------------------------------------------------
# The transport
# ---------------------------------------------------------------------------

def test_stream_endpoint_emits_sse(client):
    response = client.post("/api/chat/stream",
                           json={"messages": [{"role": "user", "content": "hi"}]})
    assert response.status_code == 200
    assert "text/event-stream" in response.headers["content-type"]
    # Buffering here would reintroduce exactly the delay this endpoint removes.
    assert response.headers.get("x-accel-buffering") == "no"


def test_stream_opens_immediately_and_always_finishes(client):
    """A turn must announce itself and must end with a terminal frame, even
    with no model configured — a client that never sees `done` hangs."""
    response = client.post("/api/chat/stream",
                           json={"messages": [{"role": "user", "content": "hi"}]})
    events = [name for name, _ in _frames(response.text)]
    assert events[0] == "open"
    assert "done" in events


def test_done_payload_matches_the_blocking_endpoint(client):
    """Same turn, same shape. If these drift the two surfaces can disagree."""
    body = {"messages": [{"role": "user", "content": "hi"}]}
    blocking = client.post("/api/chat", json=body).json()

    streamed = None
    for name, data in _frames(client.post("/api/chat/stream", json=body).text):
        if name == "done":
            streamed = data["payload"]
    assert streamed is not None
    assert set(streamed) == set(blocking)
    assert streamed["messages"] == blocking["messages"]


@pytest.mark.asyncio
async def test_process_chat_drains_the_same_generator():
    """`process_chat` is a wrapper, not a second implementation."""
    messages = [{"role": "user", "content": "hi"}]
    via_wrapper = await agent.process_chat(messages)

    payload = None
    async for event in agent.process_chat_events(messages):
        if event["type"] == "done":
            payload = event["payload"]
    assert payload is not None
    assert set(payload) == set(via_wrapper)


# ---------------------------------------------------------------------------
# open_page — the agent driving the dashboard
# ---------------------------------------------------------------------------

def test_open_page_returns_a_navigate_directive():
    result = agent.execute_tool("open_page", {"page": "blast_radius"})
    assert result["action"] == "navigate"
    # The directive carries the dashboard's own route, so it lands where a click would.
    assert result["page"] == "dependencies" and result["route"] == "/risk/dependencies"


@pytest.mark.parametrize("spoken,expected", [
    ("blast radius", "/risk/dependencies"),
    ("dashboard", "/overview"),
    ("Overview", "/overview"),
    ("roadmap", "/plan/timeline"),
    ("sensors", "/scan"),
    ("CERT-In", "/evidence/certin"),
])
def test_open_page_accepts_the_words_a_person_would_use(spoken, expected):
    """A model asked to "show the blast radius" should not have to know the
    internal route name."""
    assert agent.execute_tool("open_page", {"page": spoken})["route"] == expected


def test_open_page_refuses_an_unknown_page():
    result = agent.execute_tool("open_page", {"page": "nonsense"})
    assert "error" in result
    assert "action" not in result
    # It must say what it *can* open rather than leaving the model guessing.
    assert result["available_pages"]


def test_open_page_refuses_an_unknown_focus_asset():
    result = agent.execute_tool("open_page",
                                {"page": "inventory", "focus_asset_id": "no-such"})
    assert "error" in result
    assert "remedy" in result


def test_open_page_is_declared_and_implemented():
    names = {t["function"]["name"] for t in agent.TOOLS_SCHEMA}
    assert "open_page" in names
    assert "open_page" in agent.TOOL_IMPLEMENTATIONS
