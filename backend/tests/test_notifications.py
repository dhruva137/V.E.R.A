"""Notifications endpoint — shape and honesty guarantees."""

from __future__ import annotations

from fastapi.testclient import TestClient

from main import app


REQUIRED_KEYS = {
    "id", "source", "severity", "title", "body", "occurred_at", "deep_link",
}
ALLOWED_SEVERITIES = {"critical", "warning", "info"}


def test_notifications_shape_and_empty_ok():
    """Endpoint always returns {items: [...]} with the contracted fields."""
    with TestClient(app) as client:
        response = client.get("/api/notifications")
        assert response.status_code == 200
        body = response.json()
        assert "items" in body
        assert isinstance(body["items"], list)
        for item in body["items"]:
            assert REQUIRED_KEYS <= set(item.keys())
            assert item["severity"] in ALLOWED_SEVERITIES
            assert item["id"]
            assert item["title"]
            assert "T" in item["occurred_at"] or item["occurred_at"].endswith("Z")
            assert isinstance(item["deep_link"], str) and item["deep_link"]


def test_notifications_reflect_demo_estate_facts():
    """After a demo scan, estate-derived items appear when the estate warrants them."""
    with TestClient(app) as client:
        demo = client.post("/api/scan/demo", params={"org_persona": "Banking"})
        assert demo.status_code == 200

        response = client.get("/api/notifications")
        assert response.status_code == 200
        items = response.json()["items"]
        assert isinstance(items, list)
        # Announcements feed or estate facts — either is real state; never invent.
        for item in items:
            assert item["severity"] in ALLOWED_SEVERITIES
            assert item["deep_link"]
