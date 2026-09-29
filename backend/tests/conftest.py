"""Shared fixtures. Keeps the suite from touching operator state on disk.

The model-health registry is a process singleton that saves to
``backend/data/model_health.json``. Probe results in that file cost real
quota to obtain. Any test that drives ``AgentPool.call`` or the LLM bridge
would otherwise rewrite them with synthetic counters. Isolate every test
onto a throwaway registry so the operator's file survives the suite.
"""

from __future__ import annotations

import os

import pytest

from engine.core.model_health import ModelRegistry


# Sign-in off (the local-operator path) for the whole run, set at import so that
# module-scoped fixtures, which are built before any autouse fixture, see it too.
# tests/test_auth.py turns it on per test.
os.environ["VERA_AUTH"] = "0"
# Scans, projects and saved conversations go to a throwaway database, never the operator's backend/data/vera.db.
# Set at import, before store.py reads it.
os.environ["VERA_DB_PATH"] = str(__import__("pathlib").Path(__import__("tempfile").mkdtemp()) / "vera-tests.db")


@pytest.fixture(autouse=True)
def _isolate_users(tmp_path_factory, monkeypatch):
    """Each test gets its own user store, never the operator's auth.db."""
    from engine import auth

    monkeypatch.setenv("VERA_AUTH_DB", str(tmp_path_factory.mktemp("auth") / "auth.db"))
    monkeypatch.setattr(auth, "_store", None)


@pytest.fixture(autouse=True)
def _isolate_audit_chain(tmp_path_factory, monkeypatch):
    """Each test appends to its own chain, never the operator's audit log.

    The chain is created lazily on first append, in a directory of its own, so
    tests that never audit anything pay nothing and never see the file.
    """
    from engine import audit_chain

    monkeypatch.setattr(audit_chain, "_default", None)
    monkeypatch.setenv("VERA_AUDIT_DB", str(tmp_path_factory.mktemp("audit") / "audit_chain.db"))


@pytest.fixture(autouse=True)
def _isolate_model_health(tmp_path, monkeypatch):
    isolated = ModelRegistry(tmp_path / "model_health.json")
    monkeypatch.setattr("engine.core.model_health.REGISTRY", isolated)
    monkeypatch.setattr("engine.core.agents._MODELS", isolated)
    monkeypatch.setattr("engine.llm_bridge._MODELS", isolated)
    return isolated
