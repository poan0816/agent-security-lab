"""Shared pytest fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from security_lab.app import app
from security_lab.policy import ConfirmedAction, PolicyGate, TrustedContext
from security_lab.sandbox_tools import SandboxState

PROJECT_ROOT = Path(__file__).resolve().parents[1]
CASES_DIR = PROJECT_ROOT / "cases"

DEMO_ALICE_SESSION = "alice-summarize"
DEMO_ALICE_CONFIRMED_DELETE_SESSION = "alice-delete-own-note01"


@pytest.fixture()
def sandbox() -> SandboxState:
    """A fresh in-memory sandbox for a single test."""

    return SandboxState()


@pytest.fixture()
def gate() -> PolicyGate:
    return PolicyGate()


@pytest.fixture()
def alice_context() -> TrustedContext:
    return TrustedContext(actor_id="alice")


@pytest.fixture()
def alice_delete_context() -> TrustedContext:
    return TrustedContext(
        actor_id="alice",
        confirmed_actions=(ConfirmedAction("delete_note", "note_01"),),
    )


@pytest.fixture()
def client() -> TestClient:
    return TestClient(app)