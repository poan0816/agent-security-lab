"""Pydantic request/response contracts for the HTTP API and the evaluator.

Trust boundary note
-------------------
``RunRequest`` deliberately contains **only untrusted input fields**:

* ``user_request``: the trusted user's own instruction (still treated as data
  at the authorization layer, never as an authorization token);
* ``untrusted_document``: external material under attacker control.

Identity (``actor_id``) and authorization (``confirmed_actions``) are *not*
part of the request model. They are provided by the server-side
``TrustedContext`` (a local demo session store in this closed lab). Because the
model forbids extra fields, a client that posts ``actor_id`` or
``confirmed_actions`` in the body gets a hard 422 instead of an implicit
privilege upgrade.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

# Hard input limits. They are enforced by Pydantic on the HTTP path and by the
# evaluator before a case is executed, so an oversized payload never reaches the
# policy gate or the sandbox.
MAX_USER_REQUEST_CHARS = 2_000
MAX_DOCUMENT_CHARS = 8_000

CaseStatus = Literal["completed", "invalid_request", "error"]


class RunRequest(BaseModel):
    """Untrusted input fields only (see module docstring)."""

    model_config = ConfigDict(extra="forbid")

    user_request: str = Field(min_length=1, max_length=MAX_USER_REQUEST_CHARS)
    untrusted_document: str = Field(min_length=1, max_length=MAX_DOCUMENT_CHARS)


class ProposedAction(BaseModel):
    """An action the (mock) agent suggests. Nothing has happened yet."""

    model_config = ConfigDict(extra="forbid")

    tool: str = Field(min_length=1, max_length=64)
    arguments: dict[str, Any] = Field(default_factory=dict)


class BlockedAction(ProposedAction):
    """A proposed action rejected by the server-side policy gate."""

    reason: str
    detail: str | None = None


class ExecutedAction(ProposedAction):
    """A proposed action that passed the gate and was simulated in memory."""

    result: dict[str, Any] = Field(default_factory=dict)


class RunResponse(BaseModel):
    """Auditable outcome of one evaluated request.

    ``case_status`` only reports whether the *execution pipeline* completed. It
    says nothing about safety; safety is judged separately by the evaluator
    against each case's pre-registered expectations.
    """

    case_status: CaseStatus
    answer: str
    proposed_actions: list[ProposedAction] = Field(default_factory=list)
    blocked_actions: list[BlockedAction] = Field(default_factory=list)
    executed_actions: list[ExecutedAction] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


class HealthResponse(BaseModel):
    status: str
    service: str
    version: str
    mode: str