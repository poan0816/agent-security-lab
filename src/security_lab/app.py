"""FastAPI demo service for the Security Lab (closed local lab only).

Security-relevant design choices:

* the request body carries only untrusted fields (``user_request``,
  ``untrusted_document``);
* identity and confirmations come from a server-side demo session store keyed by
  the ``X-Demo-Session`` header. That header is a *stand-in* for authentication,
  not authentication. It exists so the demo can be exercised with ``curl`` /
  Swagger UI without pretending to implement production auth;
* extra body fields (e.g. ``actor_id``, ``confirmed_actions``) are rejected with
  422, so a caller cannot self-authorize;
* this service must not be exposed publicly.

Run it with::

    python -m uvicorn security_lab.app:app --host 127.0.0.1 --port 8000
"""

from __future__ import annotations

from fastapi import Depends, FastAPI, Header, HTTPException

from . import __version__
from .mock_agent import MockAgent
from .policy import ConfirmedAction, TrustedContext
from .runtime import execute_request
from .schemas import HealthResponse, RunRequest, RunResponse

MODE = "mock"

#: Server-side demo sessions. Hard-coded, synthetic, fixed. A client may select
#: a session id but cannot alter its actor or its confirmations.
DEMO_SESSIONS: dict[str, TrustedContext] = {
    "alice-summarize": TrustedContext(
        actor_id="alice",
        confirmed_actions=(),
        source="demo_session:alice-summarize",
    ),
    "alice-delete-own-note01": TrustedContext(
        actor_id="alice",
        confirmed_actions=(ConfirmedAction("delete_note", "note_01"),),
        source="demo_session:alice-delete-own-note01",
    ),
    "alice-send-to-ops": TrustedContext(
        actor_id="alice",
        confirmed_actions=(ConfirmedAction("send_message", "ops@example.test"),),
        source="demo_session:alice-send-to-ops",
    ),
    "bob-summarize": TrustedContext(
        actor_id="bob",
        confirmed_actions=(),
        source="demo_session:bob-summarize",
    ),
}

app = FastAPI(
    title="Security Lab (mock)",
    version=__version__,
    description=(
        "Closed local demo of a server-side Agent tool policy gate. Synthetic "
        "in-memory data only; no network side effects. Not for public "
        "deployment, and the demo session header is not real authentication."
    ),
)


def get_trusted_context(
    x_demo_session: str = Header(
        ...,
        alias="X-Demo-Session",
        description=(
            "Local demo session id. Stand-in for authentication, not real auth."
        ),
    ),
) -> TrustedContext:
    context = DEMO_SESSIONS.get(x_demo_session)
    if context is None:
        raise HTTPException(
            status_code=401,
            detail={
                "error": "unknown_demo_session",
                "valid_sessions": sorted(DEMO_SESSIONS),
            },
        )
    return context


@app.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    return HealthResponse(
        status="ok",
        service="agent-security-lab",
        version=__version__,
        mode=MODE,
    )


@app.get("/v1/demo/sessions")
def list_demo_sessions() -> dict[str, object]:
    """Describe the fixed demo sessions so the local service is usable.

    This endpoint is part of the closed demo only. It lists synthetic identities
    and pre-registered confirmations; it grants nothing by itself.
    """

    return {
        "warning": (
            "Closed local demo. Session selection stands in for authentication "
            "and must not be treated as a production authorization mechanism."
        ),
        "mode": MODE,
        "sessions": [
            {
                "session_id": session_id,
                "actor_id": context.actor_id,
                "confirmed_actions": [
                    {"action": item.action, "resource": item.resource}
                    for item in context.confirmed_actions
                ],
            }
            for session_id, context in sorted(DEMO_SESSIONS.items())
        ],
    }


@app.post("/v1/run", response_model=RunResponse)
def run(
    request: RunRequest,
    trusted_context: TrustedContext = Depends(get_trusted_context),
) -> RunResponse:
    """Run one request through the mock agent and the policy gate."""

    outcome = execute_request(
        request=request,
        trusted_context=trusted_context,
        agent=MockAgent(),
    )
    return outcome.response