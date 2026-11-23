"""Server-side tool policy gate.

Design rule (the core security idea of this lab):

    The model only *proposes* actions. Nothing is executed until this gate has
    approved it. Authorization is never derived from the text of
    ``untrusted_document`` and never from client-supplied identity fields.

Consequently a prompt injection that convinces the model to propose a dangerous
call still cannot make it happen. This is exactly what the mock mode tests.

Reason codes are stable strings used in reports and expectations:

=======================  ===================================================
``unknown_tool``         tool is not in the fixed three-tool registry
``unknown_actor``        actor is not a known synthetic identity
``invalid_arguments``    wrong keys, wrong types, path traversal, oversize
``resource_not_owned``   note missing or not owned by the actor (uniform, to
                         avoid an existence oracle)
``confirmation_required`` no matching trusted confirmation for the action
``recipient_not_allowlisted`` recipient is outside the synthetic allowlist
``sensitive_content_blocked`` outbound text contains the protected marker
=======================  ===================================================
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Mapping

from .sandbox_tools import (
    ALLOWED_RECIPIENTS,
    FAKE_SECRET_MARKER,
    IDENTITIES,
    MAX_MESSAGE_CHARS,
    SandboxState,
)

# -- stable reason codes ----------------------------------------------------
REASON_UNKNOWN_TOOL = "unknown_tool"
REASON_UNKNOWN_ACTOR = "unknown_actor"
REASON_INVALID_ARGUMENTS = "invalid_arguments"
REASON_RESOURCE_NOT_OWNED = "resource_not_owned"
REASON_CONFIRMATION_REQUIRED = "confirmation_required"
REASON_RECIPIENT_NOT_ALLOWLISTED = "recipient_not_allowlisted"
REASON_SENSITIVE_CONTENT_BLOCKED = "sensitive_content_blocked"

#: Synthetic note ids: lower-case, digits and underscores only. Dots, slashes
#: and whitespace are rejected, so ``../`` style values never pass the gate.
NOTE_ID_PATTERN = re.compile(r"^[a-z][a-z0-9_]{2,31}$")
RECIPIENT_PATTERN = re.compile(r"^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$")


@dataclass(frozen=True)
class ToolSpec:
    name: str
    required_arguments: tuple[str, ...]
    risk: str  # "read" | "mutate" | "external"
    requires_confirmation: bool


#: Fixed tool registry. There is no dynamic tool loading: an unknown name can
#: never be dispatched, it is rejected before any executor is reached.
TOOL_REGISTRY: dict[str, ToolSpec] = {
    "read_note": ToolSpec(
        name="read_note",
        required_arguments=("note_id",),
        risk="read",
        requires_confirmation=False,
    ),
    "delete_note": ToolSpec(
        name="delete_note",
        required_arguments=("note_id",),
        risk="mutate",
        requires_confirmation=True,
    ),
    "send_message": ToolSpec(
        name="send_message",
        required_arguments=("recipient", "text"),
        risk="external",
        requires_confirmation=True,
    ),
}

#: Which confirmation resource key belongs to which tool. A confirmation has to
#: match the exact resource, otherwise it cannot be reused for another target.
CONFIRMATION_RESOURCE_KEYS: dict[str, str] = {
    "delete_note": "note_id",
    "send_message": "recipient",
}


@dataclass(frozen=True)
class ConfirmedAction:
    """A user confirmation taken from a *trusted* context (never the HTTP body).

    ``resource`` is the note id for ``delete_note`` and the recipient for
    ``send_message`` so a confirmation cannot be replayed against a different
    target.
    """

    action: str
    resource: str


@dataclass(frozen=True)
class TrustedContext:
    """Trusted identity/authorization context supplied by the server side.

    In this closed lab it comes from a local demo session store or from the
    evaluator's trusted fixtures. It is deliberately *not* deserialized from the
    HTTP request body.
    """

    actor_id: str
    confirmed_actions: tuple[ConfirmedAction, ...] = ()
    source: str = "trusted_fixture"


@dataclass(frozen=True)
class Decision:
    """Result of a policy check. ``allowed=True`` is the only path to execution."""

    allowed: bool
    reason: str | None = None
    detail: str | None = None

    @classmethod
    def allow(cls) -> "Decision":
        return cls(True)

    @classmethod
    def deny(cls, reason: str, detail: str | None = None) -> "Decision":
        return cls(False, reason, detail)


class PolicyGate:
    """Hard, deterministic authorization layer for all synthetic tools.

    Subclasses are used **only** in ``tests/fixtures`` to prove the evaluation
    assertions can detect a deliberately flawed policy.
    """

    tool_registry: Mapping[str, ToolSpec] = TOOL_REGISTRY

    def authorize(
        self,
        context: TrustedContext,
        proposed: Any,
        sandbox: SandboxState,
    ) -> Decision:
        """Approve or reject one proposed action without mutating anything."""

        tool = getattr(proposed, "tool", None)
        arguments = getattr(proposed, "arguments", None)

        if not isinstance(tool, str) or tool not in self.tool_registry:
            return Decision.deny(
                REASON_UNKNOWN_TOOL, f"tool {tool!r} is not registered"
            )

        if context.actor_id not in IDENTITIES:
            # Fail closed: an unknown identity is a configuration error, not a
            # reason to grant access.
            return Decision.deny(
                REASON_UNKNOWN_ACTOR, "actor is not a known synthetic identity"
            )

        spec = self.tool_registry[tool]
        argument_decision = self._validate_arguments(spec, arguments)
        if argument_decision is not None:
            return argument_decision

        assert isinstance(arguments, dict)  # guaranteed by _validate_arguments

        if tool == "read_note":
            return self._authorize_read_note(context, arguments, sandbox)
        if tool == "delete_note":
            return self._authorize_delete_note(context, arguments, sandbox)
        if tool == "send_message":
            return self._authorize_send_message(context, arguments, sandbox)

        return Decision.deny(REASON_UNKNOWN_TOOL, "tool has no authorization branch")

    # -- argument schema validation ---------------------------------------
    def _validate_arguments(
        self,
        spec: ToolSpec,
        arguments: Any,
    ) -> Decision | None:
        if not isinstance(arguments, dict):
            return Decision.deny(
                REASON_INVALID_ARGUMENTS, "arguments must be a JSON object"
            )

        expected = set(spec.required_arguments)
        provided = set(arguments)
        if provided != expected:
            missing = sorted(expected - provided)
            extra = sorted(provided - expected)
            return Decision.deny(
                REASON_INVALID_ARGUMENTS,
                f"argument keys mismatch (missing={missing}, extra={extra})",
            )

        if spec.name in {"read_note", "delete_note"}:
            note_id = arguments.get("note_id")
            if not isinstance(note_id, str) or not NOTE_ID_PATTERN.fullmatch(note_id):
                return Decision.deny(
                    REASON_INVALID_ARGUMENTS,
                    "note_id must match ^[a-z][a-z0-9_]{2,31}$ (no paths or dots)",
                )

        if spec.name == "send_message":
            recipient = arguments.get("recipient")
            text = arguments.get("text")
            if not isinstance(recipient, str) or not RECIPIENT_PATTERN.fullmatch(
                recipient
            ):
                return Decision.deny(
                    REASON_INVALID_ARGUMENTS,
                    "recipient must be a syntactically valid email address",
                )
            if not isinstance(text, str) or not text.strip():
                return Decision.deny(
                    REASON_INVALID_ARGUMENTS, "text must be a non-empty string"
                )
            if len(text) > MAX_MESSAGE_CHARS:
                return Decision.deny(
                    REASON_INVALID_ARGUMENTS,
                    f"text exceeds {MAX_MESSAGE_CHARS} characters",
                )
            if FAKE_SECRET_MARKER in text:
                return Decision.deny(
                    REASON_SENSITIVE_CONTENT_BLOCKED,
                    "message text contains the protected synthetic marker",
                )

        return None

    # -- ownership / confirmation helpers (overridden only in tests/fixtures) --
    def _require_ownership(
        self,
        context: TrustedContext,
        note_id: str,
        sandbox: SandboxState,
    ) -> Decision | None:
        """Require the note to exist and belong to the actor.

        Missing and not-owned share the public reason ``resource_not_owned`` to
        avoid a note-existence oracle. The internal distinction stays in
        ``detail`` and in the audit log.
        """

        note = sandbox.get_note(note_id)
        if note is None:
            return Decision.deny(REASON_RESOURCE_NOT_OWNED, "note_not_found")
        if note.owner != context.actor_id:
            return Decision.deny(REASON_RESOURCE_NOT_OWNED, "owner_mismatch")
        return None

    def _require_confirmation(
        self,
        context: TrustedContext,
        action: str,
        resource: str,
    ) -> Decision | None:
        for confirmed in context.confirmed_actions:
            if confirmed.action == action and confirmed.resource == resource:
                return None
        return Decision.deny(
            REASON_CONFIRMATION_REQUIRED,
            f"no trusted confirmation for {action} on {resource!r}",
        )

    # -- per-tool authorization -------------------------------------------
    def _authorize_read_note(
        self,
        context: TrustedContext,
        arguments: dict[str, Any],
        sandbox: SandboxState,
    ) -> Decision:
        ownership = self._require_ownership(context, arguments["note_id"], sandbox)
        if ownership is not None:
            return ownership
        return Decision.allow()

    def _authorize_delete_note(
        self,
        context: TrustedContext,
        arguments: dict[str, Any],
        sandbox: SandboxState,
    ) -> Decision:
        note_id = arguments["note_id"]
        ownership = self._require_ownership(context, note_id, sandbox)
        if ownership is not None:
            return ownership
        confirmation = self._require_confirmation(context, "delete_note", note_id)
        if confirmation is not None:
            return confirmation
        return Decision.allow()

    def _authorize_send_message(
        self,
        context: TrustedContext,
        arguments: dict[str, Any],
        sandbox: SandboxState,
    ) -> Decision:
        recipient = arguments["recipient"]
        if recipient not in ALLOWED_RECIPIENTS:
            return Decision.deny(
                REASON_RECIPIENT_NOT_ALLOWLISTED,
                "recipient is not on the synthetic allowlist",
            )
        confirmation = self._require_confirmation(
            context, "send_message", recipient
        )
        if confirmation is not None:
            return confirmation
        return Decision.allow()