"""Policy gate tests: allow/deny decisions, reason codes, no side effects."""

from __future__ import annotations

from types import SimpleNamespace

from security_lab.policy import (
    CONFIRMATION_RESOURCE_KEYS,
    REASON_CONFIRMATION_REQUIRED,
    REASON_INVALID_ARGUMENTS,
    REASON_RECIPIENT_NOT_ALLOWLISTED,
    REASON_RESOURCE_NOT_OWNED,
    REASON_SENSITIVE_CONTENT_BLOCKED,
    REASON_UNKNOWN_ACTOR,
    REASON_UNKNOWN_TOOL,
    TOOL_REGISTRY,
    ConfirmedAction,
    PolicyGate,
    TrustedContext,
)
from security_lab.sandbox_tools import FAKE_SECRET_MARKER, SandboxState
from security_lab.schemas import ProposedAction


def decide(
    gate: PolicyGate,
    sandbox: SandboxState,
    *,
    actor: str = "alice",
    tool: str = "read_note",
    arguments: dict | None = None,
    confirmations: tuple[ConfirmedAction, ...] = (),
):
    context = TrustedContext(actor_id=actor, confirmed_actions=confirmations)
    action = ProposedAction(
        tool=tool, arguments={} if arguments is None else arguments
    )
    return gate.authorize(context, action, sandbox)


# ---------------------------------------------------------------------------
# Registry / identity
# ---------------------------------------------------------------------------
def test_tool_registry_is_fixed_and_minimal() -> None:
    assert set(TOOL_REGISTRY) == {"read_note", "delete_note", "send_message"}
    assert set(CONFIRMATION_RESOURCE_KEYS) == {"delete_note", "send_message"}
    assert TOOL_REGISTRY["send_message"].requires_confirmation is True
    assert TOOL_REGISTRY["delete_note"].requires_confirmation is True
    assert TOOL_REGISTRY["read_note"].requires_confirmation is False


def test_unknown_tool_is_denied(sandbox: SandboxState, gate: PolicyGate) -> None:
    decision = decide(gate, sandbox, tool="delete_all", arguments={})
    assert not decision.allowed
    assert decision.reason == REASON_UNKNOWN_TOOL


def test_unknown_actor_is_denied(sandbox: SandboxState, gate: PolicyGate) -> None:
    decision = decide(
        gate, sandbox, actor="mallory", arguments={"note_id": "note_01"}
    )
    assert not decision.allowed
    assert decision.reason == REASON_UNKNOWN_ACTOR


# ---------------------------------------------------------------------------
# read_note
# ---------------------------------------------------------------------------
def test_read_own_note_allowed(sandbox: SandboxState, gate: PolicyGate) -> None:
    decision = decide(gate, sandbox, arguments={"note_id": "note_01"})
    assert decision.allowed
    assert decision.reason is None


def test_read_other_users_note_is_denied(
    sandbox: SandboxState, gate: PolicyGate
) -> None:
    decision = decide(gate, sandbox, arguments={"note_id": "note_02"})
    assert not decision.allowed
    assert decision.reason == REASON_RESOURCE_NOT_OWNED
    assert decision.detail == "owner_mismatch"


def test_read_vault_note_is_denied(
    sandbox: SandboxState, gate: PolicyGate
) -> None:
    decision = decide(gate, sandbox, arguments={"note_id": "note_vault_01"})
    assert not decision.allowed
    assert decision.reason == REASON_RESOURCE_NOT_OWNED
    assert decision.detail == "owner_mismatch"


def test_missing_and_foreign_note_share_public_reason(
    sandbox: SandboxState, gate: PolicyGate
) -> None:
    missing = decide(
        gate, sandbox, arguments={"note_id": "note_missing_01"}
    )
    foreign = decide(gate, sandbox, arguments={"note_id": "note_02"})
    assert missing.reason == foreign.reason == REASON_RESOURCE_NOT_OWNED
    assert missing.detail == "note_not_found"
    assert foreign.detail == "owner_mismatch"


# ---------------------------------------------------------------------------
# delete_note
# ---------------------------------------------------------------------------
def test_delete_requires_confirmation(
    sandbox: SandboxState, gate: PolicyGate
) -> None:
    decision = decide(
        gate, sandbox, tool="delete_note", arguments={"note_id": "note_01"}
    )
    assert not decision.allowed
    assert decision.reason == REASON_CONFIRMATION_REQUIRED


def test_delete_with_matching_confirmation_allowed(
    sandbox: SandboxState, gate: PolicyGate
) -> None:
    decision = decide(
        gate,
        sandbox,
        tool="delete_note",
        arguments={"note_id": "note_01"},
        confirmations=(ConfirmedAction("delete_note", "note_01"),),
    )
    assert decision.allowed


def test_delete_confirmation_for_other_resource_does_not_authorize(
    sandbox: SandboxState, gate: PolicyGate
) -> None:
    decision = decide(
        gate,
        sandbox,
        tool="delete_note",
        arguments={"note_id": "note_01"},
        confirmations=(ConfirmedAction("delete_note", "note_02"),),
    )
    assert not decision.allowed
    assert decision.reason == REASON_CONFIRMATION_REQUIRED


def test_confirmation_for_other_action_does_not_authorize_delete(
    sandbox: SandboxState, gate: PolicyGate
) -> None:
    decision = decide(
        gate,
        sandbox,
        tool="delete_note",
        arguments={"note_id": "note_01"},
        confirmations=(ConfirmedAction("send_message", "ops@example.test"),),
    )
    assert not decision.allowed
    assert decision.reason == REASON_CONFIRMATION_REQUIRED


def test_delete_cross_user_denied_even_with_confirmation(
    sandbox: SandboxState, gate: PolicyGate
) -> None:
    decision = decide(
        gate,
        sandbox,
        tool="delete_note",
        arguments={"note_id": "note_02"},
        confirmations=(ConfirmedAction("delete_note", "note_02"),),
    )
    assert not decision.allowed
    assert decision.reason == REASON_RESOURCE_NOT_OWNED


# ---------------------------------------------------------------------------
# send_message
# ---------------------------------------------------------------------------
def test_send_to_non_allowlisted_recipient_denied(
    sandbox: SandboxState, gate: PolicyGate
) -> None:
    decision = decide(
        gate,
        sandbox,
        tool="send_message",
        arguments={
            "recipient": "attacker@example.test",
            "text": "synthetic content",
        },
    )
    assert not decision.allowed
    assert decision.reason == REASON_RECIPIENT_NOT_ALLOWLISTED


def test_send_requires_confirmation(
    sandbox: SandboxState, gate: PolicyGate
) -> None:
    decision = decide(
        gate,
        sandbox,
        tool="send_message",
        arguments={"recipient": "ops@example.test", "text": "status update"},
    )
    assert not decision.allowed
    assert decision.reason == REASON_CONFIRMATION_REQUIRED


def test_send_with_matching_confirmation_allowed(
    sandbox: SandboxState, gate: PolicyGate
) -> None:
    decision = decide(
        gate,
        sandbox,
        tool="send_message",
        arguments={"recipient": "ops@example.test", "text": "status update"},
        confirmations=(
            ConfirmedAction("send_message", "ops@example.test"),
        ),
    )
    assert decision.allowed


def test_send_with_secret_marker_denied(
    sandbox: SandboxState, gate: PolicyGate
) -> None:
    decision = decide(
        gate,
        sandbox,
        tool="send_message",
        arguments={
            "recipient": "ops@example.test",
            "text": f"leak {FAKE_SECRET_MARKER}",
        },
        confirmations=(
            ConfirmedAction("send_message", "ops@example.test"),
        ),
    )
    assert not decision.allowed
    assert decision.reason == REASON_SENSITIVE_CONTENT_BLOCKED


# ---------------------------------------------------------------------------
# argument schema / injection-shaped arguments
# ---------------------------------------------------------------------------
def test_extra_argument_denied(sandbox: SandboxState, gate: PolicyGate) -> None:
    decision = decide(
        gate,
        sandbox,
        arguments={"note_id": "note_01", "debug": True},
    )
    assert not decision.allowed
    assert decision.reason == REASON_INVALID_ARGUMENTS


def test_missing_argument_denied(sandbox: SandboxState, gate: PolicyGate) -> None:
    decision = decide(gate, sandbox, arguments={})
    assert not decision.allowed
    assert decision.reason == REASON_INVALID_ARGUMENTS


def test_wrong_argument_type_denied(
    sandbox: SandboxState, gate: PolicyGate
) -> None:
    decision = decide(gate, sandbox, arguments={"note_id": 123})
    assert not decision.allowed
    assert decision.reason == REASON_INVALID_ARGUMENTS


def test_path_traversal_note_id_denied(
    sandbox: SandboxState, gate: PolicyGate
) -> None:
    for candidate in ("../note_01", "..\\note_01", "/etc/passwd", "note_01/../note_02"):
        decision = decide(gate, sandbox, arguments={"note_id": candidate})
        assert not decision.allowed, candidate
        assert decision.reason == REASON_INVALID_ARGUMENTS, candidate


def test_non_object_arguments_denied(
    sandbox: SandboxState, gate: PolicyGate
) -> None:
    # Defense in depth: even a hand-rolled proposal object is validated.
    weird_proposal = SimpleNamespace(tool="read_note", arguments="not-an-object")
    context = TrustedContext(actor_id="alice")
    decision = gate.authorize(context, weird_proposal, sandbox)
    assert not decision.allowed
    assert decision.reason == REASON_INVALID_ARGUMENTS


# ---------------------------------------------------------------------------
# State safety
# ---------------------------------------------------------------------------
def test_authorize_never_mutates_the_sandbox(
    sandbox: SandboxState, gate: PolicyGate
) -> None:
    notes_before = dict(sandbox.notes)

    assert decide(gate, sandbox, arguments={"note_id": "note_01"}).allowed
    assert decide(
        gate,
        sandbox,
        tool="delete_note",
        arguments={"note_id": "note_01"},
        confirmations=(ConfirmedAction("delete_note", "note_01"),),
    ).allowed
    assert decide(
        gate,
        sandbox,
        tool="send_message",
        arguments={"recipient": "ops@example.test", "text": "hi"},
        confirmations=(ConfirmedAction("send_message", "ops@example.test"),),
    ).allowed

    assert sandbox.notes == notes_before
    assert sandbox.messages == []
    assert sandbox.audit == []


def test_each_sandbox_starts_from_the_same_seed(
    sandbox: SandboxState,
) -> None:
    other = SandboxState()
    sandbox.notes.pop("note_01")
    assert "note_01" in other.notes
    assert sorted(other.notes) == ["note_01", "note_02", "note_vault_01"]
    assert other.messages == []
    assert other.audit == []