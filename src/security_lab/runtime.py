"""Execution pipeline: propose -> policy gate -> in-memory executor -> answer.

The pipeline is the same for the HTTP demo and the batch evaluator. The only
difference is where the trusted context and the candidate actions come from.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Sequence

from .mock_agent import MockAgent
from .policy import PolicyGate, TrustedContext
from .sandbox_tools import SandboxExecutionError, SandboxState, execute_tool
from .schemas import (
    BlockedAction,
    ExecutedAction,
    ProposedAction,
    RunRequest,
    RunResponse,
)

#: Internal runtime failure (e.g. an approved action could not be fulfilled).
#: Never silently ignored: it forces ``case_status="error"`` and no further
#: execution of that action.
REASON_EXECUTION_ERROR = "execution_error"


@dataclass
class RunOutcome:
    """The auditable response plus the sandbox state it produced."""

    response: RunResponse
    sandbox: SandboxState


def execute_request(
    *,
    request: RunRequest,
    trusted_context: TrustedContext,
    agent: MockAgent,
    policy: PolicyGate | None = None,
    sandbox: SandboxState | None = None,
) -> RunOutcome:
    """Run one request end-to-end against a fresh (or supplied) sandbox.

    Safety invariants:

    * every proposed action passes :class:`PolicyGate` before any effect;
    * blocked and executed actions are both audited;
    * if anything unexpected happens the case becomes ``error`` and the action
      is *not* executed (fail closed).
    """

    gate = policy if policy is not None else PolicyGate()
    state = sandbox if sandbox is not None else SandboxState()

    errors: list[str] = []
    proposed_records: list[ProposedAction] = []
    blocked: list[BlockedAction] = []
    executed: list[ExecutedAction] = []

    try:
        proposals = list(agent.propose(request))
    except Exception as exc:  # noqa: BLE001 - fail closed on adapter bugs
        return RunOutcome(
            response=RunResponse(
                case_status="error",
                answer="",
                errors=[
                    f"agent proposal failed: {exc.__class__.__name__}: {exc}"
                ],
            ),
            sandbox=state,
        )

    for raw_proposal in proposals:
        if not isinstance(raw_proposal, ProposedAction):
            errors.append(
                "agent returned a malformed proposal of type "
                f"{type(raw_proposal).__name__}; it was not executed"
            )
            continue

        record = ProposedAction(
            tool=raw_proposal.tool, arguments=dict(raw_proposal.arguments)
        )
        proposed_records.append(record)

        decision = gate.authorize(trusted_context, raw_proposal, state)
        if not decision.allowed:
            reason = decision.reason or "policy_denied"
            # The internal detail is audit-only: it is deliberately NOT put in
            # the client-facing BlockedAction (no note-existence oracle).
            detail = decision.detail
            blocked.append(
                BlockedAction(
                    tool=record.tool,
                    arguments=record.arguments,
                    reason=reason,
                )
            )
            state.record_audit(
                actor_id=trusted_context.actor_id,
                tool=record.tool,
                arguments=record.arguments,
                outcome="blocked",
                reason=reason,
                detail=detail,
            )
            continue

        try:
            result = execute_tool(
                state,
                trusted_context.actor_id,
                raw_proposal.tool,
                raw_proposal.arguments,
            )
        except SandboxExecutionError as exc:
            detail = str(exc)
            errors.append(f"{REASON_EXECUTION_ERROR} on {record.tool}: {detail}")
            blocked.append(
                BlockedAction(
                    tool=record.tool,
                    arguments=record.arguments,
                    reason=REASON_EXECUTION_ERROR,
                )
            )
            state.record_audit(
                actor_id=trusted_context.actor_id,
                tool=record.tool,
                arguments=record.arguments,
                outcome="blocked",
                reason=REASON_EXECUTION_ERROR,
                detail=detail,
            )
            continue

        executed.append(
            ExecutedAction(
                tool=record.tool,
                arguments=record.arguments,
                result=result,
            )
        )
        state.record_audit(
            actor_id=trusted_context.actor_id,
            tool=record.tool,
            arguments=record.arguments,
            outcome="executed",
        )

    try:
        answer = agent.render(request=request, blocked=blocked, executed=executed)
    except Exception as exc:  # noqa: BLE001 - fail closed, keep audit trail
        errors.append(f"agent render failed: {exc.__class__.__name__}: {exc}")
        answer = ""

    return RunOutcome(
        response=RunResponse(
            case_status="error" if errors else "completed",
            answer=answer,
            proposed_actions=proposed_records,
            blocked_actions=blocked,
            executed_actions=executed,
            errors=errors,
        ),
        sandbox=state,
    )