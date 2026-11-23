"""Deliberately flawed policy gates used ONLY by regression tests.

They prove that the evaluator's assertions can detect a missing authorization
check. This module is never imported by the product and is not part of the
``security_lab`` package.
"""

from __future__ import annotations

from security_lab.policy import Decision, PolicyGate


class NoOwnershipPolicyGate(PolicyGate):
    """Simulates a forgotten resource-ownership check (horizontal privilege bug)."""

    def _require_ownership(self, context, note_id, sandbox):  # noqa: ANN001
        return None


class NoConfirmationPolicyGate(PolicyGate):
    """Simulates a forgotten trusted-confirmation check (unconfirmed mutation bug)."""

    def _require_confirmation(self, context, action, resource):  # noqa: ANN001
        return None