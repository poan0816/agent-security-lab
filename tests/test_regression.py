"""Regression proof: deliberately broken policies must make assertions fail.

If a future change ever weakened the evaluator (e.g. judging by ``case_id``
instead of real traces), these tests would start passing the flawed gates and
would fail loudly. The flawed gates live only in ``tests/fixtures`` and are never
part of the product.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from security_lab.evaluator import evaluate_cases, load_cases
from security_lab.policy import PolicyGate
from security_lab.sandbox_tools import FAKE_SECRET_MARKER
from tests.fixtures.flawed_policy import (
    NoConfirmationPolicyGate,
    NoOwnershipPolicyGate,
)

CASES_DIR = Path(__file__).resolve().parents[1] / "cases"


@pytest.fixture(scope="module")
def cases():
    return load_cases(CASES_DIR)


def _failed_ids(run) -> set[str]:
    return {
        evaluation.case.id
        for evaluation in run.evaluations
        if evaluation.status in {"FAIL", "ERROR"}
    }


def _case(run, case_id: str):
    return next(
        evaluation
        for evaluation in run.evaluations
        if evaluation.case.id == case_id
    )


def test_default_policy_passes_every_case(cases) -> None:
    run = evaluate_cases(cases, policy=PolicyGate())
    assert run.metrics.pass_count == 12
    assert run.metrics.violations == 0
    assert _failed_ids(run) == set()


def test_missing_ownership_check_is_detected(cases) -> None:
    """A forgotten ownership check must produce failures and a real leak."""

    run = evaluate_cases(cases, policy=NoOwnershipPolicyGate())
    failed = _failed_ids(run)

    assert {"A03", "A06"} <= failed, failed
    assert run.metrics.violations >= 2

    a03 = _case(run, "A03")
    # The marker really leaks once ownership is unguarded, so the assertion is
    # sensitive to the bug rather than passing for structural reasons.
    assert FAKE_SECRET_MARKER in a03.response.answer
    assert any(
        "answer contains forbidden snippet" in failure
        for failure in a03.failures
    )
    assert any(
        "unauthorized executed action" in failure
        for failure in a03.failures
    )

    # Controls that do not depend on ownership still pass: the flawed gate is
    # only missing one check, so failures point at the right defect.
    for case_id in ("A01", "A04", "A05"):
        assert _case(run, case_id).status == "PASS", case_id


def test_missing_confirmation_check_is_detected(cases) -> None:
    """A forgotten confirmation check must produce failures and real mutations."""

    run = evaluate_cases(cases, policy=NoConfirmationPolicyGate())
    failed = _failed_ids(run)

    assert {"A02", "A05"} <= failed, failed
    assert run.metrics.violations >= 2

    for case_id in ("A02", "A05"):
        evaluation = _case(run, case_id)
        assert [action.tool for action in evaluation.response.executed_actions] == [
            "delete_note"
        ]
        assert "note_01" not in evaluation.sandbox_snapshot["notes"]
        assert any(
            "unauthorized executed action" in failure
            for failure in evaluation.failures
        )

    # Controls that do not depend on confirmation still pass.
    for case_id in ("A03", "A06", "A07"):
        assert _case(run, case_id).status == "PASS", case_id