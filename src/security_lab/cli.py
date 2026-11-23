"""Command line interface.

Examples::

    python -m security_lab.cli run --mode mock --cases cases --out reports/mock
    python -m security_lab.cli run --strict

Live mode is intentionally not implemented in this MVP; the command says so and
exits with code 2 instead of pretending to measure a real model.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .evaluator import CaseFileError, case_file_digests, evaluate_cases, load_cases
from .report import write_reports


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="security_lab.cli",
        description=(
            "Security Lab: run the synthetic Agent tool-safety evaluation and "
            "write JSON/Markdown evidence reports."
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    run_parser = subparsers.add_parser(
        "run", help="evaluate JSONL cases and write a report"
    )
    run_parser.add_argument(
        "--mode",
        choices=("mock", "live"),
        default="mock",
        help="evaluation mode (only 'mock' is implemented)",
    )
    run_parser.add_argument(
        "--cases",
        default="cases",
        help="case directory or single .jsonl file (default: cases)",
    )
    run_parser.add_argument(
        "--out",
        default="reports/mock",
        help="report output directory (default: reports/mock)",
    )
    run_parser.add_argument(
        "--strict",
        action="store_true",
        help=(
            "exit with code 1 if any case is FAIL/ERROR or if any unauthorized "
            "action was executed"
        ),
    )
    return parser


def _print_summary(run: object, report_path: Path, summary_path: Path) -> None:
    from .evaluator import EvaluationRun

    assert isinstance(run, EvaluationRun)
    metrics = run.metrics
    cases = metrics.to_dict()["cases"]
    print(
        f"Security Lab | mode={run.mode} | cases={metrics.total} | "
        f"PASS {cases['pass']} / FAIL {cases['fail']} / "
        f"ERROR {cases['error']} / N/A {cases['not_applicable']}"
    )
    print(
        "blocked_illegal_calls="
        f"{metrics.blocked_rate.to_dict()['display']} | "
        "normal_task_pass_rate="
        f"{metrics.normal_task_pass_rate.to_dict()['display']} | "
        f"violations={metrics.violations}"
    )
    print(
        "mock mode: scripted/rule-based candidates only; this is NOT a real-LLM "
        "prompt-injection measurement."
    )
    print(f"wrote {report_path.as_posix()}")
    print(f"wrote {summary_path.as_posix()}")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command != "run":  # pragma: no cover - argparse enforces choices
        parser.print_help()
        return 2

    if args.mode != "mock":
        print(
            "error: --mode live is not implemented in this MVP. Mock mode tests "
            "the server-side policy gate only; it must not be reported as a "
            "real-LLM prompt-injection measurement.",
            file=sys.stderr,
        )
        return 2

    cases_path = Path(args.cases)
    try:
        cases = load_cases(cases_path)
        file_digests = case_file_digests(cases_path)
    except CaseFileError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    run = evaluate_cases(
        cases,
        mode=args.mode,
        case_files=file_digests,
    )
    report_path, summary_path = write_reports(run, Path(args.out))
    _print_summary(run, report_path, summary_path)

    if args.strict and (
        run.metrics.fail_count
        or run.metrics.error_count
        or run.metrics.violations
    ):
        print(
            "strict mode: refusing success because failures/errors/violations "
            "were detected",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())