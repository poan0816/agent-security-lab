"""Reproducible JSON + Markdown evidence reports.

The report is the audit artifact of one evaluation run. It contains:

* run metadata (commit, case-file hashes, Python/platform, policy class);
* aggregate metrics with explicit numerators/denominators;
* the full per-case trace (proposed / blocked / executed / audit / answer);
* failure reasons, if any;
* the exact commands needed to reproduce the run;
* the honest scope/limitations of mock mode.

Synthetic secret markers are redacted in all report text. (The evaluator checks
the raw answer before redaction, so redaction cannot hide a leak.)
"""

from __future__ import annotations

import hashlib
import json
import platform
import subprocess
from pathlib import Path
from typing import Any

from . import __version__
from .evaluator import CaseEvaluation, EvaluationRun
from .sandbox_tools import FAKE_SECRET_MARKER

REDACTED_MARKER = "[REDACTED_SYNTHETIC_MARKER]"
DOCUMENT_EXCERPT_CHARS = 400
PROJECT_ROOT = Path(__file__).resolve().parents[2]


def source_tree_digest(root: Path | None = None) -> str | None:
    """SHA-256 over the evaluated source tree (code + cases + pyproject).

    This identifies exactly which implementation was measured even after later
    documentation-only commits move ``HEAD`` forward, so the report stays
    reproducible independently of the git commit hash. Returns ``None`` if the
    tree cannot be read.
    """

    base = root if root is not None else PROJECT_ROOT
    candidates: list[Path] = []
    pyproject = base / "pyproject.toml"
    if pyproject.is_file():
        candidates.append(pyproject)
    for pattern in ("src/**/*.py", "cases/*.jsonl"):
        candidates.extend(base.glob(pattern))

    digest = hashlib.sha256()
    try:
        for path in sorted(set(candidates)):
            digest.update(path.relative_to(base).as_posix().encode("utf-8"))
            digest.update(b"\0")
            digest.update(path.read_bytes())
            digest.update(b"\0")
    except OSError:  # pragma: no cover - environment dependent
        return None
    return digest.hexdigest()

LIMITATIONS: tuple[str, ...] = (
    "Mock mode only: candidate actions are replayed from trusted scripted "
    "fixtures or produced by a deterministic rule-based stub. This report does "
    "NOT measure real-LLM prompt-injection resistance and reports no "
    "attack-success-rate.",
    "No live LLM adapter is implemented in this MVP. No network client is used "
    "at runtime; all tools are in-memory simulations with no external side "
    "effects.",
    "Synthetic data only: fake identities (alice, bob), fake notes, fake "
    "allowlisted recipients (@example.test) and a fake marker. Nothing here is "
    "a real credential or a real person's data.",
    "The HTTP demo service is a closed local test harness. The X-Demo-Session "
    "header is a stand-in for authentication, not authentication itself, and "
    "the service must not be deployed publicly.",
    "The Client cannot supply actor_id or confirmed_actions in the request "
    "body (extra fields are rejected), but a real deployment still needs a real "
    "identity provider and real authorization storage.",
    "Missing notes and not-owned notes intentionally share the public reason "
    "code resource_not_owned to avoid a note-existence oracle; the internal "
    "distinction is kept in the audit log detail.",
    "The result is reproducible for a fixed commit and case-file set, but "
    "timestamps and the git dirty flag naturally differ between runs.",
)


def _redact(value: Any) -> Any:
    """Recursively redact the synthetic marker from any string value."""

    if isinstance(value, str):
        return value.replace(FAKE_SECRET_MARKER, REDACTED_MARKER)
    if isinstance(value, list):
        return [_redact(item) for item in value]
    if isinstance(value, tuple):
        return [_redact(item) for item in value]
    if isinstance(value, dict):
        return {key: _redact(item) for key, item in value.items()}
    return value


def _excerpt(text: str, limit: int = DOCUMENT_EXCERPT_CHARS) -> str:
    condensed = text.strip()
    if len(condensed) <= limit:
        return condensed
    return condensed[:limit] + f"… [{len(condensed)} chars total]"


def _git_metadata() -> dict[str, Any]:
    """Best-effort local git metadata. Never fails the report."""

    try:
        commit = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=5,
            check=False,
        )
        status = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):  # pragma: no cover - env dependent
        return {"commit": None, "worktree_dirty": None}

    if commit.returncode != 0:
        return {"commit": None, "worktree_dirty": None}

    dirty: bool | None = None
    if status.returncode == 0:
        dirty = bool(status.stdout.strip())
    return {"commit": commit.stdout.strip() or None, "worktree_dirty": dirty}


def _confirmed_actions(graph: Any) -> list[dict[str, str]]:
    if graph is None:
        return []
    return [
        {"action": confirmed.action, "resource": confirmed.resource}
        for confirmed in graph.confirmed_actions
    ]


def _case_summary(evaluation: CaseEvaluation) -> dict[str, Any]:
    case = evaluation.case
    response = evaluation.response
    snapshot = evaluation.sandbox_snapshot
    summary = {
        "id": case.id,
        "category": case.category,
        "description": case.description,
        "status": evaluation.status,
        "case_status": response.case_status,
        "actor_id": case.actor_id,
        "user_request": case.user_request,
        "untrusted_document_excerpt": _excerpt(evaluation.document_used),
        "untrusted_document_chars": len(evaluation.document_used),
        "untrusted_document_sha256": hashlib.sha256(
            evaluation.document_used.encode("utf-8")
        ).hexdigest(),
        "trusted_fixture": {
            "confirmed_actions": _confirmed_actions(evaluation.trusted_context),
            "source": (
                evaluation.trusted_context.source
                if evaluation.trusted_context is not None
                else None
            ),
        },
        "expected": case.expected.model_dump(mode="json"),
        "proposed_actions": [
            action.model_dump(mode="json") for action in response.proposed_actions
        ],
        "blocked_actions": [
            action.model_dump(mode="json") for action in response.blocked_actions
        ],
        "executed_actions": [
            action.model_dump(mode="json") for action in response.executed_actions
        ],
        "errors": list(response.errors),
        "answer": response.answer,
        "failures": list(evaluation.failures),
        "unauthorized_executed": list(evaluation.unauthorized_executed),
        "notes_after": sorted(snapshot.get("notes", {}).keys()),
        "simulated_messages": snapshot.get("messages", []),
        "audit": snapshot.get("audit", []),
    }
    return _redact(summary)


def build_summary(run: EvaluationRun) -> dict[str, Any]:
    """Build the full serializable summary for one evaluation run."""

    return {
        "schema_version": 1,
        "run": {
            "mode": run.mode,
            "started_at_utc": run.started_at.isoformat(),
            "generated_at_utc": run.generated_at.isoformat(),
            "duration_seconds": round(run.duration_seconds, 6),
            "package_version": __version__,
            "python_version": platform.python_version(),
            "platform": platform.platform(),
            "policy": run.policy_name,
            "agent": (
                "security_lab.mock_agent.MockAgent "
                "(deterministic mock; NOT a real LLM)"
            ),
            "live_llm_calls": 0,
            "external_network_access": (
                "none by design: no network client is used by the lab"
            ),
            "external_side_effects": (
                "none by design: tools are in-memory simulations"
            ),
            "git": _git_metadata(),
            "source_tree_sha256": source_tree_digest(),
            "case_files": _redact(run.case_files),
        },
        "metrics": run.metrics.to_dict(),
        "cases": [_case_summary(evaluation) for evaluation in run.evaluations],
        "limitations": list(LIMITATIONS),
    }


# ---------------------------------------------------------------------------
# Markdown rendering
# ---------------------------------------------------------------------------
def _cell(value: Any) -> str:
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
    return text.replace("|", "\\|").replace("\n", " ")


def _compact(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def _actions_cell(actions: list[dict[str, Any]], extra_key: str | None = None) -> str:
    if not actions:
        return "—"
    cells: list[str] = []
    for action in actions:
        cell = f"`{action.get('tool')}` {_compact(action.get('arguments', {}))}"
        if extra_key is not None:
            cell += f" → **{action.get(extra_key)}**"
        cells.append(cell)
    return "<br>".join(cells)


def _evidence_cell(case: dict[str, Any]) -> str:
    parts: list[str] = []
    executed = case.get("executed_actions", [])
    blocked = case.get("blocked_actions", [])
    if executed:
        parts.append("executed: " + ", ".join(a["tool"] for a in executed))
    if blocked:
        parts.append(
            "blocked: "
            + ", ".join(f"{a['tool']}({a['reason']})" for a in blocked)
        )
    if not parts:
        parts.append("no tool actions")
    if case.get("status") in {"FAIL", "ERROR"} and case.get("failures"):
        parts.append("FAILURE: " + " / ".join(case["failures"]))
    return _cell("<br>".join(parts))


def render_markdown(summary: dict[str, Any]) -> str:
    """Render a human-readable evidence report from the summary dict."""

    run = summary["run"]
    metrics = summary["metrics"]
    cases: list[dict[str, Any]] = summary["cases"]
    lines: list[str] = []

    lines.append("# Security Lab — mock Agent security evaluation report")
    lines.append("")
    lines.append(
        "> **Mode: mock.** Candidate actions come from trusted scripted fixtures "
        "or a deterministic rule-based stub. This report does **not** measure "
        "real-LLM prompt-injection resistance, and it reports no "
        "attack-success-rate."
    )
    lines.append("")
    lines.append("| Run | Value |")
    lines.append("| --- | --- |")
    lines.append(f"| Generated (UTC) | {run['generated_at_utc']} |")
    lines.append(f"| Duration | {run['duration_seconds']} s |")
    lines.append(
        f"| Code | agent-security-lab {run['package_version']} "
        f"@ {run['git'].get('commit') or 'no-git'} "
        f"(dirty: {run['git'].get('worktree_dirty')}) |"
    )
    lines.append(
        "| Source tree (sha256) | "
        f"`{run.get('source_tree_sha256') or 'unavailable'}` |"
    )
    lines.append(f"| Policy | `{run['policy']}` |")
    lines.append(f"| Agent | {run['agent']} |")
    lines.append(
        "| Case files | "
        + "<br>".join(
            f"`{item['path']}` ({item['case_count']} cases, sha256 "
            f"`{item['sha256'][:16]}…`)"
            for item in run["case_files"]
        )
        + " |"
    )
    lines.append("")

    lines.append("## 1. Metrics")
    lines.append("")
    lines.append("| Metric | Result |")
    lines.append("| --- | --- |")
    lines.append(f"| Total cases | {metrics['cases']['total']} |")
    lines.append(
        "| PASS / FAIL / ERROR / N/A | "
        f"{metrics['cases']['pass']} / {metrics['cases']['fail']} / "
        f"{metrics['cases']['error']} / {metrics['cases']['not_applicable']} |"
    )
    lines.append(
        "| Illegal tool calls blocked | "
        f"{metrics['blocked_rate']['display']} |"
    )
    lines.append(
        "| Normal (benign) task pass rate | "
        f"{metrics['normal_task_pass_rate']['display']} |"
    )
    lines.append(
        f"| Unauthorized executed actions (violations) | {metrics['violations']} |"
    )
    lines.append(
        "| Attack success rate (real LLM) | "
        f"{metrics['attack_success_rate']['display']} |"
    )
    lines.append("")
    lines.append(
        "Metric definitions: *blocked rate* = blocked illegal candidate calls ÷ "
        "all illegal candidate calls (a case's illegal tools are declared in its "
        "`must_not_execute_tools`; an empty denominator is reported as N/A, not "
        "100%). *Normal task pass rate* = PASS benign cases ÷ all evaluated "
        "benign cases. *Violations* = executed actions that were not declared "
        "in the case's expected `must_execute` list."
    )
    lines.append("")

    lines.append("## 2. Case results")
    lines.append("")
    lines.append(
        "| ID | Category | Status | Proposed | Blocked (reason) | Executed | Evidence |"
    )
    lines.append("| --- | --- | --- | --- | --- | --- | --- |")
    for case in cases:
        lines.append(
            "| {id} | {category} | **{status}** | {proposed} | {blocked} | "
            "{executed} | {evidence} |".format(
                id=case["id"],
                category=case["category"],
                status=case["status"],
                proposed=_actions_cell(case["proposed_actions"]),
                blocked=_actions_cell(case["blocked_actions"], "reason"),
                executed=_actions_cell(case["executed_actions"]),
                evidence=_evidence_cell(case),
            )
        )
    lines.append("")

    lines.append("## 3. Blocked reason breakdown")
    lines.append("")
    reason_counts = metrics.get("blocked_reason_counts", {})
    if reason_counts:
        lines.append("| Reason | Count |")
        lines.append("| --- | --- |")
        for reason, count in reason_counts.items():
            lines.append(f"| `{reason}` | {count} |")
    else:
        lines.append("_No blocked actions._")
    lines.append("")

    lines.append("## 4. Category results")
    lines.append("")
    lines.append("| Category | Total | PASS | FAIL | ERROR | N/A |")
    lines.append("| --- | --- | --- | --- | --- | --- |")
    for category, bucket in metrics.get("categories", {}).items():
        lines.append(
            f"| {category} | {bucket['total']} | {bucket['pass']} | "
            f"{bucket['fail']} | {bucket['error']} | "
            f"{bucket['not_applicable']} |"
        )
    lines.append("")

    lines.append("## 5. Failures")
    lines.append("")
    failing = [
        case for case in cases if case["status"] in {"FAIL", "ERROR"}
    ]
    if not failing:
        lines.append(
            "_None. Every case satisfied its pre-registered expectations; this "
            "does not prove the absence of every possible defect._"
        )
    else:
        for case in failing:
            lines.append(f"### {case['id']} — {case['status']}")
            for failure in case.get("failures", []):
                lines.append(f"- {failure}")
            lines.append("")
    lines.append("")

    lines.append("## 6. Case evidence")
    lines.append("")
    for case in cases:
        lines.append(f"### {case['id']} — {case['status']}")
        lines.append("")
        lines.append(f"- category: `{case['category']}`")
        lines.append(f"- actor: `{case['actor_id']}`")
        lines.append(f"- case_status: `{case['case_status']}`")
        lines.append(f"- user_request: {_cell(case['user_request'])}")
        lines.append(
            "- untrusted_document: "
            f"{_cell(case['untrusted_document_excerpt'])} "
            f"(chars={case['untrusted_document_chars']}, "
            f"sha256={case['untrusted_document_sha256'][:16]}…)"
        )
        lines.append(
            f"- trusted confirmations: "
            f"{_compact(case['trusted_fixture']['confirmed_actions'])}"
        )
        lines.append(f"- expected: {_compact(case['expected'])}")
        lines.append(
            f"- proposed: {_compact(case['proposed_actions'])}"
        )
        lines.append(f"- blocked: {_compact(case['blocked_actions'])}")
        lines.append(f"- executed: {_compact(case['executed_actions'])}")
        lines.append(f"- answer: {_cell(case['answer']) or '_(empty)_'}")
        lines.append(f"- notes after run: {_compact(case['notes_after'])}")
        lines.append(
            f"- simulated messages: {_compact(case['simulated_messages'])}"
        )
        lines.append(
            f"- audit: {_compact(case['audit'])}"
        )
        lines.append(
            f"- failures: "
            f"{_compact(case['failures']) if case['failures'] else 'none'}"
        )
        lines.append("")

    lines.append("## 7. Reproduction")
    lines.append("")
    lines.append("```powershell")
    lines.append("py -3.11 -m venv .venv")
    lines.append(".\\.venv\\Scripts\\Activate.ps1")
    lines.append('python -m pip install -e ".[dev]"')
    lines.append("python -m pytest -q")
    lines.append(
        "python -m security_lab.cli run --mode mock --cases cases --out reports/mock"
    )
    lines.append("```")
    lines.append("")

    lines.append("## 8. Scope and limitations")
    lines.append("")
    for limitation in summary.get("limitations", []):
        lines.append(f"- {limitation}")
    lines.append("")
    lines.append(
        "Full machine-readable trace (including audit log and per-case hashes): "
        "`summary.json` next to this report."
    )
    lines.append("")

    return "\n".join(lines)


def write_reports(
    run: EvaluationRun, out_dir: str | Path
) -> tuple[Path, Path]:
    """Write ``report.md`` and ``summary.json``. Returns (markdown, json)."""

    output = Path(out_dir)
    output.mkdir(parents=True, exist_ok=True)

    summary = build_summary(run)
    report_path = output / "report.md"
    summary_path = output / "summary.json"

    report_path.write_text(
        render_markdown(summary), encoding="utf-8"
    )
    summary_path.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=False) + "\n",
        encoding="utf-8",
    )
    return report_path, summary_path