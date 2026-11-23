"""Deterministic mock agent.

This is **not** a language model and the lab must never claim otherwise. In mock
mode the "model" is either:

* a *replay* of candidate actions supplied by the trusted evaluator fixture
  (``scripted_actions``), which lets us test the server-side gate precisely; or
* a tiny rule-based simulation that derives at most one action from the
  **trusted user request only** (used by the local HTTP demo).

Because the rule-based variant never reads ``untrusted_document`` when choosing
actions, mock mode exercises the policy gate, not LLM susceptibility to prompt
injection. A real-model ``live`` adapter would be a separate, optional layer and
is intentionally not implemented in this MVP.
"""

from __future__ import annotations

import re
from collections.abc import Sequence

from .schemas import BlockedAction, ExecutedAction, ProposedAction, RunRequest

NOTE_ID_IN_TEXT = re.compile(r"\bnote_[a-z0-9_]+\b")
EMAIL_IN_TEXT = re.compile(r"[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}")
MAX_SUMMARY_CHARS = 120


class MockAgent:
    """Deterministic stand-in for an LLM's tool-proposal step."""

    def __init__(
        self,
        scripted_actions: Sequence[ProposedAction] | None = None,
        *,
        default_recipient: str = "alice@example.test",
    ) -> None:
        # ``None`` means "use the rule-based simulation"; an empty sequence means
        # "the scripted model proposes nothing", which is a different scenario.
        self._scripted = (
            tuple(scripted_actions) if scripted_actions is not None else None
        )
        self._default_recipient = default_recipient

    def propose(self, request: RunRequest) -> list[ProposedAction]:
        """Return candidate actions. They are proposals, never executions."""

        if self._scripted is not None:
            return list(self._scripted)
        return self._propose_from_trusted_request(request)

    # -- rule-based demo path ---------------------------------------------
    def _propose_from_trusted_request(
        self, request: RunRequest
    ) -> list[ProposedAction]:
        """Derive one low-risk intent from the *trusted* user request.

        ``untrusted_document`` is deliberately not consulted. This is a
        deterministic simulation, not an LLM.
        """

        text = request.user_request
        lowered = text.lower()
        note_ids = NOTE_ID_IN_TEXT.findall(text)

        if "删除" in text or "delete" in lowered:
            if note_ids:
                return [
                    ProposedAction(
                        tool="delete_note", arguments={"note_id": note_ids[0]}
                    )
                ]
            return []

        if "发送" in text or "send" in lowered:
            emails = EMAIL_IN_TEXT.findall(text)
            recipient = emails[0] if emails else self._default_recipient
            return [
                ProposedAction(
                    tool="send_message",
                    arguments={
                        "recipient": recipient,
                        "text": "模拟外发内容（仅写入审计日志）",
                    },
                )
            ]

        if note_ids:
            return [
                ProposedAction(tool="read_note", arguments={"note_id": note_ids[0]})
            ]

        return []

    # -- deterministic answer rendering ------------------------------------
    def render(
        self,
        *,
        request: RunRequest,
        blocked: Sequence[BlockedAction],
        executed: Sequence[ExecutedAction],
    ) -> str:
        """Render a deterministic answer from real tool observations.

        Only observations from *executed* actions are included. That matters for
        A03: if a flawed policy ever allowed the vault read, the synthetic marker
        would appear here and the leak assertion would fail, exactly as intended.
        """

        parts: list[str] = []

        for action in executed:
            if action.tool == "read_note":
                note_id = action.arguments.get("note_id")
                owner = action.result.get("owner")
                content = str(action.result.get("content", ""))
                parts.append(
                    f"已读取 {note_id}（所有者 {owner}）：{self._summarize(content)}"
                )
            elif action.tool == "delete_note":
                parts.append(
                    f"已删除 {action.arguments.get('note_id')}"
                    "（仅内存沙箱，未触碰磁盘）。"
                )
            elif action.tool == "send_message":
                parts.append(
                    "模拟消息已写入审计日志，收件人 "
                    f"{action.arguments.get('recipient')}（未发送任何网络请求）。"
                )
            else:  # pragma: no cover - registry prevents this in practice
                parts.append(f"已执行 {action.tool}。")

        for action in blocked:
            parts.append(f"动作 {action.tool} 被服务端策略拒绝（{action.reason}）。")

        if not parts:
            return "未提出任何工具动作，也没有执行任何工具。"

        return " ".join(parts)

    @staticmethod
    def _summarize(content: str) -> str:
        condensed = " ".join(content.split())
        if len(condensed) <= MAX_SUMMARY_CHARS:
            return condensed
        return condensed[:MAX_SUMMARY_CHARS] + "…"