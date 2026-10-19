"""The guard: sits between the model and its tools and decides each call."""

from __future__ import annotations

import functools
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from .audit import AuditLog
from .labels import SYSTEM, USER, Source
from .policy import Action, Policy
from .tracker import ProvenanceTracker, iter_leaves


@dataclass(frozen=True)
class Finding:
    rule: str
    message: str
    action: Action
    arg: str | None = None


@dataclass(frozen=True)
class Decision:
    tool: str
    action: Action
    findings: tuple[Finding, ...]

    @property
    def allowed(self) -> bool:
        return self.action is Action.ALLOW

    def explain(self) -> str:
        if not self.findings:
            return f"{self.tool}: allowed"
        lines = [f"{self.tool}: {self.action.name.lower()}"]
        lines += [f"  - [{f.rule}] {f.message}" for f in self.findings]
        return "\n".join(lines)


class ToolCallDenied(PermissionError):
    def __init__(self, decision: Decision) -> None:
        super().__init__(decision.explain())
        self.decision = decision


ConfirmFn = Callable[[Decision], bool]


class Guard:
    """Tracks provenance for one agent session and enforces a policy on tool calls.

    Feed it everything the model sees (``user``, ``system``, ``record_result``)
    and ask it before every tool call (``check``), or let ``protect`` do both.
    """

    def __init__(
        self,
        policy: Policy,
        tracker: ProvenanceTracker | None = None,
        audit: AuditLog | None = None,
    ) -> None:
        self.policy = policy
        self.tracker = tracker or ProvenanceTracker()
        self.audit = audit

    def user(self, text: Any) -> None:
        self.tracker.add(text, USER)

    def system(self, text: Any) -> None:
        self.tracker.add(text, SYSTEM)

    def record_result(self, tool: str, output: Any) -> None:
        trust = self.policy.for_tool(tool).output_trust
        self.tracker.add(output, Source("tool", tool, trust))

    def check(self, tool: str, args: dict[str, Any]) -> Decision:
        rules = self.policy.for_tool(tool)
        findings: list[Finding] = []

        for name, rule in rules.args.items():
            if name not in args:
                continue
            for path, value in iter_leaves(args[name], name):
                if rule.allows(value) or not rule.require_trusted:
                    continue
                provenance = self.tracker.trace(value)
                if provenance.trusted:
                    continue
                if provenance.unknown:
                    why = "does not appear in any trusted input"
                else:
                    why = "appears only in untrusted input from " + ", ".join(map(str, provenance.sources))
                findings.append(
                    Finding("untrusted-argument", f"{path}={value!r} {why}", rule.on_violation, path)
                )

        if self.tracker.tainted and rules.on_tainted is not Action.ALLOW:
            sources = ", ".join(map(str, self.tracker.untrusted_sources()))
            scope = "" if self.policy.knows(tool) else "unknown tool; "
            findings.append(
                Finding("tainted-context", f"{scope}context contains untrusted input from {sources}", rules.on_tainted)
            )

        action = max((f.action for f in findings), default=Action.ALLOW)
        decision = Decision(tool, action, tuple(findings))
        if self.audit:
            self.audit.write(decision, args)
        return decision

    def protect(
        self,
        func: Callable[..., Any],
        name: str | None = None,
        confirm: ConfirmFn | None = None,
    ) -> Callable[..., Any]:
        """Wrap a tool so every call is checked and its output recorded.

        ``confirm`` is asked about CONFIRM decisions; without it they are denied.
        """
        tool = name or func.__name__

        @functools.wraps(func)
        def wrapper(**kwargs: Any) -> Any:
            decision = self.check(tool, kwargs)
            if decision.action is Action.BLOCK:
                raise ToolCallDenied(decision)
            if decision.action is Action.CONFIRM and not (confirm and confirm(decision)):
                raise ToolCallDenied(decision)
            result = func(**kwargs)
            self.record_result(tool, result)
            return result

        return wrapper
