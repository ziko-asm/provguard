"""The guard: sits between the model and its tools and decides each call."""

from __future__ import annotations

import functools
import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from .audit import AuditLog
from .labels import SYSTEM, USER, Source
from .policy import Action, ArgRule, Policy
from .tracker import ProvenanceTracker, SecretReport, find_urls, iter_leaves, normalize, numeric_variants

_LOG = logging.getLogger("provguard")


@dataclass(frozen=True)
class Finding:
    rule: str
    message: str
    action: Action
    arg: str | None = None


@dataclass
class Grant:
    """A narrow, explicit exception to an argument rule, usually issued by the user.

    It lets ``tool.arg`` take a value that would otherwise fail ``require:
    trusted``: either one exact ``value`` (the IBAN the user just approved),
    or any value that ``source`` supplied (``"tool:read_file"`` for "pay the
    bill in this file"). It never waives link, secret or tainted-context
    checks. ``uses`` counts down on every executed call that needed it;
    ``None`` lasts for the session.
    """

    tool: str
    arg: str
    value: str | None = None
    source: str | None = None
    uses: int | None = 1

    def covers(self, tool: str, arg: str, value: str, sources: tuple[str, ...]) -> bool:
        if tool != self.tool or arg != self.arg or self.uses == 0:
            return False
        if self.value is not None:
            return normalize(value) in numeric_variants(normalize(self.value))
        return self.source is not None and self.source in sources


@dataclass(frozen=True)
class Decision:
    tool: str
    action: Action
    findings: tuple[Finding, ...]
    grants: tuple[Grant, ...] = field(default=(), compare=False)

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
        self.grants: list[Grant] = []
        # Policy mistakes that would otherwise pass silently (see record_result).
        self.warnings: list[str] = []

    def grant(
        self,
        tool: str,
        arg: str,
        *,
        value: Any = None,
        source: str | None = None,
        uses: int | None = 1,
    ) -> Grant:
        """Let ``tool.arg`` take one approved value, or values from one named source.

        Use it for tasks the user delegated to untrusted content ("visit the
        link Eve posted"). Grants are scoped to one argument of one tool and
        count down, so approving one IBAN does not open every payment.
        """
        if (value is None) == (source is None):
            raise ValueError("grant exactly one of value= or source=")
        if uses is not None and uses < 1:
            raise ValueError("uses must be a positive number or None")
        g = Grant(tool, arg, None if value is None else str(value), source, uses)
        self.grants.append(g)
        return g

    def commit(self, decision: Decision) -> None:
        """Count the grants a call used, once the call has actually run."""
        for g in decision.grants:
            if g.uses is not None and g.uses > 0:
                g.uses -= 1

    def user(self, text: Any) -> None:
        self.tracker.add(text, USER)

    def system(self, text: Any) -> None:
        self.tracker.add(text, SYSTEM)

    def record_result(self, tool: str, output: Any) -> None:
        rules = self.policy.for_tool(tool)
        report = self.tracker.add(
            output, Source("tool", tool, rules.output_trust, rules.output_secret), rules.secret_fields
        )
        if report is None:
            return
        if report.unmatched:
            missing = ", ".join(sorted(report.unmatched))
            seen = ", ".join(sorted(report.seen)) or "no named fields"
            self._warn(
                f"{tool}: secret fields {missing} match no field of its output "
                f"(fields seen: {seen}); the rule protects nothing"
            )
        for declared, fields in sorted(report.folded.items()):
            self._warn(
                f"{tool}: secret field {declared} covers {', '.join(fields)}, which only matches "
                f"by spelling; use the output's own field name"
            )

    def _warn(self, message: str) -> None:
        """Record a policy warning the caller can show, and log it.

        Field names are not secret (values are), so naming them is safe and is
        the only way a policy author sees the mistake.
        """
        self.warnings.append(message)
        _LOG.warning("provguard: %s", message)

    def take_warnings(self) -> list[str]:
        """The policy warnings raised since the last call, and clear them."""
        out, self.warnings = self.warnings, []
        return out

    def check(self, tool: str, args: dict[str, Any]) -> Decision:
        rules = self.policy.for_tool(tool)
        findings: list[Finding] = []
        used: list[Grant] = []

        for name, rule in rules.args.items():
            if name not in args or not rule.active:
                continue
            for path, value in iter_leaves(args[name], name):
                if rule.allows(value):
                    continue
                if rule.require_trusted:
                    finding = self._origin(tool, name, path, value, rule, used)
                    if finding:
                        findings.append(finding)
                if rule.trusted_urls:
                    findings += self._links(path, value, rule)
                if rule.forbid_secrets:
                    for secret, source in self.tracker.secrets_in(value):
                        findings.append(Finding(
                            "secret-leak",
                            f"{path} contains {_redact(secret)}, a field of secret output from {source}",
                            rule.on_violation, path,
                        ))

        if rules.unknown_args is not Action.ALLOW:
            # An argument with no rule of its own is unchecked, which is how data
            # leaves through a field nobody thought about (cc, bcc, attachments).
            # A null argument carries nothing, so it is not a finding.
            for name in args:
                if name in rules.args or args[name] is None:
                    continue
                findings.append(Finding(
                    "unlisted-argument",
                    f"argument {name} is not covered by the policy for this tool",
                    rules.unknown_args, str(name),
                ))

        if self.tracker.tainted and rules.on_tainted is not Action.ALLOW:
            sources = ", ".join(map(str, self.tracker.untrusted_sources()))
            scope = "" if self.policy.knows(tool) else "unknown tool; "
            findings.append(
                Finding("tainted-context", f"{scope}context contains untrusted input from {sources}", rules.on_tainted)
            )

        action = max((f.action for f in findings), default=Action.ALLOW)
        decision = Decision(tool, action, tuple(findings), tuple(used))
        if self.audit:
            self.audit.write(decision, args)
        return decision

    def _origin(
        self, tool: str, name: str, path: str, value: str, rule: ArgRule, used: list[Grant]
    ) -> Finding | None:
        provenance = self.tracker.trace(value)
        if provenance.trusted:
            if len(normalize(value)) >= rule.min_length:
                return None
            return Finding(
                "weak-evidence",
                f"{path}={value!r} is shorter than {rule.min_length} characters, too short to prove a trusted origin",
                rule.on_violation, path,
            )
        names = tuple(map(str, provenance.sources))
        for g in self.grants:
            if g.covers(tool, name, value, names):
                if not any(g is u for u in used):
                    used.append(g)
                return None
        if provenance.unknown:
            why = "does not appear in any trusted input"
        else:
            why = "appears only in untrusted input from " + ", ".join(names)
        return Finding("untrusted-argument", f"{path}={value!r} {why}", rule.on_violation, path)

    def _links(self, path: str, value: str, rule: ArgRule) -> list[Finding]:
        out = []
        for url in dict.fromkeys(find_urls(value)):
            if rule.allows(url) or self.tracker.trace(url).trusted:
                continue
            out.append(Finding(
                "untrusted-link", f"{path} carries the link {url!r}, which no trusted input supplied",
                rule.on_violation, path,
            ))
        return out

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
            self.commit(decision)
            self.record_result(tool, result)
            return result

        return wrapper


def _redact(value: str) -> str:
    # Findings end up in logs and in the model's context; do not repeat the secret.
    return f"'{value[:2]}…{value[-2:]}'" if len(value) > 6 else "'…'"
