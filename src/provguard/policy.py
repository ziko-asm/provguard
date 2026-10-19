"""Declarative policy: which tools are sensitive and which arguments need a trusted origin.

Example (YAML)::

    version: 1
    default:
      on_tainted: confirm          # unknown tools are never silently allowed
    tools:
      read_inbox:
        output: untrusted          # e-mail bodies are attacker-controlled
      get_contacts:
        output: trusted            # the user's own address book
      send_email:
        on_tainted: confirm
        args:
          to:
            require: trusted       # recipient must come from the user or a trusted tool
            on_violation: block
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Any

from .labels import Trust
from .tracker import normalize


class PolicyError(ValueError):
    pass


class Action(IntEnum):
    """Ordered by severity so the strictest finding wins."""

    ALLOW = 0
    CONFIRM = 1
    BLOCK = 2

    @classmethod
    def parse(cls, value: Any, where: str) -> Action:
        try:
            return cls[str(value).upper()]
        except KeyError:
            raise PolicyError(f"{where}: expected allow, confirm or block, got {value!r}") from None


@dataclass(frozen=True)
class ArgRule:
    require_trusted: bool = False
    allow: frozenset[str] = frozenset()
    on_violation: Action = Action.BLOCK

    def allows(self, value: str) -> bool:
        return normalize(value) in self.allow


@dataclass(frozen=True)
class ToolPolicy:
    output_trust: Trust = Trust.UNTRUSTED
    on_tainted: Action = Action.ALLOW
    args: Mapping[str, ArgRule] = field(default_factory=dict)


@dataclass(frozen=True)
class Policy:
    tools: Mapping[str, ToolPolicy] = field(default_factory=dict)
    default: ToolPolicy = ToolPolicy(on_tainted=Action.CONFIRM)

    def for_tool(self, name: str) -> ToolPolicy:
        return self.tools.get(name, self.default)

    def knows(self, name: str) -> bool:
        return name in self.tools

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Policy:
        if not isinstance(data, Mapping):
            raise PolicyError("policy must be a mapping")
        _check_keys(data, {"version", "default", "tools"}, "policy")
        if data.get("version", 1) != 1:
            raise PolicyError(f"unsupported policy version {data['version']!r}")
        default = _tool_policy(data.get("default") or {}, "default", Action.CONFIRM)
        tools_data = data.get("tools") or {}
        if not isinstance(tools_data, Mapping):
            raise PolicyError("tools must be a mapping of tool name to settings")
        tools = {
            str(name): _tool_policy(spec or {}, f"tools.{name}", Action.ALLOW)
            for name, spec in tools_data.items()
        }
        return cls(tools=tools, default=default)

    @classmethod
    def from_yaml(cls, path: str | Path) -> Policy:
        try:
            import yaml
        except ImportError:
            raise PolicyError("YAML policies need PyYAML: pip install 'provguard[yaml]'") from None
        with open(path, encoding="utf-8") as handle:
            return cls.from_dict(yaml.safe_load(handle) or {})


def _check_keys(data: Mapping[str, Any], allowed: set[str], where: str) -> None:
    # Typos in a security policy must fail loudly, never be ignored.
    unknown = set(data) - allowed
    if unknown:
        raise PolicyError(f"{where}: unknown keys {sorted(unknown)}")


def _tool_policy(spec: Any, where: str, on_tainted_default: Action) -> ToolPolicy:
    if not isinstance(spec, Mapping):
        raise PolicyError(f"{where}: expected a mapping")
    _check_keys(spec, {"output", "on_tainted", "args"}, where)
    output = str(spec.get("output", "untrusted")).lower()
    if output not in ("trusted", "untrusted"):
        raise PolicyError(f"{where}.output: expected trusted or untrusted, got {output!r}")
    on_tainted = Action.parse(spec.get("on_tainted", on_tainted_default.name), f"{where}.on_tainted")
    args_data = spec.get("args") or {}
    if not isinstance(args_data, Mapping):
        raise PolicyError(f"{where}.args: expected a mapping")
    args = {str(name): _arg_rule(rule or {}, f"{where}.args.{name}") for name, rule in args_data.items()}
    return ToolPolicy(
        output_trust=Trust.TRUSTED if output == "trusted" else Trust.UNTRUSTED,
        on_tainted=on_tainted,
        args=args,
    )


def _arg_rule(spec: Any, where: str) -> ArgRule:
    if not isinstance(spec, Mapping):
        raise PolicyError(f"{where}: expected a mapping")
    _check_keys(spec, {"require", "allow", "on_violation"}, where)
    require = spec.get("require")
    if require not in (None, "trusted"):
        raise PolicyError(f"{where}.require: only 'trusted' is supported, got {require!r}")
    allow = spec.get("allow") or []
    if isinstance(allow, str) or not isinstance(allow, (list, tuple)):
        raise PolicyError(f"{where}.allow: expected a list")
    return ArgRule(
        require_trusted=require == "trusted",
        allow=frozenset(normalize(item) for item in allow),
        on_violation=Action.parse(spec.get("on_violation", "block"), f"{where}.on_violation"),
    )
