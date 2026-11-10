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
            min_length: 3          # shorter values are too weak to prove an origin
            on_violation: block
          body:
            urls: trusted          # every link in the body needs a trusted origin
            secrets: forbid        # no field from a secret tool output may appear
      get_user_profile:
        output: trusted
        secret: [passport, iban]   # these fields never go into outgoing text (or: true)
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
    # A trusted match on a value shorter than this does not count as evidence.
    min_length: int = 0
    # Every link inside the value (free text included) needs a trusted origin.
    trusted_urls: bool = False
    # No field of a ``secret`` tool output may appear inside the value.
    forbid_secrets: bool = False

    @property
    def active(self) -> bool:
        return self.require_trusted or self.trusted_urls or self.forbid_secrets

    def allows(self, value: str) -> bool:
        return normalize(value) in self.allow


@dataclass(frozen=True)
class ToolPolicy:
    output_trust: Trust = Trust.UNTRUSTED
    output_secret: bool = False
    # When set, only these fields of the output are secret (e.g. passport_number).
    secret_fields: frozenset[str] | None = None
    on_tainted: Action = Action.ALLOW
    args: Mapping[str, ArgRule] = field(default_factory=dict)
    # Arguments the policy does not mention: ALLOW skips them unchecked.
    unknown_args: Action = Action.ALLOW


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


def _tool_policy(
    spec: Any,
    where: str,
    on_tainted_default: Action,
    unknown_args_default: Action = Action.ALLOW,
) -> ToolPolicy:
    if not isinstance(spec, Mapping):
        raise PolicyError(f"{where}: expected a mapping")
    _check_keys(spec, {"output", "secret", "on_tainted", "args", "unknown_args"}, where)
    output = str(spec.get("output", "untrusted")).lower()
    if output not in ("trusted", "untrusted"):
        raise PolicyError(f"{where}.output: expected trusted or untrusted, got {output!r}")
    secret = spec.get("secret", False)
    secret_fields = None
    if isinstance(secret, (list, tuple)) and secret and all(isinstance(f, str) for f in secret):
        secret_fields, secret = frozenset(secret), True
    elif not isinstance(secret, bool):
        raise PolicyError(f"{where}.secret: expected true, false or a list of field names, got {secret!r}")
    on_tainted = Action.parse(spec.get("on_tainted", on_tainted_default.name), f"{where}.on_tainted")
    unknown_args = Action.parse(
        spec.get("unknown_args", unknown_args_default.name), f"{where}.unknown_args"
    )
    args_data = spec.get("args") or {}
    if not isinstance(args_data, Mapping):
        raise PolicyError(f"{where}.args: expected a mapping")
    args = {str(name): _arg_rule(rule or {}, f"{where}.args.{name}") for name, rule in args_data.items()}
    return ToolPolicy(
        output_trust=Trust.TRUSTED if output == "trusted" else Trust.UNTRUSTED,
        output_secret=secret,
        secret_fields=secret_fields,
        on_tainted=on_tainted,
        args=args,
        unknown_args=unknown_args,
    )


def _arg_rule(spec: Any, where: str) -> ArgRule:
    if not isinstance(spec, Mapping):
        raise PolicyError(f"{where}: expected a mapping")
    _check_keys(spec, {"require", "allow", "on_violation", "min_length", "urls", "secrets"}, where)
    require = spec.get("require")
    if require not in (None, "trusted"):
        raise PolicyError(f"{where}.require: only 'trusted' is supported, got {require!r}")
    allow = spec.get("allow") or []
    if isinstance(allow, str) or not isinstance(allow, (list, tuple)):
        raise PolicyError(f"{where}.allow: expected a list")
    min_length = spec.get("min_length", 0)
    if isinstance(min_length, bool) or not isinstance(min_length, int) or min_length < 0:
        raise PolicyError(f"{where}.min_length: expected a non-negative integer, got {min_length!r}")
    urls = spec.get("urls")
    if urls not in (None, "trusted"):
        raise PolicyError(f"{where}.urls: only 'trusted' is supported, got {urls!r}")
    secrets = spec.get("secrets")
    if secrets not in (None, "allow", "forbid"):
        raise PolicyError(f"{where}.secrets: expected allow or forbid, got {secrets!r}")
    return ArgRule(
        min_length=min_length,
        trusted_urls=urls == "trusted",
        forbid_secrets=secrets == "forbid",
        require_trusted=require == "trusted",
        allow=frozenset(normalize(item) for item in allow),
        on_violation=Action.parse(spec.get("on_violation", "block"), f"{where}.on_violation"),
    )
