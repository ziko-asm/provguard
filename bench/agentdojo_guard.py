"""ProvGuard as an AgentDojo pipeline element.

``GuardedToolsExecutor`` replaces AgentDojo's ``ToolsExecutor``. Before each
tool call it rebuilds the provenance record from the conversation so far
(system and user messages trusted, tool outputs labelled by the policy) and
asks the guard. Denied calls are not executed; the model receives an error
explaining why, exactly as it would for a failing tool.

The record is rebuilt from the message history on every call, so no state
leaks between tasks.
"""

from __future__ import annotations

from ast import literal_eval
from collections.abc import Sequence
from typing import Any, Literal

import yaml
from agentdojo.agent_pipeline.tool_execution import ToolsExecutor, is_string_list
from agentdojo.functions_runtime import EmptyEnv, Env, FunctionsRuntime
from agentdojo.types import ChatMessage, ChatToolResultMessage, get_text_content_as_str, text_content_block_from_string

from provguard import Action, Decision, Guard, Policy

ConfirmMode = Literal["deny", "allow"]


def structured(text: str) -> Any:
    """Recover the structure AgentDojo serialised to YAML, so fields are judged whole."""
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError:
        return text
    return data if isinstance(data, (dict, list)) else text


def guard_from_messages(policy: Policy, messages: Sequence[ChatMessage]) -> Guard:
    guard = Guard(policy)
    for message in messages:
        content = message.get("content")
        text = get_text_content_as_str(content) if isinstance(content, list) else (content or "")
        if message["role"] == "system":
            guard.system(text)
        elif message["role"] == "user":
            guard.user(text)
        elif message["role"] == "tool" and message.get("error") is None:
            guard.record_result(message["tool_call"].function, structured(text))
    return guard


class GuardedToolsExecutor(ToolsExecutor):
    def __init__(self, policy: Policy, confirm: ConfirmMode = "deny", **kwargs) -> None:
        super().__init__(**kwargs)
        self.policy = policy
        self.confirm = confirm
        self.decisions: list[Decision] = []

    def _permits(self, decision: Decision) -> bool:
        if decision.action is Action.ALLOW:
            return True
        return decision.action is Action.CONFIRM and self.confirm == "allow"

    def query(
        self,
        query: str,
        runtime: FunctionsRuntime,
        env: Env = EmptyEnv(),
        messages: Sequence[ChatMessage] = [],
        extra_args: dict = {},
    ) -> tuple[str, FunctionsRuntime, Env, Sequence[ChatMessage], dict]:
        if not messages or messages[-1]["role"] != "assistant" or not messages[-1]["tool_calls"]:
            return query, runtime, env, messages, extra_args

        last = messages[-1]
        results: list[ChatMessage] = []
        for call in last["tool_calls"]:
            # Same coercion ToolsExecutor applies, so the guard sees what would run.
            for key, value in call.args.items():
                if isinstance(value, str) and is_string_list(value):
                    call.args[key] = literal_eval(value)

            # Earlier calls of this same turn may already have added untrusted output.
            guard = guard_from_messages(self.policy, [*messages, *results])
            decision = guard.check(call.function, dict(call.args))
            self.decisions.append(decision)

            if self._permits(decision):
                single = {**last, "tool_calls": [call]}
                _, runtime, env, ran, extra_args = super().query(
                    query, runtime, env, [*messages[:-1], single], extra_args
                )
                results.append(ran[-1])
            else:
                results.append(
                    ChatToolResultMessage(
                        role="tool",
                        content=[text_content_block_from_string("")],
                        tool_call_id=call.id,
                        tool_call=call,
                        error="Blocked by ProvGuard security policy. " + decision.explain(),
                    )
                )
        return query, runtime, env, [*messages, *results], extra_args
