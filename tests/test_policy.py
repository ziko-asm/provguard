from pathlib import Path

import pytest

from provguard import Action, Policy, PolicyError, Trust

EXAMPLE = Path(__file__).parent.parent / "examples" / "email_agent.yaml"


def test_empty_policy_confirms_unknown_tools_by_default():
    policy = Policy.from_dict({})
    assert policy.for_tool("anything").on_tainted is Action.CONFIRM
    assert not policy.knows("anything")


def test_listed_tools_default_to_allow_and_untrusted_output():
    tool = Policy.from_dict({"tools": {"read": {}}}).for_tool("read")
    assert tool.on_tainted is Action.ALLOW
    assert tool.output_trust is Trust.UNTRUSTED


def test_arg_rule_parsing():
    policy = Policy.from_dict(
        {"tools": {"send": {"args": {"to": {"require": "trusted", "allow": ["Ops@Example.com"], "on_violation": "confirm"}}}}}
    )
    rule = policy.for_tool("send").args["to"]
    assert rule.require_trusted
    assert rule.on_violation is Action.CONFIRM
    assert rule.allows(" ops@example.COM ")
    assert not rule.allows("other@example.com")


@pytest.mark.parametrize(
    "data, message",
    [
        ({"tool": {}}, "unknown keys"),
        ({"version": 2}, "unsupported policy version"),
        ({"tools": {"t": {"on_tainted": "maybe"}}}, "expected allow, confirm or block"),
        ({"tools": {"t": {"output": "sometimes"}}}, "expected trusted or untrusted"),
        ({"tools": {"t": {"args": {"a": {"require": "signed"}}}}}, "only 'trusted'"),
        ({"tools": {"t": {"args": {"a": {"allow": "x@y.z"}}}}}, "expected a list"),
        ({"tools": {"t": {"args": {"a": {"requires": "trusted"}}}}}, "unknown keys"),
        ({"tools": ["t"]}, "mapping"),
    ],
)
def test_invalid_policies_fail_loudly(data, message):
    with pytest.raises(PolicyError, match=message):
        Policy.from_dict(data)


def test_example_yaml_loads():
    pytest.importorskip("yaml")
    policy = Policy.from_yaml(EXAMPLE)
    assert policy.for_tool("get_contacts").output_trust is Trust.TRUSTED
    assert policy.for_tool("transfer_money").on_tainted is Action.BLOCK
