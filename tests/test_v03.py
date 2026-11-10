"""v0.3: unlisted arguments, and secret fields matched the way people write them."""

import logging

import pytest

from provguard import Action, Guard, Policy, PolicyError
from provguard.labels import Source, Trust
from provguard.tracker import ProvenanceTracker, fold_field

POLICY = {
    "default": {"on_tainted": "confirm"},
    "tools": {
        "read_inbox": {"output": "untrusted"},
        "send_email": {"on_tainted": "confirm", "args": {"to": {"require": "trusted"}}},
    },
}


def guard(policy=POLICY):
    return Guard(Policy.from_dict(policy))


# ---- arguments the policy never mentions ---------------------------------

UNLISTED = {
    "tools": {
        "send_email": {
            "unknown_args": "block",
            "args": {"to": {"require": "trusted"}},
        },
    },
}


def test_unlisted_argument_is_allowed_by_default():
    g = guard()
    g.user("mail alice@example.com")
    assert g.check("send_email", {"to": "alice@example.com", "bcc": "x@unknown.example"}).allowed


def test_unlisted_argument_is_blocked_when_the_policy_says_so():
    g = guard(UNLISTED)
    g.user("mail alice@example.com")
    decision = g.check("send_email", {"to": "alice@example.com", "bcc": "x@unknown.example"})
    assert decision.action is Action.BLOCK
    assert [f.rule for f in decision.findings] == ["unlisted-argument"]
    assert decision.findings[0].arg == "bcc"
    # The message names the argument and never repeats its value.
    assert "bcc" in decision.findings[0].message
    assert "x@unknown.example" not in decision.findings[0].message


def test_guarded_arguments_still_use_their_own_rule():
    g = guard(UNLISTED)
    g.user("hello")
    d = g.check("send_email", {"to": "attacker@unknown.example"})
    assert [f.rule for f in d.findings] == ["untrusted-argument"]


def test_unlisted_argument_can_be_confirmed_instead_of_blocked():
    policy = {"tools": {"send_email": {"unknown_args": "confirm", "args": {"to": {}}}}}
    g = guard(policy)
    g.user("mail alice@example.com")
    d = g.check("send_email", {"to": "alice@example.com", "cc": "bob@example.com"})
    assert d.action is Action.CONFIRM
    assert [f.rule for f in d.findings] == ["unlisted-argument"]


def test_an_empty_rule_marks_an_argument_as_known():
    policy = {"tools": {"send_email": {"unknown_args": "block", "args": {"to": {}, "body": {}}}}}
    g = guard(policy)
    g.user("mail alice@example.com")
    assert g.check("send_email", {"to": "anyone@anywhere.example", "body": "hi"}).allowed


def test_unknown_args_reaches_unknown_tools_through_default():
    policy = {"default": {"on_tainted": "allow", "unknown_args": "block"},
              "tools": {"read_inbox": {"output": "untrusted"}}}
    g = guard(policy)
    g.user("do something")
    d = g.check("some_new_tool", {"anything": "x"})
    assert d.action is Action.BLOCK and d.findings[0].rule == "unlisted-argument"


def test_a_null_unlisted_argument_is_not_a_finding():
    g = guard(UNLISTED)
    g.user("mail alice@example.com")
    assert g.check("send_email", {"to": "alice@example.com", "bcc": None}).allowed


def test_unknown_args_value_is_validated():
    for bad in ("deny", True, 1, ["block"]):
        with pytest.raises(PolicyError):
            Policy.from_dict({"tools": {"t": {"unknown_args": bad}}})
    assert Policy.from_dict({"tools": {"t": {"unknown_args": "BLOCK"}}}).for_tool("t").unknown_args is Action.BLOCK


# ---- a secret field name that matches nothing ----------------------------

SECRETS = {
    "tools": {
        "get_user": {"output": "trusted", "secret": ["passport_id"]},
        "get_plain": {"output": "trusted", "secret": ["passport_id"]},
        "send_email": {"args": {"body": {"secrets": "forbid"}}},
    },
}


def test_secret_field_name_that_matches_nothing_is_reported():
    g = guard(SECRETS)
    g.record_result("get_user", {"Passport Number": "HGK137803", "Full Name": "Emma"})
    warnings = g.take_warnings()
    assert len(warnings) == 1
    assert "passport_id" in warnings[0]
    assert "Passport Number" in warnings[0] and "Full Name" in warnings[0]
    assert "get_user" in warnings[0]
    # The value is never repeated, only the field names.
    assert "HGK137803" not in warnings[0]
    assert g.take_warnings() == []          # cleared


def test_secret_field_written_differently_still_protects_the_value():
    """The v0.2 incident: policy asked for passport_number, the tool said "Passport Number"."""
    policy = {"tools": {
        "get_user": {"output": "trusted", "secret": ["passport_number"]},
        "send_email": {"args": {"body": {"secrets": "forbid"}}},
    }}
    g = guard(policy)
    g.user("Email the hotel")
    g.record_result("get_user", {"Passport Number": "HGK137803"})
    assert g.check("send_email", {"body": "Passport HGK137803"}).action is Action.BLOCK
    warnings = g.take_warnings()
    assert len(warnings) == 1
    assert "passport_number covers Passport Number" in warnings[0]
    assert "HGK137803" not in warnings[0]


def test_folded_names_do_not_reach_unrelated_fields():
    policy = {"tools": {"get_user": {"output": "trusted", "secret": ["passport_number"]},
                        "send_email": {"args": {"body": {"secrets": "forbid"}}}}}
    g = guard(policy)
    g.user("Email the hotel")
    g.record_result("get_user", {"Passport Number": "HGK137803", "Name": "Emma"})
    assert g.check("send_email", {"body": "Regards, Emma"}).allowed


def test_matching_secret_field_is_silent():
    policy = {"tools": {"get_user": {"output": "trusted", "secret": ["passport_number"]},
                        "send_email": {"args": {"body": {"secrets": "forbid"}}}}}
    g = guard(policy)
    g.user("Email the hotel")
    g.record_result("get_user", {"passport_number": "HGK137803"})
    assert g.take_warnings() == []
    assert g.check("send_email", {"body": "Passport HGK137803"}).action is Action.BLOCK


def test_secret_fields_on_plain_text_output_are_reported():
    g = guard(SECRETS)
    g.record_result("get_plain", "Passport Number: HGK137803")
    warnings = g.take_warnings()
    assert warnings and "no named fields" in warnings[0]


def test_secret_field_warning_is_logged(caplog):
    g = guard(SECRETS)
    with caplog.at_level(logging.WARNING, logger="provguard"):
        g.record_result("get_user", {"Passport Number": "HGK137803"})
    assert "secret fields passport_id" in caplog.text


def test_list_output_without_named_fields_reports_every_declared_field():
    tracker = ProvenanceTracker()
    report = tracker.add(["HGK137803"], Source("tool", "t", Trust.TRUSTED, True),
                         frozenset({"passport"}))
    assert report is not None
    assert report.unmatched == frozenset({"passport"})
    assert report.matched == {}
    assert report.seen == frozenset()
    assert tracker.secrets_in("it is HGK137803") == []


def test_fold_field_ignores_case_and_separators():
    assert fold_field("passport_number") == fold_field("Passport Number") == "passport number"
    assert fold_field("passport-number") == "passport number"
    assert fold_field("passportNumber") == "passportnumber"


def test_report_is_none_when_no_fields_are_declared():
    tracker = ProvenanceTracker()
    assert tracker.add({"a": "b"}, Source("tool", "t", Trust.TRUSTED, False)) is None
    assert tracker.add({"a": "b"}, Source("tool", "t", Trust.TRUSTED, True)) is None
