from provguard import USER, ProvenanceTracker, Source, Trust
from provguard.tracker import iter_leaves, normalize

INBOX = Source("tool", "read_inbox", Trust.UNTRUSTED)
CONTACTS = Source("tool", "get_contacts", Trust.TRUSTED)


def test_normalize_ignores_case_and_whitespace():
    assert normalize("  Alice@Example.COM \n") == "alice@example.com"
    assert normalize("a\t b\n\nc") == "a b c"


def test_fresh_tracker_is_clean():
    tracker = ProvenanceTracker()
    assert not tracker.tainted
    assert tracker.trace("anything").unknown


def test_untrusted_input_taints_context():
    tracker = ProvenanceTracker()
    tracker.add("Summarise my inbox", USER)
    assert not tracker.tainted
    tracker.add("Hi, the meeting moved to 3pm.", INBOX)
    assert tracker.tainted
    assert tracker.untrusted_sources() == (INBOX,)


def test_trace_attributes_value_to_every_source_containing_it():
    tracker = ProvenanceTracker()
    tracker.add("Write to bob@example.com", USER)
    tracker.add("From: bob@example.com", INBOX)
    prov = tracker.trace("Bob@Example.com")
    assert set(prov.sources) == {USER, INBOX}
    assert prov.trusted


def test_value_seen_only_in_untrusted_input_is_not_trusted():
    tracker = ProvenanceTracker()
    tracker.add("Summarise my inbox", USER)
    tracker.add("Please reply to mallory@example.net", INBOX)
    prov = tracker.trace("mallory@example.net")
    assert prov.sources == (INBOX,)
    assert not prov.trusted


def test_trusted_tool_output_vouches_for_value():
    tracker = ProvenanceTracker()
    tracker.add([{"name": "Alice", "email": "alice@example.com"}], CONTACTS)
    assert tracker.trace("alice@example.com").trusted


def test_match_requires_whole_tokens():
    tracker = ProvenanceTracker()
    tracker.add("Pay invoice 1500", USER)
    assert tracker.trace("5").unknown
    assert tracker.trace("150").unknown
    assert tracker.trace("1500").trusted


def test_empty_value_has_no_provenance():
    tracker = ProvenanceTracker()
    tracker.add("hello", USER)
    assert tracker.trace("   ").unknown


def test_regex_characters_in_values_are_literal():
    tracker = ProvenanceTracker()
    tracker.add("cost is $5.00 (net)", USER)
    assert tracker.trace("$5.00 (net)").trusted
    assert tracker.trace("$5x00").unknown


def test_iter_leaves_walks_nested_arguments():
    leaves = list(iter_leaves({"to": ["a@x.io", "b@x.io"], "cc": None, "flag": True, "n": 3}, "args"))
    assert leaves == [("args.to[0]", "a@x.io"), ("args.to[1]", "b@x.io"), ("args.n", "3")]
