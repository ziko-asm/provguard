# Changelog

## Unreleased

Library
- Tool `unknown_args: allow | confirm | block` (default `allow`): an argument the policy does not mention is a finding (`unlisted-argument`), so `cc`, `bcc` or `attachments` cannot carry data out of a tool whose other arguments are guarded. An empty rule (`body: {}`) marks an argument as known and unchecked; a `null` value is not a finding.
- A `secret: [field, ...]` name is matched against the tool output exactly first, then with case, spaces, underscores and hyphens folded, so `passport_number` covers a `Passport Number` field (the v0.2 incident where the rule silently never fired). A folded match, and a name that matches no field at all, are reported: `Guard.record_result` appends to `guard.warnings` and logs at WARNING with the field names (never values); `guard.take_warnings()` returns and clears them.
- `ProvenanceTracker.add` returns a `SecretReport` (declared/matched/seen, `.unmatched`) when field-scoped secrets were requested.

MCP proxy
- Every `tools/call` is checked, including one sent as a JSON-RPC notification. A notification cannot carry a refusal, so a call the policy does not allow is dropped and logged instead of forwarded unchecked.
- Policy warnings from `record_result` are printed on the proxy's log stream.

## 0.2.0

Library
- `urls: trusted`: every link inside an argument, free text included, needs a trusted origin.
- Tool `secret: true | [fields]` and argument `secrets: forbid`: confidential fields may not appear in outgoing text, unless the user typed them. Findings redact the value.
- `Guard.grant()` / `Guard.commit()`: scoped, counted approvals for one argument of one tool, by exact value or by source.
- Numbers match by value (`240` = `240.00`, `1,000` = `1000`); a digit inside a decimal is no longer a match.
- `min_length` per argument: short values cannot prove a trusted origin.
- `provguard-mcp`: stdio MCP proxy with policy enforcement and confirmation through MCP elicitation.

Evaluation
- `bench/replay.py`: AgentDojo-free replay logic, unit-tested.
- Oracle scores attacks by AgentDojo's own `security` check, with and without human approval; separates unverifiable pairs; counts confirmations; checks task success with an approving user; lints policies against suite signatures.
- `bench/stats.py`: exact Clopper-Pearson intervals.
- `provenance_aware` adaptive attack; `pi_detector` baseline in `bench.run`; `--policies` for alternative policy folders.
- `bench/policies-v3/`: non-blind policies using the new rules, reported separately.

Site
- Numbers rendered server-side (readable without JavaScript), SEO and social tags, structured data.
- Playground: link-in-body and secret-leak scenarios, using the new rules.
- New sections: v0.2 changes, MCP proxy.
