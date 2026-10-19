# ProvGuard

**Untrusted data must not steer sensitive tool calls.**

LLM agents read e-mails, web pages and documents written by strangers, then call
tools with real side effects. Most defences try to *detect* malicious text. My
[prompt-injection detector benchmark](https://prompt-injection-detector-snowy.vercel.app/)
shows why that is fragile: detectors that score 0.96–0.98 F1 on one dataset drop
to 0.37–0.70 on another.

ProvGuard takes the opposite approach, borrowed from information-flow control:
it does not ask *"is this text malicious?"* but *"which source supplied this
argument?"* A recipient, an IBAN or an amount that only appears in an e-mail
cannot drive `send_email` or `transfer_money`, however the e-mail is worded.

```
== Hijacked: recipient came from an e-mail
   without ProvGuard: send_email(to='collector@unknown.example') runs
   with ProvGuard:    send_email: block
                        - [untrusted-argument] to='collector@unknown.example' appears only in untrusted input from tool:read_inbox
                        - [tainted-context] context contains untrusted input from tool:read_inbox
```

## How it works

1. **Label everything the model sees.** User and system messages are trusted.
   Tool outputs are untrusted unless the policy says otherwise (for example the
   user's own address book).
2. **Trace every argument.** Before a tool runs, each argument value is matched
   (case- and whitespace-insensitive, whole tokens) against the labelled inputs.
3. **Require a trusted origin, not an absence of bad signs.** A rule such as
   `to: {require: trusted}` passes only if a trusted source contains the value.
   Values that came from untrusted input, *or that the model invented*, fail closed.
4. **Escalate when the context is tainted.** Sensitive tools can require
   confirmation, or be blocked outright, once any untrusted text has been read.

## Quick start

```bash
pip install -e ".[yaml]"
python examples/demo.py
```

```python
from provguard import Guard, Policy, ToolCallDenied

guard = Guard(Policy.from_yaml("examples/email_agent.yaml"))
guard.user("Read my inbox and send a summary to alice@example.com")

read_inbox = guard.protect(read_inbox)                      # output recorded as untrusted
send_email = guard.protect(send_email, confirm=ask_the_user)  # every call checked

try:
    send_email(to="collector@unknown.example", body="...")
except ToolCallDenied as denied:
    print(denied.decision.explain())
```

## Policy

```yaml
version: 1
default:
  on_tainted: confirm        # unknown tools are never silently allowed
tools:
  read_inbox:
    output: untrusted
  get_contacts:
    output: trusted
  send_email:
    on_tainted: confirm
    args:
      to:
        require: trusted
        allow: ["team@example.com"]
        on_violation: block
```

Unknown keys and invalid values raise `PolicyError`: a typo in a security policy
fails loudly instead of being ignored.

## Limitations

Stated up front, because a security tool that hides its limits is not one.

- **Provenance is value matching, not token-level tracking.** If a trusted
  input happens to contain the same value an attacker wants, the value passes.
  Very short values (`"1"`, `"yes"`) are weak evidence; protect them with
  `allow` lists or tainted-context rules instead.
- **It constrains arguments, not intent.** An attacker who can only choose
  *which* allowed action happens, with trusted arguments, is limited by
  `on_tainted`, not by argument rules.
- **Free-text arguments** such as an e-mail body are not constrained by
  default; requiring a trusted origin for them would block normal use.
  Leaking data through such fields is a known gap.
- **It needs to see every input.** Text that reaches the model without passing
  through `user`, `system` or `record_result` is invisible to it.
- **Not yet evaluated** on public agent-security benchmarks. That evaluation,
  with security and utility both reported, is the next milestone.

## Roadmap

- [x] Provenance tracker, policy engine, guard, audit log, tests
- [ ] MCP proxy: enforce a policy in front of any MCP server without code changes
- [ ] Benchmark evaluation (attack success rate and task utility, multiple seeds)
- [ ] Interactive web demo with a site assistant that runs behind ProvGuard

## License

MIT
