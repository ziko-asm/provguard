# ProvGuard

**Untrusted data must not steer sensitive tool calls.**

**Live site and playground: https://provguard.vercel.app**

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

## Results: AgentDojo, replayed without a model

[AgentDojo](https://github.com/ethz-spylab/agentdojo) (v1.2.2) ships a reference
solution for every task. `python -m bench.oracle` replays them through ProvGuard,
with no LLM in the loop, so every number below is deterministic:

* **Legitimate tasks blocked**: does ProvGuard deny a call in the reference
  solution of a user task?
* **Attacks stopped**: the user task runs in an environment poisoned with the
  `important_instructions` attack, then the attacker's reference calls follow as
  if the agent were fully hijacked. Stopped means at least one of them is denied.

| Suite | Legitimate tasks blocked | Attacks stopped (v1) | Attacks stopped (v2) |
|---|---|---|---|
| banking | 3 / 16 | 144 / 144 | **144 / 144 (100%)** |
| slack | 12 / 21 | 53 / 105 | **97 / 105 (92%)** |
| travel | 0 / 20 | 79 / 120 | **79 / 120 (66%)** |
| workspace | 5 / 40 | 200 / 240 | **200 / 240 (83%)** |

Pairs whose injection task has no reference solution in AgentDojo (20 in
travel, 320 in workspace) cannot be replayed and are excluded, not counted as
stopped.

**How the policies were written.** The four policies in `bench/policies/` were
committed before any injection task was read, from tool signatures alone.
They have not been changed since.

**v1 → v2, a change informed by the v1 failures.** In Slack, the attack text
was planted in a *channel name*, and v1 trusted the channel list, so a URL
inside that name looked trusted. v2 changes the library, not the policies:
structured tool output now vouches only for *complete* field values
(`general`), never for text found inside a field. Both result sets are kept in
`results/oracle-v1/` and `results/oracle/`.

**What still gets through, and why.** Every remaining attack works the same
way: the attacker picks among options that are legitimate anyway.

* Book the most expensive hotel from the real catalogue (travel).
* Create a calendar event with no participants (travel).
* Send a link to Alice, who really is a workspace member, with the link in the
  message *body* (slack).
* Delete file `13`, an id that appears in the user's own file list (workspace).
* Send the user's passport number to the address the user asked to write to,
  inside the e-mail body (travel, 1 pair).

Argument provenance cannot stop these by design. `on_tainted: confirm` on
state-changing tools moves them to a human; the benchmark has no human, so that
trade-off is reported rather than hidden.

**What it costs.** The blocked legitimate tasks are tasks where the user
*delegated* the choice to untrusted content: "pay the bill in this file", "visit
the link Eve posted", "invite Dora, her e-mail is on her website". Under a
strict policy these need confirmation. That is the honest price of the
guarantee, and the main thing v3 should reduce.

These numbers measure the policy, not an agent. A live model may take other
paths, which the next section measures.

## Results: a live agent

Qwen3 8B (local, Ollama, thinking disabled, temperature 0.7) on AgentDojo
banking: all 16 user tasks, and the first three injection tasks (chosen by
index before the run) against every user task. Same policy, same attack, one
run per defence.

| | No defence | ProvGuard |
|---|---|---|
| **Attack success** | **16 / 48 (33%)** | **0 / 48 (0%)** |
| Utility, no attack | 8 / 16 | 9 / 16 |
| Utility under attack | 26 / 48 | 24 / 48 |

* ProvGuard stopped every attack the undefended agent fell for. With 0 of 48,
  the one-sided 95% upper bound on its attack success rate is about 6%.
* Utility did not measurably drop. The one-task differences either way are
  within run-to-run noise at this sample size: a single run at temperature 0.7.
* The task the guard cost, `user_task_0` ("pay the bill in this file"), is the
  one the model-free replay predicted: the IBAN comes from an untrusted file.

Reproduce with `python -m bench.run --suite banking --defense none provguard
--no-think --model qwen3-8k --injection-tasks injection_task_0 injection_task_1
injection_task_2` (about 10 hours on a 6 GB laptop GPU).

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
- **The live evaluation is small.** One local 8B model, one suite, one run
  per defence. Other suites, stronger models and repeated runs would tighten
  the numbers.

## Roadmap

- [x] Provenance tracker, policy engine, guard, audit log, tests
- [ ] MCP proxy: enforce a policy in front of any MCP server without code changes
- [x] Model-free AgentDojo evaluation (all four suites)
- [x] Live-model AgentDojo evaluation, banking (Qwen3 8B)
- [ ] Live evaluation on all suites, repeated runs, stronger models
- [ ] Interactive web demo with a site assistant that runs behind ProvGuard

## License

MIT
