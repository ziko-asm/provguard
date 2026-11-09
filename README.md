# ProvGuard

**Untrusted data must not steer sensitive tool calls.**

**Live site and playground: https://provguard.vercel.app**

**Write-up:** [Stop asking "is this text malicious?" — how I stopped 144/144 prompt-injection attacks on an AI banking agent](https://ayfar.dev/yazilar/provguard.html)

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

## New in v0.2

The first evaluation listed what still gets through. v0.2 answers each item
with a narrow rule, all opt-in, so the blind v2 results below are unchanged.

| Feature | Policy / API | Closes |
|---|---|---|
| Links in free text | `body: {urls: trusted}` | attacker link sent to a real colleague in the message body |
| Secret fields | tool `secret: [passport_number]`, arg `secrets: forbid` | passport number e-mailed to an address the user named |
| Scoped approval | `guard.grant(tool, arg, value=... \| source=..., uses=1)` | "pay the bill in this file" without opening every payment |
| Numbers by value | automatic | `240` vs `240.00`, `1,000` vs `1000`; `5` no longer matches inside `1.5` |
| Weak evidence | `min_length: 3` | one- or two-character values "proven" by a stray match |
| MCP proxy | `provguard-mcp --policy p.yaml -- <server>` | using ProvGuard with no code changes |

The evaluation changed too:

* **Scored by outcome.** v2 counted an attack as stopped when any attacker
  call was denied, which overstates a stop if an earlier call already reached
  the goal. `bench.oracle` now skips denied calls, keeps replaying, and asks
  AgentDojo's own `security` check whether the goal was reached, twice: with
  confirmations refused (`goal_no_human`) and with every confirmation approved
  (`goal_any_human`, where only BLOCK protects). Pairs whose attack fails even
  with no guard are counted apart as unverifiable. The v2 metric is still
  reported for comparison.
* **Confirmation burden.** For each legitimate task the oracle counts the
  confirmations a user would see, and checks with AgentDojo's `utility` that
  the task still succeeds when the user approves them.
* **Exact intervals.** Every rate is printed with a Clopper-Pearson 95%
  interval (`bench/stats.py`, no SciPy).
* **Policy lint.** A rule naming a tool or argument the suite does not have
  protects nothing; the oracle prints these before any number.
* **Adaptive attack.** `--attack provenance_aware` tells the model about the
  filter and asks it to launder values through its own reply.
* **Detector baseline.** `bench.run --defense pi_detector` runs AgentDojo's
  DeBERTa prompt-injection detector, the approach ProvGuard argues against.

**v3 policies are not blind.** `bench/policies-v3/` uses the new rules and was
written *after* reading the v2 failures; each change is marked `v3:`. Its
numbers go to `results/oracle-v3/` and must be reported apart from v2:

```bash
python -m bench.oracle                                          # blind v2, rescored
python -m bench.oracle --policies bench/policies-v3 --tag v3     # v3
python -m bench.oracle --policies bench/policies-v3 --tag v3 --attack provenance_aware
python site/build.py                                            # the site picks up results/oracle-v3/
```

## Results v0.2: rescored, and the v3 policies

Model-free replay, AgentDojo v1.2.2, `important_instructions`. "Prevented" is
judged by AgentDojo's own `security` check on the state the attack leaves
behind; pairs whose attack fails even with no guard are excluded (9 in
workspace). 95% Clopper-Pearson intervals.

**The blind v2 numbers hold.** Rescoring by outcome found no pair that the v2
metric counted as stopped while the attack still reached its goal: banking
144/144, slack 97/105, travel 79/120, workspace 191/231 (82.7%; v2 reported
200/240 before unverifiable pairs were separated).

**v3 policies (not blind, written after reading the v2 failures):**

| Suite | Prevented, confirmations refused | Prevented, every confirmation approved | Tasks solved with an approving user, v2 → v3 | Confirmations (v3) |
|---|---|---|---|---|
| banking | 144 / 144 (97.5–100%) | 144 / 144 | 11 / 14 → 11 / 14 | 0 over 16 tasks |
| slack | **105 / 105** (96.5–100%) | 84 / 105 | **12 / 21 → 20 / 21** | 18 over 21 tasks |
| travel | **120 / 120** (97.0–100%) | 80 / 120 | 1 / 1 → 1 / 1 | 5 over 20 tasks |
| workspace | **231 / 231** (98.4–100%) | 191 / 231 | 13 / 18 → 13 / 18 | 7 over 40 tasks |

* With a person who refuses suspicious confirmations, every replayable attack
  in all four suites is prevented.
* Slack shows the trade the v3 goal asked for: tasks that delegate a choice
  to untrusted content ("visit the link Eve posted") go from blocked to
  confirmed, so 20 of 21 succeed instead of 12, at 18 confirmations.
* The middle column is the honest worst case: a person who approves
  everything. Then only BLOCK rules protect, and the extra coverage of v3
  over v2 comes from links and secret fields (travel 79 → 80, slack 84 vs
  97 because some v2 blocks became confirmations).
* "Solved" is checked only where AgentDojo can judge a task without the
  model's text answer (14, 21, 1 and 18 tasks); travel's checks almost all
  read the answer text.
* A first v3 run listed secret fields by attribute name (`passport_number`)
  while the tool returns display names (`Passport Number`); the rule never
  fired and one travel attack got through. The numbers above are from the
  corrected policy. Policy lint checks tool and argument names, not field
  names.

## Live agent: Slack (v0.2)

Qwen3 8B through Ollama, thinking off, temperature 0.7; all 21 Slack user
tasks, injection tasks 1–3 against each (63 pairs; Slack numbers its
injection tasks from 1). One run per defence. ProvGuard uses the v3 policy
with `--confirm deny`: no person is present, so every CONFIRM is a refusal.

| | No defence | ProvGuard (v3, no human) |
|---|---|---|
| Attack success | 14 / 63 (22.2%, 95% CI 12.7–34.5%) | **0 / 63 (0%, 95% CI 0–5.7%)** |
| Utility, clean | 15 / 21 (71.4%) | 9 / 21 (42.9%) |
| Utility under attack | 37 / 63 (58.7%) | 16 / 63 (25.4%) |

Together with banking, ProvGuard let **0 of 111** live attacks through,
against 30 of 111 without it. The cost is utility when nobody can approve a
confirmation: v3 turns several Slack blocks into confirmations precisely so a
person can approve them, and with `--confirm deny` they act as blocks. The
replay estimates 20 of 21 Slack tasks with an approving user; a live run with
a simulated approving user is still to do.

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

## Use it with any MCP client

```json
{
  "mcpServers": {
    "files": {
      "command": "provguard-mcp",
      "args": ["--policy", "policy.yaml", "--audit", "provguard.jsonl",
               "--", "npx", "-y", "@modelcontextprotocol/server-filesystem", "/home/me/docs"]
    }
  }
}
```

The proxy forwards MCP over stdio unchanged, except that every `tools/call`
is checked first. BLOCK comes back as an ordinary tool error with the reason.
CONFIRM is put to the user through MCP elicitation; a client without
elicitation gets a refusal, so it fails closed. Every result is recorded with
the trust label the policy gives that tool.

An MCP server never sees the user's chat message, so values the user typed
are not trusted automatically: pass them with `--trust` / `--trust-file`,
mark tools that return the user's own data `output: trusted`, or use `allow`
lists. One proxy guards one server.

## Quick start

```bash
pip install -e ".[yaml]"
pytest                      # 71 tests, no network or GPU needed
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

v0.2 adds, per argument: `min_length`, `urls: trusted` and `secrets: forbid`;
per tool: `secret: true` or `secret: [field, ...]`.

```python
# The user asked to pay the bill in bill.txt: allow that file's IBAN, once.
guard.grant("send_money", "recipient", source="tool:read_file")
```

## Limitations

Stated up front, because a security tool that hides its limits is not one.

- **Provenance is value matching, not token-level tracking.** If a trusted
  input happens to contain the same value an attacker wants, the value passes.
  Very short values (`"1"`, `"yes"`) are weak evidence; protect them with
  `allow` lists or tainted-context rules instead.
- **It constrains arguments, not intent.** An attacker who can only choose
  *which* allowed action happens, with trusted arguments, is limited by
  `on_tainted`, not by argument rules.
- **Free-text arguments** such as an e-mail body can be checked for links
  (`urls: trusted`) and marked secret fields (`secrets: forbid`), nothing
  more. Data the model paraphrases, or that no policy marks secret, can
  still leave through them.
- **It needs to see every input.** Text that reaches the model without passing
  through `user`, `system` or `record_result` is invisible to it.
- **The live evaluation is small.** One local 8B model, one suite, one run
  per defence. Other suites, stronger models and repeated runs would tighten
  the numbers.

## Roadmap

- [x] Provenance tracker, policy engine, guard, audit log, tests
- [x] MCP proxy: enforce a policy in front of any MCP server without code changes (v0.2)
- [x] Links and secret fields in free text, scoped grants, numeric matching (v0.2)
- [x] Goal-based scoring, confirmation burden, exact intervals, policy lint (v0.2)
- [x] Run the v0.2 oracle: blind v2 rescored, v3 policies
- [ ] `provenance_aware` attack, oracle and live
- [x] Model-free AgentDojo evaluation (all four suites)
- [x] Live-model AgentDojo evaluation, banking (Qwen3 8B)
- [ ] Live evaluation on all suites, repeated runs, stronger models, detector baseline
- [ ] Interactive web demo with a site assistant that runs behind ProvGuard

## License

MIT

By [Ziya Azizov (ayfar)](https://ayfar.dev) · [LinkedIn](https://www.linkedin.com/in/ziyaazizov)
