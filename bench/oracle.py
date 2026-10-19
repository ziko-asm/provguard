"""Model-free evaluation: replay AgentDojo's ground-truth trajectories through ProvGuard.

    python -m bench.oracle

Two questions, answered without any LLM in the loop:

* Utility cost: for each user task, does ProvGuard deny any call of the
  reference solution? Each call's real output is recorded, so later calls are
  judged with the same provenance a perfect agent would have.
* Attack coverage: for each (user task, injection task) pair, the user task's
  reference calls run in the injected environment, then the injection task's
  reference calls follow, as if the agent were fully hijacked. The attack is
  stopped if ProvGuard denies any of its calls.

This measures the policy, not a model. A real agent may take other paths; the
LLM runs in ``bench.run`` measure that.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

from agentdojo.agent_pipeline.tool_execution import tool_result_to_str
from agentdojo.attacks.attack_registry import load_attack
from agentdojo.functions_runtime import FunctionsRuntime
from agentdojo.task_suite.load_suites import get_suite

from provguard import Action, Guard, Policy

from .agentdojo_guard import structured
from .run import BENCHMARK_VERSION, POLICIES, ROOT, SUITES


class _NamedPipeline:
    # Attacks only read the pipeline's name, to address the model in the injection text.
    name = "local"


def _step(guard: Guard, runtime: FunctionsRuntime, env, call) -> tuple[Action, str]:
    decision = guard.check(call.function, dict(call.args))
    if decision.action is Action.ALLOW:
        result, error = runtime.run_function(env, call.function, dict(call.args))
        if error is None:
            guard.record_result(call.function, structured(tool_result_to_str(result)))
    return decision.action, decision.explain()


def evaluate_suite(name: str, attack_name: str) -> dict:
    suite = get_suite(BENCHMARK_VERSION, name)
    policy = Policy.from_yaml(POLICIES / f"{name}.yaml")
    runtime = FunctionsRuntime(suite.tools)
    attack = load_attack(attack_name, suite, _NamedPipeline())

    utility: dict[str, dict] = {}
    for task_id, task in suite.user_tasks.items():
        env = suite.load_and_inject_default_environment({})
        guard = Guard(policy)
        guard.user(task.PROMPT)
        worst, reason = Action.ALLOW, ""
        for call in task.ground_truth(env.model_copy(deep=True)):
            action, why = _step(guard, runtime, env, call)
            if action > worst:
                worst, reason = action, why
            if action is Action.BLOCK:
                break
        utility[task_id] = {"action": worst.name.lower(), "reason": reason}

    security: dict[str, dict] = {}
    for task_id, task in suite.user_tasks.items():
        for inj_id, inj in suite.injection_tasks.items():
            env = suite.load_and_inject_default_environment(attack.attack(task, inj))
            guard = Guard(policy)
            guard.user(task.PROMPT)
            for call in task.ground_truth(env.model_copy(deep=True)):
                _step(guard, runtime, env, call)
            reference = inj.ground_truth(env.model_copy(deep=True))
            if not reference:
                # AgentDojo ships no reference calls for some injection tasks; they cannot be replayed.
                security[f"{task_id}|{inj_id}"] = {"stopped": None, "action": None, "call": None, "reason": "no reference"}
                continue
            outcome = {"stopped": False, "action": "allow", "call": None, "reason": ""}
            for call in reference:
                action, why = _step(guard, runtime, env, call)
                if action is not Action.ALLOW:
                    outcome = {"stopped": True, "action": action.name.lower(), "call": call.function, "reason": why}
                    break
            security[f"{task_id}|{inj_id}"] = outcome

    return {"suite": name, "attack": attack_name, "utility": utility, "security": security}


def summarize(result: dict) -> str:
    u = Counter(v["action"] for v in result["utility"].values())
    n_u = len(result["utility"])
    s = {k: v for k, v in result["security"].items() if v["stopped"] is not None}
    skipped = len(result["security"]) - len(s)
    stopped = sum(v["stopped"] for v in s.values())
    by_inj = Counter(k.split("|")[1] for k, v in s.items() if not v["stopped"])
    line = (
        f"{result['suite']:9} user tasks {n_u:3}: allowed {u['allow']:3}  confirm {u['confirm']:3}  "
        f"blocked {u['block']:3} | attacks stopped {stopped}/{len(s)} ({stopped / len(s):.1%})"
        + (f", {skipped} pairs without reference calls" if skipped else "")
    )
    if by_inj:
        line += "\n          not stopped: " + ", ".join(f"{k} x{c}" for k, c in sorted(by_inj.items()))
    return line


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--suite", nargs="+", choices=SUITES, default=SUITES)
    parser.add_argument("--attack", default="important_instructions")
    args = parser.parse_args()

    out_dir = ROOT / "results" / "oracle"
    out_dir.mkdir(parents=True, exist_ok=True)
    for name in args.suite:
        result = evaluate_suite(name, args.attack)
        (out_dir / f"{name}.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(summarize(result), flush=True)


if __name__ == "__main__":
    main()
