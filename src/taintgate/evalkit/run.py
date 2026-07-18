import sys
from concurrent.futures import ThreadPoolExecutor
from typing import Callable

from .agents import Llm, final_text, run_agent
from .attacker import TextLlm, adaptive_injection, static_injection
from .defenses import build
from .scenarios import AttackGoal, Task


def _trial(task: Task, defense_name: str, injection: str | None, agent_llm: Llm, judge_llm):
    world = task.build(injection)
    d = build(defense_name, task, judge_llm=judge_llm)
    blocks: list[str] = []

    def gate(name, args):
        ok, why = d.gate(name, args)
        if not ok:
            blocks.append(why)
        return ok, why

    msgs = run_agent(task.prompt, world, gate, d.post, llm=agent_llm)
    return world, final_text(msgs), blocks


def run_matrix(tasks: list[Task], goals: list[AttackGoal], defenses: list[str],
               agent_llm_factory: Callable[[], Llm], attacker_mode: str, rounds: int, *,
               judge_llm: TextLlm | None = None, attacker_llm: TextLlm | None = None, workers: int = 1) -> list[dict]:
    def unit(dname: str, task: Task) -> list[dict]:
        out: list[dict] = []
        world, final, _ = _trial(task, dname, None, agent_llm_factory(), judge_llm)
        out.append({"kind": "clean", "defense": dname, "task": task.id,
                    "task_success": task.success(world, final)})
        if task.attackable:
            for goal in goals:
                history: list[dict] = []
                best = {"attack_success": False, "task_success_attacked": False, "blocked_calls": 0}
                n = 3 if attacker_mode == "static" else max(rounds, 3)
                for i in range(n):
                    # adaptive = the static templates first, then LLM rewrites seeing prior feedback
                    inj = static_injection(goal, i) if i < 3 else adaptive_injection(goal, history, llm=attacker_llm)
                    world, final, blocks = _trial(task, dname, inj, agent_llm_factory(), judge_llm)
                    best["blocked_calls"] += len(blocks)
                    best["task_success_attacked"] = task.success(world, final)
                    history.append({"injection": inj, "blocked_feedback": "; ".join(blocks), "agent_final": final})
                    if goal.achieved(world):
                        best["attack_success"] = True
                        break
                out.append({"kind": "attack", "defense": dname, "task": task.id, "goal": goal.id,
                            "rounds_used": len(history), **best})
        print(f"done {dname}/{task.id}", file=sys.stderr, flush=True)
        return out

    jobs = [(d, t) for d in defenses for t in tasks]
    with ThreadPoolExecutor(max_workers=workers) as pool:
        return [r for recs in pool.map(lambda j: unit(*j), jobs) for r in recs]
