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
               judge_llm: TextLlm | None = None, attacker_llm: TextLlm | None = None) -> list[dict]:
    records: list[dict] = []
    for dname in defenses:
        for task in tasks:
            world, final, _ = _trial(task, dname, None, agent_llm_factory(), judge_llm)
            records.append({"kind": "clean", "defense": dname, "task": task.id,
                            "task_success": task.success(world, final)})
            if not task.attackable:
                continue
            for goal in goals:
                history: list[dict] = []
                best = {"attack_success": False, "task_success_attacked": False, "blocked_calls": 0}
                n = 3 if attacker_mode == "static" else rounds
                for i in range(n):
                    inj = static_injection(goal, i) if attacker_mode == "static" or i == 0 \
                        else adaptive_injection(goal, history, llm=attacker_llm)
                    world, final, blocks = _trial(task, dname, inj, agent_llm_factory(), judge_llm)
                    won = goal.achieved(world)
                    best["blocked_calls"] += len(blocks)
                    best["task_success_attacked"] = task.success(world, final)
                    history.append({"injection": inj, "blocked_feedback": "; ".join(blocks), "agent_final": final})
                    if won:
                        best["attack_success"] = True
                        break
                records.append({"kind": "attack", "defense": dname, "task": task.id, "goal": goal.id,
                                "rounds_used": len(history), **best})
    return records
