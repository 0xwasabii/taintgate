"""taintgate as an AgentDojo defense, plus a small runner.

Requires `pip install agentdojo`. Not imported by the core package.
"""
import json
import os
import tempfile
import uuid
from collections.abc import Sequence
from pathlib import Path

import openai
from agentdojo.agent_pipeline import (
    AgentPipeline, InitQuery, PipelineConfig, SystemMessage, ToolsExecutionLoop, ToolsExecutor,
)
from agentdojo.agent_pipeline.agent_pipeline import load_system_message
from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.agent_pipeline.llms.openai_llm import OpenAILLM
from agentdojo.agent_pipeline.tool_execution import tool_result_to_str
from agentdojo.attacks.attack_registry import load_attack
from agentdojo.benchmark import benchmark_suite_with_injections, benchmark_suite_without_injections
from agentdojo.functions_runtime import EmptyEnv, Env, FunctionsRuntime
from agentdojo.logging import OutputLogger
from agentdojo.task_suite.load_suites import get_suite
from agentdojo.types import ChatMessage, ChatToolResultMessage, text_content_block_from_string

from .engine import Engine
from .policy import Policy, Rule
from .state import StateStore

VERSION = "v1.2.2"
MODEL_ID = "openai/gpt-4o-mini-2024-07-18"  # OpenRouter slug; contains the name AgentDojo's attack looks for
BASELINES = ["none", "tool_filter", "spotlighting_with_delimiting", "repeat_user_prompt"]
DEFENSES = BASELINES + ["taintgate", "taintgate-flow"]

# Tools whose output can carry attacker-controlled text, and tools that act on the world.
SOURCES = [
    "get_most_recent_transactions", "get_scheduled_transactions", "read_file",                      # banking
    "read_channel_messages", "read_inbox", "get_webpage",                                           # slack
    "get_received_emails", "get_unread_emails", "get_sent_emails", "get_draft_emails", "search_emails",
    "get_file_by_id", "search_files", "search_files_by_filename", "list_files",                     # workspace
    "get_day_calendar_events", "search_calendar_events",
    "get_rating_reviews_for_*", "get_contact_information_for_restaurants",                          # travel
]
SINKS = [
    "send_money", "schedule_transaction", "update_scheduled_transaction", "update_password", "update_user_info",
    "send_direct_message", "send_channel_message", "post_webpage", "add_user_to_channel",
    "invite_user_to_slack", "remove_user_from_slack",
    "send_email", "delete_email", "create_file", "append_to_file", "delete_file", "share_file",
    "create_calendar_event", "cancel_calendar_event", "reschedule_calendar_event", "add_calendar_event_participants",
    "reserve_hotel", "reserve_restaurant", "reserve_car_rental",
]


BLOCK_PREFIX = "blocked by taintgate"


def executed_only_trace(messages):
    """AgentDojo's trace check counts every call the model attempted. Drop the ones taintgate blocked,
    so a blocked call is not scored as an attack that worked."""
    blocked = {m["tool_call_id"] for m in messages
               if m["role"] == "tool" and (m.get("error") or "").startswith(BLOCK_PREFIX)}
    return [c for m in messages if m["role"] == "assistant" for c in (m["tool_calls"] or []) if c.id not in blocked]


def use_trace_mode(mode: str) -> None:
    import agentdojo.task_suite.task_suite as ts
    if mode == "executed":
        ts.functions_stack_trace_from_messages = executed_only_trace


def agentdojo_policy(mode: str) -> Policy:
    return Policy([Rule(n, "source") for n in SOURCES] + [Rule(n, "sink", mode=mode, action="deny") for n in SINKS])


class TaintGateInit(BasePipelineElement):
    """Starts a fresh taintgate session for each task and records the user's request as trusted."""

    def __init__(self, engine: Engine) -> None:
        self.engine = engine

    def query(self, query: str, runtime: FunctionsRuntime, env: Env = EmptyEnv(),
              messages: Sequence[ChatMessage] = [], extra_args: dict = {}):
        sid = uuid.uuid4().hex
        self.engine.record_user_prompt(sid, query)
        return query, runtime, env, messages, {**extra_args, "tg_session": sid}


class TaintGateExecutor(ToolsExecutor):
    """ToolsExecutor that asks the engine before each call and reports each result back to it."""

    def __init__(self, engine: Engine, formatter=tool_result_to_str) -> None:
        super().__init__(formatter)
        self.engine = engine

    def query(self, query: str, runtime: FunctionsRuntime, env: Env = EmptyEnv(),
              messages: Sequence[ChatMessage] = [], extra_args: dict = {}):
        if not messages or messages[-1]["role"] != "assistant" or not messages[-1]["tool_calls"]:
            return query, runtime, env, messages, extra_args
        sid = extra_args["tg_session"]
        results = []
        for call in messages[-1]["tool_calls"]:
            decision = self.engine.check_call(sid, call.function, dict(call.args))
            if decision.action != "allow":
                results.append(ChatToolResultMessage(
                    role="tool", tool_call_id=call.id, tool_call=call, error=f"blocked by taintgate: {decision.reason}",
                    content=[text_content_block_from_string(f"Blocked by taintgate: {decision.reason}")]))
                continue
            _, _, _, out, _ = ToolsExecutor.query(self, query, runtime, env, [*messages[:-1], {**messages[-1], "tool_calls": [call]}], extra_args)
            result = out[-1]
            self.engine.record_result(sid, call.function, result["content"][0]["content"] if result["content"] else "")
            results.append(result)
        return query, runtime, env, [*messages, *results], extra_args


def build_pipeline(defense: str, client: openai.OpenAI | None = None, model: str = MODEL_ID) -> AgentPipeline:
    client = client or openai.OpenAI(base_url="https://openrouter.ai/api/v1", api_key=os.environ["OPENROUTER_API_KEY"])
    llm = OpenAILLM(client, model)
    llm.name = model
    if defense in BASELINES:
        cfg = PipelineConfig(llm=llm, model_id=None, defense=None if defense == "none" else defense,
                             system_message_name=None, system_message=None)
        return AgentPipeline.from_config(cfg)
    if defense not in ("taintgate", "taintgate-flow"):
        raise ValueError(f"unknown defense {defense!r}")
    engine = Engine(agentdojo_policy("flow" if defense == "taintgate-flow" else "strict"),
                    StateStore(Path(tempfile.mkdtemp(prefix="taintgate-agentdojo-"))))
    loop = ToolsExecutionLoop([TaintGateExecutor(engine), llm])
    pipeline = AgentPipeline([SystemMessage(load_system_message(None)), InitQuery(), TaintGateInit(engine), llm, loop])
    pipeline.name = f"{model}-{defense}"
    return pipeline


def run_suite(suite_name: str, defense: str, logdir: Path, *, attack: str = "important_instructions", trace_mode: str = "attempted",
              user_tasks: list[str] | None = None, injection_tasks: list[str] | None = None) -> dict:
    use_trace_mode(trace_mode)
    suite = get_suite(VERSION, suite_name)
    pipeline = build_pipeline(defense)
    logdir.mkdir(parents=True, exist_ok=True)
    with OutputLogger(str(logdir), live=None):
        clean = benchmark_suite_without_injections(pipeline, suite, logdir=logdir, force_rerun=False,
                                                   user_tasks=user_tasks, benchmark_version=VERSION)
        atk = load_attack(attack, suite, pipeline)
        inj = benchmark_suite_with_injections(pipeline, suite, atk, logdir=logdir, force_rerun=False,
                                              user_tasks=user_tasks, injection_tasks=injection_tasks, benchmark_version=VERSION)
    rate = lambda d: round(100 * sum(d.values()) / len(d), 1) if d else None
    return {
        "suite": suite_name, "defense": defense, "trace_mode": trace_mode, "attack": attack, "model": MODEL_ID, "version": VERSION,
        "n_clean": len(clean["utility_results"]), "utility_no_attack": rate(clean["utility_results"]),
        "n_attack": len(inj["security_results"]), "attack_success": rate(inj["security_results"]),
        "utility_under_attack": rate(inj["utility_results"]),
        "pairs": [{"user_task": u, "injection_task": i, "attack_success": s, "utility": inj["utility_results"][(u, i)]}
                  for (u, i), s in inj["security_results"].items()],
    }


def main(argv: list[str] | None = None) -> int:
    import argparse
    ap = argparse.ArgumentParser(prog="taintgate agentdojo")
    ap.add_argument("--suite", required=True)
    ap.add_argument("--defense", required=True, choices=DEFENSES)
    ap.add_argument("--attack", default="important_instructions")
    ap.add_argument("--trace-mode", choices=["attempted", "executed"], default="attempted",
                    help="attempted = AgentDojo native (blocked calls still count); executed = ignore calls taintgate blocked")
    ap.add_argument("--user-tasks", nargs="*")
    ap.add_argument("--injection-tasks", nargs="*")
    ap.add_argument("--out", default="results/agentdojo")
    a = ap.parse_args(argv)
    out = Path(a.out)
    res = run_suite(a.suite, a.defense, out / "traces" / a.defense, attack=a.attack, trace_mode=a.trace_mode,
                    user_tasks=a.user_tasks or None, injection_tasks=a.injection_tasks or None)
    (out / f"{a.suite}-{a.defense}.json").write_text(json.dumps(res, indent=1), encoding="utf-8")
    print({k: v for k, v in res.items() if k != "pairs"})
    return 0
