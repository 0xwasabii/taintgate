import argparse
import json
import os
import re
import sys
from pathlib import Path

from .engine import Engine
from .policy import load_policy
from .state import StateStore

HOOK_EVENTS = ("PreToolUse", "PostToolUse", "UserPromptSubmit")


def home() -> Path:
    return Path(os.environ.get("TAINTGATE_HOME") or Path.home() / ".taintgate")


def build_engine() -> Engine:
    h = home()
    return Engine(load_policy(os.environ.get("TAINTGATE_POLICY")), StateStore(h / "state"), h / "audit.jsonl")


def _adapter(name: str):
    if name == "claude":
        from .adapters import claude
        return claude
    from .adapters import codex
    return codex


def cmd_hook(name: str) -> int:
    adapter = _adapter(name)
    raw = sys.stdin.read()
    try:
        payload = json.loads(raw)
        out = adapter.handle(payload, build_engine())
    except Exception as e:  # noqa: BLE001 - fail closed on sink checks
        if re.search(r'"hook_event_name"\s*:\s*"PreToolUse"', raw):
            out = adapter.fail_closed_output(str(e) or type(e).__name__)
        else:
            out = None
    if out is not None:
        print(json.dumps(out))
    return 0


def hook_config(name: str) -> dict:
    cmd = f"taintgate hook {name}"
    return {"hooks": {ev: [{"matcher": "*" if ev != "UserPromptSubmit" else "",
                            "hooks": [{"type": "command", "command": cmd}]}] for ev in HOOK_EVENTS}}


def merge_hooks(existing: dict, name: str) -> dict:
    cmd = f"taintgate hook {name}"
    hooks = existing.setdefault("hooks", {})
    for ev, groups in hook_config(name)["hooks"].items():
        cur = hooks.setdefault(ev, [])
        if not any(h.get("command") == cmd for g in cur for h in g.get("hooks", [])):
            cur.extend(groups)
    return existing


def cmd_install(name: str, write: str | None) -> int:
    if name == "codex":
        from .adapters import codex
        print(codex.INSTALL_HELP)
        return 0
    if not write:
        print(json.dumps(hook_config(name), indent=2))
        return 0
    p = Path(write)
    existing = json.loads(p.read_text(encoding="utf-8")) if p.exists() else {}
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(merge_hooks(existing, name), indent=2), encoding="utf-8")
    return 0


def cmd_proxy(name: str, session: str, cmd: list[str]) -> int:
    from .proxy import McpProxy
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    if not cmd:
        print("usage: taintgate proxy [--name N] -- <server command...>", file=sys.stderr)
        return 2
    return McpProxy(build_engine(), cmd, session, name=name).run(sys.stdin, sys.stdout)


def cmd_eval(a) -> int:
    from .evalkit import report
    from .evalkit.agents import openrouter_llm, scripted_llm
    from .evalkit.attacker import text_llm
    from .evalkit.defenses import DEFENSES
    from .evalkit.run import run_matrix
    from .evalkit.scenarios import GOALS, TASKS

    llm_agent = a.agent == "llm"
    factory = (lambda: openrouter_llm(a.model)) if llm_agent else scripted_llm
    judge = text_llm(a.model) if llm_agent else None
    attacker = text_llm(a.attacker_model or a.model) if llm_agent and a.attacker == "adaptive" else None
    tasks, goals = (TASKS[: a.limit_tasks], GOALS[: a.limit_goals]) if a.limit_tasks else (TASKS, GOALS)
    recs = run_matrix(tasks, goals, a.defenses or DEFENSES, factory, a.attacker, a.rounds,
                      judge_llm=judge, attacker_llm=attacker)
    if a.out:
        Path(a.out).write_text(json.dumps(recs, indent=1), encoding="utf-8")
    print(report.to_markdown(report.summarize(recs)))
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="taintgate")
    sub = ap.add_subparsers(dest="cmd", required=True)
    h = sub.add_parser("hook"); h.add_argument("agent", choices=["claude", "codex"])
    i = sub.add_parser("install"); i.add_argument("agent", choices=["claude", "codex"]); i.add_argument("--write")
    px = sub.add_parser("proxy"); px.add_argument("--name", default="proxied")
    px.add_argument("--session", default="mcp-proxy"); px.add_argument("server_cmd", nargs=argparse.REMAINDER)
    ev = sub.add_parser("eval"); ev.add_argument("--agent", choices=["scripted", "llm"], default="scripted")
    ev.add_argument("--model", default="anthropic/claude-haiku-4.5"); ev.add_argument("--attacker-model")
    ev.add_argument("--attacker", choices=["static", "adaptive"], default="static")
    ev.add_argument("--rounds", type=int, default=5); ev.add_argument("--out")
    ev.add_argument("--defenses", nargs="*"); ev.add_argument("--limit-tasks", type=int, default=0)
    ev.add_argument("--limit-goals", type=int, default=5)
    args = ap.parse_args(argv)
    if args.cmd == "eval":
        return cmd_eval(args)
    if args.cmd == "proxy":
        return cmd_proxy(args.name, args.session, args.server_cmd)
    if args.cmd == "hook":
        return cmd_hook(args.agent)
    return cmd_install(args.agent, args.write)


if __name__ == "__main__":
    sys.exit(main())
