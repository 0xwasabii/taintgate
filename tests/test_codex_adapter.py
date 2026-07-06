import json

from taintgate.adapters import codex
from taintgate.cli import main
from taintgate.engine import Engine
from taintgate.policy import load_policy
from taintgate.state import StateStore


def mk(tmp_path):
    return Engine(load_policy(), StateStore(tmp_path / "s"), tmp_path / "a.jsonl")


def test_ask_is_mapped_to_deny(tmp_path):
    e = mk(tmp_path)
    codex.handle({"hook_event_name": "PostToolUse", "session_id": "s", "tool_name": "WebFetch", "tool_response": "x"}, e)
    out = codex.handle({"hook_event_name": "PreToolUse", "session_id": "s", "tool_name": "Bash", "tool_input": {"command": "ls"}}, e)
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_clean_allows(tmp_path):
    out = codex.handle({"hook_event_name": "PreToolUse", "session_id": "s", "tool_name": "Bash", "tool_input": {}}, mk(tmp_path))
    assert out["hookSpecificOutput"]["permissionDecision"] == "allow"


def test_prompt_returns_none(tmp_path):
    assert codex.handle({"hook_event_name": "UserPromptSubmit", "session_id": "s", "prompt": "p"}, mk(tmp_path)) is None


def test_install_codex_prints_help(capsys):
    assert main(["install", "codex"]) == 0
    assert "hooks" in capsys.readouterr().out
