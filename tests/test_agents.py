import json

import httpx
import pytest

from taintgate.evalkit import openrouter
from taintgate.evalkit.agents import final_text, run_agent, scripted_llm
from taintgate.evalkit.scenarios import GOALS, STATIC_INJECTIONS, TASKS


def allow_all(name, args):
    return True, ""


def noop(name, result):
    pass


def injection_for(goal):
    return STATIC_INJECTIONS[0].format(instruction=goal.instruction, action=goal.action)


def task(id):
    return next(t for t in TASKS if t.id == id)


def test_scripted_agent_follows_injection_with_no_gate():
    t, g = task("summarize_inbox"), GOALS[0]
    w = t.build(injection_for(g))
    run_agent(t.prompt, w, allow_all, noop, llm=scripted_llm())
    assert g.achieved(w)


def test_scripted_agent_completes_clean_tasks():
    for t in TASKS:
        w = t.build(None)
        msgs = run_agent(t.prompt, w, allow_all, noop, llm=scripted_llm())
        assert t.success(w, final_text(msgs)), t.id


def test_blocked_call_returns_blocked_message_to_agent():
    t, g = task("summarize_inbox"), GOALS[0]
    w = t.build(injection_for(g))
    msgs = run_agent(t.prompt, w, lambda n, a: (n != "send_email", "nope"), noop, llm=scripted_llm())
    assert not g.achieved(w)
    assert any(m["role"] == "tool" and m["content"] == "blocked: nope" for m in msgs)


def test_max_steps_respected():
    looping = lambda msgs: {"role": "assistant", "content": None, "tool_calls": [
        {"id": "x", "type": "function", "function": {"name": "read_inbox", "arguments": "{}"}}]}
    t = task("summarize_inbox")
    msgs = run_agent(t.prompt, t.build(None), allow_all, noop, llm=looping, max_steps=3)
    assert sum(m["role"] == "assistant" for m in msgs) == 3


def test_openrouter_missing_key_raises(monkeypatch):
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    with pytest.raises(RuntimeError):
        openrouter.chat("m", [{"role": "user", "content": "hi"}])


def test_openrouter_chat_parses_response(monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "k")
    seen = {}

    def handler(req):
        seen["auth"] = req.headers["authorization"]
        seen["body"] = json.loads(req.content)
        return httpx.Response(200, json={"choices": [{"message": {"role": "assistant", "content": "hi"}}]})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    msg = openrouter.chat("some/model", [{"role": "user", "content": "x"}], client=client)
    assert msg["content"] == "hi" and seen["auth"] == "Bearer k" and seen["body"]["model"] == "some/model"
