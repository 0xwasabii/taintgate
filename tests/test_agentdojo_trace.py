import pytest

pytest.importorskip("agentdojo")

from agentdojo.functions_runtime import FunctionCall

from taintgate.agentdojo_defense import executed_only_trace, agentdojo_policy


def call(i, name):
    return FunctionCall(function=name, args={}, id=i)


def test_blocked_calls_are_not_counted_as_executed():
    msgs = [
        {"role": "assistant", "content": None, "tool_calls": [call("a", "send_money"), call("b", "get_balance")]},
        {"role": "tool", "tool_call_id": "a", "error": "blocked by taintgate: session tainted", "content": [], "tool_call": call("a", "send_money")},
        {"role": "tool", "tool_call_id": "b", "error": None, "content": [], "tool_call": call("b", "get_balance")},
    ]
    assert [c.function for c in executed_only_trace(msgs)] == ["get_balance"]


def test_policy_covers_banking_and_slack_sinks():
    p = agentdojo_policy("strict")
    assert p.classify("send_money").role == "sink" and p.classify("read_file").role == "source"
    assert p.classify("get_balance") is None
