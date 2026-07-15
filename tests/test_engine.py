import json

import pytest

from taintgate.engine import Engine
from taintgate.policy import Policy, Rule
from taintgate.state import StateStore

POLICY = Policy([
    Rule("WebFetch", "source"),
    Rule("Trusted", "source", trust="trusted"),
    Rule("Bash", "sink", mode="strict", action="ask"),
    Rule("Write", "sink", mode="flow", action="ask"),
])


@pytest.fixture
def eng(tmp_path):
    return Engine(POLICY, StateStore(tmp_path / "s"), tmp_path / "audit.jsonl")


def test_clean_session_allows_sink(eng):
    assert eng.check_call("s", "Bash", {"command": "ls"}).action == "allow"


def test_strict_sink_gated_after_untrusted_source(eng):
    eng.record_result("s", "WebFetch", "hello")
    assert eng.check_call("s", "Bash", {"command": "ls"}).action == "ask"


def test_trusted_source_does_not_taint(eng):
    eng.record_result("s", "Trusted", "hello")
    assert eng.check_call("s", "Bash", {"command": "ls"}).action == "allow"


def test_flow_allows_unrelated_args_after_taint(eng):
    eng.record_result("s", "WebFetch", "contact evil@x.com")
    assert eng.check_call("s", "Write", {"file_path": "/tmp/notes.txt", "content": "hi"}).action == "allow"


def test_flow_blocks_untrusted_entity_in_args(eng):
    eng.record_result("s", "WebFetch", "contact evil@x.com")
    d = eng.check_call("s", "Write", {"file_path": "/tmp/n.txt", "content": "to evil@x.com"})
    assert d.action == "ask" and "evil@x.com" in d.reason


def test_user_prompt_entity_is_trusted(eng):
    eng.record_user_prompt("s", "please write to evil@x.com")
    eng.record_result("s", "WebFetch", "contact evil@x.com")
    assert eng.check_call("s", "Write", {"content": "evil@x.com"}).action == "allow"


def test_unknown_tool_allowed_and_logged(eng, tmp_path):
    assert eng.check_call("s", "Mystery", {}).action == "allow"
    assert "Mystery" in (tmp_path / "audit.jsonl").read_text()


def test_sessions_isolated(eng):
    eng.record_result("a", "WebFetch", "x")
    assert eng.check_call("b", "Bash", {}).action == "allow"


def test_audit_log_lines_are_valid_json(eng, tmp_path):
    eng.record_result("s", "WebFetch", "x")
    eng.check_call("s", "Bash", {})
    lines = (tmp_path / "audit.jsonl").read_text().splitlines()
    assert lines and all({"ts", "session", "tool", "decision"} <= json.loads(l).keys() for l in lines)


def test_state_entities_stay_bounded_across_many_results(eng):
    for i in range(20):
        eng.record_result("s", "WebFetch", " ".join(f"u{i}_{j}@x.com" for j in range(500)))
    st = eng.store.load("s")
    assert len(st.untrusted_entities) <= 2000
