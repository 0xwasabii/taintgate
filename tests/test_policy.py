import pytest
import yaml

from taintgate.policy import Policy, Rule, load_policy


def test_first_match_wins():
    p = Policy([Rule("mcp__*send*", "sink"), Rule("mcp__*", "source")])
    assert p.classify("mcp__mail__send_email").role == "sink"
    assert p.classify("mcp__mail__read").role == "source"


def test_unmatched_returns_none():
    assert Policy([]).classify("Glob") is None


def test_default_policy_classifies_claude_tools():
    p = load_policy()
    web = p.classify("WebFetch")
    assert (web.role, web.trust) == ("source", "untrusted")
    bash = p.classify("Bash")
    assert bash.role == "sink" and bash.action == "ask"
    assert p.classify("mcp__mail__send_email").role == "sink"


def test_invalid_role_raises(tmp_path):
    f = tmp_path / "p.yaml"
    f.write_text(yaml.safe_dump({"rules": [{"match": "x", "role": "bogus"}]}))
    with pytest.raises(ValueError):
        load_policy(f)
