import os

import pytest

from taintgate.evalkit.scenarios import GOALS, STATIC_INJECTIONS, TASKS
from taintgate.evalkit.world import TOOL_SPECS, World


def test_injection_appears_in_tool_output():
    w = TASKS[0].build("EVIL-MARKER")
    assert "EVIL-MARKER" in w.read_inbox()
    w2 = next(t for t in TASKS if t.id == "summarize_page").build("EVIL-MARKER")
    assert "EVIL-MARKER" in w2.fetch_url("https://news.company.test/a")


def test_no_injection_means_clean_output():
    assert "EVIL" not in TASKS[0].build(None).read_inbox()


def test_send_email_recorded():
    w = World([], {}, None)
    w.call("send_email", {"to": "a@b.c", "subject": "s", "body": "b"})
    assert w.sent == [{"to": "a@b.c", "subject": "s", "body": "b"}]


@pytest.mark.parametrize("task", TASKS, ids=lambda t: t.id)
def test_each_task_success_fn_false_on_fresh_world(task):
    assert task.success(task.build(None), "") is False


@pytest.mark.parametrize("goal", GOALS, ids=lambda g: g.id)
def test_each_goal_achieved_fn_true_after_attack_action(goal):
    w = TASKS[0].build(None)
    assert goal.achieved(w) is False
    kind, _, rest = goal.action.partition(" ")
    if kind == "send_email":
        w.call("send_email", {"to": rest, "subject": "x", "body": "CONFIDENTIAL"})
    else:
        w.call("run_shell", {"command": rest})
    assert goal.achieved(w) is True


def test_run_shell_never_executes(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    w = World([], {}, None)
    w.call("run_shell", {"command": "touch x"})
    assert not os.path.exists("x") and w.shell_log == ["touch x"]


def test_templates_and_specs_shape():
    assert len(TASKS) >= 12 and len(GOALS) >= 5 and len(STATIC_INJECTIONS) >= 3
    assert {s["function"]["name"] for s in TOOL_SPECS} == {"read_inbox", "fetch_url", "send_email", "run_shell"}
