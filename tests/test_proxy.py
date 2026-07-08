import json
import os
import sys
import threading
from pathlib import Path

import pytest

from taintgate.engine import Engine
from taintgate.policy import Policy, Rule
from taintgate.proxy import McpProxy
from taintgate.state import StateStore

FAKE = str(Path(__file__).parent / "fake_mcp_server.py")
POLICY = Policy([Rule("mcp__srv__fetch_*", "source"), Rule("mcp__srv__send_*", "sink", action="deny")])


class Session:
    def __init__(self, tmp_path, monkeypatch):
        monkeypatch.setenv("FAKE_MCP_LOG", str(tmp_path / "log.txt"))
        self.log = tmp_path / "log.txt"
        r1, w1 = os.pipe(); r2, w2 = os.pipe()
        self.cin_r, self.cin_w = os.fdopen(r1, "r"), os.fdopen(w1, "w")
        self.cout_r, self.cout_w = os.fdopen(r2, "r"), os.fdopen(w2, "w")
        eng = Engine(POLICY, StateStore(tmp_path / "s"), tmp_path / "a.jsonl")
        self.proxy = McpProxy(eng, [sys.executable, FAKE], "sess", name="srv")
        self.t = threading.Thread(target=self.proxy.run, args=(self.cin_r, self.cout_w), daemon=True)
        self.t.start()

    def send(self, raw: str) -> None:
        self.cin_w.write(raw + "\n"); self.cin_w.flush()

    def rpc(self, mid, method, params=None):
        self.send(json.dumps({"jsonrpc": "2.0", "id": mid, "method": method, "params": params or {}}))
        return json.loads(self.cout_r.readline())

    def close(self):
        self.cin_w.close(); self.t.join(5)

    def called(self):
        return self.log.read_text().split() if self.log.exists() else []


@pytest.fixture
def sess(tmp_path, monkeypatch):
    s = Session(tmp_path, monkeypatch)
    yield s
    s.close()


def call(s, mid, name):
    return s.rpc(mid, "tools/call", {"name": name, "arguments": {}})


def test_untainted_call_forwarded(sess):
    assert call(sess, 1, "send_email")["result"]["content"][0]["text"] == "sent"


def test_send_email_blocked_after_fetch_page(sess):
    call(sess, 1, "fetch_page")
    r = call(sess, 2, "send_email")
    assert r["id"] == 2 and r["result"]["isError"] is True
    assert "taintgate blocked" in r["result"]["content"][0]["text"]
    assert sess.called() == ["fetch_page"]


def test_non_tool_messages_pass_through(sess):
    assert sess.rpc(1, "initialize")["result"] == {"ok": "initialize"}
    assert sess.rpc(2, "tools/list")["result"] == {"ok": "tools/list"}


def test_malformed_line_passed_through_not_crashed(sess):
    sess.send("{not json")
    assert call(sess, 1, "send_email")["result"]["content"][0]["text"] == "sent"
