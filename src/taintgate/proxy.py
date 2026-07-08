import json
import subprocess
import threading

from .engine import Engine


class McpProxy:
    """Line-delimited JSON-RPC proxy that gates tools/call through the Engine."""

    def __init__(self, engine: Engine, argv: list[str], session_id: str, name: str = "proxied"):
        self.engine, self.argv, self.session_id, self.name = engine, argv, session_id, name
        self._pending: dict = {}
        self._lock = threading.Lock()
        self._out_lock = threading.Lock()

    def _tool(self, short: str) -> str:
        return f"mcp__{self.name}__{short}"

    def run(self, stdin, stdout) -> int:
        proc = subprocess.Popen(self.argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                text=True, bufsize=1, encoding="utf-8")

        def emit(line: str) -> None:
            with self._out_lock:
                stdout.write(line.rstrip("\n") + "\n")
                stdout.flush()

        def pump_server() -> None:
            for line in proc.stdout:
                try:
                    msg = json.loads(line)
                    with self._lock:
                        tool = self._pending.pop(msg.get("id"), None) if "id" in msg else None
                    if tool and "result" in msg:
                        self.engine.record_result(self.session_id, tool, msg["result"])
                except (ValueError, AttributeError):
                    pass
                emit(line)

        t = threading.Thread(target=pump_server, daemon=True)
        t.start()
        for line in stdin:
            blocked = None
            try:
                msg = json.loads(line)
                if isinstance(msg, dict) and msg.get("method") == "tools/call":
                    tool = self._tool(msg["params"]["name"])
                    d = self.engine.check_call(self.session_id, tool, msg["params"].get("arguments") or {})
                    if d.action != "allow":
                        blocked = {"jsonrpc": "2.0", "id": msg.get("id"), "result": {
                            "isError": True,
                            "content": [{"type": "text", "text": f"taintgate blocked: {d.reason}"}]}}
                    else:
                        with self._lock:
                            self._pending[msg.get("id")] = tool
            except (ValueError, KeyError, TypeError):
                pass  # not a well-formed tools/call: pass through untouched
            if blocked:
                emit(json.dumps(blocked))
            else:
                proc.stdin.write(line if line.endswith("\n") else line + "\n")
                proc.stdin.flush()
        proc.stdin.close()
        t.join(10)
        proc.wait(timeout=10)
        return proc.returncode or 0
