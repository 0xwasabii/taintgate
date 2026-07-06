from ..engine import Engine
from . import claude

INSTALL_HELP = """Add to ~/.codex/hooks.json (see docs/codex-hooks.md):
{"hooks": {"PreToolUse": [{"matcher": ".*", "hooks": [{"type": "command", "command": "taintgate hook codex"}]}],
           "PostToolUse": [{"matcher": ".*", "hooks": [{"type": "command", "command": "taintgate hook codex"}]}],
           "UserPromptSubmit": [{"hooks": [{"type": "command", "command": "taintgate hook codex"}]}]}}
For MCP servers, wrap them instead: command = "taintgate", args = ["proxy", "--name", "<server>", "--", "<server cmd>"]."""


def handle(payload: dict, engine: Engine) -> dict | None:
    out = claude.handle(payload, engine)
    if out and out["hookSpecificOutput"]["permissionDecision"] == "ask":
        out["hookSpecificOutput"]["permissionDecision"] = "deny"
    return out


fail_closed_output = claude.fail_closed_output
