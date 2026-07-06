from ..engine import Engine


def _pre_output(action: str, reason: str) -> dict:
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse",
                                   "permissionDecision": action, "permissionDecisionReason": reason}}


def handle(payload: dict, engine: Engine) -> dict | None:
    event = payload.get("hook_event_name")
    sid = str(payload.get("session_id", "default"))
    if event == "UserPromptSubmit":
        engine.record_user_prompt(sid, str(payload.get("prompt", "")))
    elif event == "PostToolUse":
        engine.record_result(sid, payload.get("tool_name", ""), payload.get("tool_response"))
    elif event == "PreToolUse":
        d = engine.check_call(sid, payload.get("tool_name", ""), payload.get("tool_input") or {})
        return _pre_output(d.action, f"taintgate: {d.reason}")
    return None


def fail_closed_output(reason: str) -> dict:
    return _pre_output("deny", f"taintgate error: {reason}")
