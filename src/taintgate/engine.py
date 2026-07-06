import json
import time
from pathlib import Path

from .entities import extract_entities
from .models import Decision
from .policy import Policy
from .state import StateStore


class Engine:
    def __init__(self, policy: Policy, store: StateStore, audit_path: Path | None = None):
        self.policy = policy
        self.store = store
        self.audit_path = Path(audit_path) if audit_path else None

    def _audit(self, session_id: str, tool: str, decision: str, reason: str, rule: str | None):
        if not self.audit_path:
            return
        self.audit_path.parent.mkdir(parents=True, exist_ok=True)
        line = {"ts": time.time(), "session": session_id, "tool": tool,
                "decision": decision, "reason": reason, "rule": rule}
        with open(self.audit_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(line) + "\n")

    def record_user_prompt(self, session_id: str, prompt: str) -> None:
        st = self.store.load(session_id)
        st.trusted_entities |= extract_entities(prompt)
        self.store.save(st)

    def record_result(self, session_id: str, tool: str, result: object) -> None:
        rule = self.policy.classify(tool)
        if not rule or rule.role != "source" or rule.trust != "untrusted":
            return
        st = self.store.load(session_id)
        st.tainted = True
        st.taint_sources.append(tool)
        st.untrusted_entities |= extract_entities(json.dumps(result, default=str))
        self.store.save(st)
        self._audit(session_id, tool, "taint", "untrusted source result recorded", rule.match)

    def check_call(self, session_id: str, tool: str, args: dict) -> Decision:
        rule = self.policy.classify(tool)
        if rule is None:
            d = Decision("allow", "no rule for tool")
        elif rule.role != "sink":
            d = Decision("allow", f"{rule.role} tool", rule.match)
        else:
            st = self.store.load(session_id)
            if rule.mode == "strict":
                if st.tainted:
                    d = Decision(rule.action, f"session tainted by {', '.join(st.taint_sources)}", rule.match)
                else:
                    d = Decision("allow", "session clean", rule.match)
            else:
                hits = extract_entities(json.dumps(args, default=str)) & (st.untrusted_entities - st.trusted_entities)
                if hits:
                    d = Decision(rule.action, f"args contain untrusted data: {', '.join(sorted(hits))}", rule.match)
                else:
                    d = Decision("allow", "no untrusted data in args", rule.match)
        self._audit(session_id, tool, d.action, d.reason, d.rule)
        return d
