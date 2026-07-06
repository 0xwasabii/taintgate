import json
import os
import re
import tempfile
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class SessionState:
    session_id: str
    tainted: bool = False
    taint_sources: list[str] = field(default_factory=list)
    untrusted_entities: set[str] = field(default_factory=set)
    trusted_entities: set[str] = field(default_factory=set)


class StateStore:
    def __init__(self, root: Path):
        self.root = Path(root)

    def _path(self, session_id: str) -> Path:
        return self.root / (re.sub(r"[^A-Za-z0-9_-]", "_", session_id) + ".json")

    def load(self, session_id: str) -> SessionState:
        try:
            d = json.loads(self._path(session_id).read_text(encoding="utf-8"))
            return SessionState(
                session_id=session_id,
                tainted=bool(d["tainted"]),
                taint_sources=list(d["taint_sources"]),
                untrusted_entities=set(d["untrusted_entities"]),
                trusted_entities=set(d["trusted_entities"]),
            )
        except (OSError, ValueError, KeyError, TypeError):
            return SessionState(session_id)

    def save(self, state: SessionState) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        data = {
            "tainted": state.tainted,
            "taint_sources": state.taint_sources,
            "untrusted_entities": sorted(state.untrusted_entities),
            "trusted_entities": sorted(state.trusted_entities),
        }
        fd, tmp = tempfile.mkstemp(dir=self.root, suffix=".tmp")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f)
        os.replace(tmp, self._path(state.session_id))
