from dataclasses import dataclass
from typing import Literal


@dataclass(frozen=True)
class Decision:
    action: Literal["allow", "ask", "deny"]
    reason: str
    rule: str | None = None
