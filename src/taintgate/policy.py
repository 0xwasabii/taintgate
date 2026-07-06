import fnmatch
import os
from dataclasses import dataclass, field
from importlib import resources
from typing import Literal

import yaml

ROLES = ("source", "sink", "neutral")
TRUSTS = ("untrusted", "trusted")
MODES = ("strict", "flow")
ACTIONS = ("ask", "deny")


@dataclass(frozen=True)
class Rule:
    match: str
    role: Literal["source", "sink", "neutral"]
    trust: Literal["untrusted", "trusted"] = "untrusted"
    mode: Literal["strict", "flow"] = "strict"
    action: Literal["ask", "deny"] = "ask"

    def __post_init__(self):
        for name, allowed in (("role", ROLES), ("trust", TRUSTS), ("mode", MODES), ("action", ACTIONS)):
            if getattr(self, name) not in allowed:
                raise ValueError(f"rule {self.match!r}: invalid {name} {getattr(self, name)!r}")


@dataclass
class Policy:
    rules: list[Rule] = field(default_factory=list)

    def classify(self, tool_name: str) -> Rule | None:
        for rule in self.rules:
            if fnmatch.fnmatchcase(tool_name, rule.match):
                return rule
        return None


def load_policy(path: str | os.PathLike | None = None) -> Policy:
    if path is None:
        text = resources.files("taintgate").joinpath("default_policy.yaml").read_text(encoding="utf-8")
    else:
        with open(path, encoding="utf-8") as f:
            text = f.read()
    data = yaml.safe_load(text) or {}
    return Policy([Rule(**r) for r in data.get("rules", [])])
