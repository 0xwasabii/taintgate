import json
from dataclasses import asdict
from datetime import date
from importlib import resources
from pathlib import Path

from ..policy import load_policy

NOTES = [
    "One run per cell at temperature 0, 50 attack trials per defense. Differences of a few points are noise.",
    "The same cheap model plays the agent, the judge and the attacker. Results do not transfer to other models.",
    "The adaptive attacker rarely beat the static one, so these numbers do not show whether adaptive attacks break these defenses.",
    "The allowlist is told each task's tools and recipients in advance, so it is a stronger baseline than a real deployment could build.",
    "Flow mode only sees emails, URLs, hosts and absolute paths, so an attack with none of those (rm -rf *) gets through it.",
]


def _read_jsonl(path: Path) -> list[dict]:
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
    return out


def build_data(results_dir: Path, audit_path: Path | None, policy_path: Path | None) -> dict:
    results = {}
    for mode in ("static", "adaptive"):
        f = Path(results_dir) / f"results-{mode}.json"
        results[mode] = json.loads(f.read_text(encoding="utf-8")) if f.exists() else []
    meta_file = Path(results_dir) / "meta.json"
    meta = json.loads(meta_file.read_text(encoding="utf-8")) if meta_file.exists() else {}
    meta["generated"] = date.today().isoformat()
    audit = _read_jsonl(Path(audit_path)) if audit_path and Path(audit_path).exists() else []
    if audit_path:
        meta["auditNote"] = f"Source: {Path(audit_path).name}."
    policy = [asdict(r) for r in load_policy(policy_path).rules]
    return {"results": results, "audit": audit, "policy": policy, "meta": meta, "notes": NOTES}


def render(data: dict) -> str:
    template = resources.files("taintgate.ui").joinpath("template.html").read_text(encoding="utf-8")
    payload = json.dumps(data).replace("</", "<\/")
    return template.replace("/*__DATA__*/null", payload)


def build_viewer(out: Path, results_dir: Path, audit_path: Path | None = None, policy_path: Path | None = None) -> Path:
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render(build_data(results_dir, audit_path, policy_path)), encoding="utf-8")
    return out
