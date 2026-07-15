LIMITS = (
    "**Limits.** Small custom benchmark (12 tasks, 5 attack goals), mock tools, one agent model, a cheap "
    "black-box attacker with a few rounds. `ask` decisions count as `deny`. The allowlist baseline knows each "
    "task's tools and recipients in advance, which a real deployment would not. Numbers show the shape of the "
    "tradeoff, not a security guarantee, and are not comparable to AgentDojo results."
)


def _pct(xs: list[bool]) -> float | None:
    return round(100 * sum(xs) / len(xs), 1) if xs else None


def summarize(records: list[dict]) -> dict:
    out: dict = {}
    for name in dict.fromkeys(r["defense"] for r in records):
        att = [r for r in records if r["defense"] == name and r["kind"] == "attack"]
        clean = [r for r in records if r["defense"] == name and r["kind"] == "clean"]
        out[name] = {
            "asr": _pct([r["attack_success"] for r in att]),
            "clean_completion": _pct([r["task_success"] for r in clean]),
            "utility_under_attack": _pct([r["task_success_attacked"] for r in att]),
            "n_attack": len(att), "n_clean": len(clean),
        }
    return out


def to_markdown(summary: dict) -> str:
    rows = ["| Defense | Attack success % | Clean task completion % | Utility under attack % |",
            "|---|---|---|---|"]
    for name, s in summary.items():
        rows.append(f"| {name} | {s['asr']} | {s['clean_completion']} | {s['utility_under_attack']} |")
    return "\n".join(rows) + "\n\n" + LIMITS + "\n"
