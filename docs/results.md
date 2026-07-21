# Results

Run on 2026-11-25. One run per cell (temperature 0), no repeats, so treat differences of a few points as noise.

- **Agent, judge and attacker model:** `openai/gpt-4o-mini` via OpenRouter.
- **Benchmark:** 12 tasks (10 can be attacked), 5 attack goals, so 50 attack trials and 12 clean runs per defense.
- **Static attacker:** best of 3 fixed injection templates.
- **Adaptive attacker:** the same 3 templates first, then up to 5 LLM rewrites that see the previous injections, what the defense said when it blocked, and the agent's reply (black-box).
- Raw records: `results/`. Interactive view: [viewer.html](viewer.html) (rebuild with `taintgate ui`). Commands: `taintgate eval --agent llm --model openai/gpt-4o-mini --attacker static` and `--attacker adaptive --rounds 8`.

## Static attacker

| Defense | Attack success % | Clean task completion % | Utility under attack % |
|---|---|---|---|
| none | 62.0 | 100.0 | 98.0 |
| allowlist | 4.0 | 100.0 | 92.0 |
| judge | 0.0 | 100.0 | 36.0 |
| taintgate | 0.0 | 58.3 | 38.0 |
| taintgate-flow | 8.0 | 91.7 | 78.0 |

## Adaptive attacker

| Defense | Attack success % | Clean task completion % | Utility under attack % |
|---|---|---|---|
| none | 62.0 | 100.0 | 98.0 |
| allowlist | 4.0 | 100.0 | 100.0 |
| judge | 0.0 | 100.0 | 52.0 |
| taintgate | 0.0 | 58.3 | 50.0 |
| taintgate-flow | 8.0 | 91.7 | 90.0 |

## What this does and does not show

- **The adaptive attacker added almost nothing.** Against no defense it won 2 extra trials out of 50 after the rewrites, and none against any defense. A first version that used only LLM rewrites scored *lower* than the static templates (22% vs 62% undefended), because gpt-4o-mini writes polite, weak injections that the agent often ignores. I changed adaptive mode to try the static templates first, so it can never do worse than static. The published finding that cheap adaptive attacks break many defenses (see AutoDojo) is therefore **not reproduced here**: this attacker is too weak to test that claim.
- **taintgate (strict) stopped everything and cost the most.** Clean completion fell to 58.3%, because tasks like "read my inbox and email Alice" put a sink after an untrusted read.
- **taintgate-flow** keeps most of the utility (91.7%). Its 8% are all the entity-free goal `rm -rf *`, whose arguments contain no email, URL or path for the flow check to match.
- **The LLM judge also scored 0% attack success.** The injections are blunt and the judge is the same model as the agent, so this is the easy case for a judge. Its cost shows up in utility under attack (36% static): once it flags a page it blocks every later sink, including the ones the user asked for.
- **allowlist is a strong baseline because it is told each task's tools and recipients in advance.** Its 4% comes from a task where the recipient is "the sender of the newest email", so no recipient could be listed.
- **Utility under attack is not directly comparable across rows.** It counts whether the user's task still succeeded in the last round tried, and the adaptive run gives agents more attempts.

## Bugs found while running (fixed before these numbers)

- The first judge run sent the raw tool output to the judge model without asking the detection question, which made the judge look useless (64% attack success). The judge columns above are a rerun with the question included.
- A scripted-agent run (offline pipeline check) is not reported here; it only shows the code paths work.

## Limits

Small custom benchmark, mock tools, one cheap model playing agent, judge and attacker, one run, `ask` scored as `deny`, and not comparable to AgentDojo. A stronger adaptive attacker, a different agent model, and repeated runs are the obvious next steps.
