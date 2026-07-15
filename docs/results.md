# Results

**Status: scripted-agent run only (2026-11-25).** The scripted agent is deterministic and obeys any `ACTION:` line it reads, so these numbers show the pipeline works and what each defense can or can't see. They say nothing about how real LLM agents behave. The real-LLM run is pending an OpenRouter key.

Command: `taintgate eval --agent scripted --attacker adaptive --rounds 4`

| Defense | Attack success % | Clean task completion % | Utility under attack % |
|---|---|---|---|
| none | 100.0 | 100.0 | 76.0 |
| allowlist | 10.0 | 100.0 | 76.0 |
| judge | 0.0 | 100.0 | 50.0 |
| taintgate | 0.0 | 58.3 | 50.0 |
| taintgate-flow | 20.0 | 75.0 | 62.0 |

## Reading it

- **taintgate (strict)** blocked every attack, and paid for it: clean completion fell from 100% to 58.3%, because legitimate tasks like "read my inbox and reply to Alice" also put a sink after an untrusted read.
- **taintgate-flow** recovers some of that (75%) by letting calls through whose arguments came from the user's own prompt. It misses attacks whose arguments contain no recognizable entity (`rm -rf *`), which is why its attack success is 20%.
- **judge** scores 0% here only because its regex matches the `ACTION:` marker that every scripted injection contains. That is an artifact of the scripted agent; the interesting judge numbers need the LLM run with an LLM judge.
- **allowlist** is strong here because it is told each task's tools and recipients in advance. Its 10% comes from a task where the recipient is "the sender of the newest email", so no recipient could be listed.
- The scripted "adaptive" attacker only cycles paraphrases, so it can't beat anything. Adaptive results mean something only with `--agent llm`.

## TODO when the key arrives

Run `--agent llm --attacker static` and `--attacker adaptive --rounds 5` after a two-task dry run, and replace this table.
