# taintgate

A small taint-tracking firewall for coding agents. It remembers which tool results came from untrusted places (web pages, email, outside files). When a later call to a sensitive tool (shell, send_email, file writes) could have been influenced by that content, it asks or blocks. The check is plain code, so an injected instruction can't argue with it.

Portfolio project, barely working on purpose: no sandboxing, no secret scanning, no multi-user anything.

## How it differs from similar tools

[Pipelock](https://www.helpnetsecurity.com/2026/05/04/pipelock-open-source-ai-agent-firewall/) and [HOL Guard](https://hol.org/guard) judge each message or action by itself. taintgate carries provenance across steps: *this shell command comes after the agent read an untrusted page*. The idea follows research systems such as [FIDES](https://www.microsoft.com/en-us/research/publication/securing-ai-agents-with-information-flow-control/) and [RTBAS](https://arxiv.org/html/2502.08966v2), but is small enough to read in one sitting. The evaluation includes an adaptive attacker, motivated by [AutoDojo](https://huggingface.co/papers/2606.15057.md).

## Model

- **Sources** (policy `role: source`): results mark the session tainted and their emails, URLs, hosts and absolute paths are remembered as *untrusted entities*.
- **Sinks** (policy `role: sink`):
  - `mode: strict`: gated whenever the session is tainted.
  - `mode: flow`: gated only if the call's arguments contain an untrusted entity that the user did not type in their own prompt.
- Action on a hit is `ask` or `deny`. Every decision goes to `~/.taintgate/audit.jsonl` (override with `TAINTGATE_HOME`).

Policy is YAML, first match wins, tools are `fnmatch` patterns. See `src/taintgate/default_policy.yaml`.

## Use it

```bash
pip install -e ".[dev]"

# Claude Code: merge hooks into your settings
taintgate install claude --write ~/.claude/settings.json

# Codex: see docs/codex-hooks.md (same hook shape; ask is mapped to deny)
taintgate install codex

# Any MCP server: wrap it
taintgate proxy --name mail -- npx some-mail-mcp-server
```

Sessions are separate: taint in one session never gates another.

## Evaluation

```bash
taintgate eval --agent scripted --attacker adaptive --rounds 4        # offline, free
taintgate eval --agent llm --model openai/gpt-4o-mini --attacker adaptive --rounds 8   # needs OPENROUTER_API_KEY
```

Mock inbox/web/email/shell tools, 12 tasks, 5 attack goals. Defenses compared: `none`, `allowlist` (per-task tools and recipients, an oracle-ish baseline), `judge` (injection detector), `taintgate`, `taintgate-flow`. 

Headline (gpt-4o-mini, static attacker, 50 attack trials per defense): undefended 62% attack success; allowlist 4%; LLM judge 0%; taintgate strict 0% but only 58% of clean tasks complete; taintgate-flow 8% with 92% completion. My cheap adaptive attacker did not beat any defense, so this does **not** reproduce the "adaptive attacks break defenses" result. Details and caveats: [docs/results.md](docs/results.md).

## AgentDojo

```bash
pip install agentdojo
taintgate agentdojo --suite banking --defense taintgate-flow --trace-mode executed
python scripts/agentdojo_table.py
```

On AgentDojo v1.2.2 (banking + slack, 249 attacked pairs, gpt-4o-mini) attack success fell from 55% to 12% (strict) and 16% (flow), at a large utility cost, and it did not beat every baseline. Method, caveats and the policy gaps I found are in [docs/agentdojo.md](docs/agentdojo.md).

## Viewer

```bash
taintgate ui --out docs/viewer.html     # one self-contained HTML file, open it in a browser
```

Four tabs: results (trade-off chart, numbers, per-attack heatmap, static/adaptive toggle), every trial with filters, the decision log from `~/.taintgate/audit.jsonl` (falls back to `results/demo-audit.jsonl`), and the active policy. The built copy is [docs/viewer.html](docs/viewer.html).

## Limits

- No taint through shell pipelines, or through files written and re-read later.
- `flow` mode only sees entities (emails, URLs, hosts, absolute paths); an attack whose arguments contain none (such as `rm -rf *`) gets through. `strict` catches it but costs task completion.
- Hook formats are checked against public docs and the unit tests, not against every agent version.
- This is a demo of an idea, not a security product.
