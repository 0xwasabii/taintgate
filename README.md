# taintgate

A small taint-tracking firewall for coding agents. It remembers which tool results came from untrusted places (web pages, email, outside files). When a later call to a sensitive tool (shell, send_email, file writes) could have been influenced by that content, it asks or blocks. The check is plain code, so an injected instruction can't argue with it.

Status: early research prototype (v0.1.0). Portfolio project, barely working on purpose: no sandboxing, no secret scanning, no multi-user anything.

## How it differs from similar tools

[Pipelock](https://www.helpnetsecurity.com/2026/05/04/pipelock-open-source-ai-agent-firewall/) and [HOL Guard](https://hol.org/guard) judge each message or action by itself. taintgate carries provenance across steps: *this shell command comes after the agent read an untrusted page*. The idea follows research systems such as [FIDES](https://www.microsoft.com/en-us/research/publication/securing-ai-agents-with-information-flow-control/) and [RTBAS](https://arxiv.org/html/2502.08966v2), but is small enough to read in one sitting. The evaluation includes an adaptive attacker, motivated by [AutoDojo](https://huggingface.co/papers/2606.15057.md).

## Model

- **Sources** (policy `role: source`): results mark the session tainted and their emails, URLs, hosts and absolute paths are remembered as *untrusted entities*.
- **Sinks** (policy `role: sink`):
  - `mode: strict`: gated whenever the session is tainted.
  - `mode: flow`: gated only if the call's arguments contain an untrusted entity that the user did not type in their own prompt.
- Action on a hit is `ask` or `deny`. Every decision goes to `~/.taintgate/audit.jsonl` (override with `TAINTGATE_HOME`).

Policy is YAML, first match wins, tools are `fnmatch` patterns. See `src/taintgate/default_policy.yaml`.

## Quick start

```bash
git clone https://github.com/0xwasabii/taintgate && cd taintgate
python -m venv .venv && . .venv/bin/activate      # Windows: .venv/Scripts/activate
pip install -e ".[dev]"
pytest                                             # 87 tests, no network needed
taintgate eval --agent scripted --attacker static  # offline end-to-end check
```

Python 3.11+. Runtime deps are only `pyyaml` and `httpx`. LLM-backed evals need `OPENROUTER_API_KEY` (never committed; set it in your environment). AgentDojo runs need `pip install agentdojo`.

## Layout

| Path | What it is |
|---|---|
| `src/taintgate/engine.py`, `state.py`, `entities.py`, `policy.py` | taint engine: per-session state on disk, entity extraction, YAML policy |
| `src/taintgate/adapters/` | Claude Code and Codex hook adapters |
| `src/taintgate/proxy.py` | stdio MCP proxy that gates `tools/call` |
| `src/taintgate/evalkit/` | mock-world benchmark: agents, attackers, baseline defenses, report |
| `src/taintgate/agentdojo_defense.py` | taintgate as an AgentDojo defense |
| `src/taintgate/ui/` | single-file HTML viewer generator |
| `results/`, `docs/results.md`, `docs/agentdojo.md` | raw records and write-ups (bulky traces and logs are gitignored) |
| `docs/superpowers/` | original design spec and implementation plan |

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

## Roadmap / To-do

Ordered roughly by how much each would improve the credibility of the project.

### Policy and engine
- [ ] Fix the policy gaps found on AgentDojo and report them as a **separate** row, not a replacement for the first-run table (avoids tuning on the test set):
  - [ ] Label `get_channels`-style tools whose *names/metadata* can carry injections as sources.
  - [ ] Make fetch tools (`get_webpage`, `WebFetch`) both a source and a sink.
  - [ ] Analyse why flow mode lets banking `injection_task_7` through (7 of 16 pairs).
- [ ] Taint through shell pipelines and through files written then re-read (currently a documented non-goal; start with per-file taint labels).
- [ ] Entity-free attacks in `flow` mode (e.g. `rm -rf *`): add argument-shape rules or a hybrid mode (flow by default, strict for destructive commands).
- [ ] Per-entity provenance in audit log output (which source tainted which argument).
- [ ] Real `ask` UX in the eval (human-in-the-loop simulation) instead of scoring `ask` as `deny`.
- [ ] Policy validation command (`taintgate policy check`) and clearer errors for bad YAML.
- [ ] Policy packs for common MCP servers (filesystem, GitHub, Slack, mail).

### Evaluation
- [ ] Stronger adaptive attacker (stronger attacker model, tool-aware, defense-feedback loops) so the AutoDojo claim can be actually tested; the current one did not beat any defense.
- [ ] Repeated runs with confidence intervals; right now it is one run per cell.
- [ ] More agent models (at least one frontier model, one open-weights model) and a separate judge model so agent and judge are not the same model.
- [ ] Run the remaining AgentDojo suites (workspace, travel) and additional attacks.
- [ ] Compare against more baselines (e.g. CaMeL-style, FIDES/RTBAS-style) where code is available.
- [ ] Stronger LLM-judge baseline against subtler injections.

### Integrations
- [ ] Verify Claude Code and Codex hook formats against current agent versions in CI (contract tests), including Codex on Windows.
- [ ] Support more agents (Cursor, Gemini CLI, etc.).
- [ ] Proxy: HTTP/SSE MCP transports, not only stdio.
- [ ] Publish to PyPI.

### Project hygiene
- [ ] Add a `CONTRIBUTING.md` and issue templates.
- [ ] Type checking (`mypy`) and linting (`ruff`) in CI.
- [ ] Test coverage report.
- [ ] A short write-up / blog post of the findings.

## Contributing

Issues and PRs are welcome. Run `pytest` before sending anything; the suite is offline and takes about 12 seconds.

## License

MIT, see [LICENSE](LICENSE).

## Limits

- No taint through shell pipelines, or through files written and re-read later.
- `flow` mode only sees entities (emails, URLs, hosts, absolute paths); an attack whose arguments contain none (such as `rm -rf *`) gets through. `strict` catches it but costs task completion.
- Hook formats are checked against public docs and the unit tests, not against every agent version.
- This is a demo of an idea, not a security product.
