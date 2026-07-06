# taintgate: design

A small provenance-aware firewall for coding agents. It tracks which tool results came from untrusted sources (web, email, outside files) and gates sensitive sinks (shell, send_email, network writes) when untrusted data may have influenced the call. The check is deterministic code, not a model, so an injection cannot talk its way past it.

Portfolio project. "Barely working" is the bar. No enterprise, multi-tenant or HA concerns.

## Why

Pipelock (Go) and HOL Guard (Python) gate each action on its own. FIDES and RTBAS (research) show taint/IFC works on AgentDojo but only against static attacks. AutoDojo shows a cheap black-box adaptive attack recovers attack success against most defenses that looked strong against static injections. taintgate's differentiator is (1) a readable taint model and (2) an evaluation that includes an adaptive attacker and reports the utility cost honestly.

## Goals

- Hook adapters for Claude Code and Codex, plus a stdio MCP proxy for any MCP client.
- A YAML policy that classifies tools as sources (untrusted/trusted), sinks (high/medium), or neutral.
- Two taint modes: `strict` (session tainted, then every matching sink is gated) and `flow` (gate only if the call's arguments contain entities that appeared in untrusted content and were not in the user's own prompt).
- JSONL audit log of every decision.
- Eval harness: mock tools, about 12 tasks, about 5 injection goals, agents (scripted and OpenRouter LLM), defenses (none, allowlist, LLM-judge filter, taintgate), static and adaptive attackers. Reports ASR and task completion per defense.

## Non-goals

- No sandboxing, no network egress control, no secret scanning (that's Pipelock's job).
- No taint tracking through shell pipelines or file contents written then re-read.
- No claim of security against a real adversary. The README states the eval's limits.

## Anti-goals

- Becoming a Pipelock clone (regex scanners).
- Eval numbers presented without the utility cost or without saying the benchmark is small and custom.

## Decisions (my calls)

- Python 3.11+, argparse, PyYAML, httpx, pytest. No framework.
- Session state lives on disk (hooks are one-shot processes), keyed by `session_id`.
- `ask` has no human in the eval, so it is scored as deny.
- Provider for eval LLMs: OpenRouter (OpenAI-compatible chat API), key via `OPENROUTER_API_KEY`.
- Default eval models: cheap tier, configurable.

## Approaches considered

A. Standalone proxy + hooks + mock-agent harness (chosen). B. Hooks only. C. Run on real AgentDojo (too heavy for the goal).
