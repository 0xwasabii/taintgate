# Codex hooks notes

Source: https://developers.openai.com/codex/hooks (checked 2026-11-25 via search summary, not the full page).

- Hooks live in `~/.codex/hooks.json`, `~/.codex/config.toml` or `<repo>/.codex/` equivalents.
- Events include PreToolUse / PostToolUse; blocking uses `hookSpecificOutput.permissionDecision: "deny"` or exit code 2.
- Older docs said matchers fire only for Bash and flagged Windows as unsupported. Re-check before relying on it.
- `taintgate` maps `ask` to `deny` for Codex since only deny is confirmed.
- For MCP tools in Codex, use `taintgate proxy` in `~/.codex/config.toml` as a fallback.
