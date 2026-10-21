# Backlog

Unclaimed tickets for hall-pass, one `## ` section each, in metamax's record shape
(`~/Workspace/metamax/.claude/plans/coordinator.md`, "The record"). `/spawn <id>` starts
one; its landing commit deletes the section.

## asked-by-command · metamax asks hall-pass for a decision and its Codex hook by command

Goal: metamax stops reading hall-pass's files by path. Today it reads `~/.config/hall-pass/audit.jsonl`
to explain a permission prompt (metamax `server/live/approvals.ts:71`) and builds the Codex hook
by renaming `hook.ts` to `codex-hook.ts` in the registered command (`server/live/permissions.ts:38`).
hall-pass gains two commands on the PATH: one that prints the decision and reason for a
tool_use_id as JSON, and one that prints the command to register as a Codex hook. Metamax then
asks those, and shows nothing extra when hall-pass is absent. Decided by the owner on
2026-10-21 (metamax `.claude/plans/fleet-principles-matamax.md`, "Metamax" item 3).
Done when: both commands exist with tests; given a tool_use_id in the audit log the first prints
its layer and reason, and an unknown id exits non-zero with nothing on stdout; the second prints
the same command metamax derives today.
Do not touch: hall-pass's policy and its hook's decisions.
Needs: none.
Touches: hall-pass's CLI entry and tests.
