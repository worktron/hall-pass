---
description: Scan all Claude Code settings files on the machine, extract Bash allow rules, cross-reference against hall-pass's safelist and inspectors, and integrate missing commands. Use this whenever updating hall-pass command coverage from real-world usage data, consolidating scattered allow rules, checking for safelist gaps, or when the user mentions settings files, allow rules, or wants to expand the safelist from usage patterns.
---

# Confiscate Notes

Confiscate the "notes" (always-allow rules) being passed around in Claude Code settings
files and bring them back to hall-pass for proper enforcement. This is a multi-phase workflow —
present findings and wait for user approval before making changes.

## Phase 1: Scan & Extract

Find all Claude Code settings files and extract Bash allow rules using jq:

```bash
find "$HOME" -path "*/.claude/settings*.json" \
  -not -path "*/node_modules/*" \
  -not -path "*/.Trash/*" 2>/dev/null
```

For each file found, extract Bash rules:

```bash
jq -r '.permissions.allow[]? // empty' "$file" 2>/dev/null | grep '^Bash(' || true
```

From each `Bash(...)` rule, extract the base command name — the first word after `Bash(`:
- `Bash(brew install:*)` → `brew`
- `Bash(git -C /path status)` → `git`
- `Bash(PGPASSWORD=x psql:*)` → skip env var prefix, extract `psql`
- `Bash(timeout 30 bun run:*)` → `timeout` (wrappers are handled separately)

Filter out junk entries before analysis:
- Broken shell fragments (`for`, `do`, `done` as standalone entries)
- Absolute paths used as commands (e.g., `/Users/.../some-binary:*`)
- Test entries like `some-unknown-command`
- Overly specific one-shot commands (full commit messages, inline scripts)

Collect: unique command names, which projects use each, frequency count.

## Phase 2: Cross-Reference

Read current hall-pass coverage from source:

1. **SAFE_COMMANDS** from `src/safelist.ts` — commands auto-approved with no inspection
2. **INSPECTORS** from `src/inspectors.ts` — commands with argument-level safety checks
3. **DB_CLIENTS** from `src/safelist.ts` — database clients getting SQL inspection
4. **Wrappers** from `src/wrappers.ts` — transparent wrappers (nohup, nice, timeout)

Categorize each discovered command:
- **Covered** — already in SAFE_COMMANDS, INSPECTORS, DB_CLIENTS, or wrappers
- **New** — not currently handled by hall-pass

## Phase 3: Report & Discuss

Present a clear summary to the user. For **covered** commands, show the count briefly.
For **new** commands, present each with a proposed disposition:

| Command | Projects | Proposed | Reasoning |
|---------|----------|----------|-----------|
| `example` | 3 | SAFE_COMMANDS | Read-only system info |
| `example2` | 2 | INSPECTOR | Has dangerous flag variants |

Propose one of these dispositions for each new command:
- **SAFE_COMMANDS** — read-only tools, standard dev tools, package managers (same risk
  profile as existing entries like pip, npm, brew)
- **INSPECTOR** — commands that proxy other commands (like xargs, xcrun), have
  dangerous subcommands (like defaults read vs write), or dangerous flags
- **DB_CLIENTS** — database clients that should get SQL/query inspection
- **SKIP** — one-off junk, project-specific scripts, commands too niche for the
  general safelist

**STOP HERE and wait for the user to review and approve before proceeding.**
The user prefers to discuss the approach before implementation. Do not auto-implement.

## Phase 4: Implement

After user approval:

### safelist.ts
Add approved commands to the appropriate category. Use the existing section format:
```
// ── Category Name ──────────────────────────────────────────────────
```
Place commands in the most logical existing category, or create a new one if needed.

### inspectors.ts
For commands needing inspectors, follow existing patterns:
- **Proxy commands** (wrap another command): extract inner command, evaluate via
  `ctx.evaluate()` — see `xcrun`, `xargs` for examples
- **Subcommand-based**: safe vs unsafe subcommand sets — see `docker`, `defaults`
- **Flag-based**: check for dangerous flags — see `sed`, `node`
- **Always-prompt**: for inherently dangerous commands — see `ssh`, `osascript`

### Tests
Add tests in `src/inspectors.test.ts` and `src/hook.test.ts`:
- Each SAFE_COMMANDS addition: at least one `expectAllow` test
- Each inspector: tests for both safe (allow) and unsafe (prompt) variants
- Unit tests use `cmd()` helper with `expectAllow`/`expectPrompt`
- Integration tests use `runHook()` with command strings

Run tests: `bun test src/inspectors.test.ts` then `bun test src/hook.test.ts`
(run separately — Bun can segfault under heavy parallel subprocess load).

## Phase 5: Cleanup

After tests pass, confirm with the user before cleaning up settings files.

### Strip Bash rules from settings files

For each settings file that had Bash rules, remove only the `Bash(...)` entries —
keep all non-Bash rules (WebFetch, WebSearch, Read, Skill, etc.) intact:

```bash
jq '.permissions.allow = [.permissions.allow[]? | select(startswith("Bash(") | not)]' \
  "$file" > "$file.tmp" && mv "$file.tmp" "$file"
```

After filtering:
- If `permissions.allow` is empty, check if `permissions` has other keys. If not,
  remove the `permissions` key entirely.
- If the file is now `{}`, delete it.
- If the file has other top-level keys (hooks, enabledPlugins, etc.), keep the file.

### Delete temp files
Remove any `tmp-*` files in the project directory created during this process.

### Final test run
Run the full test suite to verify: `bun test`

## Phase 6: Commit

Commit on a feature branch. The commit message should summarize:
- Number of commands added to SAFE_COMMANDS
- Number of inspectors created
- Number of settings files cleaned
- New test count vs previous
