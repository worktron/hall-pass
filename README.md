# hall-pass

A [PreToolUse hook](https://code.claude.com/docs/en/hooks-guide) for [Claude Code](https://claude.com/claude-code) that auto-approves safe commands, blocks dangerous ones, and protects sensitive files.

## The problem

Claude Code's built-in permission system can't match through pipes. `Bash(grep *)` approves `grep -r foo /path` but **not** `grep -r foo /path | head -20`. Every piped command prompts you, and one-off approvals create a bloated settings file that never generalizes.

## How it works

hall-pass has five layers of inspection, each using a real parser — not regex.

### Layer 1: Bash commands

Uses [shfmt](https://github.com/mvdan/sh) to parse commands into a proper shell AST, then walks the tree to find every command invocation. If every command is in the safelist, it auto-approves.

This correctly handles:
- Pipes: `grep foo | head -20`
- Chains: `git add . && git commit -m "msg"`
- Env var prefixes: `TEST_URL=http://localhost:3334 bun test`
- For/while/if loops: `for f in *.ts; do echo "$f"; done`
- Subshells and command substitution: `echo $(whoami)`
- Redirects: `bun run build 2>&1`
- Nested commands: `echo $(cat $(find . -name foo))`

### Layer 2: Git safety

Git commands get deeper inspection of subcommands and flags. Safe operations are auto-approved; destructive ones prompt.

| Auto-approved | Prompts |
|---|---|
| `git status`, `log`, `diff`, `show`, `branch` | `git push --force`, `push -f` |
| `git add`, `commit`, `stash`, `fetch`, `pull` | `git reset --hard` |
| `git push` (feature branches) | `git clean -f` |
| `git checkout <branch>`, `switch` | `git checkout .`, `restore .` |
| `git merge`, `cherry-pick`, `revert` | `git branch -D` |
| | `git push origin main` (protected branches) |

### Layer 3: SQL safety

Database clients (`psql`, `mysql`, `sqlite3`) get SQL-level inspection using [pgsql-ast-parser](https://github.com/oguimbal/pgsql-ast-parser). Read-only queries are auto-approved; writes prompt.

| Auto-approved | Prompts |
|---|---|
| `psql -c "SELECT * FROM users"` | `psql -c "DROP TABLE users"` |
| `psql -c "SHOW search_path"` | `psql -c "DELETE FROM users"` |
| `psql -c "WITH cte AS (...) SELECT ..."` | `psql -c "INSERT INTO ..."` |
| | `psql` (interactive session, no `-c`) |

### Layer 4: File path protection

Blocks Write/Edit tool calls and Bash commands that target sensitive files. Even safe commands like `cat` can't read protected files.

Default protected paths (always active):
- `**/.env`, `**/.env.*` — environment files
- `**/credentials*`, `**/secret*` — credential files
- `~/.ssh/**`, `~/.aws/**`, `~/.gnupg/**` — key directories
- `**/*.pem`, `**/*id_rsa*` — key files

Configurable protection levels:
- **protected** — blocks all operations (read/write/delete)
- **read_only** — allows reads, blocks writes and deletes
- **no_delete** — allows reads and writes, blocks deletes

### Layer 5: Audit logging

Optional JSON Lines audit log records every decision with timestamp, tool, input, decision, reason, and which layer made the call.

## Setup

### Prerequisites

- [Bun](https://bun.sh)

### Install (npm)

```bash
bun add -g hall-pass
hall-pass-install
```

### Install (from source)

```bash
git clone https://github.com/worktron/hall-pass.git
cd hall-pass
bun install
bun run install
```

This downloads [shfmt](https://github.com/mvdan/sh) (used to parse Bash commands), registers hooks for Bash, Write, and Edit tools in `~/.claude/settings.json`, and sets up non-Bash tool permissions (Read, Glob, Grep, WebFetch, WebSearch).

### Uninstall

```bash
bun run uninstall
```

### Verify

```bash
bun test
```

## Configuration

Configuration is **optional** — everything works with zero config. To customize, create a config file:

```bash
# Generate default config with comments
hall-pass-init
# Or with the install command
bun run install --init
```

Config location: `~/.config/hall-pass/config.toml` (override with `HALL_PASS_CONFIG` env var).

```toml
[commands]
# Additional commands to auto-approve (extends built-in safelist)
safe = ["terraform", "kubectl"]
# Additional database clients for SQL inspection
db_clients = ["pgcli"]

[git]
# Additional protected branches (extends main, master, staging, production, prod)
protected_branches = ["release"]

[paths]
# Block ALL operations on these paths
protected = ["**/production.env"]
# Allow reads, block writes and deletes
read_only = ["**/config/prod/**"]
# Allow reads and writes, block deletes
no_delete = ["**/migrations/**"]

[audit]
# Enable audit logging
enabled = true
# Log file path (default: ~/.config/hall-pass/audit.jsonl)
path = "~/.config/hall-pass/audit.jsonl"

[debug]
# Enable debug output to stderr
enabled = true
```

User config values **extend** built-in defaults — they never replace them.

## Debug mode

Enable debug output to see exactly how hall-pass makes decisions:

```bash
# Via env var (one-off)
HALL_PASS_DEBUG=1 claude

# Via config (persistent)
# Set debug.enabled = true in config.toml
```

Debug output goes to stderr so it never interferes with the hook's exit code. Format:

```
[hall-pass] input: {"toolName":"Bash","toolInput":{"command":"git status"}}
[hall-pass] commands: ["git"]
[hall-pass] git: {"args":"git status","safe":true}
```

## Audit log

When enabled, writes one JSON line per decision to `~/.config/hall-pass/audit.jsonl`:

```json
{"ts":"2025-01-15T10:30:00.000Z","tool":"Bash","input":"git status","decision":"allow","reason":"all commands safe","layer":"safelist"}
{"ts":"2025-01-15T10:30:01.000Z","tool":"Write","input":"/project/.env","decision":"prompt","reason":"matches protected path **/.env","layer":"paths"}
```

Fields: `ts` (ISO 8601), `tool` (Bash/Write/Edit), `input` (command or file path), `decision` (allow/prompt), `reason` (human-readable), `layer` (safelist/git/sql/paths/unknown).

## How the hook decides

```
Input from Claude Code: { tool_name, tool_input }
         |
         v
   Load config + init debug/audit
         |
         +-- Write/Edit tool?
         |     Check file path against protection rules
         |     Protected → prompt | Safe → allow
         |
         +-- Bash tool?
               Parse command with shfmt
               |
               For each command invocation:
               |
               +-- Path args match protected files? → prompt
               |
               +-- In safelist? → allow
               |
               +-- git? → inspect subcommand + flags
               |          safe op? → allow
               |          destructive? → prompt
               |
               +-- psql/mysql/sqlite3? → parse SQL
               |          read-only? → allow
               |          write? → prompt
               |
               +-- unknown → prompt
```

## Project structure

```
src/
  hook.ts        Entry point — reads stdin, routes by tool, checks all layers
  parser.ts      AST walker — extracts command names from shfmt JSON
  safelist.ts    Safe commands, inspected commands, DB clients
  git.ts         Git subcommand + flag safety checker
  sql.ts         SQL statement read-only checker
  config.ts      TOML config loading with defaults and merging
  paths.ts       File path protection with glob matching
  debug.ts       Debug logging to stderr
  audit.ts       Audit logging to JSON Lines file
  cli.ts         CLI for hall-pass-init
  install.ts     Registers hooks in ~/.claude/settings.json
  uninstall.ts   Removes hooks
  *.test.ts      Tests
```

## License

MIT
