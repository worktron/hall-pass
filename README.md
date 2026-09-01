# hall-pass

A [PreToolUse hook](https://code.claude.com/docs/en/hooks-guide) for [Claude Code](https://claude.com/claude-code) that auto-approves safe commands, blocks dangerous ones, and protects sensitive files. It also runs under [Codex](https://developers.openai.com/codex) — see [Codex](#codex).

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
| `git symbolic-ref <ref>` (read) | `git symbolic-ref HEAD <ref>` (repoints HEAD) |
| `git add`, `commit`, `stash`, `fetch`, `pull` | `git reset --hard` |
| `git rm`, `mv`, `apply`, `init`, `clone` | `git clean -f` |
| `git push` (feature branches) | `git checkout .`, `restore .` |
| `git checkout <branch>`, `switch` | `git branch -D` |
| `git merge`, `cherry-pick`, `revert` | `git push origin main` (protected branches) |

A variable in the command line keeps its place: `git -C $DIR reset --hard` is read as a `reset --hard`, not as bare `git`. (Expansions render as `$NAME` / `$(...)` placeholders in the parsed arguments, which can never match a protected path or branch name.)

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

### Layer 5: Audit logging + outcome monitoring

A JSON Lines audit log (on by default; past ~5MB it rotates to timestamped archives that `stats`/`eval` still read) records every decision with timestamp, tool, input, decision, reason, and which layer made the call. Each entry also carries the session, permission mode, and `tool_use_id` from Claude Code.

Two observe-only hooks close the loop: a PostToolUse hook records when a tool call actually ran (same `tool_use_id` as its decision), and a Notification hook records when Claude Code shows a native permission prompt. Joining decisions to completions tells you whether the user approved each prompt hall-pass raised:

```bash
bun run stats   # decision mix, approval rate per prompt reason, safelist gap candidates
bun run eval    # replay recorded traffic through the current decide() and diff
```

`eval` turns the audit log into a labeled regression corpus for policy changes: edit the safelist/inspectors (or point `HALL_PASS_CONFIG` at a candidate config), replay every recorded decision, and see exactly which real prompts disappear (wins), which allows start prompting (regressions), and — the failure condition — whether any prompt the user did NOT approve would now auto-allow (exit 1). On an unchanged working tree the diff is empty.

A prompt reason that is always approved is a safelist gap; one that is frequently declined is earning its keep. ("Not run" conflates user-denied with interrupted — Claude Code has no hook that reports the user's actual choice.)

## Auto mode: judgment calls go to the classifier

A hook that answers `ask` forces a permission prompt in **every** permission mode — Claude Code's docs say so, and auto mode makes no exception. In auto mode Claude Code has its own reviewer, a classifier that reads the command and the conversation around it and approves routine work silently. So in auto mode an `ask` from hall-pass for a judgment call — is this `rm`, `sudo`, `ssh`, inline `perl`, in-place `sed`, database write, or unknown git subcommand what you meant? — is a prompt that would not otherwise exist.

The audit log from a month of real use said it plainly: in auto mode, a hall-pass `ask` was followed by a visible prompt 76% of the time and a hall-pass `pass` (no opinion) 2% of the time; both ran 96% of the time. hall-pass was the source of nine prompts in ten, and the user approved nearly all of them.

So hall-pass is mode-aware. In `auto` mode (and `bypassPermissions`, which is the user saying "don't ask"), it hands judgment calls to the classifier — it answers nothing, and Claude Code proceeds through its own review. It still answers `ask` for the **hard stops**, in every mode:

- reads, writes, or redirects to protected paths (`~/.ssh`, `.env`, `*.pem`, …)
- a hardcoded secret in a command or in file content
- a known data-exfiltration domain
- piping downloaded content into a shell (`curl … | bash`)
- code-injecting environment variables (`LD_PRELOAD`, `DYLD_INSERT_LIBRARIES`, `BASH_ENV`, …)
- git config keys that execute commands (`core.hooksPath`, …)
- `git push` to a protected branch (`main`, `staging`, …) — the classifier approves pushes to any branch of the working repo, and a human checkpoint before those branches is the whole point of listing them

In `default` (Manual) and `acceptEdits` mode nothing changes: Claude Code would prompt natively for the same command, so hall-pass's `ask` costs nothing and carries a better message. `allow` decisions are unchanged in every mode — a safelisted command never waits on the classifier.

Deferred decisions are recorded in the audit log as `pass` with reason `deferred: <original reason>`, so `bun run stats` shows what would have prompted in Manual mode and whether the classifier let it through, and `bun run eval` lists what a policy change hands over. To turn this off and prompt for everything as before, set `[classifier] defer = false` in the config.

To take hall-pass out of a single session entirely — every decision left to Claude Code, no audit entries — start that session with `HALL_PASS=off` in its environment. The hook stays installed for everything else. This is the switch for a launcher that runs many hands-off sessions and wants Claude Code's own review alone.

## Codex

Codex's hook protocol is a clone of Claude Code's (same stdin fields, same `hookSpecificOutput` shape), so the whole decision pipeline runs unchanged. What differs is what a hook may say back, and hall-pass adapts at the edge (`src/codex.ts`):

- **Codex has no hook "ask".** `permissionDecision: "ask"` is parsed but unsupported: Codex marks the hook failed and runs the tool anyway. So under Codex, **hard stops are denied** — protected paths, hardcoded secrets, code injection (`curl | bash`, `LD_PRELOAD`), exfiltration domains, pushes to protected branches. Set `codex.deny_hard_stops = false` to downgrade them to a warning and let Codex's sandbox and approval prompt decide.
- **Judgment calls are never denied.** `rm`, `sudo`, `ssh`, inline `perl`, an unknown command: hall-pass shows its reason as a warning and leaves the prompt to Codex.
- **Skipping the prompt happens on `PermissionRequest`.** That event fires only when Codex is about to ask you (a sandbox escalation, network access). hall-pass answers "allow" for commands it judges safe, "deny" for hard stops, and stays silent otherwise so the native prompt stands.
- **File edits arrive as `apply_patch`.** There is no Write or Edit tool; hall-pass parses the patch (`src/patch.ts`) and applies the same path protection and secret scan to every file in it — including `apply_patch <<'EOF'` sent through the shell.
- **Outcome monitoring works the same.** Audit entries carry `host: "codex"`; a `PermissionRequest` hall-pass leaves alone is recorded as a native prompt.

Codex skips a new or changed hook until you trust it: after installing, open a Codex session and run `/hooks`.

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
bun run setup
```

This downloads [shfmt](https://github.com/mvdan/sh) (used to parse Bash commands), registers hooks for Bash, Write, and Edit tools in `~/.claude/settings.json`, and sets up non-Bash tool permissions (Read, Glob, Grep, WebFetch, WebSearch).

If you run more than one Claude account via `CLAUDE_CONFIG_DIR`, the hooks are registered in that directory's `settings.json` instead. Run setup once per account, from a session of that account. hall-pass's own config and audit log live in `~/.config/hall-pass/` and are shared by every account.

### Install for Codex

```bash
bun run setup:codex        # or: hall-pass-install --codex
```

Registers `PreToolUse`, `PermissionRequest`, and `PostToolUse` hooks for `Bash` and `apply_patch` in `~/.codex/hooks.json`. Both installs can coexist; they share the config file and the audit log. Then run `/hooks` inside Codex to trust the new hook definition.

### Uninstall

```bash
bun run uninstall            # Claude Code
bun run uninstall:codex      # Codex
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
# Or with the setup command
bun run setup --init
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
# Additional git subcommands to auto-approve (extends the built-in safe set)
safe_subcommands = ["lfs", "subtree"]

[paths]
# Block ALL operations on these paths
protected = ["**/production.env"]
# Allow reads, block writes and deletes
read_only = ["**/config/prod/**"]
# Allow reads and writes, block deletes
no_delete = ["**/migrations/**"]

[audit]
# Audit logging is on by default; set false to disable
enabled = true
# Log file path (default: ~/.config/hall-pass/audit.jsonl)
path = "~/.config/hall-pass/audit.jsonl"

[classifier]
# In auto mode (and bypassPermissions), hand judgment calls to Claude Code's
# classifier instead of forcing a prompt. Hard stops always prompt. Default true.
defer = true

[codex]
# Codex hooks cannot "ask", so hard stops are denied there. Set false to
# downgrade them to a warning and let Codex's sandbox and prompt decide.
# Judgment calls are never denied. Default true.
deny_hard_stops = true

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

Fields: `ts` (ISO 8601), `tool` (Bash/Write/Edit), `input` (command or file path), `decision` (allow/prompt/pass/feedback), `reason` (human-readable; a judgment call handed to the auto-mode classifier is a `pass` with reason `deferred: <what would have prompted>`), `layer` (safelist/git/sql/paths/classifier/unknown), plus `session`, `mode` (Claude Code's permission mode), and `tool_use_id`.

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
               +-- unknown → pass (no opinion; Claude Code decides)
               |
               Then, in auto mode / bypassPermissions:
                 hard stop (protected path, secret, injection,
                 push to protected branch)? → prompt, as in every mode
                 any other prompt?          → pass — the classifier judges it
```

## Project structure

```
src/
  hook.ts        Claude Code entry point — reads stdin, emits the decision
  codex-hook.ts  Codex entry point — same pipeline, Codex's output protocol
  codex.ts       Decision → Codex output mapping (deny hard stops, no "ask")
  decide.ts      The decision: pre-parse hard stops, per-command evaluation,
                 auto-mode deferral (DEFER_MODES)
  patch.ts       apply_patch parser + path/secret checks over each file
  diag.ts        Diagnostic log shared by the entry points
  parser.ts      AST walker — extracts command names from shfmt JSON
  safelist.ts    Safe commands, inspected commands, DB clients
  git.ts         Git subcommand + flag safety checker
  sql.ts         SQL statement read-only checker
  config.ts      TOML config loading with defaults and merging
  paths.ts       File path protection with glob matching
  debug.ts       Debug logging to stderr
  audit.ts       Audit logging to JSON Lines file
  cli.ts         CLI for hall-pass-init
  install.ts     Registers hooks in ~/.claude/settings.json (--codex: ~/.codex/hooks.json)
  uninstall.ts   Removes hooks (--codex for Codex)
  *.test.ts      Tests
```

## License

MIT
