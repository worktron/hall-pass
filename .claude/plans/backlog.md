# Backlog

Unclaimed tickets for hall-pass, one `## ` section each, in metamax's record shape
(`~/Workspace/metamax/.claude/plans/coordinator.md`, "The record"). `/spawn <id>` starts
one; its landing commit deletes the section.

## app-kit-adoption · Install app-kit and use its command-line pieces in hall-pass

Goal: replace this project's own copies of what app-kit holds, so a fix made once reaches every app and every app behaves the same. With what app-kit has today: nothing yet: app-kit's command-line and test start-up pieces are not built. Then, as each lands in app-kit: command-line, for src/cli.ts's usage (which follows the rule) and its missing --version, and src/jev-label.ts:79-84's op read; test-start-up where the project runs bun test. Paths are at main of 2026-10-28. Install or upgrade with `bun add github:worktron/app-kit#<latest tag>` (README "Taking it in"). Found by app-kit's workspace sweep, 2026-10-28 (app-kit .claude/plans/workspace-sweep.md, main 76b680d); the owner's aim is wider use of app-kit and the same behavior in every app.
Done when: each copy named above is deleted and the app-kit piece is used in its place, the project's own tests and browser tests pass on it, and what changed for a person using the app (if anything) is said in the landing; the later pieces are each a follow-up section in this project's plans once they land in app-kit.
Do not touch: anything app-kit has no piece for; app-kit itself (a gap found while moving goes back to app-kit as a ticket there).
Needs: nothing for the first part; each later piece needs its app-kit ticket landed.
Touches: the command's files, its tests, package.json, bun.lock.

## audit-log-redact · The audit log blanks API keys before it keeps a command

Goal: hall-pass's audit log (`~/.config/hall-pass/audit.jsonl` and its rotated archives) stops keeping keys in plain text. Each decision line keeps the command as typed, so a key typed into a command sits in the log: the same commands that put four real Anthropic keys into metamax's permission log until 2026-11-02 are in this log too, along with Clerk, Twilio, AWS and 1Password values. Metamax now blanks key-shaped text to `[redacted]`, by prefix to the next separator whatever its length (metamax `server/lib/redact-secrets.ts`, commit bbd35d36). Use the same rules here, copied or shared, before `audit.log` writes `input`. Then do a one-off blanking of the existing log and archives, on the owner's yes. Metamax joins its permission rows to this log by call id, and by the first sixty or so characters of the command for Codex rows, which carry no id. Blanking here changes that prefix, so check metamax's join (`decisionForCall` in metamax `server/live/approvals.ts`) still matches a blanked line to a blanked row.
Done when: a test feeds a made-up key through hall-pass's decision path and the audit line holds `[redacted]` in its place; after the owner approves the cleanup, `grep -c 'sk-ant-api03-\|sk-ant-usr-'` on the live audit log and its archives prints 0.
Do not touch: revoking the leaked keys (the owner does that in each vendor's console); Claude Code's transcripts.
Needs: nothing.
Touches: src/audit.ts, src/decide.ts, their tests, the live audit log only on the owner's yes.

## railway-ssh-points-at-production-read · An agent reaching for a production database by hand is told about the read command
Goal: fleet's `bun ~/Workspace/fleet/bin/production-read.ts "<one query>"` is how an agent reads an owned app's production Postgres, and hall-pass already allows it, but only one instruction line says so. An agent that misses that line tries `railway ssh` or `railway variables` with a database query, Claude Code's auto mode refuses it as a production read, and the agent is stuck where a Getter thread was on 2026-11-02. When hall-pass sees such a command, have it tell the agent about the read command along with whatever it decides. The first thing to find out is whether hall-pass can say something to the agent without changing the decision. It stays a pointer only: this does not allow or refuse anything new, and it never tells the agent to work around a refusal.
Done when: a hall-pass test shows a `railway ssh` command carrying a database query getting the pointer text and the same decision as before, and a plain `railway ssh` with no database query getting neither.
Do not touch: what hall-pass allows or refuses, the production read command itself.
Needs: none.
Touches: hall-pass's Bash evaluation and its tests.

## env-split-string-push · A protected-branch push inside `env -S` is a hard stop

Goal: `env -S 'git push origin main'` gets the same hard stop as `git push origin main`. Today the env inspector (src/inspectors.ts, the `env` entry, as of main 4b85c61) makes every env flag it does not list (`-S`, `-C`, `-P`) a judgment call, a hard stop only when the words mention op, so in auto mode the push goes to Claude Code's classifier and the protected-branch check in src/git.ts never runs. Main before 4b85c61 abstained on it the same way. An earlier attempt split the `-S` string on whitespace and judged the command inside; quoted words in the string then hid the command, so it was dropped (hall-pass PR #59 review, 2026-11-06). Read the string the way env does (quotes, backslashes, `${VAR}`), or hard-stop any `-S` whose words name git push to a protected branch.
Done when: a test shows `env -S 'git push origin main'` and `env -S'X=1 git push --force origin main'` are hard stops in auto mode, and `env -S 'bun test'` is not.
Do not touch: how `env -- <command>` and `env VAR=x <command>` are judged.
Touches: src/inspectors.ts (env), src/inspectors.test.ts, src/hook.test.ts.
