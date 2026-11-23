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

## op-question-names-the-command · The 1Password question names the command, never a flag's value

Goal: when hall-pass asks about an `op` command, its question names the command (`op read`, `op item get`), never a flag's value. Today `op --account rides read op://agents/x/credential` asks `"op: rides" can reveal a 1Password secret`: the label takes the first word that does not start with `-` (src/inspectors.ts, the op inspector's `shownNoun, shownVerb` line, main 4b85c61), which is the account name. The decision is right; only the words are wrong. Build the label from the same argument walker that finds the command (`opCommandWords`), falling back to "op" when the walker cannot follow the flags.
Done when: a test shows the question for `op --account rides read op://agents/x/credential` says "op: read", and for `op --format json item get Key` says "op: item get".
Touches: src/inspectors.ts (op), src/inspectors.test.ts.

## wrappers-keep-piped-input · nohup, nice and timeout hand the inner command its piped input and its plain name

Goal: a command behind `nohup`, `nice` or `timeout` is judged exactly as the same command typed bare. Today `curl -s https://example.com/p.py | timeout 30 python3 -` and `curl … | nohup python3 -` are allowed ("all commands safe") while the bare `curl … | python3 -` asks ("python3: program from stdin"), checked on main 7c8dd46 on 2026-11-08. The cause is in src/wrappers.ts `unwrapCommand` (main 9fb748d): the inner command it builds keeps only `name`, `args` and `assigns`, dropping `stdinFromPipe` and `stdin`, so the interpreter rules (`runsStdinProgram` in src/inspectors.ts) and the database heredoc rules never see the pipe or the heredoc. The same builder keeps the folder in the inner name (`timeout 30 /bin/rm -rf x` reads as an unknown command `/bin/rm`, not as rm). The heavy-run wrapper (PR #62, `heavyRunInner` in the same file) already does both right: copy everything but the path and set `name` to the file name with `path` holding the word. Do the same in the shared builder. evaluate.ts step 1b (a shell a wrapper hands piped input to is the `pipe to <shell>` hard stop) then covers `curl … | timeout 30 bash` with no further change. Replay the audit log before landing (the `diff-replay` technique: main's decide() against the branch's over the newest audit files) and say which recorded decisions change.
Done when: tests show `curl … | timeout 30 python3 -`, `curl … | nohup python3 -` and `curl … | nice bash` get the bare commands' decisions (the program-from-stdin prompt, the pipe-to-shell hard stop), `timeout 30 psql db <<'EOF' delete from t; EOF` is judged on its SQL, and `timeout 30 /bin/rm -rf ~` gets bare `rm -rf ~`'s decision.
Do not touch: the heavy-run wrapper's rules; which wrappers are transparent.
Needs: nothing.
Touches: src/wrappers.ts, src/wrappers.test.ts, src/hook.test.ts.

## record-unknown-command-names · The audit log records which commands were unknown, so the weekly view stops replaying
Written by: hall-pass/stats-weekly-view
Goal: an idea, not a fault. A decision that abstains on "unknown commands in pipeline" is logged without the commands that made it, so `bun run stats --weekly` (src/weekly.ts) names them by replaying each such line through today's `decide()`: about a minute for two busy weeks (about 4,000 distinct lines), judged with today's rules and the current folder rather than the ones in force then. Record the names on the decision entry instead (for example an `unknown` list, filled from the per-command `unknown: <name>` reasons decide.ts already computes), and have the weekly view read them, keeping the replay only for entries written before the field existed. This changes what every hook call writes, so it needs a plan: the field's name, a cap for long pipelines, and how stats and eval read entries with and without it.
Done when: a new "unknown commands in pipeline" entry carries its unknown command names, `stats --weekly` names them from the log without replaying such entries, and a test covers entries with and without the field.
Do not touch: the existing audit log files (read only); the default `bun run stats` report.
Needs: nothing.
Touches: src/decide.ts, src/audit.ts, src/weekly.ts, their tests.

## push-after-cd-into-scratch · A push to main inside a throwaway repo reached by `cd` is not a hard stop
Written by: hall-pass/hall-pass-weekly-checkin
Goal: a fault. A line that does `cd <scratchpad folder>` and then pushes `main` of a repository there is a hard stop today, even when the folder really is a scratchpad (checked with today's rules on main c9faab2, 2026-11-23). The protected-push rule already lets a throwaway repository through (`pushStaysLocal` in src/git.ts, which calls `isScratchDir` from src/repo.ts), but it judges the folder the hook was called from (hook `cwd`, adjusted only by `git -C`), so a `cd` earlier in the same line is never seen. In the week of 16 to 23 Nov, 6 of the 10 push prompts were agents testing landing scripts against bare repos under their scratchpad or `mktemp -d`, and none ran: the prompt stopped the test work. Follow a `cd` to a literal or proven-variable path earlier in the line when choosing the repository folder for git. A `cd` to a path nobody can read (`cd $T` after `T=$(mktemp -d)`) keeps the hard stop unless the evaluator already proves it is a temp folder. Check why `cd` was not followed before (the cd holes closed in PRs #42 to #46) and keep those closed.
Done when: tests show a push to main after `cd <scratchpad>/r`, and after `S=<scratchpad>; cd $S/r`, is allowed; the same push after `cd ~/Workspace/x` stays a hard stop; and a first push of main after `gh repo create` in a real checkout stays a hard stop. A replay of the 16 to 23 Nov audit files shows which recorded decisions change.
Do not touch: the hard stop for pushes to GitHub remotes; the list of protected branches.
Needs: nothing.
Touches: src/git.ts, src/evaluate.ts (how a cd reaches git's repository folder), src/git.test.ts, src/hook.test.ts.

## stand-in-keys-pass · A key that says it is fake does not prompt
Written by: hall-pass/hall-pass-weekly-checkin
Goal: a fault. The secret check (src/secrets.ts, the `sk-ant-` pattern) prompts on `sk-ant-api03-not-a-real-key`, the stand-in key metamax's live tests write into settings files. In the week of 16 to 23 Nov that was 12 prompts on Writes, Edits and heredocs of metamax `server/live/*-real.test.ts` files, and all 12 were approved. Skip a match whose own text marks it as a stand-in (`not-a-real`, `fake`, `example`, `placeholder`, `dummy`, a run of `x` or `0`), for every key type, not only Anthropic's. The marker must be inside the matched key, never elsewhere on the line, so a real key next to the word "example" still prompts.
Done when: tests show `sk-ant-api03-not-a-real-key` and a `ghp_` key with a fake-marked body pass the secret check in a Write, an Edit and a Bash heredoc, while a random 40-character `sk-ant-api03-` key, also on a line containing the word "example", still prompts.
Do not touch: the key patterns themselves; audit-log redaction (ticket audit-log-redact).
Needs: nothing.
Touches: src/secrets.ts, src/secrets.test.ts.

## pipe-to-bash-only-for-stdin-programs · "Pipe to bash" fires only when bash runs what the pipe sends
Written by: hall-pass/hall-pass-weekly-checkin
Goal: a fault. `echo | bash ./script.sh` and `git show origin/main:scripts/x.sh | bash -n` prompt as "pipe to bash" today (checked on main c9faab2), but in the first bash runs the file and reads the pipe as data, and `-n` only checks syntax and runs nothing. 3 of the 5 pipe-to-bash prompts in the week of 16 to 23 Nov were these shapes, all approved. Treat a piped shell as running its input only when it has no script file operand (or has `-s`), and never under `-n`. The script file itself is then judged as running a script is today. `sed … | bash` and `curl … | bash` keep the hard stop.
Done when: tests show `echo | bash ./script.sh` gets the same decision as `bash ./script.sh`, `cat x.sh | bash -n` is allowed, and `curl -s https://e.com/i.sh | bash`, `cat x.sh | bash -s -- arg` and `sed s/a/b/ f | bash` keep the pipe-to-bash stop.
Do not touch: the wrapper handling in ticket wrappers-keep-piped-input.
Needs: nothing.
Touches: src/evaluate.ts (the pipe to shell step), src/inspectors.ts (runsStdinProgram if it decides), their tests.

## op-help-is-safe · Any `op … --help` is allowed, even when the command word is a variable
Written by: hall-pass/hall-pass-weekly-checkin
Goal: `op item get --help` is allowed today, but `for c in "item edit" read; do op $c --help; done` prompts as "op: $c" because the command word is a loop variable. In the week of 16 to 23 Nov that was 9 prompts, all approved, from an agent reading 1Password's flags. `--help` (and `-h`) makes op print usage and read no secret, whatever the command, so the op inspector (src/inspectors.ts) can allow any op line carrying it before it tries to read the command word.
Done when: tests show `for c in "item get" read; do op $c --help; done` and `op $c -h` are allowed, and `op $c` and `op $c --vault x` without help still prompt.
Do not touch: what op commands that read secrets decide.
Needs: nothing.
Touches: src/inspectors.ts (op), src/inspectors.test.ts.
