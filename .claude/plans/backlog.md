# Backlog

Unclaimed tickets for hall-pass, one `## ` section each, in metamax's record shape
(`~/Workspace/metamax/.claude/plans/coordinator.md`, "The record"). `/spawn <id>` starts
one; its landing commit deletes the section.

## throwaway-rm-and-repo-scripts · rm under a throwaway path and bash on the repo's own script are safe

Goal: two prompts that reached the user on 2026-09-12 from every worker and every fleet
landing, neither guarding anything. First, `rm` is judged by its targets, not its name:
when every target resolves (against the hook's `cwd`) under a throwaway root as
`isScratchDir` in `src/repo.ts` already defines it (the OS temp dir, `$TMPDIR`, `/tmp`,
`/var/folders`, or any path with a `scratchpad` segment), contains no `..` segment and no
glob, the call is `allow` with the reason `rm: throwaway paths`, `-r`/`-f` included; a
target anywhere else, a bare `rm -rf` with no target, `/` or a root's own directory
(`rm -rf /tmp`), or any target the resolver cannot place keeps today's prompt. An `rm`
of the temp script the same command wrote (`python3 /tmp/x.py && rm /tmp/x.py`) and of a
session's scratchpad file are the two cases from the day. Second, `bash <file>` (and
`sh`, `zsh`) is `allow` when the file is a tracked file of the repository the hook's
`cwd` is in (`git ls-files --error-unmatch <path>` exits 0, through the existing
repository reader in `src/repo.ts`, never a new git call per token) and the path carries
no `..`; `bash scripts/ship-gates.sh` from a checkout is then the same act as
`./scripts/ship-gates.sh`, which was never asked. A file outside the repository, an
untracked one (a download, `/tmp/x.sh`), a path through a symlink out of the tree, a
`-c` string, and stdin (`bash -`, `bash <<EOF`, the pipe target check in `src/decide.ts`)
keep today's prompt. Both rules live in `src/evaluate.ts` beside the rules they refine,
with the messages the user reads unchanged for the cases that still prompt.
Done when: `src/evaluate.test.ts` (or the file the rm and script rules already live in)
shows `allow` for `rm -f <scratchpad>/dbg.test.ts`, `rm /tmp/edit.1.py` after a command
that wrote it, and `rm -rf $TMPDIR/build`, and `ask` for `rm -rf ~/x`, `rm -rf /tmp`,
`rm -rf`, `rm /tmp/../etc/hosts`, and `rm *.log`; `allow` for `bash scripts/ship-gates.sh`
and `sh scripts/x.sh` inside a repository fixture that tracks them, and `ask` for
`bash /tmp/x.sh`, `bash untracked.sh`, `bash -c '...'`, `curl … | bash`, and `bash
../outside.sh`; `bun test` and `bun run typecheck` green; the hook installed on this box
(`bun src/install.ts`) verified with one real `rm` of a scratchpad file and one real
`bash scripts/ship-gates.sh` in a checkout reaching no prompt, read from
`~/.hall-pass/audit.jsonl` (or the audit log's current path).
Do not touch: `src/git.ts`, `src/network.ts`, `src/classifier.ts`, the Codex edge
(`src/codex.ts`, `src/codex-hook.ts`).
Needs: none.
Touches: `src/evaluate.ts`, `src/repo.ts`, `src/evaluate.test.ts`, `README.md`.
