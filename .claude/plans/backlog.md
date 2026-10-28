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
