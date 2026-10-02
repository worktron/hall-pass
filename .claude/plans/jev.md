# Command kinds with Jev, offline

Goal: use Jev (TypeSafe AI's System One classifier: a choice among labels we define, a probability for each, $0.042 per million input tokens) to grow hall-pass's deterministic rules faster. Jev never decides anything at runtime.

## Why offline only

- The agent writes the command. A prompt-injected agent can put `# read-only listing` next to an rm, and always-be-closing found Jev follows wording (it called 83 of 89 tabs abandoned when asked a question the input could not answer).
- In auto and plan mode a hall-pass `pass` goes to Claude Code's own classifier, a stronger model that reads the conversation. Swapping it for Jev would weaken the guard.
- The audit log already holds every command with today's decision and whether it ran, so nothing needs to run in the hot path to measure.

## What shipped on this branch (2026-10-02)

- `src/jev.ts`: the question, redaction, extraction, the request and the report. `src/jev-label.ts` is `bun run jev`.
- One question, "What does this shell command do?", eight kinds: inspect, build, write, delete, remote, credentials, run, system. What it is, not whether it is safe; the policy stays in code. Model pinned to `jev-1.13.0`.
- The unit is one simple command, judged alone by today's rules: unknown (no rule knows the name), judgment (a judgment-call prompt: rm, perl -e, sed -i), allowed. Hard stops are never sent. Allowed commands are sampled, up to 25 per name and subcommand and 500 per name.
- Redaction, before anything leaves: home directory as `~`, environment values dropped, URLs without credentials or query values, `op://` references elided, header and `password=`-style values dropped, long opaque tokens elided, heredocs capped at 1000 characters. A line `detectSecret` flags is never sent, nor a redacted command it still flags. Codex calls are left out.
- Answers go to `~/.local/share/hall-pass/jev/answers.jsonl` (owner-only, outside every checkout), keyed by a hash of what was sent, the model and the question set, so a rerun pays only for new commands.
- The report: safelist candidates (unknown names, or name plus subcommand, read as inspect or build at 0.8 or more every time, two or more uses), possible holes (allowed commands read as delete, remote, credentials or system at 0.8 or more), judgment calls by reason with the ones read as safe, and the kind mix of allowed commands. Allowed commands are safe by construction, so that mix also says how often Jev mislabels safe commands.

`bun run jev --plan` on 2026-10-02: 91,384 distinct commands in 19 days of log; 1,642 unknown, 1,681 judgment calls, 3,962 sampled allowed; 7,285 requests, about 2.0M input tokens, about $0.09.

## Next

1. The user's yes to send the redacted commands to TypeSafe, then `bun run jev --max-cost 1`.
2. Review the candidates by hand. A wrapper (nohup, caffeinate, timeout) is not a safelist entry: it runs another command and needs wrapper handling in `src/wrappers.ts`. Each accepted candidate is an ordinary rule change with tests, checked with `bun run eval`.
3. Review the holes. Each confirmed one is a rule fix with the test that would have caught it, shipped as its own PR.
4. Only if the candidates prove useful: a narrow runtime use that changes friction and never allows, such as whether an inline `python3 -c` really is JSON parsing before the "use jq" nudge.
