#!/bin/sh
# Wrapper: tries compiled binary first, falls back to bun
DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$DIR")"

if [ -x "$DIR/hall-pass" ]; then
  exec "$DIR/hall-pass" "$@"
elif command -v bun >/dev/null 2>&1; then
  exec bun "$ROOT/src/hook.ts" "$@"
else
  echo '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask","permissionDecisionReason":"hall-pass: neither compiled binary nor bun found. Run: bun run install"}}' >&1
  exit 0
fi
