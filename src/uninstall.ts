#!/usr/bin/env bun

/**
 * hall-pass uninstall
 *
 * Removes all hall-pass hooks from the host's hook settings:
 *   default  ~/.claude/settings.json (PreToolUse, PostToolUse, Notification)
 *   --codex  ~/.codex/hooks.json     (PreToolUse, PermissionRequest, PostToolUse)
 * Does not remove non-Bash tool permissions (you probably still want those).
 */

import { resolve } from "path"
import { homedir } from "os"

const CODEX = process.argv.includes("--codex")
const HOST = CODEX ? "Codex" : "Claude Code"
const SETTINGS_PATH = CODEX
  ? resolve(homedir(), ".codex", "hooks.json")
  : resolve(homedir(), ".claude", "settings.json")

const settingsFile = Bun.file(SETTINGS_PATH)

if (!(await settingsFile.exists())) {
  console.log("No settings file found at", SETTINGS_PATH)
  process.exit(0)
}

let settings: Record<string, unknown>
try {
  settings = await settingsFile.json()
} catch {
  console.error("Could not parse", SETTINGS_PATH)
  process.exit(1)
}

const hooks = settings.hooks as Record<string, unknown[]> | undefined
if (!hooks || Object.keys(hooks).length === 0) {
  console.log("No hooks found. Nothing to remove.")
  process.exit(0)
}

let removed = 0
for (const eventName of Object.keys(hooks)) {
  const entries = hooks[eventName]
  if (!Array.isArray(entries)) continue
  const kept = entries.filter((entry) => {
    const e = entry as Record<string, unknown>
    const entryHooks = e.hooks as Array<Record<string, unknown>> | undefined
    return !entryHooks?.some((h) => (h.command as string)?.includes("hall-pass"))
  })
  removed += entries.length - kept.length
  if (kept.length === 0) delete hooks[eventName]
  else hooks[eventName] = kept
}

if (removed === 0) {
  console.log("hall-pass hook not found in settings. Nothing to remove.")
  process.exit(0)
}

// Clean up empty hooks object
if (Object.keys(hooks).length === 0) delete settings.hooks

await Bun.write(SETTINGS_PATH, JSON.stringify(settings, null, 2) + "\n")
console.log("Removed hall-pass hook from", SETTINGS_PATH)
console.log(`Restart ${HOST} sessions to pick up the change.`)
