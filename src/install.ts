#!/usr/bin/env bun

/**
 * hall-pass install
 *
 * Default (Claude Code) — sets up the hooks in ~/.claude/settings.json:
 * 1. Checks that shfmt is installed
 * 2. Adds PreToolUse (decisions) + PostToolUse (outcome monitoring) hooks for
 *    Bash, Write, and Edit, and a Notification hook for permission_prompt
 *    (records when a native permission prompt is shown)
 * 3. Adds non-Bash tool permissions (Read, Edit, Glob, Grep, WebFetch, WebSearch)
 *
 * --codex — sets up the Codex hooks in ~/.codex/hooks.json instead:
 *    PreToolUse, PermissionRequest and PostToolUse for Bash and apply_patch,
 *    pointing at src/codex-hook.ts (see codex.ts for why the entry differs).
 *    Codex asks you to review and trust a new hook definition on first use:
 *    run `/hooks` inside Codex after installing.
 *
 * --init — also writes a default ~/.config/hall-pass/config.toml.
 */

import { resolve } from "path"
import { homedir } from "os"

const CODEX = process.argv.includes("--codex")

const HOOK_PATH = resolve(import.meta.dir, CODEX ? "codex-hook.ts" : "hook.ts")
const SETTINGS_PATH = CODEX
  ? resolve(homedir(), ".codex", "hooks.json")
  : resolve(homedir(), ".claude", "settings.json")
const HOOK_COMMAND = `bun ${HOOK_PATH}`

const NON_BASH_TOOLS = ["Read", "Edit", "Glob", "Grep", "WebFetch", "WebSearch"]
const HOOK_MATCHERS = ["Bash", "Write", "Edit"]
/** One matcher group covers both Codex tools hall-pass judges (matcher is a regex). */
const CODEX_MATCHER = "Bash|apply_patch"

// -- Check / install shfmt --

const SHFMT_VERSION = "v3.13.0"

async function installShfmt(): Promise<string> {
  const platform = process.platform === "darwin" ? "darwin" : "linux"
  const arch = process.arch === "arm64" ? "arm64" : "amd64"
  const asset = `shfmt_${SHFMT_VERSION}_${platform}_${arch}`
  const url = `https://github.com/mvdan/sh/releases/download/${SHFMT_VERSION}/${asset}`

  // Install alongside hall-pass source
  const binDir = resolve(import.meta.dir, "..", "bin")
  await Bun.spawn(["mkdir", "-p", binDir]).exited
  const dest = resolve(binDir, "shfmt")

  console.log(`Downloading shfmt ${SHFMT_VERSION}...`)
  const resp = await fetch(url)
  if (!resp.ok) {
    console.error(`Failed to download shfmt: ${resp.status} ${resp.statusText}`)
    console.error(`URL: ${url}`)
    process.exit(1)
  }

  await Bun.write(dest, resp)
  await Bun.spawn(["chmod", "+x", dest]).exited
  console.log(`Installed shfmt to ${dest}`)
  return dest
}

const shfmt = Bun.spawnSync(["which", "shfmt"])
if (shfmt.exitCode !== 0) {
  await installShfmt()
} else {
  console.log("shfmt found:", shfmt.stdout.toString().trim())
}

// -- Read or create the settings file --

let settings: Record<string, unknown> = {}
const settingsFile = Bun.file(SETTINGS_PATH)

if (await settingsFile.exists()) {
  try {
    settings = await settingsFile.json()
    console.log("Found existing settings:", SETTINGS_PATH)
  } catch {
    console.error("Could not parse", SETTINGS_PATH)
    process.exit(1)
  }
} else {
  await Bun.spawn(["mkdir", "-p", resolve(SETTINGS_PATH, "..")]).exited
  console.log("Creating new settings:", SETTINGS_PATH)
}

// -- Add non-Bash tool permissions (Claude Code only) --

if (!CODEX) {
  const permissions = (settings.permissions ?? {}) as Record<string, unknown>
  const allow = new Set(permissions.allow as string[] ?? [])

  for (const tool of NON_BASH_TOOLS) {
    allow.add(tool)
  }

  permissions.allow = [...allow]
  settings.permissions = permissions
}

// -- Add hook registrations --
// Both hosts use the same three-level shape: event → matcher group → handlers.

const hooks = (settings.hooks ?? {}) as Record<string, unknown[]>

function registerHook(eventName: string, matcher: string) {
  const entries = (hooks[eventName] ?? []) as Array<Record<string, unknown>>

  // Check if hall-pass is already registered for this matcher
  const existing = entries.find((entry) => {
    if (entry.matcher !== matcher) return false
    const entryHooks = entry.hooks as Array<Record<string, unknown>> | undefined
    return entryHooks?.some((h) => {
      const cmd = h.command as string | undefined
      return cmd?.includes("hall-pass")
    })
  })

  if (existing) {
    // Update the command path in case the project moved
    const entryHooks = existing.hooks as Array<Record<string, unknown>>
    const hookEntry = entryHooks.find((h) => (h.command as string)?.includes("hall-pass"))
    if (hookEntry) hookEntry.command = HOOK_COMMAND
    console.log(`Updated existing hall-pass ${eventName} hook for ${matcher}`)
  } else {
    const handler: Record<string, unknown> = { type: "command", command: HOOK_COMMAND }
    if (CODEX) handler.statusMessage = "hall-pass"
    entries.push({ matcher, hooks: [handler] })
    console.log(`Added hall-pass ${eventName} hook for ${matcher}`)
  }

  hooks[eventName] = entries
}

if (CODEX) {
  registerHook("PreToolUse", CODEX_MATCHER)
  registerHook("PermissionRequest", CODEX_MATCHER)
  registerHook("PostToolUse", CODEX_MATCHER)
} else {
  for (const matcher of HOOK_MATCHERS) {
    registerHook("PreToolUse", matcher)
    registerHook("PostToolUse", matcher)
  }
  registerHook("Notification", "permission_prompt")
}

settings.hooks = hooks

// -- Optionally generate config --

if (process.argv.includes("--init")) {
  const { initConfig } = await import("./config.ts")
  const configPath = await initConfig()
  console.log("Created default config at", configPath)
}

// -- Write settings --

await Bun.write(SETTINGS_PATH, JSON.stringify(settings, null, 2) + "\n")
console.log("Wrote settings to", SETTINGS_PATH)
if (CODEX) {
  console.log("\nDone. Codex skips a new or changed hook until you trust it:")
  console.log("open a Codex session and run /hooks to review and trust the hall-pass hooks.")
} else {
  console.log("\nDone. Restart Claude Code sessions to pick up the new settings.")
}
