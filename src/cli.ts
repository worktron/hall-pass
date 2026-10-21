#!/usr/bin/env bun

/**
 * hall-pass CLI
 *
 * Subcommands:
 *   init                     — Generate default config at ~/.config/hall-pass/config.toml
 *   decision <tool_use_id>   — Print hall-pass's decision for one tool call as JSON:
 *                              {"decision","layer","reason"}. Exit 1, stdout empty, when
 *                              the audit log has no decision for it.
 *   codex-hook               — Print the command to register as a Codex hook.
 *
 * `decision` and `codex-hook` are how other programs (metamax) ask hall-pass,
 * instead of reading its audit log or deriving its file layout themselves.
 */

import { initConfig, loadConfig } from "./config.ts"
import { findDecision } from "./audit.ts"
import { hookCommand } from "./hook-command.ts"

const USAGE = "Usage: hall-pass [init | decision <tool_use_id> | codex-hook]"

const [command, ...args] = process.argv.slice(2)

if (command === "init" || !command) {
  const path = await initConfig()
  console.log(`Created default config at ${path}`)
  console.log("Edit this file to customize hall-pass behavior.")
} else if (command === "decision") {
  const toolUseId = args[0]
  if (!toolUseId) {
    console.error(USAGE)
    process.exit(2)
  }
  const config = await loadConfig()
  const found = config.audit.enabled ? findDecision(config.audit.path, toolUseId) : null
  if (!found) process.exit(1)
  console.log(JSON.stringify(found))
} else if (command === "codex-hook") {
  console.log(hookCommand("codex"))
} else {
  console.error(`Unknown command: ${command}`)
  console.error(USAGE)
  process.exit(2)
}
