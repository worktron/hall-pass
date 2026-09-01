#!/usr/bin/env bun

/**
 * hall-pass: Codex hook entry point
 *
 * Registered in ~/.codex/hooks.json for PreToolUse, PermissionRequest and
 * PostToolUse on the Bash and apply_patch tools (see install.ts --codex).
 *
 * Reads the tool invocation from stdin (same field names as Claude Code:
 * tool_name, tool_input, session_id, tool_use_id, permission_mode), runs the
 * shared decide() pipeline, and emits whatever Codex's protocol can carry
 * for the event — see codex.ts for the mapping and why it differs from the
 * Claude Code entry point in hook.ts.
 *
 * Events:
 *   PreToolUse        decide; deny hard stops, nudge, or step aside
 *   PermissionRequest decide again (cheap); allow skips Codex's prompt,
 *                     deny blocks, nothing leaves the prompt to the user
 *   PostToolUse       observe-only: the call ran (audit "completed")
 *
 * Only PreToolUse writes a "decision" audit entry. PermissionRequest runs
 * decide() with a silent audit logger so the same tool_use_id is not
 * counted twice, and records a "native-prompt" event when it leaves the
 * prompt to the user — the signal stats.ts joins against.
 */

import { loadConfig } from "./config.ts"
import { createDebug } from "./debug.ts"
import { createAudit, type AuditContext, type AuditLogger } from "./audit.ts"
import { decide, findShfmt } from "./decide.ts"
import { codexOutput, CODEX_TOOLS, type CodexEvent } from "./codex.ts"
import { createDiag } from "./diag.ts"

const diag = createDiag("[codex]")
const silentAudit: AuditLogger = { log() {}, event() {} }

diag("start")

if (process.env.HALL_PASS === "off") {
  diag("off (HALL_PASS=off)")
  process.exit(0)
}

let toolName: string
let toolInput: Record<string, unknown>
let hookEvent: string
let ctx: AuditContext
try {
  const parsed = JSON.parse(await Bun.stdin.text())
  toolName = parsed?.tool_name ?? ""
  toolInput = (parsed?.tool_input ?? {}) as Record<string, unknown>
  hookEvent = parsed?.hook_event_name ?? "PreToolUse"
  ctx = {
    session: parsed?.session_id,
    tool_use_id: parsed?.tool_use_id,
    mode: parsed?.permission_mode,
    host: "codex",
  }
} catch (e) {
  diag(`stdin-error: ${e}`)
  process.exit(1)
}

const command = (toolInput.command as string) ?? ""
diag(`event=${hookEvent} tool=${toolName} cmd=${command.slice(0, 80)} mode=${ctx.mode ?? "?"} id=${ctx.tool_use_id ?? "?"}`)

if (hookEvent === "PostToolUse") {
  createAudit(await loadConfig(), ctx).event("completed", { tool: toolName })
  process.exit(0)
}

if ((hookEvent !== "PreToolUse" && hookEvent !== "PermissionRequest") || !CODEX_TOOLS.has(toolName)) {
  diag(`ignored event=${hookEvent} tool=${toolName}`)
  process.exit(0)
}

const event = hookEvent as CodexEvent
const config = await loadConfig()
const debug = createDebug(config)
const audit = createAudit(config, ctx)
const shfmtBin = findShfmt()

const decision = await decide(toolName, toolInput, {
  config,
  shfmtBin,
  debug,
  audit: event === "PreToolUse" ? audit : silentAudit,
  mode: ctx.mode,
})

const output = codexOutput(event, decision, config)

if (event === "PermissionRequest" && output === null) {
  audit.event("native-prompt", { message: `codex ${toolName}: ${decision.reason}` })
}

const summary = output === null ? "NO-OUTPUT" : JSON.stringify(output).slice(0, 160)
diag(`${event} ${decision.decision.toUpperCase()} ${decision.reason} -> ${summary}`)

if (output !== null) process.stdout.write(JSON.stringify(output))
process.exit(0)
