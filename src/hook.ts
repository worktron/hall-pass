#!/usr/bin/env bun

/**
 * hall-pass: Claude Code hook entry point
 *
 * PreToolUse (the main path): read the tool invocation from stdin, delegate
 * the decision to decide() (src/decide.ts), then emit the permissionDecision
 * JSON and exit. The decision logic lives in decide.ts so it can be tested
 * in-process.
 *
 * Decision protocol (all exit 0 + JSON on stdout):
 *   { permissionDecision: "allow" }                     = auto-approve
 *   { permissionDecision: "allow", additionalContext }  = auto-approve + nudge Claude
 *   { permissionDecision: "ask" }                       = prompt user for permission
 *   (no output)                                         = step aside, let Claude Code decide
 *
 * Also handles two observe-only events for outcome monitoring (no decision,
 * just an audit entry — see audit.ts / stats.ts):
 *   PostToolUse  = the tool call ran; joined to its decision via tool_use_id
 *   Notification = a native permission prompt was shown (permission_prompt)
 */

import { loadConfig } from "./config.ts"
import { createDebug } from "./debug.ts"
import { createAudit, type AuditContext } from "./audit.ts"
import { decide, findShfmt, type HookDecision } from "./decide.ts"

// Diagnostic log — always writes to /tmp so we can debug hook failures.
// diag() appends a few lines on every tool call, so cap the file's growth:
// once per process, if it exceeds DIAG_MAX_BYTES, keep only the recent tail.
const DIAG = "/tmp/hall-pass-diag.log"
const DIAG_MAX_BYTES = 1_000_000
const DIAG_KEEP_LINES = 2000
let diagTrimChecked = false
function diag(msg: string) {
  try {
    const fs = require("fs")
    if (!diagTrimChecked) {
      diagTrimChecked = true
      try {
        if (fs.statSync(DIAG).size > DIAG_MAX_BYTES) {
          const tail = fs.readFileSync(DIAG, "utf8").split("\n").slice(-DIAG_KEEP_LINES).join("\n")
          fs.writeFileSync(DIAG, tail)
        }
      } catch {}
    }
    fs.appendFileSync(DIAG, `${new Date().toISOString()} ${msg}\n`)
  } catch {}
}

/** Emit the permissionDecision JSON to stdout, log the diagnostic line, and exit. */
function emit(decision: HookDecision): never {
  switch (decision.decision) {
    case "allow":
      diag(`ALLOW ${decision.reason}`)
      process.stdout.write(JSON.stringify({
        hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "allow", permissionDecisionReason: decision.reason },
      }))
      process.exit(0)
    case "feedback":
      diag(`FEEDBACK ${decision.suggestion}`)
      process.stdout.write(JSON.stringify({
        hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "allow", additionalContext: decision.suggestion },
      }))
      process.exit(0)
    case "ask":
      diag(`PROMPT ${decision.reason}`)
      process.stdout.write(JSON.stringify({
        hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "ask", permissionDecisionReason: decision.message },
      }))
      process.exit(0)
    case "pass":
      diag(`PASS ${decision.reason}`)
      process.exit(0)
  }
}

// -- Read hook input from stdin --

diag("start")

// HALL_PASS=off: stand down for this session — no decision, no audit entry,
// on every event. The hook stays installed globally in ~/.claude/settings.json;
// a launcher that wants Claude Code's own review alone (a control plane running
// many hands-off sessions, say) sets this in the session's environment.
if (process.env.HALL_PASS === "off") {
  diag("off (HALL_PASS=off)")
  process.exit(0)
}
let toolName: string
let toolInput: Record<string, unknown>
let hookEvent: string
let ctx: AuditContext
try {
  const input = await Bun.stdin.text()
  const parsed = JSON.parse(input)
  toolName = parsed?.tool_name ?? ""
  toolInput = parsed?.tool_input ?? {}
  hookEvent = parsed?.hook_event_name ?? "PreToolUse"
  ctx = {
    session: parsed?.session_id,
    tool_use_id: parsed?.tool_use_id,
    mode: parsed?.permission_mode,
  }
  // Observe-only events: log the outcome and step aside.
  if (hookEvent === "PostToolUse") {
    diag(`COMPLETED tool=${toolName} id=${ctx.tool_use_id ?? "?"}`)
    createAudit(await loadConfig(), ctx).event("completed", { tool: toolName })
    process.exit(0)
  }
  if (hookEvent === "Notification") {
    const message = (parsed?.message as string) ?? ""
    diag(`NATIVE-PROMPT ${message.slice(0, 120)}`)
    createAudit(await loadConfig(), ctx).event("native-prompt", { message })
    process.exit(0)
  }
} catch (e) {
  diag(`stdin-error: ${e}`)
  process.exit(1)
}

const command = (toolInput.command as string) ?? ""
diag(`tool=${toolName} cmd=${command.slice(0, 80)} keys=${Object.keys(toolInput).join(",")} mode=${ctx.mode ?? "?"} id=${ctx.tool_use_id ?? "?"}`)

// -- Load config, wire up debug/audit, decide, emit --

const config = await loadConfig()
const debug = createDebug(config)
const audit = createAudit(config, ctx)
const shfmtBin = findShfmt()

const decision = await decide(toolName, toolInput, { config, shfmtBin, debug, audit, mode: ctx.mode })
emit(decision)
