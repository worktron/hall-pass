#!/usr/bin/env bun

/**
 * hall-pass: PreToolUse hook for Claude Code
 *
 * Thin entry point: read the tool invocation from stdin, delegate the decision
 * to decide() (src/decide.ts), then emit the permissionDecision JSON and exit.
 * The decision logic lives in decide.ts so it can be tested in-process.
 *
 * Decision protocol (all exit 0 + JSON on stdout):
 *   { permissionDecision: "allow" }                     = auto-approve
 *   { permissionDecision: "allow", additionalContext }  = auto-approve + nudge Claude
 *   { permissionDecision: "ask" }                       = prompt user for permission
 *   (no output)                                         = step aside, let Claude Code decide
 */

import { loadConfig } from "./config.ts"
import { createDebug } from "./debug.ts"
import { createAudit } from "./audit.ts"
import { decide, findShfmt, type HookDecision } from "./decide.ts"

// Diagnostic log — always writes to /tmp so we can debug hook failures
const DIAG = "/tmp/hall-pass-diag.log"
function diag(msg: string) {
  try { require("fs").appendFileSync(DIAG, `${new Date().toISOString()} ${msg}\n`) } catch {}
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
let toolName: string
let toolInput: Record<string, unknown>
try {
  const input = await Bun.stdin.text()
  const parsed = JSON.parse(input)
  toolName = parsed?.tool_name ?? ""
  toolInput = parsed?.tool_input ?? {}
} catch (e) {
  diag(`stdin-error: ${e}`)
  process.exit(1)
}

const command = (toolInput.command as string) ?? ""
diag(`tool=${toolName} cmd=${command.slice(0, 80)} keys=${Object.keys(toolInput).join(",")}`)

// -- Load config, wire up debug/audit, decide, emit --

const config = await loadConfig()
const debug = createDebug(config)
const audit = createAudit(config)
const shfmtBin = findShfmt()

const decision = await decide(toolName, toolInput, { config, shfmtBin, debug, audit })
emit(decision)
