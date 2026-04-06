#!/usr/bin/env bun

/**
 * hall-pass: PreToolUse hook for Claude Code
 *
 * Routes by tool type:
 *   - Bash: unified recursive evaluation via evaluateBashCommand
 *   - Write/Edit: file path protection
 *
 * Decision protocol (all exit 0 + JSON on stdout):
 *   { permissionDecision: "allow" }                  = auto-approve
 *   { permissionDecision: "allow", additionalContext } = auto-approve + nudge Claude
 *   { permissionDecision: "ask" }                    = prompt user for permission
 */

// Diagnostic log — always writes to /tmp so we can debug hook failures
const DIAG = "/tmp/hall-pass-diag.log"
function diag(msg: string) {
  try { require("fs").appendFileSync(DIAG, `${new Date().toISOString()} ${msg}\n`) } catch {}
}

/** Output a permissionDecision JSON to stdout and exit. */
function allow(reason: string): never {
  diag(`ALLOW ${reason}`)
  const output = JSON.stringify({
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: "allow",
      permissionDecisionReason: reason,
    },
  })
  process.stdout.write(output)
  process.exit(0)
}

/** Auto-approve but nudge Claude with feedback via additionalContext. */
function feedback(suggestion: string): never {
  diag(`FEEDBACK ${suggestion}`)
  const output = JSON.stringify({
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: "allow",
      additionalContext: suggestion,
    },
  })
  process.stdout.write(output)
  process.exit(0)
}

/** Prompt the user for permission with a human-friendly message. */
function prompt(reason: string, message: string): never {
  diag(`PROMPT ${reason}`)
  const output = JSON.stringify({
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: "ask",
      permissionDecisionReason: message,
    },
  })
  process.stdout.write(output)
  process.exit(0)
}

import { resolve } from "path"
import { existsSync } from "fs"
import { extractCommandInfos, extractRedirects } from "./parser.ts"
import { loadConfig } from "./config.ts"
import { createDebug } from "./debug.ts"
import { createAudit } from "./audit.ts"
import { checkFilePath } from "./paths.ts"
import { checkFeedbackRules } from "./feedback.ts"
import { createEvalContext } from "./evaluate.ts"
import { detectSecret } from "./secrets.ts"
import { detectExfilDomain } from "./network.ts"

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

// -- Load config + initialize debug/audit --

const config = await loadConfig()

const debug = createDebug(config)
const audit = createAudit(config)

debug("input", { toolName, toolInput })

// -- Route by tool type --

if (toolName === "Write" || toolName === "Edit") {
  const filePath = toolInput.file_path as string
  if (!filePath) {
    debug("write/edit", "no file_path, allowing")
    allow("write/edit no path")
  }

  debug("write/edit", { filePath })
  const decision = checkFilePath(filePath, "write", config)
  debug("path-check", decision)

  if (!decision.allowed) {
    audit.log({ tool: toolName, input: filePath, decision: "prompt", reason: decision.reason, layer: "paths" })
    prompt(`path-blocked: ${decision.reason}`, `File path ${decision.reason}`)
  }

  // Scan Write content / Edit new_string for hardcoded secrets
  const content = (toolInput.content ?? toolInput.new_string ?? "") as string
  if (content) {
    const secret = detectSecret(content)
    if (secret) {
      audit.log({ tool: toolName, input: filePath, decision: "prompt", reason: `secret: ${secret.type}`, layer: "secrets" })
      prompt(`secret in ${toolName.toLowerCase()}: ${secret.type}`, `${toolName} contains a hardcoded ${secret.type} (${secret.preview})`)
    }
  }

  audit.log({ tool: toolName, input: filePath, decision: "allow", reason: "no path match", layer: "paths" })
  allow("write/edit allowed")
}

// -- Bash path --

if (!command) {
  debug("bash", "empty command")
  prompt("empty command", "Empty command")
}

debug("bash", { command })

// -- Parse with shfmt --

const bundledShfmt = resolve(import.meta.dir, "..", "bin", "shfmt")
const shfmtBin = existsSync(bundledShfmt) ? bundledShfmt : "shfmt"

const proc = Bun.spawn([shfmtBin, "-ln", "bash", "--tojson"], {
  stdin: new Response(command),
  stdout: "pipe",
  stderr: "pipe",
})

const stdout = await new Response(proc.stdout).text()
await proc.exited

if (proc.exitCode !== 0) {
  debug("shfmt", "parse failed")
  prompt("shfmt failed", "Could not parse command")
}

let ast: unknown
try {
  ast = JSON.parse(stdout)
} catch {
  debug("shfmt", "JSON parse failed")
  prompt("shfmt json failed", "Could not parse command")
}

// -- Pre-parse checks (on raw command string) --

// Secret detection in command text
const secret = detectSecret(command)
if (secret) {
  debug("secret", secret)
  audit.log({ tool: "Bash", input: command, decision: "prompt", reason: `secret: ${secret.type}`, layer: "secrets" })
  prompt(`secret: ${secret.type}`, `Command contains a hardcoded ${secret.type} (${secret.preview})`)
}

// Network exfiltration domain detection
const exfilDomain = detectExfilDomain(command)
if (exfilDomain) {
  debug("exfil", { domain: exfilDomain })
  audit.log({ tool: "Bash", input: command, decision: "prompt", reason: `exfil: ${exfilDomain}`, layer: "network" })
  prompt(`exfil: ${exfilDomain}`, `Command targets known data-exfiltration service "${exfilDomain}"`)
}

// -- Extract commands and AST-level data --

const commandInfos = extractCommandInfos(ast)
debug("commands", commandInfos.map(c => c.name))

// -- AST-level checks (not per-command) --

// Pipe target inspection — detect `curl | bash`, `echo | sh`, etc.
const PIPE_SHELLS = new Set(["sh", "bash", "zsh", "dash", "fish", "eval"])
for (let i = 1; i < commandInfos.length; i++) {
  const name = commandInfos[i]!.name
  if (PIPE_SHELLS.has(name)) {
    debug("pipe-target", { name, position: i })
    audit.log({ tool: "Bash", input: command, decision: "prompt", reason: `pipe to ${name}`, layer: "pipe-target" })
    prompt(`pipe to ${name}`, `Piping into "${name}" executes arbitrary piped content as code`)
  }
}

// Redirects against protected paths
const redirects = extractRedirects(ast)
debug("redirects", redirects)

for (const redir of redirects) {
  const op = redir.op === "write" ? "write" as const : "read" as const
  const decision = checkFilePath(redir.path, op, config)
  if (!decision.allowed) {
    debug("redirect-block", { path: redir.path, op, reason: decision.reason })
    audit.log({ tool: "Bash", input: command, decision: "prompt", reason: `redirect ${decision.reason}`, layer: "paths" })
    prompt(`redirect-blocked: ${decision.reason}`, `Redirect targets ${decision.reason}`)
  }
}

// Pipeline-level feedback rules (cross-command patterns)
const feedbackSuggestion = checkFeedbackRules(commandInfos)
if (feedbackSuggestion) {
  debug("feedback", { suggestion: feedbackSuggestion })
  audit.log({ tool: "Bash", input: command, decision: "feedback", reason: feedbackSuggestion, layer: "feedback" })
  feedback(feedbackSuggestion)
}

// No commands found (e.g., bare variable assignment) — safe
if (commandInfos.length === 0) {
  audit.log({ tool: "Bash", input: command, decision: "allow", reason: "no commands", layer: "safelist" })
  allow("no commands (variable assignment)")
}

// -- Per-command evaluation --

const ctx = createEvalContext(config, commandInfos, shfmtBin)

let hasPass = false

for (const cmdInfo of commandInfos) {
  const result = ctx.evaluate(cmdInfo)
  debug("eval", { name: cmdInfo.name, decision: result.decision })

  if (result.decision === "feedback") {
    audit.log({ tool: "Bash", input: command, decision: "feedback", reason: result.suggestion, layer: "evaluate" })
    feedback(result.suggestion)
  }

  if (result.decision === "prompt") {
    audit.log({ tool: "Bash", input: command, decision: "prompt", reason: result.reason, layer: "evaluate" })
    prompt(result.reason, result.message)
  }

  if (result.decision === "pass") {
    hasPass = true
  }
}

// If any command was unknown (pass), step aside — let Claude Code decide
if (hasPass) {
  diag("PASS pipeline contains unknown commands")
  audit.log({ tool: "Bash", input: command, decision: "pass", reason: "unknown commands in pipeline", layer: "evaluate" })
  process.exit(0)
}

audit.log({ tool: "Bash", input: command, decision: "allow", reason: "all commands safe", layer: "evaluate" })
allow("all commands safe")
