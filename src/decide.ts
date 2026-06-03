/**
 * Pure decision logic for the hall-pass hook, extracted from hook.ts so it can
 * be exercised in-process by tests (no per-test `bun src/hook.ts` subprocess
 * spawn — that cold start dominated test time and flaked under load).
 *
 * `decide()` returns a HookDecision; the caller (hook.ts) is responsible for
 * emitting the JSON to stdout, writing the diagnostic line, and exiting. The
 * debug() and audit logging happen here, inline, exactly as the original hook
 * did — so behavior (including the audit log) is preserved byte-for-byte.
 */

import { resolve } from "path"
import { existsSync } from "fs"
import { extractCommandInfos, extractRedirects, extractPipeTargets } from "./parser.ts"
import type { HallPassConfig } from "./config.ts"
import type { DebugFn } from "./debug.ts"
import type { AuditLogger } from "./audit.ts"
import { checkFilePath } from "./paths.ts"
import { checkFeedbackRules } from "./feedback.ts"
import { createEvalContext } from "./evaluate.ts"
import { detectSecret } from "./secrets.ts"
import { detectExfilDomain } from "./network.ts"

export type HookDecision =
  | { decision: "allow"; reason: string }
  | { decision: "feedback"; suggestion: string }
  | { decision: "ask"; reason: string; message: string }
  | { decision: "pass"; reason: string }

const allow = (reason: string): HookDecision => ({ decision: "allow", reason })
const feedback = (suggestion: string): HookDecision => ({ decision: "feedback", suggestion })
const prompt = (reason: string, message: string): HookDecision => ({ decision: "ask", reason, message })
const pass = (reason: string): HookDecision => ({ decision: "pass", reason })

export interface DecideDeps {
  config: HallPassConfig
  shfmtBin: string
  debug: DebugFn
  audit: AuditLogger
}

/** Locate the bundled shfmt binary (dev source, compiled binary, or plugin install). */
export function findShfmt(): string {
  // Relative to source (development)
  const fromSrc = resolve(import.meta.dir, "..", "bin", "shfmt")
  if (existsSync(fromSrc)) return fromSrc
  // Relative to compiled binary
  const fromBin = resolve(process.execPath, "..", "shfmt")
  if (existsSync(fromBin)) return fromBin
  // Plugin root (when installed as a Claude Code plugin)
  const pluginRoot = process.env.CLAUDE_PLUGIN_ROOT
  if (pluginRoot) {
    const fromPlugin = resolve(pluginRoot, "bin", "shfmt")
    if (existsSync(fromPlugin)) return fromPlugin
  }
  // Fall back to PATH
  return "shfmt"
}

/**
 * Decide what to do with a tool invocation. Pure of process side effects
 * (no stdout/exit) — returns the decision for the caller to emit.
 */
export async function decide(
  toolName: string,
  toolInput: Record<string, unknown>,
  deps: DecideDeps,
): Promise<HookDecision> {
  const { config, shfmtBin, debug, audit } = deps
  const command = (toolInput.command as string) ?? ""

  debug("input", { toolName, toolInput })

  // -- Write/Edit path: file-path protection + secret scanning --
  if (toolName === "Write" || toolName === "Edit") {
    const filePath = toolInput.file_path as string
    if (!filePath) {
      debug("write/edit", "no file_path, allowing")
      return allow("write/edit no path")
    }

    debug("write/edit", { filePath })
    const decision = checkFilePath(filePath, "write", config)
    debug("path-check", decision)

    if (!decision.allowed) {
      audit.log({ tool: toolName, input: filePath, decision: "prompt", reason: decision.reason, layer: "paths" })
      return prompt(`path-blocked: ${decision.reason}`, `File path ${decision.reason}`)
    }

    const content = (toolInput.content ?? toolInput.new_string ?? "") as string
    if (content) {
      const secret = detectSecret(content)
      if (secret) {
        audit.log({ tool: toolName, input: filePath, decision: "prompt", reason: `secret: ${secret.type}`, layer: "secrets" })
        return prompt(`secret in ${toolName.toLowerCase()}: ${secret.type}`, `${toolName} contains a hardcoded ${secret.type} (${secret.preview})`)
      }
    }

    audit.log({ tool: toolName, input: filePath, decision: "allow", reason: "no path match", layer: "paths" })
    return allow("write/edit allowed")
  }

  // -- Bash path --
  if (!command) {
    debug("bash", "empty command")
    return prompt("empty command", "Empty command")
  }

  debug("bash", { command })

  // Parse with shfmt
  const proc = Bun.spawn([shfmtBin, "-ln", "bash", "--tojson"], {
    stdin: new Response(command),
    stdout: "pipe",
    stderr: "pipe",
  })
  const stdout = await new Response(proc.stdout).text()
  await proc.exited

  if (proc.exitCode !== 0) {
    debug("shfmt", "parse failed")
    return prompt("shfmt failed", "Could not parse command")
  }

  let ast: unknown
  try {
    ast = JSON.parse(stdout)
  } catch {
    debug("shfmt", "JSON parse failed")
    return prompt("shfmt json failed", "Could not parse command")
  }

  // -- Pre-parse checks (on raw command string) --

  const secret = detectSecret(command)
  if (secret) {
    debug("secret", secret)
    audit.log({ tool: "Bash", input: command, decision: "prompt", reason: `secret: ${secret.type}`, layer: "secrets" })
    return prompt(`secret: ${secret.type}`, `Command contains a hardcoded ${secret.type} (${secret.preview})`)
  }

  const exfilDomain = detectExfilDomain(command)
  if (exfilDomain) {
    debug("exfil", { domain: exfilDomain })
    audit.log({ tool: "Bash", input: command, decision: "prompt", reason: `exfil: ${exfilDomain}`, layer: "network" })
    return prompt(`exfil: ${exfilDomain}`, `Command targets known data-exfiltration service "${exfilDomain}"`)
  }

  // -- Extract commands and AST-level data --

  const commandInfos = extractCommandInfos(ast)
  debug("commands", commandInfos.map((c) => c.name))

  // Pipe target inspection — genuine `curl | bash`, NOT `&&`/`||` chains.
  const PIPE_SHELLS = new Set(["sh", "bash", "zsh", "dash", "fish", "eval"])
  for (const name of extractPipeTargets(ast)) {
    if (PIPE_SHELLS.has(name)) {
      debug("pipe-target", { name })
      audit.log({ tool: "Bash", input: command, decision: "prompt", reason: `pipe to ${name}`, layer: "pipe-target" })
      return prompt(`pipe to ${name}`, `Piping into "${name}" executes arbitrary piped content as code`)
    }
  }

  // Redirects against protected paths
  const redirects = extractRedirects(ast)
  debug("redirects", redirects)

  for (const redir of redirects) {
    const op = redir.op === "write" ? ("write" as const) : ("read" as const)
    const decision = checkFilePath(redir.path, op, config)
    if (!decision.allowed) {
      debug("redirect-block", { path: redir.path, op, reason: decision.reason })
      audit.log({ tool: "Bash", input: command, decision: "prompt", reason: `redirect ${decision.reason}`, layer: "paths" })
      return prompt(`redirect-blocked: ${decision.reason}`, `Redirect targets ${decision.reason}`)
    }
  }

  // Pipeline-level feedback rules (cross-command patterns)
  const feedbackSuggestion = checkFeedbackRules(commandInfos)
  if (feedbackSuggestion) {
    debug("feedback", { suggestion: feedbackSuggestion })
    audit.log({ tool: "Bash", input: command, decision: "feedback", reason: feedbackSuggestion, layer: "feedback" })
    return feedback(feedbackSuggestion)
  }

  // No commands found (e.g., bare variable assignment) — safe
  if (commandInfos.length === 0) {
    audit.log({ tool: "Bash", input: command, decision: "allow", reason: "no commands", layer: "safelist" })
    return allow("no commands (variable assignment)")
  }

  // -- Per-command evaluation --
  const ctx = createEvalContext(config, commandInfos, shfmtBin)

  let hasPass = false
  for (const cmdInfo of commandInfos) {
    const result = ctx.evaluate(cmdInfo)
    debug("eval", { name: cmdInfo.name, decision: result.decision })

    if (result.decision === "feedback") {
      audit.log({ tool: "Bash", input: command, decision: "feedback", reason: result.suggestion, layer: "evaluate" })
      return feedback(result.suggestion)
    }

    if (result.decision === "prompt") {
      audit.log({ tool: "Bash", input: command, decision: "prompt", reason: result.reason, layer: "evaluate" })
      return prompt(result.reason, result.message)
    }

    if (result.decision === "pass") {
      hasPass = true
    }
  }

  // If any command was unknown (pass), step aside — let Claude Code decide
  if (hasPass) {
    audit.log({ tool: "Bash", input: command, decision: "pass", reason: "unknown commands in pipeline", layer: "evaluate" })
    return pass("pipeline contains unknown commands")
  }

  audit.log({ tool: "Bash", input: command, decision: "allow", reason: "all commands safe", layer: "evaluate" })
  return allow("all commands safe")
}
