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
import { createEvalContext, evaluateBashCommand, type EvalContext, type EvalResult } from "./evaluate.ts"
import { literalVariables } from "./vars.ts"
import { rootScope, scopeOf } from "./places.ts"
import { detectSecret } from "./secrets.ts"
import { detectExfilDomain } from "./network.ts"
import { parseApplyPatch, checkPatch } from "./patch.ts"
import { possibleValues, substitute, hasPlaceholder, MAX_VARIANTS, type PossibleValues } from "./values.ts"
import type { CommandInfo } from "./parser.ts"

export type HookDecision =
  | { decision: "allow"; reason: string }
  | { decision: "feedback"; suggestion: string }
  /**
   * `hard` marks an ask that is not a judgment call: protected paths,
   * secrets, code injection, exfiltration, pushes to protected branches.
   * Claude Code prompts for these in every mode. Hosts without an "ask"
   * (Codex, see codex.ts) turn them into a deny.
   */
  | { decision: "ask"; reason: string; message: string; hard?: boolean }
  | { decision: "pass"; reason: string }

const allow = (reason: string): HookDecision => ({ decision: "allow", reason })
const feedback = (suggestion: string): HookDecision => ({ decision: "feedback", suggestion })
const prompt = (reason: string, message: string): HookDecision => ({ decision: "ask", reason, message })
const hardStop = (reason: string, message: string): HookDecision => ({ decision: "ask", reason, message, hard: true })
const pass = (reason: string): HookDecision => ({ decision: "pass", reason })

export interface DecideDeps {
  config: HallPassConfig
  shfmtBin: string
  debug: DebugFn
  audit: AuditLogger
  /** Claude Code's `permission_mode` for this call (auto, default, plan, acceptEdits, bypassPermissions, dontAsk). */
  mode?: string
  /** The hook input's `cwd`: where the command runs. Git rules that look at the repository need it. */
  cwd?: string
}

/**
 * Permission modes in which a hook "ask" is the ONLY thing that can put a
 * prompt in front of the user for a judgment call.
 *
 * A hook that returns "ask" forces a prompt in every mode — Claude Code's
 * docs say so outright, and the audit log agrees: in auto mode an "ask" from
 * this hook was followed by a visible prompt 76% of the time, while a "pass"
 * (no opinion) was followed by one 2% of the time. Both ran 96% of the time.
 * Auto mode has its own reviewer, the classifier, which reads the same
 * command and the conversation around it; bypassPermissions is the user
 * saying "don't ask". In these modes an "ask" for a judgment call — is this
 * rm/sudo/ssh/inline-perl what the user meant? — adds a prompt that would
 * not otherwise exist, and the recorded approval rate for those prompts is
 * 96%. So here the hook steps aside on judgment calls and keeps "ask" for
 * the hard stops only (EvalResult.hard, and the pre-parse checks below).
 *
 * Plan mode runs shell commands through the same classifier while the
 * `useAutoModeDuringPlan` setting is on, its default (Claude Code's
 * permission-modes docs). The audit log agrees: from 2026-09-12 to
 * 2026-10-01, 8 of 8 plan-mode "pass" decisions ran with no native prompt,
 * while 9 of 12 plan-mode "ask"s drew one about 6s later; one session was
 * stopped five times on an rm of its own scratchpad. With that setting off,
 * a "pass" falls back to Claude Code's own prompt, so nothing goes unasked.
 *
 * Not listed: `default`/`acceptEdits` (Claude Code would prompt natively for
 * the same command, so "ask" costs nothing and carries a better message),
 * `dontAsk` (a "pass" there is a denial).
 */
export const DEFER_MODES = new Set(["auto", "bypassPermissions", "plan"])

function defersToClassifier(deps: DecideDeps): boolean {
  return deps.config.classifier.defer && DEFER_MODES.has(deps.mode ?? "")
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
  const defer = defersToClassifier(deps)

  /** A judgment-call prompt in a DEFER_MODES session: recorded, then handed over. */
  const deferred = (reason: string): HookDecision => {
    audit.log({ tool: "Bash", input: command, decision: "pass", reason: `deferred: ${reason}`, layer: "classifier" })
    return pass(`deferred to classifier: ${reason}`)
  }

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
      return hardStop(`path-blocked: ${decision.reason}`, `File path ${decision.reason}`)
    }

    const content = (toolInput.content ?? toolInput.new_string ?? "") as string
    if (content) {
      const secret = detectSecret(content)
      if (secret) {
        audit.log({ tool: toolName, input: filePath, decision: "prompt", reason: `secret: ${secret.type}`, layer: "secrets" })
        return hardStop(`secret in ${toolName.toLowerCase()}: ${secret.type}`, `${toolName} contains a hardcoded ${secret.type} (${secret.preview})`)
      }
    }

    audit.log({ tool: toolName, input: filePath, decision: "allow", reason: "no path match", layer: "paths" })
    return allow("write/edit allowed")
  }

  // -- apply_patch path (Codex): the same checks, over every file in the patch --
  if (toolName === "apply_patch") {
    const files = parseApplyPatch(command)
    if (files === null) {
      debug("apply_patch", "no *** Begin Patch marker")
      audit.log({ tool: toolName, input: command.slice(0, 200), decision: "pass", reason: "unparseable patch", layer: "paths" })
      return pass("apply_patch: no patch found in input")
    }
    const paths = files.map((f) => (f.movedTo ? `${f.path} -> ${f.movedTo}` : f.path)).join(", ")
    debug("apply_patch", { files: paths })

    const check = checkPatch(files, config)
    if (!check.ok) {
      const layer = check.reason.startsWith("secret") ? "secrets" : "paths"
      audit.log({ tool: toolName, input: paths, decision: "prompt", reason: check.reason, layer })
      return hardStop(check.reason, check.message)
    }

    audit.log({ tool: toolName, input: paths, decision: "allow", reason: "no path match", layer: "paths" })
    return allow(`apply_patch: ${files.length} file(s) allowed`)
  }

  // -- Bash path --
  if (!command) {
    debug("bash", "empty command")
    if (defer) return deferred("empty command")
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

  // Unparseable: this hook has no opinion to offer. The classifier reads
  // the raw text and can still judge it, so in DEFER_MODES step aside.
  if (proc.exitCode !== 0) {
    debug("shfmt", "parse failed")
    if (defer) return deferred("shfmt failed")
    return prompt("shfmt failed", "Could not parse command")
  }

  let ast: unknown
  try {
    ast = JSON.parse(stdout)
  } catch {
    debug("shfmt", "JSON parse failed")
    if (defer) return deferred("shfmt json failed")
    return prompt("shfmt json failed", "Could not parse command")
  }

  // -- Pre-parse checks (on raw command string) --

  const secret = detectSecret(command)
  if (secret) {
    debug("secret", secret)
    audit.log({ tool: "Bash", input: command, decision: "prompt", reason: `secret: ${secret.type}`, layer: "secrets" })
    return hardStop(`secret: ${secret.type}`, `Command contains a hardcoded ${secret.type} (${secret.preview})`)
  }

  const exfilDomain = detectExfilDomain(command)
  if (exfilDomain) {
    debug("exfil", { domain: exfilDomain })
    audit.log({ tool: "Bash", input: command, decision: "prompt", reason: `exfil: ${exfilDomain}`, layer: "network" })
    return hardStop(`exfil: ${exfilDomain}`, `Command targets known data-exfiltration service "${exfilDomain}"`)
  }

  // -- Extract commands and AST-level data --

  const commandInfos = extractCommandInfos(ast, literalVariables(ast))
  debug("commands", commandInfos.map((c) => c.name))

  // Every value a variable could hold on this line (values.ts). The checks
  // below run against those values as well as the words as written, so
  // `E=.env; echo x > $E` stops like `echo x > .env`. A value nobody can read
  // where a protected check looks is a judgment call, held here until every
  // command has had its chance at a hard stop.
  const values = possibleValues(ast)
  let unreadable: { reason: string; message: string } | null = null

  const redirects = extractRedirects(ast)
  debug("redirects", redirects)

  // Exfiltration domains, once more over the words with quotes removed and
  // variables substituted: `H=pastebin.com; curl https://$H/x`.
  const words = [...commandInfos.flatMap((c) => c.args.slice(1)), ...redirects.filter((r) => !r.kind).map((r) => r.path)]
  for (const word of words) {
    for (const expanded of substitute(word, values)) {
      const domain = detectExfilDomain(expanded)
      if (domain) {
        debug("exfil", { domain, word })
        audit.log({ tool: "Bash", input: command, decision: "prompt", reason: `exfil: ${domain}`, layer: "network" })
        return hardStop(`exfil: ${domain}`, `Command targets known data-exfiltration service "${domain}"`)
      }
      const host = urlHost(expanded)
      if (host !== null && hasPlaceholder(host)) {
        unreadable ??= { reason: `url-unknown: ${host}`, message: `A URL's host is held in a variable hall-pass cannot read (${word})` }
      }
    }
  }

  // Pipe target inspection — genuine `curl | bash`, NOT `&&`/`||` chains.
  const PIPE_SHELLS = new Set(["sh", "bash", "zsh", "dash", "fish", "eval"])
  for (const name of extractPipeTargets(ast)) {
    if (PIPE_SHELLS.has(name)) {
      debug("pipe-target", { name })
      audit.log({ tool: "Bash", input: command, decision: "prompt", reason: `pipe to ${name}`, layer: "pipe-target" })
      return hardStop(`pipe to ${name}`, `Piping into "${name}" executes arbitrary piped content as code`)
    }
  }

  // Redirects against protected paths, as written and with each value
  // their variables could hold.
  for (const redir of redirects) {
    const op = redir.op === "write" ? ("write" as const) : ("read" as const)
    const expanded = redir.kind ? [] : substitute(redir.path, values)
    for (const path of new Set([redir.path, ...expanded])) {
      const decision = checkFilePath(path, op, config)
      if (!decision.allowed) {
        debug("redirect-block", { path, op, reason: decision.reason })
        audit.log({ tool: "Bash", input: command, decision: "prompt", reason: `redirect ${decision.reason}`, layer: "paths" })
        return hardStop(`redirect-blocked: ${decision.reason}`, `Redirect targets ${decision.reason}`)
      }
    }
    if (expanded.some(hasPlaceholder)) {
      unreadable ??= { reason: `redirect-unknown: ${redir.path}`, message: `Redirect target is held in a variable hall-pass cannot read (${redir.path})` }
    }
  }

  // Pipeline-level feedback rules (cross-command patterns). A nudge is an
  // ALLOW with advice attached, so it can't be the verdict until every
  // command in the pipeline has been looked at: `curl … | python3 -c …` earns
  // a "use jq" nudge for the python3, but if the same line also does
  // `&& rm -rf …` the rm still has to be judged.
  let suggestion: string | null = checkFeedbackRules(commandInfos)
  let suggestionLayer = "feedback"
  if (suggestion) debug("feedback", { suggestion })

  /** The held judgment call, once nothing on the line was a hard stop. */
  const settleUnreadable = (): HookDecision | null => {
    if (!unreadable) return null
    debug("unreadable", unreadable)
    if (defer) return deferred(unreadable.reason)
    audit.log({ tool: "Bash", input: command, decision: "prompt", reason: unreadable.reason, layer: "placeholders" })
    return prompt(unreadable.reason, unreadable.message)
  }

  // No commands found (e.g., bare variable assignment) — safe
  if (commandInfos.length === 0) {
    const held = settleUnreadable()
    if (held) return held
    audit.log({ tool: "Bash", input: command, decision: "allow", reason: "no commands", layer: "safelist" })
    return allow("no commands (variable assignment)")
  }

  // -- Per-command evaluation --
  const scope = scopeOf(rootScope(deps.cwd), ast, commandInfos, command)
  const ctx = createEvalContext(config, commandInfos, shfmtBin, deps.cwd, scope)
  const strictCtx: EvalContext = { ...ctx, strictPlaceholders: true, evaluate: (cmd) => evaluateBashCommand(cmd, strictCtx) }

  let hasPass = false
  let handedOver: string | null = null   // first judgment-call prompt deferred to the classifier
  for (const cmdInfo of commandInfos) {
    const result = evaluateWithValues(cmdInfo, values, ctx, strictCtx)
    debug("eval", { name: cmdInfo.name, decision: result.decision })

    if (result.decision === "feedback") {
      if (!suggestion) { suggestion = result.suggestion; suggestionLayer = "evaluate" }
      continue
    }

    if (result.decision === "prompt") {
      if (defer && !result.hard) {
        debug("defer", { name: cmdInfo.name, reason: result.reason })
        handedOver ??= result.reason
        continue   // a later command may still be a hard stop
      }
      audit.log({ tool: "Bash", input: command, decision: "prompt", reason: result.reason, layer: "evaluate" })
      return result.hard ? hardStop(result.reason, result.message) : prompt(result.reason, result.message)
    }

    if (result.decision === "pass") {
      hasPass = true
    }
  }

  // Precedence once every command has been seen: a deferred judgment call
  // outranks a nudge (the nudge would be an allow, and the classifier has
  // to see the command); a nudge outranks an unknown command, as before.
  if (handedOver) return deferred(handedOver)
  const held = settleUnreadable()
  if (held) return held

  if (suggestion) {
    audit.log({ tool: "Bash", input: command, decision: "feedback", reason: suggestion, layer: suggestionLayer })
    return feedback(suggestion)
  }

  // If any command was unknown (pass), step aside — let Claude Code decide
  if (hasPass) {
    audit.log({ tool: "Bash", input: command, decision: "pass", reason: "unknown commands in pipeline", layer: "evaluate" })
    return pass("pipeline contains unknown commands")
  }

  audit.log({ tool: "Bash", input: command, decision: "allow", reason: "all commands safe", layer: "evaluate" })
  return allow("all commands safe")
}

/**
 * One command, judged as written and with each value its variables could
 * hold (values.ts). The command as written is judged by today's rules, so a
 * guessed value can never talk a rule into an allow. A variant can only add
 * a protected stop (the hard prompt its typed-out form gets) or, judged under
 * strictPlaceholders, the judgment call for a value nobody can read. Its
 * other judgment calls are dropped: a rule that allowed the command as
 * written read the variable on purpose (safe_scripts lists
 * `$HOME/.claude/...`, vars.ts resolves `$S` for rm).
 */
function evaluateWithValues(cmdInfo: CommandInfo, values: PossibleValues, ctx: EvalContext, strictCtx: EvalContext): EvalResult {
  const variants = commandVariants(cmdInfo, values)
  if (variants.length === 0) return strictCtx.evaluate(cmdInfo)

  const asWritten = ctx.evaluate(cmdInfo)
  if (asWritten.decision === "prompt") return asWritten
  let judgment: EvalResult | null = null
  for (const variant of variants) {
    const result = strictCtx.evaluate(variant)
    if (result.decision !== "prompt") continue
    if (result.hard) return result
    if (result.unreadable) judgment ??= result
  }
  return judgment ?? asWritten
}

/** The command with its variables replaced by candidate values; empty when none of its words change. */
function commandVariants(cmdInfo: CommandInfo, values: PossibleValues): CommandInfo[] {
  const options = cmdInfo.args.map((arg) => substitute(arg, values))
  if (options.every((o, i) => o.length === 1 && o[0] === cmdInfo.args[i])) return []

  let combos: string[][] = [[]]
  for (const opts of options) {
    const next: string[][] = []
    for (const combo of combos) {
      for (const o of opts) {
        if (next.length >= MAX_VARIANTS) break
        next.push([...combo, o])
      }
    }
    combos = next
  }
  return combos.map((args) => {
    const name = args[0]!.split("/").pop()!
    return { ...cmdInfo, name, args: [name, ...args.slice(1)] }
  })
}

/** The host of an http(s) URL in a word, without user info or port; null when the word has none. */
function urlHost(word: string): string | null {
  const m = word.match(/https?:\/\/([^/?#\s]*)/i)
  if (!m) return null
  return m[1]!.replace(/^.*@/, "").replace(/:[^:]*$/, "")
}
