/**
 * Unified recursive command evaluation.
 *
 * Every command — top-level and recursive (find -exec, xargs) — flows
 * through `evaluateBashCommand`. This replaces the scattered checks in
 * hook.ts with a single pipeline:
 *
 *   1. unwrapCommand()                     — nohup, nice, timeout
 *   2. check env vars (DANGEROUS_ENV_VARS) — LD_PRELOAD etc.
 *   3. checkCommandFeedback(cmd, pipeline) — per-command feedback rules
 *   4. path check (only PATH_AWARE cmds)   — cat, rm, cp, mv, chmod...
 *   5. SAFE_COMMANDS || configSafe         — auto-approve
 *   6. INSPECTORS[name]?                   — git, find, xargs, sed, docker, DB...
 *        └─ may call ctx.evaluate() for sub-commands → full recursion
 *   7. unknown → prompt
 */

import type { CommandInfo } from "./parser.ts"
import type { HallPassConfig } from "./config.ts"
import { SAFE_COMMANDS, DANGEROUS_COMMANDS, DB_CLIENTS, DANGEROUS_ENV_VARS } from "./safelist.ts"
import { INSPECTORS } from "./inspectors.ts"
import { unwrapCommand } from "./wrappers.ts"
import { isPathAwareCommand, checkCommandPaths } from "./paths.ts"
import { checkCommandFeedback } from "./feedback.ts"
import { extractSqlFromArgs, isSqlReadOnly } from "./sql.ts"

export type EvalResult =
  | { decision: "allow"; reason: string }
  | { decision: "prompt"; reason: string; message: string }
  | { decision: "pass"; reason: string }
  | { decision: "feedback"; suggestion: string }

export interface EvalContext {
  config: HallPassConfig
  configSafe: Set<string>
  dbClients: Set<string>
  protectedBranches?: Set<string>
  shfmtBin: string
  pipelineCommands: CommandInfo[]
  evaluate: (cmd: CommandInfo) => EvalResult
}

/**
 * Create an evaluation context with a self-referential evaluate closure.
 */
export function createEvalContext(
  config: HallPassConfig,
  pipelineCommands: CommandInfo[],
  shfmtBin: string = "shfmt",
): EvalContext {
  const configSafe = new Set(config.commands.safe)
  const dbClients = new Set([...DB_CLIENTS, ...config.commands.db_clients])
  const protectedBranches = config.git.protected_branches.length > 0
    ? new Set(config.git.protected_branches)
    : undefined

  const ctx: EvalContext = {
    config,
    configSafe,
    dbClients,
    protectedBranches,
    shfmtBin,
    pipelineCommands,
    evaluate: (cmd) => evaluateBashCommand(cmd, ctx),
  }

  return ctx
}

/**
 * Evaluate a single command through the full pipeline.
 * Called for top-level commands and recursively for sub-commands.
 */
export function evaluateBashCommand(rawCmdInfo: CommandInfo, ctx: EvalContext): EvalResult {
  // 1. Unwrap transparent wrappers (nohup, nice, timeout)
  const cmdInfo = unwrapCommand(rawCmdInfo)
  const { name } = cmdInfo

  // 2. Check env var assignments for dangerous variables
  for (const assign of cmdInfo.assigns) {
    if (DANGEROUS_ENV_VARS.has(assign.name)) {
      return { decision: "prompt", reason: `dangerous env: ${assign.name}`, message: `Sets dangerous variable "${assign.name}"` }
    }
  }

  // 3. Per-command feedback rules
  const feedback = checkCommandFeedback(cmdInfo, ctx.pipelineCommands)
  if (feedback) {
    return { decision: "feedback", suggestion: feedback }
  }

  // 4. Path checking (only for commands whose positional args are file paths)
  if (isPathAwareCommand(name)) {
    const pathDecision = checkCommandPaths(cmdInfo, ctx.config)
    if (!pathDecision.allowed) {
      return { decision: "prompt", reason: `path-blocked: ${name} ${pathDecision.reason}`, message: `"${name}" targets ${pathDecision.reason}` }
    }
  }

  // 5. Safe commands — auto-approve
  if (SAFE_COMMANDS.has(name) || ctx.configSafe.has(name)) {
    return { decision: "allow", reason: `safe: ${name}` }
  }

  // 6. Named inspectors (git, find, xargs, sed, docker, etc.)
  const inspector = INSPECTORS[name]
  if (inspector) {
    return inspector(cmdInfo, ctx)
  }

  // DB clients (built-in + config-added) get SQL inspection
  if (ctx.dbClients.has(name)) {
    return dbClientInspect(cmdInfo)
  }

  // 7. Dangerous commands — always prompt
  if (DANGEROUS_COMMANDS.has(name)) {
    return { decision: "prompt", reason: `dangerous: ${name}`, message: `"${name}" is a destructive command` }
  }

  // 8. Unknown command → pass (no opinion, let Claude Code decide)
  return { decision: "pass", reason: `unknown: ${name}` }
}

/**
 * Generic DB client inspector — extracts SQL and checks read-only.
 */
function dbClientInspect(cmdInfo: CommandInfo): EvalResult {
  const { name, args } = cmdInfo
  const sql = extractSqlFromArgs(name, args)
  const readOnly = sql ? isSqlReadOnly(sql) : false
  if (sql && readOnly) {
    return { decision: "allow", reason: `db read-only: ${name}` }
  }
  return { decision: "prompt", reason: `db client: ${name}`, message: `"${name}" session may modify data` }
}
