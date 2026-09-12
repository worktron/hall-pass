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
 *   5b. throwawayRm / repositoryScript   — rm judged by its targets, a shell by its file
 *   6. INSPECTORS[name]?                   — git, find, xargs, sed, docker, DB...
 *        └─ may call ctx.evaluate() for sub-commands → full recursion
 *   7. unknown → prompt
 */

import { resolve, isAbsolute } from "path"
import { lstatSync } from "fs"
import type { CommandInfo } from "./parser.ts"
import { expandTilde, type HallPassConfig } from "./config.ts"
import { isInsideScratchDir, gitTracksFile } from "./repo.ts"
import { SAFE_COMMANDS, DANGEROUS_COMMANDS, DB_CLIENTS, DANGEROUS_ENV_VARS, INJECTION_ENV_VARS } from "./safelist.ts"
import { INSPECTORS } from "./inspectors.ts"
import { unwrapCommand } from "./wrappers.ts"
import { isPathAwareCommand, checkCommandPaths } from "./paths.ts"
import { checkCommandFeedback } from "./feedback.ts"
import { extractSqlFromArgs, isSqlReadOnly } from "./sql.ts"

export type EvalResult =
  | { decision: "allow"; reason: string }
  /**
   * `hard` marks a prompt that stands in every permission mode: protected
   * paths, code injection, pushes to protected branches. Every other prompt
   * is a judgment call about intent, and in a mode where Claude Code has its
   * own reviewer (auto mode's classifier) decide.ts hands it over instead of
   * forcing the user to answer — see DEFER_MODES there.
   */
  | { decision: "prompt"; reason: string; message: string; hard?: boolean }
  | { decision: "pass"; reason: string }
  | { decision: "feedback"; suggestion: string }

export interface EvalContext {
  config: HallPassConfig
  configSafe: Set<string>
  dbClients: Set<string>
  protectedBranches?: Set<string>
  safeSubcommands?: Set<string>
  shfmtBin: string
  /** Where the command runs (the hook's cwd); git rules that look at the repository use it. */
  cwd?: string
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
  cwd?: string,
): EvalContext {
  const configSafe = new Set(config.commands.safe)
  const dbClients = new Set([...DB_CLIENTS, ...config.commands.db_clients])
  const protectedBranches = config.git.protected_branches.length > 0
    ? new Set(config.git.protected_branches)
    : undefined
  const safeSubcommands = config.git.safe_subcommands.length > 0
    ? new Set(config.git.safe_subcommands)
    : undefined

  const ctx: EvalContext = {
    config,
    configSafe,
    dbClients,
    protectedBranches,
    safeSubcommands,
    shfmtBin,
    cwd,
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
      return {
        decision: "prompt",
        reason: `dangerous env: ${assign.name}`,
        message: `Sets dangerous variable "${assign.name}"`,
        hard: INJECTION_ENV_VARS.has(assign.name),
      }
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
      return { decision: "prompt", reason: `path-blocked: ${name} ${pathDecision.reason}`, message: `"${name}" targets ${pathDecision.reason}`, hard: true }
    }
  }

  // 5. Safe commands — auto-approve
  if (SAFE_COMMANDS.has(name) || ctx.configSafe.has(name)) {
    return { decision: "allow", reason: `safe: ${name}` }
  }

  // 5b. Two rules that refine the prompts below by reading the operands:
  //     rm on throwaway paths, a shell running the repository's own script.
  //     Each allows or stays silent, so the messages below are unchanged.
  if (name === "rm") {
    const refined = throwawayRm(cmdInfo, ctx)
    if (refined) return refined
  } else if (SCRIPT_SHELLS.has(name)) {
    const refined = repositoryScript(cmdInfo, ctx)
    if (refined) return refined
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

/** Characters the shell would still expand, or that the parser left as a placeholder: no rule here can place such a path. */
const UNRESOLVABLE_PATH = /[*?\[\]{}$`]/

/** True when a path has a `..` segment: it may climb out of wherever its prefix put it. */
function climbsOut(path: string): boolean {
  return path.split("/").includes("..")
}

/**
 * `rm` judged by its targets rather than its name. Allowed when every
 * target is a literal path that lands strictly inside a throwaway root
 * (isInsideScratchDir: the OS tmpdir, $TMPDIR, /tmp, /var/folders, a
 * `scratchpad` directory) with no `..` segment; `-r` and `-f` change
 * nothing. `$TMPDIR/x` is read with the hook's own TMPDIR, since the
 * command's shell inherits the same one. A bare `rm -rf`, a root itself
 * (`rm -rf /tmp`), a glob, any other variable, a relative path with no cwd,
 * or a target anywhere else keeps the dangerous-command prompt.
 */
function throwawayRm(cmdInfo: CommandInfo, ctx: EvalContext): EvalResult | null {
  const targets: string[] = []
  let optionsDone = false
  for (const arg of cmdInfo.args.slice(1)) {
    if (!optionsDone && arg === "--") { optionsDone = true; continue }
    if (!optionsDone && arg.startsWith("-") && arg !== "-") continue
    targets.push(arg)
  }
  if (targets.length === 0) return null

  for (const raw of targets) {
    let target = raw
    if (target === "$TMPDIR" || target.startsWith("$TMPDIR/")) {
      const tmp = process.env.TMPDIR
      if (!tmp) return null
      target = tmp.replace(/\/+$/, "") + target.slice("$TMPDIR".length)
    }
    if (UNRESOLVABLE_PATH.test(target) || climbsOut(target)) return null
    target = expandTilde(target)
    if (!isAbsolute(target)) {
      if (!ctx.cwd) return null
      target = resolve(ctx.cwd, target)
    }
    if (!isInsideScratchDir(target)) return null
  }
  return { decision: "allow", reason: "rm: throwaway paths" }
}

const SCRIPT_SHELLS = new Set(["sh", "bash", "zsh"])

/**
 * `bash <file>` (`sh`, `zsh`) judged by the file it runs. Allowed when the
 * file is a regular file the repository at the hook's cwd tracks
 * (gitTracksFile), named by a literal path with no `..` segment, and is not
 * itself a symlink (git never tracks a path through one, so the file is in
 * the tree). Running the repository's own script by name is the same act as
 * `./scripts/x.sh`, which the safelist never asked about. A `-c` string, a
 * script on stdin (`bash -`, a heredoc, a pipe), an untracked file, a file
 * outside the repository, or no cwd stays with the shell inspector.
 */
function repositoryScript(cmdInfo: CommandInfo, ctx: EvalContext): EvalResult | null {
  if (!ctx.cwd) return null
  let script: string | null = null
  for (const arg of cmdInfo.args.slice(1)) {
    if (arg.startsWith("-")) {
      // -c, alone or in a cluster (-xc): the program is the next argument, not a file.
      if (!arg.startsWith("--") && arg.includes("c")) return null
      continue
    }
    script = arg
    break
  }
  if (!script) return null
  if (UNRESOLVABLE_PATH.test(script) || climbsOut(script)) return null
  if (script.startsWith("~") || script.startsWith(":")) return null   // not a plain path, or pathspec magic
  if (!gitTracksFile(ctx.cwd, script)) return null
  try {
    if (!lstatSync(resolve(ctx.cwd, script)).isFile()) return null
  } catch {
    return null
  }
  return { decision: "allow", reason: `${cmdInfo.name}: repository script ${script}` }
}

/**
 * Generic DB client inspector — extracts SQL and checks read-only.
 *
 * SQL reaches a client two ways: inline on the command line (`-c`, `-e`, a
 * positional) or on standard input, which in practice means a heredoc:
 *
 *   psql "$DB" -X <<'EOF'
 *   select ... ;
 *   EOF
 *
 * Only the first was ever read. A heredoc is a redirect rather than an
 * argument, so extractSqlFromArgs returned null and every such command
 * prompted — not because the SQL looked risky, but because nothing looked
 * at it. Heredoc SQL is now checked by the same read-only rules.
 *
 * Both sources are checked when both are present.
 */
function dbClientInspect(cmdInfo: CommandInfo): EvalResult {
  const { name, args, stdin } = cmdInfo
  const inlineSql = extractSqlFromArgs(name, args)

  const sources = [inlineSql, stdin].filter((s): s is string => s !== null && s !== undefined)
  if (sources.length > 0 && sources.every(isSqlReadOnly)) {
    return { decision: "allow", reason: `db read-only: ${name}` }
  }
  return { decision: "prompt", reason: `db client: ${name}`, message: `"${name}" session may modify data` }
}
