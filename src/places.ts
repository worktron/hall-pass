/**
 * Where a script's relative paths land, and whether its `$TMPDIR` is the
 * hook's own.
 *
 * Two rules in evaluate.ts judge a command by a path: throwawayRm (is every
 * target inside a throwaway directory?) and repositoryScript (does the
 * repository track the script a shell runs?). Both used to resolve a
 * relative path against the hook's cwd and `$TMPDIR` against the hook's own
 * environment, so a line that moved first was judged in the wrong place:
 *
 *   cd ~/Workspace/proj && rm -rf src          (hook cwd: a scratchpad)
 *   cd /tmp/evil && bash bin/run-hook.sh       (the repository tracks bin/run-hook.sh)
 *   TMPDIR=$HOME; rm -rf $TMPDIR/Documents
 *
 * A Scope answers both questions for one script, without tracking which
 * command runs after which `cd` (`;`, `||`, subshells and loops make that a
 * control-flow question). A relative path has to pass in every directory the
 * script could be standing in: the one it starts in plus every `cd`/`pushd`
 * target. One shape is read more closely, because agents write it all the
 * time: a script that is a single `cd /dir && …` chain never runs anything
 * after a failed cd, so the starting directory drops out.
 */

import { isAbsolute } from "path"
import { BINARY, type CommandInfo } from "./parser.ts"
import { expandTilde } from "./config.ts"
import { unwrapCommand } from "./wrappers.ts"
import { scanWriters } from "./vars.ts"

export interface Scope {
  /** Every directory a relative path may be resolved against; null when a directory change cannot be placed. */
  places: string[] | null
  /** True when `$TMPDIR` is the hook's own TMPDIR: nothing in the script, or around it, can have set it. */
  tmpdirTrusted: boolean
}

/** A script with nothing around it: it starts in the hook's cwd, with the hook's environment. */
export function rootScope(cwd?: string): Scope {
  return { places: cwd ? [cwd] : null, tmpdirTrusted: true }
}

type Node = Record<string, unknown>

/**
 * The scope of a script that starts in `outer`. `ast` is the script's shfmt
 * AST, `commands` its commands as extractCommandInfos returned them (in
 * source order), `text` the script itself.
 */
export function scopeOf(outer: Scope, ast: unknown, commands: CommandInfo[], text: string): Scope {
  return {
    places: placesOf(outer.places, ast, commands),
    tmpdirTrusted: outer.tmpdirTrusted && !writesTmpdir(ast, text),
  }
}

function placesOf(start: string[] | null, ast: unknown, commands: CommandInfo[]): string[] | null {
  const targets: string[] = []
  for (const cmd of commands) {
    const target = dirChange(cmd)
    if (target === undefined) continue
    if (target === null) return null
    targets.push(target)
  }
  if (targets.length === 0) return start
  const base = leadsWithCd(ast) ? [] : start
  if (base === null) return null
  return [...new Set([...base, ...targets])]
}

const DIR_CHANGERS = new Set(["cd", "pushd", "popd"])

/** Options of cd and pushd that still take the directory operand as given. */
const PLAIN_CD_OPTIONS = /^-[LPe@]+$/

/**
 * The directory a command moves to: undefined when it does not change
 * directory, null when it does and the place cannot be named (a variable,
 * a relative path, `-`, a bare `cd`, `popd`, `pushd +1`, `cd old new`).
 * A variable the line set to a literal path reads as that path (resolvedArgs).
 */
function dirChange(raw: CommandInfo): string | null | undefined {
  const cmd = unwrapCommand(raw)
  let args = cmd.resolvedArgs ?? cmd.args
  // `builtin cd`, `command cd`
  while (args[0] === "builtin" || args[0] === "command") {
    let i = 1
    while (i < args.length && args[i]!.startsWith("-")) i++
    args = args.slice(i)
  }
  const name = args[0]?.split("/").pop()
  if (!name || !DIR_CHANGERS.has(name)) return undefined
  if (name === "popd") return null

  const operands: string[] = []
  let optionsDone = false
  for (const arg of args.slice(1)) {
    if (!optionsDone && arg === "--") { optionsDone = true; continue }
    if (!optionsDone && PLAIN_CD_OPTIONS.test(arg)) continue
    if (!optionsDone && (arg.startsWith("-") || arg.startsWith("+"))) return null
    operands.push(arg)
  }
  if (operands.length !== 1) return null

  const target = expandTilde(operands[0]!)
  if (!isAbsolute(target) || /[*?\[\]{}$`]/.test(target) || target.split("/").includes("..")) return null
  return target.replace(/(.)\/+$/, "$1")
}

/**
 * True when the whole script is one `cd /dir && …` chain: a single statement
 * whose left spine is `&&` all the way down to a plain `cd` or `pushd`, with
 * nothing negated or backgrounded on the way. Nothing in it runs unless the
 * cd succeeded. The caller has already checked the cd's target.
 */
function leadsWithCd(ast: unknown): boolean {
  const stmts = (ast as Node | null)?.Stmts
  if (!Array.isArray(stmts) || stmts.length !== 1) return false
  let stmt = stmts[0] as Node
  for (;;) {
    if (stmt.Negated || stmt.Background || stmt.Coprocess) return false
    const cmd = stmt.Cmd as Node | undefined
    if (!cmd) return false
    if (cmd.Type === "BinaryCmd") {
      if (cmd.Op !== BINARY.and) return false
      stmt = cmd.X as Node
      continue
    }
    if (cmd.Type !== "CallExpr") return false
    const first = ((cmd.Args as Node[] | undefined)?.[0]?.Parts as Node[] | undefined)?.[0]
    return first?.Type === "Lit" && (first.Value === "cd" || first.Value === "pushd")
  }
}

/**
 * True when the script may set TMPDIR. Any mention of the name other than a
 * plain `$TMPDIR` or `${TMPDIR}` counts (`TMPDIR=x`, `TMPDIR=x rm …`,
 * `export`, `read`, `for … in`, `unset`, `${TMPDIR:=x}`), and so does a
 * script that can write a variable its text does not name (scanWriters:
 * `eval`, `declare $V=…`, arithmetic). A false positive costs only a prompt.
 */
function writesTmpdir(ast: unknown, text: string): boolean {
  const others = text.replace(/\$TMPDIR(?!\w)|\$\{TMPDIR\}/g, "")
  return others.includes("TMPDIR") || scanWriters(ast).unbounded
}
