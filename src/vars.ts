/**
 * Variables a command line sets to a literal path, read back where the
 * line uses them.
 *
 *   S=/tmp/claude-501/…/scratchpad/mt2; rm -rf $S; mkdir -p $S
 *
 * The parser renders `$S` as a placeholder, so a rule that judges paths
 * (throwawayRm) cannot see that `$S` is a scratch directory. literalVariables
 * finds the variables whose value at every later read is known from the text
 * alone; extractCommandInfos substitutes them into CommandInfo.resolvedArgs.
 *
 * The rule is strict, and any doubt drops the variable:
 *   - set by a bare assignment that is its own top-level statement (not
 *     `S=x cmd`, not inside `&&`, `if`, a loop, a subshell or a function),
 *     not backgrounded, to a literal absolute path with no whitespace,
 *     backslash, tilde or glob character;
 *   - assigned exactly once anywhere in the script;
 *   - never named by anything else that can write it: `for S in`, `read`,
 *     `printf -v`, `unset`, `export`/`declare`/`local`, `${S:=x}`,
 *     `coproc S`, `exec {S}>file`;
 *   - not a variable the shell maintains itself (`PWD`, `_`, `REPLY`…).
 * And nothing resolves at all when the script can write a variable whose
 * name its text does not show: it runs a string as code (`eval`, `source`,
 * `trap`, a command whose name is an expansion), names a writer's target
 * with an expansion (`read $V`), declares a nameref or integer variable,
 * does any arithmetic (bash evaluates a variable's value as an expression,
 * so `X='S=5'; (( X ))` assigns S), or touches IFS.
 * Only a plain read (`$S`, `${S}`) that comes after the assignment in the
 * text resolves; `${S:-x}` and other expansions keep their placeholder.
 */

export interface LiteralVar {
  /** The value the assignment gives the variable. */
  value: string
  /** Offset where the assigning statement ends: a read before it sees the inherited value. */
  after: number
}

export type LiteralVars = ReadonlyMap<string, LiteralVar>

type Node = Record<string, unknown>

/** Variables the shell sets on its own (cd, read, getopts, every command for `_`). */
const SHELL_MANAGED = new Set([
  "_", "PWD", "OLDPWD", "REPLY", "OPTARG", "OPTIND", "RANDOM", "SRANDOM", "SECONDS",
  "LINENO", "BASHPID", "PPID", "UID", "EUID", "GROUPS", "PIPESTATUS", "FUNCNAME",
  "HISTCMD", "EPOCHSECONDS", "EPOCHREALTIME", "COLUMNS", "LINES", "MAPFILE", "COPROC",
  "IFS", "HOSTNAME", "SHLVL", "DIRSTACK",
])

/** Builtins that run a string or a file as shell code: anything could be assigned. */
const EVALUATORS = new Set(["eval", "source", ".", "trap", "alias", "enable", "fc"])

/** Builtins that write a variable named by an argument (printf only with -v: writesWithV). */
const VARIABLE_WRITERS = new Set(["read", "mapfile", "readarray", "getopts", "unset", "wait"])

/** Arithmetic evaluates variables' values as expressions, which can assign anything. */
const ARITHMETIC_NODES = new Set(["ArithmCmd", "ArithmExp", "LetClause", "CStyleLoop"])

/**
 * `[[ ]]` operators that compare as arithmetic (-eq -ne -le -ge -lt -gt),
 * as the pinned shfmt numbers them; vars.test.ts checks each one.
 */
export const ARITHMETIC_TESTS: ReadonlySet<number> = new Set([133, 134, 135, 136, 137, 138])

/** ParamExp fields that make it more than a read of the value. */
const EXPANSION_FIELDS = ["Excl", "Length", "Width", "Index", "Slice", "Repl", "Names", "Exp", "NestedParam"]

/** True for `$S` and `${S}`: a read of the value with nothing applied to it. */
export function isPlainRead(part: Node): boolean {
  return part.Type === "ParamExp" && EXPANSION_FIELDS.every((f) => part[f] === undefined || part[f] === false)
}

/** The value a plain read of a known variable expands to here, or null. */
export function resolveRead(part: Node, vars: LiteralVars): string | null {
  if (!isPlainRead(part)) return null
  const name = (part.Param as Node | undefined)?.Value
  const known = typeof name === "string" ? vars.get(name) : undefined
  if (!known) return null
  const offset = (part.Pos as Node | undefined)?.Offset
  return typeof offset === "number" && offset > known.after ? known.value : null
}

export function literalVariables(ast: unknown): Map<string, LiteralVar> {
  const vars = new Map<string, LiteralVar>()
  const stmts = (ast as Node | null)?.Stmts
  if (!Array.isArray(stmts)) return vars

  for (const stmt of stmts as Node[]) {
    const cmd = stmt.Cmd as Node | undefined
    if (!cmd || cmd.Type !== "CallExpr") continue
    if ((cmd.Args as unknown[] | undefined)?.length) continue
    if (stmt.Background || stmt.Coprocess || stmt.Negated || (stmt.Redirs as unknown[] | undefined)?.length) continue
    const end = (stmt.End as Node | undefined)?.Offset
    if (typeof end !== "number") continue
    for (const assign of (cmd.Assigns as Node[] | undefined) ?? []) {
      const name = (assign.Name as Node | undefined)?.Value
      if (typeof name !== "string" || SHELL_MANAGED.has(name) || name.startsWith("BASH")) continue
      if (assign.Append || assign.Naked || assign.Array || assign.Index || !assign.Value) continue
      const value = literalText(assign.Value as Node)
      // An unquoted read would split on whitespace and glob on * ? [.
      if (value === null || !value.startsWith("/") || /[\s\\~*?[]/.test(value)) continue
      vars.set(name, { value, after: end })
    }
  }
  if (vars.size === 0) return vars

  const scan = scanWriters(ast)
  if (scan.unbounded) return new Map()
  for (const name of vars.keys()) {
    const named = scan.writerText.some((text) => text.includes(name))
    if (scan.assigns.get(name) !== 1 || scan.doubted.has(name) || named) vars.delete(name)
  }
  return vars
}

interface WriterScan {
  /** How many assignments name each variable, anywhere in the script. */
  assigns: Map<string, number>
  /** Variables written some other way (`for S in`) or expanded with an operator. */
  doubted: Set<string>
  /** Literal text in the arguments of a builtin that writes a variable it names. */
  writerText: string[]
  /** The script can write a variable its text does not name. */
  unbounded: boolean
}

function scanWriters(ast: unknown): WriterScan {
  const scan: WriterScan = { assigns: new Map(), doubted: new Set(), writerText: [], unbounded: false }

  const countAssign = (assign: Node) => {
    const name = (assign.Name as Node | undefined)?.Value
    if (typeof name !== "string") return
    scan.assigns.set(name, (scan.assigns.get(name) ?? 0) + 1)
    if (name === "IFS") scan.unbounded = true
  }

  /** A writer's arguments: their text names what it writes, and an expansion could name anything. */
  const writerArgs = (words: Node[]) => {
    for (const word of words) {
      const text = literalText(word)
      if (text === null) scan.unbounded = true
      else scan.writerText.push(text)
    }
  }

  const walk = (node: unknown): void => {
    if (Array.isArray(node)) {
      for (const item of node) walk(item)
      return
    }
    if (!node || typeof node !== "object") return
    const n = node as Node
    if (ARITHMETIC_NODES.has(n.Type as string)) scan.unbounded = true

    switch (n.Type) {
      case "CallExpr": {
        for (const assign of (n.Assigns as Node[] | undefined) ?? []) countAssign(assign)
        const name = commandName(n)
        const args = ((n.Args as Node[] | undefined) ?? []).slice(1)
        if (name === null || EVALUATORS.has(name)) scan.unbounded = true
        else if (VARIABLE_WRITERS.has(name) || (name === "printf" && writesWithV(n))) writerArgs(args)
        break
      }
      case "DeclClause":
        // export, declare, local, typeset, readonly
        for (const arg of (n.Args as Node[] | undefined) ?? []) {
          countAssign(arg)
          if (arg.Name) {
            // `declare -n r=S` names S in the value. An expanded value only
            // names a variable under -n, which makes the scan unbounded below.
            const value = arg.Value as Node | undefined
            const text = value ? literalText(value) : null
            if (text !== null) scan.writerText.push(text)
            continue
          }
          const word = arg.Value as Node | undefined
          const text = word ? literalText(word) : null
          // `declare $V`, or -n (nameref) / -i (integer: assignments are arithmetic)
          if (text === null || (/^[-+]/.test(text) && /[ni]/.test(text))) scan.unbounded = true
          else scan.writerText.push(text)
        }
        break
      case "TestClause":
      case "BinaryTest":
        if (ARITHMETIC_TESTS.has(n.Op as number)) scan.unbounded = true
        break
      case "CoprocClause": {
        // coproc NAME makes NAME an array of file descriptors.
        const word = n.Name as Node | undefined
        const name = word ? literalText(word) : ""
        if (name === null) scan.unbounded = true
        else if (name) scan.doubted.add(name)
        break
      }
      case "WordIter": {
        const name = (n.Name as Node | undefined)?.Value
        if (typeof name === "string") scan.doubted.add(name)
        break
      }
      case "ParamExp": {
        const name = (n.Param as Node | undefined)?.Value
        if (typeof name === "string" && !isPlainRead(n)) scan.doubted.add(name)
        // An index is arithmetic unless it is a plain number, @ or *.
        const index = n.Index as Node | undefined
        const indexText = index ? literalText(index) : ""
        if (n.Slice !== undefined || indexText === null || (indexText !== "" && !/^(\d+|@|\*)$/.test(indexText))) {
          scan.unbounded = true
        }
        break
      }
    }

    // A redirect `{S}>file` stores the file descriptor it opens in S.
    const fd = (n.N as Node | undefined)?.Value
    if (typeof fd === "string" && fd.startsWith("{")) scan.doubted.add(fd.slice(1, -1))

    for (const value of Object.values(n)) {
      if (value && typeof value === "object") walk(value)
    }
  }

  walk(ast)
  if (scan.writerText.some((text) => text.includes("IFS"))) scan.unbounded = true
  return scan
}

/**
 * The builtin a CallExpr runs, looking through `command` and `builtin`.
 * Null when the name is itself an expansion (`$X …` could be `eval`).
 * A bare assignment has no name, and runs nothing: "".
 */
function commandName(call: Node): string | null {
  const words = (call.Args as Node[] | undefined) ?? []
  let i = 0
  while (i < words.length) {
    const text = literalText(words[i]!)
    if (text === null) return null
    if (text !== "command" && text !== "builtin") return text
    i++
    while (i < words.length && literalText(words[i]!)?.startsWith("-")) i++
  }
  return ""
}

/** `printf -v NAME` or `printf -vNAME`: printf stores its output in a variable. */
function writesWithV(call: Node): boolean {
  return ((call.Args as Node[] | undefined) ?? []).some((w) => literalText(w)?.startsWith("-v") ?? true)
}

/** The text of a Word made only of literal parts, or null if the shell would expand any of it. */
function literalText(word: Node): string | null {
  const parts = word.Parts as Node[] | undefined
  if (!parts) return null
  let text = ""
  for (const part of parts) {
    if (part.Type === "Lit" || part.Type === "SglQuoted") text += String(part.Value ?? "")
    else if (part.Type === "DblQuoted") {
      const inner = part.Parts ? literalText(part) : ""
      if (inner === null) return null
      text += inner
    } else return null
  }
  return text
}
