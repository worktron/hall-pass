/**
 * Every value a shell variable could hold on one command line.
 *
 * The parser renders an expansion as a placeholder (`$E`), and the protected
 * checks compare words against their lists. A placeholder never matches, so
 * `E=.env; echo x > $E` used to read as a write to a file named `$E`, while
 * `echo x > .env` stops. This module lists what `$E` could be so each check
 * can run against the values as if they were typed out.
 *
 * The answer is deliberately an over-approximation, used only to ADD checks:
 * a name assigned in two places has two candidate values, an assignment
 * inside a branch or a prefix (`E=x cmd`) counts as well, and anything the
 * line cannot pin down (`$(...)`, `read`, `X+=`, string surgery) adds the
 * placeholder itself as a candidate, meaning "unknown". A rule that loosens
 * needs the opposite question, "what is this value for certain", and must
 * not use this.
 */

import { homedir } from "os"
import { extractWordValue, PARAM_OP } from "./parser.ts"

/** Candidate values per variable name. A candidate that still holds a `$` is (partly) unknown. */
export type PossibleValues = Map<string, string[]>

/** Combinations substitute() returns at most, per word or per command. */
export const MAX_VARIANTS = 32

/** How deep a value that mentions another variable is expanded. */
const MAX_DEPTH = 4

const NAME_TOKEN = /\$([A-Za-z_][A-Za-z0-9_]*)/g

/** Stands for "a value the line cannot pin down" while values are collected; rendered as `$NAME`. */
const UNKNOWN = "\0unknown"

/** Parameter-expansion operators whose word is a value the expansion can produce. */
const VALUE_OPS: ReadonlySet<number> = new Set([
  PARAM_OP.alt, PARAM_OP.colAlt, PARAM_OP.def, PARAM_OP.colDef, PARAM_OP.assign, PARAM_OP.colAssign,
])

/** Builtins whose operands name variables they write. */
const VAR_WRITERS = new Set(["read", "mapfile", "readarray", "getopts"])

/**
 * Walk a shfmt AST and collect, for every variable name, the values the line
 * could give it. HOME and TMPDIR start with the hook's own values, since the
 * command's shell inherits the same environment.
 */
export function possibleValues(ast: unknown, env: { home?: string; tmpdir?: string } = {}): PossibleValues {
  const raw = new Map<string, string[]>()
  const add = (name: string | undefined, value: string) => {
    if (!name) return
    const list = raw.get(name) ?? []
    if (!list.includes(value)) list.push(value)
    raw.set(name, list)
  }
  const unknown = (name: string | undefined) => { if (name) add(name, UNKNOWN) }

  const home = env.home ?? homedir()
  const tmpdir = env.tmpdir ?? process.env.TMPDIR
  if (home) add("HOME", home)
  if (tmpdir) add("TMPDIR", tmpdir.replace(/\/+$/, ""))
  else unknown("TMPDIR")

  walk(ast, (n) => {
    // NAME=value, as a statement, a prefix, or under export/declare/local.
    const name = (n.Name as Record<string, unknown> | undefined)?.Value as string | undefined
    // shfmt's Assign node is the one node with a Name and no Type.
    if (name && n.Type === undefined) {
      if (n.Append || n.Array || n.Index) unknown(name)
      else if (n.Value) add(name, extractWordValue(n.Value as Record<string, unknown>) ?? "")
      else if (!n.Naked) add(name, "")
    }

    // for NAME in items; a bare `for NAME` iterates over "$@".
    if (n.Type === "WordIter" && name) {
      const items = n.Items as Array<Record<string, unknown>> | undefined
      if (!items || items.length === 0) unknown(name)
      for (const item of items ?? []) add(name, extractWordValue(item) ?? "")
    }

    if (n.Type === "ParamExp") {
      const pname = (n.Param as Record<string, unknown> | undefined)?.Value as string | undefined
      const exp = n.Exp as Record<string, unknown> | undefined
      if (exp && VALUE_OPS.has(exp.Op as number) && exp.Word) {
        add(pname, extractWordValue(exp.Word as Record<string, unknown>) ?? "")
      } else if (exp || n.Repl || n.Slice || n.Index || n.Length || n.Excl || n.Width) {
        // The rendered `$X` is not X's value here: ${X%.bak}, ${#X}, ${!X}…
        unknown(pname)
      }
    }

    // read X, mapfile X, getopts spec X, printf -v X.
    if (n.Type === "CallExpr" && Array.isArray(n.Args)) {
      const words = (n.Args as Array<Record<string, unknown>>).map((w) => extractWordValue(w) ?? "")
      const cmd = words[0]
      if (cmd && VAR_WRITERS.has(cmd)) {
        for (const w of words.slice(1)) if (/^[A-Za-z_][A-Za-z0-9_]*$/.test(w)) unknown(w)
      } else if (cmd === "printf") {
        const i = words.indexOf("-v")
        if (i > 0) unknown(words[i + 1])
      }
    }
  })

  // Expand values that mention other variables (V=$S/verify).
  const resolved: PossibleValues = new Map()
  for (const [name, values] of raw) {
    const out: string[] = []
    for (const v of values) {
      const expanded = v === UNKNOWN ? [`$${name}`] : expand(v, raw, MAX_DEPTH, new Set([name]))
      for (const e of expanded) if (!out.includes(e)) out.push(e)
    }
    resolved.set(name, out.slice(0, MAX_VARIANTS))
  }
  return resolved
}

/**
 * Every way to write `word` with its `$NAME` tokens replaced by candidate
 * values, at most MAX_VARIANTS. A name with no candidates stays as written.
 * Returns `[word]` when nothing is known.
 */
export function substitute(word: string, values: PossibleValues): string[] {
  return expandWith(word, (name) => values.get(name))
}

/** True when a word still holds something the shell would expand: a variable, `$(...)`, `$1`… */
export function hasPlaceholder(word: string): boolean {
  return word.includes("$")
}

/**
 * A value with the variables it mentions expanded. A reference back to a
 * name being expanded (`P=$P/b`, `X=$X cmd`) takes that name's other values,
 * the ones that do not mention it; with none, it stays unknown.
 */
function expand(value: string, raw: Map<string, string[]>, depth: number, seen: Set<string>): string[] {
  if (depth === 0) return [value]
  return expandWith(value, (name) => {
    const list = raw.get(name)
    if (!list) return undefined
    const own = new RegExp(`\\$${name}(?![A-Za-z0-9_])`)
    const usable = seen.has(name) ? list.filter((v) => !own.test(v)) : list
    if (usable.length === 0) return undefined
    const next = new Set(seen).add(name)
    return usable.flatMap((v) => (v === UNKNOWN ? [`$${name}`] : expand(v, raw, depth - 1, next)))
  })
}

function expandWith(word: string, lookup: (name: string) => string[] | undefined): string[] {
  if (!word.includes("$")) return [word]
  let results = [""]
  let last = 0
  for (const m of word.matchAll(NAME_TOKEN)) {
    const literal = word.slice(last, m.index)
    last = m.index! + m[0].length
    const options = lookup(m[1]!) ?? [m[0]]
    const next: string[] = []
    for (const r of results) {
      for (const o of options) {
        if (next.length >= MAX_VARIANTS) break
        next.push(r + literal + o)
      }
    }
    results = next
  }
  const tail = word.slice(last)
  return [...new Set(results.map((r) => r + tail))]
}

function walk(node: unknown, visit: (n: Record<string, unknown>) => void): void {
  if (!node || typeof node !== "object") return
  if (Array.isArray(node)) {
    for (const item of node) walk(item, visit)
    return
  }
  const n = node as Record<string, unknown>
  visit(n)
  for (const value of Object.values(n)) if (value && typeof value === "object") walk(value, visit)
}
