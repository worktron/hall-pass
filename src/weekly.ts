/**
 * hall-pass weekly view (`bun run stats --weekly`): the 7 days up to a
 * moment against the 7 days before, for a Monday check-in that reads it cold.
 *
 * Usage swings week to week, so counts come with a rate per 1,000 calls
 * hall-pass judged (every recorded decision: Bash, Write and Edit).
 *
 * The log does not record WHICH command on a line was unknown, only
 * "unknown commands in pipeline". Those lines are replayed through today's
 * decide() to name them, so a line today's rules now handle counts as
 * "now decided" instead of naming a command.
 */

import { statSync } from "fs"
import { auditArchives, type AuditEntry } from "./audit.ts"
import { makeDecideReplay } from "./eval.ts"

export const WEEK_MS = 7 * 86_400_000
const UNKNOWN_PIPELINE = "unknown commands in pipeline"
const TOP_REASONS = 10
const TOP_UNKNOWN = 15

export interface ReasonCount {
  total: number
  /** Went on to run: a "completed" event for its tool_use_id, at any time. */
  ran: number
}

export interface UnknownLine {
  input: string
  mode?: string
  count: number
}

export interface Week {
  start: number
  end: number
  decisions: number
  /** decision name → count */
  mix: Map<string, number>
  prompts: number
  nativePrompts: number
  promptReasons: Map<string, ReasonCount>
  passReasons: Map<string, ReasonCount>
  /** Bytes this week's entries take in the log (audit.ts writes JSON.stringify + "\n"). */
  bytes: number
  /** Distinct "unknown commands in pipeline" lines, with how often each was recorded. */
  unknownLines: UnknownLine[]
}

const isDecision = (e: AuditEntry) => (e.event ?? "decision") === "decision"
const bump = (m: Map<string, number>, k: string, n = 1) => m.set(k, (m.get(k) ?? 0) + n)

export function completedIds(entries: AuditEntry[]): Set<string> {
  const ids = new Set<string>()
  for (const e of entries) if (e.event === "completed" && e.tool_use_id) ids.add(e.tool_use_id)
  return ids
}

/** Figures for entries with start <= ts < end. `ran` joins against the whole corpus's completions. */
export function weekOf(entries: AuditEntry[], start: number, end: number, completed: Set<string>): Week {
  const week: Week = {
    start, end, decisions: 0, mix: new Map(), prompts: 0, nativePrompts: 0,
    promptReasons: new Map(), passReasons: new Map(), bytes: 0, unknownLines: [],
  }
  const unknown = new Map<string, UnknownLine>()
  const count = (m: Map<string, ReasonCount>, e: AuditEntry) => {
    const s = m.get(e.reason ?? "?") ?? { total: 0, ran: 0 }
    s.total++
    if (e.tool_use_id && completed.has(e.tool_use_id)) s.ran++
    m.set(e.reason ?? "?", s)
  }

  for (const e of entries) {
    const t = Date.parse(e.ts)
    if (!(t >= start && t < end)) continue
    week.bytes += Buffer.byteLength(JSON.stringify(e)) + 1
    if (e.event === "native-prompt") week.nativePrompts++
    if (!isDecision(e)) continue
    week.decisions++
    bump(week.mix, e.decision ?? "?")
    if (e.decision === "prompt") {
      week.prompts++
      count(week.promptReasons, e)
    } else if (e.decision === "pass") {
      count(week.passReasons, e)
      if (e.reason === UNKNOWN_PIPELINE && e.input) {
        const key = `${e.mode ?? ""}\0${e.input}`
        const line = unknown.get(key) ?? { input: e.input, mode: e.mode, count: 0 }
        line.count++
        unknown.set(key, line)
      }
    }
  }
  week.unknownLines = [...unknown.values()]
  return week
}

/** What today's rules make of one recorded line. */
export interface Replayed {
  /** Today's decision is still an abstain for unknown commands. */
  stillUnknown: boolean
  /** The unknown commands on the line, each once. */
  unknown: string[]
}

export type UnknownReplay = (input: string, mode?: string) => Promise<Replayed>

export interface UnknownNames {
  /** Recorded lines (with repeats) and how many of them still abstain today. */
  lines: number
  stillUnknown: number
  /** command → recorded lines it appears on */
  names: Map<string, number>
}

/** Name the unknown commands behind a week's abstains. `cache` is shared across weeks so a line is replayed once. */
export async function unknownNames(
  lines: UnknownLine[],
  replay: UnknownReplay,
  cache: Map<string, Replayed> = new Map(),
): Promise<UnknownNames> {
  const result: UnknownNames = { lines: 0, stillUnknown: 0, names: new Map() }
  for (const line of lines) {
    const key = `${line.mode ?? ""}\0${line.input}`
    let r = cache.get(key)
    if (!r) {
      r = await replay(line.input, line.mode)
      cache.set(key, r)
    }
    result.lines += line.count
    if (!r.stillUnknown) continue
    result.stillUnknown += line.count
    for (const name of r.unknown) bump(result.names, name, line.count)
  }
  return result
}

/** Replay through today's decide() (eval.ts's setup), collecting each per-command "unknown: <name>". */
export async function makeUnknownReplay(): Promise<UnknownReplay> {
  let found: string[] = []
  const replay = await makeDecideReplay({
    debug: (label, data) => {
      if (label !== "eval") return
      const reason = (data as { reason?: unknown } | undefined)?.reason
      if (typeof reason === "string" && reason.startsWith("unknown: ")) found.push(reason.slice("unknown: ".length))
    },
  })
  return async (input, mode) => {
    found = []
    const d = await replay("Bash", input, mode)
    return {
      stillUnknown: d?.decision === "pass" && d.reason === "pipeline contains unknown commands",
      unknown: [...new Set(found)],
    }
  }
}

export interface DiskUse {
  bytes: number
  files: number
}

/** The live log and its rotated archives, as they sit on disk. */
export function diskUse(path: string): DiskUse {
  const use: DiskUse = { bytes: 0, files: 0 }
  for (const file of [...auditArchives(path), path]) {
    try {
      use.bytes += statSync(file).size
      use.files++
    } catch {}
  }
  return use
}

export interface WeeklyReport {
  path: string
  thisWeek: Week
  lastWeek: Week
  unknownThis: UnknownNames
  unknownLast: UnknownNames
  disk: DiskUse
  oldest?: string
}

export async function weeklyReport(
  entries: AuditEntry[],
  options: { until: number; path: string; replay: UnknownReplay },
): Promise<WeeklyReport> {
  const completed = completedIds(entries)
  const { until } = options
  const thisWeek = weekOf(entries, until - WEEK_MS, until, completed)
  const lastWeek = weekOf(entries, until - 2 * WEEK_MS, until - WEEK_MS, completed)
  const cache = new Map<string, Replayed>()
  const unknownThis = await unknownNames(thisWeek.unknownLines, options.replay, cache)
  const unknownLast = await unknownNames(lastWeek.unknownLines, options.replay, cache)
  let oldest: string | undefined
  for (const e of entries) if (!oldest || e.ts < oldest) oldest = e.ts
  return { path: options.path, thisWeek, lastWeek, unknownThis, unknownLast, disk: diskUse(options.path), oldest }
}

// -- Text --

const int = (n: number) => n.toLocaleString("en-US")
const pct = (n: number, of: number) => (of === 0 ? "-" : `${((n / of) * 100).toFixed(1)}%`)
/** Rate per 1,000 calls: one decimal, two below 1 so rare reasons do not all read 0.0. */
export const perThousand = (n: number, of: number) =>
  of === 0 ? "-" : n === 0 ? "0" : ((n / of) * 1000).toFixed(n / of >= 0.001 ? 1 : 2)
const mb = (bytes: number) => `${(bytes / 1_000_000).toFixed(1)} MB`
const when = (ms: number) =>
  new Date(ms).toLocaleString("en-GB", { weekday: "short", day: "numeric", month: "short", hour: "2-digit", minute: "2-digit", timeZoneName: "short" })

function table(rows: string[][], rightAligned: number): string[] {
  const widths = rows[0]!.map((_, i) => Math.max(...rows.map((r) => (r[i] ?? "").length)))
  return rows.map((r) =>
    "  " + r.map((cell, i) => (i < rightAligned ? cell.padStart(widths[i]!) : i === r.length - 1 ? cell : cell.padEnd(widths[i]!))).join("  ").trimEnd(),
  )
}

/**
 * Which keys a comparison table shows: this week's top `n`, then any of last
 * week's top `n` not already listed, so a reason or command that fell away
 * (to zero, or below this week's cut) still shows its drop.
 */
export function comparedKeys(now: Map<string, number>, before: Map<string, number>, n: number): { keys: string[]; more: number } {
  const ranked = (m: Map<string, number>) =>
    [...m.entries()].filter(([, c]) => c > 0).sort((x, y) => y[1] - x[1] || x[0].localeCompare(y[0])).slice(0, n).map(([k]) => k)
  const keys = [...new Set([...ranked(now), ...ranked(before)])]
  const all = new Set([...now.keys(), ...before.keys()])
  return { keys, more: all.size - keys.length }
}

const totals = (m: Map<string, ReasonCount>) => new Map([...m].map(([k, s]) => [k, s.total]))

function reasonRows(title: string, thisWeek: Week, lastWeek: Week, pick: (w: Week) => Map<string, ReasonCount>): string[] {
  const now = pick(thisWeek)
  const before = pick(lastWeek)
  const { keys, more } = comparedKeys(totals(now), totals(before), TOP_REASONS)
  if (keys.length === 0) return [`\n${title}: none in either week.`]
  const rows = [["this week", "per 1,000", "ran", "last week", "per 1,000", "reason"]]
  for (const reason of keys) {
    const s = now.get(reason) ?? { total: 0, ran: 0 }
    const last = before.get(reason)?.total ?? 0
    rows.push([int(s.total), perThousand(s.total, thisWeek.decisions), int(s.ran), int(last), perThousand(last, lastWeek.decisions), reason])
  }
  return [`\n${title}:`, ...table(rows, 5), ...(more > 0 ? [`  and ${more} more reasons`] : [])]
}

export function formatWeekly(r: WeeklyReport): string {
  const { thisWeek: a, lastWeek: b } = r
  const out: string[] = []
  out.push(`hall-pass weekly: ${when(a.start)} to ${when(a.end)}, against the 7 days before (${when(b.start)} to ${when(b.end)})`)
  out.push(`audit log: ${r.path}`)

  const mixNames = [...new Set([...a.mix.keys(), ...b.mix.keys()])].sort((x, y) => (a.mix.get(y) ?? 0) - (a.mix.get(x) ?? 0) || x.localeCompare(y))
  const rows = [
    ["", "this week", "", "last week", ""],
    ["calls judged", int(a.decisions), "", int(b.decisions), ""],
    ...mixNames.map((d) => [`  ${d}`, int(a.mix.get(d) ?? 0), pct(a.mix.get(d) ?? 0, a.decisions), int(b.mix.get(d) ?? 0), pct(b.mix.get(d) ?? 0, b.decisions)]),
    ["hall-pass prompts", int(a.prompts), `${perThousand(a.prompts, a.decisions)} per 1,000`, int(b.prompts), `${perThousand(b.prompts, b.decisions)} per 1,000`],
    ["native prompts", int(a.nativePrompts), `${perThousand(a.nativePrompts, a.decisions)} per 1,000`, int(b.nativePrompts), `${perThousand(b.nativePrompts, b.decisions)} per 1,000`],
  ]
  // Label column left-aligned, numbers right-aligned.
  const widths = rows[0]!.map((_, i) => Math.max(...rows.map((row) => row[i]!.length)))
  out.push("")
  for (const row of rows) out.push(("  " + row.map((c, i) => (i === 0 ? c.padEnd(widths[0]!) : c.padStart(widths[i]!))).join("  ")).trimEnd())
  out.push(`  Native prompts include ones hall-pass did not cause.`)

  out.push(...reasonRows(`Top prompt reasons ("ran" = the command went on to run, even after the week ended)`, a, b, (w) => w.promptReasons))
  out.push(...reasonRows(`Top pass reasons (hall-pass abstained; "deferred" ones went to the auto-mode classifier)`, a, b, (w) => w.passReasons))

  const u = r.unknownThis
  const v = r.unknownLast
  out.push(`\nUnknown commands behind "${UNKNOWN_PIPELINE}" (lines replayed through today's rules):`)
  const { keys: names, more } = comparedKeys(u.names, v.names, TOP_UNKNOWN)
  if (names.length > 0) {
    const nameRows = [["this week", "last week", "command"], ...names.map((name) => [int(u.names.get(name) ?? 0), int(v.names.get(name) ?? 0), name])]
    out.push(...table(nameRows, 2))
    if (more > 0) out.push(`  and ${more} more commands`)
  }
  const summary = (label: string, x: UnknownNames) =>
    `  ${label}: ${int(x.lines)} lines, ${int(x.stillUnknown)} still unknown today, ${int(x.lines - x.stillUnknown)} now decided.`
  out.push(summary("This week", u), summary("Last week", v))

  out.push(`\nAudit log on disk: ${mb(r.disk.bytes)} in ${int(r.disk.files)} files${r.oldest ? `, oldest entry ${r.oldest.slice(0, 10)}` : ""}`)
  out.push(`  this week added ${mb(a.bytes)}, last week ${mb(b.bytes)}`)
  return out.join("\n")
}
