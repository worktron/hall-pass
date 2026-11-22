import { afterAll, beforeAll, describe, expect, test } from "bun:test"
import { mkdtempSync, rmSync, statSync, writeFileSync } from "fs"
import { tmpdir } from "os"
import { join, resolve } from "path"
import type { AuditEntry } from "./audit.ts"
import { comparedKeys, completedIds, diskUse, makeUnknownReplay, unknownNames, weekOf, WEEK_MS, type Replayed } from "./weekly.ts"

const STATS = resolve(import.meta.dir, "stats.ts")
const DAY = 86_400_000
const UNTIL = Date.parse("2026-11-22T18:00:00Z")
const at = (msBeforeUntil: number) => new Date(UNTIL - msBeforeUntil).toISOString()

let id = 0
function decision(ts: string, decision: AuditEntry["decision"], reason: string, extra: Partial<AuditEntry> = {}): AuditEntry {
  return { ts, event: "decision", tool: "Bash", input: `cmd ${id}`, decision, reason, layer: "evaluate", tool_use_id: `t${id++}`, mode: "default", ...extra }
}
const completed = (e: AuditEntry, ts: string): AuditEntry => ({ ts, event: "completed", tool_use_id: e.tool_use_id })
const nativePrompt = (ts: string): AuditEntry => ({ ts, event: "native-prompt" })

/**
 * Two weeks of traffic ending at UNTIL, plus entries on each edge:
 *   this week  [UNTIL-7d, UNTIL)   last week  [UNTIL-14d, UNTIL-7d)
 */
function fixture(): AuditEntry[] {
  id = 0
  const entries: AuditEntry[] = []
  const add = (...es: AuditEntry[]) => entries.push(...es)

  // Older than both weeks: never counted.
  add(decision(at(20 * DAY), "prompt", "op: read"))

  // Last week: 10 calls, 1 prompt (ran), 2 unknown-pipeline passes, 1 native prompt.
  const lastPrompt = decision(at(10 * DAY), "prompt", "op: read")
  add(lastPrompt, completed(lastPrompt, at(10 * DAY - 1000)))
  add(decision(at(9 * DAY), "pass", "unknown commands in pipeline", { input: "xcrun simctl list | cat" }))
  add(decision(at(9 * DAY), "pass", "unknown commands in pipeline", { input: "xcrun simctl list | cat" }))
  for (let i = 0; i < 7; i++) add(decision(at(8 * DAY), "allow", "all commands safe"))
  add(nativePrompt(at(8 * DAY)))
  // Exactly on last week's start: in last week.
  add(decision(at(14 * DAY), "allow", "all commands safe"))

  // This week: 19 calls.
  // Exactly on this week's start: in this week, not last.
  add(decision(at(7 * DAY), "allow", "all commands safe"))
  // Two prompts for op: item get; one ran, the other ran only after the window closed.
  const p1 = decision(at(3 * DAY), "prompt", "op: item get")
  const p2 = decision(at(1000), "prompt", "op: item get")
  add(p1, completed(p1, at(3 * DAY - 1000)), p2)
  // One prompt that never ran.
  add(decision(at(2 * DAY), "prompt", "secret: Anthropic API key"))
  // Passes: two deferred (one ran), three unknown pipelines over two distinct lines.
  const d1 = decision(at(2 * DAY), "pass", "deferred: bash: script execution")
  add(d1, completed(d1, at(2 * DAY - 1000)))
  add(decision(at(2 * DAY), "pass", "deferred: bash: script execution"))
  add(decision(at(1 * DAY), "pass", "unknown commands in pipeline", { input: "xcrun simctl list | cat", mode: "auto" }))
  add(decision(at(1 * DAY), "pass", "unknown commands in pipeline", { input: "xcrun simctl list | cat", mode: "auto" }))
  add(decision(at(1 * DAY), "pass", "unknown commands in pipeline", { input: "axe tap && tmux ls" }))
  add(decision(at(1 * DAY), "feedback", "use jq"))
  for (let i = 0; i < 9; i++) add(decision(at(1 * DAY), "allow", "all commands safe"))
  add(nativePrompt(at(1 * DAY)), nativePrompt(at(1 * DAY)))
  // Exactly on the end: next week's, not this week's. Its completion counts for p2.
  add(decision(at(0), "prompt", "op: read"))
  add(completed(p2, at(-1000)))

  return entries.sort((a, b) => a.ts.localeCompare(b.ts))
}

let dir: string
let logPath: string
let configPath: string

beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), "hall-pass-weekly-"))
  logPath = join(dir, "audit.jsonl")
  configPath = join(dir, "config.toml")
  writeFileSync(configPath, "")
  const lines = fixture().map((e) => JSON.stringify(e) + "\n")
  // Split the corpus the way rotation does: an older archive and the live log.
  writeFileSync(`${logPath}.2026-11-10T00-00-00-000Z`, lines.slice(0, 8).join(""))
  writeFileSync(logPath, lines.slice(8).join(""))
})
afterAll(() => rmSync(dir, { recursive: true, force: true }))

async function runStats(...args: string[]) {
  const proc = Bun.spawn(["bun", STATS, ...args], {
    stdout: "pipe",
    stderr: "pipe",
    env: { ...process.env, HALL_PASS_CONFIG: configPath, TZ: "UTC" },
  })
  const [stdout, stderr] = await Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text()])
  const exitCode = await proc.exited
  return { stdout: stdout.replaceAll(dir, "<dir>"), stderr, exitCode }
}

describe("stats without --weekly", () => {
  test("prints the full-corpus report exactly as before", async () => {
    const r = await runStats(logPath)
    expect(r.exitCode).toBe(0)
    expect(r.stdout).toMatchInlineSnapshot(`
      "hall-pass stats — 32 decisions, 2026-11-02 18:00 → 2026-11-22 18:00
      audit log: <dir>/audit.jsonl

      Decision mix:
        allow         18  56.3%
        pass           7  21.9%
        prompt         6  18.8%
        feedback       1  3.1%

      Interjections (prompt/feedback) by permission mode:
        default                 7

      Interjection outcomes (7 joinable; "not run" = denied OR interrupted):
           1/3    approved ( 33%)  op: read
           2/2    approved (100%)  op: item get
           0/1    approved (  0%)  secret: Anthropic API key
           0/1    approved (  0%)  use jq

      Deferred to the classifier (2; would have prompted in Manual mode — "ran" = the classifier let it through):
           1/2    ran   bash: script execution

      Abstains (pass): 5 joinable, 0 ran anyway (allowed by rules or user)
      Native permission prompts observed: 3 (includes prompts hall-pass didn't cause)
      "
    `)
  })
})

describe("weekOf", () => {
  const entries = fixture()
  const done = completedIds(entries)
  const thisWeek = weekOf(entries, UNTIL - WEEK_MS, UNTIL, done)
  const lastWeek = weekOf(entries, UNTIL - 2 * WEEK_MS, UNTIL - WEEK_MS, done)

  test("an entry exactly at a week's start is in that week; one exactly at its end is not", () => {
    expect(thisWeek.decisions).toBe(19)
    expect(lastWeek.decisions).toBe(11)
    // The op: read at UNTIL belongs to the week after, the one at -20 days to neither.
    expect(thisWeek.promptReasons.has("op: read")).toBe(false)
    expect(lastWeek.promptReasons.get("op: read")).toEqual({ total: 1, ran: 1 })
  })

  test("counts the decision mix, prompts and native prompts", () => {
    expect(Object.fromEntries(thisWeek.mix)).toEqual({ allow: 10, prompt: 3, pass: 5, feedback: 1 })
    expect(thisWeek.prompts).toBe(3)
    expect(thisWeek.nativePrompts).toBe(2)
    expect(lastWeek.nativePrompts).toBe(1)
  })

  test("a prompt counts as ran when its command completed after the week ended", () => {
    expect(thisWeek.promptReasons.get("op: item get")).toEqual({ total: 2, ran: 2 })
    expect(thisWeek.promptReasons.get("secret: Anthropic API key")).toEqual({ total: 1, ran: 0 })
    expect(thisWeek.passReasons.get("deferred: bash: script execution")).toEqual({ total: 2, ran: 1 })
  })

  test("groups unknown-pipeline lines by input and mode, with how often each was recorded", () => {
    const lines = thisWeek.unknownLines.map((l) => [l.input, l.mode, l.count])
    expect(lines).toEqual([
      ["xcrun simctl list | cat", "auto", 2],
      ["axe tap && tmux ls", "default", 1],
    ])
  })

  test("a week's bytes are the bytes its lines take in the log", () => {
    const inWeek = entries.filter((e) => Date.parse(e.ts) >= UNTIL - WEEK_MS && Date.parse(e.ts) < UNTIL)
    expect(thisWeek.bytes).toBe(Buffer.byteLength(inWeek.map((e) => JSON.stringify(e) + "\n").join("")))
  })
})

describe("unknownNames", () => {
  const lines = [
    { input: "xcrun simctl list | cat", mode: "auto", count: 2 },
    { input: "axe tap && tmux ls", mode: "default", count: 1 },
    { input: "now-safelisted | cat", mode: "default", count: 4 },
  ]
  const replayed: Record<string, Replayed> = {
    "xcrun simctl list | cat": { stillUnknown: true, unknown: ["xcrun"] },
    "axe tap && tmux ls": { stillUnknown: true, unknown: ["axe", "tmux"] },
    "now-safelisted | cat": { stillUnknown: false, unknown: [] },
  }

  test("weights each name by the times its line was recorded and counts lines now decided", async () => {
    const r = await unknownNames(lines, async (input) => replayed[input]!)
    expect(Object.fromEntries(r.names)).toEqual({ xcrun: 2, axe: 1, tmux: 1 })
    expect(r.lines).toBe(7)
    expect(r.stillUnknown).toBe(3)
  })

  test("a line already replayed for one week is not replayed again for the other", async () => {
    const calls: string[] = []
    const replay = async (input: string) => (calls.push(input), replayed[input]!)
    const cache = new Map<string, Replayed>()
    await unknownNames(lines, replay, cache)
    await unknownNames(lines.slice(0, 1), replay, cache)
    expect(calls).toEqual(lines.map((l) => l.input))
  })

  test("today's decide() names the unknown command, including one a wrapper hides", async () => {
    const replay = await makeUnknownReplay()
    expect(await replay("notarealcommand123 --flag | cat", "default")).toEqual({ stillUnknown: true, unknown: ["notarealcommand123"] })
    expect(await replay("timeout 5 notarealcommand456", "default")).toEqual({ stillUnknown: true, unknown: ["notarealcommand456"] })
    expect(await replay("ls | cat", "default")).toEqual({ stillUnknown: false, unknown: [] })
  })
})

describe("comparedKeys", () => {
  test("lists this week's top, then last week's top that fell away, and counts the rest", () => {
    const now = new Map([["a", 9], ["b", 5], ["c", 1]])
    const before = new Map([["gone", 20], ["a", 3], ["c", 8], ["tail", 1]])
    expect(comparedKeys(now, before, 2)).toEqual({ keys: ["a", "b", "gone", "c"], more: 1 })
  })
})

describe("diskUse", () => {
  test("adds up the live log and its archives", () => {
    const use = diskUse(logPath)
    const sizes = [logPath, `${logPath}.2026-11-10T00-00-00-000Z`].map((f) => statSync(f).size)
    expect(use).toEqual({ bytes: sizes[0]! + sizes[1]!, files: 2 })
  })
})

describe("stats --weekly", () => {
  test("prints this week against last week with every section", async () => {
    const r = await runStats("--weekly", "--until", new Date(UNTIL).toISOString(), logPath)
    expect(r.stderr).toBe("")
    expect(r.exitCode).toBe(0)
    // Two weeks after the corpus starts, so last week is not empty.
    expect(r.stdout).toMatchInlineSnapshot(`
      "hall-pass weekly: Sun 15 Nov at 18:00 UTC to Sun 22 Nov at 18:00 UTC, against the 7 days before (Sun 8 Nov at 18:00 UTC to Sun 15 Nov at 18:00 UTC)
      audit log: <dir>/audit.jsonl

                           this week                   last week
        calls judged              19                          11
          allow                   10            52.6%          8           72.7%
          pass                     5            26.3%          2           18.2%
          prompt                   3            15.8%          1            9.1%
          feedback                 1             5.3%          0            0.0%
        hall-pass prompts          3  157.9 per 1,000          1  90.9 per 1,000
        native prompts             2  105.3 per 1,000          1  90.9 per 1,000
        Native prompts include ones hall-pass did not cause.

      Top prompt reasons ("ran" = the command went on to run, even after the week ended):
        this week  per 1,000  ran  last week  per 1,000  reason
                2      105.3    2          0          0  op: item get
                1       52.6    0          0          0  secret: Anthropic API key
                0          0    0          1       90.9  op: read

      Top pass reasons (hall-pass abstained; "deferred" ones went to the auto-mode classifier):
        this week  per 1,000  ran  last week  per 1,000  reason
                3      157.9    0          2      181.8  unknown commands in pipeline
                2      105.3    1          0          0  deferred: bash: script execution

      Unknown commands behind "unknown commands in pipeline" (lines replayed through today's rules):
        this week  last week  command
                2          2  simctl
                1          0  axe
                1          0  tmux
        This week: 3 lines, 3 still unknown today, 0 now decided.
        Last week: 2 lines, 2 still unknown today, 0 now decided.

      Audit log on disk: 0.0 MB in 2 files, oldest entry 2026-11-02
        this week added 0.0 MB, last week 0.0 MB
      "
    `)
  })

  test("--until without --weekly is refused", async () => {
    const r = await runStats("--until", "2026-11-22T18:00:00Z", logPath)
    expect(r.exitCode).toBe(2)
    expect(r.stderr).toContain("--until only applies with --weekly")
  })

  test("a time --until cannot read is refused", async () => {
    const r = await runStats("--weekly", "--until", "monday", logPath)
    expect(r.exitCode).toBe(2)
    expect(r.stderr).toContain("--until needs a time")
  })
})
