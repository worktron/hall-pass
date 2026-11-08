#!/usr/bin/env bun

/**
 * hall-pass eval: replay recorded traffic through the current decide().
 *
 * The audit log records every decision with its full input and, via
 * tool_use_id joins, whether the call ultimately ran (see audit.ts). That
 * makes it a labeled corpus: replay each recorded input through the
 * working-tree decide() and diff against what was recorded to see exactly
 * what a safelist/inspector change does to real traffic before shipping it.
 *
 * Buckets that matter:
 *   wins        recorded prompt the user APPROVED that would now auto-allow
 *   DANGERS     recorded prompt that did NOT run (declined or interrupted)
 *               that would now auto-allow — fails the eval (exit 1)
 *   regressions recorded allow that would now prompt (new friction)
 *
 * Caveats: "not run" conflates declined with interrupted with still-pending
 * (a prompt approved hours later completes then — labels firm up as the log
 * ages), so dangers need a human eyeball, not just a red exit code. Replay uses the current config
 * and cwd, so project-local .hall-pass files from other repos don't apply;
 * on an unchanged working tree the diff should be ~empty (self-check).
 * Write/Edit prompts caused by secret CONTENT can't replay (content isn't
 * recorded) and are skipped.
 */

import { loadConfig } from "./config.ts"
import { decide, findShfmt, DEFER_MODES } from "./decide.ts"
import { readAuditLog, type AuditEntry } from "./audit.ts"

/** Recorded decision names; replayed "ask" is normalized to "prompt". */
type DecisionName = "allow" | "prompt" | "feedback" | "pass" | "block"

export type Outcome = "ran" | "not-run" | "unknown"

export interface ReplayOutcome {
  decision: DecisionName
  reason: string
}

/**
 * Returns null to skip an entry that can't be faithfully replayed. `mode` is
 * the permission mode the entry was recorded in — decide() reads it.
 */
export type ReplayFn = (tool: string, input: string, mode?: string) => Promise<ReplayOutcome | null>

export interface ChangedRow {
  tool: string
  input: string
  recordedReason: string
  replayedDecision: DecisionName
  replayedReason: string
  outcome: Outcome
  mode?: string
}

export interface EvalReport {
  from?: string
  to?: string
  total: number
  replayed: number
  skipped: number
  /** "recorded→replayed" → count, only where the decision changed */
  transitions: Record<string, number>
  wins: ChangedRow[]
  dangers: ChangedRow[]
  unknownLoosened: ChangedRow[]
  regressions: ChangedRow[]
  /**
   * Recorded prompts that would now be handed to the classifier (prompt →
   * pass in a DEFER_MODES session). Not an auto-allow — the classifier still
   * reviews each one — so these never fail the eval, but the not-run ones are
   * listed for a human eyeball: the classifier will now judge what the user
   * declined (or interrupted) before.
   */
  deferred: ChangedRow[]
  ok: boolean
}

function outcomeOf(entry: AuditEntry, completed: Set<string>): Outcome {
  if (!entry.tool_use_id) return "unknown"
  return completed.has(entry.tool_use_id) ? "ran" : "not-run"
}

export async function runEval(entries: AuditEntry[], replay: ReplayFn): Promise<EvalReport> {
  const decisions = entries.filter(
    (e) =>
      (e.event ?? "decision") === "decision" &&
      e.tool &&
      e.input !== undefined &&
      e.decision !== undefined,
  )
  const completed = new Set(
    entries
      .filter((e) => e.event === "completed" && e.tool_use_id)
      .map((e) => e.tool_use_id as string),
  )

  const report: EvalReport = {
    from: decisions[0]?.ts,
    to: decisions[decisions.length - 1]?.ts,
    total: decisions.length,
    replayed: 0,
    skipped: 0,
    transitions: {},
    wins: [],
    dangers: [],
    unknownLoosened: [],
    regressions: [],
    deferred: [],
    ok: true,
  }

  const memo = new Map<string, ReplayOutcome | null>()

  for (const entry of decisions) {
    const key = `${entry.mode ?? ""}|${entry.tool} ${entry.input}`
    let replayed = memo.get(key)
    if (replayed === undefined) {
      replayed = await replay(entry.tool!, entry.input!, entry.mode)
      memo.set(key, replayed)
    }
    if (replayed === null) {
      report.skipped++
      continue
    }
    report.replayed++

    const recorded = entry.decision as DecisionName
    if (replayed.decision === recorded) continue

    const transition = `${recorded}→${replayed.decision}`
    report.transitions[transition] = (report.transitions[transition] ?? 0) + 1

    const row: ChangedRow = {
      tool: entry.tool!,
      input: entry.input!,
      recordedReason: entry.reason ?? "?",
      replayedDecision: replayed.decision,
      replayedReason: replayed.reason,
      outcome: outcomeOf(entry, completed),
      mode: entry.mode,
    }

    const loosened =
      (recorded === "prompt" || recorded === "feedback") &&
      (replayed.decision === "allow" || replayed.decision === "feedback")
    const tightened = recorded === "allow" && replayed.decision === "prompt"
    const handedOver = recorded === "prompt" && replayed.decision === "pass" && DEFER_MODES.has(entry.mode ?? "")

    if (loosened) {
      if (row.outcome === "ran") report.wins.push(row)
      else if (row.outcome === "not-run") report.dangers.push(row)
      else report.unknownLoosened.push(row)
    } else if (tightened) {
      report.regressions.push(row)
    } else if (handedOver) {
      report.deferred.push(row)
    }
  }

  report.ok = report.dangers.length === 0
  return report
}

/** Replay through the working-tree decide() with the current config. */
export async function makeDecideReplay(): Promise<ReplayFn> {
  const config = await loadConfig()
  const shfmtBin = findShfmt()
  const deps = { config, shfmtBin, debug: () => {}, audit: { log() {}, event() {} }, metamaxHome: process.env.METAMAX_HOME }

  return async (tool, input, mode) => {
    let toolInput: Record<string, unknown>
    if (tool === "Bash") {
      toolInput = { command: input }
    } else if (tool === "Write" || tool === "Edit") {
      // Content wasn't recorded, so content-based secret prompts can't
      // reproduce — path-only replay would misread them as loosenings.
      toolInput = { file_path: input }
    } else {
      return null
    }
    const d = await decide(tool, toolInput, { ...deps, mode })
    return { decision: d.decision === "ask" ? "prompt" : d.decision, reason: d.reason ?? "" }
  }
}

function shortInput(s: string): string {
  const flat = s.replace(/\n/g, " ")
  return flat.length > 90 ? flat.slice(0, 90) + "…" : flat
}

function printRows(rows: ChangedRow[]) {
  for (const row of rows) {
    console.log(`    [${row.recordedReason}] ${shortInput(row.input)}`)
    console.log(`      → ${row.replayedDecision} (${row.replayedReason})${row.mode ? `  mode=${row.mode}` : ""}`)
  }
}

if (import.meta.main) {
  const config = await loadConfig()
  const path = process.argv[2] ?? config.audit.path

  // Includes rotated archives (<path>.<timestamp>) — the full corpus.
  const entries = readAuditLog(path)
  if (entries.length === 0) {
    console.error(`No audit log at ${path}`)
    process.exit(1)
  }

  const skippable = entries.filter(
    (e) =>
      (e.event ?? "decision") === "decision" &&
      (e.tool === "Write" || e.tool === "Edit") &&
      e.reason?.startsWith("secret:"),
  ).length

  const replay = await makeDecideReplay()

  // Secret-content Write/Edit prompts can't reproduce (content wasn't
  // recorded) — drop them from the corpus rather than misread them as wins.
  const corpus = entries.filter(
    (e) =>
      !(
        (e.event ?? "decision") === "decision" &&
        (e.tool === "Write" || e.tool === "Edit") &&
        e.reason?.startsWith("secret:")
      ),
  )

  const report = await runEval(corpus, replay)

  const period =
    report.from && report.to
      ? `${report.from.slice(0, 16).replace("T", " ")} → ${report.to.slice(0, 16).replace("T", " ")}`
      : "empty"
  console.log(`hall-pass eval — ${report.total} recorded decisions (${period})`)
  console.log(`replayed ${report.replayed}, skipped ${report.skipped + skippable} (${skippable} secret-content write/edit)\n`)

  const transitionKeys = Object.keys(report.transitions)
  if (transitionKeys.length === 0) {
    console.log("No decision changes — working tree matches recorded behavior.")
  } else {
    console.log("Decision changes (recorded → replayed):")
    for (const key of transitionKeys.sort((a, b) => report.transitions[b]! - report.transitions[a]!)) {
      console.log(`  ${key.padEnd(20)} ${report.transitions[key]}`)
    }

    if (report.wins.length > 0) {
      console.log(`\nWins — approved prompts that would no longer prompt (${report.wins.length}):`)
      printRows(report.wins)
    }
    if (report.unknownLoosened.length > 0) {
      console.log(`\nLoosened, outcome unknown — verify by hand (${report.unknownLoosened.length}):`)
      printRows(report.unknownLoosened)
    }
    if (report.regressions.length > 0) {
      console.log(`\nRegressions — allows that would start prompting (${report.regressions.length}):`)
      printRows(report.regressions)
    }
    if (report.deferred.length > 0) {
      const ran = report.deferred.filter((r) => r.outcome === "ran")
      const notRun = report.deferred.filter((r) => r.outcome === "not-run")
      console.log(
        `\nDeferred — prompts the classifier would now judge instead (${report.deferred.length}: ${ran.length} were approved, ${notRun.length} did not run):`,
      )
      if (notRun.length > 0) {
        console.log(`  The ${notRun.length} that did not run, for a human eyeball (declined, or just interrupted):`)
        printRows(notRun)
      }
    }
    if (report.dangers.length > 0) {
      console.log(`\nDANGER — prompts that did NOT run (declined or interrupted) that would now auto-allow (${report.dangers.length}):`)
      printRows(report.dangers)
    }
  }

  console.log(`\nResult: ${report.ok ? "OK" : `FAIL — ${report.dangers.length} declined/interrupted prompt(s) would now auto-allow`}`)
  process.exit(report.ok ? 0 : 1)
}
