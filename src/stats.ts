#!/usr/bin/env bun

/**
 * hall-pass stats: join audit decisions to outcomes and report.
 *
 * Reads the audit log (JSON Lines, see audit.ts) and answers:
 *   - how often does hall-pass interject (prompt/feedback), and in what mode?
 *   - when it interjects, does the user approve? (decision joined to a
 *     "completed" event via tool_use_id — completed = the command ran)
 *   - which prompt reasons are ~always approved? (safelist gap candidates)
 *   - how often do abstains (pass) end in a native permission prompt?
 *
 * Caveat: "not run" conflates user-denied with interrupted/session-ended —
 * Claude Code has no hook that reports the user's actual choice.
 */

import { loadConfig } from "./config.ts"
import { readAuditLog, type AuditEntry } from "./audit.ts"

const GAP_MIN_SAMPLES = 3

const config = await loadConfig()
const path = process.argv[2] ?? config.audit.path

// Includes rotated archives (<path>.<timestamp>) — the full corpus.
const entries = readAuditLog(path)
if (entries.length === 0) {
  console.error(`No audit log at ${path}`)
  console.error(`Audit logging writes it as you work (audit.enabled in config).`)
  process.exit(1)
}

// Older entries (pre-outcome-monitoring) lack an event field: treat as decisions.
const decisions = entries.filter((e) => (e.event ?? "decision") === "decision")
const completedIds = new Set(
  entries.filter((e) => e.event === "completed" && e.tool_use_id).map((e) => e.tool_use_id),
)
const nativePrompts = entries.filter((e) => e.event === "native-prompt")

if (decisions.length === 0) {
  console.log(`No decisions recorded yet in ${path}`)
  process.exit(0)
}

const first = decisions[0]!.ts.slice(0, 16).replace("T", " ")
const last = decisions[decisions.length - 1]!.ts.slice(0, 16).replace("T", " ")
console.log(`hall-pass stats — ${decisions.length} decisions, ${first} → ${last}`)
console.log(`audit log: ${path}\n`)

// -- Decision mix --

const byDecision = new Map<string, number>()
for (const d of decisions) {
  byDecision.set(d.decision ?? "?", (byDecision.get(d.decision ?? "?") ?? 0) + 1)
}
console.log("Decision mix:")
for (const [decision, count] of [...byDecision.entries()].sort((a, b) => b[1] - a[1])) {
  const pct = ((count / decisions.length) * 100).toFixed(1)
  console.log(`  ${decision.padEnd(9)} ${String(count).padStart(6)}  ${pct}%`)
}

// -- Permission-mode mix for interjections --

const interjections = decisions.filter(
  (d) => d.decision === "prompt" || d.decision === "feedback",
)
const byMode = new Map<string, number>()
for (const d of interjections) {
  byMode.set(d.mode ?? "unknown", (byMode.get(d.mode ?? "unknown") ?? 0) + 1)
}
if (interjections.length > 0) {
  console.log("\nInterjections (prompt/feedback) by permission mode:")
  for (const [mode, count] of [...byMode.entries()].sort((a, b) => b[1] - a[1])) {
    console.log(`  ${mode.padEnd(18)} ${String(count).padStart(6)}`)
  }
}

// -- Approval rate per prompt reason --

interface ReasonStats {
  total: number
  approved: number
}

const joinable = interjections.filter((d) => d.tool_use_id)
const byReason = new Map<string, ReasonStats>()
for (const d of joinable) {
  const reason = d.reason ?? "?"
  const s = byReason.get(reason) ?? { total: 0, approved: 0 }
  s.total++
  if (completedIds.has(d.tool_use_id)) s.approved++
  byReason.set(reason, s)
}

if (joinable.length === 0) {
  console.log("\nNo interjections with tool_use_id yet — outcome joins need entries")
  console.log("written after outcome monitoring was installed.")
} else {
  console.log(`\nInterjection outcomes (${joinable.length} joinable; "not run" = denied OR interrupted):`)
  const rows = [...byReason.entries()].sort((a, b) => b[1].total - a[1].total)
  for (const [reason, s] of rows) {
    const rate = ((s.approved / s.total) * 100).toFixed(0)
    console.log(
      `  ${String(s.approved).padStart(4)}/${String(s.total).padEnd(4)} approved (${rate.padStart(3)}%)  ${reason}`,
    )
  }

  const gaps = rows.filter(([, s]) => s.total >= GAP_MIN_SAMPLES && s.approved === s.total)
  if (gaps.length > 0) {
    console.log(`\nSafelist gap candidates (always approved, ≥${GAP_MIN_SAMPLES} samples):`)
    for (const [reason, s] of gaps) {
      console.log(`  ${reason} (${s.total}/${s.total})`)
    }
  }
}

// -- Deferred to the classifier --

const isDeferred = (d: AuditEntry) => d.decision === "pass" && (d.reason ?? "").startsWith("deferred: ")
const deferred = decisions.filter(isDeferred)
if (deferred.length > 0) {
  const byOriginal = new Map<string, ReasonStats>()
  for (const d of deferred) {
    const reason = (d.reason ?? "").slice("deferred: ".length)
    const s = byOriginal.get(reason) ?? { total: 0, approved: 0 }
    s.total++
    if (d.tool_use_id && completedIds.has(d.tool_use_id)) s.approved++
    byOriginal.set(reason, s)
  }
  console.log(`\nDeferred to the classifier (${deferred.length}; would have prompted in Manual mode — "ran" = the classifier let it through):`)
  for (const [reason, s] of [...byOriginal.entries()].sort((a, b) => b[1].total - a[1].total)) {
    console.log(`  ${String(s.approved).padStart(4)}/${String(s.total).padEnd(4)} ran   ${reason}`)
  }
}

// -- Abstains and native prompts --

const passes = decisions.filter((d) => d.decision === "pass" && d.tool_use_id && !isDeferred(d))
const passRan = passes.filter((d) => completedIds.has(d.tool_use_id)).length
console.log(
  `\nAbstains (pass): ${passes.length} joinable, ${passRan} ran anyway (allowed by rules or user)`,
)
console.log(
  `Native permission prompts observed: ${nativePrompts.length} (includes prompts hall-pass didn't cause)`,
)
