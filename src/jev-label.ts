#!/usr/bin/env bun

/**
 * hall-pass jev: label the audit log's commands with Jev, then report
 * safelist candidates and possible holes for a person to review. See jev.ts
 * for what is sent and why Jev never decides anything at runtime.
 *
 *   bun run jev --plan                 counts, cost, sample requests; sends nothing
 *   bun run jev --max-cost 1           ask about what is not answered yet, then report
 *   bun run jev --report               report from stored answers only
 *
 *   --buckets unknown,judgment,allowed   which commands to ask about (default all)
 *   --per-group <n>                      allowed commands asked per name or subcommand (default 25, 0 for all)
 *   --show <n>                           sample requests --plan prints (default 12)
 *   --min-confidence <p>                 report threshold (default 0.8)
 *
 * Answers are appended to answers.jsonl in ~/.local/share/hall-pass/jev/
 * (HALL_PASS_JEV_DATA overrides), outside every checkout and owner-only, as
 * they return. A rerun pays only for commands with no answer from this model
 * and question set. The key is TYPESAFE_API_KEY, an op:// reference resolved
 * with `op read` (default op://Personal/TypeSafe API/credential); a raw key
 * also works.
 */

import { appendFileSync, chmodSync, existsSync, mkdirSync, readFileSync } from "fs"
import { homedir } from "os"
import { join } from "path"
import { readAuditLog } from "./audit.ts"
import { loadConfig } from "./config.ts"
import { findShfmt } from "./decide.ts"
import {
  askJev, buildReport, estimateTokens, extractItems, selectItems,
  JEV_MODEL, KINDS, PRICE_PER_INPUT_TOKEN, QUESTIONS_VERSION,
  type Answer, type Bucket, type Item, type Kind, type Report,
} from "./jev.ts"

const BUCKETS: Bucket[] = ["unknown", "judgment", "allowed"]

function flag(name: string): string | undefined {
  const at = process.argv.indexOf(name)
  return at >= 0 ? process.argv[at + 1] : undefined
}

const planOnly = process.argv.includes("--plan")
const reportOnly = process.argv.includes("--report")
const maxCost = Number(flag("--max-cost") ?? 0)
const show = Number(flag("--show") ?? 12)
const minConfidence = Number(flag("--min-confidence") ?? 0.8)
const buckets = new Set((flag("--buckets") ?? BUCKETS.join(",")).split(",") as Bucket[])
const perGroup = Number(flag("--per-group") ?? 25)

if (!planOnly && !reportOnly && !(maxCost > 0)) {
  console.error("pass --plan, --report, or --max-cost <dollars>")
  process.exit(2)
}
for (const b of buckets) {
  if (!BUCKETS.includes(b)) {
    console.error(`unknown bucket "${b}"; use ${BUCKETS.join(", ")}`)
    process.exit(2)
  }
}

const dataDir = process.env.HALL_PASS_JEV_DATA ?? join(homedir(), ".local", "share", "hall-pass", "jev")
const answersPath = join(dataDir, "answers.jsonl")

function loadAnswers(): Map<string, Answer> {
  const answers = new Map<string, Answer>()
  if (!existsSync(answersPath)) return answers
  for (const line of readFileSync(answersPath, "utf8").split("\n")) {
    if (!line) continue
    try {
      const a = JSON.parse(line) as Answer
      if (a.questionsVersion === QUESTIONS_VERSION && a.model === JEV_MODEL) answers.set(a.key, a)
    } catch {}
  }
  return answers
}

async function resolveKey(): Promise<string> {
  const raw = process.env.TYPESAFE_API_KEY ?? "op://Personal/TypeSafe API/credential"
  if (!raw.startsWith("op://")) return raw
  const p = Bun.spawnSync(["op", "read", raw])
  if (p.exitCode !== 0) throw new Error(`op read failed: ${p.stderr.toString().trim()}`)
  return p.stdout.toString().trim()
}

const money = (tokens: number) => `$${(tokens * PRICE_PER_INPUT_TOKEN).toFixed(2)}`
const short = (s: string, n = 110) => {
  const flat = s.replace(/\n/g, "⏎")
  return flat.length > n ? flat.slice(0, n) + "…" : flat
}
const kinds = (k: Partial<Record<Kind, number>>) =>
  KINDS.filter((x) => k[x]).map((x) => `${x} ${k[x]}`).join(", ") || "none answered"

function printReport(report: Report) {
  console.log(`\nAnswered (model ${JEV_MODEL}, question set ${QUESTIONS_VERSION}, confidence bar ${minConfidence}):`)
  for (const b of BUCKETS) console.log(`  ${b.padEnd(9)} ${report.answered[b].answered}/${report.answered[b].items}`)

  console.log(`\nSafelist candidates: unknown commands Jev reads as inspect or build every time (${report.candidates.length}):`)
  for (const c of report.candidates) {
    console.log(`  ${c.group.padEnd(28)} ${String(c.uses).padStart(5)} uses, ${c.commands} distinct, min ${c.minConfidence.toFixed(2)}  [${kinds(c.kinds)}]`)
    for (const ex of c.examples) console.log(`      ${short(ex)}`)
  }

  console.log(`\nPossible holes: allowed today, Jev reads as delete, remote, credentials or system (${report.holes.length}):`)
  for (const { item, answer } of report.holes.slice(0, 60)) {
    console.log(`  ${answer.kind.padEnd(11)} ${answer.confidence.toFixed(2)}  ${String(item.uses).padStart(4)}x  ${short(item.state.command)}`)
  }
  if (report.holes.length > 60) console.log(`  … ${report.holes.length - 60} more`)

  console.log(`\nJudgment calls, by today's reason: how Jev reads them, and the ones it reads as inspect or build:`)
  for (const j of report.judgment) {
    console.log(`  ${j.reason.padEnd(40)} ${String(j.uses).padStart(5)} uses, ${j.items} distinct  [${kinds(j.kinds)}]`)
    for (const s of j.safe.slice(0, 3)) console.log(`      ${short(s.state.command)}`)
  }

  console.log(`\nHow Jev reads commands allowed today (risky kinds here are holes or Jev mistakes): ${kinds(report.allowedKinds)}`)
}

const config = await loadConfig()
const entries = readAuditLog(config.audit.path)
if (entries.length === 0) {
  console.error(`No audit log at ${config.audit.path}`)
  process.exit(1)
}

const all = await extractItems(entries, { config, shfmtBin: findShfmt() })
const answers = loadAnswers()

if (reportOnly) {
  printReport(buildReport(all, answers, { minConfidence }))
  process.exit(0)
}

const todo = selectItems(all, { buckets, perGroup }).filter((i) => !answers.has(i.key))
const tokens = todo.reduce((n, i) => n + estimateTokens(i), 0)
console.log(`hall-pass jev — ${entries.length} audit entries, ${all.length} distinct commands`)
for (const b of BUCKETS) {
  const inBucket = all.filter((i) => i.bucket === b)
  const asking = todo.filter((i) => i.bucket === b)
  const est = asking.reduce((n, i) => n + estimateTokens(i), 0)
  console.log(`  ${b.padEnd(9)} ${String(inBucket.length).padStart(6)} distinct, ${String(asking.length).padStart(6)} to ask${buckets.has(b) ? (b === "allowed" && perGroup > 0 ? ` (up to ${perGroup} per group)` : "") : " (not selected)"}, about ${money(est)}`)
}
console.log(`to send: ${todo.length} requests, about ${(tokens / 1e6).toFixed(2)}M input tokens, ${money(tokens)} (already answered: ${answers.size})`)

if (planOnly) {
  // A spread-out sample of exactly what would be sent.
  const step = Math.max(1, Math.floor(todo.length / Math.max(1, show)))
  const sample = todo.filter((_, i) => i % step === 0).slice(0, show)
  if (sample.length) console.log(`\nSample requests (state only, as sent):`)
  for (const item of sample) console.log(`  [${item.bucket}] ${JSON.stringify(item.state).slice(0, 300)}`)
  process.exit(0)
}

if (todo.length > 0) {
  const key = await resolveKey()
  mkdirSync(dataDir, { recursive: true, mode: 0o700 })
  chmodSync(dataDir, 0o700)
  let spent = 0
  let asked = 0
  let failed = 0
  let stopped = false
  let cursor = 0
  await Promise.all(
    Array.from({ length: 8 }, async () => {
      while (cursor < todo.length && !stopped) {
        if (spent * PRICE_PER_INPUT_TOKEN >= maxCost) {
          stopped = true
          return
        }
        const item: Item = todo[cursor++]!
        try {
          const answer = await askJev(item, key)
          spent += answer.inputTokens
          appendFileSync(answersPath, JSON.stringify(answer) + "\n", { mode: 0o600 })
          answers.set(item.key, answer)
          if (++asked % 500 === 0) console.log(`  ${asked}/${todo.length}  ${money(spent)}`)
        } catch (e) {
          if (++failed <= 5) console.warn(`  failed ${item.key}: ${e instanceof Error ? e.message : e}`)
        }
      }
    }),
  )
  if (existsSync(answersPath)) chmodSync(answersPath, 0o600)
  console.log(`asked ${asked}, failed ${failed}${stopped ? `, stopped at the $${maxCost} cap` : ""}; ${spent} input tokens, ${money(spent)}`)
}

printReport(buildReport(all, answers, { minConfidence }))
