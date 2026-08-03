/**
 * Audit logging for hall-pass.
 *
 * Appends JSON Lines entries to a log file. Two kinds of entries:
 *   - decisions (event: "decision")     — one per PreToolUse evaluation
 *   - outcomes  (event: "completed")    — PostToolUse fired, i.e. the call ran
 *   - outcomes  (event: "native-prompt") — Claude Code showed a permission prompt
 *
 * Decisions and completions share a tool_use_id, so joining them tells you
 * whether a prompted command was approved (ran) or not (see stats.ts).
 *
 * Writes are synchronous: the hook process calls process.exit() right after
 * emitting its decision, which would kill an in-flight async write.
 *
 * Past ~5MB the live log rotates to `<path>.<timestamp>` — archives are
 * never deleted, and readAuditLog() reads archives + live as one corpus.
 */

import type { HallPassConfig } from "./config.ts"
import { appendFileSync, mkdirSync, readFileSync, readdirSync, renameSync, statSync } from "fs"
import { basename, dirname, resolve } from "path"

export const AUDIT_MAX_BYTES = 5_000_000

/** Per-invocation context from the hook's stdin, stamped onto every entry. */
export interface AuditContext {
  session?: string
  tool_use_id?: string
  mode?: string
}

export interface AuditEntry extends AuditContext {
  ts: string
  event: "decision" | "completed" | "native-prompt"
  tool?: string
  input?: string
  decision?: "allow" | "prompt" | "block" | "feedback" | "pass"
  reason?: string
  layer?: string
  message?: string
}

export interface DecisionEntry {
  tool: string
  input: string
  decision: "allow" | "prompt" | "block" | "feedback" | "pass"
  reason: string
  layer: string
}

export interface AuditLogger {
  /** Record a PreToolUse decision. Context is stamped automatically. */
  log(entry: DecisionEntry): void
  /** Record an outcome event (tool call completed, native prompt shown). */
  event(event: "completed" | "native-prompt", fields?: Partial<AuditEntry>): void
}

/**
 * Read every audit entry: rotated archives (oldest first — timestamp
 * suffixes sort lexically) followed by the live log. Missing files and
 * malformed lines are skipped.
 */
export function readAuditLog(path: string): AuditEntry[] {
  const base = basename(path)
  let files: string[] = []
  try {
    files = readdirSync(dirname(path))
      .filter((f) => f.startsWith(`${base}.`))
      .sort()
      .map((f) => resolve(dirname(path), f))
  } catch {}
  files.push(path)

  const entries: AuditEntry[] = []
  for (const file of files) {
    let text: string
    try {
      text = readFileSync(file, "utf8")
    } catch {
      continue
    }
    for (const line of text.split("\n")) {
      if (!line) continue
      try {
        entries.push(JSON.parse(line))
      } catch {}
    }
  }
  return entries
}

export function createAudit(config: HallPassConfig, ctx: AuditContext = {}): AuditLogger {
  if (!config.audit.enabled) {
    return { log() {}, event() {} }
  }

  let prepared = false

  function write(entry: Omit<AuditEntry, "ts">) {
    // Audit failure should never block the hook.
    try {
      if (!prepared) {
        prepared = true
        mkdirSync(dirname(config.audit.path), { recursive: true })
        try {
          // Rotate rather than trim: the log is the eval corpus (see
          // eval.ts), so history archives instead of evaporating. Rename
          // is atomic; a concurrent writer just starts the fresh file.
          if (statSync(config.audit.path).size > AUDIT_MAX_BYTES) {
            const stamp = new Date().toISOString().replace(/[:.]/g, "-")
            renameSync(config.audit.path, `${config.audit.path}.${stamp}`)
          }
        } catch {}
      }
      const full: AuditEntry = { ts: new Date().toISOString(), ...ctx, ...entry }
      appendFileSync(config.audit.path, JSON.stringify(full) + "\n")
    } catch {}
  }

  return {
    log(entry: DecisionEntry) {
      write({ event: "decision", ...entry })
    },
    event(event, fields = {}) {
      write({ event, ...fields })
    },
  }
}
