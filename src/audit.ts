/**
 * Audit logging for hall-pass.
 *
 * Appends JSON Lines entries to a log file for review.
 * Fire-and-forget — never blocks hook exit.
 */

import type { HallPassConfig } from "./config.ts"
import { dirname } from "path"

export interface AuditEntry {
  ts: string
  tool: string
  input: string
  decision: "allow" | "prompt" | "block" | "feedback" | "pass"
  reason: string
  layer: string
}

export interface AuditLogger {
  log(entry: Omit<AuditEntry, "ts">): void
}

export function createAudit(config: HallPassConfig): AuditLogger {
  if (!config.audit.enabled) {
    return { log() {} }
  }

  let dirCreated = false

  return {
    log(entry: Omit<AuditEntry, "ts">) {
      const full: AuditEntry = { ts: new Date().toISOString(), ...entry }
      const line = JSON.stringify(full) + "\n"

      // Fire-and-forget — don't await
      void (async () => {
        try {
          if (!dirCreated) {
            const dir = dirname(config.audit.path)
            await Bun.spawn(["mkdir", "-p", dir]).exited
            dirCreated = true
          }
          const file = Bun.file(config.audit.path)
          const existing = await file.exists() ? await file.text() : ""
          await Bun.write(config.audit.path, existing + line)
        } catch {
          // Audit failure should never block the hook
        }
      })()
    },
  }
}
