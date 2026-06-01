import { describe, test, expect, beforeEach, afterEach } from "bun:test"
import { createAudit } from "./audit.ts"
import type { HallPassConfig } from "./config.ts"
import { resolve } from "path"
import { mkdtemp, rm } from "fs/promises"
import { tmpdir } from "os"

function makeConfig(enabled: boolean, path: string): HallPassConfig {
  return {
    commands: { safe: [], db_clients: [], safe_scripts: [] },
    git: { protected_branches: [] },
    paths: { protected: [], read_only: [], no_delete: [] },
    audit: { enabled, path },
    debug: { enabled: false },
  }
}

describe("audit", () => {
  let tmpDir: string

  beforeEach(async () => {
    tmpDir = await mkdtemp(resolve(tmpdir(), "hall-pass-audit-"))
  })

  afterEach(async () => {
    await rm(tmpDir, { recursive: true, force: true })
  })

  test("no file created when disabled", async () => {
    const auditPath = resolve(tmpDir, "audit.jsonl")
    const audit = createAudit(makeConfig(false, auditPath))
    audit.log({
      tool: "Bash",
      input: "echo hello",
      decision: "allow",
      reason: "safelist",
      layer: "safelist",
    })

    // Give fire-and-forget a moment
    await Bun.sleep(50)

    const file = Bun.file(auditPath)
    expect(await file.exists()).toBe(false)
  })

  test("writes valid JSON Lines when enabled", async () => {
    const auditPath = resolve(tmpDir, "audit.jsonl")
    const audit = createAudit(makeConfig(true, auditPath))

    audit.log({
      tool: "Bash",
      input: "git status",
      decision: "allow",
      reason: "safelist match",
      layer: "safelist",
    })

    audit.log({
      tool: "Bash",
      input: "rm -rf /",
      decision: "prompt",
      reason: "unknown command",
      layer: "unknown",
    })

    // Wait for fire-and-forget writes
    await Bun.sleep(200)

    const file = Bun.file(auditPath)
    expect(await file.exists()).toBe(true)

    const content = await file.text()
    const lines = content.trim().split("\n")
    expect(lines.length).toBe(2)

    for (const line of lines) {
      const entry = JSON.parse(line)
      expect(entry).toHaveProperty("ts")
      expect(entry).toHaveProperty("tool")
      expect(entry).toHaveProperty("input")
      expect(entry).toHaveProperty("decision")
      expect(entry).toHaveProperty("reason")
      expect(entry).toHaveProperty("layer")

      // ts should be a valid ISO 8601 date
      expect(new Date(entry.ts).toISOString()).toBe(entry.ts)
    }
  })

  test("each entry has required fields", async () => {
    const auditPath = resolve(tmpDir, "audit.jsonl")
    const audit = createAudit(makeConfig(true, auditPath))

    audit.log({
      tool: "Write",
      input: "/path/to/file.ts",
      decision: "prompt",
      reason: "matches protected path **/.env",
      layer: "paths",
    })

    await Bun.sleep(100)

    const content = await Bun.file(auditPath).text()
    const entry = JSON.parse(content.trim())

    expect(entry.tool).toBe("Write")
    expect(entry.input).toBe("/path/to/file.ts")
    expect(entry.decision).toBe("prompt")
    expect(entry.reason).toBe("matches protected path **/.env")
    expect(entry.layer).toBe("paths")
    expect(typeof entry.ts).toBe("string")
  })

  test("handles missing directory (creates it)", async () => {
    const auditPath = resolve(tmpDir, "nested", "dir", "audit.jsonl")
    const audit = createAudit(makeConfig(true, auditPath))

    audit.log({
      tool: "Bash",
      input: "echo test",
      decision: "allow",
      reason: "safelist",
      layer: "safelist",
    })

    await Bun.sleep(200)

    const file = Bun.file(auditPath)
    expect(await file.exists()).toBe(true)
  })
})
