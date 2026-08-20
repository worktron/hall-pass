import { describe, test, expect, beforeEach, afterEach } from "bun:test"
import { createAudit, readAuditLog, AUDIT_MAX_BYTES } from "./audit.ts"
import { readdirSync, writeFileSync } from "fs"
import type { HallPassConfig } from "./config.ts"
import { resolve } from "path"
import { mkdtemp, rm } from "fs/promises"
import { tmpdir } from "os"

function makeConfig(enabled: boolean, path: string): HallPassConfig {
  return {
    commands: { safe: [], db_clients: [], safe_scripts: [] },
    git: { protected_branches: [], safe_subcommands: [] },
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

  test("writes are synchronous — entry on disk immediately (survives process.exit)", async () => {
    const auditPath = resolve(tmpDir, "audit.jsonl")
    const audit = createAudit(makeConfig(true, auditPath))

    audit.log({
      tool: "Bash",
      input: "git status",
      decision: "allow",
      reason: "safelist",
      layer: "safelist",
    })

    // No sleep: the hook calls process.exit() right after deciding, so the
    // entry must already be on disk here.
    const entry = JSON.parse((await Bun.file(auditPath).text()).trim())
    expect(entry.decision).toBe("allow")
  })

  test("stamps context (session, tool_use_id, mode) onto decision entries", async () => {
    const auditPath = resolve(tmpDir, "audit.jsonl")
    const audit = createAudit(makeConfig(true, auditPath), {
      session: "sess_1",
      tool_use_id: "toolu_1",
      mode: "acceptEdits",
    })

    audit.log({
      tool: "Bash",
      input: "rm -rf build",
      decision: "prompt",
      reason: "dangerous: rm",
      layer: "evaluate",
    })

    const entry = JSON.parse((await Bun.file(auditPath).text()).trim())
    expect(entry.event).toBe("decision")
    expect(entry.session).toBe("sess_1")
    expect(entry.tool_use_id).toBe("toolu_1")
    expect(entry.mode).toBe("acceptEdits")
  })

  test("event() writes completed and native-prompt entries", async () => {
    const auditPath = resolve(tmpDir, "audit.jsonl")
    const audit = createAudit(makeConfig(true, auditPath), { tool_use_id: "toolu_2" })

    audit.event("completed", { tool: "Bash" })
    audit.event("native-prompt", { message: "Permission needed to run: Bash(npm test)" })

    const lines = (await Bun.file(auditPath).text()).trim().split("\n")
    expect(lines.length).toBe(2)

    const completed = JSON.parse(lines[0]!)
    expect(completed.event).toBe("completed")
    expect(completed.tool).toBe("Bash")
    expect(completed.tool_use_id).toBe("toolu_2")

    const prompt = JSON.parse(lines[1]!)
    expect(prompt.event).toBe("native-prompt")
    expect(prompt.message).toContain("npm test")
  })

  test("event() is a no-op when disabled", async () => {
    const auditPath = resolve(tmpDir, "audit.jsonl")
    const audit = createAudit(makeConfig(false, auditPath))
    audit.event("completed", { tool: "Bash" })
    expect(await Bun.file(auditPath).exists()).toBe(false)
  })

  test("rotates an oversized log to a timestamped archive instead of trimming", async () => {
    const auditPath = resolve(tmpDir, "audit.jsonl")
    const oldLine = JSON.stringify({ ts: "2026-01-01T00:00:00.000Z", event: "decision" }) + "\n"
    writeFileSync(auditPath, oldLine + "x".repeat(AUDIT_MAX_BYTES + 1024) + "\n")

    const audit = createAudit(makeConfig(true, auditPath))
    audit.log({
      tool: "Bash",
      input: "echo fresh",
      decision: "allow",
      reason: "safelist",
      layer: "safelist",
    })

    const archives = readdirSync(tmpDir).filter((f) => f.startsWith("audit.jsonl."))
    expect(archives.length).toBe(1)

    // Fresh live log holds only the new entry; the old content is archived intact.
    const live = (await Bun.file(auditPath).text()).trim().split("\n")
    expect(live.length).toBe(1)
    expect(JSON.parse(live[0]!).input).toBe("echo fresh")
    const archived = await Bun.file(resolve(tmpDir, archives[0]!)).text()
    expect(archived.startsWith(oldLine)).toBe(true)
  })

  test("readAuditLog merges archives (oldest first) with the live log", async () => {
    const auditPath = resolve(tmpDir, "audit.jsonl")
    const line = (input: string) =>
      JSON.stringify({ ts: "2026-01-01T00:00:00.000Z", event: "decision", tool: "Bash", input }) + "\n"

    writeFileSync(resolve(tmpDir, "audit.jsonl.2026-06-01T00-00-00-000Z"), line("oldest"))
    writeFileSync(resolve(tmpDir, "audit.jsonl.2026-07-01T00-00-00-000Z"), line("middle") + "not json\n")
    writeFileSync(auditPath, line("live"))

    const entries = readAuditLog(auditPath)
    expect(entries.map((e) => e.input)).toEqual(["oldest", "middle", "live"])
  })

  test("readAuditLog returns empty for a missing log", () => {
    expect(readAuditLog(resolve(tmpDir, "nope", "audit.jsonl"))).toEqual([])
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
