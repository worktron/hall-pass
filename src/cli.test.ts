/**
 * The `hall-pass` command other programs ask instead of reading hall-pass's
 * files: `decision <tool_use_id>` and `codex-hook`. Spawned for real, since
 * the exit code and an empty stdout are the contract; the lookup itself is
 * tested in-process in audit.test.ts.
 */
import { afterAll, describe, expect, test } from "bun:test"
import { mkdtempSync, rmSync, writeFileSync } from "fs"
import { resolve } from "path"
import { tmpdir } from "os"
import { hookCommand } from "./hook-command.ts"

const CLI = resolve(import.meta.dir, "cli.ts")
const dir = mkdtempSync(resolve(tmpdir(), "hall-pass-cli-"))
const auditPath = resolve(dir, "audit.jsonl")
const configPath = resolve(dir, "config.toml")
writeFileSync(configPath, `[audit]\nenabled = true\npath = "${auditPath}"\n`)
writeFileSync(
  auditPath,
  JSON.stringify({ ts: "2026-10-21T00:00:00.000Z", tool_use_id: "toolu_push", event: "decision", tool: "Bash", input: "git push origin main", decision: "prompt", reason: "git: push to protected branch main", layer: "git" }) + "\n",
)

afterAll(() => rmSync(dir, { recursive: true, force: true }))

async function cli(...args: string[]) {
  // cwd is the scratch dir so no project-local .hall-pass config applies.
  const proc = Bun.spawn(["bun", CLI, ...args], { cwd: dir, stdout: "pipe", stderr: "pipe", env: { ...process.env, HALL_PASS_CONFIG: configPath } })
  const [stdout, stderr] = await Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text()])
  return { exitCode: await proc.exited, stdout, stderr }
}

describe("hall-pass decision", () => {
  test("prints the layer and reason for a tool_use_id in the audit log", async () => {
    const r = await cli("decision", "toolu_push")
    expect(r.exitCode).toBe(0)
    expect(JSON.parse(r.stdout)).toEqual({ decision: "prompt", layer: "git", reason: "git: push to protected branch main" })
  })

  test("an unknown id exits 1 with nothing on stdout", async () => {
    const r = await cli("decision", "toolu_unknown")
    expect(r.exitCode).toBe(1)
    expect(r.stdout).toBe("")
  })

  test("no id is a usage error", async () => {
    const r = await cli("decision")
    expect(r.exitCode).toBe(2)
    expect(r.stdout).toBe("")
    expect(r.stderr).toContain("Usage")
  })
})

describe("hall-pass codex-hook", () => {
  test("prints the Codex hook command, the Claude hook's with codex-hook.ts as its entry", async () => {
    const r = await cli("codex-hook")
    expect(r.exitCode).toBe(0)
    expect(r.stdout.trim()).toBe(hookCommand("codex"))
    // What metamax derives today from the registered Claude hook.
    expect(hookCommand("claude").replace(/(^|[/\s])hook\.ts(\s|$)/, "$1codex-hook.ts$2")).toBe(r.stdout.trim())
  })
})
