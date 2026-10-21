/**
 * The `hall-pass` command other programs ask instead of reading hall-pass's
 * files: `decision <tool_use_id>` and `codex-hook`. Spawned for real, since
 * the exit code and an empty stdout are the contract; the lookup itself is
 * tested in-process in audit.test.ts.
 */
import { afterAll, describe, expect, test } from "bun:test"
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "fs"
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

// Each init test gets its own config path, so the shared one above (which the
// decision tests read) is never written and no test depends on another's file.
const INIT = resolve(import.meta.dir, "init.ts")
const MINE = '[commands]\nsafe_scripts = ["~/my-script.sh"]\n'

async function spawnWith(entry: string, config: string, ...args: string[]) {
  const proc = Bun.spawn(["bun", entry, ...args], { cwd: dir, stdout: "pipe", stderr: "pipe", env: { ...process.env, HALL_PASS_CONFIG: config } })
  const [stdout, stderr] = await Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text()])
  return { exitCode: await proc.exited, stdout, stderr }
}

function scratchConfig(withMine: boolean): string {
  const path = resolve(mkdtempSync(resolve(dir, "init-")), "config.toml")
  if (withMine) writeFileSync(path, MINE)
  return path
}

describe("bare hall-pass", () => {
  test("prints the usage and creates no config", async () => {
    const config = scratchConfig(false)
    const r = await spawnWith(CLI, config)
    expect(r.exitCode).toBe(0)
    expect(r.stdout).toContain("Usage: hall-pass")
    expect(r.stdout).toContain("init")
    expect(existsSync(config)).toBe(false)
  })

  test("leaves an existing config's bytes unchanged", async () => {
    const config = scratchConfig(true)
    const r = await spawnWith(CLI, config)
    expect(r.exitCode).toBe(0)
    expect(readFileSync(config, "utf8")).toBe(MINE)
  })

  test("--help prints the usage too", async () => {
    const r = await spawnWith(CLI, scratchConfig(false), "--help")
    expect(r.exitCode).toBe(0)
    expect(r.stdout).toContain("Usage: hall-pass")
  })
})

describe.each([
  ["hall-pass init", CLI, ["init"]],
  ["hall-pass-init", INIT, []],
])("%s", (_name, entry, args) => {
  test("creates the default config when none exists", async () => {
    const config = scratchConfig(false)
    const r = await spawnWith(entry, config, ...args)
    expect(r.exitCode).toBe(0)
    expect(r.stdout).toContain(`Created default config at ${config}`)
    expect(readFileSync(config, "utf8")).toContain("[commands]")
  })

  test("refuses when a config exists: exit 1, names the file and how to replace it, bytes unchanged", async () => {
    const config = scratchConfig(true)
    const r = await spawnWith(entry, config, ...args)
    expect(r.exitCode).toBe(1)
    expect(r.stdout).toBe("")
    expect(r.stderr).toContain(`Config already exists at ${config}`)
    expect(r.stderr).toContain(`mv ${config} ${config}.bak`)
    expect(readFileSync(config, "utf8")).toBe(MINE)
  })
})
