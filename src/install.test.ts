/**
 * The setup and uninstall scripts must register hooks in the settings file
 * the running Claude Code account actually reads: $CLAUDE_CONFIG_DIR when
 * set (one directory per account), else ~/.claude. Writing to ~/.claude
 * while an account runs from another directory leaves that account with
 * stale or missing hooks. Both scripts are spawned against a scratch HOME
 * so the real settings are never touched.
 */
import { describe, expect, test } from "bun:test"
import { resolve } from "path"
import { existsSync, mkdtempSync, mkdirSync, readFileSync, realpathSync, writeFileSync } from "fs"
import { tmpdir } from "os"

const INSTALL = resolve(import.meta.dir, "install.ts")
const UNINSTALL = resolve(import.meta.dir, "uninstall.ts")

async function run(script: string, env: Record<string, string | undefined>, args: string[] = []) {
  const proc = Bun.spawn(["bun", script, ...args], {
    stdout: "pipe",
    stderr: "pipe",
    env: { ...process.env, ...env },
  })
  const [stdout, stderr] = await Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text()])
  await proc.exited
  return { exitCode: proc.exitCode ?? 1, stdout, stderr }
}

function hookCommands(path: string): string[] {
  const settings = JSON.parse(readFileSync(path, "utf8"))
  const out: string[] = []
  for (const entries of Object.values((settings.hooks ?? {}) as Record<string, Array<{ hooks: Array<{ command: string }> }>>)) {
    for (const entry of entries) for (const h of entry.hooks) out.push(h.command)
  }
  return out
}

function scratchHome(): { home: string; env: Record<string, string | undefined> } {
  const home = mkdtempSync(resolve(tmpdir(), "hall-pass-install-"))
  // BUN_INSTALL too: setup runs `bun link`, which must not repoint the
  // machine's real `hall-pass` command at this checkout.
  return { home, env: { HOME: home, CLAUDE_CONFIG_DIR: undefined, BUN_INSTALL: resolve(home, ".bun") } }
}

describe("setup honors CLAUDE_CONFIG_DIR", () => {
  test("without it, registers in ~/.claude/settings.json", async () => {
    const { home, env } = scratchHome()
    const r = await run(INSTALL, env)
    expect(r.exitCode).toBe(0)
    const path = resolve(home, ".claude", "settings.json")
    expect(existsSync(path)).toBe(true)
    expect(hookCommands(path).every((c) => c.includes("hall-pass"))).toBe(true)
    expect(hookCommands(path).length).toBeGreaterThan(0)
  })

  test("with it, registers there and leaves ~/.claude alone", async () => {
    const { home, env } = scratchHome()
    const account = resolve(home, "accounts", "worktron", "claude")
    mkdirSync(account, { recursive: true })
    writeFileSync(resolve(account, "settings.json"), JSON.stringify({ permissions: { allow: ["Bash(ls *)"] } }))

    const r = await run(INSTALL, { ...env, CLAUDE_CONFIG_DIR: account })
    expect(r.exitCode).toBe(0)
    expect(r.stdout).toContain(account)

    const written = JSON.parse(readFileSync(resolve(account, "settings.json"), "utf8"))
    expect(written.permissions.allow).toContain("Bash(ls *)") // merged, not replaced
    expect(hookCommands(resolve(account, "settings.json")).length).toBeGreaterThan(0)
    expect(existsSync(resolve(home, ".claude", "settings.json"))).toBe(false)
  })

  test("--codex is unaffected: Codex has no per-account split", async () => {
    const { home, env } = scratchHome()
    const account = resolve(home, "accounts", "worktron", "claude")
    mkdirSync(account, { recursive: true })
    const r = await run(INSTALL, { ...env, CLAUDE_CONFIG_DIR: account }, ["--codex"])
    expect(r.exitCode).toBe(0)
    expect(existsSync(resolve(home, ".codex", "hooks.json"))).toBe(true)
    expect(existsSync(resolve(account, "settings.json"))).toBe(false)
  })
})

describe("setup puts the hall-pass command on the PATH", () => {
  test("the linked command's codex-hook prints what setup --codex registers, naming the real checkout", async () => {
    const { home, env } = scratchHome()
    const r = await run(INSTALL, env, ["--codex"])
    expect(r.exitCode).toBe(0)
    const linked = resolve(home, ".bun", "bin", "hall-pass")
    expect(existsSync(linked)).toBe(true)

    const printed = await run(linked, env, ["codex-hook"])
    expect(printed.exitCode).toBe(0)
    const registered = new Set(hookCommands(resolve(home, ".codex", "hooks.json")))
    expect([...registered]).toEqual([printed.stdout.trim()])
    // Through the link, yet the command names the checkout, never bun's bin directory.
    expect(printed.stdout.trim()).toBe(`bun ${resolve(realpathSync(import.meta.dir), "codex-hook.ts")}`)
  })
})

describe("uninstall honors CLAUDE_CONFIG_DIR", () => {
  test("removes the hooks from the account directory it was given", async () => {
    const { home, env } = scratchHome()
    const account = resolve(home, "accounts", "worktron", "claude")
    mkdirSync(account, { recursive: true })
    const accountEnv = { ...env, CLAUDE_CONFIG_DIR: account }

    await run(INSTALL, accountEnv)
    expect(hookCommands(resolve(account, "settings.json")).length).toBeGreaterThan(0)

    const r = await run(UNINSTALL, accountEnv)
    expect(r.exitCode).toBe(0)
    expect(r.stdout).toContain(account)
    expect(hookCommands(resolve(account, "settings.json"))).toEqual([])
  })
})

describe("setup --init", () => {
  test("creates the config when none exists", async () => {
    const { home, env } = scratchHome()
    const config = resolve(home, ".config", "hall-pass", "config.toml")
    const r = await run(INSTALL, { ...env, HALL_PASS_CONFIG: config }, ["--init"])
    expect(r.exitCode).toBe(0)
    expect(r.stdout).toContain(`Created default config at ${config}`)
    expect(readFileSync(config, "utf8")).toContain("[commands]")
  })

  test("keeps an existing config byte for byte, says so, and still registers the hooks", async () => {
    const { home, env } = scratchHome()
    const config = resolve(home, ".config", "hall-pass", "config.toml")
    const mine = '[commands]\nsafe_scripts = ["~/my-script.sh"]\n'
    mkdirSync(resolve(config, ".."), { recursive: true })
    writeFileSync(config, mine)

    const r = await run(INSTALL, { ...env, HALL_PASS_CONFIG: config }, ["--init"])
    expect(r.exitCode).toBe(0)
    expect(r.stdout).toContain(`Config already exists at ${config}`)
    expect(r.stdout).toContain(`mv ${config} ${config}.bak`)
    expect(readFileSync(config, "utf8")).toBe(mine)
    expect(hookCommands(resolve(home, ".claude", "settings.json")).length).toBeGreaterThan(0)
  })
})
