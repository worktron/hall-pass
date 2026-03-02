import { describe, test, expect, beforeEach, afterEach } from "bun:test"
import { loadConfig, expandTilde, generateDefaultConfig, DEFAULT_PROTECTED_PATHS, DEFAULT_READ_ONLY_PATHS, initConfig } from "./config.ts"
import { homedir } from "os"
import { resolve } from "path"
import { mkdtemp, rm } from "fs/promises"
import { tmpdir } from "os"

describe("config", () => {
  let tmpDir: string

  beforeEach(async () => {
    tmpDir = await mkdtemp(resolve(tmpdir(), "hall-pass-test-"))
  })

  afterEach(async () => {
    await rm(tmpDir, { recursive: true, force: true })
    delete process.env.HALL_PASS_CONFIG
  })

  test("returns defaults when no config file exists", async () => {
    process.env.HALL_PASS_CONFIG = resolve(tmpDir, "nonexistent.toml")
    const config = await loadConfig()

    expect(config.commands.safe).toEqual([])
    expect(config.commands.db_clients).toEqual([])
    expect(config.git.protected_branches).toEqual([])
    expect(config.audit.enabled).toBe(false)
    expect(config.debug.enabled).toBe(false)
    // Default protected paths should have ~ expanded
    expect(config.paths.protected.length).toBeGreaterThan(0)
  })

  test("parses valid TOML and merges with defaults", async () => {
    const configPath = resolve(tmpDir, "config.toml")
    await Bun.write(configPath, `
[commands]
safe = ["terraform", "kubectl"]
db_clients = ["pgcli"]

[git]
protected_branches = ["release"]

[paths]
protected = ["**/production.env"]
read_only = ["**/config/prod/**"]
no_delete = ["**/migrations/**"]

[audit]
enabled = true
path = "${tmpDir}/audit.jsonl"

[debug]
enabled = true
`)
    process.env.HALL_PASS_CONFIG = configPath
    const config = await loadConfig()

    // User commands extend defaults
    expect(config.commands.safe).toEqual(["terraform", "kubectl"])
    expect(config.commands.db_clients).toEqual(["pgcli"])
    expect(config.git.protected_branches).toEqual(["release"])

    // User paths extend default protected paths
    expect(config.paths.protected).toContain("**/production.env")
    for (const defaultPath of DEFAULT_PROTECTED_PATHS) {
      expect(config.paths.protected).toContain(expandTilde(defaultPath))
    }

    expect(config.paths.read_only).toEqual([...DEFAULT_READ_ONLY_PATHS, "**/config/prod/**"])
    expect(config.paths.no_delete).toEqual(["**/migrations/**"])

    expect(config.audit.enabled).toBe(true)
    expect(config.audit.path).toBe(`${tmpDir}/audit.jsonl`)
    expect(config.debug.enabled).toBe(true)
  })

  test("user commands extend (not replace) built-in defaults", async () => {
    const configPath = resolve(tmpDir, "config.toml")
    await Bun.write(configPath, `
[paths]
protected = ["**/my-secret"]
`)
    process.env.HALL_PASS_CONFIG = configPath
    const config = await loadConfig()

    // Should have both default and user paths
    expect(config.paths.protected).toContain("**/my-secret")
    // Default .env pattern should be in read_only (with ~ expanded)
    expect(config.paths.read_only.some(p => p.includes(".env"))).toBe(true)
  })

  test("expands ~ in paths", async () => {
    const configPath = resolve(tmpDir, "config.toml")
    await Bun.write(configPath, `
[paths]
protected = ["~/my-secrets/**"]

[audit]
enabled = true
path = "~/logs/audit.jsonl"
`)
    process.env.HALL_PASS_CONFIG = configPath
    const config = await loadConfig()

    const home = homedir()
    expect(config.paths.protected).toContain(resolve(home, "my-secrets/**"))
    expect(config.audit.path).toBe(resolve(home, "logs/audit.jsonl"))
  })

  test("handles malformed TOML gracefully (returns defaults)", async () => {
    const configPath = resolve(tmpDir, "config.toml")
    await Bun.write(configPath, "this is not [valid toml {{{{")
    process.env.HALL_PASS_CONFIG = configPath
    const config = await loadConfig()

    // Should return defaults without throwing
    expect(config.commands.safe).toEqual([])
    expect(config.paths.protected.length).toBeGreaterThan(0)
  })

  test("handles empty config file", async () => {
    const configPath = resolve(tmpDir, "config.toml")
    await Bun.write(configPath, "")
    process.env.HALL_PASS_CONFIG = configPath
    const config = await loadConfig()

    expect(config.commands.safe).toEqual([])
    expect(config.audit.enabled).toBe(false)
  })

  test("HALL_PASS_CONFIG env var overrides default path", async () => {
    const configPath = resolve(tmpDir, "custom-config.toml")
    await Bun.write(configPath, `
[debug]
enabled = true
`)
    process.env.HALL_PASS_CONFIG = configPath
    const config = await loadConfig()
    expect(config.debug.enabled).toBe(true)
  })
})

describe("expandTilde", () => {
  test("expands ~/path", () => {
    const result = expandTilde("~/foo/bar")
    expect(result).toBe(resolve(homedir(), "foo/bar"))
  })

  test("expands bare ~", () => {
    const result = expandTilde("~")
    expect(result).toBe(homedir())
  })

  test("leaves absolute paths unchanged", () => {
    expect(expandTilde("/usr/bin")).toBe("/usr/bin")
  })

  test("leaves relative paths unchanged", () => {
    expect(expandTilde("./foo")).toBe("./foo")
  })
})

describe("generateDefaultConfig", () => {
  test("produces valid TOML with comments", () => {
    const config = generateDefaultConfig()
    expect(config).toContain("[commands]")
    expect(config).toContain("[git]")
    expect(config).toContain("[paths]")
    expect(config).toContain("[audit]")
    expect(config).toContain("[debug]")
    expect(config).toContain("#")
  })
})

describe("initConfig", () => {
  let tmpDir: string

  beforeEach(async () => {
    tmpDir = await mkdtemp(resolve(tmpdir(), "hall-pass-init-"))
  })

  afterEach(async () => {
    await rm(tmpDir, { recursive: true, force: true })
    delete process.env.HALL_PASS_CONFIG
  })

  test("creates config file with defaults", async () => {
    const configPath = resolve(tmpDir, "subdir", "config.toml")
    process.env.HALL_PASS_CONFIG = configPath
    const result = await initConfig()

    expect(result).toBe(configPath)
    const file = Bun.file(configPath)
    expect(await file.exists()).toBe(true)
    const content = await file.text()
    expect(content).toContain("[commands]")
  })
})
