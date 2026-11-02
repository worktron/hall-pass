import { afterAll, describe, test, expect } from "bun:test"
import { checkFilePath, checkCommandPaths } from "./paths.ts"
import { DEFAULT_EXEMPT_TRACKED_SOURCE_CODE, DEFAULT_PROTECTED_PATHS, type HallPassConfig } from "./config.ts"
import type { CommandInfo } from "./parser.ts"
import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "fs"
import { homedir, tmpdir } from "os"
import { dirname, resolve } from "path"

function makeConfig(overrides: Partial<HallPassConfig["paths"]> = {}): HallPassConfig {
  return {
    commands: { safe: [], db_clients: [], safe_scripts: [] },
    git: { protected_branches: [], safe_subcommands: [] },
    paths: {
      protected: overrides.protected ?? [],
      read_only: overrides.read_only ?? [],
      no_delete: overrides.no_delete ?? [],
      exempt_tracked_source_code: overrides.exempt_tracked_source_code,
    },
    audit: { enabled: false, path: "/tmp/audit.jsonl" },
    debug: { enabled: false },
  }
}

describe("checkFilePath", () => {
  test("protected paths block read/write/delete", () => {
    const config = makeConfig({ protected: ["**/.env"] })

    expect(checkFilePath("/project/.env", "read", config).allowed).toBe(false)
    expect(checkFilePath("/project/.env", "write", config).allowed).toBe(false)
    expect(checkFilePath("/project/.env", "delete", config).allowed).toBe(false)
  })

  test("read-only paths allow read, block write and delete", () => {
    const config = makeConfig({ read_only: ["**/config/prod/**"] })

    expect(checkFilePath("/project/config/prod/db.yml", "read", config).allowed).toBe(true)
    expect(checkFilePath("/project/config/prod/db.yml", "write", config).allowed).toBe(false)
    expect(checkFilePath("/project/config/prod/db.yml", "delete", config).allowed).toBe(false)
  })

  test("no-delete paths allow read/write, block delete", () => {
    const config = makeConfig({ no_delete: ["**/migrations/**"] })

    expect(checkFilePath("/project/migrations/001.sql", "read", config).allowed).toBe(true)
    expect(checkFilePath("/project/migrations/001.sql", "write", config).allowed).toBe(true)
    expect(checkFilePath("/project/migrations/001.sql", "delete", config).allowed).toBe(false)
  })

  test("glob patterns work with **/.env", () => {
    const config = makeConfig({ protected: ["**/.env"] })

    expect(checkFilePath("/a/b/c/.env", "read", config).allowed).toBe(false)
    expect(checkFilePath("/project/.env", "write", config).allowed).toBe(false)
    expect(checkFilePath("/project/.env.local", "read", config).allowed).toBe(true)
  })

  test("glob patterns work with **/.env.*", () => {
    const config = makeConfig({ protected: ["**/.env.*"] })

    expect(checkFilePath("/project/.env.local", "read", config).allowed).toBe(false)
    expect(checkFilePath("/project/.env.production", "write", config).allowed).toBe(false)
    expect(checkFilePath("/project/.env", "read", config).allowed).toBe(true)
  })

  test("~ expansion works in patterns", () => {
    const home = homedir()
    const config = makeConfig({ protected: [`${home}/.ssh/**`] })

    expect(checkFilePath(`${home}/.ssh/id_rsa`, "read", config).allowed).toBe(false)
    expect(checkFilePath(`${home}/.ssh/config`, "write", config).allowed).toBe(false)
    expect(checkFilePath("/tmp/safe-file", "read", config).allowed).toBe(true)
  })

  test("unmatched paths are allowed", () => {
    const config = makeConfig({ protected: ["**/.env"] })

    expect(checkFilePath("/project/src/index.ts", "read", config).allowed).toBe(true)
    expect(checkFilePath("/project/src/index.ts", "write", config).allowed).toBe(true)
    expect(checkFilePath("/project/src/index.ts", "delete", config).allowed).toBe(true)
  })

  test("reason includes the matched pattern", () => {
    const config = makeConfig({ protected: ["**/.env"] })

    const result = checkFilePath("/project/.env", "read", config)
    expect(result.reason).toContain("**/.env")
  })

  test("default .env paths are read-only (reads allowed, writes blocked)", () => {
    const config = makeConfig({ read_only: ["**/.env", "**/.env.*"] })

    expect(checkFilePath("/project/.env", "read", config).allowed).toBe(true)
    expect(checkFilePath("/project/.env.local", "read", config).allowed).toBe(true)
    expect(checkFilePath("/project/.env", "write", config).allowed).toBe(false)
    expect(checkFilePath("/project/.env.local", "write", config).allowed).toBe(false)
    expect(checkFilePath("/project/.env", "delete", config).allowed).toBe(false)
  })

  test("default protected paths catch credentials", () => {
    const config = makeConfig({ protected: ["**/credentials*"] })

    expect(checkFilePath("/project/credentials.json", "write", config).allowed).toBe(false)
    expect(checkFilePath("/project/credentials", "read", config).allowed).toBe(false)
  })

  describe("source code named after secrets or credentials", () => {
    // A scratch repository that tracks code named after secrets and one real
    // data file, and leaves a Django-style secrets.py out of the index, the
    // way a project keeps real values beside its code.
    const repo = realpathSync(mkdtempSync(resolve(tmpdir(), "hall-pass-paths-")))
    const git = (...args: string[]) => {
      const r = Bun.spawnSync(["git", "-C", repo, ...args], { stdout: "ignore", stderr: "pipe" })
      if (r.exitCode !== 0) throw new Error(`git ${args.join(" ")}: ${r.stderr.toString()}`)
    }
    const tracked = ["bin/secrets.ts", "bin/secrets.test.ts", "pkg/credentials.go", "Sources/Credentials.swift", "secrets.json"]
    const untracked = ["app/secrets.py", "web/credentials.php", "bin/secret_new.ts"]
    git("init", "-q")
    for (const file of [...tracked, ...untracked]) {
      mkdirSync(dirname(resolve(repo, file)), { recursive: true })
      writeFileSync(resolve(repo, file), "x\n")
    }
    git("add", ...tracked)
    afterAll(() => rmSync(repo, { recursive: true, force: true }))

    const defaults = makeConfig({
      protected: DEFAULT_PROTECTED_PATHS,
      exempt_tracked_source_code: DEFAULT_EXEMPT_TRACKED_SOURCE_CODE,
    })

    test("tracked source files are not secret stores", () => {
      for (const file of ["bin/secrets.ts", "bin/secrets.test.ts", "pkg/credentials.go", "Sources/Credentials.swift"]) {
        expect(checkFilePath(resolve(repo, file), "read", defaults)).toEqual({ allowed: true, reason: "" })
        expect(checkFilePath(resolve(repo, file), "write", defaults)).toEqual({ allowed: true, reason: "" })
      }
    })

    test("untracked source files stay protected: they may hold real values", () => {
      for (const file of untracked) {
        expect(checkFilePath(resolve(repo, file), "read", defaults).allowed).toBe(false)
      }
    })

    test("data files stay protected, tracked or not", () => {
      expect(checkFilePath(resolve(repo, "secrets.json"), "read", defaults).allowed).toBe(false)
      for (const file of ["/nowhere/secrets.yaml", "/nowhere/secrets.sh", "/nowhere/secret.key", "/nowhere/credentials"]) {
        expect(checkFilePath(file, "read", defaults).allowed).toBe(false)
      }
    })

    test("source files outside any repository stay protected", () => {
      expect(checkFilePath("/nowhere/bin/secrets.ts", "write", defaults).allowed).toBe(false)
    })

    test("with no exemption configured, every match stays protected", () => {
      const strict = makeConfig({ protected: DEFAULT_PROTECTED_PATHS })
      expect(checkFilePath(resolve(repo, "bin/secrets.ts"), "write", strict).allowed).toBe(false)
    })
  })

  test("default protected paths catch .ssh", () => {
    const home = homedir()
    const config = makeConfig({ protected: [`${home}/.ssh/**`] })

    expect(checkFilePath(`${home}/.ssh/id_rsa`, "read", config).allowed).toBe(false)
    expect(checkFilePath(`${home}/.ssh/known_hosts`, "write", config).allowed).toBe(false)
  })

  test("*.pem pattern", () => {
    const config = makeConfig({ protected: ["**/*.pem"] })

    expect(checkFilePath("/project/server.pem", "read", config).allowed).toBe(false)
    expect(checkFilePath("/certs/ca.pem", "write", config).allowed).toBe(false)
  })
})

describe("checkCommandPaths", () => {
  test("non-path arguments are skipped", () => {
    const config = makeConfig({ protected: ["**/.env"] })
    const cmd: CommandInfo = { assigns: [], name: "echo", args: ["echo", "hello", "world"] }

    expect(checkCommandPaths(cmd, config).allowed).toBe(true)
  })

  test("flags are skipped", () => {
    const config = makeConfig({ protected: ["**/.env"] })
    const cmd: CommandInfo = { assigns: [], name: "cat", args: ["cat", "-n", "--number", "/safe/file.txt"] }

    expect(checkCommandPaths(cmd, config).allowed).toBe(true)
  })

  test("read commands get read operation type", () => {
    const config = makeConfig({ read_only: ["**/config/prod/**"] })
    const cmd: CommandInfo = { assigns: [], name: "cat", args: ["cat", "/project/config/prod/db.yml"] }

    // cat is a read command, read-only allows read
    expect(checkCommandPaths(cmd, config).allowed).toBe(true)
  })

  test("write commands get write operation type", () => {
    const config = makeConfig({ read_only: ["**/config/prod/**"] })
    const cmd: CommandInfo = { assigns: [], name: "cp", args: ["cp", "/tmp/new.yml", "/project/config/prod/db.yml"] }

    // cp is a write command, read-only blocks write
    expect(checkCommandPaths(cmd, config).allowed).toBe(false)
  })

  test("delete commands get delete operation type", () => {
    const config = makeConfig({ no_delete: ["**/migrations/**"] })
    const cmd: CommandInfo = { assigns: [], name: "rm", args: ["rm", "/project/migrations/001.sql"] }

    expect(checkCommandPaths(cmd, config).allowed).toBe(false)
  })

  test("protected paths block even read commands", () => {
    const config = makeConfig({ protected: ["**/.env"] })
    const cmd: CommandInfo = { assigns: [], name: "cat", args: ["cat", "/project/.env"] }

    expect(checkCommandPaths(cmd, config).allowed).toBe(false)
  })

  test("path-like arguments with / are checked", () => {
    const config = makeConfig({ protected: ["**/.env"] })
    const cmd: CommandInfo = { assigns: [], name: "cp", args: ["cp", "/project/.env", "/tmp/backup"] }

    expect(checkCommandPaths(cmd, config).allowed).toBe(false)
  })

  test("path-like arguments with . prefix are checked", () => {
    const config = makeConfig({ protected: ["**/.env"] })
    const cmd: CommandInfo = { assigns: [], name: "cp", args: ["cp", "./.env", "/tmp/backup"] }

    expect(checkCommandPaths(cmd, config).allowed).toBe(false)
  })
})
