import { describe, test, expect } from "bun:test"
import { checkFilePath, checkCommandPaths } from "./paths.ts"
import type { HallPassConfig } from "./config.ts"
import type { CommandInfo } from "./parser.ts"
import { homedir } from "os"
import { resolve } from "path"

function makeConfig(overrides: Partial<HallPassConfig["paths"]> = {}): HallPassConfig {
  return {
    commands: { safe: [], db_clients: [] },
    git: { protected_branches: [] },
    paths: {
      protected: overrides.protected ?? [],
      read_only: overrides.read_only ?? [],
      no_delete: overrides.no_delete ?? [],
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
    const cmd: CommandInfo = { name: "echo", args: ["echo", "hello", "world"] }

    expect(checkCommandPaths(cmd, config).allowed).toBe(true)
  })

  test("flags are skipped", () => {
    const config = makeConfig({ protected: ["**/.env"] })
    const cmd: CommandInfo = { name: "cat", args: ["cat", "-n", "--number", "/safe/file.txt"] }

    expect(checkCommandPaths(cmd, config).allowed).toBe(true)
  })

  test("read commands get read operation type", () => {
    const config = makeConfig({ read_only: ["**/config/prod/**"] })
    const cmd: CommandInfo = { name: "cat", args: ["cat", "/project/config/prod/db.yml"] }

    // cat is a read command, read-only allows read
    expect(checkCommandPaths(cmd, config).allowed).toBe(true)
  })

  test("write commands get write operation type", () => {
    const config = makeConfig({ read_only: ["**/config/prod/**"] })
    const cmd: CommandInfo = { name: "cp", args: ["cp", "/tmp/new.yml", "/project/config/prod/db.yml"] }

    // cp is a write command, read-only blocks write
    expect(checkCommandPaths(cmd, config).allowed).toBe(false)
  })

  test("delete commands get delete operation type", () => {
    const config = makeConfig({ no_delete: ["**/migrations/**"] })
    const cmd: CommandInfo = { name: "rm", args: ["rm", "/project/migrations/001.sql"] }

    expect(checkCommandPaths(cmd, config).allowed).toBe(false)
  })

  test("protected paths block even read commands", () => {
    const config = makeConfig({ protected: ["**/.env"] })
    const cmd: CommandInfo = { name: "cat", args: ["cat", "/project/.env"] }

    expect(checkCommandPaths(cmd, config).allowed).toBe(false)
  })

  test("path-like arguments with / are checked", () => {
    const config = makeConfig({ protected: ["**/.env"] })
    const cmd: CommandInfo = { name: "cp", args: ["cp", "/project/.env", "/tmp/backup"] }

    expect(checkCommandPaths(cmd, config).allowed).toBe(false)
  })

  test("path-like arguments with . prefix are checked", () => {
    const config = makeConfig({ protected: ["**/.env"] })
    const cmd: CommandInfo = { name: "cp", args: ["cp", "./.env", "/tmp/backup"] }

    expect(checkCommandPaths(cmd, config).allowed).toBe(false)
  })
})
