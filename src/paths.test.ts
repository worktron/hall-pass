import { describe, test, expect } from "bun:test"
import { checkFilePath, checkCommandPaths, isPathAwareCommand } from "./paths.ts"
import type { HallPassConfig } from "./config.ts"
import type { CommandInfo } from "./parser.ts"
import { homedir } from "os"
import { resolve } from "path"

function makeConfig(overrides: Partial<HallPassConfig["paths"]> = {}): HallPassConfig {
  return {
    commands: { safe: [], db_clients: [], safe_scripts: [] },
    git: { protected_branches: [], safe_subcommands: [] },
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

describe("readers honor protected paths", () => {
  const config = makeConfig({ protected: ["~/.ssh/**", "~/.aws/**", "**/secret*"] })
  const blocked = (...args: string[]) => checkCommandPaths({ assigns: [], name: args[0]!, args }, config).allowed === false

  test("every reader that prints a file is path-aware", () => {
    for (const name of ["grep", "rg", "jq", "awk", "base64", "sort", "cut", "tar", "zip", "nl"]) {
      expect(isPathAwareCommand(name)).toBe(true)
    }
  })

  test("a reader given a protected file stops, as cat does", () => {
    expect(blocked("grep", "x", "~/.ssh/id_rsa")).toBe(true)
    expect(blocked("jq", ".", "~/.aws/credentials")).toBe(true)
    expect(blocked("awk", "1", "~/.ssh/id_rsa")).toBe(true)
    expect(blocked("base64", "~/.ssh/id_rsa")).toBe(true)
    expect(blocked("base64", "-i", "~/.ssh/id_rsa", "-o", "/tmp/k")).toBe(true)
    expect(blocked("sort", "~/.ssh/known_hosts")).toBe(true)
    expect(blocked("rg", "key", "~/.ssh")).toBe(true)
  })

  test("the directory a dir/** pattern protects is protected too", () => {
    expect(checkFilePath("~/.ssh", "read", config).allowed).toBe(false)
    expect(checkFilePath("~/.ssh/", "read", config).allowed).toBe(false)
    expect(blocked("tar", "czf", "/tmp/x.tgz", "~/.ssh")).toBe(true)
    expect(blocked("grep", "-r", "key", "~/.aws")).toBe(true)
    expect(checkFilePath("~/.sshfoo", "read", config).allowed).toBe(true)
    expect(checkFilePath("~/Workspace", "read", config).allowed).toBe(true)
  })

  test("the pattern or program is not a path", () => {
    expect(blocked("grep", "-n", "api/secret", "src/app.ts")).toBe(false)
    expect(blocked("grep", "-A", "3", "api/secret", "src/app.ts")).toBe(false)
    expect(blocked("rg", "-g", "*.ts", "api/secret", "src/")).toBe(false)
    expect(blocked("awk", "-F", "/", "{print $2}", "data/a.txt")).toBe(false)
    expect(blocked("jq", "-r", ".a/secret", "data/a.json")).toBe(false)
    expect(blocked("jq", "--arg", "k", "./secret", ".x", "data/a.json")).toBe(false)
  })

  test("with -e or -f the pattern comes from the option, so every operand is a file", () => {
    expect(blocked("grep", "-e", "x", "./secret.txt")).toBe(true)
    expect(blocked("grep", "-rne", "x", "./secret.txt")).toBe(true)
    expect(blocked("grep", "--regexp=x", "./secret.txt")).toBe(true)
    expect(blocked("awk", "-f", "prog.awk", "./secret.txt")).toBe(true)
    expect(blocked("rg", "--files", "~/.ssh")).toBe(true)
  })

  test("a pattern or program file is read too", () => {
    expect(blocked("grep", "-f", "~/.ssh/id_rsa", "notes.txt")).toBe(true)
    expect(blocked("grep", "-f~/.ssh/id_rsa", "notes.txt")).toBe(true)
    expect(blocked("jq", "--rawfile", "k", "~/.ssh/id_rsa", "-n", "$k")).toBe(true)
    expect(blocked("jq", "-f", "~/.ssh/prog.jq", "a.json")).toBe(true)
  })

  test("jq --args turns the rest into strings, not files", () => {
    expect(blocked("jq", "-n", "$ARGS", "--args", "./secret")).toBe(false)
  })
})

describe("default protected paths", () => {
  test("Railway's token file is protected", async () => {
    const { DEFAULT_PROTECTED_PATHS } = await import("./config.ts")
    const config = makeConfig({ protected: DEFAULT_PROTECTED_PATHS })
    expect(checkFilePath("~/.railway/config.json", "read", config).allowed).toBe(false)
    expect(checkCommandPaths({ assigns: [], name: "jq", args: ["jq", "-r", ".user.accessToken", "~/.railway/config.json"] }, config).allowed).toBe(false)
  })
})
