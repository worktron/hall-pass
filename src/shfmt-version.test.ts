import { describe, expect, test } from "bun:test"
import { readFileSync } from "node:fs"
import { resolve } from "node:path"
import { findShfmt } from "./decide"

/**
 * The operator tables in parser.ts (REDIR, BINARY) are read off one shfmt
 * version, the one install.ts pins. A bundled binary of another version
 * renumbers them silently and the redirect guard lets `> .env` through, so
 * the two are held together here.
 */
describe("bundled shfmt", () => {
  test("is the version install.ts pins", () => {
    const install = readFileSync(resolve(import.meta.dir, "install.ts"), "utf8")
    const pinned = install.match(/SHFMT_VERSION = "v([^"]+)"/)?.[1]
    expect(pinned).toBeDefined()
    const proc = Bun.spawnSync([findShfmt(), "--version"])
    const actual = proc.stdout.toString().trim().replace(/^v/, "")
    expect(actual).toBe(pinned!)
  })
})
