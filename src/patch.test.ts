import { describe, test, expect } from "bun:test"
import { homedir } from "os"
import { resolve } from "path"
import { parseApplyPatch, checkPatch } from "./patch.ts"
import { loadConfig, type HallPassConfig } from "./config.ts"

let _config: HallPassConfig | undefined
async function getConfig(): Promise<HallPassConfig> {
  return (_config ??= await loadConfig())
}

const PATCH = `*** Begin Patch
*** Add File: src/new.ts
+export const a = 1
+export const b = 2
*** Update File: src/old.ts
*** Move to: src/renamed.ts
@@ export function f() {
 context line
-removed line
+added line
*** Delete File: src/gone.ts
*** End Patch`

describe("parseApplyPatch", () => {
  test("extracts add, update (with move), and delete blocks", () => {
    const files = parseApplyPatch(PATCH)!
    expect(files).toHaveLength(3)
    expect(files[0]).toEqual({ op: "add", path: "src/new.ts", added: "export const a = 1\nexport const b = 2" })
    expect(files[1]).toEqual({ op: "update", path: "src/old.ts", movedTo: "src/renamed.ts", added: "added line" })
    expect(files[2]).toEqual({ op: "delete", path: "src/gone.ts", added: "" })
  })

  test("ignores context, removals, hunk headers, and end-of-file markers", () => {
    const files = parseApplyPatch(`*** Begin Patch
*** Update File: a.txt
@@ -1,3 +1,3 @@
 keep
-old
+new
*** End of File
*** End Patch`)!
    expect(files).toHaveLength(1)
    expect(files[0]!.added).toBe("new")
  })

  test("accepts the patch with a leading apply_patch invocation or surrounding text", () => {
    const files = parseApplyPatch(`apply_patch <<'EOF'\n*** Begin Patch\n*** Add File: x.ts\n+1\n*** End Patch\nEOF`)!
    expect(files).toEqual([{ op: "add", path: "x.ts", added: "1" }])
  })

  test("tolerates a missing End Patch marker and CRLF line endings", () => {
    const files = parseApplyPatch("*** Begin Patch\r\n*** Add File: x.ts\r\n+1\r\n")!
    expect(files).toEqual([{ op: "add", path: "x.ts", added: "1" }])
  })

  test("returns null when there is no Begin Patch marker", () => {
    expect(parseApplyPatch("not a patch")).toBeNull()
    expect(parseApplyPatch("")).toBeNull()
  })

  test("a patch with a marker but no file blocks is an empty list", () => {
    expect(parseApplyPatch("*** Begin Patch\n*** End Patch")).toEqual([])
  })
})

describe("checkPatch", () => {
  test("ordinary source files pass", async () => {
    const files = parseApplyPatch(PATCH)!
    expect(checkPatch(files, await getConfig()).ok).toBe(true)
  })

  test("a write to a protected path is blocked", async () => {
    const target = resolve(homedir(), ".ssh", "config")
    const files = parseApplyPatch(`*** Begin Patch\n*** Update File: ${target}\n+Host evil\n*** End Patch`)!
    const check = checkPatch(files, await getConfig())
    expect(check.ok).toBe(false)
    if (!check.ok) {
      expect(check.reason).toMatch(/^path-blocked: matches protected path/)
      expect(check.message).toContain(target)
    }
  })

  test("a write to a read-only path (.env) is blocked", async () => {
    const files = parseApplyPatch("*** Begin Patch\n*** Update File: .env\n+FOO=1\n*** End Patch")!
    const check = checkPatch(files, await getConfig())
    expect(check.ok).toBe(false)
    if (!check.ok) expect(check.reason).toContain("read-only path **/.env")
  })

  test("a move whose destination is protected is blocked", async () => {
    const dest = resolve(homedir(), ".aws", "credentials")
    const files = parseApplyPatch(`*** Begin Patch\n*** Update File: notes.txt\n*** Move to: ${dest}\n+x\n*** End Patch`)!
    const check = checkPatch(files, await getConfig())
    expect(check.ok).toBe(false)
    if (!check.ok) expect(check.message).toContain(dest)
  })

  test("a delete honors no_delete paths", async () => {
    const config = await getConfig()
    const strict: HallPassConfig = { ...config, paths: { ...config.paths, no_delete: ["**/migrations/**"] } }
    const files = parseApplyPatch("*** Begin Patch\n*** Delete File: db/migrations/001.sql\n*** End Patch")!
    expect(checkPatch(files, config).ok).toBe(true)
    const check = checkPatch(files, strict)
    expect(check.ok).toBe(false)
    if (!check.ok) expect(check.reason).toContain("no-delete path")
  })

  test("a hardcoded secret in added lines is blocked", async () => {
    const files = parseApplyPatch('*** Begin Patch\n*** Add File: src/k.ts\n+const k = "AKIAIOSFODNN7EXAMPLE"\n*** End Patch')!
    const check = checkPatch(files, await getConfig())
    expect(check.ok).toBe(false)
    if (!check.ok) expect(check.reason).toBe("secret: AWS access key")
  })

  test("a secret in a removed line is not a finding", async () => {
    const files = parseApplyPatch('*** Begin Patch\n*** Update File: src/k.ts\n-const k = "AKIAIOSFODNN7EXAMPLE"\n+const k = process.env.KEY\n*** End Patch')!
    expect(checkPatch(files, await getConfig()).ok).toBe(true)
  })
})
