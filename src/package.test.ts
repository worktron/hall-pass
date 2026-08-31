/**
 * hall-pass's setup script REGISTERS ITS HOOKS in ~/.claude/settings.json,
 * pointing at the checkout it runs from. That must only ever happen when a
 * human asks for it.
 *
 * It was once named "install", which is a package-manager lifecycle name: a
 * plain `bun install` for dependencies — in a clone, a worktree, a CI job —
 * silently re-registered every hook on the machine to that directory. When
 * the directory was a temporary worktree that later went away, every Claude
 * Code session on the machine failed with "Module not found" on every tool
 * call. Renaming it to "setup" fixed that; this test keeps it fixed.
 *
 * The list is what `bun install` / `bun add` were observed to run (bun 1.x,
 * verified against a throwaway package): the three install phases plus
 * prepare. "uninstall" is NOT triggered by any of them, so it keeps its name.
 */
import { describe, expect, test } from "bun:test"
import { resolve } from "path"
import { readFileSync } from "fs"

const LIFECYCLE_SCRIPTS = [
  "preinstall",
  "install",
  "postinstall",
  "prepare",
  "preprepare",
  "postprepare",
  "prepublish",
  "prepublishOnly",
  "postpublish",
  "prepack",
  "postpack",
]

const pkg = JSON.parse(readFileSync(resolve(import.meta.dir, "..", "package.json"), "utf8"))

describe("package.json scripts", () => {
  test("no script uses a package-manager lifecycle name", () => {
    const declared = Object.keys(pkg.scripts ?? {})
    const lifecycle = declared.filter((name) => LIFECYCLE_SCRIPTS.includes(name))
    expect(lifecycle).toEqual([])
  })

  test("setup is the name of the hook-registering script", () => {
    expect(pkg.scripts?.setup).toBe("bun src/install.ts")
  })

  test("the global binaries are unchanged — npm users still run hall-pass-install", () => {
    expect(pkg.bin?.["hall-pass-install"]).toBe("./src/install.ts")
    expect(pkg.bin?.["hall-pass-uninstall"]).toBe("./src/uninstall.ts")
  })
})
