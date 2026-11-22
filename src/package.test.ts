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
import { join, resolve } from "path"
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "fs"
import { tmpdir } from "os"

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

  test("hall-pass-init runs init, not the bare hall-pass command, which only prints the usage", () => {
    expect(pkg.bin?.["hall-pass-init"]).toBe("./src/init.ts")
  })
})

/**
 * `typecheck` once ran `bun build --no-bundle`, which strips types without
 * checking them: the landing gate passed while the compiler found 22 errors.
 * TypeScript 7 also loads no @types package unless tsconfig names it, so
 * without `"types": ["bun"]` every file fails on `bun:test`.
 */
describe("typecheck", () => {
  const root = resolve(import.meta.dir, "..")

  test("the typecheck script runs the TypeScript compiler", () => {
    expect(pkg.scripts.typecheck).toBe("tsc --noEmit")
  })

  test("with the project's settings, the compiler reads Bun's types and refuses a type error", async () => {
    const dir = mkdtempSync(join(tmpdir(), "hall-pass-typecheck-"))
    try {
      writeFileSync(join(dir, "good.ts"), `import { test } from "bun:test"\ntest("x", () => {})\nexport const size: number = Bun.file("x").size\n`)
      writeFileSync(join(dir, "bad.ts"), `export const n: number = "not a number"\n`)
      const config = (file: string) =>
        JSON.stringify({ extends: join(root, "tsconfig.json"), compilerOptions: { typeRoots: [join(root, "node_modules", "@types")], incremental: false }, files: [file] })
      const tsc = async (file: string) => {
        writeFileSync(join(dir, "tsconfig.json"), config(file))
        const p = Bun.spawn([join(root, "node_modules", ".bin", "tsc"), "--noEmit", "--pretty", "false", "-p", dir], { stdout: "pipe", stderr: "pipe" })
        const out = await new Response(p.stdout).text()
        return { code: await p.exited, out }
      }
      expect(await tsc("good.ts")).toEqual({ code: 0, out: "" })
      const bad = await tsc("bad.ts")
      expect(bad.code).not.toBe(0)
      expect(bad.out).toContain("bad.ts(1,14): error TS2322")
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })
})
