import { describe, expect, test } from "bun:test"
import { mkdtempSync, readdirSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { findShfmt } from "./decide"
import { ensurePinnedShfmt, SHFMT_VERSION, shfmtReleaseUrl, shfmtVersion } from "./shfmt-install"

/**
 * The operator tables in parser.ts (REDIR, BINARY) are read off one shfmt
 * version, the one shfmt-install.ts pins. A bundled binary of another version
 * renumbers them silently and the redirect guard lets `> .env` through, so
 * the two are held together here.
 */
describe("bundled shfmt", () => {
  test("is the version shfmt-install.ts pins", () => {
    const actual = shfmtVersion(findShfmt())
    expect(actual).toBe(SHFMT_VERSION.replace(/^v/, ""))
  })
})

/** A stand-in for a shfmt release: a script that prints `version`. */
function fakeShfmt(path: string, version: string): void {
  writeFileSync(path, `#!/bin/sh\necho v${version}\n`, { mode: 0o755 })
}

describe("ensurePinnedShfmt", () => {
  const withBinDir = async (run: (binDir: string, fetched: string[]) => Promise<void>) => {
    const binDir = mkdtempSync(join(tmpdir(), "hall-pass-shfmt-"))
    try {
      await run(binDir, [])
    } finally {
      rmSync(binDir, { recursive: true, force: true })
    }
  }
  const quiet = () => {}

  test("downloads the pinned release when bin/ has no shfmt", async () => {
    await withBinDir(async (binDir, fetched) => {
      const result = await ensurePinnedShfmt({
        binDir,
        version: "v3.13.0",
        log: quiet,
        fetchTo: async (url, dest) => {
          fetched.push(url)
          fakeShfmt(dest, "3.13.0")
        },
      })
      expect(result).toBe("installed")
      expect(fetched).toEqual([shfmtReleaseUrl("v3.13.0")])
      expect(shfmtVersion(join(binDir, "shfmt"))).toBe("3.13.0")
    })
  })

  test("replaces a shfmt of another version", async () => {
    await withBinDir(async (binDir, fetched) => {
      fakeShfmt(join(binDir, "shfmt"), "3.13.1")
      const result = await ensurePinnedShfmt({
        binDir,
        version: "v3.13.0",
        log: quiet,
        fetchTo: async (url, dest) => {
          fetched.push(url)
          fakeShfmt(dest, "3.13.0")
        },
      })
      expect(result).toBe("installed")
      expect(fetched.length).toBe(1)
      expect(shfmtVersion(join(binDir, "shfmt"))).toBe("3.13.0")
    })
  })

  test("leaves the pinned shfmt alone and downloads nothing", async () => {
    await withBinDir(async (binDir, fetched) => {
      fakeShfmt(join(binDir, "shfmt"), "3.13.0")
      const result = await ensurePinnedShfmt({
        binDir,
        version: "v3.13.0",
        log: quiet,
        fetchTo: async (url) => {
          fetched.push(url)
        },
      })
      expect(result).toBe("already-pinned")
      expect(fetched).toEqual([])
    })
  })

  test("a download of another version fails and leaves the old binary in place", async () => {
    await withBinDir(async (binDir) => {
      fakeShfmt(join(binDir, "shfmt"), "3.13.1")
      const run = ensurePinnedShfmt({
        binDir,
        version: "v3.13.0",
        log: quiet,
        fetchTo: async (_url, dest) => fakeShfmt(dest, "3.12.0"),
      })
      await expect(run).rejects.toThrow("downloaded shfmt reports 3.12.0, not 3.13.0")
      expect(shfmtVersion(join(binDir, "shfmt"))).toBe("3.13.1")
      expect(readdirSync(binDir)).toEqual(["shfmt"])
    })
  })

  test("a download that breaks off leaves the old binary in place", async () => {
    await withBinDir(async (binDir) => {
      fakeShfmt(join(binDir, "shfmt"), "3.13.1")
      const run = ensurePinnedShfmt({
        binDir,
        version: "v3.13.0",
        log: quiet,
        fetchTo: async (_url, dest) => {
          writeFileSync(dest, "#!/bin/sh\nec")
          throw new Error("connection reset")
        },
      })
      await expect(run).rejects.toThrow("connection reset")
      expect(shfmtVersion(join(binDir, "shfmt"))).toBe("3.13.1")
      expect(readdirSync(binDir)).toEqual(["shfmt"])
    })
  })

  test("a partial download a killed install left is removed, one still being written is kept", async () => {
    await withBinDir(async (binDir) => {
      fakeShfmt(join(binDir, "shfmt"), "3.13.0")
      const ended = Bun.spawnSync(["true"]).pid
      const running = process.ppid
      writeFileSync(join(binDir, `.shfmt-${ended}.partial`), "#!/bin/sh\nec")
      writeFileSync(join(binDir, `.shfmt-${running}.partial`), "#!/bin/sh\nec")
      const result = await ensurePinnedShfmt({ binDir, version: "v3.13.0", log: quiet, fetchTo: async () => {} })
      expect(result).toBe("already-pinned")
      expect(readdirSync(binDir).sort()).toEqual([`.shfmt-${running}.partial`, "shfmt"])
    })
  })

  test("git ignores a partial download in bin/", () => {
    const p = Bun.spawnSync(["git", "check-ignore", "-q", "--no-index", "bin/.shfmt-12345.partial"], {
      cwd: join(import.meta.dir, ".."),
    })
    expect(p.exitCode).toBe(0)
  })

  test("the new binary never appears at bin/shfmt until it is whole", async () => {
    await withBinDir(async (binDir) => {
      fakeShfmt(join(binDir, "shfmt"), "3.13.1")
      let seenDuringDownload: string | null = null
      await ensurePinnedShfmt({
        binDir,
        version: "v3.13.0",
        log: quiet,
        fetchTo: async (_url, dest) => {
          expect(dest).not.toBe(join(binDir, "shfmt"))
          fakeShfmt(dest, "3.13.0")
          seenDuringDownload = shfmtVersion(join(binDir, "shfmt"))
        },
      })
      expect(seenDuringDownload).toBe("3.13.1")
      expect(shfmtVersion(join(binDir, "shfmt"))).toBe("3.13.0")
    })
  })
})
