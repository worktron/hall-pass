/**
 * Puts the pinned shfmt in hall-pass's bin/, where findShfmt looks first.
 *
 * parser.ts reads its operator tables off this one shfmt version, so hall-pass
 * must run it and not whichever shfmt happens to be on PATH. Both setup
 * (install.ts) and a new worktree's setup (metamax.json) call this.
 *
 * Run directly: `bun src/shfmt-install.ts`.
 */

import { chmodSync, existsSync, mkdirSync, renameSync, rmSync } from "node:fs"
import { resolve } from "node:path"

export const SHFMT_VERSION = "v3.13.0"

export const BUNDLED_SHFMT_DIR = resolve(import.meta.dir, "..", "bin")

/** The version a shfmt binary reports, without its leading "v", or null when it does not run. */
export function shfmtVersion(bin: string): string | null {
  if (!existsSync(bin)) return null
  try {
    const p = Bun.spawnSync([bin, "--version"])
    if (p.exitCode !== 0) return null
    return p.stdout.toString().trim().replace(/^v/, "")
  } catch {
    return null
  }
}

export function shfmtReleaseUrl(version = SHFMT_VERSION): string {
  const platform = process.platform === "darwin" ? "darwin" : "linux"
  const arch = process.arch === "arm64" ? "arm64" : "amd64"
  return `https://github.com/mvdan/sh/releases/download/${version}/shfmt_${version}_${platform}_${arch}`
}

/** Writes the binary at `url` to `dest`. Throws when the download fails. */
async function download(url: string, dest: string): Promise<void> {
  const resp = await fetch(url)
  if (!resp.ok) throw new Error(`Failed to download shfmt: ${resp.status} ${resp.statusText} (${url})`)
  await Bun.write(dest, resp)
}

export type EnsureResult = "already-pinned" | "installed"

/**
 * Makes `<binDir>/shfmt` the pinned version: leaves it when it already is,
 * else downloads the pinned release over it. Throws when the downloaded
 * binary still reports another version.
 */
export async function ensurePinnedShfmt(opts: {
  binDir?: string
  version?: string
  fetchTo?: (url: string, dest: string) => Promise<void>
  log?: (line: string) => void
} = {}): Promise<EnsureResult> {
  const binDir = opts.binDir ?? BUNDLED_SHFMT_DIR
  const version = opts.version ?? SHFMT_VERSION
  const fetchTo = opts.fetchTo ?? download
  const log = opts.log ?? console.log
  const dest = resolve(binDir, "shfmt")
  const want = version.replace(/^v/, "")

  const have = shfmtVersion(dest)
  if (have === want) {
    log(`shfmt ${version} already at ${dest}`)
    return "already-pinned"
  }

  log(have ? `shfmt at ${dest} is ${have}, replacing it with ${version}` : `Downloading shfmt ${version}...`)
  mkdirSync(binDir, { recursive: true })
  // Every hook runs bin/shfmt, so the new binary is written beside it, checked,
  // and renamed over it: no hook sees a partial file, and a failed download
  // leaves the old binary in place.
  const partial = resolve(binDir, `.shfmt-${process.pid}.partial`)
  try {
    await fetchTo(shfmtReleaseUrl(version), partial)
    chmodSync(partial, 0o755)
    const got = shfmtVersion(partial)
    if (got !== want) throw new Error(`downloaded shfmt reports ${got ?? "nothing"}, not ${want}; ${dest} left as it was`)
    renameSync(partial, dest)
  } finally {
    rmSync(partial, { force: true })
  }
  log(`Installed shfmt ${version} to ${dest}`)
  return "installed"
}

if (import.meta.main) {
  try {
    await ensurePinnedShfmt()
  } catch (err) {
    console.error(err instanceof Error ? err.message : String(err))
    process.exit(1)
  }
}
