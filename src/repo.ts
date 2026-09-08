/**
 * What hall-pass can learn about the repository a git command runs in.
 *
 * Two git rules need more than the command line: setting `core.hooksPath`
 * (a hard stop, unless the value is the repo's own hook directory) and a
 * push to a protected branch (a hard stop, unless the remote is a local
 * path or the repository is a throwaway under a temp directory). Both need
 * the repository's top level, its remotes, and its `metamax.json`. Every
 * lookup here is best-effort and returns null on failure; the caller keeps
 * the conservative rule when it learns nothing.
 *
 * The lookups spawn `git`, so they run only on the rare command that needs
 * them, never on the hot path of a plain `git status`.
 */

import { readFileSync, realpathSync } from "fs"
import { join } from "path"
import { tmpdir } from "os"

/** Run a read-only git query in `dir`; null on any failure or empty output. */
export function gitQuery(dir: string, args: string[]): string | null {
  try {
    const result = Bun.spawnSync(["git", "-C", dir, ...args], {
      stdout: "pipe",
      stderr: "ignore",
      stdin: "ignore",
      timeout: 5000,
    })
    if (result.exitCode !== 0) return null
    const out = result.stdout.toString().trim()
    return out || null
  } catch {
    return null
  }
}

/** Top-level directory of the working tree containing `dir`. */
export function gitTopLevel(dir: string): string | null {
  return gitQuery(dir, ["rev-parse", "--show-toplevel"])
}

/** The URL a push to remote `name` goes to (insteadOf rewrites applied). */
export function gitRemoteUrl(dir: string, name: string): string | null {
  return gitQuery(dir, ["remote", "get-url", "--push", name])
}

/**
 * True when a remote's URL is a filesystem path: `/srv/x.git`, `../bare`,
 * `~/x`, `file:///x`, or a bare relative name. A scheme (`https://`,
 * `ssh://`) or an scp-style `host:path` is a network remote.
 */
export function isLocalRemoteUrl(url: string): boolean {
  if (url.startsWith("file://")) return true
  if (url.startsWith("/") || url.startsWith("./") || url.startsWith("../") || url.startsWith("~")) return true
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(url)) return false
  if (/^[^/]+:/.test(url)) return false
  return true
}

/** A path with macOS's /private prefix dropped, resolved through symlinks when it exists. */
function canonical(path: string): string {
  let resolved = path
  try {
    resolved = realpathSync(path)
  } catch {
    /* keep the path as given */
  }
  return resolved.replace(/^\/private\//, "/")
}

/**
 * True when `dir` is under a temp directory (the OS tmpdir, /tmp, macOS's
 * /var/folders) or has a `scratchpad` segment: a repository there is a
 * throwaway, never the one whose main branch needs a human checkpoint.
 */
export function isScratchDir(dir: string): boolean {
  const target = canonical(dir)
  const roots = [tmpdir(), process.env.TMPDIR, "/tmp", "/var/folders"]
    .filter((root): root is string => Boolean(root))
    .map(canonical)
  for (const root of roots) {
    if (target === root || target.startsWith(root.endsWith("/") ? root : `${root}/`)) return true
  }
  return target.split("/").includes("scratchpad")
}

/** The `worktreeSetup` commands of `metamax.json` at `top`, or null when absent. */
export function readWorktreeSetup(top: string): string[] | null {
  try {
    const raw = JSON.parse(readFileSync(join(top, "metamax.json"), "utf-8")) as { worktreeSetup?: unknown }
    const cmds = raw?.worktreeSetup
    if (Array.isArray(cmds) && cmds.every((c) => typeof c === "string")) return cmds as string[]
  } catch {
    /* no manifest, or unparseable */
  }
  return null
}
