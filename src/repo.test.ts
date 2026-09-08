import { describe, test, expect } from "bun:test"
import { resolve } from "path"
import { tmpdir } from "os"
import { isLocalRemoteUrl, isScratchDir, readWorktreeSetup, gitRemoteUrl, gitTopLevel } from "./repo.ts"

describe("isLocalRemoteUrl", () => {
  const local = ["/srv/git/x.git", "../bare.git", "./bare", "~/repos/x", "file:///srv/x.git", "bare.git", "sub/dir/x.git"]
  for (const url of local) test(`local: ${url}`, () => expect(isLocalRemoteUrl(url)).toBe(true))

  const remote = [
    "git@github.com:worktron/x.git",
    "git@github.com-worktron:worktron/hall-pass.git",
    "https://github.com/worktron/x.git",
    "ssh://git@github.com/worktron/x.git",
    "git://example.com/x.git",
    "host:path/x.git",
  ]
  for (const url of remote) test(`remote: ${url}`, () => expect(isLocalRemoteUrl(url)).toBe(false))
})

describe("isScratchDir", () => {
  test("the OS temp directory and children", () => {
    expect(isScratchDir(tmpdir())).toBe(true)
    expect(isScratchDir(resolve(tmpdir(), "hall-pass-x", "repo"))).toBe(true)
  })
  test("/tmp and /private/tmp", () => {
    expect(isScratchDir("/tmp/x")).toBe(true)
    expect(isScratchDir("/private/tmp/claude-501/abc/scratchpad/repo")).toBe(true)
  })
  test("a scratchpad segment anywhere", () => {
    expect(isScratchDir("/Users/me/work/scratchpad/repo")).toBe(true)
  })
  test("an ordinary checkout is not scratch", () => {
    expect(isScratchDir("/Users/me/Workspace/hall-pass")).toBe(false)
    expect(isScratchDir("/Users/me/.metamax/worktrees/hall-pass/t11")).toBe(false)
    expect(isScratchDir("/Users/me/tmpfiles/repo")).toBe(false)
    expect(isScratchDir("/Users/me/my-scratchpad-notes/repo")).toBe(false)
  })
})

describe("readWorktreeSetup", () => {
  test("null where there is no metamax.json", () => {
    expect(readWorktreeSetup(tmpdir())).toBeNull()
  })
})

describe("git queries", () => {
  test("this checkout: top level and a push URL", () => {
    const here = resolve(import.meta.dir, "..")
    expect(gitTopLevel(here)).toBe(here.replace(/^\/private\//, "/"))
    const origin = gitRemoteUrl(here, "origin")
    expect(origin === null || typeof origin === "string").toBe(true)
  })
  test("null outside a repository and for an unknown remote", () => {
    expect(gitTopLevel(tmpdir())).toBeNull()
    expect(gitRemoteUrl(resolve(import.meta.dir, ".."), "no-such-remote")).toBeNull()
  })
})
