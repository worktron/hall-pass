import { describe, test, expect } from "bun:test"
import { checkGitCommand } from "./git.ts"

describe("checkGitCommand", () => {
  describe("read-only commands — should be safe", () => {
    const safe = [
      "git status",
      "git log --oneline -5",
      "git diff",
      "git diff --stat",
      "git diff HEAD~3",
      "git show HEAD",
      "git branch",
      "git branch -a",
      "git remote -v",
      "git rev-parse HEAD",
      "git log --oneline --all -- docs/",
      "git shortlog -sn",
      "git blame src/hook.ts",
      "git describe --tags",
      "git ls-files",
      "git ls-remote --heads origin",
      "git cat-file -p HEAD",
      "git reflog",
      "git config user.email",
      "git merge-base HEAD origin/main",
      "git check-ignore .env.local",
      "git grep -l -e PlacementField -e SheetColumn",
      "git grep -n TODO",
      "git show-ref",
      "git show-ref --heads",
      "git show-branch",
      "git for-each-ref refs/heads/",
      "git check-attr -a src/hook.ts",
      "git check-mailmap 'Anthony Yam <a@b.com>'",
      "git check-ref-format refs/heads/feat/x",
      "git diff-tree -r HEAD",
      "git diff-index HEAD",
      "git diff-files",
      "git range-diff main..feat/a main..feat/b",
      "git var GIT_AUTHOR_IDENT",
      "git help log",
      "git annotate src/hook.ts",
    ]

    for (const cmd of safe) {
      test(cmd, () => expect(checkGitCommand(cmd).safe).toBe(true))
    }
  })

  describe("safe local writes — should be safe", () => {
    const safe = [
      "git add .",
      "git add -A",
      "git add src/hook.ts src/parser.ts",
      "git commit -m 'feat: add feature'",
      'git commit -m "fix: something"',
      "git stash",
      "git stash pop",
      "git stash list",
      "git fetch",
      "git fetch origin",
      "git pull",
      "git pull --rebase",
      "git merge feature-branch",
      "git cherry-pick abc123",
      "git revert abc123",
      "git mv old.ts new.ts",
      "git am patch.mbox",
      "git format-patch -1 HEAD",
      "git archive --format=tar HEAD",
      "git bundle create repo.bundle --all",
      "git request-pull origin/main origin feat/x",
      // Safe branch deletion — git refuses to delete unmerged branches
      "git branch -d feat/old",
      "git branch --delete feat/old",
    ]

    for (const cmd of safe) {
      test(cmd, () => expect(checkGitCommand(cmd).safe).toBe(true))
    }
  })

  describe("push/rebase on feature branches — should be safe", () => {
    const safe = [
      "git push",
      "git push origin",
      "git push origin feat/search",
      "git push -u origin feat/search",
      "git push origin HEAD",
      "git rebase feat/other",
    ]

    for (const cmd of safe) {
      test(cmd, () => expect(checkGitCommand(cmd).safe).toBe(true))
    }
  })

  describe("push to protected branches — should prompt", () => {
    const dangerous = [
      "git push origin main",
      "git push origin master",
      "git push origin staging",
      "git push origin production",
      "git push origin HEAD:main",
    ]

    for (const cmd of dangerous) {
      test(cmd, () => expect(checkGitCommand(cmd).safe).toBe(false))
    }
  })

  describe("force push to feature branches — should be safe", () => {
    const safe = [
      "git push --force",
      "git push -f origin feat/search",
      "git push --force-with-lease",
      "git push --force-with-lease origin feat/search",
      "git push origin HEAD --force-with-lease",
      "git push origin HEAD --force",
    ]

    for (const cmd of safe) {
      test(cmd, () => expect(checkGitCommand(cmd).safe).toBe(true))
    }
  })

  describe("force push to protected branches — should prompt", () => {
    const dangerous = [
      "git push --force origin main",
      "git push -f origin main",
      "git push --force-with-lease origin main",
      "git push --force origin HEAD:main",
      "git push -f origin HEAD:staging",
    ]

    for (const cmd of dangerous) {
      test(cmd, () => expect(checkGitCommand(cmd).safe).toBe(false))
    }
  })

  describe("destructive operations — should prompt", () => {
    const dangerous = [
      // Reset
      "git reset --hard",
      "git reset --hard HEAD~3",
      "git reset --hard origin/main",
      // Clean
      "git clean -f",
      "git clean -fd",
      // Discard all changes
      "git checkout .",
      "git restore .",
      // Force-delete branch (loses unmerged commits)
      "git branch -D feat/old",
      "git branch --delete --force feat/old",
      // Stash destruction
      "git stash drop",
      "git stash clear",
    ]

    for (const cmd of dangerous) {
      test(cmd, () => expect(checkGitCommand(cmd).safe).toBe(false))
    }
  })

  describe("git with path prefix — should still work", () => {
    test("git -C /path status", () => {
      expect(checkGitCommand("git -C /some/path status").safe).toBe(true)
    })

    test("git -C /path push --force (feature branch)", () => {
      expect(checkGitCommand("git -C /some/path push --force").safe).toBe(true)
    })

    test("git -C /path push --force to main", () => {
      expect(checkGitCommand("git -C /some/path push --force origin main").safe).toBe(false)
    })

    test("git -C /path add .", () => {
      expect(checkGitCommand("git -C /some/path add .").safe).toBe(true)
    })

    test("git -C /path reset --hard", () => {
      expect(checkGitCommand("git -C /some/path reset --hard").safe).toBe(false)
    })
  })

  test("bare git — safe (shows help)", () => {
    expect(checkGitCommand("git").safe).toBe(true)
  })

  describe("accepts pre-parsed args array (from shfmt)", () => {
    test("safe: parsed git status", () => {
      expect(checkGitCommand(["git", "status"]).safe).toBe(true)
    })

    test("safe: parsed git push to feature branch", () => {
      expect(checkGitCommand(["git", "push", "-u", "origin", "feat/search"]).safe).toBe(true)
    })

    test("safe: parsed git push --force (feature branch)", () => {
      expect(checkGitCommand(["git", "push", "--force"]).safe).toBe(true)
    })

    test("unsafe: parsed git push --force to main", () => {
      expect(checkGitCommand(["git", "push", "--force", "origin", "main"]).safe).toBe(false)
    })

    test("unsafe: parsed git push to protected branch", () => {
      expect(checkGitCommand(["git", "push", "origin", "main"]).safe).toBe(false)
    })

    test("safe: parsed git commit with message", () => {
      expect(checkGitCommand(["git", "commit", "-m", "feat: add feature"]).safe).toBe(true)
    })

    test("unsafe: parsed git reset --hard", () => {
      expect(checkGitCommand(["git", "reset", "--hard"]).safe).toBe(false)
    })
  })

  describe("git config — should inspect for dangerous keys", () => {
    const safeConfigs = [
      "git config --list",
      "git config --get user.email",
      "git config user.email",
      "git config --get-regexp remote",
      "git config user.name 'My Name'",
    ]

    for (const cmd of safeConfigs) {
      test(`safe: ${cmd}`, () => expect(checkGitCommand(cmd).safe).toBe(true))
    }

    const dangerousConfigs = [
      `git config alias.x "!rm -rf /"`,
      `git config credential.helper "!evil"`,
      `git config core.fsmonitor "evil"`,
      `git config core.hooksPath /evil`,
      `git config core.sshCommand "evil"`,
      `git config filter.clean "evil"`,
    ]

    for (const cmd of dangerousConfigs) {
      test(`unsafe: ${cmd}`, () => expect(checkGitCommand(cmd).safe).toBe(false))
    }
  })

  describe("git -c config injection — should block dangerous configs", () => {
    const dangerous = [
      `git -c core.fsmonitor="rm -rf /" status`,
      `git -c core.sshCommand="evil" fetch`,
      `git -c core.hooksPath=/evil pull`,
      `git -c diff.external="evil" diff`,
      `git -c pager.log="evil" log`,
      `git -c alias.x="!evil" status`,
    ]

    for (const cmd of dangerous) {
      test(`unsafe: ${cmd}`, () => expect(checkGitCommand(cmd).safe).toBe(false))
    }

    test("safe: git -c color.ui=auto status", () => {
      expect(checkGitCommand("git -c color.ui=auto status").safe).toBe(true)
    })
  })
  describe("symbolic-ref — reads safe, writes prompt", () => {
    const safe = [
      "git symbolic-ref refs/remotes/origin/HEAD",
      "git symbolic-ref --short HEAD",
      "git symbolic-ref -q HEAD",
      "git symbolic-ref --short refs/remotes/origin/HEAD",
    ]
    for (const cmd of safe) {
      test(`safe: ${cmd}`, () => expect(checkGitCommand(cmd).safe).toBe(true))
    }

    const unsafe = [
      "git symbolic-ref HEAD refs/heads/other",
      "git symbolic-ref --delete HEAD",
      "git symbolic-ref -d refs/remotes/origin/HEAD",
    ]
    for (const cmd of unsafe) {
      test(`unsafe: ${cmd}`, () => expect(checkGitCommand(cmd).safe).toBe(false))
    }

    test("the /receive lookup is auto-approved", () => {
      expect(checkGitCommand("git symbolic-ref refs/remotes/origin/HEAD").safe).toBe(true)
    })
  })

  describe("config-supplied safe subcommands", () => {
    test("unknown subcommand prompts by default", () => {
      expect(checkGitCommand("git lfs ls-files").safe).toBe(false)
    })

    test("same subcommand is safe once added via config", () => {
      expect(checkGitCommand("git lfs ls-files", undefined, new Set(["lfs"])).safe).toBe(true)
    })

    test("config cannot override a destructive subcommand", () => {
      expect(checkGitCommand("git reset --hard", undefined, new Set(["reset"])).safe).toBe(false)
    })

    test("config cannot override protected-branch push gating", () => {
      expect(checkGitCommand("git push origin main", undefined, new Set(["push"])).safe).toBe(false)
    })
  })
})

// -- Repository-aware rules: core.hooksPath and pushes judged by the remote --
//
// Real repositories, because the rules read the repository: top level,
// remotes, metamax.json. Two homes: a temp directory (a throwaway by the
// push rule) and node_modules/.cache (not temp, so a GitHub remote there
// keeps the protected-branch rule).

import { beforeAll, afterAll } from "bun:test"
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "fs"
import { tmpdir } from "os"
import { resolve } from "path"

function sh(cwd: string, ...args: string[]): void {
  const r = Bun.spawnSync(args, { cwd, stdout: "ignore", stderr: "pipe" })
  if (r.exitCode !== 0) throw new Error(`${args.join(" ")} failed in ${cwd}: ${r.stderr.toString()}`)
}

function makeRepo(dir: string, origin: string | null, extra: (dir: string) => void = () => {}): string {
  mkdirSync(dir, { recursive: true })
  sh(dir, "git", "init", "-q")
  if (origin) sh(dir, "git", "remote", "add", "origin", origin)
  extra(dir)
  return dir
}

const scratch = mkdtempSync(resolve(tmpdir(), "hall-pass-repo-"))
const permanent = resolve(import.meta.dir, "..", "node_modules", ".cache", `hall-pass-repo-${process.pid}`)
const GITHUB = "git@github.com:worktron/example.git"

let bare: string          // a local bare repository, the origin of the local repos
let ghRepo: string        // GitHub origin, scripts/git-hooks, metamax.json naming it
let localRepo: string     // origin is the local bare directory
let customRepo: string    // GitHub origin, metamax.json sets tools/hooks
let tmpGhRepo: string     // GitHub origin but under a temp directory

beforeAll(() => {
  bare = resolve(scratch, "bare.git")
  mkdirSync(bare)
  sh(bare, "git", "init", "-q", "--bare")
  ghRepo = makeRepo(resolve(permanent, "gh"), GITHUB, (d) => {
    mkdirSync(resolve(d, "scripts", "git-hooks"), { recursive: true })
    mkdirSync(resolve(d, "src"))
    mkdirSync(resolve(d, "tools", "hooks"), { recursive: true })   // exists, but no manifest names it
    writeFileSync(resolve(d, "metamax.json"), JSON.stringify({ worktreeSetup: ["git config core.hooksPath scripts/git-hooks"] }))
  })
  localRepo = makeRepo(resolve(permanent, "local"), bare)
  customRepo = makeRepo(resolve(permanent, "custom"), GITHUB, (d) => {
    mkdirSync(resolve(d, "tools", "hooks"), { recursive: true })
    writeFileSync(resolve(d, "metamax.json"), JSON.stringify({ worktreeSetup: ["bun install", "git config --local core.hooksPath ./tools/hooks"] }))
  })
  tmpGhRepo = makeRepo(resolve(scratch, "gh"), GITHUB)
})

afterAll(() => {
  rmSync(scratch, { recursive: true, force: true })
  rmSync(permanent, { recursive: true, force: true })
})

describe("core.hooksPath — the repo's own hook directory is allowed, anything else stops", () => {
  test("git -c core.hooksPath=scripts/git-hooks commit passes in a repo that has it", () => {
    expect(checkGitCommand("git -c core.hooksPath=scripts/git-hooks commit -m x", undefined, undefined, { cwd: ghRepo })).toEqual({ safe: true })
  })

  test("git config core.hooksPath scripts/git-hooks passes", () => {
    expect(checkGitCommand("git config core.hooksPath scripts/git-hooks", undefined, undefined, { cwd: ghRepo }).safe).toBe(true)
  })

  test("--local and a ./ prefix and a trailing slash are the same directory", () => {
    expect(checkGitCommand("git config --local core.hooksPath ./scripts/git-hooks/", undefined, undefined, { cwd: ghRepo }).safe).toBe(true)
  })

  test("from a subdirectory the path is still relative to the top level", () => {
    expect(checkGitCommand("git config core.hooksPath scripts/git-hooks", undefined, undefined, { cwd: resolve(ghRepo, "src") }).safe).toBe(true)
  })

  test("-C picks the repository", () => {
    expect(checkGitCommand(`git -C ${ghRepo} config core.hooksPath scripts/git-hooks`, undefined, undefined, { cwd: scratch }).safe).toBe(true)
  })

  test("a directory metamax.json's worktreeSetup names is allowed", () => {
    expect(checkGitCommand("git config core.hooksPath tools/hooks", undefined, undefined, { cwd: customRepo }).safe).toBe(true)
    expect(checkGitCommand("git -c core.hooksPath=tools/hooks commit -m x", undefined, undefined, { cwd: customRepo }).safe).toBe(true)
  })

  const stops: Array<[string, string, () => string | undefined]> = [
    ["git config core.hooksPath /tmp/x", "an absolute path", () => ghRepo],
    ["git -c core.hooksPath=/tmp/x status", "an absolute path via -c", () => ghRepo],
    ["git -c core.hooksPath=/tmp/hooks commit -m x", "an absolute path on a commit", () => ghRepo],
    ["git config core.hooksPath ~/hooks", "a home-relative path", () => ghRepo],
    ["git config core.hooksPath ../scripts/git-hooks", "a path that escapes the repository", () => ghRepo],
    ["git config core.hooksPath scripts/nope", "a directory that does not exist", () => ghRepo],
    ["git config core.hooksPath tools/hooks", "a directory nothing names, even though it exists", () => ghRepo],
    ["git config core.hooksPath scripts/git-hooks", "the right path in a repo that lacks it", () => localRepo],
    ["git config core.hooksPath scripts/git-hooks", "the right path with no cwd", () => undefined],
    ["git config core.hooksPath scripts/git-hooks", "the right path outside any repository", () => scratch],
    ["git -C $DIR config core.hooksPath scripts/git-hooks", "a placeholder in -C", () => ghRepo],
    ["git config --global core.hooksPath scripts/git-hooks", "--global reaches every repository", () => ghRepo],
    ["git config --system core.hooksPath scripts/git-hooks", "--system reaches every repository", () => ghRepo],
    ["git config core.hooksPath $HOOKS", "a placeholder value", () => ghRepo],
    ["git config set core.hooksPath /tmp/x", "the git 2.46 set verb", () => ghRepo],
    ["git config set core.hooksPath scripts/nope", "the set verb with a missing directory", () => ghRepo],
    ["git -c core.hooksPath=scripts/git-hooks commit -m x", "no cwd at all", () => undefined],
  ]
  for (const [cmd, why, cwd] of stops) {
    test(`stops: ${cmd} (${why})`, () => {
      const d = checkGitCommand(cmd, undefined, undefined, { cwd: cwd() })
      expect(d.safe).toBe(false)
      if (!d.safe) {
        expect(d.hard).toBe(true)
        expect(d.reason).toMatch(/core\.hookspath/)
      }
    })
  }

  test("the set verb with the repo's own directory passes", () => {
    expect(checkGitCommand("git config set core.hooksPath scripts/git-hooks", undefined, undefined, { cwd: ghRepo }).safe).toBe(true)
  })

  test("the stop message says why", () => {
    const d = checkGitCommand("git config core.hooksPath scripts/nope", undefined, undefined, { cwd: ghRepo })
    expect(d.safe).toBe(false)
    if (!d.safe) expect(d.message).toContain("does not exist")
  })
})

describe("push to a protected branch name — protected is decided from the remote", () => {
  const passes: Array<[string, string, () => string]> = [
    ["git push origin main", "origin is a local bare directory", () => localRepo],
    ["git push origin HEAD:main", "HEAD:main to a local origin", () => localRepo],
    ["git push -u origin main", "-u to a local origin", () => localRepo],
    ["git push --force origin main", "force to a local origin", () => localRepo],
    ["git push -o ci.skip origin main", "a push option before the remote", () => localRepo],
    ["git push origin main", "a GitHub origin, but the repository is under a temp directory", () => tmpGhRepo],
    ["git push origin main", "from a subdirectory of the temp repository", () => resolve(tmpGhRepo, ".git")],
  ]
  for (const [cmd, why, cwd] of passes) {
    test(`passes: ${cmd} (${why})`, () => {
      expect(checkGitCommand(cmd, undefined, undefined, { cwd: cwd() })).toEqual({ safe: true })
    })
  }

  test("-C names the local repository from elsewhere", () => {
    expect(checkGitCommand(`git -C ${localRepo} push origin main`, undefined, undefined, { cwd: ghRepo }).safe).toBe(true)
  })

  test("an inline local path as the remote passes", () => {
    expect(checkGitCommand(`git push ${bare} main`, undefined, undefined, { cwd: ghRepo }).safe).toBe(true)
    expect(checkGitCommand(`git push ../bare.git HEAD:main`, undefined, undefined, { cwd: ghRepo }).safe).toBe(true)
  })

  const stops: Array<[string, string, () => string | undefined]> = [
    ["git push origin main", "origin is GitHub", () => ghRepo],
    ["git push origin HEAD:main", "HEAD:main to GitHub", () => ghRepo],
    ["git push origin staging", "staging on GitHub", () => ghRepo],
    ["git push -o ci.skip origin main", "a push option before a GitHub remote", () => ghRepo],
    ["git push --force origin main", "force to GitHub", () => ghRepo],
    ["git push origin main", "no cwd", () => undefined],
    ["git -C $CL push origin HEAD:main", "a placeholder in -C", () => localRepo],
    ["git push nosuch main", "a remote that does not exist", () => localRepo],
    ["git push origin main", "outside any repository", () => permanent],
    ["git push git@github.com:worktron/x.git main", "an inline GitHub URL", () => localRepo],
    ["git push https://github.com/worktron/x.git HEAD:main", "an inline https URL", () => localRepo],
    ["git push --repo=git@github.com:worktron/x.git origin main", "--repo overrides the remote", () => localRepo],
  ]
  for (const [cmd, why, cwd] of stops) {
    test(`stops: ${cmd} (${why})`, () => {
      const d = checkGitCommand(cmd, undefined, undefined, { cwd: cwd() })
      expect(d.safe).toBe(false)
      if (!d.safe) {
        expect(d.hard).toBe(true)
        expect(d.reason).toMatch(/push to protected branch/)
      }
    })
  }

  test("-C to the GitHub repository from a temp cwd still stops", () => {
    expect(checkGitCommand(`git -C ${ghRepo} push origin main`, undefined, undefined, { cwd: scratch }).safe).toBe(false)
  })

  test("a rebase onto main is unchanged: a judgment call, wherever the repository is", () => {
    const d = checkGitCommand("git rebase main", undefined, undefined, { cwd: localRepo })
    expect(d.safe).toBe(false)
    if (!d.safe) expect(d.hard).toBeUndefined()
  })

  test("a feature-branch push is safe without any lookup", () => {
    expect(checkGitCommand("git push origin feat/x", undefined, undefined, { cwd: ghRepo })).toEqual({ safe: true })
  })
})
