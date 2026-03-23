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
      "git cat-file -p HEAD",
      "git reflog",
      "git config user.email",
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
      // Delete branch
      "git branch -D feat/old",
      "git branch -d feat/old",
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
})
