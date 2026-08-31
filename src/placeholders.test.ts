/**
 * Shell expansions keep their argument slot.
 *
 * A word like `$CL` used to render as nothing and fall out of the argument
 * list, shifting everything after it: `git -C $CL fetch origin` was read as
 * `git -C fetch origin` (subcommand "origin" → prompt) and `git -C $D reset
 * --hard` as bare `git` (safe → allowed). Expansions now render as
 * placeholders — `$NAME`, `$(...)`, `$((...))` — so the shape survives.
 */
import { describe, test, expect } from "bun:test"
import { resolve } from "path"
import { existsSync } from "fs"
import { extractCommandInfos } from "./parser.ts"
import { checkGitCommand } from "./git.ts"
import { decide } from "./decide.ts"
import { loadConfig, type HallPassConfig } from "./config.ts"

const bundledShfmt = resolve(import.meta.dir, "..", "bin", "shfmt")
const shfmtBin = existsSync(bundledShfmt) ? bundledShfmt : "shfmt"

let _config: HallPassConfig | undefined
async function getConfig(): Promise<HallPassConfig> {
  return (_config ??= await loadConfig())
}

async function parse(command: string) {
  const proc = Bun.spawn([shfmtBin, "-ln", "bash", "--tojson"], { stdin: new Response(command), stdout: "pipe", stderr: "pipe" })
  const out = await new Response(proc.stdout).text()
  await proc.exited
  return extractCommandInfos(JSON.parse(out))
}

async function run(command: string, mode = "default") {
  return decide("Bash", { command }, { config: await getConfig(), shfmtBin, debug: () => {}, audit: { log() {}, event() {} }, mode })
}

describe("parser: expansions render as placeholders", () => {
  test("bare parameter", async () => {
    const [git] = await parse("git -C $CL fetch origin --quiet")
    expect(git!.args).toEqual(["git", "-C", "$CL", "fetch", "origin", "--quiet"])
  })

  test("quoted parameter, braces, defaults", async () => {
    const [git] = await parse('git -C "$d" config --get remote.origin.url')
    expect(git!.args).toEqual(["git", "-C", "$d", "config", "--get", "remote.origin.url"])
    const [echo] = await parse('echo ${BASE:-main} "$@" $1')
    expect(echo!.args).toEqual(["echo", "$BASE", "$@", "$1"])
  })

  test("mixed literal and expansion stays one word", async () => {
    const [echo] = await parse('echo "pre-$V-post" HEAD:$BRANCH')
    expect(echo!.args).toEqual(["echo", "pre-$V-post", "HEAD:$BRANCH"])
  })

  test("command and arithmetic substitutions", async () => {
    const [echo] = await parse("echo $(date) $((1 + 2))")
    expect(echo!.args).toEqual(["echo", "$(...)", "$((...))"])
  })

  test("a command whose NAME is an expansion is reported, not dropped", async () => {
    const infos = await parse("$PYTHON script.py")
    expect(infos.map((c) => c.name)).toEqual(["$PYTHON"])
  })
})

describe("git: -C with a variable path keeps the real subcommand", () => {
  test("fetch through -C $VAR is safe", () => {
    expect(checkGitCommand(["git", "-C", "$CL", "fetch", "origin", "--quiet"]).safe).toBe(true)
  })

  test("config --get through -C $VAR is safe", () => {
    expect(checkGitCommand(["git", "-C", "$d", "config", "--get", "remote.origin.url"]).safe).toBe(true)
  })

  test("remote get-url through -C $VAR is safe", () => {
    expect(checkGitCommand(["git", "-C", "$d", "remote", "get-url", "origin"]).safe).toBe(true)
  })

  test("reset --hard through -C $VAR is NOT safe (it used to read as bare git)", () => {
    const d = checkGitCommand(["git", "-C", "$D", "reset", "--hard"])
    expect(d.safe).toBe(false)
    if (!d.safe) expect(d.reason).toBe("git: destructive subcommand reset")
  })

  test("push to a protected branch through -C $VAR is caught, as a hard stop", () => {
    const d = checkGitCommand(["git", "-C", "$CL", "push", "origin", "HEAD:staging"])
    expect(d.safe).toBe(false)
    if (!d.safe) {
      expect(d.reason).toBe("git: push to protected branch staging")
      expect(d.hard).toBe(true)
    }
  })

  test("push to $BRANCH is a feature-branch push", () => {
    expect(checkGitCommand(["git", "push", "origin", "$BRANCH"]).safe).toBe(true)
    expect(checkGitCommand(["git", "push", "origin", "HEAD:$BRANCH"]).safe).toBe(true)
  })

  test("push $LOCAL:main is still a push to main", () => {
    expect(checkGitCommand(["git", "push", "origin", "$LOCAL:main"]).safe).toBe(false)
  })

  test("symbolic-ref HEAD $REF is a write", () => {
    expect(checkGitCommand(["git", "symbolic-ref", "HEAD", "$REF"]).safe).toBe(false)
  })
})

describe("git: subcommands that stopped prompting", () => {
  for (const cmd of [
    "git rm --cached --ignore-unmatch a.db-wal a.db-shm",
    "git rm -r -q src/importers",
    "git apply /tmp/fix.patch",
    "git init",
    "git clone https://github.com/x/y.git",
    "git merge-tree --write-tree main feature",
    "git hash-object -w file.txt",
  ]) {
    test(`safe: ${cmd}`, () => {
      expect(checkGitCommand(cmd).safe).toBe(true)
    })
  }

  for (const cmd of ["git filter-repo --path x", "git remote set-url origin git@evil:x.git", "git credential-osxkeychain get"]) {
    test(`still prompts: ${cmd}`, () => {
      expect(checkGitCommand(cmd).safe).toBe(false)
    })
  }
})

describe("end to end", () => {
  test("git -C $CL fetch origin --quiet allows", async () => {
    expect((await run("git -C $CL fetch origin --quiet")).decision).toBe("allow")
  })

  test("the remote-sweep loop allows", async () => {
    const d = await run('for d in */; do u=$(git -C "$d" config --get remote.origin.url 2>/dev/null) || continue; echo "$d $u"; done')
    expect(d.decision).toBe("allow")
  })

  test("sed -i on a variable target prompts (target unverifiable)", async () => {
    const d = await run("sed -i 's/a/b/' $FILE")
    expect(d.decision).toBe("ask")
    if (d.decision === "ask") expect(d.reason).toBe("sed: -i with unverifiable target")
  })

  test("sed -i on a literal unprotected file still allows", async () => {
    expect((await run("sed -i 's/a/b/' notes.txt")).decision).toBe("allow")
  })

  test("xargs $CMD no longer counts as xargs' default echo", async () => {
    const d = await run("ls | xargs $CMD")
    expect(d.decision).toBe("pass")
  })
})
