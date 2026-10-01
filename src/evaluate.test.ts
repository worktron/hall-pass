/**
 * The two operand-judged rules in evaluate.ts: `rm` allowed when every
 * target is inside a throwaway root, and `bash <file>` (sh, zsh) allowed
 * when the file is one the repository at the hook's cwd tracks. Every
 * other rm and script keeps the prompt it had, with the same message.
 */
import { describe, test, expect, afterAll } from "bun:test"
import { resolve } from "path"
import { existsSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "fs"
import { tmpdir } from "os"
import { evaluateBashCommand, createEvalContext, type EvalResult } from "./evaluate.ts"
import { decide } from "./decide.ts"
import type { CommandInfo } from "./parser.ts"
import type { HallPassConfig } from "./config.ts"

const bundledShfmt = resolve(import.meta.dir, "..", "bin", "shfmt")
const shfmtBin = existsSync(bundledShfmt) ? bundledShfmt : "shfmt"

/** No safe_scripts, so a script passes only through the tracked-file rule. */
const TEST_CONFIG: HallPassConfig = {
  commands: { safe: [], db_clients: [], safe_scripts: [] },
  git: { protected_branches: [], safe_subcommands: [] },
  paths: { protected: [], read_only: [], no_delete: [] },
  audit: { enabled: false, path: "" },
  classifier: { defer: true },
  codex: { deny_hard_stops: true },
  debug: { enabled: false },
}

function cmd(name: string, ...rest: string[]): CommandInfo {
  return { name, args: [name, ...rest], assigns: [] }
}

function judge(cmdInfo: CommandInfo, cwd?: string): EvalResult {
  return evaluateBashCommand(cmdInfo, createEvalContext(TEST_CONFIG, [], shfmtBin, cwd))
}

/** The whole command line through decide(), the way the hook judges it. */
async function judgeLine(command: string, cwd?: string) {
  return decide("Bash", { command }, { config: TEST_CONFIG, shfmtBin, debug: () => {}, audit: { log() {}, event() {} }, cwd })
}

function sh(cwd: string, ...args: string[]): void {
  const r = Bun.spawnSync(args, { cwd, stdout: "ignore", stderr: "pipe" })
  if (r.exitCode !== 0) throw new Error(`${args.join(" ")} failed: ${r.stderr.toString()}`)
}

// A repository fixture that is NOT under a temp directory, so a relative rm
// there is judged against a real project path. It tracks scripts/ship-gates.sh
// and scripts/x.sh, leaves untracked.sh out of the index, tracks a symlink
// scripts/away.sh that points out of the tree, and has ../outside.sh beside it.
const home = resolve(import.meta.dir, "..", "node_modules", ".cache", `hall-pass-evaluate-${process.pid}`)
const repo = resolve(home, "repo")
mkdirSync(resolve(repo, "scripts"), { recursive: true })
sh(repo, "git", "init", "-q")
writeFileSync(resolve(repo, "scripts", "ship-gates.sh"), "#!/bin/sh\necho gates\n")
writeFileSync(resolve(repo, "scripts", "x.sh"), "#!/bin/sh\necho x\n")
writeFileSync(resolve(repo, "untracked.sh"), "#!/bin/sh\necho untracked\n")
writeFileSync(resolve(home, "outside.sh"), "#!/bin/sh\necho outside\n")
symlinkSync(resolve(home, "outside.sh"), resolve(repo, "scripts", "away.sh"))
sh(repo, "git", "add", "scripts/ship-gates.sh", "scripts/x.sh", "scripts/away.sh")

afterAll(() => rmSync(home, { recursive: true, force: true }))

describe("rm judged by its targets", () => {
  const scratchpad = "/private/tmp/claude-501/-Users-me-proj/7a8c79ec/scratchpad"

  test("rm -f <scratchpad>/dbg.test.ts → allow", () => {
    expect(judge(cmd("rm", "-f", `${scratchpad}/dbg.test.ts`))).toEqual({ decision: "allow", reason: "rm: throwaway paths" })
  })

  test("rm /tmp/edit.1.py after the command that wrote it → allow, the whole line", async () => {
    const line = "cat > /tmp/edit.1.py <<'EOF'\nprint('hi')\nEOF\npython3 /tmp/edit.1.py && rm /tmp/edit.1.py"
    expect(await judgeLine(line)).toEqual({ decision: "allow", reason: "all commands safe" })
    expect(judge(cmd("rm", "/tmp/edit.1.py")).decision).toBe("allow")
  })

  test("rm -rf $TMPDIR/build → allow when the hook has a TMPDIR", () => {
    const saved = process.env.TMPDIR
    process.env.TMPDIR = saved || tmpdir()
    try {
      expect(judge(cmd("rm", "-rf", "$TMPDIR/build")).decision).toBe("allow")
      expect(judge(cmd("rm", "-rf", "$TMPDIR")).decision).toBe("prompt")   // the root itself
    } finally {
      if (saved === undefined) delete process.env.TMPDIR
      else process.env.TMPDIR = saved
    }
  })

  test("rm -rf $TMPDIR/build → prompt when the hook has no TMPDIR to read it with", () => {
    const saved = process.env.TMPDIR
    delete process.env.TMPDIR
    try {
      expect(judge(cmd("rm", "-rf", "$TMPDIR/build")).decision).toBe("prompt")
    } finally {
      if (saved !== undefined) process.env.TMPDIR = saved
    }
  })

  test("-r, -f, --, a trailing slash, a scratchpad outside /tmp, a relative path from a scratch cwd → allow", () => {
    expect(judge(cmd("rm", "-r", "-f", "--", "/tmp/build/")).decision).toBe("allow")
    expect(judge(cmd("rm", "-rf", "/var/folders/g5/abc/T/x")).decision).toBe("allow")
    expect(judge(cmd("rm", "/Users/me/work/scratchpad/notes.md")).decision).toBe("allow")
    expect(judge(cmd("rm", "-rf", "build"), "/tmp/throwaway-project").decision).toBe("allow")
    expect(judge(cmd("rm", "/tmp/a", "/tmp/b")).decision).toBe("allow")
  })

  const asks: Array<[string, string[]]> = [
    ["rm -rf ~/x", ["-rf", "~/x"]],
    ["rm -rf /tmp", ["-rf", "/tmp"]],
    ["rm -rf /tmp/", ["-rf", "/tmp/"]],
    ["rm -rf /var/folders", ["-rf", "/var/folders"]],
    ["rm -rf /Users/me/work/scratchpad", ["-rf", "/Users/me/work/scratchpad"]],
    ["rm -rf", ["-rf"]],
    ["rm -rf /", ["-rf", "/"]],
    ["rm /tmp/../etc/hosts", ["/tmp/../etc/hosts"]],
    ["rm *.log", ["*.log"]],
    ["rm /tmp/*.log", ["/tmp/*.log"]],
    ["rm /tmp/{a,b}", ["/tmp/{a,b}"]],
    ["rm -rf $DIR/build", ["-rf", "$DIR/build"]],
    ["rm -rf /tmp/x /home/y", ["-rf", "/tmp/x", "/home/y"]],
    ["rm -rf /Users/me/Workspace/proj/build", ["-rf", "/Users/me/Workspace/proj/build"]],
  ]
  for (const [label, args] of asks) {
    test(`${label} → prompt, with the dangerous-command message`, () => {
      const result = judge(cmd("rm", ...args), repo)
      expect(result).toEqual({ decision: "prompt", reason: "dangerous: rm", message: `"rm" is a destructive command` })
    })
  }

  test("a relative target with no cwd cannot be placed → prompt", () => {
    expect(judge(cmd("rm", "-rf", "build")).decision).toBe("prompt")
  })

  test("a relative target from a project cwd → prompt", () => {
    expect(judge(cmd("rm", "-rf", "build"), repo).decision).toBe("prompt")
  })

  test("a symlink under /tmp that points out of it → prompt", () => {
    const dir = mkdtempSync(resolve(tmpdir(), "hall-pass-rm-"))
    const link = resolve(dir, "away")
    symlinkSync(home, link)
    try {
      expect(judge(cmd("rm", "-rf", link)).decision).toBe("prompt")
      expect(judge(cmd("rm", "-rf", resolve(dir, "real"))).decision).toBe("allow")
    } finally {
      rmSync(dir, { recursive: true, force: true })
    }
  })

  test("a protected path under /tmp keeps the hard stop", () => {
    const config: HallPassConfig = { ...TEST_CONFIG, paths: { protected: ["**/.ssh/**"], read_only: [], no_delete: [] } }
    const result = evaluateBashCommand(cmd("rm", "/tmp/x/.ssh/id_rsa"), createEvalContext(config, [], shfmtBin))
    expect(result.decision).toBe("prompt")
    if (result.decision === "prompt") expect(result.hard).toBe(true)
  })

  test("rm reached through xargs, find -exec, and sudo keeps its prompt", async () => {
    expect((await judgeLine("echo /tmp | xargs rm -rf")).decision).toBe("ask")
    expect((await judgeLine("find /tmp -name '*.log' -exec rm -rf {} \;")).decision).toBe("ask")
    expect((await judgeLine("sudo rm -rf /tmp/x")).decision).toBe("ask")
  })
})

describe("rm reads a variable the same line set", () => {
  const S = "/private/tmp/claude-501/-Users-me-proj/7a8c79ec/scratchpad/mt2"
  const ALLOW = { decision: "allow", reason: "all commands safe" } as const
  const ASK = { decision: "ask", reason: "dangerous: rm", message: `"rm" is a destructive command` } as const

  const allows: string[] = [
    `S=${S}; rm -rf $S; mkdir -p $S`,
    `S=${S}; rm -rf "$S"`,
    `S=${S}; rm -rf \${S}`,
    `S=${S}; rm -rf $S/sub/path "\${S}/other"`,
    `S='${S}'; rm -rf "$S"`,
    `S=${S}\nrm -rf $S`,
    `S=${S}; timeout 5 rm -rf $S`,
    `S=${S}; if [ -d $S ]; then rm -rf $S; fi`,
    `S=${S}; for i in 1 2; do rm -rf $S; done`,
    `A=/tmp/a B=${S}; rm -rf $A $B`,
    `S=${S}; rm -rf $S; $S/cat x`,
    `S=${S}; rm -rf $S; mkdir -p $S; "$S"/cat x`,
  ]
  for (const line of allows) {
    test(`${JSON.stringify(line)} → allow`, async () => {
      expect(await judgeLine(line, repo)).toEqual(ALLOW)
    })
  }

  const asks: Array<[string, string]> = [
    ["reassigned later", `S=${S}; S=/Users/me; rm -rf $S`],
    ["reassigned after the rm", `S=${S}; rm -rf $S; S=/Users/me`],
    ["assigned in an && chain", `true && S=${S}; rm -rf $S`],
    ["assigned in an || chain", `S=${S} || S=/Users/me; rm -rf $S`],
    ["assigned only in an if", `if true; then S=${S}; fi; rm -rf $S`],
    ["also assigned in an if", `S=${S}; if true; then S=/Users/me; fi; rm -rf $S`],
    ["also assigned in a subshell", `S=${S}; (S=/Users/me); rm -rf $S`],
    ["also assigned in a function", `S=${S}; f() { S=/Users/me; }; f; rm -rf $S`],
    ["local in a function", `S=${S}; f() { local S=/Users/me; rm -rf $S; }; f`],
    ["prefix-assigned on the rm", `S=${S} rm -rf $S`],
    ["prefix-assigned on another command", `S=${S} true; rm -rf $S`],
    ["also prefix-assigned elsewhere", `S=${S}; S=/Users/me env; rm -rf $S`],
    ["read before it is assigned", `rm -rf $S; S=${S}`],
    ["a function body written before the assignment", `f() { rm -rf $S; }; S=${S}; f`],
    ["non-scratch value", `S=/Users/me/work; rm -rf $S`],
    ["the scratch root itself", `S=/tmp; rm -rf $S`],
    ["value with an expansion", `S=$HOME/x; rm -rf $S`],
    ["value with a command substitution", `S=$(mktemp -d); rm -rf $S`],
    ["relative value", `S=build; rm -rf $S`],
    ["tilde value", `S=~/x; rm -rf $S`],
    ["value with a space", `S="/tmp/a b"; rm -rf $S`],
    ["value with a glob", `S='/tmp/*'; rm -rf $S`],
    ["empty value", `S=; rm -rf $S/`],
    ["value that climbs out", `S=/tmp/../Users/me; rm -rf $S`],
    ["appended to", `S=${S}; S+=/../../..; rm -rf $S`],
    ["backgrounded assignment", `S=${S} & rm -rf $S`],
    ["\${S:-x} default", `S=${S}; rm -rf \${S:-/Users/me}`],
    ["\${S:=x} assigns", `S=${S}; echo \${S:=/Users/me}; rm -rf $S`],
    ["single-quoted $S is literal text", `S=${S}; rm -rf '$S'`],
    ["for S in", `S=${S}; for S in /Users/me; do :; done; rm -rf $S`],
    ["read S", `S=${S}; read S < /dev/null; rm -rf $S`],
    ["printf -v S", `S=${S}; printf -v S /Users/me; rm -rf $S`],
    ["printf -vS", `S=${S}; printf -vS /Users/me; rm -rf $S`],
    ["export S=", `S=${S}; export S=/Users/me; rm -rf $S`],
    ["declare -n nameref", `S=${S}; declare -n r=S; r=/Users/me; rm -rf $S`],
    ["unset S", `S=${S}; unset S; rm -rf $S/x`],
    ["arithmetic assignment", `S=${S}; ((S=1)); rm -rf $S`],
    ["let", `S=${S}; let S=1; rm -rf $S`],
    ["[[ arithmetic ]] assignment", `S=${S}; [[ 1 -eq S=1 ]]; rm -rf $S`],
    ["eval anywhere", `S=${S}; eval "$X"; rm -rf $S`],
    ["trap anywhere", `S=${S}; trap 'S=/Users/me' DEBUG; rm -rf $S`],
    ["command eval", `S=${S}; command eval "$X"; rm -rf $S`],
    ["eval spelled as a brace expansion", `S=${S}; {eval,S=/Users/me}; rm -rf $S`],
    ["an expanded command name", `S=${S}; $Y; rm -rf $S`],
    ["eval through a variable", `X=eval; S=${S}; $X 'S=/Users/me'; rm -rf $S`],
    ["eval split out of $X/foo", `X='eval S=/Users/me #'; S=${S}; $X/foo; rm -rf $S`],
    ["a path command through a variable assigned twice", `P=/bin; P=/x; S=${S}; $P/foo; rm -rf $S`],
    ["eval spelled as a glob", `S=${S}; touch eval; [e]val S=/Users/me; rm -rf $S`],
    ["PWD reassigned, then cd", `PWD=${S}; cd /Users/me; rm -rf $PWD`],
    ["IFS reassigned", `IFS=/; S=${S}; rm -rf $S`],
    ["one target resolves, another does not", `S=${S}; rm -rf $S $T`],
  ]
  for (const [label, line] of asks) {
    test(`${label}: ${JSON.stringify(line)} → prompt`, async () => {
      expect(await judgeLine(line, repo)).toEqual(ASK)
    })
  }

  test("a script run through the variable leaves the rm judged as written out", async () => {
    // loop.sh is a script hall-pass does not know: no opinion, as when typed out.
    const typed = await judgeLine(`rm -rf ${S}; ${S}/loop.sh a`, repo)
    expect(typed).toEqual({ decision: "pass", reason: "pipeline contains unknown commands" })
    expect(await judgeLine(`S=${S}; rm -rf $S; $S/loop.sh a`, repo)).toEqual(typed)
    expect(await judgeLine(`S=${S}; rm -rf $S; mkdir -p $S; $S/loop.sh a b`, repo)).toEqual(typed)
  })

  test("a variable rm resolves stays a placeholder for every other rule", () => {
    expect(judge(cmd("rm", "-rf", "$S"), repo).decision).toBe("prompt")
  })
})

describe("a shell judged by the repository script it runs", () => {
  test("bash scripts/ship-gates.sh inside a repository that tracks it → allow", () => {
    expect(judge(cmd("bash", "scripts/ship-gates.sh"), repo)).toEqual({ decision: "allow", reason: "bash: repository script scripts/ship-gates.sh" })
  })

  test("sh scripts/x.sh → allow; zsh too; with arguments and shell flags too", () => {
    expect(judge(cmd("sh", "scripts/x.sh"), repo).decision).toBe("allow")
    expect(judge(cmd("zsh", "scripts/x.sh"), repo).decision).toBe("allow")
    expect(judge(cmd("bash", "scripts/ship-gates.sh", "--post-rebase"), repo).decision).toBe("allow")
    expect(judge(cmd("bash", "-x", "-e", "scripts/x.sh"), repo).decision).toBe("allow")
  })

  test("an absolute path to the tracked file, and a cwd below the top level → allow", () => {
    expect(judge(cmd("bash", resolve(repo, "scripts", "x.sh")), repo).decision).toBe("allow")
    expect(judge(cmd("bash", "x.sh"), resolve(repo, "scripts")).decision).toBe("allow")
    expect(judge(cmd("bash", "./x.sh"), resolve(repo, "scripts")).decision).toBe("allow")
  })

  test("the whole line through decide(): bash scripts/ship-gates.sh → allow", async () => {
    expect(await judgeLine("bash scripts/ship-gates.sh", repo)).toEqual({ decision: "allow", reason: "all commands safe" })
  })

  const scriptPrompt = (shell: string) => ({ decision: "prompt", reason: `${shell}: script execution`, message: `Running "${shell}" with a script file` })

  test("bash /tmp/x.sh → prompt (outside the repository)", () => {
    expect(judge(cmd("bash", "/tmp/x.sh"), repo)).toEqual(scriptPrompt("bash"))
  })

  test("bash untracked.sh → prompt (in the tree, not tracked)", () => {
    expect(judge(cmd("bash", "untracked.sh"), repo)).toEqual(scriptPrompt("bash"))
    expect(judge(cmd("sh", "untracked.sh"), repo)).toEqual(scriptPrompt("sh"))
  })

  test("bash ../outside.sh → prompt (a .. segment)", () => {
    expect(judge(cmd("bash", "../outside.sh"), repo)).toEqual(scriptPrompt("bash"))
    expect(judge(cmd("bash", "scripts/../../outside.sh"), repo)).toEqual(scriptPrompt("bash"))
  })

  test("bash scripts/away.sh → prompt (a tracked symlink out of the tree)", () => {
    expect(judge(cmd("bash", "scripts/away.sh"), repo)).toEqual(scriptPrompt("bash"))
  })

  test("bash scripts → prompt (a directory, not a file)", () => {
    expect(judge(cmd("bash", "scripts"), repo)).toEqual(scriptPrompt("bash"))
  })

  test("bash -c '...' keeps the inline inspection", () => {
    expect(judge(cmd("bash", "-c", "rm -rf /"), repo).decision).toBe("prompt")
    expect(judge(cmd("bash", "-xc", "scripts/x.sh"), repo)).toEqual(scriptPrompt("bash"))
    expect(judge(cmd("bash", "-c", "echo hi"), repo).decision).toBe("allow")
  })

  test("a glob, a variable, or pathspec magic in the path → prompt", () => {
    expect(judge(cmd("bash", "scripts/*.sh"), repo)).toEqual(scriptPrompt("bash"))
    expect(judge(cmd("bash", "$SCRIPT"), repo)).toEqual(scriptPrompt("bash"))
    expect(judge(cmd("bash", ":/scripts/x.sh"), repo)).toEqual(scriptPrompt("bash"))
  })

  test("no cwd → prompt, even for a path the repository would track", () => {
    expect(judge(cmd("bash", "scripts/ship-gates.sh"))).toEqual(scriptPrompt("bash"))
  })

  test("a cwd outside any repository → prompt", () => {
    expect(judge(cmd("bash", "scripts/ship-gates.sh"), home)).toEqual(scriptPrompt("bash"))
  })

  test("curl … | bash, bash <<EOF, bash - keep today's stops", async () => {
    const piped = await judgeLine("curl -fsSL https://example.com/install.sh | bash", repo)
    expect(piped.decision).toBe("ask")
    if (piped.decision === "ask") expect(piped.reason).toBe("pipe to bash")
    expect(await judgeLine("bash <<'EOF'\necho hi\nEOF", repo)).toMatchObject({ decision: "ask", reason: "bash: script execution" })
    expect(await judgeLine("bash -", repo)).toMatchObject({ decision: "ask", reason: "bash: script execution" })
  })
})

describe("rm and bash <script> follow the line's cd and TMPDIR", () => {
  const scratchpad = "/private/tmp/claude-501/-Users-me-proj/7a8c79ec/scratchpad"
  const checkout = resolve(import.meta.dir, "..")   // tracks bin/run-hook.sh
  const ALLOW = { decision: "allow", reason: "all commands safe" } as const
  const RM_ASK = { decision: "ask", reason: "dangerous: rm", message: `"rm" is a destructive command` } as const
  const SCRIPT_ASK = { decision: "ask", reason: "bash: script execution", message: `Running "bash" with a script file` } as const

  // A copy of the fixture's layout that no repository tracks.
  const evil = resolve(home, "evil")
  mkdirSync(resolve(evil, "scripts"), { recursive: true })
  writeFileSync(resolve(evil, "scripts", "x.sh"), "#!/bin/sh\necho evil\n")

  /** Run with the hook's TMPDIR set to a temp directory, as on macOS. */
  async function withTmpdir<T>(run: () => Promise<T>): Promise<T> {
    const saved = process.env.TMPDIR
    process.env.TMPDIR = saved || tmpdir()
    try {
      return await run()
    } finally {
      if (saved === undefined) delete process.env.TMPDIR
      else process.env.TMPDIR = saved
    }
  }

  test("cd ~/Workspace/hall-pass && rm -rf src from a scratchpad → prompt; rm -rf src alone → allow", async () => {
    expect(await judgeLine("cd ~/Workspace/hall-pass && rm -rf src", scratchpad)).toEqual(RM_ASK)
    expect(await judgeLine(`cd ${repo} && rm -rf src`, scratchpad)).toEqual(RM_ASK)
    expect(await judgeLine("rm -rf src", scratchpad)).toEqual(ALLOW)
  })

  test("cd /private/tmp/evil && bash bin/run-hook.sh from the checkout → prompt; bash bin/run-hook.sh alone → allow", async () => {
    expect(await judgeLine("cd /private/tmp/evil && bash bin/run-hook.sh", checkout)).toEqual(SCRIPT_ASK)
    expect(await judgeLine(`cd ${evil} && bash scripts/x.sh`, repo)).toEqual(SCRIPT_ASK)
    expect(await judgeLine("bash bin/run-hook.sh", checkout)).toEqual(ALLOW)
  })

  test("TMPDIR=$HOME; rm -rf $TMPDIR/Documents → prompt; rm -rf $TMPDIR/Documents alone → allow", async () => {
    await withTmpdir(async () => {
      expect(await judgeLine("TMPDIR=$HOME; rm -rf $TMPDIR/Documents", scratchpad)).toEqual(RM_ASK)
      expect(await judgeLine("rm -rf $TMPDIR/Documents", scratchpad)).toEqual(ALLOW)
      expect(await judgeLine("rm -rf ${TMPDIR}/Documents", scratchpad)).toEqual(ALLOW)
    })
  })

  const tmpdirWrites: [string, string][] = [
    ["export", "export TMPDIR=$HOME; rm -rf $TMPDIR/Documents"],
    ["prefix assignment", "TMPDIR=$HOME rm -rf $TMPDIR/Documents"],
    ["read", "read TMPDIR; rm -rf $TMPDIR/Documents"],
    ["for loop", "for TMPDIR in $HOME; do rm -rf $TMPDIR/Documents; done"],
    ["assigning expansion", "echo ${TMPDIR:=$HOME}; rm -rf $TMPDIR/Documents"],
    ["a writer whose target the text does not show", "declare $V=$HOME; rm -rf $TMPDIR/Documents"],
    ["inside bash -c", "bash -c 'TMPDIR=$HOME; rm -rf $TMPDIR/Documents'"],
    ["around bash -c", "TMPDIR=$HOME bash -c 'rm -rf $TMPDIR/Documents'"],
    ["inside eval", "eval 'TMPDIR=$HOME; rm -rf $TMPDIR/Documents'"],
  ]
  for (const [label, line] of tmpdirWrites) {
    test(`TMPDIR written by ${label}: ${JSON.stringify(line)} → prompt`, async () => {
      await withTmpdir(async () => {
        expect((await judgeLine(line, scratchpad)).decision).toBe("ask")
      })
    })
  }

  const moves: [string, string][] = [
    ["inside bash -c", "bash -c 'cd ~/Workspace/hall-pass && rm -rf src'"],
    ["inside eval", "eval 'cd ~/Workspace/hall-pass; rm -rf src'"],
    ["in a subshell", "(cd ~/Workspace/hall-pass; rm -rf src)"],
    ["in a command substitution", "x=$(cd ~/Workspace/hall-pass && rm -rf src)"],
    ["after pushd", "pushd ~/Workspace/hall-pass && rm -rf src"],
    ["after builtin cd", "builtin cd ~/Workspace/hall-pass && rm -rf src"],
    ["through find -execdir", "find ~/Workspace -name x -execdir rm -rf src \;"],
    ["after cd to a variable", "cd $D && rm -rf build"],
    ["after a relative cd", "cd sub && rm -rf build"],
    ["after cd -", "cd - && rm -rf build"],
    ["after popd", "popd && rm -rf build"],
    ["after a bare cd", "cd && rm -rf build"],
  ]
  for (const [label, line] of moves) {
    test(`a relative rm ${label}: ${JSON.stringify(line)} → prompt`, async () => {
      expect(await judgeLine(line, scratchpad)).toEqual(RM_ASK)
    })
  }

  test("cd <scratchpad> && rm -rf out from a project → allow: a leading cd chain runs only there", async () => {
    expect(await judgeLine(`cd ${scratchpad} && rm -rf out`, repo)).toEqual(ALLOW)
    expect(await judgeLine(`cd ${scratchpad}/ && rm -rf out && mkdir out`, repo)).toEqual(ALLOW)
    expect(await judgeLine(`cd ${scratchpad} && cd ${scratchpad}/a && rm -rf out`, repo)).toEqual(ALLOW)
  })

  test("a variable the line set to a scratchpad path places the cd", async () => {
    expect(await judgeLine(`S=${scratchpad}; cd $S && rm -rf out`, scratchpad)).toEqual(ALLOW)
  })

  test("cd <scratchpad> without a clean && chain, from a project → prompt: rm may run in the project", async () => {
    expect(await judgeLine(`cd ${scratchpad}; rm -rf out`, repo)).toEqual(RM_ASK)
    expect(await judgeLine(`cd ${scratchpad} || true; rm -rf out`, repo)).toEqual(RM_ASK)
    expect(await judgeLine(`cd ${scratchpad} && true || rm -rf out`, repo)).toEqual(RM_ASK)
    expect(await judgeLine(`! cd ${scratchpad} && rm -rf out`, repo)).toEqual(RM_ASK)
    expect(await judgeLine(`rm -rf out; cd ${scratchpad}`, repo)).toEqual(RM_ASK)
  })

  test("cd <scratchpad>; rm -rf out from that scratchpad → allow: every place is a scratchpad", async () => {
    expect(await judgeLine(`cd ${scratchpad}/a; rm -rf out`, scratchpad)).toEqual(ALLOW)
  })

  test("an absolute rm target does not move with a cd", async () => {
    expect(await judgeLine(`cd ${repo} && rm -rf ${scratchpad}/out`, repo)).toEqual(ALLOW)
  })

  test("cd <repo> && bash scripts/x.sh → allow; the same from another repository's cwd needs both to track it", async () => {
    expect(await judgeLine(`cd ${repo} && bash scripts/x.sh`, scratchpad)).toEqual(ALLOW)
    expect(await judgeLine(`cd ${repo}; bash scripts/x.sh`, repo)).toEqual(ALLOW)
    expect(await judgeLine(`cd ${repo}; bash scripts/x.sh`, evil)).toEqual(SCRIPT_ASK)
  })

  test("an absolute script path is judged by the hook's cwd, as before", async () => {
    expect(await judgeLine(`cd ${evil} && bash ${resolve(repo, "scripts", "x.sh")}`, repo)).toEqual(ALLOW)
  })

  test("bash -c and eval start where the line is", async () => {
    expect(await judgeLine(`cd ${evil} && bash -c 'bash scripts/x.sh'`, repo)).toEqual(SCRIPT_ASK)
    expect(await judgeLine("bash -c 'rm -rf src'", scratchpad)).toEqual(ALLOW)
    expect(await judgeLine(`bash -c 'cd ${scratchpad}/a && rm -rf out'`, repo)).toEqual(ALLOW)
  })
})
