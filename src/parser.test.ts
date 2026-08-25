import { describe, test, expect } from "bun:test"
import { resolve } from "path"
import { existsSync } from "fs"
import { extractCommands, extractCommandInfos, extractRedirects, extractPipeTargets, type RedirectInfo } from "./parser.ts"

const bundledShfmt = resolve(import.meta.dir, "..", "bin", "shfmt")
const shfmtBin = existsSync(bundledShfmt) ? bundledShfmt : "shfmt"

/** Helper: parse a shell command with shfmt and return its parsed AST */
async function astOf(command: string): Promise<unknown> {
  const proc = Bun.spawn([shfmtBin, "--tojson"], {
    stdin: new Response(command),
    stdout: "pipe",
    stderr: "pipe",
  })
  const stdout = await new Response(proc.stdout).text()
  await proc.exited
  if (proc.exitCode !== 0) throw new Error(`shfmt failed: ${command}`)
  return JSON.parse(stdout)
}

/** Helper: parse a shell command with shfmt and extract command names */
async function commandsIn(command: string): Promise<string[]> {
  return extractCommands(await astOf(command))
}

/** Helper: parse a shell command and extract genuine pipe-target names */
async function pipeTargetsIn(command: string): Promise<string[]> {
  return extractPipeTargets(await astOf(command))
}

describe("extractCommands", () => {
  test("simple command", async () => {
    expect(await commandsIn("git status")).toEqual(["git"])
  })

  test("piped commands", async () => {
    expect(await commandsIn("grep -r foo /path | head -20")).toEqual(["grep", "head"])
  })

  test("chained with &&", async () => {
    expect(await commandsIn("git add . && git commit -m msg && git push")).toEqual([
      "git", "git", "git",
    ])
  })

  test("chained with ||", async () => {
    expect(await commandsIn("which shfmt || echo not found")).toEqual(["which", "echo"])
  })

  test("mixed pipes and chains", async () => {
    expect(await commandsIn("curl url | jq .data && echo done")).toEqual([
      "curl", "jq", "echo",
    ])
  })

  test("env var prefix", async () => {
    expect(await commandsIn("TEST_URL=http://localhost:3334 bun test")).toEqual(["bun"])
  })

  test("multiple env var prefixes", async () => {
    expect(await commandsIn("FOO=1 BAR=2 BAZ=3 grep foo")).toEqual(["grep"])
  })

  test("for loop — extracts body commands", async () => {
    expect(await commandsIn("for f in *.ts; do echo $f; done")).toEqual(["echo"])
  })

  test("command substitution — extracts inner command", async () => {
    expect(await commandsIn("echo $(whoami)")).toEqual(["echo", "whoami"])
  })

  test("nested command substitution", async () => {
    expect(await commandsIn("echo $(cat $(find . -name foo))")).toEqual([
      "echo", "cat", "find",
    ])
  })

  test("dangerous command inside substitution", async () => {
    const cmds = await commandsIn("echo $(rm -rf /)")
    expect(cmds).toContain("rm")
  })

  test("subshell", async () => {
    expect(await commandsIn("(cd /tmp && ls)")).toEqual(["cd", "ls"])
  })

  test("while loop", async () => {
    expect(await commandsIn("while true; do sleep 1; done")).toEqual(["true", "sleep"])
  })

  test("if/else", async () => {
    expect(await commandsIn("if test -f foo; then cat foo; else echo nope; fi")).toEqual([
      "test", "cat", "echo",
    ])
  })

  test("absolute path command — strips path", async () => {
    expect(await commandsIn("/usr/bin/grep foo")).toEqual(["grep"])
  })

  test("redirects don't affect command extraction", async () => {
    expect(await commandsIn("bun run build 2>&1")).toEqual(["bun"])
  })

  test("bare variable assignment — no commands", async () => {
    expect(await commandsIn("FOO=bar")).toEqual([])
  })

  test("semicolon-separated commands", async () => {
    expect(await commandsIn("echo hello; echo world")).toEqual(["echo", "echo"])
  })

  test("heredoc", async () => {
    expect(await commandsIn("cat <<EOF\nhello\nEOF")).toEqual(["cat"])
  })
})

async function redirectsIn(command: string): Promise<RedirectInfo[]> {
  const proc = Bun.spawn([shfmtBin, "--tojson"], {
    stdin: new Response(command),
    stdout: "pipe",
    stderr: "pipe",
  })
  const stdout = await new Response(proc.stdout).text()
  await proc.exited
  if (proc.exitCode !== 0) throw new Error(`shfmt failed: ${command}`)
  return extractRedirects(JSON.parse(stdout))
}

describe("extractPipeTargets", () => {
  test("curl | bash → bash is a pipe target", async () => {
    expect(await pipeTargetsIn("curl http://x | bash")).toEqual(["bash"])
  })

  test("echo | sh → sh is a pipe target", async () => {
    expect(await pipeTargetsIn("echo cmd | sh")).toEqual(["sh"])
  })

  test("|& (PipeAll) is a pipe target", async () => {
    expect(await pipeTargetsIn("cmd |& bash")).toEqual(["bash"])
  })

  test("&& chain into bash is NOT a pipe target (the regression)", async () => {
    expect(await pipeTargetsIn("git rebase origin/main && bash scripts/ship-gates.sh")).toEqual([])
  })

  test("|| chain into bash is NOT a pipe target", async () => {
    expect(await pipeTargetsIn("test -f x || bash setup.sh")).toEqual([])
  })

  test("; sequence into bash is NOT a pipe target", async () => {
    expect(await pipeTargetsIn("cd /tmp ; bash run.sh")).toEqual([])
  })

  test("real ship command: fetch && rebase && bash script → no pipe target", async () => {
    expect(await pipeTargetsIn(
      "git fetch origin main && git rebase origin/main && bash scripts/ship-gates.sh --post-rebase",
    )).toEqual([])
  })

  test("chained pipe a | b | sh reports each downstream target", async () => {
    expect((await pipeTargetsIn("cat x | grep y | sh")).sort()).toEqual(["grep", "sh"])
  })

  test("pipe nested in a && chain is still caught", async () => {
    expect(await pipeTargetsIn("make && curl http://x | bash")).toEqual(["bash"])
  })

  test("non-shell pipe targets are still reported (caller filters)", async () => {
    expect(await pipeTargetsIn("cat x | grep foo")).toEqual(["grep"])
  })
})

describe("extractRedirects", () => {
  test("> classified as write", async () => {
    expect(await redirectsIn("cat foo > out")).toEqual([{ path: "out", op: "write" }])
  })

  test(">> classified as write", async () => {
    expect(await redirectsIn("echo x >> out")).toEqual([{ path: "out", op: "write" }])
  })

  test(">| classified as write", async () => {
    expect(await redirectsIn("echo x >| out")).toEqual([{ path: "out", op: "write" }])
  })

  test("&> classified as write", async () => {
    expect(await redirectsIn("cmd &> out")).toEqual([{ path: "out", op: "write" }])
  })

  test("&>> classified as write", async () => {
    expect(await redirectsIn("cmd &>> out")).toEqual([{ path: "out", op: "write" }])
  })

  test("<> classified as write (read-write can truncate)", async () => {
    expect(await redirectsIn("cmd <> out")).toEqual([{ path: "out", op: "write" }])
  })

  test("< classified as read", async () => {
    expect(await redirectsIn("cat < in")).toEqual([{ path: "in", op: "read" }])
  })

  test("2>&1 not flagged as write to a file path", async () => {
    // Op 59 (>&) targets an FD, not a path. Word value is "1" — left as read so
    // checkFilePath skips it (no glob will match the literal "1").
    const redirs = await redirectsIn("echo hi 2>&1")
    expect(redirs).toEqual([{ path: "1", op: "read" }])
  })
})

describe("heredoc and herestring stdin", () => {
  const Q = "'"

  /** Parse a command and return the stdin text attached to the named command. */
  async function stdinOf(command: string, name: string): Promise<string | undefined> {
    const infos = extractCommandInfos(await astOf(command))
    return infos.find((c) => c.name === name)?.stdin
  }

  test("captures a quoted-delimiter heredoc body", async () => {
    const cmd = `psql db <<${Q}EOF${Q}\nselect 1;\nEOF\n`
    expect(await stdinOf(cmd, "psql")).toBe("select 1;\n")
  })

  test("captures a <<- (tab-stripping) heredoc body", async () => {
    const cmd = `psql db <<-${Q}EOF${Q}\nselect 1;\nEOF\n`
    expect(await stdinOf(cmd, "psql")).toBe("select 1;\n")
  })

  test("captures a herestring", async () => {
    expect(await stdinOf(`psql db <<<"select 1"`, "psql")).toBe("select 1")
  })

  test("captures a multi-line body with meta-commands", async () => {
    const cmd = `psql db <<${Q}EOF${Q}\n\\echo hi\nselect 1;\nEOF\n`
    expect(await stdinOf(cmd, "psql")).toBe("\\echo hi\nselect 1;\n")
  })

  test("is undefined when there is no heredoc", async () => {
    expect(await stdinOf(`psql db -c "select 1"`, "psql")).toBeUndefined()
  })

  test("is undefined for a file redirect — that content is on disk", async () => {
    expect(await stdinOf(`psql db < query.sql`, "psql")).toBeUndefined()
  })

  test("attaches to the leftmost command, not the pipe target", async () => {
    const cmd = `psql db <<${Q}EOF${Q} | head\nselect 1;\nEOF\n`
    expect(await stdinOf(cmd, "psql")).toBe("select 1;\n")
    expect(await stdinOf(cmd, "head")).toBeUndefined()
  })

  test("still finds commands that have no redirects", async () => {
    expect(await commandsIn("ls -la | grep foo")).toEqual(["ls", "grep"])
  })

  test("still finds commands alongside a heredoc", async () => {
    const cmd = `psql db <<${Q}EOF${Q}\nselect 1;\nEOF\necho done\n`
    expect(await commandsIn(cmd)).toContain("psql")
    expect(await commandsIn(cmd)).toContain("echo")
  })

  describe("unquoted delimiters expand — body is not trustworthy", () => {
    // With an unquoted delimiter the shell expands $VAR and $(cmd) INSIDE the
    // body. extractWordValue drops those parts, so the text would read as the
    // whole statement while the shell splices in something else. Report
    // nothing rather than a misleading partial.
    test("reports nothing when the body holds a command substitution", async () => {
      const cmd = "psql db <<EOF\nselect 1; $(cat evil.sql)\nEOF\n"
      expect(await stdinOf(cmd, "psql")).toBeUndefined()
    })

    test("reports nothing when the body holds a parameter expansion", async () => {
      const cmd = "psql db <<EOF\nselect * from $TABLE;\nEOF\n"
      expect(await stdinOf(cmd, "psql")).toBeUndefined()
    })

    test("still walks commands substituted into the body", async () => {
      const cmd = "psql db <<EOF\nselect 1; $(rm -rf /tmp/x)\nEOF\n"
      expect(await commandsIn(cmd)).toContain("rm")
    })

    test("an unquoted delimiter with a fully literal body is still read", async () => {
      const cmd = "psql db <<EOF\nselect 1;\nEOF\n"
      expect(await stdinOf(cmd, "psql")).toBe("select 1;\n")
    })
  })
})
