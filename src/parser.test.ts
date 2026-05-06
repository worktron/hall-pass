import { describe, test, expect } from "bun:test"
import { resolve } from "path"
import { existsSync } from "fs"
import { extractCommands, extractRedirects, type RedirectInfo } from "./parser.ts"

const bundledShfmt = resolve(import.meta.dir, "..", "bin", "shfmt")
const shfmtBin = existsSync(bundledShfmt) ? bundledShfmt : "shfmt"

/** Helper: parse a shell command with shfmt and extract command names */
async function commandsIn(command: string): Promise<string[]> {
  const proc = Bun.spawn([shfmtBin, "--tojson"], {
    stdin: new Response(command),
    stdout: "pipe",
    stderr: "pipe",
  })
  const stdout = await new Response(proc.stdout).text()
  await proc.exited
  if (proc.exitCode !== 0) throw new Error(`shfmt failed: ${command}`)
  return extractCommands(JSON.parse(stdout))
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
