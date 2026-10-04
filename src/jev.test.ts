import { describe, test, expect } from "bun:test"
import type { AuditEntry } from "./audit.ts"
import { loadConfig } from "./config.ts"
import { findShfmt } from "./decide.ts"
import {
  askJev, buildReport, buildRequest, extractItems, parseAnswer, redactCommand, redactText, redactUrl, selectItems,
  JEV_MODEL, KINDS, QUESTIONS_VERSION, type Answer, type Item, type Kind,
} from "./jev.ts"

const HOME = "/Users/someone"

function bash(input: string, decision: AuditEntry["decision"] = "pass"): AuditEntry {
  return { ts: "2026-10-01T00:00:00.000Z", event: "decision", tool: "Bash", input, decision, reason: "recorded" }
}

function answer(key: string, kind: Kind, confidence = 0.95): Answer {
  const probabilities = Object.fromEntries(KINDS.map((k) => [k, k === kind ? confidence : 0])) as Record<Kind, number>
  return { key, questionsVersion: QUESTIONS_VERSION, model: JEV_MODEL, kind, confidence, probabilities, inputTokens: 300, askedAt: "2026-10-02T00:00:00.000Z" }
}

function item(key: string, name: string, bucket: Item["bucket"], extra: Partial<Item> = {}): Item {
  return { key, state: { command: `${name} ${key}` }, name, group: name, bucket, uses: 1, ...extra }
}

describe("redaction", () => {
  test("a URL keeps its origin and path, and only the names of its query parameters", () => {
    expect(redactUrl("https://user:pw@example.com/cb?code=abc123&state=xyz")).toBe("https://example.com/cb?code=…&state=…")
    expect(redactUrl("https://example.com/docs")).toBe("https://example.com/docs")
  })

  test("op:// references lose their vault and item", () => {
    expect(redactUrl("op://Personal/TypeSafe API/credential")).toBe("op://…")
    expect(redactText("op read op://Private/abc/password")).toBe("op read op://…")
  })

  test("the home directory reads as ~", () => {
    expect(redactText(`${HOME}/Workspace/app/src`, HOME)).toBe("~/Workspace/app/src")
  })

  test("header and assignment style secrets lose their value", () => {
    expect(redactText("Authorization: Bearer abc")).toBe("Authorization: …")
    expect(redactText("password=hunter2")).toBe("password=…")
  })

  test("long opaque tokens are elided, ordinary words are not", () => {
    expect(redactText("key 9f8e7d6c5b4a39281706f5e4d3c2b1a0ffeeddcc end")).toBe("key … end")
    expect(redactText("src/components/really-long-component-name.tsx")).toBe("src/components/really-long-component-name.tsx")
  })

  test("environment values on the command are dropped", () => {
    const state = redactCommand({ name: "deploy", args: ["deploy", "--prod"], assigns: [{ name: "TOKEN", value: "s3cret" }] }, HOME)
    expect(state).toEqual({ command: "TOKEN=… deploy --prod" })
  })

  test("a heredoc rides along, capped", () => {
    const state = redactCommand({ name: "psql", args: ["psql", "db"], assigns: [], stdin: "select 1;\n".repeat(200) }, HOME)
    expect(state!.stdin!.length).toBeLessThanOrEqual(1002)
    expect(state!.stdin!.startsWith("select 1;")).toBe(true)
  })

  test("a command still carrying a secret is never sent", () => {
    const state = redactCommand({ name: "cat", args: ["cat"], assigns: [], stdin: "-----BEGIN PRIVATE KEY-----\nabc" }, HOME)
    expect(state).toBeNull()
  })
})

describe("extractItems", () => {
  test("buckets each simple command by how today's rules judge it alone", async () => {
    const config = await loadConfig()
    const items = await extractItems(
      [
        bash("git status && frobnicate list --all"),
        bash("git status && frobnicate list --all"),
        bash("rm -rf build"),
        bash(`ls ${HOME}/Workspace`, "allow"),
      ],
      { config, shfmtBin: findShfmt(), home: HOME },
    )
    const by = (cmd: string) => items.find((i) => i.state.command === cmd)
    expect(by("frobnicate list --all")).toMatchObject({ bucket: "unknown", name: "frobnicate", group: "frobnicate list", uses: 2 })
    expect(by("git status")).toMatchObject({ bucket: "allowed", uses: 2 })
    expect(by("rm -rf build")).toMatchObject({ bucket: "judgment", reason: "dangerous: rm" })
    expect(by("ls ~/Workspace")).toMatchObject({ bucket: "allowed" })
  })

  test("hard stops, lines with a secret, and Codex calls are left out", async () => {
    const config = await loadConfig()
    const items = await extractItems(
      [
        bash("cat ~/.ssh/id_rsa", "prompt"),
        bash("curl -H 'Authorization: Bearer abcdefghijklmnopqrstuvwxyz0123' https://x.test", "prompt"),
        { ...bash("frobnicate"), host: "codex" },
      ],
      { config, shfmtBin: findShfmt(), home: HOME },
    )
    expect(items).toEqual([])
  })
})

describe("the request", () => {
  test("pins the model and asks the one kind question", () => {
    const body = buildRequest({ command: "ls" })
    expect(body.model).toBe(JEV_MODEL)
    expect(Object.keys(body.questions)).toEqual(["kind"])
    expect(body.state).toEqual({ command: "ls" })
  })

  test("parseAnswer keeps the kind, confidence and every probability", () => {
    const parsed = parseAnswer({
      model: "jev-1.13.0",
      answers: { kind: { choice: "inspect", confidence: 0.91, probabilities: { inspect: 0.91, build: 0.05 } } },
      usage: { input_tokens: 280 },
    })
    expect(parsed).toMatchObject({ kind: "inspect", confidence: 0.91, inputTokens: 280 })
    expect(parsed!.probabilities.delete).toBe(0)
  })

  test("parseAnswer refuses a kind we did not offer, or no confidence", () => {
    expect(parseAnswer({ answers: { kind: { choice: "safe", confidence: 0.9 } } })).toBeNull()
    expect(parseAnswer({ answers: { kind: { choice: "inspect" } } })).toBeNull()
    expect(parseAnswer({})).toBeNull()
  })

  test("askJev sends the key and the state, and stamps the answer", async () => {
    let sent: { auth: string | null; body: unknown } | null = null
    const fetchImpl = (async (_url: string, init: RequestInit) => {
      sent = { auth: new Headers(init.headers).get("authorization"), body: JSON.parse(init.body as string) }
      return Response.json({ model: JEV_MODEL, answers: { kind: { choice: "build", confidence: 0.88, probabilities: { build: 0.88 } } }, usage: { input_tokens: 290 } })
    }) as unknown as typeof fetch
    const a = await askJev(item("k1", "make", "unknown"), "sk-test", { fetchImpl, now: () => new Date("2026-10-02T00:00:00Z") })
    expect(sent!.auth).toBe("Bearer sk-test")
    expect((sent!.body as { state: unknown }).state).toEqual({ command: "make k1" })
    expect(a).toMatchObject({ key: "k1", kind: "build", questionsVersion: QUESTIONS_VERSION, askedAt: "2026-10-02T00:00:00.000Z" })
  })

  test("askJev throws on a refusal it should not retry", async () => {
    const fetchImpl = (async () => new Response("bad key", { status: 401 })) as unknown as typeof fetch
    await expect(askJev(item("k1", "make", "unknown"), "sk-test", { fetchImpl })).rejects.toThrow("401")
  })
})

describe("buildReport", () => {
  test("a name whose every use reads safe is a candidate", () => {
    const items = [item("a", "frob", "unknown", { uses: 3 }), item("b", "frob", "unknown", { uses: 2 })]
    const report = buildReport(items, new Map([["a", answer("a", "inspect")], ["b", answer("b", "build", 0.85)]]))
    expect(report.candidates).toHaveLength(1)
    expect(report.candidates[0]).toMatchObject({ group: "frob", uses: 5, commands: 2, minConfidence: 0.85, kinds: { inspect: 1, build: 1 } })
  })

  test("when one subcommand is risky, the safe subcommands are candidates on their own", () => {
    const items = [
      item("a", "tmux", "unknown", { group: "tmux ls", uses: 4 }),
      item("b", "tmux", "unknown", { group: "tmux kill-server", uses: 2 }),
    ]
    const report = buildReport(items, new Map([["a", answer("a", "inspect")], ["b", answer("b", "system")]]))
    expect(report.candidates.map((c) => c.group)).toEqual(["tmux ls"])
  })

  test("low confidence, an unanswered use, or too few uses keep a name off the list", () => {
    const items = [
      item("a", "low", "unknown", { uses: 5 }),
      item("b", "partial", "unknown", { uses: 5 }),
      item("c", "partial", "unknown", { uses: 5 }),
      item("d", "once", "unknown", { uses: 1 }),
    ]
    const report = buildReport(items, new Map([["a", answer("a", "inspect", 0.6)], ["b", answer("b", "inspect")], ["d", answer("d", "inspect")]]))
    expect(report.candidates).toEqual([])
    expect(report.answered.unknown).toEqual({ items: 4, answered: 3 })
  })

  test("an allowed command read as risky is a possible hole; the rest only count", () => {
    const items = [item("a", "ls", "allowed"), item("b", "weird", "allowed"), item("c", "meh", "allowed")]
    const report = buildReport(items, new Map([["a", answer("a", "inspect")], ["b", answer("b", "delete", 0.93)], ["c", answer("c", "remote", 0.5)]]))
    expect(report.holes.map((h) => h.item.key)).toEqual(["b"])
    expect(report.allowedKinds).toEqual({ inspect: 1, delete: 1, remote: 1 })
  })

  test("judgment calls group by reason and list the ones read as safe", () => {
    const items = [
      item("a", "perl", "judgment", { reason: "perl: inline code", uses: 3 }),
      item("b", "perl", "judgment", { reason: "perl: inline code", uses: 1 }),
      item("c", "rm", "judgment", { reason: "dangerous: rm", uses: 9 }),
    ]
    const report = buildReport(items, new Map([["a", answer("a", "inspect")], ["b", answer("b", "write")], ["c", answer("c", "delete")]]))
    expect(report.judgment.map((j) => j.reason)).toEqual(["dangerous: rm", "perl: inline code"])
    expect(report.judgment[1]!.safe.map((s) => s.key)).toEqual(["a"])
    expect(report.judgment[1]!.kinds).toEqual({ inspect: 1, write: 1 })
  })
})

describe("selectItems", () => {
  test("every unknown and judgment item, and a capped sample of allowed ones per group", () => {
    const items = [
      item("a1", "grep", "allowed"),
      item("a2", "grep", "allowed"),
      item("a3", "grep", "allowed"),
      item("b1", "cp", "allowed"),
      item("u1", "frob", "unknown"),
      item("u2", "frob", "unknown"),
      item("j1", "rm", "judgment"),
    ]
    const all = new Set(["unknown", "judgment", "allowed"] as const)
    expect(selectItems(items, { buckets: all, perGroup: 2 }).map((i) => i.key)).toEqual(["a1", "a2", "b1", "j1", "u1", "u2"])
    expect(selectItems(items, { buckets: all, perGroup: 0 })).toHaveLength(7)
    expect(selectItems(items, { buckets: new Set(["unknown"] as const), perGroup: 2 }).map((i) => i.key)).toEqual(["u1", "u2"])
  })
})

describe("groups", () => {
  test("only the word right after the name is a subcommand", async () => {
    const config = await loadConfig()
    const items = await extractItems(
      [bash("frobnicate -n pattern file.txt"), bash("frobnicate list"), bash("frobnicate ./file.txt")],
      { config, shfmtBin: findShfmt(), home: HOME },
    )
    expect(items.map((i) => i.group).sort()).toEqual(["frobnicate", "frobnicate", "frobnicate list"])
  })

  test("a name with many first arguments is capped at twenty groups' worth", () => {
    const items = Array.from({ length: 30 }, (_, n) => item(`k${String(n).padStart(2, "0")}`, "grep", "allowed", { group: `grep w${n}` }))
    expect(selectItems(items, { buckets: new Set(["allowed"] as const), perGroup: 1 })).toHaveLength(20)
  })
})
