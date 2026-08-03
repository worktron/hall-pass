import { describe, test, expect } from "bun:test"
import { runEval, makeDecideReplay, type ReplayFn } from "./eval.ts"
import type { AuditEntry } from "./audit.ts"

function decision(
  input: string,
  d: "allow" | "prompt" | "feedback" | "pass",
  id?: string,
  overrides: Partial<AuditEntry> = {},
): AuditEntry {
  return {
    ts: "2026-08-03T00:00:00.000Z",
    event: "decision",
    tool: "Bash",
    input,
    decision: d,
    reason: `recorded: ${d}`,
    layer: "evaluate",
    tool_use_id: id,
    ...overrides,
  }
}

function completed(id: string): AuditEntry {
  return { ts: "2026-08-03T00:00:01.000Z", event: "completed", tool: "Bash", tool_use_id: id }
}

/** Replay that answers from a fixed table; unknown inputs keep their recorded decision. */
function tableReplay(table: Record<string, "allow" | "prompt" | "feedback" | "pass">): ReplayFn {
  return async (_tool, input) => {
    const d = table[input]
    if (!d) return { decision: "pass", reason: "not in table" }
    return { decision: d, reason: `replayed: ${d}` }
  }
}

describe("runEval", () => {
  test("unchanged decisions produce an empty report", async () => {
    const entries = [
      decision("git status", "allow", "t1"),
      completed("t1"),
      decision("rm -rf build", "prompt", "t2"),
    ]
    const replay = tableReplay({ "git status": "allow", "rm -rf build": "prompt" })
    const report = await runEval(entries, replay)

    expect(report.total).toBe(2)
    expect(report.replayed).toBe(2)
    expect(Object.keys(report.transitions)).toEqual([])
    expect(report.ok).toBe(true)
  })

  test("approved prompt that now allows is a win", async () => {
    const entries = [
      decision("git symbolic-ref HEAD", "prompt", "t1"),
      completed("t1"),
    ]
    const report = await runEval(entries, tableReplay({ "git symbolic-ref HEAD": "allow" }))

    expect(report.transitions["prompt→allow"]).toBe(1)
    expect(report.wins.length).toBe(1)
    expect(report.wins[0]!.outcome).toBe("ran")
    expect(report.dangers.length).toBe(0)
    expect(report.ok).toBe(true)
  })

  test("declined prompt that now allows is a danger and fails the eval", async () => {
    const entries = [
      decision("rm -rf /opt/data", "prompt", "t1"),
      // no completed event — the user declined (or interrupted)
    ]
    const report = await runEval(entries, tableReplay({ "rm -rf /opt/data": "allow" }))

    expect(report.dangers.length).toBe(1)
    expect(report.dangers[0]!.outcome).toBe("not-run")
    expect(report.ok).toBe(false)
  })

  test("loosened prompt without tool_use_id lands in unknownLoosened, not dangers", async () => {
    const entries = [decision("legacy command", "prompt")]
    const report = await runEval(entries, tableReplay({ "legacy command": "allow" }))

    expect(report.unknownLoosened.length).toBe(1)
    expect(report.unknownLoosened[0]!.outcome).toBe("unknown")
    expect(report.dangers.length).toBe(0)
    expect(report.ok).toBe(true)
  })

  test("allow that now prompts is a regression but does not fail the eval", async () => {
    const entries = [decision("terraform plan", "allow", "t1"), completed("t1")]
    const report = await runEval(entries, tableReplay({ "terraform plan": "prompt" }))

    expect(report.regressions.length).toBe(1)
    expect(report.transitions["allow→prompt"]).toBe(1)
    expect(report.ok).toBe(true)
  })

  test("feedback that now allows counts as a win (nudge removed, still ran)", async () => {
    const entries = [decision("curl x | python3 -c 'import json'", "feedback", "t1"), completed("t1")]
    const report = await runEval(
      entries,
      tableReplay({ "curl x | python3 -c 'import json'": "allow" }),
    )

    expect(report.wins.length).toBe(1)
    expect(report.ok).toBe(true)
  })

  test("replay skips (null) are counted and excluded from diffs", async () => {
    const skipAll: ReplayFn = async () => null
    const entries = [decision("anything", "prompt", "t1")]
    const report = await runEval(entries, skipAll)

    expect(report.skipped).toBe(1)
    expect(report.replayed).toBe(0)
    expect(Object.keys(report.transitions)).toEqual([])
  })

  test("identical inputs are replayed once but counted per occurrence", async () => {
    let calls = 0
    const countingReplay: ReplayFn = async () => {
      calls++
      return { decision: "allow", reason: "counted" }
    }
    const entries = [
      decision("git fetch", "prompt", "t1"),
      completed("t1"),
      decision("git fetch", "prompt", "t2"),
      completed("t2"),
      decision("git fetch", "prompt", "t3"),
    ]
    const report = await runEval(entries, countingReplay)

    expect(calls).toBe(1)
    expect(report.transitions["prompt→allow"]).toBe(3)
    expect(report.wins.length).toBe(2)
    expect(report.unknownLoosened.length).toBe(0)
    expect(report.dangers.length).toBe(1)
    expect(report.ok).toBe(false)
  })

  test("non-decision events and malformed decisions are ignored", async () => {
    const entries: AuditEntry[] = [
      { ts: "2026-08-03T00:00:00.000Z", event: "native-prompt", message: "Claude needs your permission" },
      completed("t9"),
      { ts: "2026-08-03T00:00:02.000Z", event: "decision", tool: "Bash" }, // no input/decision
      decision("git status", "allow", "t1"),
    ]
    const report = await runEval(entries, tableReplay({ "git status": "allow" }))
    expect(report.total).toBe(1)
  })
})

describe("makeDecideReplay (integration with real decide)", () => {
  test("replays a safelisted command as allow and a dangerous one as prompt", async () => {
    const replay = await makeDecideReplay()

    const safe = await replay("Bash", "git status")
    expect(safe?.decision).toBe("allow")

    const dangerous = await replay("Bash", "git push --force origin main")
    expect(dangerous?.decision).toBe("prompt")
  })

  test("returns null for tools it cannot replay", async () => {
    const replay = await makeDecideReplay()
    expect(await replay("Glob", "**/*.ts")).toBeNull()
  })

  test("end-to-end: recorded corpus with current decide() self-checks clean", async () => {
    const replay = await makeDecideReplay()
    // Recorded decisions that match current behavior → empty diff.
    const entries = [
      decision("git status", "allow", "t1"),
      completed("t1"),
      decision("git push --force origin main", "prompt", "t2"),
    ]
    const report = await runEval(entries, replay)
    expect(Object.keys(report.transitions)).toEqual([])
    expect(report.ok).toBe(true)
  })
})
