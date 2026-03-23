import { describe, test, expect, beforeEach, afterEach, spyOn } from "bun:test"
import { createDebug } from "./debug.ts"
import type { HallPassConfig } from "./config.ts"

function makeConfig(debugEnabled: boolean): HallPassConfig {
  return {
    commands: { safe: [], db_clients: [] },
    git: { protected_branches: [] },
    paths: { protected: [], read_only: [], no_delete: [] },
    audit: { enabled: false, path: "/tmp/audit.jsonl" },
    debug: { enabled: debugEnabled },
  }
}

describe("debug", () => {
  let stderrSpy: ReturnType<typeof spyOn>

  beforeEach(() => {
    stderrSpy = spyOn(process.stderr, "write").mockImplementation(() => true)
    delete process.env.HALL_PASS_DEBUG
  })

  afterEach(() => {
    stderrSpy.mockRestore()
    delete process.env.HALL_PASS_DEBUG
  })

  test("silent when disabled", () => {
    const debug = createDebug(makeConfig(false))
    debug("test", { foo: "bar" })
    expect(stderrSpy).not.toHaveBeenCalled()
  })

  test("outputs to stderr when config.debug.enabled = true", () => {
    const debug = createDebug(makeConfig(true))
    debug("test-label", { key: "value" })
    expect(stderrSpy).toHaveBeenCalledTimes(1)
    const output = stderrSpy.mock.calls[0][0] as string
    expect(output).toContain("[hall-pass]")
    expect(output).toContain("test-label")
    expect(output).toContain('"key"')
  })

  test("outputs to stderr when HALL_PASS_DEBUG=1", () => {
    process.env.HALL_PASS_DEBUG = "1"
    const debug = createDebug(makeConfig(false))
    debug("env-test", "data")
    expect(stderrSpy).toHaveBeenCalledTimes(1)
    const output = stderrSpy.mock.calls[0][0] as string
    expect(output).toContain("[hall-pass]")
    expect(output).toContain("env-test")
  })

  test("format is parseable", () => {
    const debug = createDebug(makeConfig(true))
    debug("parse-test", { num: 42, str: "hello" })
    const output = stderrSpy.mock.calls[0][0] as string

    // Format: [hall-pass] <label>: <JSON>
    const match = output.match(/\[hall-pass\] (.+?): (.+)\n/)
    expect(match).not.toBeNull()
    expect(match![1]).toBe("parse-test")
    const parsed = JSON.parse(match![2]!)
    expect(parsed).toEqual({ num: 42, str: "hello" })
  })

  test("handles label-only (no data)", () => {
    const debug = createDebug(makeConfig(true))
    debug("bare-label")
    const output = stderrSpy.mock.calls[0][0] as string
    expect(output).toBe("[hall-pass] bare-label\n")
  })

  test("handles multiple data arguments", () => {
    const debug = createDebug(makeConfig(true))
    debug("multi", "a", "b", "c")
    const output = stderrSpy.mock.calls[0][0] as string
    expect(output).toContain("[hall-pass] multi:")
    const match = output.match(/: (.+)\n/)
    const parsed = JSON.parse(match![1]!)
    expect(parsed).toEqual(["a", "b", "c"])
  })
})
