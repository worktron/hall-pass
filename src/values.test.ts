/**
 * possibleValues(): every value a variable could hold on one line, read off
 * real shfmt ASTs (the bundled binary, so PARAM_OP's codes are checked too).
 */
import { describe, test, expect } from "bun:test"
import { resolve } from "path"
import { existsSync } from "fs"
import { possibleValues, substitute, hasPlaceholder, MAX_VARIANTS } from "./values.ts"

const bundledShfmt = resolve(import.meta.dir, "..", "bin", "shfmt")
const shfmtBin = existsSync(bundledShfmt) ? bundledShfmt : "shfmt"
const env = { home: "/Users/me", tmpdir: "/var/folders/xy/T/" }

async function valuesOf(command: string) {
  const proc = Bun.spawn([shfmtBin, "-ln", "bash", "--tojson"], { stdin: new Response(command), stdout: "pipe", stderr: "pipe" })
  const out = await new Response(proc.stdout).text()
  await proc.exited
  return possibleValues(JSON.parse(out), env)
}

describe("possibleValues", () => {
  test("a plain assignment", async () => {
    expect((await valuesOf("E=.env; echo x > $E")).get("E")).toEqual([".env"])
  })

  test("every assignment counts, branches, prefixes and export included", async () => {
    const v = await valuesOf("if x; then B=main; else B=dev; fi; B=next git push; export B=last")
    expect(v.get("B")).toEqual(["main", "dev", "next", "last"])
  })

  test("HOME and TMPDIR start from the hook's environment, trailing slash dropped", async () => {
    const v = await valuesOf("echo hi")
    expect(v.get("HOME")).toEqual(["/Users/me"])
    expect(v.get("TMPDIR")).toEqual(["/var/folders/xy/T"])
  })

  test("a value that mentions another variable is expanded", async () => {
    const v = await valuesOf("S=/tmp/s; V=$S/verify; echo > $V/out")
    expect(v.get("V")).toEqual(["/tmp/s/verify"])
    expect(substitute("$V/out", v)).toEqual(["/tmp/s/verify/out"])
  })

  test("a self-reference stops expanding and stays unknown", async () => {
    const v = await valuesOf("P=/a; P=$P/b")
    expect(v.get("P")).toEqual(["/a", "$P/b"])
  })

  test("for-loop items are values; a loop over command output is unknown", async () => {
    expect((await valuesOf("for b in main dev; do git push origin $b; done")).get("b")).toEqual(["main", "dev"])
    expect((await valuesOf("for f in $(ls); do cat $f; done")).get("f")).toEqual(["$(...)"])
    expect((await valuesOf("for g; do :; done")).get("g")).toEqual(["$g"])
  })

  test("defaults and alternatives in ${X:-v} are values of X (PARAM_OP codes)", async () => {
    for (const exp of ["${X-.env}", "${X:-.env}", "${X=.env}", "${X:=.env}", "${X+.env}", "${X:+.env}"]) {
      expect((await valuesOf(`echo > ${exp}`)).get("X")).toEqual([".env"])
    }
  })

  test("string surgery, read, printf -v, X+= make a name unknown", async () => {
    const v = await valuesOf("A=.envx; echo ${A%x}; read -r R; printf -v P '%s' x; C=a; C+=b; mapfile M")
    expect(v.get("A")).toEqual([".envx", "$A"])
    expect(v.get("R")).toEqual(["$R"])
    expect(v.get("P")).toEqual(["$P"])
    expect(v.get("C")).toEqual(["a", "$C"])
    expect(v.get("M")).toEqual(["$M"])
  })
})

describe("substitute", () => {
  test("a name with no values stays as written", () => {
    expect(substitute("$NOPE/x", new Map())).toEqual(["$NOPE/x"])
  })

  test("every combination, capped", () => {
    const v = new Map([["A", ["1", "2"]], ["B", ["x", "y"]]])
    expect(substitute("$A-$B", v)).toEqual(["1-x", "1-y", "2-x", "2-y"])
    const many = new Map([["A", Array.from({ length: 10 }, (_, i) => `${i}`)]])
    expect(substitute("$A$A", many).length).toBeLessThanOrEqual(MAX_VARIANTS)
  })

  test("command substitutions and positionals are not names", () => {
    expect(substitute("$(...)/$1", new Map([["1", ["x"]]]))).toEqual(["$(...)/$1"])
    expect(hasPlaceholder("$(...)/x")).toBe(true)
    expect(hasPlaceholder("/tmp/x")).toBe(false)
  })
})
