/**
 * literalVariables: which variables a line sets to a literal path that
 * nothing else on the line can change. Each case is parsed by the pinned
 * shfmt, so the shapes are the ones the hook sees.
 */
import { describe, test, expect } from "bun:test"
import { resolve } from "path"
import { existsSync } from "fs"
import { literalVariables, ARITHMETIC_TESTS } from "./vars.ts"
import { extractCommandInfos } from "./parser.ts"

const bundledShfmt = resolve(import.meta.dir, "..", "bin", "shfmt")
const shfmtBin = existsSync(bundledShfmt) ? bundledShfmt : "shfmt"

function parse(command: string): unknown {
  const r = Bun.spawnSync([shfmtBin, "-ln", "bash", "--tojson"], { stdin: new TextEncoder().encode(command) })
  if (r.exitCode !== 0) throw new Error(`shfmt failed on ${command}: ${r.stderr.toString()}`)
  return JSON.parse(r.stdout.toString())
}

function known(command: string): Record<string, string> {
  return Object.fromEntries([...literalVariables(parse(command))].map(([k, v]) => [k, v.value]))
}

describe("literalVariables", () => {
  test("a bare top-level assignment of a literal absolute path is known", () => {
    expect(known("S=/tmp/x; rm -rf $S")).toEqual({ S: "/tmp/x" })
    expect(known(`S='/tmp/x'; D="/tmp/y"; rm -rf $S $D`)).toEqual({ S: "/tmp/x", D: "/tmp/y" })
    expect(known("A=/tmp/a B=/tmp/b\nrm $A $B")).toEqual({ A: "/tmp/a", B: "/tmp/b" })
    expect(known("S=/tmp/x; printf '%s\\n' Saved; rm -rf $S")).toEqual({ S: "/tmp/x" })
    expect(known(`S=/tmp/x; [[ -d $S ]] && echo "\${a[0]}" "\${a[@]}"; export PATH=$PATH:/x; rm -rf $S`)).toEqual({ S: "/tmp/x" })
  })

  const unknown: Array<[string, string]> = [
    ["prefix assignment", "S=/tmp/x rm -rf $S"],
    ["inside &&", "true && S=/tmp/x; rm $S"],
    ["inside if", "if true; then S=/tmp/x; fi"],
    ["inside a subshell", "(S=/tmp/x)"],
    ["backgrounded", "S=/tmp/x &"],
    ["negated", "! S=/tmp/x"],
    ["assigned twice", "S=/tmp/x; S=/tmp/x"],
    ["also assigned in a function", "S=/tmp/x; f() { S=/; }"],
    ["also a prefix assignment", "S=/tmp/x; S=/ true"],
    ["appended", "S=/tmp/x; S+=y"],
    ["an array", "S=(/tmp/x)"],
    ["an array element set", "S=/tmp/x; S[1]=/"],
    ["relative", "S=tmp/x"],
    ["tilde", "S=~/x"],
    ["whitespace", "S='/tmp/a b'"],
    ["a glob", "S='/tmp/*'"],
    ["coproc S", "S=/tmp/x; coproc S { cat; }"],
    ["coproc with an expanded name", "S=/tmp/x; coproc $X { cat; }"],
    ["an fd variable redirect", "S=/tmp/x; exec {S}>/tmp/f"],
    ["backslash", "S=/tmp/a\\*"],
    ["an expansion", "S=/tmp/$X"],
    ["a command substitution", "S=$(mktemp -d)"],
    ["for loop variable", "S=/tmp/x; for S in a; do :; done"],
    ["select variable", "S=/tmp/x; select S in a; do :; done"],
    ["read", "S=/tmp/x; read -r S"],
    ["mapfile", "S=/tmp/x; mapfile S"],
    ["getopts", "S=/tmp/x; getopts ab S"],
    ["printf -v", "S=/tmp/x; printf -v S y"],
    ["printf -vS", "S=/tmp/x; printf -vS y"],
    ["printf with an expanded option", "S=/tmp/x; printf $O y"],
    ["read into an expanded name", "S=/tmp/x; read $V"],
    ["declare an expanded name", "S=/tmp/x; declare $V=/"],
    ["a nameref named by an expansion", "S=/tmp/x; declare -n r=$V; r=/"],
    ["an integer variable", "S=/tmp/x; declare -i n; n=S=1"],
    ["arithmetic that names nothing", "S=/tmp/x; X='S=1'; (( X ))"],
    ["$(( )) that names nothing", "S=/tmp/x; echo $((X))"],
    ["a variable array index", "S=/tmp/x; echo ${a[X]}"],
    ["[[ -lt ]] that names nothing", "S=/tmp/x; [[ X -lt 1 ]]"],
    ["unset", "S=/tmp/x; unset S"],
    ["wait -p", "S=/tmp/x; wait -p S"],
    ["export", "S=/tmp/x; export S=/"],
    ["export naked", "S=/tmp/x; export S"],
    ["local", "S=/tmp/x; f() { local S; }"],
    ["nameref", "S=/tmp/x; declare -n r=S"],
    ["builtin read", "S=/tmp/x; builtin read S"],
    ["command -p read", "S=/tmp/x; command -p read S"],
    ["let", "S=/tmp/x; let S=1"],
    ["(( ))", "S=/tmp/x; ((S=1))"],
    ["$(( ))", "S=/tmp/x; echo $((S=1))"],
    ["for (( ))", "S=/tmp/x; for ((S=0; S<1; S++)); do :; done"],
    ["[[ arithmetic ]]", "S=/tmp/x; [[ 1 -eq S=1 ]]"],
    ["array index", "S=/tmp/x; echo ${a[S=1]}"],
    ["${S:=x}", "S=/tmp/x; echo ${S:=/}"],
    ["${S:-x}", "S=/tmp/x; echo ${S:-/}"],
    ["${#S}", "S=/tmp/x; echo ${#S}"],
    ["${!S}", "S=/tmp/x; echo ${!S}"],
    ["eval", "S=/tmp/x; eval true"],
    ["source", "S=/tmp/x; source ./env.sh"],
    ["dot", "S=/tmp/x; . ./env.sh"],
    ["trap", "S=/tmp/x; trap 'S=/' DEBUG"],
    ["alias", "S=/tmp/x; alias rm='S=/ rm'"],
    ["command eval", "S=/tmp/x; command eval true"],
    ["an expanded command name", "S=/tmp/x; $CMD true"],
    ["IFS assigned", "IFS=/; S=/tmp/x"],
    ["IFS read", "S=/tmp/x; read -r IFS"],
    ["PWD", "PWD=/tmp/x"],
    ["_", "_=/tmp/x"],
    ["REPLY", "REPLY=/tmp/x"],
    ["BASH_ENV", "BASH_ENV=/tmp/x"],
  ]
  for (const [label, line] of unknown) {
    test(`${label}: ${JSON.stringify(line)} → not known`, () => {
      expect(known(line).S ?? known(line).PWD ?? known(line)._ ?? known(line).REPLY ?? known(line).BASH_ENV).toBeUndefined()
    })
  }
})

test("ARITHMETIC_TESTS are the pinned shfmt's codes for -eq -ne -le -ge -lt -gt", () => {
  const codes = ["-eq", "-ne", "-le", "-ge", "-lt", "-gt"].map((op) => {
    const ast = parse(`[[ 1 ${op} 2 ]]`) as { Stmts: Array<{ Cmd: { X: { Op: number } } }> }
    return ast.Stmts[0]!.Cmd.X.Op
  })
  expect(new Set(codes)).toEqual(new Set(ARITHMETIC_TESTS))
  expect(ARITHMETIC_TESTS.has((parse("[[ a == b ]]") as { Stmts: Array<{ Cmd: { X: { Op: number } } }> }).Stmts[0]!.Cmd.X.Op)).toBe(false)
})

describe("resolvedArgs", () => {
  function rm(command: string) {
    const ast = parse(command)
    return extractCommandInfos(ast, literalVariables(ast)).find((c) => c.name === "rm")!
  }

  test("plain reads after the assignment resolve, in every quoting", () => {
    expect(rm(`S=/tmp/x; rm -rf $S "$S" \${S} $S/a "\${S}/b" pre$S`).resolvedArgs)
      .toEqual(["rm", "-rf", "/tmp/x", "/tmp/x", "/tmp/x", "/tmp/x/a", "/tmp/x/b", "pre/tmp/x"])
  })

  test("args keep the placeholder; other rules see what they saw before", () => {
    expect(rm("S=/tmp/x; rm -rf $S").args).toEqual(["rm", "-rf", "$S"])
  })

  test("a read before the assignment, a single-quoted $S, and ${S:-x} stay unresolved", () => {
    expect(rm("rm -rf $S; S=/tmp/x").resolvedArgs).toBeUndefined()
    expect(rm("S=/tmp/x; rm -rf '$S' ${S:-y} $T").resolvedArgs).toBeUndefined()
  })

  test("without the line's variables nothing resolves", () => {
    expect(extractCommandInfos(parse("S=/tmp/x; rm -rf $S"))[0]!.resolvedArgs).toBeUndefined()
  })
})
