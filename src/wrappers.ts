/**
 * Transparent command wrappers — commands that don't change security
 * properties of the wrapped command. They affect process lifetime,
 * scheduling, or timing, but not what the command actually does.
 *
 * When we encounter one, we strip it and its flags, then evaluate
 * the inner command through the normal pipeline.
 */

import type { CommandInfo } from "./parser.ts"
import type { Scope } from "./places.ts"
import { lstatSync } from "fs"
import { resolve } from "path"
import { isTopOfSameRepository, gitTracksFile } from "./repo.ts"

/**
 * Given the args after the wrapper name, return the index where
 * the inner command starts. Returns null if the inner command
 * can't be determined (e.g., wrapper used with no command).
 */
type FlagSkipper = (rest: string[]) => number | null

const TRANSPARENT_WRAPPERS = new Map<string, FlagSkipper>([
  // nohup has no flags — first arg is the command
  ["nohup", () => 0],

  // nice [-n adjustment] command
  ["nice", (rest) => {
    let i = 0
    if (rest[i] === "-n" || rest[i] === "--adjustment") {
      i += 2 // -n N
    } else if (rest[i]?.match(/^-n\d/)) {
      i += 1 // -n10
    } else if (rest[i]?.startsWith("--adjustment=")) {
      i += 1 // --adjustment=10
    } else if (rest[i]?.match(/^-\d+$/)) {
      i += 1 // -10 (BSD form)
    }
    return i < rest.length ? i : null
  }],

  // timeout [options] DURATION command
  ["timeout", (rest) => {
    let i = 0
    // Skip flags
    while (i < rest.length) {
      const arg = rest[i]
      // Two-arg flags
      if (arg === "-s" || arg === "--signal" || arg === "-k" || arg === "--kill-after") {
        i += 2
        continue
      }
      // Combined flags: --signal=TERM, --kill-after=5s
      if (arg?.startsWith("--signal=") || arg?.startsWith("--kill-after=") || arg?.startsWith("-k=")) {
        i += 1
        continue
      }
      // Boolean flags
      if (arg === "--preserve-status" || arg === "--foreground" || arg === "-v" || arg === "--verbose") {
        i += 1
        continue
      }
      break
    }
    // Next positional arg is DURATION — skip it
    if (i < rest.length) i += 1
    return i < rest.length ? i : null
  }],
])

/**
 * True when `word`, the path a command line gives a script, is metamax's
 * heavy-run script: `$METAMAX_HOME/scripts/heavy-run.sh` (the variable read
 * as the hook's own value, which scope.metamaxHome holds only when nothing
 * on the line can have changed it), that path written out, or
 * `scripts/heavy-run.sh` run from the top folder of a checkout of metamax's
 * own repository (every place the line could be standing in). A file that
 * only shares the name is not it: another repository's heavy-run.sh could
 * do anything.
 */
function isMetamaxHeavyRun(word: string, scope: Scope): boolean {
  const home = scope.metamaxHome
  if (!home) return false
  const written = word.replace(/^\$(METAMAX_HOME(?!\w)|\{METAMAX_HOME\})/, home)
  if (written === `${home}/scripts/heavy-run.sh`) return true
  if (word !== "scripts/heavy-run.sh" && word !== "./scripts/heavy-run.sh") return false
  // The checkout's own copy: the file its repository tracks, not a symlink
  // or an untracked file put in its place.
  return scope.places !== null && scope.places.every((place) =>
    isTopOfSameRepository(place, home) && gitTracksFile(place, word) && isRegularFile(resolve(place, word)))
}

function isRegularFile(path: string): boolean {
  try {
    return lstatSync(path).isFile()
  } catch {
    return false
  }
}

/** Shells that run metamax's heavy-run script as a file: `bash "$METAMAX_HOME/scripts/heavy-run.sh" …`. */
const SCRIPT_SHELLS = new Set(["bash", "sh", "zsh"])

/**
 * The command metamax's heavy-run script runs, or null when `cmdInfo` is not
 * that script. heavy-run.sh waits for a machine-wide place for a test suite
 * and then runs its arguments, so it changes when the command runs, not what
 * it does. It takes one flag, `--landing`; any other flag before the command
 * is one hall-pass does not know, and the line is judged as written. Run by a
 * shell, only the plain `bash <script> …` form counts, with no shell flags.
 * The inner command is named as the parser would name it typed bare, and
 * keeps the standard input the line gives the script.
 */
function heavyRunInner(cmdInfo: CommandInfo, scope: Scope): CommandInfo | null {
  const first = cmdInfo.path ?? cmdInfo.args[0]!
  let rest: string[]
  if (first.split("/").pop() === "heavy-run.sh" && isMetamaxHeavyRun(first, scope)) {
    rest = cmdInfo.args.slice(1)
  } else if (SCRIPT_SHELLS.has(cmdInfo.name) && cmdInfo.args[1] !== undefined && isMetamaxHeavyRun(cmdInfo.args[1], scope)) {
    rest = cmdInfo.args.slice(2)
  } else {
    return null
  }
  if (rest[0] === "--landing") rest = rest.slice(1)
  if (rest.length === 0 || rest[0]!.startsWith("-")) return null
  const word = rest[0]!
  const name = word.split("/").pop()!
  // Everything else about the command carries over: its assignments, and
  // the standard input the script hands on (a heredoc, a pipe), which the
  // interpreter and database rules read.
  const { path: _script, ...carried } = cmdInfo
  return {
    ...carried,
    name,
    args: [name, ...rest.slice(1)],
    ...(word !== name && { path: word }),
  }
}

/**
 * If the command is a transparent wrapper, unwrap it to get the real
 * inner command. Recurses to handle nesting (e.g., nohup nice bun ...).
 * Returns the original CommandInfo if it's not a wrapper. metamax's
 * heavy-run script is looked through only with a scope, which says where
 * metamax lives and where the line stands.
 */
export function unwrapCommand(cmdInfo: CommandInfo, scope?: Scope): CommandInfo {
  const heavy = scope ? heavyRunInner(cmdInfo, scope) : null
  if (heavy) return unwrapCommand(heavy, scope)

  const skipper = TRANSPARENT_WRAPPERS.get(cmdInfo.name)
  if (!skipper) return cmdInfo

  // args is [wrapperName, ...rest]
  const rest = cmdInfo.args.slice(1)
  const innerStart = skipper(rest)
  if (innerStart === null || innerStart >= rest.length) return cmdInfo

  const innerArgs = rest.slice(innerStart)
  if (innerArgs.length === 0) return cmdInfo

  const innerName = innerArgs[0]!
  const innerCmd: CommandInfo = {
    name: innerName,
    args: innerArgs,
    assigns: cmdInfo.assigns, // pass through env var assigns
  }

  // Recurse to handle nesting
  return unwrapCommand(innerCmd, scope)
}

/** Exported for testing */
export { TRANSPARENT_WRAPPERS }
