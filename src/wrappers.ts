/**
 * Transparent command wrappers — commands that don't change security
 * properties of the wrapped command. They affect process lifetime,
 * scheduling, or timing, but not what the command actually does.
 *
 * When we encounter one, we strip it and its flags, then evaluate
 * the inner command through the normal pipeline.
 */

import type { CommandInfo } from "./parser.ts"

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
 * If the command is a transparent wrapper, unwrap it to get the real
 * inner command. Recurses to handle nesting (e.g., nohup nice bun ...).
 * Returns the original CommandInfo if it's not a wrapper.
 */
export function unwrapCommand(cmdInfo: CommandInfo): CommandInfo {
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
  return unwrapCommand(innerCmd)
}

/** Exported for testing */
export { TRANSPARENT_WRAPPERS }
