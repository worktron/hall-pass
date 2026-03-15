/**
 * Argument inspectors for commands that need deeper safety checking.
 *
 * Each inspector takes a parsed CommandInfo and EvalContext, and returns
 * an EvalResult. Inspectors may recurse via ctx.evaluate() for sub-commands
 * (find -exec, xargs), giving sub-commands the full evaluation pipeline.
 */

import type { CommandInfo } from "./parser.ts"
import { extractCommandInfos } from "./parser.ts"
import type { EvalResult, EvalContext } from "./evaluate.ts"
import { isGitCommandSafe } from "./git.ts"
import { DANGEROUS_ENV_VARS } from "./safelist.ts"

export type Inspector = (cmdInfo: CommandInfo, ctx: EvalContext) => EvalResult

const allow = (reason: string): EvalResult => ({ decision: "allow", reason })
const prompt = (reason: string): EvalResult => ({ decision: "prompt", reason })

export const INSPECTORS: Record<string, Inspector> = {
  // -- Version control --

  git: (cmdInfo, ctx) => {
    const safe = isGitCommandSafe(cmdInfo.args, ctx.protectedBranches)
    return safe ? allow("git: safe") : prompt("git: unsafe")
  },

  // -- Commands that proxy other commands --

  xargs: (cmdInfo, ctx) => {
    const args = cmdInfo.args
    // xargs [flags] command [initial-args...]
    for (let i = 1; i < args.length; i++) {
      const arg = args[i]
      // Skip xargs flags and their values
      if (arg === "-I" || arg === "-L" || arg === "-n" || arg === "-P" ||
          arg === "-d" || arg === "-s" || arg === "-a" || arg === "-R") {
        i++ // skip value
        continue
      }
      if (arg.startsWith("-")) continue
      // Everything from here is the sub-command + its args
      const subArgs = args.slice(i)
      const subCmd: CommandInfo = { name: subArgs[0], args: subArgs, assigns: [] }
      return ctx.evaluate(subCmd)
    }
    // No command specified — xargs defaults to echo, which is safe
    return allow("xargs: defaults to echo")
  },

  source: () => {
    // source/. executes arbitrary scripts — always prompt
    return prompt("source: executes arbitrary scripts")
  },

  sh: (cmdInfo, ctx) => shellInspector(cmdInfo, ctx),
  bash: (cmdInfo, ctx) => shellInspector(cmdInfo, ctx),
  zsh: (cmdInfo, ctx) => shellInspector(cmdInfo, ctx),

  env: (cmdInfo, ctx) => {
    const args = cmdInfo.args
    // bare `env` prints environment — safe
    if (args.length === 1) return allow("env: prints environment")

    for (let i = 1; i < args.length; i++) {
      const arg = args[i]
      // Skip flags
      if (arg === "-i" || arg === "--ignore-environment" || arg === "-0" || arg === "--null") continue
      if (arg === "-u" || arg === "--unset") { i++; continue }
      if (arg.startsWith("-u") || arg.startsWith("--unset=")) continue
      if (arg === "--") { i++; /* next is command */ break }

      // VAR=val assignment — check for dangerous vars
      if (arg.includes("=")) {
        const varName = arg.split("=")[0]
        if (DANGEROUS_ENV_VARS.has(varName)) {
          return prompt(`env: dangerous var ${varName}`)
        }
        continue
      }

      // First non-flag, non-assignment arg is the command
      const subArgs = args.slice(i)
      const subCmd: CommandInfo = { name: subArgs[0], args: subArgs, assigns: [] }
      return ctx.evaluate(subCmd)
    }

    return allow("env: no command")
  },

  command: (cmdInfo, ctx) => {
    const args = cmdInfo.args
    if (args.length === 1) return allow("command: no args")

    for (let i = 1; i < args.length; i++) {
      const arg = args[i]
      // command -v / -V just prints command info (like which)
      if (arg === "-v" || arg === "-V") return allow("command: lookup")
      if (arg === "-p") continue // use default PATH
      if (arg === "--") { i++; break }

      // First non-flag arg is the command to run
      const subArgs = args.slice(i)
      const subCmd: CommandInfo = { name: subArgs[0], args: subArgs, assigns: [] }
      return ctx.evaluate(subCmd)
    }

    return allow("command: no command found")
  },

  // -- Commands with dangerous flag variants --

  perl: (cmdInfo) => {
    for (const arg of cmdInfo.args) {
      if (arg === "-e" || arg === "-E") return prompt("perl: inline code")
    }
    return allow("perl: script runner")
  },

  ruby: (cmdInfo) => {
    for (const arg of cmdInfo.args) {
      if (arg === "-e") return prompt("ruby: inline code")
    }
    return allow("ruby: script runner")
  },


  find: (cmdInfo, ctx) => {
    const args = cmdInfo.args
    // find is safe UNLESS it uses -exec, -execdir, -delete, or -ok
    for (let i = 0; i < args.length; i++) {
      const arg = args[i]

      // -delete and -ok always prompt (no sub-command to inspect)
      if (arg === "-delete" || arg === "-ok") return prompt(`find: ${arg}`)

      if (arg === "-exec" || arg === "-execdir") {
        // Extract sub-command: everything from next arg up to ; or +
        const subArgs: string[] = []
        for (let j = i + 1; j < args.length; j++) {
          if (args[j] === ";" || args[j] === "+") {
            i = j // skip past terminator
            break
          }
          subArgs.push(args[j])
        }
        if (subArgs.length === 0) return prompt("find: empty -exec")
        const subCmd: CommandInfo = { name: subArgs[0], args: subArgs, assigns: [] }
        const result = ctx.evaluate(subCmd)
        if (result.decision !== "allow") return result
      }
    }
    return allow("find: safe")
  },

  sed: (cmdInfo) => {
    // sed is safe UNLESS it uses -i (in-place editing)
    for (const arg of cmdInfo.args) {
      if (arg === "-i" || arg.startsWith("-i")) return prompt("sed: -i in-place")
    }
    return allow("sed: read-only")
  },

  awk: (cmdInfo) => {
    // awk is safe UNLESS the script contains system() or getline
    for (const arg of cmdInfo.args) {
      if (arg.startsWith("-")) continue
      if (arg.includes("system(") || arg.includes("system (")) return prompt("awk: system()")
      if (arg.includes("| getline") || arg.includes("|getline")) return prompt("awk: getline")
    }
    return allow("awk: safe")
  },

  kill: (cmdInfo) => {
    const args = cmdInfo.args
    // kill [-signal] pid...
    let signalSeen = false
    for (let i = 1; i < args.length; i++) {
      const arg = args[i]
      if (arg === "-s") { i++; signalSeen = true; continue }
      if (arg === "-l" || arg === "--list") continue
      if (!signalSeen && (/^-\d+$/.test(arg) || /^-[A-Z]+$/.test(arg))) {
        signalSeen = true
        continue
      }
      if (arg === "1" || arg === "-1") return prompt("kill: dangerous PID")
    }
    return allow("kill: safe")
  },

  chmod: (cmdInfo) => {
    const args = cmdInfo.args
    for (let i = 1; i < args.length; i++) {
      const arg = args[i]
      if (arg.startsWith("-")) continue
      if (/^\d{3,4}$/.test(arg)) {
        const mode = arg.length === 4 ? arg : "0" + arg
        const special = parseInt(mode[0])
        const other = parseInt(mode[3])
        if (special > 0) return prompt("chmod: setuid/setgid/sticky")
        if (other >= 6) return prompt("chmod: world-writable")
      }
      if (/[+]s/.test(arg)) return prompt("chmod: setuid/setgid")
      if (/[oa][+]w/.test(arg)) return prompt("chmod: world-writable")
      if (arg === "777" || arg === "666") return prompt("chmod: unsafe mode")
    }
    return allow("chmod: safe")
  },

  docker: (cmdInfo) => {
    const args = cmdInfo.args
    if (args.length < 2) return allow("docker: no subcommand")
    const subcmd = args[1]

    const safeSubcmds = new Set([
      "ps", "images", "logs", "inspect", "stats", "top",
      "version", "info", "network", "volume", "system",
      "build", "pull", "tag", "login", "logout",
      "compose", "container", "image",
    ])
    if (safeSubcmds.has(subcmd)) return allow(`docker: ${subcmd}`)

    if (subcmd === "run" || subcmd === "exec") {
      for (const arg of args) {
        if (arg === "--privileged") return prompt("docker: --privileged")
        if (arg === "--pid=host" || arg === "--net=host" || arg === "--network=host") {
          return prompt("docker: host namespace")
        }
        if (arg.startsWith("-v") || arg.startsWith("--volume")) {
          const vol = arg.includes("=") ? arg.split("=")[1] : args[args.indexOf(arg) + 1]
          if (vol && vol.startsWith("/:/")) return prompt("docker: root volume mount")
        }
      }
      return allow(`docker: ${subcmd}`)
    }

    if (subcmd === "stop" || subcmd === "rm" || subcmd === "rmi" || subcmd === "restart") {
      return allow(`docker: ${subcmd}`)
    }

    return prompt(`docker: unknown subcommand ${subcmd}`)
  },

  node: (cmdInfo) => {
    for (const arg of cmdInfo.args) {
      if (arg === "-e" || arg === "--eval" || arg === "-p" || arg === "--print") {
        return prompt("node: inline code")
      }
    }
    return allow("node: script runner")
  },

  python: (cmdInfo) => {
    for (const arg of cmdInfo.args) {
      if (arg === "-c") return prompt("python: inline code")
    }
    return allow("python: script runner")
  },

  python3: (cmdInfo) => {
    for (const arg of cmdInfo.args) {
      if (arg === "-c") return prompt("python3: inline code")
    }
    return allow("python3: script runner")
  },
}

/**
 * Inspector for sh/bash/zsh -c 'script'.
 * Parses the inline script with shfmt and evaluates each sub-command
 * through the full pipeline. Without -c, prompts (arbitrary script file).
 */
function shellInspector(cmdInfo: CommandInfo, ctx: EvalContext): EvalResult {
  const args = cmdInfo.args
  const shell = cmdInfo.name

  // Find -c flag
  let script: string | undefined
  for (let i = 1; i < args.length; i++) {
    if (args[i] === "-c") {
      script = args[i + 1]
      break
    }
  }

  // No -c flag — running a script file, always prompt
  if (script === undefined) {
    return prompt(`${shell}: script execution`)
  }

  if (!script) {
    return prompt(`${shell}: -c with empty script`)
  }

  // Parse the inline script with shfmt
  const proc = Bun.spawnSync(["shfmt", "--tojson"], {
    stdin: Buffer.from(script),
  })

  if (proc.exitCode !== 0) {
    return prompt(`${shell}: -c script parse failed`)
  }

  let ast: unknown
  try {
    ast = JSON.parse(proc.stdout.toString())
  } catch {
    return prompt(`${shell}: -c script JSON parse failed`)
  }

  // Extract and evaluate all commands in the inline script
  const subCommands = extractCommandInfos(ast)

  if (subCommands.length === 0) {
    return allow(`${shell} -c: no commands`)
  }

  for (const subCmd of subCommands) {
    const result = ctx.evaluate(subCmd)
    if (result.decision !== "allow") return result
  }

  return allow(`${shell} -c: all commands safe`)
}
