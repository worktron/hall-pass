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
import { checkGitCommand } from "./git.ts"
import { DANGEROUS_ENV_VARS } from "./safelist.ts"

export type Inspector = (cmdInfo: CommandInfo, ctx: EvalContext) => EvalResult

const allow = (reason: string): EvalResult => ({ decision: "allow", reason })
const prompt = (reason: string, message: string): EvalResult => ({ decision: "prompt", reason, message })

export const INSPECTORS: Record<string, Inspector> = {
  // -- Version control --

  git: (cmdInfo, ctx) => {
    const decision = checkGitCommand(cmdInfo.args, ctx.protectedBranches)
    return decision.safe ? allow("git: safe") : prompt(decision.reason, decision.message)
  },

  // -- Commands that proxy other commands --

  xargs: (cmdInfo, ctx) => {
    const args = cmdInfo.args
    // xargs [flags] command [initial-args...]
    for (let i = 1; i < args.length; i++) {
      const arg = args[i]!
      // Skip xargs flags and their values
      if (arg === "-I" || arg === "-L" || arg === "-n" || arg === "-P" ||
          arg === "-d" || arg === "-s" || arg === "-a" || arg === "-R") {
        i++ // skip value
        continue
      }
      if (arg.startsWith("-")) continue
      // Everything from here is the sub-command + its args
      const subArgs = args.slice(i)
      const subCmd: CommandInfo = { name: subArgs[0]!, args: subArgs, assigns: [] }
      return ctx.evaluate(subCmd)
    }
    // No command specified — xargs defaults to echo, which is safe
    return allow("xargs: defaults to echo")
  },

  source: () => {
    // source/. executes arbitrary scripts — always prompt
    return prompt("source: executes arbitrary scripts", `"source" executes an external script`)
  },

  eval: (cmdInfo, ctx) => {
    const args = cmdInfo.args
    if (args.length === 1) return allow("eval: no args")
    // eval concatenates all args and re-parses — parse with shfmt
    const script = args.slice(1).join(" ")
    const proc = Bun.spawnSync(["shfmt", "-ln", "bash", "--tojson"], {
      stdin: Buffer.from(script),
    })
    if (proc.exitCode !== 0) {
      return prompt("eval: script parse failed", `Could not parse "eval" script`)
    }
    let ast: unknown
    try {
      ast = JSON.parse(proc.stdout.toString())
    } catch {
      return prompt("eval: JSON parse failed", `Could not parse "eval" script`)
    }
    const subCommands = extractCommandInfos(ast)
    if (subCommands.length === 0) return allow("eval: no commands")
    for (const subCmd of subCommands) {
      const result = ctx.evaluate(subCmd)
      if (result.decision !== "allow") return result
    }
    return allow("eval: all commands safe")
  },

  exec: (cmdInfo, ctx) => {
    const args = cmdInfo.args
    if (args.length === 1) return allow("exec: no args")
    // exec [-cl] [-a name] command [args...]
    for (let i = 1; i < args.length; i++) {
      const arg = args[i]!
      if (arg === "-c" || arg === "-l" || arg === "-cl" || arg === "-lc") continue
      if (arg === "-a") { i++; continue }
      // First non-flag arg is the command to run
      const subArgs = args.slice(i)
      const subCmd: CommandInfo = { name: subArgs[0]!, args: subArgs, assigns: [] }
      return ctx.evaluate(subCmd)
    }
    return allow("exec: no command found")
  },

  sh: (cmdInfo, ctx) => shellInspector(cmdInfo, ctx),
  bash: (cmdInfo, ctx) => shellInspector(cmdInfo, ctx),
  zsh: (cmdInfo, ctx) => shellInspector(cmdInfo, ctx),

  env: (cmdInfo, ctx) => {
    const args = cmdInfo.args
    // bare `env` prints environment — safe
    if (args.length === 1) return allow("env: prints environment")

    for (let i = 1; i < args.length; i++) {
      const arg = args[i]!
      // Skip flags
      if (arg === "-i" || arg === "--ignore-environment" || arg === "-0" || arg === "--null") continue
      if (arg === "-u" || arg === "--unset") { i++; continue }
      if (arg.startsWith("-u") || arg.startsWith("--unset=")) continue
      if (arg === "--") { i++; /* next is command */ break }

      // VAR=val assignment — check for dangerous vars
      if (arg.includes("=")) {
        const varName = arg.split("=")[0]!
        if (DANGEROUS_ENV_VARS.has(varName)) {
          return prompt(`env: dangerous var ${varName}`, `Sets dangerous variable "${varName}"`)
        }
        continue
      }

      // First non-flag, non-assignment arg is the command
      const subArgs = args.slice(i)
      const subCmd: CommandInfo = { name: subArgs[0]!, args: subArgs, assigns: [] }
      return ctx.evaluate(subCmd)
    }

    return allow("env: no command")
  },

  command: (cmdInfo, ctx) => {
    const args = cmdInfo.args
    if (args.length === 1) return allow("command: no args")

    for (let i = 1; i < args.length; i++) {
      const arg = args[i]!
      // command -v / -V just prints command info (like which)
      if (arg === "-v" || arg === "-V") return allow("command: lookup")
      if (arg === "-p") continue // use default PATH
      if (arg === "--") { i++; break }

      // First non-flag arg is the command to run
      const subArgs = args.slice(i)
      const subCmd: CommandInfo = { name: subArgs[0]!, args: subArgs, assigns: [] }
      return ctx.evaluate(subCmd)
    }

    return allow("command: no command found")
  },

  // -- Commands with dangerous flag variants --

  perl: (cmdInfo) => {
    for (const arg of cmdInfo.args) {
      if (arg === "-e" || arg === "-E") return prompt("perl: inline code", "Perl -e runs arbitrary inline code")
    }
    return allow("perl: script runner")
  },

  ruby: (cmdInfo) => {
    for (const arg of cmdInfo.args) {
      if (arg === "-e") return prompt("ruby: inline code", "Ruby -e runs arbitrary inline code")
    }
    return allow("ruby: script runner")
  },


  find: (cmdInfo, ctx) => {
    const args = cmdInfo.args
    // find is safe UNLESS it uses -exec, -execdir, -delete, or -ok
    for (let i = 0; i < args.length; i++) {
      const arg = args[i]!

      // -delete and -ok always prompt (no sub-command to inspect)
      if (arg === "-delete") return prompt("find: -delete", `"find -delete" permanently removes matched files`)
      if (arg === "-ok") return prompt("find: -ok", `"find -ok" executes a command on matched files`)

      if (arg === "-exec" || arg === "-execdir") {
        // Extract sub-command: everything from next arg up to ; or +
        const subArgs: string[] = []
        for (let j = i + 1; j < args.length; j++) {
          if (args[j] === ";" || args[j] === "+") {
            i = j // skip past terminator
            break
          }
          subArgs.push(args[j]!)
        }
        if (subArgs.length === 0) return prompt("find: empty -exec", `"find -exec" with no command specified`)
        const subCmd: CommandInfo = { name: subArgs[0]!, args: subArgs, assigns: [] }
        const result = ctx.evaluate(subCmd)
        if (result.decision !== "allow") return result
      }
    }
    return allow("find: safe")
  },

  sed: (cmdInfo) => {
    // sed is safe UNLESS it uses -i (in-place editing)
    for (const arg of cmdInfo.args) {
      if (arg === "-i" || arg.startsWith("-i")) return prompt("sed: -i in-place", `"sed -i" edits files in-place`)
    }
    return allow("sed: read-only")
  },

  awk: (cmdInfo) => {
    // awk is safe UNLESS the script contains system() or getline
    for (const arg of cmdInfo.args) {
      if (arg.startsWith("-")) continue
      if (arg.includes("system(") || arg.includes("system (")) return prompt("awk: system()", "awk script calls system() to execute shell commands")
      if (arg.includes("| getline") || arg.includes("|getline")) return prompt("awk: getline", "awk script uses getline which can execute commands")
    }
    return allow("awk: safe")
  },

  kill: (cmdInfo) => {
    const args = cmdInfo.args
    // kill [-signal] pid...
    let signalSeen = false
    for (let i = 1; i < args.length; i++) {
      const arg = args[i]!
      if (arg === "-s") { i++; signalSeen = true; continue }
      if (arg === "-l" || arg === "--list") continue
      if (!signalSeen && (/^-\d+$/.test(arg) || /^-[A-Z]+$/.test(arg))) {
        signalSeen = true
        continue
      }
      if (arg === "1" || arg === "-1") return prompt("kill: dangerous PID", "Sending signal to PID 1 affects critical system processes")
    }
    return allow("kill: safe")
  },

  chmod: (cmdInfo) => {
    const args = cmdInfo.args
    for (let i = 1; i < args.length; i++) {
      const arg = args[i]!
      if (arg.startsWith("-")) continue
      if (/^\d{3,4}$/.test(arg)) {
        const mode = arg.length === 4 ? arg : "0" + arg
        const special = parseInt(mode[0]!)
        const other = parseInt(mode[3]!)
        if (special > 0) return prompt("chmod: setuid/setgid/sticky", "Sets setuid/setgid bit which can escalate privileges")
        if (other >= 6) return prompt("chmod: world-writable", "Makes file world-writable")
      }
      if (/[+]s/.test(arg)) return prompt("chmod: setuid/setgid", "Sets setuid/setgid bit which can escalate privileges")
      if (/[oa][+]w/.test(arg)) return prompt("chmod: world-writable", "Makes file world-writable")
      if (arg === "777" || arg === "666") return prompt("chmod: unsafe mode", `chmod ${arg} makes file world-readable and writable`)
    }
    return allow("chmod: safe")
  },

  docker: (cmdInfo) => {
    const args = cmdInfo.args
    if (args.length < 2) return allow("docker: no subcommand")
    const subcmd = args[1]!

    const safeSubcmds = new Set([
      "ps", "images", "logs", "inspect", "stats", "top",
      "version", "info", "network", "volume", "system",
      "build", "pull", "tag", "login", "logout",
      "compose", "container", "image",
    ])
    if (safeSubcmds.has(subcmd)) return allow(`docker: ${subcmd}`)

    if (subcmd === "run" || subcmd === "exec") {
      for (const arg of args) {
        if (arg === "--privileged") return prompt("docker: --privileged", "Docker --privileged gives full host access")
        if (arg === "--pid=host" || arg === "--net=host" || arg === "--network=host") {
          return prompt("docker: host namespace", "Docker with host namespace shares host's process/network space")
        }
        if (arg.startsWith("-v") || arg.startsWith("--volume")) {
          const vol = arg.includes("=") ? arg.split("=")[1] : args[args.indexOf(arg) + 1]
          if (vol && vol.startsWith("/:/")) return prompt("docker: root volume mount", "Docker mounts root filesystem into container")
        }
      }
      return allow(`docker: ${subcmd}`)
    }

    if (subcmd === "stop" || subcmd === "rm" || subcmd === "rmi" || subcmd === "restart") {
      return allow(`docker: ${subcmd}`)
    }

    return prompt(`docker: unknown subcommand ${subcmd}`, `Unknown docker subcommand "${subcmd}"`)
  },

  node: (cmdInfo) => {
    for (const arg of cmdInfo.args) {
      if (arg === "-e" || arg === "--eval" || arg === "-p" || arg === "--print") {
        return prompt("node: inline code", "Node -e/--eval runs arbitrary inline code")
      }
    }
    return allow("node: script runner")
  },

  python: (cmdInfo) => {
    for (const arg of cmdInfo.args) {
      if (arg === "-c") return prompt("python: inline code", "Python -c runs arbitrary inline code")
    }
    return allow("python: script runner")
  },

  python3: (cmdInfo) => {
    for (const arg of cmdInfo.args) {
      if (arg === "-c") return prompt("python3: inline code", "Python -c runs arbitrary inline code")
    }
    return allow("python3: script runner")
  },

  // -- Command wrappers (proxy another command) --

  xcrun: (cmdInfo, ctx) => {
    const args = cmdInfo.args
    // xcrun [options] tool [args...]
    for (let i = 1; i < args.length; i++) {
      const arg = args[i]!
      if (arg === "--sdk" || arg === "--toolchain") { i++; continue }
      if (arg === "--find" || arg === "--show-sdk-path" || arg === "--show-sdk-version" ||
          arg === "--show-sdk-platform-path" || arg === "--show-sdk-platform-version") {
        return allow("xcrun: info query")
      }
      if (arg === "-l" || arg === "--log" || arg === "-n" || arg === "--no-cache") continue
      if (arg.startsWith("-")) continue
      // First non-flag arg is the tool to run
      const subArgs = args.slice(i)
      const subCmd: CommandInfo = { name: subArgs[0]!, args: subArgs, assigns: [] }
      return ctx.evaluate(subCmd)
    }
    return allow("xcrun: no tool specified")
  },

  // -- Remote access & scripting --

  ssh: () => {
    return prompt("ssh: remote access", "SSH opens a remote shell session")
  },

  osascript: () => {
    return prompt("osascript: AppleScript execution", "osascript can execute system-level AppleScript commands")
  },

  // -- Commands with safe/unsafe subcommands --

  defaults: (cmdInfo) => {
    const args = cmdInfo.args
    if (args.length < 2) return allow("defaults: no subcommand")
    const subcmd = args[1]!
    const readCmds = new Set(["read", "read-type", "find", "domains", "export"])
    if (readCmds.has(subcmd)) return allow(`defaults: ${subcmd}`)
    return prompt(`defaults: ${subcmd}`, `"defaults ${subcmd}" modifies macOS system preferences`)
  },

  launchctl: (cmdInfo) => {
    const args = cmdInfo.args
    if (args.length < 2) return allow("launchctl: no subcommand")
    const subcmd = args[1]!
    const safeCmds = new Set(["list", "print", "blame", "dumpstate", "dumpjpcategory"])
    if (safeCmds.has(subcmd)) return allow(`launchctl: ${subcmd}`)
    return prompt(`launchctl: ${subcmd}`, `"launchctl ${subcmd}" modifies system services`)
  },

  networksetup: (cmdInfo) => {
    const args = cmdInfo.args
    for (const arg of args) {
      if (arg.startsWith("-set") || arg.startsWith("-create") ||
          arg.startsWith("-remove") || arg.startsWith("-add") ||
          arg === "-ordernetworkservices" || arg === "-switchtodefault") {
        return prompt("networksetup: modifies network config", "networksetup modifies system network configuration")
      }
    }
    return allow("networksetup: read-only query")
  },

  security: (cmdInfo) => {
    const args = cmdInfo.args
    if (args.length < 2) return allow("security: no subcommand")
    const subcmd = args[1]!
    // Read-only info queries that don't reveal secrets
    const safeCmds = new Set([
      "list-keychains", "default-keychain", "login-keychain",
      "show-keychain-info", "find-certificate", "verify-cert", "error",
    ])
    if (safeCmds.has(subcmd)) return allow(`security: ${subcmd}`)
    return prompt(`security: ${subcmd}`, `"security ${subcmd}" accesses or modifies Keychain data`)
  },

  railway: (cmdInfo, ctx) => {
    const args = cmdInfo.args
    if (args.length < 2) return allow("railway: no subcommand")
    // Skip flags like --json, -e, --environment before the subcommand
    let subcmdIdx = 1
    while (subcmdIdx < args.length) {
      const arg = args[subcmdIdx]!
      if (arg === "-e" || arg === "--environment" || arg === "--service" || arg === "--project") {
        subcmdIdx += 2
        continue
      }
      if (arg === "--json" || arg === "-j") { subcmdIdx++; continue }
      if (arg.startsWith("-")) { subcmdIdx++; continue }
      break
    }
    if (subcmdIdx >= args.length) return allow("railway: flags only")
    const subcmd = args[subcmdIdx]!

    const safeCmds = new Set([
      "whoami", "status", "logs", "version",
      "init", "link", "unlink", "service",
      "variables", "environment", "domain", "volume",
      "login", "logout", "docs", "shell", "open",
      "list",
    ])
    if (safeCmds.has(subcmd)) return allow(`railway: ${subcmd}`)

    // `railway run` proxies another command — evaluate the inner command
    if (subcmd === "run") {
      const innerArgs = args.slice(subcmdIdx + 1)
      if (innerArgs.length === 0) return prompt("railway run: no command", "railway run with no command")
      const subCmd: CommandInfo = { name: innerArgs[0]!, args: innerArgs, assigns: [] }
      return ctx.evaluate(subCmd)
    }

    return prompt(`railway: ${subcmd}`, `"railway ${subcmd}" may modify deployment state`)
  },

  "redis-cli": (cmdInfo) => {
    const args = cmdInfo.args
    // redis-cli [options] [command [args...]]
    // Find the Redis command (first non-flag, non-value positional arg)
    const READ_ONLY_CMDS = new Set([
      "ping", "echo", "info", "dbsize", "time", "lastsave",
      "get", "mget", "strlen", "getrange", "exists", "type", "ttl", "pttl",
      "keys", "scan", "randomkey", "object",
      "llen", "lrange", "lindex",
      "scard", "smembers", "sismember", "srandmember", "sscan",
      "hget", "hgetall", "hlen", "hkeys", "hvals", "hexists", "hmget", "hscan",
      "zcard", "zrange", "zrangebyscore", "zscore", "zrank", "zscan", "zcount",
      "xlen", "xrange", "xrevrange", "xinfo",
      "pubsub", "client",
    ])
    for (let i = 1; i < args.length; i++) {
      const arg = args[i]!
      // Skip redis-cli flags and their values
      if (arg === "-h" || arg === "-p" || arg === "-a" || arg === "-n" ||
          arg === "-u" || arg === "--user" || arg === "--pass" ||
          arg === "--tls-cert" || arg === "--tls-key" || arg === "--tls-ca-cert") {
        i++; continue
      }
      if (arg === "--tls" || arg === "--no-auth-warning" || arg === "--resp2" || arg === "--resp3") continue
      if (arg.startsWith("-")) continue
      // First positional is the Redis command
      if (READ_ONLY_CMDS.has(arg.toLowerCase())) {
        return allow(`redis-cli: ${arg.toLowerCase()}`)
      }
      return prompt(`redis-cli: ${arg.toLowerCase()}`, `redis-cli "${arg.toLowerCase()}" can modify data`)
    }
    // No command = interactive mode
    return prompt("redis-cli: interactive session", "Interactive redis-cli session has unrestricted access")
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
    return prompt(`${shell}: script execution`, `Running "${shell}" with a script file`)
  }

  if (!script) {
    return prompt(`${shell}: -c with empty script`, `"${shell} -c" with empty script`)
  }

  // Parse the inline script with shfmt
  const proc = Bun.spawnSync(["shfmt", "-ln", "bash", "--tojson"], {
    stdin: Buffer.from(script),
  })

  if (proc.exitCode !== 0) {
    return prompt(`${shell}: -c script parse failed`, `Could not parse inline "${shell} -c" script`)
  }

  let ast: unknown
  try {
    ast = JSON.parse(proc.stdout.toString())
  } catch {
    return prompt(`${shell}: -c script JSON parse failed`, `Could not parse inline "${shell} -c" script`)
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
