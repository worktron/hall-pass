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
import { checkFilePath } from "./paths.ts"

export type Inspector = (cmdInfo: CommandInfo, ctx: EvalContext) => EvalResult

const allow = (reason: string): EvalResult => ({ decision: "allow", reason })
const prompt = (reason: string, message: string): EvalResult => ({ decision: "prompt", reason, message })

export const INSPECTORS: Record<string, Inspector> = {
  // -- Version control --

  git: (cmdInfo, ctx) => {
    const decision = checkGitCommand(cmdInfo.args, ctx.protectedBranches, ctx.safeSubcommands)
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
    const proc = Bun.spawnSync([ctx.shfmtBin, "-ln", "bash", "--tojson"], {
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
    if (hasInlineCode(cmdInfo.args, PERL_INLINE))
      return prompt("perl: inline code", "Perl -e runs arbitrary inline code")
    return allow("perl: script runner")
  },

  ruby: (cmdInfo) => {
    if (hasInlineCode(cmdInfo.args, RUBY_INLINE))
      return prompt("ruby: inline code", "Ruby -e runs arbitrary inline code")
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

  rsync: (cmdInfo) => {
    const args = cmdInfo.args
    // rsync is cp-equivalent for local copies, UNLESS it deletes destination
    // files, runs a custom transport command, or touches a remote host
    for (let i = 1; i < args.length; i++) {
      const arg = args[i]!
      if (arg === "--delete" || arg === "--del" || arg.startsWith("--delete-")) {
        return prompt("rsync: --delete", `"rsync ${arg}" removes files from the destination`)
      }
      if (arg === "--remove-source-files" || arg === "--remove-sent-files") {
        return prompt("rsync: removes sources", `"rsync ${arg}" deletes source files after transfer`)
      }
      if (arg === "--rsh" || arg.startsWith("--rsh=") || /^-[a-zA-Z0-9]*e/.test(arg)) {
        return prompt("rsync: custom transport", `"rsync -e/--rsh" executes an arbitrary transport command`)
      }
      // Remote path: rsync:// URL, or a colon before the first slash (host: / user@host:)
      if (!arg.startsWith("-") && (arg.startsWith("rsync://") || /^[^/]*:/.test(arg))) {
        return prompt("rsync: remote path", `rsync to/from a remote host ("${arg}") transfers files over the network`)
      }
    }
    return allow("rsync: local copy")
  },

  sed: (cmdInfo, ctx) => {
    // sed only writes with in-place editing. Without it, nothing to check.
    const parsed = parseSedArgs(cmdInfo.args)
    if (!parsed.inPlace) return allow("sed: read-only")

    // "sed -i" does what the Edit tool does, so it gets the same two checks
    // Edit gets in decide.ts: the target path, then the content for secrets.
    // Blanket-prompting instead would be inconsistent with Edit, which
    // auto-approves a write to an unprotected path.
    if (parsed.uncertain || parsed.files.length === 0) {
      return prompt("sed: -i with unverifiable target", `"sed -i" edits in place and the target file could not be determined`)
    }

    for (const file of parsed.files) {
      const decision = checkFilePath(file, "write", ctx.config)
      if (!decision.allowed) {
        return prompt(`path-blocked: sed ${decision.reason}`, `"sed -i" targets ${decision.reason}`)
      }
    }

    // No secret scan here: decide.ts already scans the whole Bash command
    // string for credentials before evaluation ever reaches an inspector.
    return allow(`sed: -i on ${parsed.files.length} unprotected file(s)`)
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
    if (hasInlineCode(cmdInfo.args, NODE_INLINE))
      return prompt("node: inline code", "Node -e/--eval runs arbitrary inline code")
    return allow("node: script runner")
  },

  python: (cmdInfo) => {
    if (hasInlineCode(cmdInfo.args, PYTHON_INLINE))
      return prompt("python: inline code", "Python -c runs arbitrary inline code")
    return allow("python: script runner")
  },

  python3: (cmdInfo) => {
    if (hasInlineCode(cmdInfo.args, PYTHON_INLINE))
      return prompt("python3: inline code", "Python -c runs arbitrary inline code")
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

  tmutil: (cmdInfo) => {
    const args = cmdInfo.args
    if (args.length < 2) return allow("tmutil: no subcommand")
    const subcmd = args[1]!
    const safeCmds = new Set([
      "version", "status", "destinationinfo", "latestbackup", "listbackups",
      "machinedirectory", "calculatedrift", "compare", "uniquesize",
      "isexcludedpath", "associatedisk",
    ])
    if (safeCmds.has(subcmd)) return allow(`tmutil: ${subcmd}`)
    return prompt(`tmutil: ${subcmd}`, `"tmutil ${subcmd}" modifies Time Machine backups`)
  },

  diskutil: (cmdInfo) => {
    const args = cmdInfo.args
    if (args.length < 2) return allow("diskutil: no subcommand")
    const subcmd = args[1]!
    const safeCmds = new Set([
      "list", "info", "activity", "verifyDisk", "verifyVolume",
    ])
    if (safeCmds.has(subcmd)) return allow(`diskutil: ${subcmd}`)
    // `diskutil apfs` has its own subcommands — only allow read-only ones
    if (subcmd === "apfs") {
      const apfsSub = args[2]
      const apfsSafe = new Set(["list", "listUsers", "listCryptoUsers", "listGroups"])
      if (apfsSub && apfsSafe.has(apfsSub)) return allow(`diskutil apfs: ${apfsSub}`)
      return prompt(`diskutil apfs: ${apfsSub ?? "no subcommand"}`, `"diskutil apfs ${apfsSub ?? ""}" can modify APFS volumes`)
    }
    return prompt(`diskutil: ${subcmd}`, `"diskutil ${subcmd}" can modify or erase disks`)
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

  // 1Password CLI. Allow read-only metadata; prompt on anything that exposes
  // secret values (item get, read, document get), mutates vaults, or runs
  // commands with injected secrets (run, inject). Default is prompt — a
  // secrets manager should fail closed.
  op: (cmdInfo) => {
    const args = cmdInfo.args
    // First positional after "op" is the noun/command; second is the verb.
    const positionals = args.slice(1).filter((a) => !a.startsWith("-"))
    const noun = positionals[0]
    const verb = positionals[1]

    // No subcommand (interactive/auth) or auth-only commands — safe.
    if (noun === undefined || noun === "whoami" || noun === "signin" || noun === "signout") {
      return allow(`op: ${noun ?? "interactive"}`)
    }
    // Metadata listings/queries that never return secret values.
    const META_NOUNS = new Set(["account", "vault", "user", "group", "connect", "events-api"])
    if (META_NOUNS.has(noun) && (verb === "list" || verb === "get" || verb === undefined)) {
      return allow(`op: ${noun} ${verb ?? ""}`.trim())
    }
    if (noun === "item" && verb === "list") {
      return allow("op: item list")
    }
    const label = `op: ${noun}${verb ? " " + verb : ""}`
    return prompt(label, `"${label}" may expose secrets, mutate vaults, or run commands`)
  },

  // yt-dlp media downloader. Network fetch + file writes are in the same risk
  // class as curl/wget (already safe). Prompt only when flags can execute
  // arbitrary commands or external programs on downloaded content.
  "yt-dlp": (cmdInfo) => {
    const EXEC_FLAGS = new Set([
      "--exec", "--exec-before-download",
      "--external-downloader", "--downloader", "--downloader-args",
    ])
    for (const arg of cmdInfo.args.slice(1)) {
      const flag = arg.split("=")[0]!
      if (EXEC_FLAGS.has(flag)) {
        return prompt(`yt-dlp: ${flag}`, `yt-dlp "${flag}" can execute arbitrary commands or external programs`)
      }
    }
    return allow("yt-dlp: download")
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

  aws: (cmdInfo) => {
    const args = cmdInfo.args
    // aws [global-options] <service> <verb> [params]
    // Walk past leading global options to find the service token.
    let i = 1
    while (i < args.length) {
      const arg = args[i]!
      if (arg === "--version") return allow("aws: version")
      if (arg === "--help" || arg === "-h" || arg === "help") return allow("aws: help")
      // Boolean global flags
      if (arg === "--debug" || arg === "--no-paginate" || arg === "--no-cli-pager" ||
          arg === "--no-sign-request" || arg === "--no-verify-ssl" ||
          arg === "--cli-auto-prompt" || arg === "--no-cli-auto-prompt") {
        i++; continue
      }
      // Global flags with attached value (--foo=bar)
      if (arg.startsWith("--profile=") || arg.startsWith("--region=") ||
          arg.startsWith("--output=") || arg.startsWith("--query=") ||
          arg.startsWith("--endpoint-url=") || arg.startsWith("--ca-bundle=") ||
          arg.startsWith("--cli-read-timeout=") || arg.startsWith("--cli-connect-timeout=") ||
          arg.startsWith("--color=")) {
        i++; continue
      }
      // Global flags taking the next arg as value
      if (arg === "--profile" || arg === "--region" || arg === "--output" ||
          arg === "--query" || arg === "--endpoint-url" || arg === "--ca-bundle" ||
          arg === "--cli-read-timeout" || arg === "--cli-connect-timeout" ||
          arg === "--color") {
        i += 2; continue
      }
      if (arg.startsWith("-")) { i++; continue }
      break
    }
    if (i >= args.length) return allow("aws: no service")
    const service = args[i]!.toLowerCase()
    const verb = args[i + 1]?.toLowerCase()
    if (!verb || verb === "help" || verb === "--help") return allow(`aws ${service}: help/no verb`)

    // s3 has its own command verbs (not the standard service API verbs)
    if (service === "s3") {
      if (verb === "ls" || verb === "presign") return allow(`aws s3: ${verb}`)
      return prompt(`aws s3: ${verb}`, `"aws s3 ${verb}" can modify or remove S3 objects`)
    }

    // sts: only allow info verbs; assume-role* and federation issue credentials
    if (service === "sts") {
      const safeSts = new Set([
        "get-caller-identity", "get-session-token",
        "get-access-key-info", "decode-authorization-message",
      ])
      if (safeSts.has(verb)) return allow(`aws sts: ${verb}`)
      return prompt(`aws sts: ${verb}`, `"aws sts ${verb}" can issue or assume credentials`)
    }

    // configure: list/get are read-only; set/import/sso modify config
    if (service === "configure") {
      const safeConfigure = new Set(["list", "list-profiles", "get"])
      if (safeConfigure.has(verb)) return allow(`aws configure: ${verb}`)
      return prompt(`aws configure: ${verb}`, `"aws configure ${verb}" modifies AWS CLI config`)
    }

    // sso: login/logout open browsers and rewrite credentials
    if (service === "sso") {
      const safeSso = new Set(["list-accounts", "list-account-roles", "get-role-credentials"])
      if (safeSso.has(verb)) return allow(`aws sso: ${verb}`)
      return prompt(`aws sso: ${verb}`, `"aws sso ${verb}" affects SSO session state`)
    }

    // Generic verb-prefix heuristic for standard service APIs.
    const READ_ONLY_PREFIXES = [
      "describe-", "list-", "get-", "lookup-", "head-", "search-",
      "select-", "view-", "validate-", "check-", "count-", "batch-get-",
    ]
    if (READ_ONLY_PREFIXES.some(p => verb.startsWith(p))) {
      return allow(`aws ${service}: ${verb}`)
    }
    // Service-specific read verbs without a standard prefix
    const READ_ONLY_VERBS = new Set(["scan", "query"])
    if (READ_ONLY_VERBS.has(verb)) return allow(`aws ${service}: ${verb}`)

    return prompt(`aws ${service}: ${verb}`, `"aws ${service} ${verb}" may modify AWS resources`)
  },

  openssl: (cmdInfo) => {
    const args = cmdInfo.args
    if (args.length < 2) return allow("openssl: no subcommand")
    const subcmd = args[1]!.toLowerCase()
    if (subcmd === "version" || subcmd === "--version" || subcmd === "-v" ||
        subcmd === "help" || subcmd === "--help" || subcmd === "-h") {
      return allow(`openssl: ${subcmd}`)
    }

    // Always-safe subcommands: pure information / TLS handshake / verification.
    const ALWAYS_SAFE = new Set([
      "list", "ciphers", "s_client", "verify",
      "asn1parse", "prime", "errstr", "info",
    ])
    if (ALWAYS_SAFE.has(subcmd)) return allow(`openssl: ${subcmd}`)

    // Inspect-style subcommands: read by default, but several flags turn them
    // into write/sign operations.
    const INSPECT_SUBCMDS = new Set(["x509", "rsa", "ec", "pkey", "dgst", "dsa", "crl", "req"])
    if (INSPECT_SUBCMDS.has(subcmd)) {
      const WRITE_FLAGS = new Set(["-out", "-signkey", "-CAkey", "-keyout", "-passout"])
      // `req -new`/`-newkey`/`-x509` create a CSR or self-signed cert (often with a key)
      if (subcmd === "req") {
        for (const arg of args.slice(2)) {
          if (arg === "-new" || arg === "-newkey" || arg === "-x509") {
            return prompt(`openssl req: ${arg}`, `"openssl req ${arg}" generates keys or self-signed certs`)
          }
        }
      }
      for (const arg of args.slice(2)) {
        if (WRITE_FLAGS.has(arg)) {
          return prompt(`openssl ${subcmd}: ${arg}`, `"openssl ${subcmd} ${arg}" writes key material or signed output`)
        }
      }
      return allow(`openssl: ${subcmd}`)
    }

    return prompt(`openssl: ${subcmd}`, `"openssl ${subcmd}" can generate keys, sign, or encrypt`)
  },

  tailscale: (cmdInfo, ctx) => tailscaleInspector(cmdInfo, ctx),

  // The macOS app bundle ships the binary as .../MacOS/Tailscale, and the
  // parser basenames command paths — so the capitalized name has to map to
  // the same inspector or the app-bundle path escapes inspection entirely.
  Tailscale: (cmdInfo, ctx) => tailscaleInspector(cmdInfo, ctx),

  xattr: (cmdInfo) => {
    // xattr [-lrsvx] file...                  list/print (read)
    // xattr -p [-lrsvx] attr_name file...      print specific attr (read)
    // xattr -w [-rsx] attr_name value file...  write attr (modifies file metadata)
    // xattr -d [-rsv] attr_name file...        delete attr
    // xattr -c [-rsv] file...                  clear all attrs
    const args = cmdInfo.args
    for (let i = 1; i < args.length; i++) {
      const arg = args[i]!
      if (!arg.startsWith("-") || arg === "-") break
      // Long flags
      if (arg === "--help" || arg === "--version") return allow("xattr: help/version")
      // Short flag bundles like -lp, -ls. Check each char.
      for (const ch of arg.slice(1)) {
        if (ch === "w" || ch === "d" || ch === "c") {
          return prompt(`xattr: -${ch}`, `"xattr -${ch}" modifies file extended attributes`)
        }
      }
    }
    return allow("xattr: read-only")
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

  // -- Publishing / project CLIs --

  dfract: (cmdInfo) => {
    // dfract <subcommand> [file] [--flags] — publishes markdown to Google Docs.
    const args = cmdInfo.args
    const sub = args[1]?.toLowerCase()
    if (!sub) return allow("dfract: no subcommand")
    if (sub === "--version" || sub === "-v") return allow("dfract: version")
    if (sub === "help" || sub === "--help" || sub === "-h") return allow("dfract: help")

    // Read-only: inspect local state or fetch from Drive without writing.
    const safeCmds = new Set(["status", "check", "list", "revisions", "preview"])
    if (safeCmds.has(sub)) return allow(`dfract: ${sub}`)

    // publish writes to a Google Doc, but Drive keeps full revision history
    // and it is the command this is actually used for.
    if (sub === "publish") return allow("dfract: publish")

    // merge overwrites the LOCAL markdown from the doc — that loses uncommitted
    // edits, so it prompts. auth/init/mv/export/docx/style-import write too.
    return prompt(`dfract: ${sub}`, `"dfract ${sub}" writes files or credentials`)
  },

  claude: (cmdInfo) => {
    // Spawning Claude Code from inside a hook: `-p` runs an autonomous agent,
    // and `mcp add` / `config set` rewrite settings this hook is enforcing.
    const args = cmdInfo.args
    const sub = args[1]?.toLowerCase()
    if (!sub) {
      return prompt("claude: interactive session", "Starts an interactive Claude Code session")
    }
    if (sub === "--version" || sub === "-v") return allow("claude: version")
    if (sub === "help" || sub === "--help" || sub === "-h") return allow("claude: help")
    if (sub === "doctor") return allow("claude: doctor")

    // Sub-subcommand readers
    const verb = args[2]?.toLowerCase()
    if (sub === "mcp" || sub === "plugin" || sub === "config") {
      const readVerbs = new Set(["list", "get", "ls"])
      if (!verb || readVerbs.has(verb)) return allow(`claude ${sub}: ${verb ?? "list"}`)
      return prompt(`claude ${sub}: ${verb}`, `"claude ${sub} ${verb}" changes Claude Code configuration`)
    }

    if (sub === "-p" || sub === "--print") {
      return prompt("claude: -p", `"claude -p" runs an autonomous agent with its own tool access`)
    }
    return prompt(`claude: ${sub}`, `"claude ${sub}" may run an agent or change configuration`)
  },

  // -- Scheduled jobs --

  crontab: (cmdInfo) => {
    // crontab -l lists; -r wipes every job, -e and `crontab <file>` install them.
    const args = cmdInfo.args
    if (args.length === 1) {
      return prompt("crontab: reads stdin", "Bare \"crontab\" replaces the crontab from stdin")
    }
    let sawList = false
    for (let i = 1; i < args.length; i++) {
      const arg = args[i]!
      if (arg === "-u") { i++; continue }          // -u <user>, still needs a verb
      if (arg === "-l") { sawList = true; continue }
      if (arg === "-r" || arg === "-e" || arg === "-i") {
        return prompt(`crontab: ${arg}`, `"crontab ${arg}" edits or removes scheduled jobs`)
      }
      if (arg.startsWith("-")) continue
      // A positional file argument installs a new crontab.
      return prompt("crontab: install from file", `"crontab ${arg}" replaces the current crontab`)
    }
    if (sawList) return allow("crontab: -l")
    return prompt("crontab: unknown form", "Could not confirm this crontab invocation only reads")
  },

  // -- Cloud CLIs --

  gcloud: (cmdInfo) => {
    // gcloud <group> [<subgroup>...] <verb> [resource-name] [--flags]
    // Group names are open-ended, so instead of guessing where the groups end,
    // scan left to right for the first token that is a known verb. A trailing
    // resource name must not be mistaken for the verb —
    // "gcloud sql databases describe mydb" is a read, not a write.
    const READ_ONLY_VERBS = new Set([
      "list", "describe", "get", "get-iam-policy", "search", "lookup",
      "explain", "tail", "history", "check", "validate", "diagnose",
    ])
    const WRITE_VERBS = new Set([
      "create", "delete", "update", "patch", "deploy", "set", "add", "remove",
      "import", "export", "ssh", "scp", "start", "stop", "restart", "reset",
      "enable", "disable", "apply", "submit", "run", "login", "logout",
      "revoke", "promote", "rollback", "undelete", "clone", "copy", "move",
      "resize", "attach", "detach", "set-iam-policy", "add-iam-policy-binding",
      "remove-iam-policy-binding", "activate", "install", "uninstall", "config",
    ])

    const args = cmdInfo.args
    const positionals: string[] = []
    for (let i = 1; i < args.length; i++) {
      const arg = args[i]!
      if (arg === "--version" || arg === "-v") return allow("gcloud: version")
      if (arg === "--help" || arg === "-h" || arg === "help") return allow("gcloud: help")
      // Value-taking global flags — skip the value so it can't look like a verb.
      if (arg === "--project" || arg === "--account" || arg === "--format" ||
          arg === "--configuration" || arg === "--zone" || arg === "--region" ||
          arg === "--filter" || arg === "--impersonate-service-account") {
        i++
        continue
      }
      if (arg.startsWith("-")) continue
      positionals.push(arg.toLowerCase())
    }
    if (positionals.length === 0) return allow("gcloud: no subcommand")
    if (positionals[0] === "version" || positionals[0] === "info") {
      return allow(`gcloud: ${positionals[0]}`)
    }

    // Start at 1: the first positional is always a group, never a verb. Several
    // top-level groups share a name with a verb ("run", "config", "auth"), and
    // treating those as verbs made reads like "gcloud run services list" prompt.
    for (let i = 1; i < positionals.length; i++) {
      const token = positionals[i]!
      const group = positionals.slice(0, i).join(" ")
      if (READ_ONLY_VERBS.has(token) || token.startsWith("list-") || token.startsWith("describe-")) {
        return allow(`gcloud ${group}: ${token}`)
      }
      if (WRITE_VERBS.has(token)) {
        return prompt(`gcloud ${group}: ${token}`, `"gcloud ${group} ${token}" may modify cloud resources`)
      }
    }
    // No recognizable verb — fail closed.
    return prompt(`gcloud: ${positionals.join(" ")}`, `Could not confirm "gcloud ${positionals.join(" ")}" only reads`)
  },

  rclone: (cmdInfo) => {
    // rclone <subcommand> — sync/delete/purge can destroy remote or local data.
    const args = cmdInfo.args
    const sub = args[1]?.toLowerCase()
    if (!sub) return allow("rclone: no subcommand")
    if (sub === "--version" || sub === "-v" || sub === "version") return allow("rclone: version")
    if (sub === "help" || sub === "--help" || sub === "-h") return allow("rclone: help")

    const safeCmds = new Set([
      "ls", "lsd", "lsl", "lsf", "lsjson", "listremotes",
      "about", "size", "md5sum", "sha1sum", "hashsum", "cat", "tree",
      "check", "obscure",
    ])
    if (safeCmds.has(sub)) return allow(`rclone: ${sub}`)
    // `rclone config show` reads; bare `config` is an interactive editor.
    if (sub === "config") {
      const verb = args[2]?.toLowerCase()
      if (verb === "show" || verb === "dump" || verb === "file" || verb === "userinfo") {
        return allow(`rclone config: ${verb}`)
      }
      return prompt(`rclone config: ${verb ?? "(interactive)"}`, `"rclone config" edits remote credentials`)
    }
    return prompt(`rclone: ${sub}`, `"rclone ${sub}" can move or delete data`)
  },

  // -- macOS system utilities --

  plutil: (cmdInfo) => {
    // plutil -p / -lint read. -convert rewrites the plist IN PLACE unless
    // the output is redirected to stdout with `-o -`.
    const args = cmdInfo.args
    let converting = false
    let outputsToStdout = false
    for (let i = 1; i < args.length; i++) {
      const arg = args[i]!
      if (arg === "-p" || arg === "-lint" || arg === "-help") continue
      if (arg === "-extract") { i++; continue }       // -extract <keypath> <fmt>
      if (arg === "-convert") { converting = true; i++; continue }
      if (arg === "-o" || arg === "--output") {
        if (args[i + 1] === "-") outputsToStdout = true
        i++
        continue
      }
      if (arg === "-insert" || arg === "-replace" || arg === "-remove") {
        return prompt(`plutil: ${arg}`, `"plutil ${arg}" modifies the plist`)
      }
    }
    if (converting && !outputsToStdout) {
      return prompt("plutil: -convert in place", `"plutil -convert" rewrites the plist unless you pass "-o -"`)
    }
    return allow("plutil: read-only")
  },

  mdutil: (cmdInfo) => {
    // mdutil -s reads index status; -E erases it and -i off disables indexing.
    const args = cmdInfo.args
    for (let i = 1; i < args.length; i++) {
      const arg = args[i]!
      if (arg === "-E") {
        return prompt("mdutil: -E", `"mdutil -E" erases the Spotlight index`)
      }
      if (arg === "-i" || arg === "-d" || arg === "-X" || arg === "-p") {
        return prompt(`mdutil: ${arg}`, `"mdutil ${arg}" changes Spotlight indexing state`)
      }
    }
    return allow("mdutil: read-only")
  },

  // -- Editors --

  code: (cmdInfo) => {
    // Opening a file is harmless; installing an extension is arbitrary code.
    const args = cmdInfo.args
    for (let i = 1; i < args.length; i++) {
      const arg = args[i]!
      if (arg === "--install-extension" || arg === "--uninstall-extension" ||
          arg.startsWith("--install-extension=") || arg.startsWith("--uninstall-extension=")) {
        return prompt(`code: ${arg.split("=")[0]}`, `"code ${arg.split("=")[0]}" installs or removes an extension`)
      }
    }
    return allow("code: opens editor")
  },
}

/**
 * How one interpreter spells "run this string as code".
 *
 * These options are matched with getopt rules, not by exact token. Checking
 * `arg === "-e"` misses both `-e'code'` (value attached to the flag) and
 * `-ne code` (code letter bundled behind another short flag) — and every
 * interpreter here accepts both spellings.
 */
interface InlineCodeSpec {
  /** Short letters whose value is code to execute. */
  codeLetters: Set<string>
  /** Short letters that consume the rest of the token as their value. */
  valueLetters: Set<string>
  /** Short letters taking an OPTIONAL numeric value, after which parsing continues. */
  numericLetters: Set<string>
  /** Long options whose value is code, in both `--opt value` and `--opt=value` form. */
  longFlags: Set<string>
}

// perl: -e and -E both eval. -0/-l/-C take optional octal and parsing continues
// after the digits, which is what makes `-0777pe` three separate options.
const PERL_INLINE: InlineCodeSpec = {
  codeLetters: new Set(["e", "E"]),
  valueLetters: new Set(["F", "i", "I", "m", "M", "x", "S", "D"]),
  numericLetters: new Set(["0", "l", "C"]),
  longFlags: new Set(),
}

// ruby: only -e evals. Note -E is an ENCODING flag here, unlike perl.
const RUBY_INLINE: InlineCodeSpec = {
  codeLetters: new Set(["e"]),
  valueLetters: new Set(["C", "E", "F", "I", "K", "r", "T", "W", "x", "S"]),
  numericLetters: new Set(["0"]),
  longFlags: new Set(),
}

// node: -p/--print evaluates and prints, same exposure as -e/--eval.
const NODE_INLINE: InlineCodeSpec = {
  codeLetters: new Set(["e", "p"]),
  valueLetters: new Set(["r", "C"]),
  numericLetters: new Set(),
  longFlags: new Set(["--eval", "--print"]),
}

// python: -c only. -m runs a module, which stays allowed as before.
const PYTHON_INLINE: InlineCodeSpec = {
  codeLetters: new Set(["c"]),
  valueLetters: new Set(["m", "Q", "W", "X"]),
  numericLetters: new Set(),
  longFlags: new Set(),
}

/** Does this invocation carry an inline-code flag, in any spelling? */
function hasInlineCode(args: string[], spec: InlineCodeSpec): boolean {
  for (let i = 1; i < args.length; i++) {
    const arg = args[i]!
    if (arg === "--") break            // everything after is the script and its args
    if (arg === "-" || !arg.startsWith("-")) continue

    if (arg.startsWith("--")) {
      const name = arg.split("=")[0]!
      if (spec.longFlags.has(name)) return true
      continue
    }

    // Short-option bundle: walk it letter by letter with getopt rules.
    for (let c = 1; c < arg.length; c++) {
      const letter = arg[c]!
      if (spec.codeLetters.has(letter)) return true
      if (spec.numericLetters.has(letter)) {
        // Consume an optional numeric argument, then keep walking the bundle.
        while (c + 1 < arg.length && arg[c + 1]! >= "0" && arg[c + 1]! <= "9") c++
        continue
      }
      // Any other value-taking letter swallows the rest of the token, so a
      // later `e` there is part of its value (`-Mfeature`), not a code flag.
      if (spec.valueLetters.has(letter)) break
    }
  }
  return false
}

interface SedParse {
  /** True if any form of in-place editing was requested. */
  inPlace: boolean
  /** The sed script(s) — tracked so they are never mistaken for file operands. */
  scripts: string[]
  /** File operands the edit would rewrite. */
  files: string[]
  /** Set when the arguments could not be resolved confidently — fail closed. */
  uncertain: boolean
}

/** Operands that cannot be resolved to a concrete path at hook time. */
const UNRESOLVABLE_OPERAND = /[*?$`{}\[\]]/

/** Short sed options that take a value (getopt: rest of the token, else next arg). */
const SED_VALUE_LETTERS = new Set(["e", "f"])

/**
 * Parse sed's arguments well enough to answer two questions: does this edit in
 * place, and which files would it rewrite?
 *
 *   sed [-Ealnrsuz] [-i[suffix]] script [file ...]
 *   sed [-Ealnrsuz] [-e script] [-f file] [-i[suffix]] [file ...]
 *
 * The previous check was `arg.startsWith("-i")`, which only sees `i` as the
 * FIRST letter of an option. `--in-place`, `-ni`, `-si` and `-Ei` all edit in
 * place and all slipped through.
 */
function parseSedArgs(args: string[]): SedParse {
  const out: SedParse = { inPlace: false, scripts: [], files: [], uncertain: false }
  const positionals: string[] = []
  let sawScriptFlag = false   // -e or -f given, so every positional is a file

  for (let i = 1; i < args.length; i++) {
    const arg = args[i]!

    if (arg === "--") {
      positionals.push(...args.slice(i + 1))
      break
    }

    // Long options
    if (arg.startsWith("--")) {
      if (arg === "--in-place" || arg.startsWith("--in-place=")) { out.inPlace = true; continue }
      if (arg === "--expression" || arg === "--file") {
        sawScriptFlag = true
        const value = args[++i]
        if (value === undefined) { out.uncertain = true; break }
        out.scripts.push(value)
        continue
      }
      if (arg.startsWith("--expression=") || arg.startsWith("--file=")) {
        sawScriptFlag = true
        out.scripts.push(arg.slice(arg.indexOf("=") + 1))
        continue
      }
      continue  // other long options take no value we care about
    }

    // Short option bundle — walk it with getopt rules.
    if (arg.startsWith("-") && arg.length > 1) {
      let consumedNext = false
      for (let c = 1; c < arg.length; c++) {
        const letter = arg[c]!
        if (letter === "i") {
          // Everything after `i` is GNU's attached backup suffix.
          out.inPlace = true
          break
        }
        if (SED_VALUE_LETTERS.has(letter)) {
          sawScriptFlag = true
          const attached = arg.slice(c + 1)
          if (attached) {
            out.scripts.push(attached)
          } else {
            const value = args[++i]
            if (value === undefined) { out.uncertain = true }
            else out.scripts.push(value)
            consumedNext = true
          }
          break
        }
        // Any other letter is a boolean flag — keep walking the bundle.
      }
      if (consumedNext) continue
      continue
    }

    positionals.push(arg)
  }

  if (out.uncertain) return out

  // BSD sed requires a separate backup-suffix argument after a bare `-i`;
  // GNU sed attaches it. When `-i` stood alone, the first positional may be
  // that suffix rather than the script.
  const bareI = args.some((a, idx) => idx > 0 && a === "-i")
  if (bareI && positionals.length > 0) {
    const first = positionals[0]!
    // The BSD form in practice is `sed -i '' ...` (empty suffix) or `-i .bak`.
    if (first === "" || (first.startsWith(".") && !first.includes("/"))) {
      positionals.shift()
    }
  }

  if (!sawScriptFlag) {
    // First remaining positional is the script; the rest are files.
    const script = positionals.shift()
    if (script === undefined) {
      out.uncertain = true
      return out
    }
    out.scripts.push(script)
  }

  // A file operand only tells us what gets rewritten if it names a real path.
  // find's "{}" placeholder, an unexpanded glob, or a shell variable could each
  // stand for anything — including a protected file — so fail closed instead.
  if (positionals.some((f) => UNRESOLVABLE_OPERAND.test(f))) {
    out.uncertain = true
    return out
  }

  out.files = positionals
  return out
}

/** Shared by the lowercase `tailscale` binary and the capitalized app-bundle name. */
function tailscaleInspector(cmdInfo: CommandInfo, _ctx: EvalContext): EvalResult {
  const args = cmdInfo.args
  if (args.length < 2) return allow("tailscale: no subcommand")
  const subcmd = args[1]!.toLowerCase()
  if (subcmd === "version" || subcmd === "--version" || subcmd === "-v") return allow("tailscale: version")
  if (subcmd === "help" || subcmd === "--help" || subcmd === "-h") return allow("tailscale: help")
  const safeCmds = new Set([
    "status", "ip", "netcheck", "ping", "whois",
    "dns",          // dns has only read sub-subcommands (status, query)
    "bugreport", "metrics", "licenses",
  ])
  if (safeCmds.has(subcmd)) return allow(`tailscale: ${subcmd}`)
  return prompt(`tailscale: ${subcmd}`, `"tailscale ${subcmd}" can change Tailscale network state`)
}

/** First positional (non-flag) argument after the shell name — the script file. */
function findScriptArg(args: string[]): string | null {
  for (let i = 1; i < args.length; i++) {
    const a = args[i]!
    if (a.startsWith("-")) continue
    return a
  }
  return null
}

/**
 * Match a script path against the configured safe_scripts globs. Each glob is
 * tested against the path as written and against the basename, so both
 * "**\/scripts/ship-gates.sh" and "ship-gates.sh" match "scripts/ship-gates.sh".
 */
function matchesSafeScript(scriptPath: string, patterns: string[]): boolean {
  if (patterns.length === 0) return false
  const base = scriptPath.split("/").pop() ?? scriptPath
  for (const pattern of patterns) {
    const glob = new Bun.Glob(pattern)
    if (glob.match(scriptPath) || glob.match(base)) return true
  }
  return false
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

  // No -c flag — running a script file. Auto-approve if the script path
  // matches a user-configured safe_scripts glob; otherwise prompt.
  if (script === undefined) {
    const scriptPath = findScriptArg(args)
    if (scriptPath && matchesSafeScript(scriptPath, ctx.config.commands.safe_scripts)) {
      return allow(`${shell}: trusted script ${scriptPath.split("/").pop()}`)
    }
    return prompt(`${shell}: script execution`, `Running "${shell}" with a script file`)
  }

  if (!script) {
    return prompt(`${shell}: -c with empty script`, `"${shell} -c" with empty script`)
  }

  // Parse the inline script with shfmt
  const proc = Bun.spawnSync([ctx.shfmtBin, "-ln", "bash", "--tojson"], {
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
