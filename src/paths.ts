/**
 * File path protection for hall-pass.
 *
 * Checks file paths against configured protection rules using
 * Bun.Glob for pattern matching.
 */

import type { HallPassConfig } from "./config.ts"
import { expandTilde } from "./config.ts"
import { resolve } from "path"
import type { CommandInfo } from "./parser.ts"

export interface PathDecision {
  allowed: boolean
  reason: string
  /**
   * Set (with allowed true) when an argument holds a value the line does not
   * pin down, so no rule can say whether it is protected. Only reported when
   * the caller asks for it (checkCommandPaths' `strict`).
   */
  unknown?: string
}

/**
 * Readers that print or transform what they read: each one can put a
 * protected file's contents on screen as surely as cat. Their operands are
 * routinely a loop variable or `$(git ls-files)`, so a value nobody can read
 * is not held as a judgment call for them (checkCommandPaths' strict): over
 * 22 days of audit log that would have handed 281 calls to the classifier. A
 * variable the line sets is still read (vars.ts, values.ts), so
 * `f=~/.ssh/id_rsa; grep x $f` still stops.
 */
const STREAM_READERS = new Set([
  "base64", "cut", "sort", "uniq", "nl", "tac", "rev", "fold", "column",
  "paste", "join", "comm", "hexdump", "cksum", "shasum", "md5", "bat",
  "zcat", "gzcat", "bzcat", "xzcat", "iconv", "expand", "unexpand", "fmt", "pr",
  // Archivers read every file they are given, a directory's whole tree included.
  "tar", "zip",
  // Pattern first, then files: see PATTERN_FIRST.
  "grep", "egrep", "fgrep", "rg", "awk", "gawk", "jq",
])

/** Commands that only read files. */
const READ_COMMANDS = new Set([
  "cat", "head", "tail", "less", "more", "file", "stat", "wc", "strings",
  "diff", "md5sum", "sha256sum", "sha1sum", "xxd", "od",
  ...STREAM_READERS,
])

/** Commands that delete files. */
const DELETE_COMMANDS = new Set(["rm", "rmdir", "unlink"])

/**
 * Commands whose positional arguments are file paths.
 * Only these commands get path protection checking.
 *
 * docker, git, curl, npm etc. are NOT here — their args aren't file paths.
 * This prevents false positives like `docker compose --env-file .env.local`.
 * sed reads its files too; its inspector checks them (inspectors.ts), since
 * it already parses sed's script apart from its files.
 */
const PATH_AWARE_COMMANDS = new Set([
  // Read
  ...READ_COMMANDS,
  // Write
  "cp", "mv", "mkdir", "touch", "tee", "ln", "install",
  // Delete
  ...DELETE_COMMANDS,
  // Permissions
  "chmod", "chown", "chgrp",
])

/**
 * How a pattern-first reader's words split into its pattern and its files.
 * The first operand is the pattern or program, unless an option supplied
 * one; `grep "api/secret" notes.md` reads notes.md, not a file called
 * api/secret. Values of `value` options are not files, except `file` ones.
 */
interface ReaderSpec {
  /** Options whose value is the next word, or attached to the option. */
  value: string[]
  /** Options that supply the pattern or program, so every operand is a file. */
  script: string[]
  /** Options whose value is a file the command reads. */
  file: string[]
  /** Options that take two words; the second is a file for those also in `file`. */
  pair?: string[]
  /** Options after which no operand is a pattern (rg --files lists files). */
  noPattern?: string[]
  /** Options after which operands are no longer files (jq --args). */
  stop?: string[]
}

const GREP: ReaderSpec = {
  value: [
    "-e", "-f", "-A", "-B", "-C", "-m", "-d", "-D",
    "--regexp", "--file", "--max-count", "--after-context", "--before-context", "--context",
    "--include", "--exclude", "--exclude-dir", "--label", "--devices", "--directories", "--binary-files",
  ],
  script: ["-e", "-f", "--regexp", "--file"],
  file: ["-f", "--file"],
}

const PATTERN_FIRST: Record<string, ReaderSpec> = {
  grep: GREP,
  egrep: GREP,
  fgrep: GREP,
  rg: {
    value: [
      "-e", "-f", "-g", "-t", "-T", "-A", "-B", "-C", "-m", "-M", "-j", "-r", "-E", "-d",
      "--regexp", "--file", "--glob", "--iglob", "--type", "--type-not", "--type-add", "--max-count",
      "--max-columns", "--threads", "--replace", "--encoding", "--max-depth", "--context",
      "--after-context", "--before-context", "--sort", "--sortr", "--pre", "--pre-glob",
      "--ignore-file", "--colors", "--max-filesize", "--path-separator",
    ],
    script: ["-e", "-f", "--regexp", "--file"],
    file: ["-f", "--file", "--ignore-file"],
    noPattern: ["--files", "--type-list"],
  },
  awk: { value: ["-F", "-v", "-f", "--field-separator", "--assign", "--file"], script: ["-f", "--file"], file: ["-f", "--file"] },
  gawk: { value: ["-F", "-v", "-f", "--field-separator", "--assign", "--file"], script: ["-f", "--file"], file: ["-f", "--file"] },
  jq: {
    value: ["-f", "-L", "--from-file", "--indent"],
    script: ["-f", "--from-file"],
    file: ["-f", "--from-file", "--slurpfile", "--rawfile"],
    pair: ["--arg", "--argjson", "--slurpfile", "--rawfile"],
    stop: ["--args", "--jsonargs"],
  },
}

/** The words of a pattern-first reader that name files it reads. */
export function readerFiles(args: string[], spec: ReaderSpec): string[] {
  const shortValue = new Set(spec.value.filter((o) => /^-[^-]$/.test(o)).map((o) => o[1]!))
  const files: string[] = []
  const operands: string[] = []
  let patternGiven = false
  const take = (option: string, value: string | undefined) => {
    if (spec.script.includes(option)) patternGiven = true
    if (value !== undefined && spec.file.includes(option)) files.push(value)
  }
  for (let i = 1; i < args.length; i++) {
    const arg = args[i]!
    if (arg === "--") {
      operands.push(...args.slice(i + 1))
      break
    }
    if (spec.stop?.includes(arg)) break
    if (arg.startsWith("--")) {
      const eq = arg.indexOf("=")
      const option = eq >= 0 ? arg.slice(0, eq) : arg
      if (spec.noPattern?.includes(option)) patternGiven = true
      if (spec.pair?.includes(option)) {
        i += 2
        if (spec.file.includes(option)) files.push(args[i] ?? "")
        continue
      }
      if (!spec.value.includes(option)) continue
      take(option, eq >= 0 ? arg.slice(eq + 1) : args[++i])
      continue
    }
    if (arg.startsWith("-") && arg.length > 1) {
      // A short cluster, getopt style: the first option that takes a value
      // takes the rest of the word, or else the next word.
      for (let c = 1; c < arg.length; c++) {
        if (!shortValue.has(arg[c]!)) continue
        const attached = arg.slice(c + 1)
        take(`-${arg[c]}`, attached || args[++i])
        break
      }
      continue
    }
    operands.push(arg)
  }
  if (!patternGiven) operands.shift()
  return [...files, ...operands]
}

export function isPathAwareCommand(name: string): boolean {
  return PATH_AWARE_COMMANDS.has(name)
}

/** Check if a string looks like a file path. */
function looksLikePath(arg: string): boolean {
  return arg.includes("/") || arg.startsWith(".") || arg.startsWith("~")
}

/** Match a resolved path against a glob pattern. */
function matchesPattern(filePath: string, pattern: string): boolean {
  // Resolve the path for consistent matching
  const resolved = resolve(expandTilde(filePath))
  const expandedPattern = expandTilde(pattern)

  if (new Bun.Glob(expandedPattern).match(resolved)) return true
  // The directory a `dir/**` pattern protects is protected too: `cp -r ~/.ssh`,
  // `tar czf x ~/.ssh` and `grep -r key ~/.ssh` read everything under it.
  return expandedPattern.endsWith("/**") && new Bun.Glob(expandedPattern.slice(0, -3)).match(resolved)
}

/**
 * Check a single file path against protection rules.
 */
export function checkFilePath(
  filePath: string,
  operation: "read" | "write" | "delete",
  config: HallPassConfig,
): PathDecision {
  // Check protected paths — block ALL operations
  for (const pattern of config.paths.protected) {
    if (matchesPattern(filePath, pattern)) {
      return { allowed: false, reason: `matches protected path ${pattern}` }
    }
  }

  // Check read_only paths — block write/delete
  if (operation === "write" || operation === "delete") {
    for (const pattern of config.paths.read_only) {
      if (matchesPattern(filePath, pattern)) {
        return { allowed: false, reason: `matches read-only path ${pattern}` }
      }
    }
  }

  // Check no_delete paths — block delete
  if (operation === "delete") {
    for (const pattern of config.paths.no_delete) {
      if (matchesPattern(filePath, pattern)) {
        return { allowed: false, reason: `matches no-delete path ${pattern}` }
      }
    }
  }

  return { allowed: true, reason: "" }
}

/** Determine the operation type for a command. */
function getOperationType(commandName: string): "read" | "write" | "delete" {
  if (READ_COMMANDS.has(commandName)) return "read"
  if (DELETE_COMMANDS.has(commandName)) return "delete"
  return "write"
}

/**
 * Check all path-like arguments in a parsed command against protection rules.
 */
export function checkCommandPaths(
  commandInfo: CommandInfo,
  config: HallPassConfig,
  strict = false,
): PathDecision {
  const operation = getOperationType(commandInfo.name)
  // args[0] is the command name itself, skip it. A pattern-first reader's
  // pattern is not a path: only the words that name files it reads are.
  const spec = PATTERN_FIRST[commandInfo.name]
  const args = spec ? readerFiles(commandInfo.args, spec) : commandInfo.args.slice(1)
  let unknown: string | undefined

  for (const arg of args) {
    if (arg.startsWith("-")) continue // skip flags
    if (strict && !STREAM_READERS.has(commandInfo.name) && arg.includes("$")) unknown ??= arg
    if (!looksLikePath(arg)) continue

    const decision = checkFilePath(arg, operation, config)
    if (!decision.allowed) return decision
  }

  return unknown ? { allowed: true, reason: "", unknown } : { allowed: true, reason: "" }
}
