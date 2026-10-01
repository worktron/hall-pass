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

/** Commands that only read files. */
const READ_COMMANDS = new Set([
  "cat", "head", "tail", "less", "more", "file", "stat", "wc", "strings",
  "diff", "md5sum", "sha256sum", "sha1sum", "xxd", "od",
])

/** Commands that delete files. */
const DELETE_COMMANDS = new Set(["rm", "rmdir", "unlink"])

/**
 * Commands whose positional arguments are file paths.
 * Only these commands get path protection checking.
 *
 * docker, git, curl, npm etc. are NOT here — their args aren't file paths.
 * This prevents false positives like `docker compose --env-file .env.local`.
 */
const PATH_AWARE_COMMANDS = new Set([
  // Read
  "cat", "head", "tail", "less", "more", "file", "stat", "wc", "strings",
  "diff", "md5sum", "sha256sum", "sha1sum", "xxd", "od",
  // Write
  "cp", "mv", "mkdir", "touch", "tee", "ln", "install",
  // Delete
  "rm", "rmdir", "unlink",
  // Permissions
  "chmod", "chown", "chgrp",
])

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

  const glob = new Bun.Glob(expandedPattern)
  return glob.match(resolved)
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
  // args[0] is the command name itself, skip it
  const args = commandInfo.args.slice(1)
  let unknown: string | undefined

  for (const arg of args) {
    if (arg.startsWith("-")) continue // skip flags
    if (strict && arg.includes("$")) unknown ??= arg
    if (!looksLikePath(arg)) continue

    const decision = checkFilePath(arg, operation, config)
    if (!decision.allowed) return decision
  }

  return unknown ? { allowed: true, reason: "", unknown } : { allowed: true, reason: "" }
}
