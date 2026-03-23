/**
 * Git command safety checker.
 *
 * Parses git commands and checks whether they're safe to auto-approve.
 * Read-only commands and safe local writes are allowed.
 * Destructive operations that can lose work are flagged.
 *
 * Returns a GitDecision — safe: true or safe: false with reason + human message.
 */

export type GitDecision =
  | { safe: true }
  | { safe: false; reason: string; message: string }

/**
 * Git subcommands that are always safe (read-only or easily reversible).
 */
const SAFE_SUBCOMMANDS = new Set([
  // Read-only
  "status", "log", "diff", "show", "branch", "tag", "remote",
  "describe", "rev-parse", "rev-list", "ls-files", "ls-tree",
  "cat-file", "reflog", "shortlog", "blame", "bisect",
  "name-rev", "cherry", "count-objects", "fsck", "verify-pack",
  "whatchanged",

  // Safe local writes
  "add", "commit", "stash", "fetch", "pull", "merge",
  "cherry-pick", "revert", "notes", "worktree",

  // Branch/navigation (without destructive flags)
  "checkout", "switch", "restore",

  // Maintenance
  "gc", "prune", "repack",
])

/**
 * Git config keys that execute commands. Setting these is dangerous.
 */
const DANGEROUS_GIT_CONFIGS = [
  "core.fsmonitor",
  "core.hooksPath",
  "core.sshCommand",
  "diff.external",
  "merge.tool",
  "credential.helper",
  "pager.",
  "alias.",
  "filter.",
  "remote.", // remote.*.url could point to malicious repo
]

/**
 * Git subcommands that are safe ONLY on non-protected branches.
 */
const BRANCH_GATED_SUBCOMMANDS = new Set([
  "push",
  "rebase",
])

/**
 * Branches that should always prompt before push/rebase.
 */
const PROTECTED_BRANCHES = new Set([
  "main", "master", "staging", "production", "prod",
])

/**
 * Flags that make otherwise-safe commands destructive.
 */
const DESTRUCTIVE_FLAGS: Record<string, Set<string>> = {
  push: new Set(["--force", "-f", "--force-with-lease", "--force-if-includes"]),
  reset: new Set(["--hard"]),
  checkout: new Set(["."]),     // git checkout . = discard all changes
  restore: new Set(["."]),      // git restore . = discard all changes
  clean: new Set(["-f", "-fd", "-fx", "-fxd", "-fdx", "-ff"]),
  branch: new Set(["-D", "--force", "-d"]),  // -d is less destructive but still deletes
  stash: new Set(["drop", "clear"]),
}

/**
 * Subcommands that are always destructive — never auto-approve.
 */
const ALWAYS_DESTRUCTIVE = new Set([
  "reset",   // even soft reset can be surprising
  "clean",   // deletes untracked files
])

/**
 * Extract the git subcommand and flags from a full git command string.
 * Handles: git -C /path subcommand --flags args
 * Also captures -c config values for security inspection.
 */
function parseGitCommand(args: string[]): { subcommand: string; flags: string[]; rest: string[]; configs: string[] } {
  const remaining = [...args]
  const configs: string[] = []

  // Skip git-level flags before the subcommand
  // These are flags that go between "git" and the subcommand
  while (remaining.length > 0) {
    const arg = remaining[0]!
    if (arg === "-C" || arg === "--git-dir" || arg === "--work-tree") {
      remaining.shift() // the flag
      remaining.shift() // its value
    } else if (arg === "-c") {
      remaining.shift() // the -c flag
      const configVal = remaining.shift() // the config key=value
      if (configVal) configs.push(configVal)
    } else if (arg.startsWith("-")) {
      remaining.shift() // other git-level flags like --no-pager
    } else {
      break
    }
  }

  const subcommand = remaining.shift() ?? ""
  const flags: string[] = []
  const rest: string[] = []

  for (const arg of remaining) {
    if (arg.startsWith("-")) {
      flags.push(arg)
    } else {
      rest.push(arg)
    }
  }

  return { subcommand, flags, rest, configs }
}

/**
 * Check if a git command is safe to auto-approve.
 *
 * Accepts either pre-parsed args (from shfmt AST) or a raw command string.
 * Prefer passing parsed args to avoid redundant tokenization.
 */
const safe: GitDecision = { safe: true }
const unsafe = (reason: string, message: string): GitDecision => ({ safe: false, reason, message })

export function checkGitCommand(argsOrCommand: string[] | string, customProtectedBranches?: Set<string>): GitDecision {
  const args = typeof argsOrCommand === "string"
    ? tokenize(argsOrCommand)
    : [...argsOrCommand]

  // Remove "git" if it's the first token
  if (args[0] === "git") args.shift()

  const { subcommand, flags, rest, configs } = parseGitCommand(args)

  if (!subcommand) return safe // bare "git" — safe (just shows help)

  // Check for dangerous -c config values (e.g., git -c core.fsmonitor="evil" status)
  for (const config of configs) {
    const key = config.split("=")[0]!.toLowerCase()
    for (const dangerous of DANGEROUS_GIT_CONFIGS) {
      if (key.startsWith(dangerous.toLowerCase())) {
        return unsafe(`git: dangerous -c config ${key}`, `git -c sets executable config key "${key}"`)
      }
    }
  }

  // Always destructive — prompt no matter what
  if (ALWAYS_DESTRUCTIVE.has(subcommand)) {
    const messages: Record<string, string> = {
      reset: "git reset can discard commits and staged changes",
      clean: "git clean deletes untracked files permanently",
    }
    return unsafe(`git: destructive subcommand ${subcommand}`, messages[subcommand] ?? `git ${subcommand} is destructive`)
  }

  // git config — safe for reads, dangerous for writes that set executable values
  if (subcommand === "config") {
    // git config --get, --list, --get-regexp, etc. = safe reads
    const readFlags = new Set(["--get", "--get-all", "--get-regexp", "--list", "-l", "--show-origin", "--show-scope"])
    for (const flag of flags) {
      if (readFlags.has(flag)) return safe
    }
    // git config key (no value) = read, git config key value = write
    // If there are 2+ positional args, it's a write — check if the key is dangerous
    if (rest.length >= 2) {
      const key = rest[0]!.toLowerCase()
      for (const dangerous of DANGEROUS_GIT_CONFIGS) {
        if (key.startsWith(dangerous.toLowerCase())) {
          return unsafe(`git: dangerous config write ${key}`, `git config sets executable key "${key}"`)
        }
      }
    }
    // Single arg = read, or non-dangerous write
    return safe
  }

  // Check for destructive flags on otherwise-safe commands.
  // For branch-gated commands (push, rebase), destructive flags are only
  // dangerous on protected branches — force pushing a feature branch is normal.
  const dangerousFlags = DESTRUCTIVE_FLAGS[subcommand]
  if (dangerousFlags && !BRANCH_GATED_SUBCOMMANDS.has(subcommand)) {
    for (const flag of flags) {
      if (dangerousFlags.has(flag)) {
        return unsafe(`git: ${subcommand} ${flag}`, describeDestructiveFlag(subcommand, flag))
      }
    }
    // Also check rest args for things like "git checkout ."
    for (const arg of rest) {
      if (dangerousFlags.has(arg)) {
        return unsafe(`git: ${subcommand} ${arg}`, describeDestructiveFlag(subcommand, arg))
      }
    }
  }

  // Branch-gated commands: safe on feature branches, prompt on protected branches.
  // Force flags are only dangerous when targeting a protected branch.
  if (BRANCH_GATED_SUBCOMMANDS.has(subcommand)) {
    const branches = customProtectedBranches ?? PROTECTED_BRANCHES
    for (const arg of rest) {
      const target = arg.includes(":") ? arg.split(":").pop()! : arg
      if (branches.has(target)) {
        return unsafe(`git: ${subcommand} to protected branch ${target}`, `git ${subcommand} to protected branch "${target}"`)
      }
    }
    return safe
  }

  // Known safe subcommands
  if (SAFE_SUBCOMMANDS.has(subcommand)) return safe

  // Unknown subcommand — prompt
  return unsafe(`git: unknown subcommand ${subcommand}`, `Unknown git subcommand "${subcommand}"`)
}

/** Human-friendly description for a destructive flag on a git subcommand. */
function describeDestructiveFlag(subcommand: string, flag: string): string {
  const key = `${subcommand} ${flag}`
  const descriptions: Record<string, string> = {
    "reset --hard": "git reset --hard discards all uncommitted changes",
    "checkout .": "git checkout . discards all unstaged changes",
    "restore .": "git restore . discards all unstaged changes",
    "clean -f": "git clean permanently deletes untracked files",
    "clean -fd": "git clean permanently deletes untracked files and directories",
    "clean -fx": "git clean permanently deletes untracked and ignored files",
    "clean -fxd": "git clean permanently deletes untracked, ignored files and directories",
    "clean -fdx": "git clean permanently deletes untracked, ignored files and directories",
    "clean -ff": "git clean permanently deletes untracked files (force)",
    "branch -D": "Force-deletes a branch regardless of merge status",
    "branch -d": "Deletes a branch",
    "branch --force": "Force-overwrites a branch",
    "stash drop": "git stash drop permanently removes stashed changes",
    "stash clear": "git stash clear permanently removes all stashed changes",
  }
  return descriptions[key] ?? `git ${subcommand} with ${flag} is destructive`
}

/**
 * Simple shell-aware tokenizer for git arguments.
 * Handles single and double quotes.
 */
function tokenize(input: string): string[] {
  const tokens: string[] = []
  let current = ""
  let inSingle = false
  let inDouble = false

  for (let i = 0; i < input.length; i++) {
    const ch = input[i]

    if (ch === "'" && !inDouble) {
      inSingle = !inSingle
    } else if (ch === '"' && !inSingle) {
      inDouble = !inDouble
    } else if (ch === " " && !inSingle && !inDouble) {
      if (current) tokens.push(current)
      current = ""
    } else {
      current += ch
    }
  }

  if (current) tokens.push(current)
  return tokens
}
