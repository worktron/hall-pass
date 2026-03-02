/**
 * Configuration system for hall-pass.
 *
 * Loads optional TOML config from ~/.config/hall-pass/config.toml
 * (overridable via HALL_PASS_CONFIG env var). Everything works with
 * zero config using sensible defaults.
 */

import { parse as parseTOML } from "smol-toml"
import { homedir } from "os"
import { resolve, dirname } from "path"

export interface HallPassConfig {
  commands: { safe: string[]; db_clients: string[] }
  git: { protected_branches: string[] }
  paths: { protected: string[]; read_only: string[]; no_delete: string[] }
  audit: { enabled: boolean; path: string }
  debug: { enabled: boolean }
}

/** Default protected path patterns — always active even without config. */
export const DEFAULT_PROTECTED_PATHS = [
  "**/credentials*",
  "**/secret*",
  "~/.ssh/**",
  "~/.aws/**",
  "~/.gnupg/**",
  "**/*.pem",
  "**/*id_rsa*",
]

/** Default read-only path patterns — reads allowed, writes/deletes blocked. */
export const DEFAULT_READ_ONLY_PATHS = [
  "**/.env",
  "**/.env.*",
]

const DEFAULT_CONFIG: HallPassConfig = {
  commands: { safe: [], db_clients: [] },
  git: { protected_branches: [] },
  paths: { protected: DEFAULT_PROTECTED_PATHS, read_only: DEFAULT_READ_ONLY_PATHS, no_delete: [] },
  audit: { enabled: false, path: resolve(homedir(), ".config", "hall-pass", "audit.jsonl") },
  debug: { enabled: false },
}

/** Expand ~ to the user's home directory in a path string. */
export function expandTilde(p: string): string {
  if (p.startsWith("~/") || p === "~") {
    return resolve(homedir(), p.slice(2))
  }
  return p
}

/** Expand ~ in all path values within a config. */
function expandConfigPaths(config: HallPassConfig): HallPassConfig {
  return {
    ...config,
    paths: {
      protected: config.paths.protected.map(expandTilde),
      read_only: config.paths.read_only.map(expandTilde),
      no_delete: config.paths.no_delete.map(expandTilde),
    },
    audit: {
      ...config.audit,
      path: expandTilde(config.audit.path),
    },
  }
}

/** Deep-merge user config with defaults. User values ADD to defaults, not replace. */
function mergeConfig(defaults: HallPassConfig, user: Partial<Record<string, unknown>>): HallPassConfig {
  const commands = user.commands as Partial<Record<string, string[]>> | undefined
  const git = user.git as Partial<Record<string, string[]>> | undefined
  const paths = user.paths as Partial<Record<string, string[]>> | undefined
  const audit = user.audit as Partial<Record<string, unknown>> | undefined
  const debug = user.debug as Partial<Record<string, unknown>> | undefined

  return {
    commands: {
      safe: [...defaults.commands.safe, ...(commands?.safe ?? [])],
      db_clients: [...defaults.commands.db_clients, ...(commands?.db_clients ?? [])],
    },
    git: {
      protected_branches: [...defaults.git.protected_branches, ...(git?.protected_branches ?? [])],
    },
    paths: {
      protected: [...defaults.paths.protected, ...(paths?.protected ?? [])],
      read_only: [...defaults.paths.read_only, ...(paths?.read_only ?? [])],
      no_delete: [...defaults.paths.no_delete, ...(paths?.no_delete ?? [])],
    },
    audit: {
      enabled: (audit?.enabled as boolean) ?? defaults.audit.enabled,
      path: (audit?.path as string) ?? defaults.audit.path,
    },
    debug: {
      enabled: (debug?.enabled as boolean) ?? defaults.debug.enabled,
    },
  }
}

/** Resolve the config file path. */
function getConfigPath(): string {
  return process.env.HALL_PASS_CONFIG
    ?? resolve(homedir(), ".config", "hall-pass", "config.toml")
}

/**
 * Load config from TOML file. Returns defaults if no file exists or on parse error.
 */
export async function loadConfig(): Promise<HallPassConfig> {
  const configPath = getConfigPath()

  try {
    const file = Bun.file(configPath)
    if (!(await file.exists())) {
      return expandConfigPaths(DEFAULT_CONFIG)
    }
    const text = await file.text()
    const parsed = parseTOML(text) as Partial<Record<string, unknown>>
    const merged = mergeConfig(DEFAULT_CONFIG, parsed)
    return expandConfigPaths(merged)
  } catch {
    return expandConfigPaths(DEFAULT_CONFIG)
  }
}

/** Generate a default config TOML string with comments. */
export function generateDefaultConfig(): string {
  return `# hall-pass configuration
# See https://github.com/anthropics/hall-pass for documentation

[commands]
# Additional commands to auto-approve (added to built-in safelist)
# safe = ["terraform", "kubectl"]
# Additional database clients to inspect SQL for
# db_clients = ["pgcli"]

[git]
# Additional branches to protect (added to main, master, staging, production, prod)
# protected_branches = ["release"]

[paths]
# Paths where ALL operations are blocked
# protected = ["**/production.env"]
# Paths where writes are blocked (reads allowed)
# read_only = ["**/config/prod/**"]
# Paths where deletes are blocked (reads and writes allowed)
# no_delete = ["**/migrations/**"]

[audit]
# Enable audit logging
# enabled = true
# Audit log file path (default: ~/.config/hall-pass/audit.jsonl)
# path = "~/.config/hall-pass/audit.jsonl"

[debug]
# Enable debug output to stderr
# enabled = true
`
}

/** Ensure the config directory exists and write the default config. */
export async function initConfig(): Promise<string> {
  const configPath = getConfigPath()
  const dir = dirname(configPath)
  await Bun.spawn(["mkdir", "-p", dir]).exited

  await Bun.write(configPath, generateDefaultConfig())
  return configPath
}
