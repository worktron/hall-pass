/**
 * Configuration system for hall-pass.
 *
 * Loads optional TOML config from ~/.config/hall-pass/config.toml
 * (overridable via HALL_PASS_CONFIG env var). Everything works with
 * zero config using sensible defaults.
 */

import { parse as parseTOML } from "smol-toml";
import { homedir } from "os";
import { resolve, dirname } from "path";
import { existsSync } from "fs";

export interface HallPassConfig {
  commands: { safe: string[]; db_clients: string[]; safe_scripts: string[] };
  git: { protected_branches: string[]; safe_subcommands: string[] };
  paths: { protected: string[]; read_only: string[]; no_delete: string[] };
  audit: { enabled: boolean; path: string };
  debug: { enabled: boolean };
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
];

/** Default read-only path patterns — reads allowed, writes/deletes blocked. */
export const DEFAULT_READ_ONLY_PATHS = ["**/.env", "**/.env.*"];

const DEFAULT_CONFIG: HallPassConfig = {
  commands: { safe: [], db_clients: [], safe_scripts: [] },
  git: { protected_branches: [], safe_subcommands: [] },
  paths: {
    protected: DEFAULT_PROTECTED_PATHS,
    read_only: DEFAULT_READ_ONLY_PATHS,
    no_delete: [],
  },
  audit: {
    // On by default: decision + outcome entries power `bun run stats`
    // and `bun run eval`. Rotates past ~5MB (archives kept), see audit.ts.
    enabled: true,
    path: resolve(homedir(), ".config", "hall-pass", "audit.jsonl"),
  },
  debug: { enabled: false },
};

/** Expand ~ to the user's home directory in a path string. */
export function expandTilde(p: string): string {
  if (p.startsWith("~/") || p === "~") {
    return resolve(homedir(), p.slice(2));
  }
  return p;
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
  };
}

/** Deep-merge user config with defaults. User values ADD to defaults, not replace. */
function mergeConfig(
  defaults: HallPassConfig,
  user: Partial<Record<string, unknown>>,
): HallPassConfig {
  const commands = user.commands as
    | Partial<Record<string, string[]>>
    | undefined;
  const git = user.git as Partial<Record<string, string[]>> | undefined;
  const paths = user.paths as Partial<Record<string, string[]>> | undefined;
  const audit = user.audit as Partial<Record<string, unknown>> | undefined;
  const debug = user.debug as Partial<Record<string, unknown>> | undefined;

  return {
    commands: {
      safe: [...defaults.commands.safe, ...(commands?.safe ?? [])],
      db_clients: [
        ...defaults.commands.db_clients,
        ...(commands?.db_clients ?? []),
      ],
      safe_scripts: [
        ...defaults.commands.safe_scripts,
        ...(commands?.safe_scripts ?? []),
      ],
    },
    git: {
      protected_branches: [
        ...defaults.git.protected_branches,
        ...(git?.protected_branches ?? []),
      ],
      safe_subcommands: [
        ...defaults.git.safe_subcommands,
        ...(git?.safe_subcommands ?? []),
      ],
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
  };
}

/** Resolve the global config file path. */
function getConfigPath(): string {
  return (
    process.env.HALL_PASS_CONFIG ??
    resolve(homedir(), ".config", "hall-pass", "config.toml")
  );
}

/**
 * Walk up from `start` looking for a `.hall-pass` file at a directory that
 * also contains a `.git` entry (i.e. the repo root). Returns the path to the
 * file or `null` if not found. We anchor on `.git` so a stray `.hall-pass`
 * outside a repo can't grant trust by accident.
 */
function findProjectConfig(start: string): string | null {
  let dir = resolve(start);
  while (true) {
    const candidate = resolve(dir, ".hall-pass");
    if (existsSync(candidate) && existsSync(resolve(dir, ".git"))) {
      return candidate;
    }
    const parent = dirname(dir);
    if (parent === dir) return null;
    dir = parent;
  }
}

/** Parse a TOML config file. Returns null if missing or unparseable. */
async function readTomlConfig(
  path: string,
): Promise<Partial<Record<string, unknown>> | null> {
  try {
    const file = Bun.file(path);
    if (!(await file.exists())) return null;
    const text = await file.text();
    return parseTOML(text) as Partial<Record<string, unknown>>;
  } catch {
    return null;
  }
}

/**
 * Load config. Layered: defaults < global (~/.config/hall-pass/config.toml)
 * < project-local (<repo-root>/.hall-pass). Project-local entries are
 * additive — they extend the safelists rather than replacing them. The
 * project file is anchored on a sibling `.git` entry so an unrelated
 * `.hall-pass` outside a repo can't grant trust by accident.
 */
export async function loadConfig(): Promise<HallPassConfig> {
  let result: HallPassConfig = DEFAULT_CONFIG;

  const globalParsed = await readTomlConfig(getConfigPath());
  if (globalParsed) result = mergeConfig(result, globalParsed);

  const projectConfigPath = findProjectConfig(process.cwd());
  if (projectConfigPath) {
    const projectParsed = await readTomlConfig(projectConfigPath);
    if (projectParsed) result = mergeConfig(result, projectParsed);
  }

  return expandConfigPaths(result);
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
# Local script paths (globs) to auto-approve when run via "bash <script>".
# Trust implication: matched scripts run WITHOUT a prompt, so list only
# scripts you control. Each glob is matched against the path as written and
# against the basename, so "**/scripts/ship-gates.sh" and "ship-gates.sh"
# both match "bash scripts/ship-gates.sh".
# safe_scripts = ["**/scripts/ship-gates.sh", "**/scripts/deep-ship.sh"]

[git]
# Additional branches to protect (added to main, master, staging, production, prod)
# protected_branches = ["release"]
# Additional git subcommands to auto-approve (extends the built-in safe set).
# Trust implication: a listed subcommand is approved on its own; per-subcommand
# arg/flag inspection still applies where hall-pass defines it.
# safe_subcommands = ["lfs", "subtree"]

[paths]
# Paths where ALL operations are blocked
# protected = ["**/production.env"]
# Paths where writes are blocked (reads allowed)
# read_only = ["**/config/prod/**"]
# Paths where deletes are blocked (reads and writes allowed)
# no_delete = ["**/migrations/**"]

[audit]
# Audit logging is ON by default — it records decisions and outcomes
# (JSON Lines, rotated past ~5MB with archives kept) and powers
# \`bun run stats\` and \`bun run eval\`.
# enabled = false
# Audit log file path (default: ~/.config/hall-pass/audit.jsonl)
# path = "~/.config/hall-pass/audit.jsonl"

[debug]
# Enable debug output to stderr
# enabled = true
`;
}

/** Ensure the config directory exists and write the default config. */
export async function initConfig(): Promise<string> {
  const configPath = getConfigPath();
  const dir = dirname(configPath);
  await Bun.spawn(["mkdir", "-p", dir]).exited;

  await Bun.write(configPath, generateDefaultConfig());
  return configPath;
}
