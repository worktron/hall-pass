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
import { writeFile } from "fs/promises";

export interface HallPassConfig {
  commands: { safe: string[]; db_clients: string[]; safe_scripts: string[] };
  git: { protected_branches: string[]; safe_subcommands: string[] };
  paths: { protected: string[]; read_only: string[]; no_delete: string[] };
  audit: { enabled: boolean; path: string };
  debug: { enabled: boolean };
  /**
   * defer: in permission modes where Claude Code has its own reviewer (the
   * classifier, in auto and plan mode), hand judgment-call prompts to it instead of forcing
   * the user to answer. Hard stops (protected paths, secrets, code injection,
   * pushes to protected branches) prompt regardless. See decide.ts.
   */
  classifier: { defer: boolean };
  /**
   * deny_hard_stops: Codex has no hook "ask" (it is parsed but unsupported,
   * and the tool runs anyway). Hard stops — protected paths, secrets, code
   * injection, exfiltration, pushes to protected branches — become a DENY
   * under Codex when this is true. When false they become a warning and
   * Codex's own sandbox and approval flow decide. See codex.ts.
   */
  codex: { deny_hard_stops: boolean };
  /**
   * readable_references: 1Password references (`op://vault/item/field`,
   * matched as exact text) that `op read` may read without a prompt. Read
   * only from the global config, never from a repository's `.hall-pass`.
   * See the op inspector.
   */
  op: { readable_references: string[] };
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
  classifier: { defer: true },
  codex: { deny_hard_stops: true },
  op: { readable_references: [] },
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
  const classifier = user.classifier as Partial<Record<string, unknown>> | undefined;
  const codex = user.codex as Partial<Record<string, unknown>> | undefined;
  const op = user.op as Partial<Record<string, unknown>> | undefined;

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
    classifier: {
      defer: (classifier?.defer as boolean) ?? defaults.classifier.defer,
    },
    codex: {
      deny_hard_stops: (codex?.deny_hard_stops as boolean) ?? defaults.codex.deny_hard_stops,
    },
    op: {
      readable_references: [
        ...defaults.op.readable_references,
        ...readableReferences(op?.readable_references),
      ],
    },
  };
}

/**
 * The entries of a readable_references value that can name a reference:
 * text starting with `op://` with no `$` (which is how a variable hall-pass
 * cannot read looks in a command). Anything else, a string in place of a
 * list, a number, a table, is dropped, so a typo keeps the prompt instead of
 * breaking the hook.
 */
function readableReferences(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.filter((v): v is string => typeof v === "string" && v.startsWith("op://") && !v.includes("$"));
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
    // A repository does not get to name your secrets: [op] is global only.
    if (projectParsed) result = mergeConfig(result, { ...projectParsed, op: undefined });
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

[classifier]
# In auto and plan mode (and bypassPermissions), judgment-call prompts — rm, sudo,
# ssh, inline perl/python, in-place sed, database writes, unknown git
# subcommands — are handed to Claude Code's own classifier instead of
# forcing a prompt (a hook "ask" prompts in EVERY mode). Hard stops still
# prompt: protected paths, secrets, code injection, pushes to protected
# branches. Set false to prompt for everything, as before.
# defer = false

[codex]
# Codex hooks cannot "ask" — a hook can only allow, deny, or step aside.
# Hard stops (protected paths, secrets, code injection, exfiltration domains,
# pushes to protected branches) are therefore DENIED under Codex. Set false
# to downgrade them to a warning and let Codex's sandbox and approval prompt
# decide. Judgment calls (rm, sudo, ssh, ...) are never denied: hall-pass
# shows its reason and leaves the prompt to Codex.
# deny_hard_stops = false

[op]
# 1Password references that "op read" may read without a prompt, matched as
# exact text. Trust implication: an agent that may read a reference may know
# its value and send it anywhere, so list only keys whose leak costs little
# (read-only and revocable). Read only from this file, never from a
# repository's .hall-pass.
# readable_references = ["op://Example/Read-only key/credential"]

[debug]
# Enable debug output to stderr
# enabled = true
`;
}

/**
 * Ensure the config directory exists and write the default config, unless a
 * config is already there: the "wx" flag makes the existence check and the
 * write one step, so an existing file is never replaced.
 */
export async function initConfig(): Promise<{ path: string; created: boolean }> {
  const configPath = getConfigPath();
  const dir = dirname(configPath);
  await Bun.spawn(["mkdir", "-p", dir]).exited;

  try {
    await writeFile(configPath, generateDefaultConfig(), { flag: "wx" });
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "EEXIST") return { path: configPath, created: false };
    throw err;
  }
  return { path: configPath, created: true };
}

/** What init says when a config already exists: the file, and how to replace it on purpose. */
export function configExistsMessage(path: string): string {
  return `Config already exists at ${path}; left unchanged.\nTo replace it with the defaults, move it aside (mv ${path} ${path}.bak) and run hall-pass init again.`;
}
