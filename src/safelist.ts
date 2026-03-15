/**
 * Commands that are safe to auto-approve in a development context.
 * If a command isn't here, it falls through to the normal permission prompt.
 *
 * IMPORTANT: Commands in this list are auto-approved with NO argument inspection.
 * Do not add commands that can execute arbitrary code via flags (e.g., python -c,
 * node -e) or that proxy other commands (e.g., xargs, nohup, exec).
 */
export const SAFE_COMMANDS = new Set([
  // Version control
  "gh",

  // JS/TS runtimes & package managers
  "bun", "bunx", "npm", "npx", "yarn", "pnpm", "deno", "tsc",

  // Build tools & language toolchains
  "cargo", "go", "make", "cmake", "pip", "uv", "poetry",
  "java", "javac", "mvn", "gradle",
  "gem", "bundle", "rake",
  "dotnet",
  "swift", "swiftc",
  "rustc",

  // Process management
  "lsof", "ps", "sleep", "pkill", "killall",

  // Network
  "curl", "wget",

  // Text processing
  "grep", "egrep", "fgrep", "rg", "sort", "uniq",
  "tr", "cut", "wc", "head", "tail", "tee", "jq",

  // File operations
  "ls", "cat", "cp", "mv", "mkdir", "touch", "diff",

  // File inspection
  "file", "stat", "strings", "realpath", "basename", "dirname",
  "less", "more", "xxd", "od", "md5sum", "sha256sum", "sha1sum",

  // Shell builtins & utilities
  "echo", "printf", "pwd", "which", "whoami", "test", "true", "false",
  "cd", "pushd", "popd", "export", "set", "unset", "read",
  "type",

  // System info (read-only)
  "hostname", "uname", "id", "df", "du", "free", "uptime", "nproc", "arch",

  // Scripting (safe subset — no arbitrary code execution)
  "date",

  // Dev tools
  "shfmt",

  // Linters & formatters
  "eslint", "prettier", "biome",
  "ruff", "black", "mypy", "flake8", "pylint", "isort",
  "golangci-lint", "gofmt", "rustfmt",

  // Test runners
  "jest", "vitest", "mocha", "pytest", "phpunit",

  // Archive & compression
  "tar", "zip", "unzip", "gzip", "gunzip", "bzip2", "bunzip2", "xz", "unxz",

  // Clipboard (macOS)
  "pbcopy", "pbpaste",

  // Version managers
  "volta", "fnm", "mise", "asdf",

  // Document processing
  "pandoc",

  // Local databases (file-based, no remote server risk)
  "sqlite3",
])


/**
 * Database clients that get deeper inspection.
 * Not auto-approved — their SQL is parsed to check if it's read-only.
 */
export const DB_CLIENTS = new Set([
  "psql",
  "mysql",
])

/**
 * Commands that should always prompt — known to be destructive or dangerous.
 * These are checked after inspectors, before the unknown-command passthrough.
 */
export const DANGEROUS_COMMANDS = new Set([
  // File deletion
  "rm", "rmdir", "unlink", "shred",
  // Privilege escalation
  "sudo", "su", "doas",
  // Raw disk / system
  "dd", "mkfs", "fdisk", "parted", "mount", "umount",
  // System control
  "shutdown", "reboot", "halt", "poweroff", "init",
  // Dangerous network
  "nc", "ncat",
])

/**
 * Environment variables that should never be set as command prefixes.
 * These can inject code into otherwise-safe commands.
 */
export const DANGEROUS_ENV_VARS = new Set([
  "LD_PRELOAD",
  "LD_LIBRARY_PATH",
  "DYLD_INSERT_LIBRARIES",  // macOS equivalent
  "DYLD_LIBRARY_PATH",
  "BASH_ENV",
  "ENV",                     // sh equivalent of BASH_ENV
  "PROMPT_COMMAND",
])
