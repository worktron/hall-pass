/**
 * psql meta-command safety checker.
 *
 * psql backslash commands aren't SQL — pgsql-ast-parser can't parse them.
 * We maintain an allowlist of read-only meta-commands and reject the rest.
 */

/**
 * Safe psql meta-commands — read-only introspection and display.
 * Each entry is the command name without the leading backslash.
 *
 * All commands may optionally be followed by + (verbose) or arguments.
 *
 * NOT included (dangerous):
 *   \! — shell escape
 *   \copy — client-side file I/O
 *   \i / \ir — execute SQL from file
 *   \o — redirect output to file
 *   \w — write query buffer to file
 */
const SAFE_PSQL_META_COMMANDS = new Set([
  // Describe / introspection (\d family)
  "d",        // describe table
  "dt",       // list tables
  "di",       // list indexes
  "ds",       // list sequences
  "da",       // list aggregates
  "dm",       // list materialized views
  "dv",       // list views
  "dE",       // list foreign tables
  "dn",       // list schemas
  "df",       // list functions
  "du",       // list roles
  "dT",       // list data types
  "dp",       // list privileges
  "dD",       // list domains
  "dF",       // list text search configs
  "dx",       // list extensions
  "dy",       // list event triggers
  "dg",       // list roles (alias for \du)
  "dO",       // list collations
  "db",       // list tablespaces
  "dc",       // list conversions
  "dC",       // list casts
  "dA",       // list access methods
  "dL",       // list procedural languages
  "do",       // list operators
  "des",      // list foreign servers
  "det",      // list foreign tables (alt)
  "dew",      // list foreign data wrappers
  "dl",       // list large objects

  // Information / display
  "l",        // list databases
  "conninfo", // connection info
  "encoding", // show client encoding
  "timing",   // toggle timing display

  // Formatting
  "pset",     // set output format options
  "x",        // toggle expanded output
  "a",        // toggle aligned/unaligned
  "H",        // toggle HTML output

  // Display / echo
  "echo",     // print to stdout
  "qecho",    // print to query output

  // History (bare only — see BARE_ONLY_PSQL_META_COMMANDS)
  "s",        // show command history

  // Show definitions (read-only)
  "sf",       // show function definition
  "sv",       // show view definition

  // Informational
  "copyright",   // show copyright
  "errverbose",  // show last error verbose
  "z",           // list privileges (alias for \dp)

  // Query execution (bare only — see BARE_ONLY_PSQL_META_COMMANDS)
  "g",        // re-execute query buffer

  // Conditional (harmless in -c context)
  "if",
  "elif",
  "else",
  "endif",
])

/**
 * Safe ONLY with no argument. Each of these takes an optional operand that
 * turns it into a write:
 *
 *   \g file      send query output to a file
 *   \g | cmd     pipe query output through a shell command
 *   \s file      write the command history to disk
 *
 * Bare, they re-run the query buffer / print history to the screen.
 * They used to sit in SAFE_PSQL_META_COMMANDS unconditionally, so
 * `\g | sh` and `\g /tmp/out` were auto-approved.
 */
const BARE_ONLY_PSQL_META_COMMANDS = new Set([
  "g",
  "s",
])

/**
 * Check if a single psql meta-command (backslash command) is read-only.
 *
 * Takes ONE line. A string holding a meta-command plus anything else is
 * rejected: `\dt\nDROP TABLE users;` matched `dt` and returned true for
 * the whole thing, carrying the DROP along with it. Callers split scripts
 * into lines first — see isClientScriptReadOnly in sql.ts.
 */
export function isPsqlMetaCommandSafe(input: string): boolean {
  const trimmed = input.trim()
  if (!trimmed.startsWith("\\")) return false
  if (trimmed.includes("\n")) return false

  // Command name: the letters after the backslash. A trailing + (verbose,
  // as in \dt+) stops the match on its own and needs no special casing.
  const rest = trimmed.slice(1)
  const match = rest.match(/^([a-zA-Z]+)/)
  if (!match) return false

  const cmd = match[1]!
  // Everything after the name, minus a bare verbose marker.
  const operand = rest.slice(cmd.length).replace(/^\+/, "").trim()

  if (BARE_ONLY_PSQL_META_COMMANDS.has(cmd)) return operand === ""
  return SAFE_PSQL_META_COMMANDS.has(cmd)
}
