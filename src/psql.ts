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

  // History
  "s",        // show command history

  // Show definitions (read-only)
  "sf",       // show function definition
  "sv",       // show view definition
  "ef",       // edit function (opens in editor — read-only in -c context)
  "ev",       // edit view (opens in editor — read-only in -c context)

  // Informational
  "copyright",   // show copyright
  "errverbose",  // show last error verbose
  "z",           // list privileges (alias for \dp)

  // Query execution (re-send current buffer)
  "g",        // execute query buffer

  // Conditional (harmless in -c context)
  "if",
  "elif",
  "else",
  "endif",
])

/**
 * Check if a psql meta-command (backslash command) is read-only.
 * Returns true for safe introspection commands, false for dangerous ones.
 */
export function isPsqlMetaCommandSafe(input: string): boolean {
  const trimmed = input.trim()
  if (!trimmed.startsWith("\\")) return false

  // Extract the command name: everything after \ up to the first space or +
  const rest = trimmed.slice(1)
  const match = rest.match(/^([a-zA-Z]+)/)
  if (!match) return false

  const cmd = match[1]!

  // Check with and without trailing + (verbose flag)
  if (SAFE_PSQL_META_COMMANDS.has(cmd)) return true
  if (cmd.endsWith("+") && SAFE_PSQL_META_COMMANDS.has(cmd.slice(0, -1))) return true

  return false
}
