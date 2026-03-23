/**
 * SQLite safety checkers for dot-commands and PRAGMAs.
 *
 * Neither dot-commands nor PRAGMAs are standard SQL —
 * pgsql-ast-parser can't parse them. We handle them here.
 */

/**
 * Safe SQLite dot-commands — read-only introspection and display.
 * Each entry is the command name without the leading dot.
 *
 * NOT included (dangerous):
 *   .import   — load data from file
 *   .restore  — restore database from file
 *   .open     — open a database (can create/overwrite)
 *   .output   — redirect output to file
 *   .once     — redirect next output to file
 *   .log      — write to log file
 *   .save     — write database to file
 *   .backup   — backup database to file
 *   .clone    — clone database to file
 *   .read     — execute SQL from file
 *   .system   — run shell command
 *   .shell    — run shell command
 */
const SAFE_SQLITE_DOT_COMMANDS = new Set([
  // Schema / introspection
  "schema",       // show CREATE statements
  "tables",       // list tables
  "databases",    // list attached databases
  "indexes",      // list indexes
  "indices",      // alias for .indexes
  "fullschema",   // show complete schema including stats

  // Display / formatting
  "headers",      // toggle column headers
  "mode",         // set output mode (csv, column, json, etc.)
  "separator",    // set column separator
  "width",        // set column widths
  "nullvalue",    // set string for NULL values
  "print",        // print text

  // Informational
  "show",         // show current settings
  "dbinfo",       // show database info
  "dbconfig",     // show database config
  "stats",        // show query stats
  "version",      // show SQLite version
  "help",         // show help
  "sha3sum",      // compute hash of database content

  // Display control
  "explain",      // set EXPLAIN formatting
  "eqp",          // set EXPLAIN QUERY PLAN mode
  "timer",        // toggle timing display

  // Dump (outputs SQL text to stdout — read-only)
  "dump",         // dump database as SQL

  // Lint
  "lint",         // check for potential issues
])

/**
 * Check if a SQLite dot-command is read-only.
 * Returns true for safe introspection commands, false for dangerous ones.
 */
export function isSqliteDotCommandSafe(input: string): boolean {
  const trimmed = input.trim()
  if (!trimmed.startsWith(".")) return false

  // Extract the command name: everything after . up to the first space
  const rest = trimmed.slice(1)
  const match = rest.match(/^([a-zA-Z0-9_]+)/)
  if (!match) return false

  return SAFE_SQLITE_DOT_COMMANDS.has(match[1]!.toLowerCase())
}

/**
 * Check if a PRAGMA statement is read-only.
 *
 * PRAGMA comes in two forms:
 *   PRAGMA name            — query (read-only)
 *   PRAGMA name(arg)       — query (read-only)
 *   PRAGMA name = value    — setter (write)
 *
 * Returns true for queries, false for setters.
 */
export function isSqlitePragmaReadOnly(input: string): boolean {
  const trimmed = input.trim()

  // Strip trailing semicolons
  const cleaned = trimmed.replace(/;+\s*$/, "")

  // Must start with PRAGMA (case-insensitive)
  if (!/^pragma\s/i.test(cleaned)) return false

  // If it contains '=', it's a setter
  return !cleaned.includes("=")
}
