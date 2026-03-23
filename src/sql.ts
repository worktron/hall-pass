/**
 * SQL statement safety checker.
 *
 * Parses SQL using pgsql-ast-parser and checks if all statements
 * are read-only. Used when the Bash command is a database client
 * like psql, mysql, or sqlite3.
 *
 * Returns:
 *   "allow"   — all statements are read-only
 *   "prompt"  — contains writes or couldn't parse
 */

import { parse } from "pgsql-ast-parser"
import { isPsqlMetaCommandSafe } from "./psql.ts"
import { isSqliteDotCommandSafe, isSqlitePragmaReadOnly } from "./sqlite.ts"

const READ_ONLY_TYPES = new Set([
  "select",
  "with",        // WITH ... SELECT (CTEs)
  "show",
  "values",      // bare VALUES clause
])

/**
 * Flags that introduce an inline SQL string, per DB client.
 * The value after the flag is the SQL to inspect.
 */
const SQL_FLAGS: Record<string, Set<string>> = {
  psql:    new Set(["-c", "--command"]),
  mysql:   new Set(["-e", "--execute"]),
  sqlite3: new Set([]),  // sqlite3 takes SQL as a positional arg
}

/**
 * Extract the SQL string from a DB client command's parsed args.
 *
 * Works with all supported clients:
 *   psql -c "SELECT ..."       / psql --command "SELECT ..."
 *   mysql -e "SELECT ..."      / mysql --execute "SELECT ..."
 *   sqlite3 db.sqlite "SELECT ..."  (positional after db path)
 *
 * Args come from the shfmt parser, so quotes are already stripped.
 * Returns null if no inline SQL found (e.g., interactive session).
 */
export function extractSqlFromArgs(clientName: string, args: string[]): string | null {
  const flags = SQL_FLAGS[clientName]

  // sqlite3: SQL is a positional arg (the one after the database path)
  // sqlite3 [options] db_file "SQL"
  if (clientName === "sqlite3") {
    // Walk args, skip flags and their values, find positional args
    const positional: string[] = []
    for (let i = 1; i < args.length; i++) {
      const arg = args[i]!
      if (arg === "-cmd" || arg === "-separator" || arg === "-newline") {
        i++ // skip value
      } else if (arg.startsWith("-")) {
        continue // skip boolean flags
      } else {
        positional.push(arg)
      }
    }
    // First positional = db file, second = SQL
    return positional.length >= 2 ? positional[1]! : null
  }

  // psql/mysql: look for -c/-e/--command/--execute followed by SQL
  if (flags) {
    for (let i = 1; i < args.length; i++) {
      const arg = args[i]!
      // Handle --flag=value form
      for (const flag of flags) {
        if (arg.startsWith(flag + "=")) {
          return arg.slice(flag.length + 1)
        }
      }
      // Handle --flag value form
      if (flags.has(arg) && i + 1 < args.length) {
        return args[i + 1]!
      }
    }
  }

  return null
}

/**
 * @deprecated Use extractSqlFromArgs instead. Kept for backward compatibility.
 */
export function extractSqlFromPsql(command: string): string | null {
  const patterns = [
    /-c\s+"([^"]+)"/,
    /-c\s+'([^']+)'/,
    /--command="([^"]+)"/,
    /--command='([^']+)'/,
    /-c\s+(\S+)/,
  ]

  for (const pattern of patterns) {
    const match = command.match(pattern)
    if (match) return match[1]!
  }

  return null
}

/**
 * Check if a SQL string contains only read-only statements.
 */
export function isSqlReadOnly(sql: string): boolean {
  const trimmed = sql.trim()
  if (!trimmed) return true

  // psql meta-commands start with backslash — not parseable as SQL
  if (trimmed.startsWith("\\")) {
    return isPsqlMetaCommandSafe(trimmed)
  }

  // SQLite dot-commands start with . — not parseable as SQL
  if (trimmed.startsWith(".")) {
    return isSqliteDotCommandSafe(trimmed)
  }

  // SQLite PRAGMAs — not parseable by pgsql-ast-parser
  if (/^pragma\s/i.test(trimmed)) {
    return isSqlitePragmaReadOnly(trimmed)
  }

  try {
    const statements = parse(trimmed)
    if (statements.length === 0) return true
    return statements.every((stmt) => READ_ONLY_TYPES.has(stmt.type))
  } catch {
    // Can't parse = can't guarantee safety = prompt
    return false
  }
}
