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
 * Short-option semantics for un-bundling combined flags like
 * `psql -tAc "SELECT ..."` (= -t -A -c). Walked with getopt rules:
 * boolean letters continue the bundle; a value-taking letter consumes
 * the rest of the token, or the next arg when it's last; the sql
 * letter's value is the SQL to inspect. An unrecognized letter aborts
 * extraction entirely (fail safe to prompt).
 *
 * Only psql for now — mysql's `-p[password]` takes an OPTIONAL attached
 * value, which breaks getopt walking; bundled `-e` stays a prompt there.
 */
const SHORT_OPTS: Record<string, { boolean: string; value: string; sql: string }> = {
  psql: { boolean: "aAbeEHlnqsStwWxXz01V", value: "dfFhLopPRTUv", sql: "c" },
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

  // psql/mysql: look for -c/-e/--command/--execute followed by SQL.
  // Collect EVERY occurrence — psql executes all -c flags in order, so
  // returning just the first would let `-c "SELECT 1" -c "DROP x"`
  // masquerade as read-only. The joined string parses as multiple
  // statements and each must pass the read-only check.
  if (flags) {
    const short = SHORT_OPTS[clientName]
    const collected: string[] = []
    for (let i = 1; i < args.length; i++) {
      const arg = args[i]!
      // Handle --flag=value form
      const eqFlag = [...flags].find((f) => arg.startsWith(f + "="))
      if (eqFlag) {
        collected.push(arg.slice(eqFlag.length + 1))
        continue
      }
      // Handle --flag value form
      if (flags.has(arg)) {
        if (i + 1 < args.length) {
          collected.push(args[i + 1]!)
          i++
        }
        continue
      }
      // Bundled/short options: -tAc "SQL", -h host, -Fc (F's value is "c").
      // Only the letters BEFORE the sql/value letter are validated; the
      // walk breaks at the first of those, so attached values (-tAcSELECT,
      // -p5432) pass through untouched and any unknown letter aborts.
      if (short && !arg.startsWith("--") && /^-[A-Za-z0-9]/.test(arg)) {
        const letters = arg.slice(1)
        for (let j = 0; j < letters.length; j++) {
          const ch = letters[j]!
          if (ch === short.sql) {
            const attached = letters.slice(j + 1)
            if (attached) {
              collected.push(attached)
            } else if (i + 1 < args.length) {
              collected.push(args[i + 1]!)
              i++
            }
            break
          }
          if (short.value.includes(ch)) {
            // Rest of the token is this option's value; if there is
            // no rest, the NEXT arg is — skip it so `-F -c` doesn't
            // read the literal "-c" separator value as a command flag.
            if (j === letters.length - 1) i++
            break
          }
          if (!short.boolean.includes(ch)) {
            return null // unknown letter — don't guess, force a prompt
          }
        }
      }
    }
    return collected.length > 0 ? collected.join(";\n") : null
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
