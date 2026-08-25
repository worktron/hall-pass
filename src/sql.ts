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

/**
 * Statement types that read and cannot write, whatever they contain.
 * Compound and CTE statements are NOT here — they wrap other statements
 * and have to be walked, see isStatementReadOnly.
 */
const READ_ONLY_TYPES = new Set([
  "select",
  "show",
  "values",      // bare VALUES clause
])

/**
 * Set-operation nodes. Read-only iff both branches are.
 * A bare `SELECT ... UNION ALL SELECT ...` parses to a top-level
 * "union all" node, not a "select" — checking only the top-level type
 * made every read-only union prompt.
 */
const COMPOUND_TYPES = new Set([
  "union",
  "union all",
  "intersect",
  "intersect all",
  "except",
  "except all",
])

/**
 * Is this parsed statement read-only, all the way down?
 *
 * Top-level type alone is not enough. Postgres allows data-modifying CTEs —
 * `WITH x AS (DELETE FROM t RETURNING id) SELECT * FROM x` is a "with" node
 * that deletes rows. Treating "with" as read-only auto-approved those writes,
 * so every wrapper node gets walked into instead.
 */
export function isStatementReadOnly(stmt: unknown): boolean {
  if (!stmt || typeof stmt !== "object") return false
  const node = stmt as Record<string, unknown>
  const type = node.type

  if (typeof type !== "string") return false
  if (READ_ONLY_TYPES.has(type)) return true

  if (COMPOUND_TYPES.has(type)) {
    return isStatementReadOnly(node.left) && isStatementReadOnly(node.right)
  }

  if (type === "with") {
    // Each CTE body can be an INSERT/UPDATE/DELETE; the final statement can too.
    const bind = node.bind
    if (!Array.isArray(bind)) return false
    const bindingsOk = bind.every(
      (b) => isStatementReadOnly((b as Record<string, unknown> | null)?.statement),
    )
    return bindingsOk && isStatementReadOnly(node.in)
  }

  // Unknown or writing statement type — fail closed.
  return false
}

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
 * Check a chunk that is plain SQL — no meta-commands mixed in.
 */
function isPlainSqlReadOnly(sql: string): boolean {
  // SQLite PRAGMAs — not parseable by pgsql-ast-parser
  if (/^pragma\s/i.test(sql)) {
    return isSqlitePragmaReadOnly(sql)
  }

  try {
    const statements = parse(sql)
    if (statements.length === 0) return true
    return statements.every(isStatementReadOnly)
  } catch {
    // Can't parse = can't guarantee safety = prompt
    return false
  }
}

/**
 * Check a whole client script, which interleaves meta-commands with SQL.
 *
 * psql scripts mix backslash commands with statements, sqlite3 scripts mix
 * dot-commands with them, and both arrive as one blob — from `-c`, and (once
 * the parser forwards them) from heredocs. This used to branch on the FIRST
 * character of the blob and hand the ENTIRE thing to one checker, so a script
 * opening with a safe meta-command was approved wholesale:
 *
 *   \dt
 *   DROP TABLE users;     <- rode along on \dt's approval
 *
 * Now each line is classified on its own: meta-command lines go to their
 * checker, runs of ordinary lines are gathered and parsed as SQL. Every
 * part has to pass.
 */
function isClientScriptReadOnly(script: string): boolean {
  let sqlLines: string[] = []

  // Parse and clear whatever plain SQL has accumulated.
  const sqlChunkOk = (): boolean => {
    const sql = sqlLines.join("\n").trim()
    sqlLines = []
    return sql === "" || isPlainSqlReadOnly(sql)
  }

  for (const line of script.split("\n")) {
    const trimmed = line.trim()

    if (trimmed.startsWith("\\")) {
      if (!sqlChunkOk()) return false
      if (!isPsqlMetaCommandSafe(trimmed)) return false
    } else if (trimmed.startsWith(".")) {
      if (!sqlChunkOk()) return false
      if (!isSqliteDotCommandSafe(trimmed)) return false
    } else {
      sqlLines.push(line)
    }
  }

  return sqlChunkOk()
}

/**
 * Check if a SQL string contains only read-only statements.
 */
export function isSqlReadOnly(sql: string): boolean {
  const trimmed = sql.trim()
  if (!trimmed) return true
  return isClientScriptReadOnly(trimmed)
}
