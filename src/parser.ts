/**
 * Walks a shfmt JSON AST and extracts every command invocation.
 *
 * shfmt represents commands as CallExpr nodes where Args[0] is the
 * command name. The recursive walk finds CallExpr nodes inside pipes,
 * chains (&&/||), loops, conditionals, subshells, and command substitutions.
 */

export interface CommandInfo {
  /** The command name, e.g., "git", "grep" */
  name: string
  /** All arguments as strings, e.g., ["git", "push", "--force", "origin", "main"] */
  args: string[]
  /** Environment variable assignments on this command, e.g., [{ name: "LD_PRELOAD", value: "evil.so" }] */
  assigns: AssignInfo[]
  /**
   * Literal text fed to this command's standard input by a heredoc
   * (`<<EOF`, `<<-EOF`) or a herestring (`<<<"..."`), when there is one.
   *
   * A command can take its real instructions from stdin rather than from
   * argv — `psql db <<EOF ... EOF` is the usual way to send multi-line SQL.
   * Inspectors that read args alone see nothing there and have to assume the
   * worst. Undefined means no heredoc, NOT an empty one.
   *
   * `< file.sql` is deliberately absent: that content lives on disk and
   * would have to be read (and could change before the command runs).
   */
  stdin?: string
}

export interface RedirectInfo {
  /** The file path being redirected to/from */
  path: string
  /** Whether this is a write (>, >>) or read (<) redirect */
  op: "write" | "read"
}

export interface AssignInfo {
  /** Variable name */
  name: string
  /** Variable value (may be partial if it contains expansions) */
  value: string
}

/**
 * Extract just command names (simple API for basic safelist checking).
 */
export function extractCommands(node: unknown): string[] {
  return extractCommandInfos(node).map((c) => c.name)
}

/**
 * Extract full command info including arguments.
 */
export function extractCommandInfos(node: unknown): CommandInfo[] {
  if (!node || typeof node !== "object") return []

  const n = node as Record<string, unknown>
  const commands: CommandInfo[] = []

  // Stmt with redirects — the heredoc body hangs off the Stmt, while the
  // command it feeds is the sibling .Cmd. Handle the pair here so the text
  // can be attached; walking them independently would lose the association.
  if (Array.isArray(n.Redirs) && n.Cmd) {
    const stdin = extractHeredocText(n.Redirs as Array<Record<string, unknown>>)
    const inner = extractCommandInfos(n.Cmd)
    // Leftmost command owns the redirect: in `psql <<EOF | head`, the
    // heredoc feeds psql, not head.
    if (stdin !== null && inner.length > 0) inner[0]!.stdin = stdin
    commands.push(...inner)
    // Redirect targets can themselves contain command substitutions.
    for (const redir of n.Redirs) commands.push(...extractCommandInfos(redir))
    return commands
  }

  // CallExpr = a command invocation
  if (n.Type === "CallExpr" && Array.isArray(n.Args) && n.Args.length > 0) {
    const args = (n.Args as Array<Record<string, unknown>>).map(extractWordValue).filter(Boolean) as string[]
    if (args.length > 0) {
      const name = args[0]!.split("/").pop()!
      commands.push({
        name,
        args: [name, ...args.slice(1)],
        assigns: extractAssigns(n),
      })
    }
  }

  // Recurse into all child values to find nested commands
  for (const value of Object.values(n)) {
    if (Array.isArray(value)) {
      for (const item of value) {
        commands.push(...extractCommandInfos(item))
      }
    } else if (typeof value === "object" && value !== null) {
      commands.push(...extractCommandInfos(value))
    }
  }

  return commands
}

/**
 * Concatenate the literal text every heredoc/herestring in a Stmt's Redirs
 * feeds to standard input. Returns null when there is none.
 *
 * Op values from shfmt's syntax.RedirOperator (verified against shfmt v3.12+):
 *   61 = <<    62 = <<-    63 = <<<
 * << and <<- carry their body in .Hdoc; <<< puts its string in .Word.
 * Only FULLY LITERAL bodies are returned. A quoted delimiter (`<<'EOF'`)
 * suppresses expansion and yields one literal — the common case, and the
 * only one that can be read with confidence. An unquoted delimiter expands
 * `$VAR` and `$(cmd)` inside the body, and extractWordValue drops those
 * parts silently; the resulting text would look like the whole story while
 * the shell splices in something else at runtime. Such a body reports null
 * (unreadable), so callers keep whatever they do when there is no heredoc
 * at all. The substituted commands are still walked separately.
 */
function extractHeredocText(redirs: Array<Record<string, unknown>>): string | null {
  const bodies: string[] = []

  for (const redir of redirs) {
    const op = redir.Op as number | undefined
    // << and <<- carry the body in .Hdoc; <<< puts its string in .Word.
    const source =
      op === 61 || op === 62 ? redir.Hdoc :
      op === 63 ? redir.Word :
      undefined
    if (!source || typeof source !== "object") continue

    const word = source as Record<string, unknown>
    if (!isFullyLiteral(word)) return null

    const text = extractWordValue(word)
    if (text !== null) bodies.push(text)
  }

  return bodies.length > 0 ? bodies.join("\n") : null
}

/**
 * True when a Word is made only of literal text — no parameter expansion,
 * command substitution, or arithmetic. Quoted segments count as literal
 * provided their own contents are.
 */
function isFullyLiteral(word: Record<string, unknown>): boolean {
  const parts = word.Parts as Array<Record<string, unknown>> | undefined
  if (!parts) return false

  return parts.every((part) => {
    if (part.Type === "Lit") return true
    if (part.Type === "SglQuoted") return true  // no expansion inside '...'
    if (part.Type === "DblQuoted") return isFullyLiteral(part)
    return false
  })
}

/**
 * Extract all redirect targets from the entire AST.
 * Returns a flat list — every redirect in every statement.
 */
export function extractRedirects(node: unknown): RedirectInfo[] {
  if (!node || typeof node !== "object") return []

  const n = node as Record<string, unknown>
  const results: RedirectInfo[] = []

  // Check for Redirs array (lives on Stmt nodes)
  if (Array.isArray(n.Redirs)) {
    for (const redir of n.Redirs as Array<Record<string, unknown>>) {
      const word = redir.Word as Record<string, unknown> | undefined
      const path = word ? extractWordValue(word) : null
      if (!path) continue

      // Op values from shfmt's syntax.RedirOperator (verified against shfmt v3.12+):
      // 54 = >    55 = >>    56 = <      57 = <>     59 = >& (dup FD)
      // 60 = >|   61 = <<    63 = <<<    64 = &>     65 = &>>
      // Treat as write: redirect operators that can clobber a file path target.
      // <> is read-write — counted as write because it can truncate/create.
      // 59 (>&) targets a file descriptor, not a path — leave as read so the
      // path check skips it (the "path" is just a numeric FD).
      const op = redir.Op as number | undefined
      const isWrite = op !== undefined && (op === 54 || op === 55 || op === 57 || op === 60 || op === 64 || op === 65)
      results.push({ path, op: isWrite ? "write" : "read" })
    }
  }

  // Recurse into all child values
  for (const value of Object.values(n)) {
    if (Array.isArray(value)) {
      for (const item of value) {
        results.push(...extractRedirects(item))
      }
    } else if (typeof value === "object" && value !== null) {
      results.push(...extractRedirects(value))
    }
  }

  return results
}

/**
 * Extract the names of commands that are genuine pipe targets — the
 * right-hand side of a `|` or `|&` pipe.
 *
 * Op values from shfmt's syntax.BinaryOperator (verified against shfmt v3.12+):
 *   10 = &&   11 = ||   12 = |   13 = |&
 * Only 12 and 13 are real pipes. This deliberately does NOT match `&&`/`||`
 * chains (which run sequentially, not piped) or `;`-separated statements
 * (which shfmt represents as separate Stmts, not a BinaryCmd). So
 * `git rebase && bash deploy.sh` is NOT reported as a pipe into bash, while
 * `curl x | bash` is.
 */
export function extractPipeTargets(node: unknown): string[] {
  if (!node || typeof node !== "object") return []

  const n = node as Record<string, unknown>
  const results: string[] = []

  if (n.Type === "BinaryCmd" && (n.Op === 12 || n.Op === 13)) {
    const name = leftmostCommandName(n.Y)
    if (name) results.push(name)
  }

  // Recurse into all child values (catches pipes nested in subshells,
  // command substitutions, loops, etc.)
  for (const value of Object.values(n)) {
    if (Array.isArray(value)) {
      for (const item of value) results.push(...extractPipeTargets(item))
    } else if (typeof value === "object" && value !== null) {
      results.push(...extractPipeTargets(value))
    }
  }

  return results
}

/**
 * Name of the first (leftmost) command reachable from a Stmt/Cmd node.
 * Descends through Stmt wrappers and the left side of nested pipes so that
 * `a | b | c` reports both `b` and `c` as pipe targets.
 */
function leftmostCommandName(node: unknown): string | null {
  if (!node || typeof node !== "object") return null

  const n = node as Record<string, unknown>
  // Stmt wraps the actual command in .Cmd
  if (n.Cmd) return leftmostCommandName(n.Cmd)
  // Nested pipe/chain — the immediate target is the left operand
  if (n.Type === "BinaryCmd") return leftmostCommandName(n.X)
  // CallExpr — extract the command name (strip any path prefix)
  if (n.Type === "CallExpr" && Array.isArray(n.Args) && n.Args.length > 0) {
    const first = extractWordValue(n.Args[0] as Record<string, unknown>)
    return first ? first.split("/").pop()! : null
  }
  return null
}

/**
 * Extract environment variable assignments from a CallExpr node.
 * shfmt puts env var prefixes in CallExpr.Assigns[].
 */
function extractAssigns(node: Record<string, unknown>): AssignInfo[] {
  const assigns = node.Assigns as Array<Record<string, unknown>> | undefined
  if (!assigns) return []

  const results: AssignInfo[] = []
  for (const assign of assigns) {
    const nameNode = assign.Name as Record<string, unknown> | undefined
    const name = nameNode?.Value as string | undefined
    const valueNode = assign.Value as Record<string, unknown> | undefined
    const value = valueNode ? (extractWordValue(valueNode) ?? "") : ""
    if (name) results.push({ name, value })
  }

  return results
}

/**
 * Extract the string value from a shfmt Word node.
 * Concatenates all Lit parts (ignores complex expansions).
 */
function extractWordValue(word: Record<string, unknown>): string | null {
  const parts = word?.Parts as Array<Record<string, unknown>> | undefined
  if (!parts) return null

  let result = ""
  for (const part of parts) {
    if (part.Value !== undefined) {
      result += String(part.Value)
    } else if (part.Type === "DblQuoted" || part.Type === "SglQuoted") {
      // Quoted string — recurse into its parts
      const innerParts = part.Parts as Array<Record<string, unknown>> | undefined
      if (innerParts) {
        for (const inner of innerParts) {
          if (inner.Value !== undefined) result += String(inner.Value)
        }
      }
      if (part.Value !== undefined) result += String(part.Value)
    }
  }

  return result || null
}
