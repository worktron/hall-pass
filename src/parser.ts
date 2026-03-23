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

      // Op values in shfmt: 54 = >, 56 = >>, 55 = >|, 62 = &>, 63 = &>>
      // Read ops: 52 = <
      const op = redir.Op as number | undefined
      const isWrite = op !== undefined && (op === 54 || op === 55 || op === 56 || op === 62 || op === 63)
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
