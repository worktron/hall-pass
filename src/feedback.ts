/**
 * Agent feedback layer ("isThisIdiotic").
 *
 * Checks commands against structured feedback rules. When a rule matches,
 * hall-pass denies the command (exit 0 + permissionDecision: "deny") and
 * sends a suggestion via permissionDecisionReason that Claude sees in-context.
 *
 * Rules receive the full list of CommandInfo objects so they can reason
 * about pipeline context (e.g., "python3 -c receiving piped input from curl").
 */

import type { CommandInfo } from "./parser.ts"

/**
 * A feedback rule is a function that receives all commands in the pipeline
 * and returns a suggestion string if the pattern is bad, or null if no match.
 */
export type FeedbackRule = (commandInfos: CommandInfo[]) => string | null

/** JSON-related keywords that indicate JSON processing in inline code */
const JSON_KEYWORDS = ["json", "JSON", "json.loads", "json.load", "json.dumps", "json.dump", "JSON.parse", "JSON.stringify"]

/** Simple string operation patterns in inline code */
const STRING_OP_KEYWORDS = [
  // Python string ops
  ".split(", ".strip(", ".replace(", ".join(", ".upper()", ".lower()",
  ".startswith(", ".endswith(", ".find(", ".count(",
  // Node string ops
  ".split(", ".trim(", ".replace(", ".join(", ".toUpperCase()", ".toLowerCase(",
  ".startsWith(", ".endsWith(", ".indexOf(", ".includes(",
  // Python regex
  "re.sub(", "re.match(", "re.search(", "re.findall(",
]

/**
 * Check if a command is python3 -c or python -c with inline code.
 * Returns the inline code string, or null.
 */
function getPythonInlineCode(cmd: CommandInfo): string | null {
  if (cmd.name !== "python3" && cmd.name !== "python") return null
  const cIdx = cmd.args.indexOf("-c")
  if (cIdx === -1 || cIdx + 1 >= cmd.args.length) return null
  return cmd.args[cIdx + 1] ?? null
}

/**
 * Check if a command is node -e/--eval with inline code.
 * Returns the inline code string, or null.
 */
function getNodeInlineCode(cmd: CommandInfo): string | null {
  if (cmd.name !== "node") return null
  for (let i = 0; i < cmd.args.length; i++) {
    const arg = cmd.args[i]
    if ((arg === "-e" || arg === "--eval" || arg === "-p" || arg === "--print") && i + 1 < cmd.args.length) {
      return cmd.args[i + 1] ?? null
    }
  }
  return null
}

/** Get inline code from a command, if it's python -c or node -e. */
function getInlineCode(cmd: CommandInfo): string | null {
  return getPythonInlineCode(cmd) ?? getNodeInlineCode(cmd)
}

/**
 * Rule: json-parsing
 *
 * Detects python3 -c or node -e doing JSON processing when the data
 * is being piped from curl/wget. Suggests jq instead.
 */
const jsonParsing: FeedbackRule = (commandInfos) => {
  // Check if any command in the pipeline is doing inline JSON processing
  for (const cmd of commandInfos) {
    const code = getInlineCode(cmd)
    if (!code) continue

    const hasJsonKeyword = JSON_KEYWORDS.some(kw => code.includes(kw))
    if (!hasJsonKeyword) continue

    // Check if curl/wget is in the pipeline (piping JSON data)
    const hasFetcher = commandInfos.some(c => c.name === "curl" || c.name === "wget")

    if (hasFetcher) {
      return `hall-pass: Use \`jq\` for JSON parsing — it's purpose-built, safer, and auto-approved by hall-pass. Example: curl ... | jq '.field'`
    }

    // Even without curl/wget, flag standalone JSON processing
    return `hall-pass: Use \`jq\` for JSON parsing instead of inline ${cmd.name} — it's purpose-built, safer, and auto-approved by hall-pass.`
  }

  return null
}

/**
 * Rule: inline-code-as-tool
 *
 * Detects python3 -c or node -e doing simple string operations that
 * shell builtins handle better. Suggests sed/awk/tr/cut instead.
 */
const inlineCodeAsTool: FeedbackRule = (commandInfos) => {
  for (const cmd of commandInfos) {
    const code = getInlineCode(cmd)
    if (!code) continue

    // Skip if this already matched JSON (avoid double-flagging)
    const hasJsonKeyword = JSON_KEYWORDS.some(kw => code.includes(kw))
    if (hasJsonKeyword) continue

    const hasStringOp = STRING_OP_KEYWORDS.some(kw => code.includes(kw))
    if (!hasStringOp) continue

    return `hall-pass: Use shell builtins (sed, awk, tr, cut) instead of inline ${cmd.name} scripting — they're auto-approved by hall-pass.`
  }

  return null
}

/** All feedback rules, checked in order. First match wins. */
export const FEEDBACK_RULES: FeedbackRule[] = [
  jsonParsing,
  inlineCodeAsTool,
]

/**
 * Run all feedback rules against the parsed command list.
 * Returns the first matching suggestion, or null if no rules match.
 *
 * Used in hook.ts for pipeline-level cross-command patterns
 * (e.g., curl in one command + python3 -c in another).
 */
export function checkFeedbackRules(commandInfos: CommandInfo[]): string | null {
  for (const rule of FEEDBACK_RULES) {
    const suggestion = rule(commandInfos)
    if (suggestion) return suggestion
  }
  return null
}

/**
 * Per-command feedback check — called from evaluateBashCommand for each command
 * including recursive sub-commands from find -exec and xargs.
 *
 * For top-level commands, pipelineContext is the full pipeline.
 * For sub-commands, pipelineContext provides the pipeline context for
 * cross-command pattern matching (e.g., detecting curl upstream).
 */
export function checkCommandFeedback(
  cmdInfo: CommandInfo,
  pipelineContext: CommandInfo[],
): string | null {
  const code = getInlineCode(cmdInfo)
  if (!code) return null

  // JSON parsing check
  const hasJsonKeyword = JSON_KEYWORDS.some(kw => code.includes(kw))
  if (hasJsonKeyword) {
    const hasFetcher = pipelineContext.some(c => c.name === "curl" || c.name === "wget")
    if (hasFetcher) {
      return `hall-pass: Use \`jq\` for JSON parsing — it's purpose-built, safer, and auto-approved by hall-pass. Example: curl ... | jq '.field'`
    }
    return `hall-pass: Use \`jq\` for JSON parsing instead of inline ${cmdInfo.name} — it's purpose-built, safer, and auto-approved by hall-pass.`
  }

  // String operations check
  const hasStringOp = STRING_OP_KEYWORDS.some(kw => code.includes(kw))
  if (hasStringOp) {
    return `hall-pass: Use shell builtins (sed, awk, tr, cut) instead of inline ${cmdInfo.name} scripting — they're auto-approved by hall-pass.`
  }

  return null
}
