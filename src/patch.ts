/**
 * Codex `apply_patch` format — the one file-edit primitive Codex has.
 *
 * Codex has no Write or Edit tool: every file change arrives as a single
 * patch document, either as the `apply_patch` tool (hook input
 * `tool_input.command` holds the patch) or as `apply_patch <<'EOF' … EOF`
 * through the shell tool. The format is simple and line-oriented:
 *
 *   *** Begin Patch
 *   *** Add File: src/new.ts
 *   +line of new content
 *   *** Update File: src/old.ts
 *   *** Move to: src/renamed.ts        (optional, right after Update File)
 *   @@ hunk context
 *    context line
 *   -removed line
 *   +added line
 *   *** Delete File: src/gone.ts
 *   *** End Patch
 *
 * This module extracts what the safety checks need: which paths are
 * touched, how (write vs delete), and the text being added. It does not
 * apply the patch.
 */

import type { HallPassConfig } from "./config.ts"
import { checkFilePath } from "./paths.ts"
import { detectSecret } from "./secrets.ts"

export interface PatchFile {
  op: "add" | "update" | "delete"
  path: string
  /** Destination of a `*** Move to:` rename on an Update File block. */
  movedTo?: string
  /** Lines the patch adds (leading `+` stripped), joined with newlines. */
  added: string
}

const BEGIN = "*** Begin Patch"
const END = "*** End Patch"

/**
 * Parse an apply_patch document into per-file operations. Returns null when
 * the text has no `*** Begin Patch` marker — the caller then has no patch
 * to judge and should say so rather than guess.
 */
export function parseApplyPatch(text: string): PatchFile[] | null {
  const start = text.indexOf(BEGIN)
  if (start === -1) return null
  const body = text.slice(start + BEGIN.length)
  const end = body.indexOf(END)
  const lines = (end === -1 ? body : body.slice(0, end)).split("\n")

  const files: PatchFile[] = []
  let current: PatchFile | null = null
  const addedLines: string[] = []
  const flush = () => {
    if (current) {
      current.added = addedLines.join("\n")
      files.push(current)
    }
    addedLines.length = 0
  }

  for (const raw of lines) {
    const line = raw.replace(/\r$/, "")
    let m: RegExpMatchArray | null
    if ((m = line.match(/^\*\*\* Add File: (.+)$/))) {
      flush()
      current = { op: "add", path: m[1]!.trim(), added: "" }
    } else if ((m = line.match(/^\*\*\* Update File: (.+)$/))) {
      flush()
      current = { op: "update", path: m[1]!.trim(), added: "" }
    } else if ((m = line.match(/^\*\*\* Delete File: (.+)$/))) {
      flush()
      current = { op: "delete", path: m[1]!.trim(), added: "" }
    } else if ((m = line.match(/^\*\*\* Move to: (.+)$/))) {
      if (current) current.movedTo = m[1]!.trim()
    } else if (line.startsWith("+") && current) {
      addedLines.push(line.slice(1))
    }
    // "@@" hunk headers, " " context, "-" removals, "*** End of File": ignored
  }
  flush()
  return files
}

export type PatchCheck =
  | { ok: true; files: PatchFile[] }
  | { ok: false; reason: string; message: string; files: PatchFile[] }

/**
 * Run the file-path protection and secret scan over every file in a patch.
 * Same rules the Write/Edit path applies in Claude Code: protected and
 * read-only paths block writes, no-delete paths block deletes, and added
 * content must not carry a hardcoded credential.
 */
export function checkPatch(files: PatchFile[], config: HallPassConfig): PatchCheck {
  for (const file of files) {
    const op = file.op === "delete" ? "delete" : "write"
    const targets = file.movedTo ? [file.path, file.movedTo] : [file.path]
    for (const target of targets) {
      const decision = checkFilePath(target, op, config)
      if (!decision.allowed) {
        return { ok: false, reason: `path-blocked: ${decision.reason}`, message: `Patch targets ${target}, which ${decision.reason}`, files }
      }
    }
    if (file.added) {
      const secret = detectSecret(file.added)
      if (secret) {
        return { ok: false, reason: `secret: ${secret.type}`, message: `Patch to ${file.path} contains a hardcoded ${secret.type} (${secret.preview})`, files }
      }
    }
  }
  return { ok: true, files }
}
