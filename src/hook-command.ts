/**
 * The command a host registers to run hall-pass's hook.
 *
 * One owner for the string: install.ts writes it into the host's settings,
 * and `hall-pass codex-hook` (cli.ts) prints it for programs that write a
 * Codex hooks file of their own. The path is the real checkout, even when
 * hall-pass was reached through a link on the PATH, because the hook must
 * keep running from where the source lives.
 */

import { realpathSync } from "fs"
import { resolve } from "path"

export type HookHost = "claude" | "codex"

export function hookCommand(host: HookHost): string {
  const entry = host === "codex" ? "codex-hook.ts" : "hook.ts"
  return `bun ${resolve(realpathSync(import.meta.dir), entry)}`
}
