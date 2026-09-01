/**
 * Diagnostic log shared by the hook entry points.
 *
 * Always writes to /tmp so a hook that fails before it can load config still
 * leaves a trace. Each entry point appends a few lines per tool call, so the
 * file's growth is capped: once per process, if it exceeds DIAG_MAX_BYTES,
 * only the recent tail is kept.
 */

const DIAG = "/tmp/hall-pass-diag.log"
const DIAG_MAX_BYTES = 1_000_000
const DIAG_KEEP_LINES = 2000

export type DiagFn = (msg: string) => void

/** Build a logger. `prefix` tags every line, e.g. "[codex]". */
export function createDiag(prefix = ""): DiagFn {
  let trimChecked = false
  const tag = prefix ? `${prefix} ` : ""
  return (msg: string) => {
    try {
      const fs = require("fs")
      if (!trimChecked) {
        trimChecked = true
        try {
          if (fs.statSync(DIAG).size > DIAG_MAX_BYTES) {
            const tail = fs.readFileSync(DIAG, "utf8").split("\n").slice(-DIAG_KEEP_LINES).join("\n")
            fs.writeFileSync(DIAG, tail)
          }
        } catch {}
      }
      fs.appendFileSync(DIAG, `${new Date().toISOString()} ${tag}${msg}\n`)
    } catch {}
  }
}
