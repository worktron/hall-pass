/**
 * Command kinds with Jev, offline.
 *
 * Jev is TypeSafe AI's System One classifier: it answers a choice among
 * labels we define, with a probability for each, at $0.042 per million
 * input tokens. Here it labels the commands the audit log already holds, so
 * a person can grow the deterministic rules from the result. It never
 * decides anything at runtime: the agent writes the command, a prompt-
 * injected agent can write `# read-only listing` next to an rm, and Jev
 * follows wording (always-be-closing found it calling 83 of 89 tabs
 * "abandoned" when asked a question the input could not answer).
 *
 * The unit is one simple command, judged by today's rules on its own:
 *   unknown   no rule knows the name: the safelist candidates come from here
 *   judgment  a judgment-call prompt (rm, perl -e, sed -i, bash script.sh)
 *   allowed   allowed today: Jev's view of these finds possible holes, and
 *             since they are safe by construction, shows how often Jev
 *             mislabels safe commands
 * Hard stops (protected paths, secrets, injection) are never sent.
 *
 * What leaves the machine is the command's words and up to 1000 characters
 * of a heredoc it reads, after redactCommand: home directory as ~, no
 * environment values, URLs without credentials or query values, op://
 * references and long opaque tokens elided. A line detectSecret flags is
 * never sent at all.
 */

import { createHash } from "crypto"
import { homedir } from "os"
import type { AuditEntry } from "./audit.ts"
import type { HallPassConfig } from "./config.ts"
import { createEvalContext } from "./evaluate.ts"
import { extractCommandInfos, type CommandInfo } from "./parser.ts"
import { detectSecret } from "./secrets.ts"

export const JEV_ENDPOINT = process.env.HALL_PASS_JEV_ENDPOINT ?? "https://api.typesafe.ai/v1/systemone"
// Pinned: stored confidences are only comparable within one model version.
export const JEV_MODEL = "jev-1.13.0"
export const PRICE_PER_INPUT_TOKEN = 0.042 / 1e6

// What the command does, not whether it is safe: Jev answers what is on the
// line, and the policy stays in code.
export const KIND_QUESTION = {
  type: "choice",
  instructions: "What does this shell command do?",
  criteria: {
    inspect: "Only reads or prints: lists files, shows contents, status, logs, help or version, or queries without changing anything",
    build: "Builds, tests, typechecks, lints, formats, or installs dependencies for the project in the current directory",
    write: "Creates, edits, moves, or copies files in the project or a temporary directory",
    delete: "Deletes or overwrites files, branches, data, or history",
    remote: "Changes or sends something to another machine or service: push, deploy, publish, upload, send a message, write to a database or an API",
    credentials: "Reads, prints, creates, or moves passwords, keys, tokens, or other credentials",
    run: "Runs code the command line does not show: a script file, inline code, or a program passed as an argument",
    system: "Changes the machine itself: system settings, services, processes, users, file permissions, or shell configuration",
  },
} as const

export type Kind = keyof typeof KIND_QUESTION.criteria
export const KINDS = Object.keys(KIND_QUESTION.criteria) as Kind[]
export const SAFE_KINDS: ReadonlySet<Kind> = new Set(["inspect", "build"])
export const RISKY_KINDS: ReadonlySet<Kind> = new Set(["delete", "remote", "credentials", "system"])

export const QUESTIONS_VERSION = createHash("sha256").update(JSON.stringify(KIND_QUESTION)).digest("hex").slice(0, 12)

// ── Redaction ────────────────────────────────────────

const ARG_CHARS = 2000
const STDIN_CHARS = 1000

/** Origin and path, with credentials dropped and only query parameter names kept. */
export function redactUrl(raw: string): string {
  if (/^op:\/\//i.test(raw)) return "op://…"
  try {
    const url = new URL(raw)
    const names = [...url.searchParams.keys()]
    const query = names.length ? "?" + names.map((n) => `${n}=…`).join("&") : ""
    const host = url.host ? `//${url.host}` : ""
    return `${url.protocol}${host}${url.pathname}${query}`
  } catch {
    return raw.replace(/\?.*$/, "?…")
  }
}

/** One word or heredoc with everything that might be a secret taken out. */
export function redactText(text: string, home = homedir()): string {
  let out = text
  if (home) out = out.split(home).join("~")
  out = out.replace(/\b[a-z][a-z0-9+.-]*:\/\/[^\s'"`]+/gi, (url) => redactUrl(url))
  out = out.replace(
    /\b(authorization|cookie|x-api-key|api[-_]?key|access[-_]?token|token|password|passwd|secret)(\s*[:=]\s*)((?:bearer|basic|token)\s+\S+|"[^"]*"|'[^']*'|\S+)/gi,
    "$1$2…",
  )
  // Long opaque strings with letters and digits: keys, tokens, hashes.
  out = out.replace(/(?<![\w/.-])(?=[A-Za-z0-9_+/=-]*\d)(?=[A-Za-z0-9_+/=-]*[A-Za-z])[A-Za-z0-9_+/=-]{32,}/g, "…")
  return out
}

function quote(word: string): string {
  if (word === "") return "''"
  if (/^[A-Za-z0-9_@%+=:,./~…-]+$/.test(word)) return word
  return `'${word.replace(/'/g, `'\\''`)}'`
}

function cap(text: string, max: number): string {
  return text.length > max ? text.slice(0, max) + " …" : text
}

export interface JevState {
  command: string
  stdin?: string
}

/** What Jev sees for one command, or null when it must not be sent. */
export function redactCommand(cmd: CommandInfo, home = homedir()): JevState | null {
  const words = [...cmd.assigns.map((a) => `${a.name}=…`), ...cmd.args.map((a) => quote(redactText(a, home)))]
  const state: JevState = { command: cap(words.join(" "), ARG_CHARS) }
  if (cmd.stdin) state.stdin = cap(redactText(cmd.stdin, home), STDIN_CHARS)
  if (detectSecret(JSON.stringify(state))) return null
  return state
}

// ── Extraction ───────────────────────────────────────

export type Bucket = "unknown" | "judgment" | "allowed"

export interface Item {
  /** Hash of the state: one paid answer per distinct thing sent. */
  key: string
  state: JevState
  name: string
  /** The name and its subcommand when it has one: `tmux ls`, `dev status`. */
  group: string
  bucket: Bucket
  /** Today's reason, for judgment calls. */
  reason?: string
  /** Times this command appeared in the audit log. */
  uses: number
}

export function stateKey(state: JevState): string {
  return createHash("sha256").update(JSON.stringify(state)).digest("hex").slice(0, 16)
}

function groupOf(cmd: CommandInfo): string {
  // Only the word right after the name: in `grep -n announce` the pattern is not a subcommand.
  const sub = cmd.args[1]
  return sub && /^[a-z][a-z0-9-]*$/.test(sub) ? `${cmd.name} ${sub}` : cmd.name
}

export type ParseFn = (command: string) => Promise<unknown | null>

/** shfmt's AST for a line, or null when it does not parse. */
export function shfmtParser(shfmtBin: string): ParseFn {
  return async (command) => {
    const proc = Bun.spawn([shfmtBin, "-ln", "bash", "--tojson"], { stdin: new Response(command), stdout: "pipe", stderr: "pipe" })
    const stdout = await new Response(proc.stdout).text()
    if ((await proc.exited) !== 0) return null
    try {
      return JSON.parse(stdout)
    } catch {
      return null
    }
  }
}

/**
 * Every distinct simple command in the log's Bash decisions, bucketed by
 * how today's rules judge it alone. Lines with a secret are left out whole.
 */
export async function extractItems(
  entries: AuditEntry[],
  opts: { config: HallPassConfig; shfmtBin: string; parse?: ParseFn; home?: string; concurrency?: number },
): Promise<Item[]> {
  const parse = opts.parse ?? shfmtParser(opts.shfmtBin)
  const lines = new Map<string, number>()
  for (const e of entries) {
    if ((e.event ?? "decision") !== "decision" || e.tool !== "Bash" || !e.input) continue
    if (e.host === "codex") continue
    lines.set(e.input, (lines.get(e.input) ?? 0) + 1)
  }

  const items = new Map<string, Item>()
  const todo = [...lines.entries()].filter(([line]) => !detectSecret(line))
  let cursor = 0
  const worker = async () => {
    while (cursor < todo.length) {
      const [line, count] = todo[cursor++]!
      const ast = await parse(line)
      if (!ast) continue
      const infos = extractCommandInfos(ast)
      const ctx = createEvalContext(opts.config, infos, opts.shfmtBin)
      for (const cmd of infos) {
        const result = ctx.evaluate(cmd)
        let bucket: Bucket
        let reason: string | undefined
        if (result.decision === "allow") bucket = "allowed"
        else if (result.decision === "pass") bucket = "unknown"
        else if (result.decision === "feedback") {
          bucket = "judgment"
          reason = "nudge"
        } else if (result.hard) continue
        else {
          bucket = "judgment"
          reason = result.reason
        }
        const state = redactCommand(cmd, opts.home)
        if (!state) continue
        const key = stateKey(state)
        const seen = items.get(key)
        if (seen) seen.uses += count
        else items.set(key, { key, state, name: cmd.name, group: groupOf(cmd), bucket, reason, uses: count })
      }
    }
  }
  await Promise.all(Array.from({ length: opts.concurrency ?? 16 }, worker))
  return [...items.values()].sort((a, b) => a.key.localeCompare(b.key))
}

// ── The request ──────────────────────────────────────

export function buildRequest(state: JevState) {
  return { model: JEV_MODEL, state, questions: { kind: KIND_QUESTION } }
}

export interface Answer {
  key: string
  questionsVersion: string
  model: string
  kind: Kind
  confidence: number
  probabilities: Record<Kind, number>
  inputTokens: number
  askedAt: string
}

/** The kind with its confidence and every kind's probability, or null for anything malformed. */
export function parseAnswer(body: unknown): Omit<Answer, "key" | "questionsVersion" | "askedAt"> | null {
  const b = body as { model?: string; answers?: { kind?: { choice?: string; confidence?: number; probabilities?: Record<string, number> } }; usage?: { input_tokens?: number } }
  const answer = b?.answers?.kind
  if (!answer || !answer.choice || !(answer.choice in KIND_QUESTION.criteria)) return null
  if (!Number.isFinite(answer.confidence)) return null
  const probabilities = {} as Record<Kind, number>
  for (const kind of KINDS) {
    const p = answer.probabilities?.[kind]
    probabilities[kind] = Number.isFinite(p) ? p! : 0
  }
  return {
    model: b.model || JEV_MODEL,
    kind: answer.choice as Kind,
    confidence: answer.confidence!,
    probabilities,
    inputTokens: Number.isFinite(b.usage?.input_tokens) ? b.usage!.input_tokens! : 0,
  }
}

export async function askJev(item: Item, key: string, opts: { fetchImpl?: typeof fetch; now?: () => Date } = {}): Promise<Answer> {
  const fetchImpl = opts.fetchImpl ?? fetch
  for (let attempt = 1; ; attempt++) {
    const res = await fetchImpl(JEV_ENDPOINT, {
      method: "POST",
      headers: { Authorization: `Bearer ${key}`, "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify(buildRequest(item.state)),
    })
    if (res.ok) {
      const parsed = parseAnswer(await res.json())
      if (!parsed) throw new Error("Jev answered without a usable kind")
      return { key: item.key, questionsVersion: QUESTIONS_VERSION, askedAt: (opts.now?.() ?? new Date()).toISOString(), ...parsed }
    }
    if ((res.status === 429 || res.status >= 500) && attempt < 6) {
      await Bun.sleep(1000 * 2 ** (attempt - 1))
      continue
    }
    throw new Error(`Jev answered ${res.status}: ${(await res.text()).slice(0, 200)}`)
  }
}

/**
 * Rough input tokens for one request. Jev bills about one token per two
 * characters of the request: the first full run (2026-10-04) sent 7,303
 * requests, estimated at 2.05M tokens by four characters a token, and was
 * billed 4.18M.
 */
export function estimateTokens(item: Item): number {
  return Math.ceil(JSON.stringify(buildRequest(item.state)).length / 2)
}

// ── The report ───────────────────────────────────────

export interface Candidate {
  /** A command name, or a name and subcommand. */
  group: string
  uses: number
  commands: number
  minConfidence: number
  kinds: Partial<Record<Kind, number>>
  examples: string[]
}

export interface Report {
  answered: Record<Bucket, { items: number; answered: number }>
  /** Unknown names (or name + subcommand) Jev reads as inspect or build every time. */
  candidates: Candidate[]
  /** Allowed commands Jev reads as delete, remote, credentials or system. */
  holes: { item: Item; answer: Answer }[]
  /** Per judgment-call reason: how Jev reads those commands. */
  judgment: { reason: string; items: number; uses: number; kinds: Partial<Record<Kind, number>>; safe: Item[] }[]
  /** How Jev reads commands today's rules allow: anything risky here is a hole or a Jev mistake. */
  allowedKinds: Partial<Record<Kind, number>>
}

function tally(answers: Answer[]): Partial<Record<Kind, number>> {
  const out: Partial<Record<Kind, number>> = {}
  for (const a of answers) out[a.kind] = (out[a.kind] ?? 0) + 1
  return out
}

export function buildReport(items: Item[], answers: Map<string, Answer>, opts: { minConfidence?: number; minUses?: number } = {}): Report {
  const minConfidence = opts.minConfidence ?? 0.8
  const minUses = opts.minUses ?? 2
  const isSafe = (a: Answer | undefined) => !!a && SAFE_KINDS.has(a.kind) && a.confidence >= minConfidence

  const answered = { unknown: { items: 0, answered: 0 }, judgment: { items: 0, answered: 0 }, allowed: { items: 0, answered: 0 } }
  for (const item of items) {
    answered[item.bucket].items++
    if (answers.has(item.key)) answered[item.bucket].answered++
  }

  // Safelist candidates: a whole name when every use of it reads safe,
  // else each of its subcommands that does. Only fully answered groups count.
  const unknown = items.filter((i) => i.bucket === "unknown")
  const byName = Map.groupBy(unknown, (i) => i.name)
  const candidates: Candidate[] = []
  const candidate = (group: string, members: Item[]): Candidate | null => {
    const memberAnswers = members.map((m) => answers.get(m.key))
    if (!memberAnswers.every(isSafe)) return null
    const uses = members.reduce((n, m) => n + m.uses, 0)
    if (uses < minUses) return null
    const known = memberAnswers as Answer[]
    return {
      group,
      uses,
      commands: members.length,
      minConfidence: Math.min(...known.map((a) => a.confidence)),
      kinds: tally(known),
      examples: [...members].sort((a, b) => b.uses - a.uses).slice(0, 3).map((m) => m.state.command),
    }
  }
  for (const [name, members] of byName) {
    const whole = candidate(name, members)
    if (whole) {
      candidates.push(whole)
      continue
    }
    for (const [group, sub] of Map.groupBy(members, (m) => m.group)) {
      if (group === name) continue
      const c = candidate(group, sub)
      if (c) candidates.push(c)
    }
  }
  candidates.sort((a, b) => b.uses - a.uses || a.group.localeCompare(b.group))

  const allowed = items.filter((i) => i.bucket === "allowed")
  const holes = allowed
    .map((item) => ({ item, answer: answers.get(item.key)! }))
    .filter(({ answer }) => answer && RISKY_KINDS.has(answer.kind) && answer.confidence >= minConfidence)
    .sort((a, b) => b.answer.confidence - a.answer.confidence || b.item.uses - a.item.uses)

  const judgmentItems = items.filter((i) => i.bucket === "judgment")
  const judgment = [...Map.groupBy(judgmentItems, (i) => i.reason ?? "?")]
    .map(([reason, members]) => {
      const known = members.map((m) => answers.get(m.key)).filter((a): a is Answer => !!a)
      return {
        reason,
        items: members.length,
        uses: members.reduce((n, m) => n + m.uses, 0),
        kinds: tally(known),
        safe: members.filter((m) => isSafe(answers.get(m.key))).sort((a, b) => b.uses - a.uses),
      }
    })
    .sort((a, b) => b.uses - a.uses)

  const allowedKinds = tally(allowed.map((i) => answers.get(i.key)).filter((a): a is Answer => !!a))

  return { answered, candidates, holes, judgment, allowedKinds }
}

// ── Selection ────────────────────────────────────────

/**
 * What to ask about: every unknown command and judgment call, and up to
 * `perGroup` allowed commands per name or name and subcommand, and twenty
 * times that per name (0 for all). A first argument is not always a
 * subcommand (`grep presence`), so the per-name cap bounds those.
 * Allowed commands are tens of thousands of greps and seds; a sample per
 * group covers every shape of command for the holes list at a fraction of
 * the requests and of the text sent. Keys are hashes, so the first few by
 * key are a stable pseudo-random sample.
 */
export function selectItems(items: Item[], opts: { buckets: ReadonlySet<Bucket>; perGroup: number }): Item[] {
  const taken = new Map<string, number>()
  const perName = new Map<string, number>()
  return [...items]
    .sort((a, b) => a.key.localeCompare(b.key))
    .filter((item) => {
      if (!opts.buckets.has(item.bucket)) return false
      if (item.bucket !== "allowed" || opts.perGroup <= 0) return true
      const n = taken.get(item.group) ?? 0
      const m = perName.get(item.name) ?? 0
      if (n >= opts.perGroup || m >= opts.perGroup * 20) return false
      taken.set(item.group, n + 1)
      perName.set(item.name, m + 1)
      return true
    })
}
