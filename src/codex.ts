/**
 * Codex adapter: turn a hall-pass decision into what Codex's hook protocol
 * can carry.
 *
 * Codex cloned Claude Code's hook wire format (same stdin fields, same
 * `hookSpecificOutput` shape), so the decision pipeline in decide.ts runs
 * unchanged. What differs is what a hook is allowed to say back:
 *
 *   PreToolUse — can DENY or add context. `permissionDecision: "ask"` is
 *     parsed but unsupported: Codex marks the hook failed and runs the
 *     tool anyway. So a hall-pass "ask" cannot become a prompt here.
 *
 *   PermissionRequest — fires only when Codex is about to show its own
 *     approval prompt (a sandbox escalation, network access). A hook can
 *     ALLOW (the prompt is skipped), DENY, or say nothing (the prompt is
 *     shown). This is where hall-pass's "allow" earns its keep.
 *
 * The mapping, per decision:
 *
 *   allow     PreToolUse: nothing.  PermissionRequest: allow.
 *   feedback  PreToolUse: additionalContext (the nudge).  PermissionRequest: allow.
 *   ask, hard PreToolUse: deny.  PermissionRequest: deny.
 *             (config `codex.deny_hard_stops = false` downgrades both to
 *             the soft-ask behavior below)
 *   ask, soft PreToolUse: a systemMessage carrying hall-pass's reason, so
 *             the user sees why before Codex's native prompt.
 *             PermissionRequest: nothing — the native prompt stands.
 *   pass      nothing on either event.
 *
 * Hard stops are the class Claude Code would never auto-approve either:
 * protected paths, hardcoded secrets, code injection (curl | bash, LD_PRELOAD),
 * exfiltration domains, pushes to protected branches. In Claude Code they
 * become an "ask" so the user stays in charge; Codex has no "ask", so they
 * become a deny. In sandboxed Codex modes most of them would have hit a
 * PermissionRequest anyway (network is off, writes outside the workspace
 * are blocked); the deny matters in danger-full-access, where nothing else
 * would stop them.
 */

import type { HookDecision } from "./decide.ts"
import type { HallPassConfig } from "./config.ts"

export type CodexEvent = "PreToolUse" | "PermissionRequest"

/** Tool names hall-pass judges under Codex. Everything else is left alone. */
export const CODEX_TOOLS = new Set(["Bash", "apply_patch"])

/**
 * The JSON to write to stdout for `event`, or null to write nothing
 * (exit 0 with no output: "no opinion", Codex continues its normal flow).
 */
export function codexOutput(event: CodexEvent, decision: HookDecision, config: HallPassConfig): Record<string, unknown> | null {
  const deny = decision.decision === "ask" && decision.hard === true && config.codex.deny_hard_stops

  if (event === "PreToolUse") {
    switch (decision.decision) {
      case "allow":
      case "pass":
        return null
      case "feedback":
        return { hookSpecificOutput: { hookEventName: "PreToolUse", additionalContext: decision.suggestion } }
      case "ask":
        if (deny) {
          return {
            hookSpecificOutput: {
              hookEventName: "PreToolUse",
              permissionDecision: "deny",
              permissionDecisionReason: `hall-pass: ${decision.message}`,
            },
          }
        }
        return { systemMessage: `hall-pass: ${decision.message}` }
    }
  }

  // PermissionRequest
  switch (decision.decision) {
    case "allow":
    case "feedback":
      return { hookSpecificOutput: { hookEventName: "PermissionRequest", decision: { behavior: "allow" } } }
    case "ask":
      if (deny) {
        return {
          hookSpecificOutput: {
            hookEventName: "PermissionRequest",
            decision: { behavior: "deny", message: `hall-pass: ${decision.message}` },
          },
        }
      }
      return null
    case "pass":
      return null
  }
}
