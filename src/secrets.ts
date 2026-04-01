/**
 * Secret detection — scans strings for hardcoded credentials.
 *
 * Used for:
 *   - Bash command strings (catch `curl -H "Authorization: Bearer sk-..."`)
 *   - Write/Edit content (catch secrets being written to files)
 *
 * Returns the first match found, or null if clean.
 */

interface SecretMatch {
  type: string
  /** Short redacted preview: first 4 chars + "..." */
  preview: string
}

const SECRET_PATTERNS: { type: string; pattern: RegExp }[] = [
  // AWS access keys
  { type: "AWS access key", pattern: /\b(AKIA|ASIA)[0-9A-Z]{16}\b/ },
  // GitHub tokens (classic + fine-grained)
  { type: "GitHub token", pattern: /\b(ghp_|ghs_|gho_|ghu_|ghr_)[0-9a-zA-Z]{36}\b/ },
  { type: "GitHub PAT", pattern: /\bgithub_pat_[0-9a-zA-Z_]{22,}\b/ },
  // Anthropic API keys
  { type: "Anthropic API key", pattern: /\bsk-ant-[0-9a-zA-Z_-]{20,}\b/ },
  // OpenAI API keys (sk-proj-..., sk-svcacct-..., etc.)
  { type: "OpenAI API key", pattern: /\bsk-(?:proj|svcacct|[a-zA-Z0-9])[a-zA-Z0-9_-]{20,}\b/ },
  // Slack tokens
  { type: "Slack token", pattern: /\bxox[baprs]-[0-9a-zA-Z-]{10,}\b/ },
  // PEM private keys
  { type: "PEM private key", pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/ },
  // Generic "Bearer" tokens in headers (common in curl commands)
  { type: "Bearer token", pattern: /Bearer\s+[0-9a-zA-Z_.-]{20,}/ },
]

/**
 * Scan a string for hardcoded secrets.
 * Returns the first match found, or null.
 */
export function detectSecret(text: string): SecretMatch | null {
  for (const { type, pattern } of SECRET_PATTERNS) {
    const match = pattern.exec(text)
    if (match) {
      const value = match[0]
      const preview = value.slice(0, 8) + "..."
      return { type, preview }
    }
  }
  return null
}
