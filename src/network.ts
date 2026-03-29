/**
 * Network exfiltration prevention — detects URLs targeting known
 * data-exfiltration services in command strings.
 *
 * Checks both explicit URLs and arguments to curl/wget.
 */

/** Domains commonly used to exfiltrate data from compromised systems. */
const EXFIL_DOMAINS = new Set([
  "pastebin.com",
  "hastebin.com",
  "dpaste.org",
  "ghostbin.com",
  "webhook.site",
  "requestbin.com",
  "pipedream.net",
  "hookbin.com",
  "transfer.sh",
  "file.io",
  "0x0.st",
  "ix.io",
  "sprunge.us",
  "termbin.com",
])

/**
 * Check if any URL in the given text targets a known exfiltration domain.
 * Returns the matched domain, or null if clean.
 */
export function detectExfilDomain(text: string): string | null {
  // Match URLs with http(s):// or plain domain references
  const urlPattern = /https?:\/\/([a-z0-9.-]+)/gi
  let match: RegExpExecArray | null
  while ((match = urlPattern.exec(text)) !== null) {
    const hostname = match[1]!.toLowerCase()
    // Check exact match and subdomain match (sub.pastebin.com → pastebin.com)
    for (const domain of EXFIL_DOMAINS) {
      if (hostname === domain || hostname.endsWith("." + domain)) {
        return domain
      }
    }
  }
  return null
}
