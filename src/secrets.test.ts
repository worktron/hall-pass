import { describe, test, expect } from "bun:test"
import { detectSecret } from "./secrets.ts"

describe("detectSecret", () => {
  test("detects AWS access key", () => {
    const result = detectSecret("export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE")
    expect(result).not.toBeNull()
    expect(result!.type).toBe("AWS access key")
  })

  test("detects GitHub token (classic)", () => {
    const result = detectSecret("curl -H 'Authorization: token ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij'")
    expect(result).not.toBeNull()
    expect(result!.type).toBe("GitHub token")
  })

  test("detects GitHub PAT (fine-grained)", () => {
    const result = detectSecret("GITHUB_TOKEN=github_pat_abcdefghijklmnopqrstuv_1234567890")
    expect(result).not.toBeNull()
    expect(result!.type).toBe("GitHub PAT")
  })

  test("detects Anthropic API key", () => {
    const result = detectSecret("ANTHROPIC_API_KEY=sk-ant-api03-abcdefghijklmnopqrstuvwx")
    expect(result).not.toBeNull()
    expect(result!.type).toBe("Anthropic API key")
  })

  test("detects OpenAI API key", () => {
    const result = detectSecret("OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz1234567890")
    expect(result).not.toBeNull()
    expect(result!.type).toBe("OpenAI API key")
  })

  test("detects Slack token", () => {
    const result = detectSecret("SLACK_TOKEN=xoxb-123456789-abcdefgh")
    expect(result).not.toBeNull()
    expect(result!.type).toBe("Slack token")
  })

  test("detects PEM private key header", () => {
    const result = detectSecret("-----BEGIN RSA PRIVATE KEY-----\nMIIEow...")
    expect(result).not.toBeNull()
    expect(result!.type).toBe("PEM private key")
  })

  test("detects Bearer token in curl header", () => {
    const result = detectSecret(`curl -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM"`)
    expect(result).not.toBeNull()
    expect(result!.type).toBe("Bearer token")
  })

  test("returns null for clean commands", () => {
    expect(detectSecret("echo hello world")).toBeNull()
    expect(detectSecret("git status")).toBeNull()
    expect(detectSecret("curl https://example.com")).toBeNull()
  })

  test("returns null for short strings that look like prefixes", () => {
    // sk- alone is too short
    expect(detectSecret("sk-short")).toBeNull()
    // AKIA alone without 16 trailing chars
    expect(detectSecret("AKIA")).toBeNull()
  })

  test("preview is redacted", () => {
    const result = detectSecret("AKIAIOSFODNN7EXAMPLE")
    expect(result).not.toBeNull()
    expect(result!.preview.endsWith("...")).toBe(true)
    expect(result!.preview.length).toBeLessThanOrEqual(11)
  })
})
