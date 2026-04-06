import { describe, test, expect } from "bun:test"

const HOOK_PATH = new URL("./hook.ts", import.meta.url).pathname

interface HookResult {
  exitCode: number
  stdout: string
  stderr: string
}

/** Run the hook with a simulated Claude Code Bash input */
async function runHook(command: string): Promise<HookResult> {
  const input = JSON.stringify({ tool_name: "Bash", tool_input: { command } })
  const proc = Bun.spawn(["bun", HOOK_PATH], {
    stdin: new Response(input),
    stdout: "pipe",
    stderr: "pipe",
  })
  const [stdout, stderr] = await Promise.all([
    new Response(proc.stdout).text(),
    new Response(proc.stderr).text(),
  ])
  await proc.exited
  return { exitCode: proc.exitCode ?? 1, stdout, stderr }
}

/** Run the hook with a Write/Edit tool input */
async function runHookForTool(toolName: string, toolInput: Record<string, unknown>): Promise<HookResult> {
  const input = JSON.stringify({ tool_name: toolName, tool_input: toolInput })
  const proc = Bun.spawn(["bun", HOOK_PATH], {
    stdin: new Response(input),
    stdout: "pipe",
    stderr: "pipe",
  })
  const [stdout, stderr] = await Promise.all([
    new Response(proc.stdout).text(),
    new Response(proc.stderr).text(),
  ])
  await proc.exited
  return { exitCode: proc.exitCode ?? 1, stdout, stderr }
}

/** Check that the hook allowed (exit 0 + permissionDecision: "allow" on stdout) */
function expectAllow(result: HookResult) {
  expect(result.exitCode).toBe(0)
  const parsed = JSON.parse(result.stdout)
  expect(parsed.hookSpecificOutput.permissionDecision).toBe("allow")
}

/** Check that the hook prompted (exit 0 + ask JSON, no additionalContext) */
function expectPrompt(result: HookResult) {
  expect(result.exitCode).toBe(0)
  const parsed = JSON.parse(result.stdout)
  expect(parsed.hookSpecificOutput.permissionDecision).toBe("ask")
  expect(parsed.hookSpecificOutput.additionalContext).toBeUndefined()
}

/** Check that the hook passed (exit 0, no stdout — no opinion) */
function expectPass(result: HookResult) {
  expect(result.exitCode).toBe(0)
  expect(result.stdout).toBe("")
}

/** Check that the hook allowed with feedback (exit 0 + allow JSON with additionalContext) */
function expectFeedback(result: HookResult, containsText?: string) {
  expect(result.exitCode).toBe(0)
  const parsed = JSON.parse(result.stdout)
  expect(parsed.hookSpecificOutput.permissionDecision).toBe("allow")
  expect(typeof parsed.hookSpecificOutput.additionalContext).toBe("string")
  if (containsText) {
    expect(parsed.hookSpecificOutput.additionalContext).toContain(containsText)
  }
}

describe("hook integration", () => {
  describe("should ALLOW (exit 0 + JSON)", () => {
    const allowed = [
      "git status",
      "git add . && git commit -m 'msg' && git push",
      "grep -r foo /path | head -20",
      "TEST_URL=http://localhost:3334 bun test server/",
      "lsof -ti :3334 | xargs kill",
      "for f in *.ts; do echo $f; done",
      "curl https://example.com | jq .data | sort | head -5",
      "bun run db:generate search-index 2>&1",
      "FOO=bar",
      "docker ps --format '{{.Names}}'",
      "git log --oneline -5 | cat",
      "find . -name '*.ts' | wc -l",
      `find /path -name "*.tsx" -type f -exec grep -l "<Gate " {} \\; 2>/dev/null | head -10`,
      "echo hello && echo world || echo fallback",
      "lsof -i :3334 | grep LISTEN 2>/dev/null",
      "TEST_BASE_URL=http://localhost:3333 bun test server/tests/search.test.ts 2>&1",
    ]

    for (const cmd of allowed) {
      test(cmd, async () => {
        expectAllow(await runHook(cmd))
      })
    }
  })

  describe("git — should ALLOW safe operations (exit 0 + JSON)", () => {
    const allowed = [
      "git status",
      "git log --oneline -5",
      "git diff --stat",
      "git add . && git commit -m 'msg' && git push",
      "git log --oneline -5 | cat",
      "git fetch && git pull",
      "git stash && git checkout main && git stash pop",
      "git -C /some/path status",
      "git branch -a",
      "git push -u origin feat/search",
    ]

    for (const cmd of allowed) {
      test(cmd, async () => {
        expectAllow(await runHook(cmd))
      })
    }
  })

  describe("git — should PROMPT for destructive ops (exit 1)", () => {
    const prompted = [
      // Force push on feature branches is now allowed (f9dc841)
      // Only protected branches prompt:
      "git push --force origin main",
      "git reset --hard",
      "git reset --hard HEAD~3",
      "git clean -f",
      "git checkout .",
      "git restore .",
      "git branch -D feat/old",
      "git push origin main",
      "git stash drop",
      "git stash clear",
    ]

    for (const cmd of prompted) {
      test(cmd, async () => {
        expectPrompt(await runHook(cmd))
      })
    }
  })

  describe("should PROMPT for dangerous commands", () => {
    const prompted = [
      "rm -rf /",
      "sudo apt install foo",
      "dd if=/dev/zero of=disk.img",
      "echo $(rm -rf /)",
      "safe-looking | rm -rf /tmp",
    ]

    for (const cmd of prompted) {
      test(cmd, async () => {
        expectPrompt(await runHook(cmd))
      })
    }
  })

  describe("should PASS for unknown commands (no opinion)", () => {
    const passed = [
      "some-unknown-command --flag",
      "git add . && unknown-cmd",
    ]

    for (const cmd of passed) {
      test(cmd, async () => {
        expectPass(await runHook(cmd))
      })
    }
  })

  describe("transparent wrappers — should ALLOW safe wrapped commands", () => {
    const allowed = [
      "nohup bun server/index.ts",
      "nohup bun --env-file=.env.test.local server/index.ts",
      "nice bun server/index.ts",
      "nice -n 10 bun server/index.ts",
      "timeout 30 bun server/index.ts",
      "timeout --signal=TERM 30 bun server/index.ts",
      "nohup nice bun server/index.ts",
      "timeout 30 git status",
    ]

    for (const cmd of allowed) {
      test(cmd, async () => {
        expectAllow(await runHook(cmd))
      })
    }
  })

  describe("transparent wrappers — should PROMPT for dangerous wrapped commands", () => {
    const prompted = [
      "nohup rm -rf /",
      "nice -n 10 rm -rf /",
    ]

    for (const cmd of prompted) {
      test(cmd, async () => {
        expectPrompt(await runHook(cmd))
      })
    }
  })

  describe("transparent wrappers — should PASS for unknown wrapped commands", () => {
    const passed = [
      "timeout 30 some-unknown-command",
      "nohup unknown-tool --flag",
    ]

    for (const cmd of passed) {
      test(cmd, async () => {
        expectPass(await runHook(cmd))
      })
    }
  })

  test("empty command falls through", async () => {
    expectPrompt(await runHook(""))
  })

  describe("psql — should ALLOW read-only SQL (exit 0 + JSON)", () => {
    const allowed = [
      `psql postgres://user:pass@localhost:5433/db -t -c "SELECT * FROM users"`,
      `psql postgres://user:pass@localhost:5433/db -c "SELECT DISTINCT advertiser_id FROM search_index LIMIT 1" 2>&1`,
      `psql postgres://localhost/db -t -c "SELECT count(*) FROM orders"`,
      `psql -c 'SHOW search_path'`,
      `PGPASSWORD=testpass psql -h localhost -p 5434 -U testuser -d testdb -c "\\dt api_keys"`,
      `psql -c "\\d+ users"`,
      `psql -c "\\l"`,
    ]

    for (const cmd of allowed) {
      test(cmd, async () => {
        expectAllow(await runHook(cmd))
      })
    }
  })

  describe("psql — should PROMPT for writes (exit 1)", () => {
    const prompted = [
      `psql postgres://localhost/db -c "DROP TABLE users"`,
      `psql -c "INSERT INTO users VALUES (1, 'test')"`,
      `psql -c "DELETE FROM users WHERE id = 1"`,
      `psql -c "UPDATE users SET name = 'test'"`,
      `psql -c "TRUNCATE users"`,
      `psql -c "SELECT 1; DROP TABLE users"`,
      // Interactive session (no -c flag) — prompt
      `psql postgres://localhost/db`,
    ]

    for (const cmd of prompted) {
      test(cmd, async () => {
        expectPrompt(await runHook(cmd))
      })
    }
  })

  describe("mysql — should ALLOW read-only SQL (exit 0 + JSON)", () => {
    const allowed = [
      `mysql -u root -e "SELECT * FROM users"`,
      `mysql mydb -e "SHOW TABLES"`,
      `mysql mydb --execute "SELECT count(*) FROM orders"`,
    ]

    for (const cmd of allowed) {
      test(cmd, async () => {
        expectAllow(await runHook(cmd))
      })
    }
  })

  describe("mysql — should PROMPT for writes (exit 1)", () => {
    const prompted = [
      `mysql mydb -e "DROP TABLE users"`,
      `mysql -e "INSERT INTO users VALUES (1, 'test')"`,
      // Interactive session (no -e flag) — prompt
      `mysql -u root mydb`,
    ]

    for (const cmd of prompted) {
      test(cmd, async () => {
        expectPrompt(await runHook(cmd))
      })
    }
  })

  describe("sqlite3 — should ALLOW all (local file-based DB)", () => {
    const allowed = [
      `sqlite3 db.sqlite "SELECT * FROM users"`,
      `sqlite3 -header -column db.sqlite "SELECT count(*) FROM orders"`,
      `sqlite3 db.sqlite "DROP TABLE users"`,
      `sqlite3 db.sqlite "INSERT INTO users VALUES (1, 'test')"`,
      `sqlite3 db.sqlite`,
    ]

    for (const cmd of allowed) {
      test(cmd, async () => {
        expectAllow(await runHook(cmd))
      })
    }
  })

  test("invalid JSON input falls through", async () => {
    const proc = Bun.spawn(["bun", HOOK_PATH], {
      stdin: new Response("not json"),
      stdout: "pipe",
      stderr: "pipe",
    })
    await proc.exited
    expect(proc.exitCode).toBe(1)
  })

  test("allow response contains valid JSON with permissionDecision", async () => {
    const result = await runHook("echo hello")
    expect(result.exitCode).toBe(0)
    const parsed = JSON.parse(result.stdout)
    expect(parsed.hookSpecificOutput.hookEventName).toBe("PreToolUse")
    expect(parsed.hookSpecificOutput.permissionDecision).toBe("allow")
    expect(typeof parsed.hookSpecificOutput.permissionDecisionReason).toBe("string")
  })
})

describe("Write/Edit tool integration", () => {
  describe("Write tool", () => {
    test("safe path → allow", async () => {
      expectAllow(await runHookForTool("Write", { file_path: "/tmp/safe-file.ts" }))
    })

    test("no file_path → allow", async () => {
      expectAllow(await runHookForTool("Write", {}))
    })
  })

  describe("Edit tool", () => {
    test("safe path → allow", async () => {
      expectAllow(await runHookForTool("Edit", { file_path: "/tmp/safe-file.ts" }))
    })

    test("no file_path → allow", async () => {
      expectAllow(await runHookForTool("Edit", {}))
    })
  })
})

describe("Write/Edit secret detection", () => {
  test("Write with AWS key in content → prompt", async () => {
    expectPrompt(await runHookForTool("Write", {
      file_path: "/tmp/config.ts",
      content: `const key = "AKIAIOSFODNN7EXAMPLE"`,
    }))
  })

  test("Edit with GitHub token in new_string → prompt", async () => {
    expectPrompt(await runHookForTool("Edit", {
      file_path: "/tmp/config.ts",
      new_string: `const token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"`,
      old_string: `const token = ""`,
    }))
  })

  test("Write with clean content → allow", async () => {
    expectAllow(await runHookForTool("Write", {
      file_path: "/tmp/safe.ts",
      content: `export const greeting = "hello world"`,
    }))
  })

  test("Edit with PEM private key → prompt", async () => {
    expectPrompt(await runHookForTool("Edit", {
      file_path: "/tmp/certs.ts",
      new_string: `-----BEGIN RSA PRIVATE KEY-----\nMIIEow...`,
      old_string: `// placeholder`,
    }))
  })
})

describe("feedback layer — should ALLOW with additionalContext nudge", () => {
  test("curl | python3 -c with json.loads → allow with jq nudge", async () => {
    const cmd = `curl -s https://api.example.com | python3 -c "import json, sys; print(json.loads(sys.stdin.read())['key'])"`
    expectFeedback(await runHook(cmd), "jq")
  })

  test("curl | node -e with JSON.parse → allow with jq nudge", async () => {
    const cmd = `curl -s https://api.example.com | node -e "process.stdin.on('data', d => console.log(JSON.parse(d).key))"`
    expectFeedback(await runHook(cmd), "jq")
  })

  test("python3 -c with string .split() → allow with shell builtins nudge", async () => {
    const cmd = `python3 -c "print('a,b,c'.split(',')[0])"`
    expectFeedback(await runHook(cmd), "shell builtins")
  })

  test("node -e with .trim() → allow with shell builtins nudge", async () => {
    const cmd = `node -e "console.log(' hello '.trim())"`
    expectFeedback(await runHook(cmd), "shell builtins")
  })
})

describe("docker compose — path false positive fix", () => {
  test("docker compose --env-file .env.local -p myapp ps → allow", async () => {
    expectAllow(await runHook("docker compose --env-file .env.local -p myapp ps"))
  })

  test("docker compose -f docker-compose.yml up -d → allow", async () => {
    expectAllow(await runHook("docker compose -f docker-compose.yml up -d"))
  })
})

describe("recursive feedback — should ALLOW with additionalContext nudge", () => {
  test("find -exec python3 -c with json.loads → allow with jq nudge", async () => {
    const cmd = `find . -exec python3 -c "json.loads(data)" {} \\;`
    expectFeedback(await runHook(cmd), "jq")
  })

  test("find -exec node -e with JSON.parse → allow with jq nudge", async () => {
    const cmd = `find . -exec node -e "JSON.parse(data)" {} \\;`
    expectFeedback(await runHook(cmd), "jq")
  })
})

describe("expanded safelist — integration", () => {
  describe("should ALLOW new safe commands", () => {
    const allowed = [
      "brew install node",
      "brew list",
      "pip3 install flask",
      "xcodebuild -project App.xcodeproj",
      "sw_vers",
      "dig example.com",
      "nslookup example.com",
      "ping -c 3 8.8.8.8",
      "pgrep node",
      "open index.html",
      "ln -s source target",
      "mdfind 'query'",
      "system_profiler SPHardwareDataType",
      "vm_stat",
      "memory_pressure",
      "caddy version",
      "vercel ls",
      "direnv allow",
      "ssh-add -l",
      "ssh-keygen -t ed25519",
      "docker-compose up -d",
      "docker-compose logs",
      "tree -L 2 src/",
      "fold -w 80 file.txt",
      "column -t data.tsv",
      "last -10",
      "log show --last 1h",
      "textutil -convert txt file.docx",
      "osxphotos query --json",
      "powermetrics --samplers smc",
      "pdftotext file.pdf",
      "pdftoppm file.pdf output",
      "pdfinfo file.pdf",
      "ngrok http 3000",
      "sips -g pixelWidth image.png",
      "md5 file.bin",
      "sysctl hw.memsize",
      "dscacheutil -flushcache",
      "pmset -g batt",
      "top -l 1",
      "dns-sd -B _http._tcp local",
      "ioreg -l",
      "mkcert localhost",
    ]

    for (const cmd of allowed) {
      test(cmd, async () => {
        expectAllow(await runHook(cmd))
      })
    }
  })

  describe("should ALLOW timeout wrapping new safe commands", () => {
    const allowed = [
      "timeout 30 brew install node",
      "timeout 10 ping -c 3 8.8.8.8",
      "timeout 5 caddy reload",
    ]

    for (const cmd of allowed) {
      test(cmd, async () => {
        expectAllow(await runHook(cmd))
      })
    }
  })
})

describe("new inspectors — integration", () => {
  describe("xcrun — should evaluate inner command", () => {
    test("xcrun --show-sdk-path → allow", async () => {
      expectAllow(await runHook("xcrun --show-sdk-path"))
    })

    test("xcrun --sdk macosx swiftc main.swift → allow", async () => {
      expectAllow(await runHook("xcrun --sdk macosx swiftc main.swift"))
    })
  })

  describe("ssh — should PROMPT", () => {
    test("ssh user@host → prompt", async () => {
      expectPrompt(await runHook("ssh user@host"))
    })
  })

  describe("osascript — should PROMPT", () => {
    test("osascript -e script → prompt", async () => {
      expectPrompt(await runHook("osascript -e 'display dialog'"))
    })
  })

  describe("defaults — read vs write", () => {
    test("defaults read com.apple.finder → allow", async () => {
      expectAllow(await runHook("defaults read com.apple.finder"))
    })

    test("defaults write com.apple.finder Key -bool true → prompt", async () => {
      expectPrompt(await runHook("defaults write com.apple.finder Key -bool true"))
    })
  })

  describe("launchctl — list vs load", () => {
    test("launchctl list → allow", async () => {
      expectAllow(await runHook("launchctl list"))
    })

    test("launchctl load service.plist → prompt", async () => {
      expectPrompt(await runHook("launchctl load service.plist"))
    })
  })

  describe("networksetup — get vs set", () => {
    test("networksetup -listallnetworkservices → allow", async () => {
      expectAllow(await runHook("networksetup -listallnetworkservices"))
    })

    test("networksetup -setdnsservers Wi-Fi 8.8.8.8 → prompt", async () => {
      expectPrompt(await runHook("networksetup -setdnsservers Wi-Fi 8.8.8.8"))
    })
  })

  describe("railway — subcommand inspection", () => {
    test("railway whoami → allow", async () => {
      expectAllow(await runHook("railway whoami"))
    })

    test("railway status → allow", async () => {
      expectAllow(await runHook("railway status"))
    })

    test("railway run bun start → allow", async () => {
      expectAllow(await runHook("railway run bun start"))
    })

    test("railway run rm -rf / → prompt", async () => {
      expectPrompt(await runHook("railway run rm -rf /"))
    })

    test("railway up → prompt", async () => {
      expectPrompt(await runHook("railway up"))
    })
  })

  describe("new safe commands", () => {
    test("ipconfig getifaddr en0 → allow", async () => {
      expectAllow(await runHook("ipconfig getifaddr en0"))
    })

    test("cc -o main main.c → allow", async () => {
      expectAllow(await runHook("cc -o main main.c"))
    })

    test("gcc -Wall -o test test.c → allow", async () => {
      expectAllow(await runHook("gcc -Wall -o test test.c"))
    })
  })

  describe("redis-cli — read vs write", () => {
    test("redis-cli ping → allow", async () => {
      expectAllow(await runHook("redis-cli ping"))
    })

    test("redis-cli get mykey → allow", async () => {
      expectAllow(await runHook("redis-cli get mykey"))
    })

    test("redis-cli -h localhost -p 6379 info → allow", async () => {
      expectAllow(await runHook("redis-cli -h localhost -p 6379 info"))
    })

    test("redis-cli set mykey value → prompt", async () => {
      expectPrompt(await runHook("redis-cli set mykey value"))
    })

    test("redis-cli flushall → prompt", async () => {
      expectPrompt(await runHook("redis-cli flushall"))
    })

    test("redis-cli (interactive) → prompt", async () => {
      expectPrompt(await runHook("redis-cli"))
    })
  })
})

describe("Write/Edit secret detection", () => {
  test("Write with AWS key in content → prompt", async () => {
    expectPrompt(await runHookForTool("Write", {
      file_path: "/tmp/config.ts",
      content: `const key = "AKIAIOSFODNN7EXAMPLE"`,
    }))
  })

  test("Edit with GitHub token in new_string → prompt", async () => {
    expectPrompt(await runHookForTool("Edit", {
      file_path: "/tmp/config.ts",
      new_string: `const token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"`,
      old_string: `const token = ""`,
    }))
  })

  test("Write with clean content → allow", async () => {
    expectAllow(await runHookForTool("Write", {
      file_path: "/tmp/safe.ts",
      content: `export const greeting = "hello world"`,
    }))
  })

  test("Edit with PEM private key → prompt", async () => {
    expectPrompt(await runHookForTool("Edit", {
      file_path: "/tmp/certs.ts",
      new_string: `-----BEGIN RSA PRIVATE KEY-----\nMIIEow...`,
      old_string: `// placeholder`,
    }))
  })
})

describe("feedback layer — should NOT block legitimate usage", () => {
  test("python3 script.py → allow (not deny)", async () => {
    const result = await runHook("python3 script.py")
    // Should allow (inspector sees no -c flag), NOT deny
    expectAllow(result)
  })

  test("node server.js → allow (not deny)", async () => {
    const result = await runHook("node server.js")
    // Should be allowed (no -e flag), NOT denied
    expectAllow(result)
  })

  test("curl | jq → allow (already using jq)", async () => {
    const result = await runHook("curl -s https://example.com | jq .data")
    expectAllow(result)
  })
})
