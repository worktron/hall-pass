/**
 * Test preload — loaded once per test process via bunfig.toml `[test] preload`.
 *
 * The hook integration tests (hook.test.ts, adversarial.test.ts) spawn a fresh
 * `bun src/hook.ts` subprocess per case (~300 total). A cold bun spawn is ~0.4s
 * normally, but balloons past bun's 5000ms default per-test timeout when the
 * machine is under load (e.g. overlapping test runs), causing spurious
 * "timed out after 5000ms" failures. The fail count tracked wall-clock time,
 * not code. 20s gives ample headroom so transient slow spawns don't flake.
 *
 * Note: bun does NOT honor `[test] timeout` in bunfig.toml (verified on 1.3.14),
 * so the timeout must be set here via setDefaultTimeout().
 */
import { setDefaultTimeout } from "bun:test"

setDefaultTimeout(20_000)
