#!/usr/bin/env bun

/**
 * `hall-pass init` and the `hall-pass-init` alias: write the default config
 * when none exists. An existing config is left as it is, and init exits 1
 * naming it, so a mistyped or exploratory call never loses the user's config.
 */

import { configExistsMessage, initConfig } from "./config.ts"

export async function runInit(): Promise<number> {
  const { path, created } = await initConfig()
  if (!created) {
    console.error(configExistsMessage(path))
    return 1
  }
  console.log(`Created default config at ${path}`)
  console.log("Edit this file to customize hall-pass behavior.")
  return 0
}

if (import.meta.main) process.exit(await runInit())
