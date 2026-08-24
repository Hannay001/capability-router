#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const projectRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const launcher = join(projectRoot, "scripts", "capability-registry");
const result = spawnSync(launcher, // POSIX only: the launcher is an extensionless shebang script
   process.argv.slice(2), {
  env: process.env,
  stdio: "inherit",
});

if (result.error) {
  console.error(`status: error\nsummary: ${result.error.message}`);
  process.exitCode = 1;
} else {
  process.exitCode = result.status ?? 1;
}
