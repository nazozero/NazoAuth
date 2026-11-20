import { spawnSync } from "node:child_process";
import { mkdtempSync, renameSync, rmSync } from "node:fs";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../../", import.meta.url));
const output = fileURLToPath(new URL("./bundled", import.meta.url));
const staging = mkdtempSync(`${output}-`);
try {
  const result = spawnSync(process.execPath, [
    fileURLToPath(new URL("./node_modules/wrangler/bin/wrangler.js", import.meta.url)),
    "deploy", "--dry-run", "--outdir", staging, "--config", "wrangler.toml",
  ], { cwd: root, stdio: "inherit" });
  if (result.error) throw result.error;
  process.exitCode = result.status ?? 1;
  if (process.exitCode === 0) {
    // A successful bundle replaces its complete module graph. Older hashed
    // WASM files must never become part of a later release directory.
    rmSync(output, { recursive: true, force: true });
    renameSync(staging, output);
  }
} finally {
  rmSync(staging, { recursive: true, force: true });
}
