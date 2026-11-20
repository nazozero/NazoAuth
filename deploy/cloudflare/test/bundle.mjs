import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

function fixture(status, invalid = false) {
  const root = mkdtempSync(join(tmpdir(), "nazo-worker-bundle-"));
  const directory = join(root, "deploy/cloudflare");
  mkdirSync(join(directory, "node_modules/wrangler/bin"), { recursive: true });
  copyFileSync(new URL("../bundle.mjs", import.meta.url), join(directory, "bundle.mjs"));
  // These tests exercise atomic publication, independently of the real Binaryen
  // integration and ABI checks in prune-worker.mjs's own contract suite.
  writeFileSync(join(directory, "prune-worker.mjs"), `
    import assert from "node:assert/strict";
    import { readFileSync } from "node:fs";
    import { join } from "node:path";
    export function verifyPublishedBundle(directory) {
      assert.equal(readFileSync(join(directory, "current.wasm"), "utf8"), "current artifact");
      if (${invalid}) throw new Error("invalid published ABI");
    }
  `);
  mkdirSync(join(directory, "bundled"));
  writeFileSync(join(directory, "bundled/old.wasm"), "previous validated artifact");
  writeFileSync(join(directory, "node_modules/wrangler/bin/wrangler.js"), `
    const assert = require("node:assert/strict");
    const { writeFileSync } = require("node:fs");
    const { join } = require("node:path");
    const args = process.argv.slice(2);
    assert.deepEqual(args.slice(0, 3), ["deploy", "--dry-run", "--outdir"]);
    assert.deepEqual(args.slice(4), ["--config", "wrangler.toml"]);
    writeFileSync(join(args[3], "current.wasm"), "current artifact");
    writeFileSync(join(args[3], "shim.js"), "import './current.wasm';");
    process.exitCode = ${status};
  `);
  return { root, directory };
}

test("a successful bundle contains only its current module graph", () => {
  const { root, directory } = fixture(0);
  try {
    const result = spawnSync(process.execPath, [join(directory, "bundle.mjs")], { encoding: "utf8" });
    assert.equal(result.status, 0, result.stderr);
    assert.deepEqual(readdirSync(join(directory, "bundled")).sort(), ["current.wasm", "shim.js"]);
    assert.equal(readFileSync(join(directory, "bundled/current.wasm"), "utf8"), "current artifact");
    assert.equal(readdirSync(directory).filter(name => name.startsWith("bundled-")).length, 0);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("a failed build preserves the previous bundle and removes partial output", () => {
  const { root, directory } = fixture(23);
  try {
    const result = spawnSync(process.execPath, [join(directory, "bundle.mjs")], { encoding: "utf8" });
    assert.equal(result.status, 23, result.stderr);
    assert.deepEqual(readdirSync(join(directory, "bundled")), ["old.wasm"]);
    assert.equal(existsSync(join(directory, "bundled/current.wasm")), false);
    assert.equal(readdirSync(directory).filter(name => name.startsWith("bundled-")).length, 0);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("an invalid published ABI preserves the previous bundle", () => {
  const { root, directory } = fixture(0, true);
  try {
    const result = spawnSync(process.execPath, [join(directory, "bundle.mjs")], { encoding: "utf8" });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /invalid published ABI/);
    assert.deepEqual(readdirSync(join(directory, "bundled")), ["old.wasm"]);
    assert.equal(readdirSync(directory).filter(name => name.startsWith("bundled-")).length, 0);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
