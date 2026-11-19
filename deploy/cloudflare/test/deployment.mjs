import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../../../', import.meta.url));
const read = path => readFileSync(new URL(path, import.meta.url), 'utf8');

test('Cloudflare button uses the complete Rust workspace root', () => {
  const rootPkg = JSON.parse(read('../../../package.json'));
  const wrangler = read('../../../wrangler.toml');
  assert.match(rootPkg.scripts.build, /prepare-build\.sh/);
  assert.match(rootPkg.scripts.deploy, /publish\.sh/);
  assert.match(wrangler, /^main = "crates\/server-worker\/build\/worker\/shim\.mjs"$/m);
  assert.match(wrangler, /^migrations_dir = "crates\/authorization-server-d1\/migrations"$/m);
  assert.match(wrangler, /^binding = "NAZO_DB"$/m);
  assert.match(wrangler, /^workers_dev = false$/m);
  assert.match(wrangler, /^binding = "NAZO_VERSION"$/m);
  const nested = JSON.parse(read('../package.json'));
  assert.match(nested.scripts['db:migrate'], /NAZO_DB --remote --config \.\.\/\.\.\/wrangler\.toml/);
  assert.match(nested.scripts.deploy, /--config \.\.\/\.\.\/wrangler\.toml/);
});

test('build and publish entrypoints use pinned tooling and migration before deploy', () => {
  const build = read('../prepare-build.sh');
  const publish = read('../publish.sh');
  assert.match(build, /1\.100\.0/);
  assert.match(build, /wasm32-unknown-unknown/);
  assert.match(build, /worker-build --version 0\.9\.0 --locked/);
  assert.ok(publish.indexOf('db:migrate') < publish.indexOf('npm run deploy'));
});

test('bootstrap refuses missing private input without touching remote resources', () => {
  const outcome = spawnSync(process.execPath, [fileURLToPath(new URL('../bootstrap.mjs', import.meta.url))], {
    cwd: root, encoding: 'utf8',
  });
  assert.notEqual(outcome.status, 0);
  assert.match(outcome.stderr, /Usage: npm run bootstrap/);
});
