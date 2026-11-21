import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { delimiter, join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../../../', import.meta.url));
const read = path => readFileSync(new URL(path, import.meta.url), 'utf8');

test('Cloudflare button uses the complete Rust workspace root', () => {
  const rootPkg = JSON.parse(read('../../../package.json'));
  const wrangler = read('../../../wrangler.toml');
  assert.match(rootPkg.scripts.build, /prepare-build\.sh/);
  assert.match(rootPkg.scripts.deploy, /publish\.mjs/);
  assert.match(wrangler, /^main = "deploy\/cloudflare\/shim\.mjs"$/m);
  assert.match(wrangler, /^migrations_dir = "crates\/authorization-server-d1\/migrations"$/m);
  assert.match(wrangler, /^binding = "NAZO_DB"$/m);
  assert.match(wrangler, /^workers_dev = false$/m);
  assert.match(wrangler, /^preview_urls = false$/m);
  assert.doesNotMatch(wrangler, /^database_id =/m);
  assert.doesNotMatch(wrangler, /^cpu_ms =/m);
  assert.match(wrangler, /"machine_only":true/);
  assert.match(wrangler, /^binding = "NAZO_VERSION"$/m);
  const nested = JSON.parse(read('../package.json'));
  assert.equal(nested.scripts.bundle, 'node bundle.mjs');
  assert.match(read('../shim.mjs'), /export \{ default \} from "\.\.\/\.\.\/crates\/server-worker\/build\/index\.js"/);
  assert.match(read('../build-worker.sh'), /worker-build --release --locked --no-default-features/);
  assert.match(wrangler, /^cwd = "crates\/server-worker"$/m);
  assert.match(nested.scripts['db:migrate'], /NAZO_DB --remote --config wrangler\.toml/);
  assert.match(nested.scripts.deploy, /--config wrangler\.toml/);
});

test('the build entrypoint uses pinned tooling', () => {
  const build = read('../prepare-build.sh');
  assert.match(build, /1\.100\.0/);
  assert.match(build, /wasm32-unknown-unknown/);
  assert.match(build, /worker-build --version 0\.9\.0 --locked/);
  assert.match(read('../bootstrap.mjs'), /machine_only/);
});

function publish(configuration, failMigration = false) {
  const temporary = mkdtempSync(join(tmpdir(), 'nazo-publish-'));
  try {
    const log = join(temporary, 'commands.log');
    writeFileSync(join(temporary, 'wrangler.toml'), configuration);
    writeFileSync(join(temporary, 'npm'), `#!/bin/sh
printf '%s\\n' "$2" >> "$NAZO_TEST_PUBLISH_LOG"
if [ "$2" = db:migrate ] && [ "$NAZO_TEST_FAIL_MIGRATION" = 1 ]; then exit 23; fi
`, { mode: 0o700 });
    const result = spawnSync(process.execPath, [fileURLToPath(new URL('../publish.mjs', import.meta.url))], {
      cwd: temporary, encoding: 'utf8', env: { ...process.env,
        PATH: temporary + delimiter + process.env.PATH,
        NAZO_TEST_PUBLISH_LOG: log, NAZO_TEST_FAIL_MIGRATION: failMigration ? '1' : '0',
        WRANGLER_SEND_METRICS: 'false',
      },
    });
    return { ...result, steps: existsSync(log) ? readFileSync(log, 'utf8').trim().split('\n') : [] };
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
}

test('the private template provisions D1 before its first migration', () => {
  const result = publish(read('../../../wrangler.toml'));
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(result.steps, ['deploy', 'db:migrate']);
});

test('uncommenting the template custom domain applies migration before deployment', () => {
  const result = publish(read('../../../wrangler.toml').replace(/^# routes =/m, 'routes ='));
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(result.steps, ['db:migrate', 'deploy']);
});

for (const [name, route] of [
  ['indented routes', '  routes = [{ pattern = "auth.example.com", custom_domain = true }]'],
  ['single route', 'route = { pattern = "auth.example.com", custom_domain = true }'],
  ['route array of tables', '[[routes]]\npattern = "auth.example.com"\ncustom_domain = true'],
]) {
  test(`${name} applies migrations before deployment`, () => {
    const result = publish(`name = "nazo-test"\nworkers_dev = false\n${route}\n`);
    assert.equal(result.status, 0, result.stderr);
    assert.deepEqual(result.steps, ['db:migrate', 'deploy']);
  });
}

for (const endpoint of ['workers_dev = true', 'workers_dev = false\npreview_urls = true']) {
  test(`${endpoint.replaceAll('\n', ', ')} applies migrations before deployment`, () => {
    const result = publish(`name = "nazo-test"\n${endpoint}\n`);
    assert.equal(result.status, 0, result.stderr);
    assert.deepEqual(result.steps, ['db:migrate', 'deploy']);
  });
}

test('a failed public migration leaves the deployed Worker unchanged', () => {
  const result = publish('name = "nazo-test"\nworkers_dev = true\n', true);
  assert.notEqual(result.status, 0);
  assert.deepEqual(result.steps, ['db:migrate']);
});

test('invalid Wrangler configuration stops before any deployment command', () => {
  const result = publish('routes = [\n');
  assert.notEqual(result.status, 0);
  assert.deepEqual(result.steps, []);
});

test('bootstrap refuses missing private input without touching remote resources', () => {
  const outcome = spawnSync(process.execPath, [fileURLToPath(new URL('../bootstrap.mjs', import.meta.url))], {
    cwd: root, encoding: 'utf8',
  });
  assert.notEqual(outcome.status, 0);
  assert.match(outcome.stderr, /Usage: npm run bootstrap/);
});
