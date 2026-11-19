#!/usr/bin/env node
// Provision a fresh NazoAuth D1 issuer without placing secrets in Git or URLs.
import { execFileSync } from 'node:child_process';
import { randomBytes, randomUUID } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { delimiter, join, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../../', import.meta.url));
const wranglerConfig = join(root, 'wrangler.toml');
const wranglerCli = join(root, 'deploy/cloudflare/node_modules/wrangler/bin/wrangler.js');
const cargoPath = join(homedir(), '.cargo', 'bin');
const env = { ...process.env, PATH: cargoPath + delimiter + process.env.PATH };

function execute(binary, args, options = {}) {
  return execFileSync(binary, args, {
    cwd: root, env, encoding: 'utf8', maxBuffer: 8 * 1024 * 1024,
    stdio: ['pipe', 'pipe', 'pipe'], ...options,
  });
}

function wrangler(...args) {
  return execute(process.execPath, [wranglerCli, ...args, '--config', wranglerConfig]);
}

function requiredOrigin(value, label) {
  if (typeof value !== 'string') throw new Error(label + ' is required');
  const url = new URL(value);
  if (url.protocol !== 'https:' || url.username || url.password ||
      url.pathname !== '/' || url.search || url.hash ||
      ![url.origin, url.origin + '/'].includes(value)) {
    throw new Error(label + ' must be a canonical HTTPS origin');
  }
  return url.origin;
}

function configuration(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw new Error('Bootstrap input must be a JSON object');
  }
  const issuer = requiredOrigin(input.issuer, 'issuer');
  const frontend = requiredOrigin(input.frontend_base_url, 'frontend_base_url');
  if (!Array.isArray(input.clients) || !Array.isArray(input.users)) {
    throw new Error('clients and users must be arrays (empty arrays are allowed)');
  }
  const machineOnly = input.machine_only !== false;
  if (machineOnly) {
    if (input.users.length !== 0) {
      throw new Error('Free machine-only profile cannot register password users');
    }
    if (!input.clients.every(client => client.client_type === 'confidential' &&
        Array.isArray(client.redirect_uris) && client.redirect_uris.length === 0 &&
        Array.isArray(client.grant_types) && client.grant_types.length === 1 &&
        client.grant_types[0] === 'client_credentials')) {
      throw new Error('Free machine-only profile needs confidential client_credentials clients');
    }
    if ((input.modules ?? []).length !== 0) {
      throw new Error('Free machine-only profile cannot enable browser modules');
    }
  }
  for (const user of input.users) {
    if (typeof user.password !== 'string' || user.password.length < 12 ||
        /REPLACE|CHANGE_ME|PASSWORD_HERE|^</i.test(user.password)) {
      throw new Error('Every user needs an original password of at least 12 bytes');
    }
  }
  const tenant = input.tenant ?? {
    tenant_id: randomUUID(), realm_id: randomUUID(), organization_id: randomUUID(),
  };
  const config = {
    tenant, issuer, frontend_base_url: frontend, ingress: 'direct_cloudflare',
    cors_allowed_origins: input.cors_allowed_origins ?? [frontend],
    modules: input.modules ?? [], machine_only: machineOnly,
  };
  return { config, clients: input.clients, users: input.users };
}

function assertUnusedDatabase() {
  const query = 'SELECT ' +
    '(SELECT COUNT(*) FROM nazo_signing_keys) AS signing_keys, ' +
    '(SELECT COUNT(*) FROM nazo_clients) AS clients, ' +
    '(SELECT COUNT(*) FROM nazo_users) AS users, ' +
    '(SELECT COUNT(*) FROM nazo_modules) AS modules';
  const output = wrangler('d1', 'execute', 'NAZO_DB', '--remote', '--json', '--command', query);
  const parsed = JSON.parse(output);
  const result = (Array.isArray(parsed) ? parsed : [parsed])[0];
  const row = result?.results?.[0];
  if (!result?.success || !row ||
      !['signing_keys', 'clients', 'users', 'modules'].every(key => Number.isSafeInteger(row[key]))) {
    throw new Error('Unable to confirm remote D1 is empty; no seed was imported');
  }
  if (Object.values(row).some(value => value !== 0)) {
    throw new Error('Remote D1 already contains provisioned data; refusing to reinitialize');
  }
}

function privatePath(value, label) {
  if (!value) throw new Error('Usage: npm run bootstrap -- ABSOLUTE_PRIVATE_INPUT.json ABSOLUTE_PRIVATE_OUTPUT.json');
  const full = resolve(value);
  if (full === root || full.startsWith(root + sep)) {
    throw new Error(label + ' must be stored outside the repository');
  }
  return full;
}

function setConfig(config, keyId) {
  const original = readFileSync(wranglerConfig, 'utf8');
  const pattern = /^NAZO_CONFIG = '''[^\n]*'''$/m;
  const idPattern = /^NAZO_SIGNING_KEY_ID = "[^\n]*"$/m;
  if (!pattern.test(original) || !idPattern.test(original)) {
    throw new Error('Expected NAZO_CONFIG and NAZO_SIGNING_KEY_ID bindings not found');
  }
  const updated = original.replace(pattern, () => "NAZO_CONFIG = '''" + JSON.stringify(config) + "'''")
    .replace(idPattern, () => 'NAZO_SIGNING_KEY_ID = "' + keyId + '"');
  writeFileSync(wranglerConfig, updated);
}

function main() {
  if (process.argv.length !== 4) {
    throw new Error('Usage: npm run bootstrap -- ABSOLUTE_PRIVATE_INPUT.json ABSOLUTE_PRIVATE_OUTPUT.json');
  }
  const inputPath = privatePath(process.argv[2], 'input');
  const outputPath = privatePath(process.argv[3], 'output');
  if (inputPath === outputPath) throw new Error('Input and output must be distinct');
  if (statSync(inputPath).size > 1024 * 1024) throw new Error('Input exceeds 1 MiB');
  const { config, clients, users } = configuration(JSON.parse(readFileSync(inputPath, 'utf8')));
  // Wrangler resolves the auto-provisioned D1 by binding name, even if
  // Cloudflare's button did not write the database ID back to this TOML file.
  // Migrations are idempotent. Read the actual remote authority before importing.
  wrangler('d1', 'migrations', 'apply', 'NAZO_DB', '--remote');
  assertUnusedDatabase();

  const temporary = mkdtempSync(join(tmpdir(), 'nazoauth-init-'));
  try {
    const key = randomBytes(32).toString('base64');
    const pepper = randomBytes(32).toString('base64');
    const keyId = 'primary';
    const sqlite = join(temporary, 'seed.sqlite');
    const provision = {
      configuration: config, signing_key_id: keyId, signing_key_base64: key,
      client_secret_pepper: pepper, clients, users,
    };
    const issued = JSON.parse(execute('cargo', [
      'run', '--quiet', '--locked', '--release', '-p', 'nazo-server-worker',
      '--features', 'provisioning', '--bin', 'nazo-worker-provision', '--', sqlite,
    ], { input: JSON.stringify(provision) }));

    // Save recovery material before any remote write. The file must not exist.
    writeFileSync(outputPath, JSON.stringify({
      configuration: config, signing_key_id: keyId, signing_key_base64: key,
      client_secret_pepper: pepper, ...issued,
    }, null, 2) + '\n', { flag: 'wx', mode: 0o600 });

    const seedSql = join(temporary, 'seed.sql');
    writeFileSync(seedSql, execute('python3', [
      join(root, 'deploy/cloudflare/export-seed.py'), sqlite,
    ]), { mode: 0o600 });
    wrangler('d1', 'execute', 'NAZO_DB', '--remote', '--file', seedSql);

    setConfig(config, keyId);
    const secrets = join(temporary, 'secrets.json');
    writeFileSync(secrets, JSON.stringify({
      NAZO_SIGNING_KEY: key,
      NAZO_CLIENT_SECRET_PEPPER: pepper,
      NAZO_DUMMY_PASSWORD_HASH: issued.dummy_password_hash,
    }), { mode: 0o600 });
    wrangler('deploy', '--secrets-file', secrets);
    console.log('D1 initialized; private recovery credentials saved to ' + outputPath);
    console.log('The Worker is not public. Configure the zone WAF and HTTPS route first.');
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
}

try {
  main();
} catch (error) {
  // Never print secret material, provisioning JSON or subprocess output.
  console.error('Cloudflare bootstrap stopped: ' + error.message.split('\n')[0]);
  process.exitCode = 1;
}
