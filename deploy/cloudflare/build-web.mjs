import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { cpSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { applyWorkerOverlay } from './web-adapter/apply.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const source = JSON.parse(readFileSync(resolve(here, 'web-source.json'), 'utf8'));
const work = resolve(here, 'web-build');
const output = resolve(here, 'web-dist');
const run = (program, args, cwd = work, env = process.env) =>
  execFileSync(program, args, { cwd, env, stdio: 'inherit' });

// The server consumes a pinned Web source; it does not become a second owner of
// that application. Only this Worker build applies the small browser adapter.
rmSync(work, { recursive: true, force: true });
mkdirSync(work, { recursive: true });
run('git', ['init', '--quiet']);
run('git', ['remote', 'add', 'origin', source.repository]);
run('git', ['fetch', '--quiet', '--depth=1', 'origin', source.revision]);
run('git', ['checkout', '--quiet', '--detach', 'FETCH_HEAD']);
const revision = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: work, encoding: 'utf8' }).trim();
if (revision !== source.revision) throw new Error('NazoAuthWeb source revision mismatch');
const manifest = JSON.parse(readFileSync(resolve(work, 'package.json'), 'utf8'));
if (manifest.version !== source.version) throw new Error('NazoAuthWeb source version mismatch');

applyWorkerOverlay(work);
const npmArgs = ['exec', '--yes', `--package=node@${source.node}`, `--package=npm@${source.npm}`, '--', 'npm'];
run('npm', [...npmArgs, 'ci', '--no-audit', '--no-fund']);
run('npm', [...npmArgs, 'run', 'security:source']);
run('npm', [...npmArgs, 'run', 'test:unit', '--', 'src/components/WorkerAuthentication.test.tsx', 'src/components/WorkerPendingSession.test.tsx', 'src/components/WorkerSecurity.test.tsx', 'src/pages/admin/RuntimeModulesPanel.test.tsx', 'src/pages/admin/runtimeModuleView.test.tsx', 'src/components/WorkerGrantHistory.test.tsx']);
run('npm', [...npmArgs, 'run', 'build'], work, { ...process.env, VITE_BASE_PATH: source.base, VITE_API_BASE_URL: '' });
run('npm', [...npmArgs, 'run', 'verify:dist']);
run('npm', [...npmArgs, 'run', 'security:dist']);
rmSync(output, { recursive: true, force: true });
mkdirSync(output, { recursive: true });
cpSync(resolve(work, 'dist'), resolve(output, 'ui'), { recursive: true });
const html = readFileSync(resolve(output, 'ui/index.html'), 'utf8');
const scriptHashes = [...html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/g)]
  .filter(([, attributes, body]) => !/\bsrc\s*=/.test(attributes) && body.trim())
  .map(([, , body]) => `'sha256-${createHash('sha256').update(body).digest('base64')}'`);
const csp = `default-src 'self'; script-src 'self' ${scriptHashes.join(' ')}; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' https: data:; connect-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'`;
writeFileSync(resolve(output, '_headers'), `/ui/*\n  Content-Security-Policy: ${csp}\n  Referrer-Policy: no-referrer\n  X-Content-Type-Options: nosniff\n  Permissions-Policy: camera=(), microphone=(), geolocation=()\n\n/ui/assets/*\n  Cache-Control: public, max-age=31536000, immutable\n\n/ui/index.html\n  Cache-Control: no-cache\n`);
writeFileSync(resolve(output, 'ui/source.json'), JSON.stringify({
  repository: source.repository, revision: source.revision, version: source.version,
  adapter: 'nazoauth-cloudflare',
}) + '\n');
console.log(`Built NazoAuthWeb ${source.version} (${revision}) at /ui/`);
