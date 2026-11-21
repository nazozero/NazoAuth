import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

test('published Web assets carry transport headers and retain their executable-script CSP', () => {
  const rules = readFileSync(new URL('../web-dist/_headers', import.meta.url), 'utf8');
  const ui = rules.split('\n\n').find(block => block.startsWith('/ui/*\n'));
  assert.ok(ui, 'all Web assets need the security header policy');
  assert.match(ui, /^  Strict-Transport-Security: max-age=31536000$/m);
  assert.match(ui, /^  X-Frame-Options: DENY$/m);
  assert.match(ui, /^  Referrer-Policy: no-referrer$/m);
  assert.match(ui, /^  X-Content-Type-Options: nosniff$/m);
  const csp = ui.match(/^  Content-Security-Policy: (.+)$/m)?.[1];
  assert.ok(csp);
  assert.match(csp, /frame-ancestors 'none'/);
  assert.match(csp, /script-src 'self'/);
  const html = readFileSync(new URL('../web-dist/ui/index.html', import.meta.url), 'utf8');
  for (const [, attributes, body] of html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/g)) {
    if (/\bsrc\s*=/.test(attributes) || !body.trim()) continue;
    assert.ok(csp.includes(`'sha256-${createHash('sha256').update(body).digest('base64')}'`));
  }
});
