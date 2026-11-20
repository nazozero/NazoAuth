import { chmod, readFile, rename, writeFile } from 'node:fs/promises';
import { test } from 'node:test';
import { runPublicAcceptance } from '../test-support/public-acceptance.mjs';

// Public requests require an explicit, private input file. Ordinary workerd CI
// never consumes a deployed issuer's enrollment ticket or changes its state.
const inputPath = process.env.NAZO_WORKER_ACCEPTANCE_INPUT;
async function readPrivateJson(path) {
  const contents = await readFile(path, 'utf8');
  try { return JSON.parse(contents); }
  catch { throw new Error('Private acceptance input is not valid JSON; contents omitted.'); }
}
test('public HTTPS Worker protocol acceptance', {
  skip: !inputPath,
  timeout: 600_000,
}, async () => {
  const input = await readPrivateJson(inputPath);
  const statePath = process.env.NAZO_WORKER_ACCEPTANCE_AUTHENTICATOR;
  if (statePath) {
    try { input.authenticator = await readPrivateJson(statePath); }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
  }
  const saveAuthenticator = statePath ? async state => {
    const temporary = statePath + '.pending';
    await writeFile(temporary, JSON.stringify(state) + '\n', { mode: 0o600 });
    await chmod(temporary, 0o600);
    await rename(temporary, statePath);
  } : undefined;
  const result = await runPublicAcceptance(input, fetch, saveAuthenticator);
  const encoded = JSON.stringify(result, null, 2) + '\n';
  if (process.env.NAZO_WORKER_ACCEPTANCE_OUTPUT) {
    await writeFile(process.env.NAZO_WORKER_ACCEPTANCE_OUTPUT, encoded, { mode: 0o600, flag: 'wx' });
  }
  console.log(encoded);
  if (result.failed) throw new Error('Public acceptance failed; inspect the redacted step results.');
});
