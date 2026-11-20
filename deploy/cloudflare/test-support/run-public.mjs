// Cloudflare Builds acceptance client. Temporary secret inputs are explicitly
// installed on the existing isolated build trigger by the operator.
import { runPublicAcceptance } from './public-acceptance.mjs';
import { publicTransport } from './public-transport.mjs';

if (process.env.WORKERS_CI_BRANCH !== 'feat/cloudflare-workers-206') {
  throw new Error('Acceptance branch guard failed');
}
const parts = Object.keys(process.env).filter(name => /^NAZO_PROBE_INPUT_\d+$/.test(name))
  .sort((left, right) => Number(left.split('_').at(-1)) - Number(right.split('_').at(-1)));
if (!parts.length || parts.length > 16) throw new Error('Missing bounded private acceptance input');
let input;
try { input = JSON.parse(parts.map(name => process.env[name]).join('')); }
catch { throw new Error('Private acceptance input is invalid; contents omitted'); }
if (input.issuer !== 'https://free-test-206.nazoauth.com') throw new Error('Isolated issuer guard failed');
const transport = publicTransport(input);
try {
  const result = await runPublicAcceptance(input, transport.fetch);
  const output = JSON.stringify(result);
  for (let offset = 0; offset < output.length; offset += 3000) {
    console.log('NAZO_PART ' + offset + ' ' + output.slice(offset, offset + 3000));
  }
  process.exitCode = result.failed ? 1 : 0;
} finally { transport.close(); }
