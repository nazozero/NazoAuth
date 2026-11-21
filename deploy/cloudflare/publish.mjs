import { execFileSync } from 'node:child_process';
import { homedir } from 'node:os';
import { delimiter, join } from 'node:path';
import { unstable_readConfig as readConfig } from 'wrangler';

const configuration = readConfig({ config: 'wrangler.toml' });
const publicEndpoint = configuration.workers_dev !== false
  || configuration.preview_urls === true
  || Boolean(configuration.route)
  || (configuration.routes?.length ?? 0) > 0;
// The private template's first deploy provisions D1. Public deployments apply
// migrations before replacing their running code.
const steps = publicEndpoint ? ['db:migrate', 'deploy'] : ['deploy', 'db:migrate'];
const env = { ...process.env, PATH: join(homedir(), '.cargo', 'bin') + delimiter + process.env.PATH };
for (const step of steps) {
  execFileSync('npm', ['run', step, '--prefix', 'deploy/cloudflare'], { env, stdio: 'inherit' });
}
