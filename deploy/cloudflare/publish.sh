#!/bin/sh
set -eu
export PATH="$HOME/.cargo/bin:$PATH"

# An unpublished template needs its first deploy for D1 auto-provisioning.
# Once an issuer has a public route, apply migrations before publishing code.
if grep -Eq '^routes[[:space:]]*=' wrangler.toml; then
  npm run db:migrate --prefix deploy/cloudflare
  npm run deploy --prefix deploy/cloudflare
else
  npm run deploy --prefix deploy/cloudflare
  npm run db:migrate --prefix deploy/cloudflare
fi
