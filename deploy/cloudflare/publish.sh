#!/bin/sh
set -eu

# The build and deploy commands run in separate shells in Workers Builds.
export PATH="$HOME/.cargo/bin:$PATH"
npm run db:migrate --prefix deploy/cloudflare
npm run deploy --prefix deploy/cloudflare
