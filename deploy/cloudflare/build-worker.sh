#!/bin/sh
set -eu

# Reuse the CLI pinned by prepare-build.sh. worker-build otherwise downloads
# its own copy even when the matching executable is already on PATH.
if [ -z "${WASM_BINDGEN_BIN:-}" ] && command -v wasm-bindgen >/dev/null 2>&1; then
  WASM_BINDGEN_BIN=$(command -v wasm-bindgen)
  export WASM_BINDGEN_BIN
fi

cd "$(dirname "$0")/../../crates/server-worker"
worker-build --release --locked --no-default-features
exec node ../../deploy/cloudflare/prune-worker.mjs build
