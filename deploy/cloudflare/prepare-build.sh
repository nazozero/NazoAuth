#!/bin/sh
# Workers Builds ships Node and curl but not the pinned Rust/WASM toolchain.
set -eu

if ! command -v rustup >/dev/null 2>&1; then
  curl --proto '=https' --tlsv1.2 -fsSL https://sh.rustup.rs |
    sh -s -- -y --profile minimal --default-toolchain 1.100.0 --no-modify-path
fi
export PATH="$HOME/.cargo/bin:$PATH"
rustup toolchain install 1.100.0 --profile minimal
rustup target add --toolchain 1.100.0 wasm32-unknown-unknown
if ! cargo install --list | grep -q '^worker-build v0\.9\.0:'; then
  cargo +1.100.0 install worker-build --version 0.9.0 --locked
fi
if ! cargo install --list | grep -q '^wasm-bindgen-cli v0\.2\.130:'; then
  cargo +1.100.0 install wasm-bindgen-cli --version 0.2.130 --locked
fi
