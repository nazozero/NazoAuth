#!/usr/bin/env bash
set -euo pipefail

cargo test --locked --all-features -p nazo-server --test tenant_directory_convergence \
  two_processes_converge_on_lifecycle_mutations_and_survive_cache_failures -- --nocapture
cargo test --locked --all-features -p nazo-server --test token_issuance_simplification -- --nocapture
