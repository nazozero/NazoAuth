#!/usr/bin/env bash
# Interleave products at a common rate. The trial digits keep issue and introspect windows distinct.
set -euo pipefail
cd "$(dirname "$0")"
export BENCH_MACHINE_SCENARIO=${1:?machine or introspect}
shift
for trial in "$@"; do
  case "$trial" in
    K-*) bash peer-ref.sh keycloak "$trial" ;;
    H-*) bash peer-ref.sh hydra "$trial" ;;
    B-*|A-*|D-*|N-*) bash compare-machine-policy.sh "$trial" ;;
    *) exit 2 ;;
  esac
done
