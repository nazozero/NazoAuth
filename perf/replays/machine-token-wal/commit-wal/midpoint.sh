#!/usr/bin/env bash
# Rotate all three services at the earlier shared mid-load reference.
set -euo pipefail
cd "$(dirname "$0")"
for trial in F-2400-1 K-2400-1 E-2400-1 E-2400-2 F-2400-2 K-2400-2 K-2400-3 E-2400-3 F-2400-3; do
  case "$trial" in
    K-*) bash peer-ref.sh keycloak "$trial" ;;
    *) bash compare-app.sh "$trial" ;;
  esac
done
