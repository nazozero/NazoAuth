#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p results
docker start oauthbench-pg oauthbench-k6 >/dev/null
for _ in {1..80}; do
  if docker exec oauthbench-pg pg_isready -q -U postgres; then break; fi
  sleep .4
done
python3 metadata.py results/environment-before.json
bash compare-app.sh \
  E-400-1 F-400-1 F-6000-1 E-6000-1 E-8000-1 F-8000-1 \
  F-400-2 E-400-2 E-6000-2 F-6000-2 F-8000-2 E-8000-2 \
  E-400-3 F-400-3 F-6000-3 E-6000-3 E-8000-3 F-8000-3
bash peer-ref.sh keycloak K-400-1 K-6000-1 K-8000-1 K-8000-2 K-6000-2 K-400-2 K-400-3 K-6000-3 K-8000-3
bash midpoint.sh
bash peer-ref.sh hydra H-400-1 H-2400-1 H-6000-1 H-8000-1 H-8000-2 H-6000-2 H-2400-2 H-400-2 H-400-3 H-2400-3 H-6000-3 H-8000-3
bash http-timing.sh 400 6000
python3 metadata.py results/environment-after.json
cmp results/environment-before.json results/environment-after.json
