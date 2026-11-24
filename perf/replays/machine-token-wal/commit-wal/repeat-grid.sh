#!/usr/bin/env bash
# Three time-separated repeats of each product and load, using the stock k6 point.
set -euo pipefail
cd "$(dirname "$0")"
run=${1:-$(date -u +%Y%m%d%H%M%S)}
[[ $run =~ ^[0-9]+$ ]]
dest="$PWD/results/grid-$run"
mkdir -p results
mkdir "$dest"
mkdir "$dest/windows" "$dest/excluded"
export BENCH_KEYCLOAK_EVENTS_FILE="$dest/keycloak-events.json"
bash check-defaults.sh
cp results/default-proof-{nazo,keycloak,hydra}.json "$dest/"
python3 metadata.py "$dest/start.json" revised

rates=(6000 6750 7500 9000 12000 2400)
arms=(D K H)
for round in 0 1 2; do
  # Move each rate to a different time within each round.
  case $round in
    0) order=(0 4 1 3 2 5) ;;
    1) order=(2 5 3 1 4 0) ;;
    2) order=(4 3 5 0 2 1) ;;
  esac
  for index in "${order[@]}"; do
    rate=${rates[index]}
    scenario=machine
    if [[ $rate == 2400 ]]; then scenario=introspect; fi
    for seat in 0 1 2; do
      arm=${arms[(index+round+seat)%3]}
      label="$arm-$rate-$run$round"
      file="results/$label.json"
      printf '%s\t%s\t%s\t%s\t%s\n' "$((round+1))" "$((seat+1))" "$arm" "$rate" "$label" >>"$dest/order.tsv"
      if ! bash policy-peers.sh "$scenario" "$label"; then
        # A recycled WAL segment invalidates the count. Retain the incomplete
        # observation separately and repeat only this instrument failure.
        jq -e '.audit_observation=="unverified"' "$file" >/dev/null
        mv "$file" "$dest/excluded/$label.json"
        bash policy-peers.sh "$scenario" "$label"
      fi
      mv "$file" "$dest/windows/$label.json"
      if [[ $arm == K ]]; then jq -e '.eventsEnabled == false' "$BENCH_KEYCLOAK_EVENTS_FILE" >/dev/null; fi
    done
  done
done
python3 metadata.py "$dest/end.json" revised
cmp "$dest/start.json" "$dest/end.json"
