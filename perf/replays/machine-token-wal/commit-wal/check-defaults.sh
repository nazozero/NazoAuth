#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/support.sh"
docker start "$pg" >/dev/null
ready_pg "$pg"
start_deps
prepare_machine_app D nazo-machine-policy-D
mkdir -p results
trap 'docker stop -t 10 "$app" >/dev/null; docker exec "$prep" rm -f /tmp/commit-kc-bootstrap.json' EXIT
for peer in nazo keycloak hydra; do
  case $peer in
    nazo) app=nazo-machine-policy-D; fixture=revised; discovery=/health ;;
    keycloak) app=$kc; fixture=keycloak; discovery=/realms/api-audit/.well-known/openid-configuration ;;
    hydra) app=$hy; fixture=hydra; discovery=/.well-known/openid-configuration ;;
  esac
  docker start "$app" >/dev/null
  ready "$app" "$discovery"
  if [[ $peer == keycloak ]]; then
    docker cp ../private/keycloak.json "$prep:/tmp/commit-kc-bootstrap.json"
    docker cp align-machine-scope.py "$prep:/tmp/align-machine-scope.py"
    docker exec "$prep" python3 /tmp/align-machine-scope.py
  fi
  docker exec "$prep" cp "/tmp/$fixture.json" /tmp/state.json
  docker exec "$prep" /affinity "$BENCH_CONTROL_CPU" python3 /tmp/verify-machine.py "$peer" >"results/default-proof-$peer.json"
  jq -e '.signature_verified and .signature == "RS256" and .rsa_bits == 2048 and .ttl_seconds == 300 and .returned_scope == ["profile"]' "results/default-proof-$peer.json" >/dev/null
  docker stop -t 10 "$app" >/dev/null
done
