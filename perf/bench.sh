#!/usr/bin/env bash
set -euo pipefail
umask 077
export PERF=$(cd "$(dirname "$0")" && pwd)
repo=$(dirname "$PERF")
export WORK=${BENCH_WORK:-$PERF/.work}
case ${1:-} in
  verify) shift; exec python3 "$PERF/report.py" --check "$@";;
  report) shift; exec python3 "$PERF/report.py" "$@";;
  setup|run|matrix) ;;
  *) echo 'Usage: bash perf/bench.sh {setup|matrix|run PEER SCENARIO TPS [ROUNDS]|verify|report}' >&2; exit 2;;
esac
mkdir -p "$WORK"
cd "$WORK"
export WORK=$PWD
exec 9>"$WORK/bench.lock"
flock -n 9 || { echo 'Another benchmark is active in this workspace.' >&2; exit 1; }
source "$PERF/deploy.sh"
if [[ $1 == setup ]]; then
  test "$(uname -m)" = x86_64
  test "$(wc -l < /proc/swaps)" -eq 1 || { echo 'Disable swap on the dedicated benchmark host.' >&2; exit 1; }
  mkdir -p build private out results
  python3 "$PERF/monitor/topology.py" >masks.new
  if [[ -f masks ]]; then cmp masks.new masks; fi
  mv masks.new masks
  source masks
  cc -static -O2 "$PERF/monitor/affinity.c" -o build/affinity
  cc -static -O2 "$PERF/monitor/sampler.c" -o build/sample-cpu
  sha=af4b849c63e1e8a68b5d7564f3513a54f991a5fc
  builder=rust@sha256:6f14b2b4b278ec0d50aa1d69541c304ce0f95e0f6268487aa9924af1c2e9aebe
  patch="$PERF/fixture/token-ip-quota.patch"
  echo "a8f192f123f6558f0a1663ef0302b1eb9c56743e71f726fbe4fd5e4f01d21443  $patch" | sha256sum -c -
  # git archive excludes the benchmark workspace and any local product edits.
  src=$(mktemp -d "$WORK/build/product.XXXXXX")
  git -C "$repo" archive "$sha" | tar xf - -C "$src"
  (cd "$src" && patch --silent -p1 < "$patch")
  docker build --target fixture -f "$PERF/runner/Containerfile" -t "$fixture_image" "$repo"
  docker build -f "$PERF/runner/Containerfile" -t oidc-bench-goose-image "$repo"
  docker build -f "$PERF/fixture/app.Containerfile" -t "$app_image" "$PERF/fixture"
  # Transfer via Docker's API so the Docker daemon need not share the CNB workspace mount.
  build_id=$(docker create --entrypoint sleep "$builder" infinity)
  trap 'docker rm -f "$build_id" >/dev/null' EXIT
  docker start "$build_id" >/dev/null
  docker exec "$build_id" mkdir -p /build
  tar cf - -C "$src" . | docker exec -i -w /build "$build_id" tar xf -
  docker exec -w /build "$build_id" cargo build --locked --release -p nazo-server --bin nazoauth
  docker cp "$build_id:/build/target/release/nazoauth" out/nazoauth
  infra
  printf '%s\n' "${BENCH_NETWORK:-base}" >private/network-profile
  bootstrap_nazo
  bootstrap_keycloak
  bootstrap_hydra
  source "$PERF/native-deploy.sh"
  exit 0
fi
source masks
source private/secrets.env
expected_network=base
if [[ ${BENCH_PROFILE:-base} == journal-wide ]]; then expected_network=wide; fi
[[ $(cat private/network-profile) == "$expected_network" ]] || { echo "Expected a $expected_network deployment." >&2; exit 2; }
one() {
  local peer=$1 op=$2 rate=$3 round=$4 users=$5 families=$6
  export SCENARIO=$op BENCH_GO_PROFILE=$7 BENCH_PROTOCOL_USERS=$users BENCH_REFRESH_MAX_FAMILIES=$families
  export BENCH_GO_WORKERS=15 BENCH_SLOTS=8192 BENCH_SILENT=0 BENCH_TOKEN_SUBJECT=client BENCH_WARM_SECONDS=10
  local seconds=36
  case "$op" in
    authorize-silent) op=authorize; export BENCH_SILENT=1;;
    user-introspect) op=introspect; export BENCH_TOKEN_SUBJECT=user;;
    machine-introspect) op=introspect;;
    exchange|mixed-core) export BENCH_WARM_SECONDS=5; seconds=20;;
    machine|introspect|refresh|authorize|userinfo|mixed) ;;
    *) echo "Unknown scenario: $op" >&2; return 2;;
  esac
  case "$peer:$op" in hydra:authorize|hydra:mixed*|rauthy:refresh|rauthy:mixed-core|kanidm:refresh|kanidm:exchange|kanidm:mixed-core) echo "Outside the common protocol group: $peer/$op" >&2; return 2;; esac
  case "$peer" in nazo|keycloak|hydra|rauthy|kanidm) ;; *) return 2;; esac
  stop_apps
  if [[ $peer == rauthy ]]; then docker start oidc-bench-rauthy-db >/dev/null; else docker stop oidc-bench-rauthy-db >/dev/null; fi
  if [[ $peer == nazo ]]; then docker start "$vk" >/dev/null; else docker stop "$vk" >/dev/null; fi
  docker start "oidc-bench-$peer" >/dev/null
  case "$peer" in
    nazo) ready oidc-bench-nazo /health;;
    keycloak) ready "$kc" /realms/api-audit/.well-known/openid-configuration;;
    hydra) ready "$hy" /.well-known/openid-configuration;;
    rauthy|kanidm)
      local attempt
      for attempt in {1..60}; do
        if docker exec "$prep" python3 /tmp/prepare-replay-profiles.py "$peer" >/dev/null 2>&1; then break; fi
        if (( attempt == 60 )); then
          echo "Failed to prepare $peer benchmark profile." >&2
          return 1
        fi
        sleep 1
      done;;
  esac
  if [[ $BENCH_GO_PROFILE == journal-wide ]]; then
    export BENCH_SLOTS=32768 BENCH_GO_WORKERS=24
    docker exec oidc-bench-goose sh -ec 'test "$(cat /proc/sys/net/ipv4/ip_local_port_range | xargs)" = "1024 65535" && test "$(cat /proc/sys/net/ipv4/tcp_tw_reuse)" = 1' || { echo 'Wide profile requires BENCH_NETWORK=wide at setup in a fresh deployment.' >&2; return 1; }
  fi
  bash "$PERF/window.sh" "$peer" "$op" "$rate" "$round" "$seconds"
}
if [[ $1 == matrix ]]; then
  prefix=$(date -u +%Y%m%dT%H%M%SZ)
  python3 "$PERF/report.py" --plan >"$WORK/plan.tsv"
  while IFS=$'\t' read -r peer scenario rate round users families profile; do
    one "$peer" "$scenario" "$rate" "$prefix-$round" "$users" "$families" "$profile"
  done < "$WORK/plan.tsv"
else
  peer=${2:?peer}; scenario=${3:?scenario}; rate=${4:?target TPS}; rounds=${5:-3}
  [[ $rate =~ ^[1-9][0-9]*$ && $rounds =~ ^[1-9][0-9]*$ ]] || exit 2
  users=32; families=8
  if [[ $scenario == refresh && $rate -ge 1000 ]]; then users=64; fi
  if [[ $scenario == refresh && $rate -ge 3000 ]]; then users=128; families=10; fi
  prefix=$(date -u +%Y%m%dT%H%M%SZ)
  for ((i=1;i<=rounds;i++)); do one "$peer" "$scenario" "$rate" "$prefix-$i" "$users" "$families" "${BENCH_PROFILE:-base}"; done
fi
