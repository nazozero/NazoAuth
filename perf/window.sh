#!/usr/bin/env bash
set -euo pipefail
cd "$WORK"
peer=${1:?peer}; flow=${2:?operation}; rate=${3:?rate}; label=${4:?round ID}; seconds=${5:-36}
app="${BENCH_APP_CONTAINER:-oidc-bench-$peer}"
fx=oidc-bench-fixture
gen=${BENCH_GENERATOR_CONTAINER:-oidc-bench-goose}
dest="$WORK/windows/$peer/$SCENARIO/$label-$rate"
mkdir -p "$(dirname "$dest")"
mkdir "$dest"
umask 077
taskset -c "$BENCH_CONTROL_CPU" python3 "$PERF/monitor/quiet.py" >"$dest/pre.json"
warm=${BENCH_WARM_SECONDS:-10}
bin=/oauth-goose
case "$flow" in
  exchange|refresh|authorize|userinfo|mixed-core)
    req=/tmp/goose-protocol-private.json
    if [[ $flow == mixed-core ]]; then
      docker exec "$fx" /affinity "$BENCH_CONTROL_CPU" python3 /tmp/cnb-clients.py "$peer" >/dev/null
      docker exec "$fx" /affinity "$BENCH_GEN_CPUS" python3 /tmp/fixtures.py "/tmp/goose8-$peer.json" \
        /tmp/goose8-fixtures --per-client 32 >"$dest/machine-fixture-proof.json"
      jq -e '.clients==16 and .unique_tokens==512 and .all_introspected_active' "$dest/machine-fixture-proof.json" >/dev/null
      for op in machine introspect; do
        docker exec "$fx" cp "/tmp/goose8-fixtures/$op.json" "/tmp/goose-mixed-$op.json"
      done
    fi
    docker exec -e BENCH_SILENT -e BENCH_REFRESH_MAX_FAMILIES -e BENCH_RATE="$rate" "$fx" /affinity "$BENCH_GEN_CPUS" python3 /tmp/protocol_fixtures.py \
      "$peer" "$flow" "$((rate*(seconds+warm)))" "${BENCH_PROTOCOL_USERS:-32}" "$req" >"$dest/proof.json"
    ;;
  *)
    # Validate the live token cohort before timing.
    if [[ $flow == introspect && ${BENCH_TOKEN_SUBJECT:-client} == user ]]; then
      docker exec "$fx" /affinity "$BENCH_GEN_CPUS" python3 /tmp/user_introspection.py >"$dest/proof.json"
    else
    docker exec "$fx" /affinity "$BENCH_CONTROL_CPU" python3 /tmp/cnb-clients.py "$peer" >/dev/null
    count=1
    if [[ $flow == introspect || $flow == mixed ]]; then count=32; fi
    docker exec "$fx" /affinity "$BENCH_CONTROL_CPU" python3 /tmp/fixtures.py "/tmp/goose8-$peer.json" /tmp/goose8-fixtures \
      --per-client "$count" >"$dest/proof.json"
    jq -e --argjson count "$((16*count))" \
      '.clients==16 and .unique_tokens==$count and .all_introspected_active' "$dest/proof.json" >/dev/null
    fi
    req=/tmp/goose8-fixtures/$flow.json
    if [[ $flow == mixed ]]; then
      docker exec "$fx" python3 -c 'import json;from pathlib import Path;p=Path("/tmp/goose8-fixtures");a=json.loads((p/"machine.json").read_text());b=json.loads((p/"introspect.json").read_text());v=[];[v.extend((a[i%len(a)],b[2*i],b[2*i+1])) for i in range(len(b)//2)];(p/"mixed.json").write_text(json.dumps(v))'
    fi
    ;;
esac
scratch=$(mktemp -d)
cleanup() {
  if [[ -n ${pss_pid:-} ]]; then kill "$pss_pid" 2>/dev/null || true; wait "$pss_pid" 2>/dev/null || true; fi
  if [[ -n ${host:-} ]]; then kill "$host" 2>/dev/null || true; wait "$host" 2>/dev/null || true; fi
  if [[ -n ${driver:-} ]]; then kill "$driver" 2>/dev/null || true; wait "$driver" 2>/dev/null || true; fi
  docker exec "$gen" rm -f /tmp/goose8-request.json /tmp/goose8-window.tsv >/dev/null 2>&1 || true
  if [[ $flow == authorize || $flow == exchange || $flow == refresh || $flow == userinfo || $flow == mixed-core ]]; then
    docker exec "$fx" rm -f /tmp/goose-protocol-private.json /tmp/goose-mixed-machine.json \
      /tmp/goose-mixed-introspect.json >/dev/null 2>&1 || true
  fi
  rm -rf "$scratch"
}
trap cleanup EXIT
docker cp "$fx:$req" "$scratch/request.json"
docker cp "$scratch/request.json" "$gen:/tmp/goose8-request.json"
check_code_expiry() {
  if [[ $flow != exchange && $flow != mixed-core ]]; then return; fi
  # Worst case bound: every prepared code can remain usable until the last slot.
  python3 - "$dest/proof.json" "$warm" "$seconds" <<'PY_EXPIRY'
import json, sys, time
p = json.load(open(sys.argv[1]))
latest = p.get("latest_safe_start_epoch")
if latest is None:
    latest = (p["fixture_ready_epoch"] + p["code_ttl_seconds"]
              - p["fixture_oldest_upper_age_seconds"] - int(sys.argv[2]) - int(sys.argv[3]) - 2)
if time.time() > latest:
    sys.exit("INVALID prepared-code expiry budget: collection ended too late for the timed window")
PY_EXPIRY
}
check_code_expiry
docker exec "$gen" sha256sum "$bin" >"$dest/driver.sha256"
cpus=$BENCH_APP_CPUS
run_driver() {
  local tls=()
  if [[ $peer == kanidm ]]; then tls=(BENCH_CA_PEM=/tmp/goose-kanidm-root.pem); fi
  docker exec -e BENCH_GO_PROFILE -e BENCH_ARRIVAL_PHASES "$gen" /affinity "$BENCH_GEN_CPUS" env TOKIO_WORKER_THREADS="${BENCH_GO_WORKERS:-15}" "${tls[@]}" \
    "$bin" "$rate" "$warm" "$seconds" "${BENCH_SLOTS:-8192}" /tmp/goose8-request.json /tmp/goose8-window.tsv \
    >"$dest/driver.stdout" 2>"$dest/window"
}
{
  # The driver's epoch begins after it has parsed and validated its fixtures.
  : >"$dest/window"
  run_driver &
  driver=$!
  while ! grep -q '^epoch_ns=' "$dest/window" 2>/dev/null; do
    if ! kill -0 "$driver" 2>/dev/null; then
      wait "$driver" || true
      driver=""
      echo 'INVALID Goose finished before publishing a measurement epoch' >&2
      exit 1
    fi
    sleep .1
  done
  if ! check_code_expiry; then
    wait "$driver" || true
    driver=""
    docker cp "$gen:/tmp/goose8-window.tsv" "$dest/arrivals.tsv" >/dev/null 2>&1 || true
    exit 1
  fi
}
monitor() {
  docker exec -u 0 -e OAUTH_BENCH_CGROUPS=1 "$1" /affinity "$BENCH_CONTROL_CPU" /sample-cpu "$2" "$(( (warm+seconds+4)/2+1 ))" "$3" \
    >"$dest/$4.cpu.tsv" 2>"$dest/$4.cgroup.tsv" &
  pids+=("$!")
}
pids=()
app_comm=
if [[ $peer == nazo ]]; then app_comm=nazoauth; fi
monitor "$app" "$cpus" "$app_comm" app
monitor "$gen" "$BENCH_GEN_CPUS" oauth-goose generator
case "$peer" in
  nazo) monitor oidc-bench-postgres "$BENCH_PG_CPUS" postgres postgres; monitor oidc-bench-valkey "$BENCH_VK_CPUS" valkey-server valkey;;
  keycloak|hydra) monitor oidc-bench-postgres "$BENCH_PG_CPUS" '' postgres;;
  rauthy) monitor oidc-bench-rauthy-db "$BENCH_PG_CPUS" '' postgres;;
esac
if [[ $peer == nazo && $flow == userinfo ]]; then
  taskset -c "$BENCH_CONTROL_CPU" python3 "$PERF/monitor/pss.py" >"$dest/pss.tsv" &
  pss_pid=$!
fi
taskset -c "$BENCH_CONTROL_CPU" python3 "$PERF/monitor/host.py" >"$dest/pressure.jsonl" &
host=$!
status=0
if [[ -n ${driver:-} ]]; then
  wait "$driver" || status=$?
  driver=""
else
  run_driver || status=$?
fi
for pid in "${pids[@]}"; do wait "$pid" || status=1; done
docker inspect --format '{{json .State}}' "$app" | jq '{Running,OOMKilled,ExitCode}' >"$dest/app-state.json"
if (( status != 0 )); then
  if [[ -z ${BENCH_ARRIVAL_PHASES:-} ]] || jq -e '.Running' "$dest/app-state.json" >/dev/null ||
      ! docker exec "$gen" test -s /tmp/goose8-window.tsv; then
    printf 'INVALID driver or sampler exited %s\n' "$status" >&2
    exit 1
  fi
fi
docker cp "$gen:/tmp/goose8-window.tsv" "$dest/arrivals.tsv"
taskset -c "$BENCH_CONTROL_CPU" python3 "$PERF/monitor/seal.py" "$dest" "$peer" "$flow" "$rate" "$seconds" >"$dest/summary.json.tmp"
mv "$dest/summary.json.tmp" "$dest/summary.json"
jq -c '[.status,.operations.all.successful_tps,.operations.all.failed,.operations.all.not_sent,.operations.all.offered_to_completion_success_ms["99"],.resources.app.mean_cpu_cores,.resources.app.max_single_process_rss_mib,.host_cpu_psi_pct]' "$dest/summary.json"


taskset -c "$BENCH_CONTROL_CPU" python3 "$PERF/monitor/quiet.py" >"$dest/post.json"
python3 "$PERF/monitor/placement.py" "$dest"
jq -c '{status, invalid_reasons, host_cpu_psi_pct}' "$dest/summary.json"
