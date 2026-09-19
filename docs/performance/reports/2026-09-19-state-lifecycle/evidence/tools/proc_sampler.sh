#!/bin/bash
OUT=${1:-/workspace/perf-results/proc-stats.csv}
echo "epoch,app_jif,app_rss_kb,pg_jif,pg_rss_kb,vk_jif,vk_rss_kb,run_jif,run_rss_kb" > "$OUT"
samp() {
  c=$(docker ps --format "{{.Names}}" | grep -E "^$1" | head -1)
  [ -z "$c" ] && { echo ","; return; }
  docker exec "$c" sh -c 'j=0;r=0
for f in /proc/[0-9]*/stat; do
  read -r line < "$f" 2>/dev/null || continue
  rest=${line##*) }
  set -- $rest
  j=$((j + ${12:-0} + ${13:-0}))
done
for f in /proc/[0-9]*/status; do
  while read -r k v _; do [ "$k" = "VmRSS:" ] && r=$((r+v)) && break; done < "$f" 2>/dev/null
done
echo "$j,$r"' 2>/dev/null || echo ","
}
while [ ! -f /workspace/perf-results/STOP_SAMPLER ]; do
  ts=$(date +%s)
  a=$(samp "nazoauth-perf-nazoauth-")
  p=$(samp "nazoauth-perf-postgres-")
  v=$(samp "nazoauth-perf-valkey-")
  r=$(samp "nazoauth-perf-perf-run-")
  echo "$ts,$a,$p,$v,$r" >> "$OUT"
  sleep 2
done
