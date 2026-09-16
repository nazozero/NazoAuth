#!/bin/bash
# Samples /proc RSS + CPU jiffies for app/pg/valkey containers every second.
# CSV: epoch,app_rss_kb,app_jiffies,pg_rss_kb,pg_jiffies,vk_rss_kb,vk_jiffies
OUT=/workspace/perf-results/cgroup-stats.csv
echo "epoch,app_rss_kb,app_jiffies,pg_rss_kb,pg_jiffies,vk_rss_kb,vk_jiffies" > "$OUT"
read_stats() {
  docker exec "$1" sh -c 'awk "/VmRSS/{print \$2}" /proc/1/status; sed "s/.*) //" /proc/1/stat | awk "{print \$12+\$13}"' 2>/dev/null | tr '\n' ','
}
while true; do
  a=$(read_stats nazoauth-perf-nazoauth-1)
  p=$(read_stats nazoauth-perf-postgres-1)
  v=$(read_stats nazoauth-perf-valkey-1)
  echo "$(date +%s),${a}${p}${v}" >> "$OUT"
  sleep 1
done
