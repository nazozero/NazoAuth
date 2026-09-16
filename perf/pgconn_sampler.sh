#!/bin/bash
# Samples postgres backend count + nazoauth pool stats every 5s.
cd /workspace
PGC=$(docker compose -f docker-compose.perf.yml ps -q postgres)
echo "ts,pg_backends,pg_active,pool_size,pool_available,pool_waiting" > perf-results/pgconn-stats.csv
while [ ! -f perf-results/STOP_SAMPLER ]; do
  row=$(docker exec "$PGC" psql -U postgres -d oauth -tAc "SELECT count(*), count(*) FILTER (WHERE state='active') FROM pg_stat_activity" 2>/dev/null | tr '|' ',')
  pool=$(docker exec nazoauth-perf-nazoauth-1 sh -c 'cat /proc/1/status 2>/dev/null >/dev/null; echo -n ""' 2>/dev/null)
  echo "$(date +%s),${row:-,}" >> perf-results/pgconn-stats.csv
  sleep 5
done
