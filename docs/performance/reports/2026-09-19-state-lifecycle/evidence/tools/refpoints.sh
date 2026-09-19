#!/bin/bash
# Reference points: wait for baseline run, then patched 2000+2500
cd /workspace
LOG=/workspace/perf-results/refpoints.log
echo "refs start $(date -u +%FT%TZ)" >> $LOG
# wait for baseline r2000 container to finish
while docker ps --format "{{.Names}}" | grep -q "perf-run"; do sleep 15; done
mv /workspace/perf-results/ladder/cap_mixed-r2000 /workspace/perf-results/ladder/baseline-cap_mixed-r2000 2>/dev/null
echo "baseline done $(date -u +%FT%TZ)" >> $LOG
# swap to patched image
docker tag nazoauth-perf-nazoauth:patched nazoauth-perf-nazoauth:latest 2>/dev/null || docker tag d363903d601a nazoauth-perf-nazoauth:latest
docker compose -f docker-compose.perf.yml up -d --force-recreate --no-deps nazoauth >> $LOG 2>&1
for i in $(seq 1 60); do
  H=$(docker inspect nazoauth-perf-nazoauth-1 --format "{{.State.Health.Status}}" 2>/dev/null)
  [ "$H" = "healthy" ] && break; sleep 5
done
echo "patched healthy=$H $(date -u +%FT%TZ)" >> $LOG
bash perf-results/arrive.sh cap_mixed 2000 300 >> $LOG 2>&1
bash perf-results/arrive.sh cap_mixed 2500 300 >> $LOG 2>&1
echo "REFS_DONE $(date -u +%FT%TZ)" >> $LOG
