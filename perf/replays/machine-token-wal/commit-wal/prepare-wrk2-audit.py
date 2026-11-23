"""Copy the stock wrk2 point, bracketing only the measured request stream with audit observations."""
from pathlib import Path

source = Path("bench/capacity/point.sh").read_text()
k6 = Path("bench/comparison-point.sh").read_text()
snapshot = k6[k6.index("snapshot() {"):k6.index('snapshot >"$scratch/count-before"')]
lsn = next(line for line in k6.splitlines() if line.startswith("lsn() {"))

# Fixture validation issues a real token. Start both observations after validation
# and before the resource samplers and wrk2 start. Use k6's native observer verbatim.
before = "n=$(((seconds + 4) / 2 + 1))"
assert source.count(before) == 1
source = source.replace(before, snapshot + lsn + """
snapshot >"$scratch/count-before"
lo=$(lsn)
""" + before)
# screen.py reads any existing summary even when the subprocess exits nonzero.
# Preserve HTTP and resource evidence, and mark an incomplete observation invalid.
trap = "trap cleanup EXIT"
assert source.count(trap) == 1
source = source.replace(trap, """finish() {
  local code=$?
  if ((code != 0)) && [[ -s $out ]]; then
    jq '.accepted=false | .outcome="harness" | .audit_observation="incomplete"' \
      "$out" >"$scratch/invalid.json" && mv "$scratch/invalid.json" "$out"
  fi
  cleanup
}
trap finish EXIT""")
# The stock point waits for wrk2 and its samplers, then seals the HTTP metrics.
# At this boundary the generator has stopped and no subsequent fixture has run.
source += '''
snapshot >"$scratch/count-after"
hi=$(lsn)
read -r before_rows _ <"$scratch/count-before"
read -r after_rows _ <"$scratch/count-after"
acknowledged=$((after_rows - before_rows))
if [[ "$lo" == "$hi" ]]; then
  python3 "$BENCH_WRK2_WAL_COUNT" "$BENCH_WRK2_AUDIT_REL" "$out" --wrk2 "$acknowledged" </dev/null
else
  docker exec -u postgres "$PG" pg_waldump -s "$lo" -e "$hi" \\
    | python3 "$BENCH_WRK2_WAL_COUNT" "$BENCH_WRK2_AUDIT_REL" "$out" --wrk2 "$acknowledged"
fi
'''
Path("bench/capacity/audited-point.sh").write_text(source)

