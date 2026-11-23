"""Extend the diagnostic k6 copy with HTTP timings. The comparison script stays pinned."""

from pathlib import Path
import sys

src, dest = map(Path, sys.argv[1:])
s = src.read_text()
marker = "const latency = new Trend('successful_operation_ms', true);"
assert s.count(marker) == 1
s = s.replace(
    marker,
    marker
    + """
const afterCommit = new Trend('after_commit_ms', true);
const waitFirst = new Trend('wait_first_byte_ms', true);
const receive = new Trend('receive_ms', true);
const sampleCount = new Counter('postcommit_samples');
""",
)
marker = "    success.add(1);"
assert s.count(marker) == 1
s = s.replace(
    marker,
    marker
    + """
    waitFirst.add(response.timings.waiting);
    receive.add(response.timings.receiving);
    const header = response.headers['X-Bench-After-Commit-Ns'];
    if (header !== undefined) {
      afterCommit.add(Number(header) / 1e6);
      sampleCount.add(1);
    }
""",
)
marker = "return {'/tmp/k6-window.json':"
assert s.count(marker) == 1
s = s.replace(
    marker,
    """const timing = {};
  for (const key of ['after_commit_ms', 'wait_first_byte_ms', 'receive_ms', 'postcommit_samples', 'measured_success']) {
    timing[key] = data.metrics[key].values;
  }
  return {'/tmp/k6-http-timing.json': JSON.stringify(timing), '/tmp/k6-window.json':""",
)
dest.write_text(s)
