# Machine access token issuance on a fixed PostgreSQL server

The control and candidate use the same Rust release toolchain, API-provisioned
client, PostgreSQL process, database, Valkey instance and k6 workload. The
candidate combines the client fence and audit insert in one SQL statement
inside the existing explicit transaction. Each NazoAuth arm counts an audit
event after the transaction confirms its commit. The runner independently
matches audit heap insertions with committed transaction IDs in flushed WAL.
Keycloak and Ory Hydra each use their own database. The runner records the
actual Keycloak realm event configuration through its administration API.

Use a dedicated Linux amd64 Docker host with Bash, Python 3, Git, jq, OpenSSL,
`flock`, `taskset`, a C compiler with static linking support and access to
the pinned images. Reserve the named Docker network and containers for this
fixture. The fixture generates its credentials locally. Its stock k6 workload,
API provisioners and resource samplers are pinned in the source-only
`fixture-sources.tgz` archive (SHA-256
`9917d77b53767fa4d625f38f5404ae3a45b8e73abfdfac678f4f66b26e884f75`).

```bash
repo=$(git rev-parse --show-toplevel)
kit="$repo/perf/replays/machine-token-wal"
work=$(mktemp -d)
tar -xzf "$kit/fixture-sources.tgz" -C "$work"
cp -R "$kit/commit-wal" "$work/"
cd "$work/commit-wal"
bash build-app.sh "$repo"
bash setup-fixture.sh
bash build-probe.sh
bash diagnose.sh 400 6000
bash run-all.sh
python3 report.py results
```

The original CPU masks are in `retest.sh`. For another host export
`BENCH_APP_CPUS`, `BENCH_PG_CPUS`, `BENCH_VK_CPUS`, `BENCH_K6_CPUS`
and `BENCH_CONTROL_CPU` before setup. Use 16 distinct physical cores for the
application, 14 logical CPUs for PostgreSQL, two for Valkey, 15 for k6 and
one for sampling. Keep the application's SMT siblings out of the other
assignments. The samplers verify the live thread masks in every window.

The two diagnostic windows use socket boundaries, PostgreSQL's reported wait
type around WAL system calls, Linux per-backend scheduler counters and the
thread CPU clock. A temporary observer runs the stock PostgreSQL executable
against the same volume, with the original server stopped. The timed A/B and
peer windows use the original uninstrumented PostgreSQL process. It stays up
while the runner rotates the applications. Each window uses ten seconds of
warm-up, then 30 seconds at 400 requests/s or 36 seconds at the higher rates.
The 2,400 requests/s comparison rotates the two NazoAuth builds and Keycloak.
Hydra runs separately on the same server after that rotation. Late requests
drain before reconciliation.

Two response diagnostics sample the control application once every 16
requests. A request-scoped timestamp measures the interval from the
repository's commit confirmation to the outer HTTP middleware's response.
The diagnostic k6 copy measures time to first byte and response transfer.
The unmodified k6 workload is restored after these windows.

`F` identifies the unchanged NazoAuth transaction, `E` the application
candidate, `K` Keycloak and `H` Hydra. CPU is reported as mean cores and memory as
maximum sampled single-process RSS. PostgreSQL has multiple processes. Host
pressure and shared-cgroup I/O are available separately in the window JSON.
The Markdown report compares equal offered loads and retains dropped
arrivals. Each window's WAL interval starts after fixture validation and
covers the warm-up. Counting the physical audit relation assumes that this
fixture is its only audit producer during the window.
