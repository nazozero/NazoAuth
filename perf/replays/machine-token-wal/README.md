# Machine access token issuance on a fixed PostgreSQL server

The [machine-grant replay](#machine-token-success-audit) compares the previous
implementation, the current default with a committed success event, and the
same binary with that event disabled. It also compares Keycloak and Ory Hydra
and measures valid-token introspection. The [comparison tables and round-by-round
measurements](https://github.com/nazozero/NazoAuth/pull/310) include CPU, memory,
latency, failed requests and missed arrivals.

## Earlier commit-latency experiment

The control and candidate use the same Rust release toolchain, API-provisioned
client, PostgreSQL process, database, Valkey instance and k6 workload. The
candidate combines the client fence and audit insert in one SQL statement
inside the existing explicit transaction. Each NazoAuth arm counts an audit
event after the transaction confirms its commit. The runner independently
matches audit heap insertions with committed transaction IDs in flushed WAL.
Keycloak and Ory Hydra each use their own database. The runner records the
actual Keycloak realm event configuration through its administration API.
The [reference measurements](https://github.com/nazozero/NazoAuth/pull/310)
include per-window throughput, latency and audit counts.

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

The retained NazoAuth implementation also runs three trials at 4,375 and
5,000 requests/s to narrow the interval between the common 2,400 and 6,000
settings. These are capacity measurements for NazoAuth alone.

`F` identifies the unchanged NazoAuth transaction, `E` the application
candidate, `K` Keycloak and `H` Hydra. CPU is reported as mean cores and memory as
maximum sampled single-process RSS. PostgreSQL has multiple processes. Host
pressure and shared-cgroup I/O are available separately in the window JSON.
The Markdown report compares equal offered loads and retains dropped
arrivals. Each window's WAL interval starts after fixture validation and
covers the warm-up. Counting the physical audit relation assumes that this
fixture is its only audit producer during the window.

## Machine-token success audit

In the 2026-11-23 k6 comparison, each service received 2,400 requests/s to
issue a machine access token. P95 and P99 give the time within which 95% and
99% of successful requests finished. Each cell is the median of three windows.

| Service and success-event setting | Successful requests/s | P95 (ms) | P99 (ms) | Passing windows |
| --- | ---: | ---: | ---: | ---: |
| NazoAuth before the change, durable event | 2,400.0 | 5.391 | 12.756 | 3/3 |
| NazoAuth revised default, durable event | 2,400.0 | 4.682 | 9.104 | 3/3 |
| NazoAuth revised, success event disabled | 2,400.0 | 0.796 | 0.922 | 3/3 |
| Keycloak 26.8.2, realm event storage disabled | 2,400.0 | 1.396 | 1.709 | 3/3 |
| Ory Hydra 26.2.0 | 0.2 | 4,013.678 | 4,808.042 | 0/3 |

Hydra timed out at this load. Its percentiles cover the few successful
responses. Every success in the revised default windows had a committed
audit row (331,204 including warm-up). The
[full results](https://github.com/nazozero/NazoAuth/pull/310) also include a
common lower load, valid-token introspection, higher offered rates and resource
observations for each process role.

To replay the machine-grant refactor, extract the fixture archive and copy
the `commit-wal` directory as above. From that directory, run:

```sh
bash build-machine-policy.sh "$repo" HEAD
bash setup-fixture.sh
bash compare-machine-policy.sh \
  B-2400-1 A-2400-1 N-2400-1 N-2400-2 B-2400-2 A-2400-2 A-2400-3 N-2400-3 B-2400-3
bash peer-ref.sh keycloak K-2400-1 K-2400-2 K-2400-3
bash peer-ref.sh hydra H-2400-1 H-2400-2 H-2400-3
```

`B` runs the previous implementation. `A` uses the revised binary with its
default audit configuration. `N` uses the same binary with
`AUDIT_CLIENT_CREDENTIALS_ISSUANCE=false`. Use a new trial label for each
window. Supply the desired rate as the middle field and rotate the arms
between rounds. All three share the API-created machine client and NazoAuth
database. Each peer retains its own database. For audited runs the controller
matches HTTP successes, committed-event acknowledgements and committed audit
inserts in flushed WAL. For the explicitly disabled setting it requires zero
acknowledgements and zero audit inserts, while applying the same load and
resource checks. Table row locks can generate WAL in either mode.

Use `BENCH_MACHINE_SCENARIO=introspect` with either comparison script to query
a valid access token prepared through the product API before measurement.
`policy-peers.sh` accepts `machine` or `introspect` followed by window names
with prefixes `B`, `A`, `N`, `K` (Keycloak) or `H` (Hydra) to rotate products.
`metadata.py results/environment.json control revised` records the benchmark
binary and k6 workload hashes and checks the original PostgreSQL durability settings.

For the optional client-lookup diagnostic, set `BENCH_BUILD_SNAPSHOT_TIMING=1`
when building, then set `BENCH_REVISED_BINARY=out/diagnostic` for one A or N window.
Pass the completed window JSON to `snapshot-share.py` with timestamped Docker
logs on standard input. It retains only aggregates from the measured interval.
The diagnostic samples one in 32 machine requests and times the full client
lookup and the interval from that lookup's start through grant completion.
Use the builds without the request-timing probe for the comparative latency
and capacity tables. To reproduce the lock-only transaction experiment, build
`f6334de07687dddce1d81db803d896b050cbca9a` first and copy `out/revised` to
`out/ref-lock`. Then build `864215aac8818235ef5646fb69481821e332ea7e`.
Use `BENCH_NO_AUDIT_REFERENCE=out/ref-lock` with `compare-machine-policy.sh`
to run `P` alongside the final builds. The optional client-relation WAL counts
show how many observed lock transactions committed or aborted.

To render a comparison from a specified set of windows, run:

```sh
python3 policy-report.py --details results/{B,A,N}-2400-{4,5,6}.json
```

Select matching builds, scenarios and trial numbers. Capacity uses three
passing windows at one offered rate. Each k6 window checks all responses and
missed arrivals, including warm-up. PostgreSQL connection startup, fixture
checks and issuance of a token for introspection precede the counted window.

For the separate wrk2 capacity search, run `bash policy-wrk2.sh N machine 12000`
or `bash policy-wrk2.sh N introspect 15000`. Select `K` or `H` for the peers.
The third argument supplies the first rate to try. The fixture's original
search uses 15 threads and 960 connections, 24-second screens and three
36-second confirmations. Each response is checked. The wrk2 percentiles are
corrected for coordinated omission and its timings include shutdown. Keep these
results separate from the k6 open-arrival measurements. Arm `A machine` also
records the native commit-counter delta and the committed audit rows in flushed
WAL for each wrk2 point. Its observations start after the fixture's test token.
At shutdown, wrk2 may close connections before the client reads every response.
The report retains any difference between committed rows and completed responses.
The k6 full-window counters support exact success-to-audit comparisons.

For a common lower-concurrency profile, export `BENCH_WRK2_CONNECTIONS=64`
for each service. The replay retains the 15 generator threads and the same
response, throughput and resource checks, and writes the separate profile to
`results/wrk2-c64`. Compare products at the same number of connections.
