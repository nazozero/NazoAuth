# Embedded transient state

The optional `nazo-kevy` adapter implements the native server's existing transient
state ports with Kevy 7.0.0. It supports one owner process per deployment, with
threads and tenant bindings sharing that process's backend. PostgreSQL continues
to own durable accounts, grants, token consumption, refresh rotation and audit.

## Build and configuration

```sh
cargo build --release --locked -p nazo-server \
  --no-default-features --features kevy --bin nazoauth-kevy
target/release/nazoauth-kevy server
```

The first invocation generates the normal native configuration and the selected
adapter's configuration. An existing configuration uses these state settings:

```yaml
KEVY_REPLAY_DIR: "runtime/kevy-replay"
KEVY_STATE_EPOCH: "019c8ca2-30a6-7000-8000-00000000e103"
```

Generate a fresh UUIDv7 for the deployment's recovery epoch instead of copying
the example. `KEVY_REPLAY_DIR` is resolved relative to the configuration file.
Use a persistent local filesystem, retain the directory across process restarts,
and restrict access to the service account. The default path is
`runtime/kevy-replay`. PostgreSQL and all ordinary native configuration still
apply. Valkey-specific configuration belongs to the default `nazoauth` launcher.

The `valkey` Cargo feature remains the default. The embedded production graph
built above excludes Fred and the Valkey adapter. Kevy enables only `core` and
`persist`; its listener, replication, indexing, vector and tiering features are
disabled. Its internal `kevy-resp` dependency supplies command metadata and AOF
encoding. The adapter calls native Rust methods without a RESP client, listener,
socket, command dispatcher or Lua interpreter.

Embedders construct `KevyBackend::open(path, deployment_id)` once, outside the
request path, then pass `server_state_bindings(backend)` to their existing
composition. Opening/replay is blocking startup work. Tenant binding clones
shared handles and does not open another store.

## State and restart behavior

| State | Owner | Restart behavior |
| --- | --- | --- |
| Sessions, PAR, consent, authorization-code payloads, Device/CIBA state and ping work, reauthentication and DPoP nonces, Passkey/federation state, email challenges, delivery and avatar stages, rate counters | In-memory Kevy store | Discarded; users log in again and restart pending workflows. Counters restart empty. |
| Accepted DPoP, JAR, JWT assertions, client-attestation PoP, CIBA request objects, SAML and HTTP-signature replay markers | Exclusive persistent Kevy replay store | Retained through their acceptance deadline, including across process crashes. |
| Tenant directory projection | Shared process-local snapshot | Rebuilt from the authoritative persistence provider. |
| Authorization decisions, code consumption receipts, refresh families, revocations and required audit | Existing persistence provider | Existing transaction and recovery rules apply. |

The volatile store has one shard so compound changes publish atomically under
one native lock. Records retain their original logical expiry during CAS and
lease transitions. CIBA due work uses a bounded ordered index with independent
member expiry; the whole queue never receives a TTL.

The replay store uses `AppendFsync::Always`, AOF enabled and no eviction. Each
successful consumption waits for the native synchronous write. An async replay
mutex owns the check and write; blocking disk work runs outside Tokio worker
threads. A write, rewrite or required directory-sync error latches this replay
owner unavailable, including subsequent consumption and health checks. An
ambiguous write never becomes an accepted proof.

The volatile store uses native TTL reclamation. Replay markers carry their
absolute deadline in the value and have no native TTL: consumption checks that
deadline so AOF recovery cannot shorten a proof's replay-protection window.
Compaction removes expired markers; an idle store retains them until the next
compaction.

The adapter disables background AOF rewrite because Kevy 7.0.0 logs its cutover
errors without returning them to the caller. Within the same replay lock, it
removes logically expired markers and calls the native `rewrite_aof` when
the log reaches 64 MiB, then waits for at least twice the last compacted size
(with a 64 MiB floor) before the next rewrite. A reopened log above the floor is
compacted on its next accepted consumption. Rewriting pauses proof consumption
while the native engine writes the compacted image; workflow operations remain
independent. Startup syncs the AOF directory and all newly created ancestor
entries; each successful rewrite syncs the directory before accepting its
triggering proof. Ordinary appends need only native file sync. Live markers
remain necessary storage until their acceptance windows end.

Proof keys bind tenant, purpose and length-delimited identifiers. They deliberately
exclude `KEVY_STATE_EPOCH`: rotating an operational epoch cannot invalidate an
external signed proof and must not forget its consumption marker. The configured
epoch remains the identity checked by the existing `RecoveryInvalidate` operator
command. The replay directory is bound to one deployment identity.

## Ownership and recovery

Only one process may serve the deployment. The adapter locks its retained
directory handle before inspecting the log; Kevy also holds its native process
lock. Different directories are independent
security authorities; they must not serve the same deployment simultaneously.
Use Valkey for multiple application processes or shared-state deployment.

A normal restart reopens the retained replay directory before admitting traffic.
No workflow snapshot is restored. Do not restore an old replay snapshot, delete
the replay directory, or treat it as disposable cache. A new empty directory is
appropriate only for a new deployment or a completed state-loss recovery.

Startup validates the AOF through the native streaming reader while holding the
directory lock, before opening the engine. Damaged, truncated or unexpected
zero-filled tails are rejected without modifying the original file. Existing
quarantine files and staging rings also block startup. This adds one read of
the log at startup and prevents the engine's automatic repair from erasing
evidence across an interrupted open. Preserve the directory for inspection.
After replay-state loss, corruption or rollback, keep
ingress closed until every applicable accepted-proof window has drained under
the verified clock bound, or invalidate the corresponding trust/credentials.
Changing the epoch alone is insufficient. The existing refresh/access/ID-token
recovery wait is not a substitute for externally signed proof windows; see
[client-attestation replay](../protocol/client-attestation-replay.md) and
[state-loss recovery](ha-operations.md).

An offline copy of a stopped store preserves its files, but restoring an older
copy can lose subsequently acknowledged markers. Such a restore follows the
same state-loss procedure. Local synchronous persistence does not provide
replication or a multi-instance failover protocol.

## Reproducible comparison

Build the existing [Goose runner](../../perf/README.md), prepare separate native
Valkey and embedded runs with the same PostgreSQL fixture and signing/profile
settings, and use [bench-kevy-valkey.py](../../scripts/bench-kevy-valkey.py).
All service processes, including PostgreSQL and Valkey when present, share the
same server CPU set. Run Goose and the resource sampler on a disjoint CPU set.
Keep Valkey persistence and no-eviction settings consistent with the required
replay guarantee.

The runner retains the per-arrival ledger and reports successful TPS,
P95/P99/P99.9, failed/unsent requests, per-component and combined CPU/PSS, and
available host-pressure measurements. Alternate backends, repeat each offered
load, and repeat the boundary where delivered throughput ceases to track the
target. A low-load pair alone does not establish sustainable capacity.

Use authenticated authorization plus code exchange to exercise the common
session/one-use path. Also measure a proof-bearing profile when assessing replay
throughput: its synchronous proof-marker writes have a different cost from
ordinary in-memory workflow operations. Keep run-specific records and adoption
decisions with the tested PR/revision rather than adding generated runs to source.
