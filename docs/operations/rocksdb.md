# Single-process RocksDB deployment

`nazoauth-rocksdb` is an opt-in native executable for one server process with a
local durable database. It implements the existing persistence ports with
RocksDB `TransactionDB`. The ordinary `nazoauth` executable, release images and
managed PostgreSQL deployment keep their existing backend. Cloudflare Workers
continue to use D1.

The RocksDB executable still uses Valkey for transient security state and the
normal local/S3 avatar adapter. It does not provide a multi-process database,
replication, PostgreSQL role isolation, or an independent audit exporter.

## Build and configuration

Build from source with the optional native feature:

```sh
cargo build --release -p nazo-server --features rocksdb --bin nazoauth-rocksdb
```

The native build needs a C++ compiler and libclang for the RocksDB bindings in
addition to the workspace's usual build dependencies. Only the optional
`rocksdb` feature pulls this dependency into the native host.

Use the normal [native configuration](configuration.md), with these values:

```yaml
DATABASE_URL: "runtime/rocksdb"
SECURITY_AUDIT_REQUIRE_LEAST_PRIVILEGE: false
AUDIT_ANCHOR_MODE: "disabled"
```

For this executable, `DATABASE_URL` names a filesystem directory, not a network
connection string. Relative paths resolve against the configuration working
directory, just like other persistent native paths. A URL containing `://` is
rejected. The default is `runtime/rocksdb`; `DATABASE_MAX_CONNECTIONS` does not
create a RocksDB connection pool. Put the directory on a local persistent
volume owned by the service account. Do not place it on an ephemeral container
layer or share it between instances.

Keep the normal deployment identity, `VALKEY_URL`, fresh initial
`VALKEY_STATE_EPOCH`, issuer, signing-key wrapping root and transport settings.
The same TOTP and OpenID4VC encryption configuration applies. Supply and back
up the encryption roots independently of the database ciphertext.

With the configuration and encryption roots in place, initialize the directory
and tenant signing material, then start the service:

```sh
./target/release/nazoauth-rocksdb migrate
./target/release/nazoauth-rocksdb server
```

The adapter creates schema version 1 on first open and rejects unknown schema
versions. `migrate` initializes the existing native tenant/bootstrap lifecycle;
there is no PostgreSQL-to-RocksDB data conversion. Start with a new directory or
restore a backup made by this adapter. Existing NazoAuthCtl PostgreSQL
installation/release workflows do not provision this source-built executable.

## Ownership and durability

One process owns the database directory. Cloned adapter handles inside that
process share the same `TransactionDB`. A second process opening the directory
fails on the RocksDB lock, including a second server or an offline CLI command.
Stop the server before invoking `operator-task`, `admin-provision`, `migrate`,
`tenant-bootstrap` or the mdoc management commands with this executable.
Online HTTP administration uses the server's existing handle.

Security-sensitive mutations use synchronous WAL commits. Account/client
authority checks, one-use consumption, refresh-family changes, required audit
events and operation receipts participate in their owning transaction.
Point reads decode pinned database values directly; multi-record reads use
consistent snapshots. Synchronous RocksDB work runs on Tokio's blocking pool.
Application ports still return their existing owned records, so this does not
claim end-to-end zero-copy deserialization.

The audit ledger remains part of those atomic commits. RocksDB has no separate
database roles, so this deployment requires an explicit
`SECURITY_AUDIT_REQUIRE_LEAST_PRIVILEGE: false`. Startup rejects the default
`true` posture and any enabled `AUDIT_ANCHOR_MODE`. The standalone
`audit-anchor-worker` command is unsupported because it would require another
database owner. Choose PostgreSQL when independent database privileges or the
separate exporter are required.

Required audit and source-event history, controller recovery receipts,
allocation replay fences and retired recovery-key history are retained. There
is no automatic history pruning or external audit export in this deployment;
account for this retained data when sizing the volume and backups. Expired
identity-approval tokens are eligible for bounded maintenance.

Protocol expiry is checked when state is used. Background maintenance removes
eligible stored state in bounded batches; expiry is not dependent on a
successful compaction or sweep. Keep adequate free disk space for the WAL,
memtables and compaction output. Disk errors fail the affected operation; a
retry of a receipt-bearing operation must retain its original identity and
payload.

## Backup

For the standalone executable, stop ingress, drain and stop the server, then
copy the **entire closed database directory** to an independent backup location.
Include all RocksDB files and WAL files. Copying selected SST files or copying
the live directory with a filesystem traversal does not create a consistent
backup. Record the application revision and configuration used with the copy.

Embedders that already own the open handle can call
`RocksDb::checkpoint(destination)` to create a consistent checkpoint in a new
directory. The destination must not already exist. Checkpoints may hard-link
immutable files on the same filesystem; copy the completed checkpoint to an
independent durable volume before treating it as a backup. Opening a second
process to make the checkpoint is not supported while the server owns the DB.

Back up the matching signing-key wrapping roots, TOTP key ring, OpenID4VC data
encryption key, deployment configuration and avatar objects. An encrypted
database backup without its required keys cannot restore those credentials.
Protect backup access as access to authentication data. Rehearse restoration
before relying on a backup.

## Restore and rollback

1. Keep public ingress closed and stop the server. Restore a complete backup
   into a separate directory and restore its matching encryption material.
2. Point the RocksDB executable at that directory. Use a compatible schema and
   application revision. A directory copied from PostgreSQL or a partially
   restored RocksDB directory is not valid input.
3. Select a **new UUIDv7 `VALKEY_STATE_EPOCH`** before starting the restored
   candidate. Never reuse the pre-restore transient namespace or restore an old
   Valkey snapshot as a security-state shortcut.
4. Execute the normal accepted `RecoveryInvalidate` operator operation against
   the stopped instance's restored store. It durably revokes refresh families
   and records the replayable `not_before` receipt. Keep the same operation
   identity when resolving an uncertain result.
5. Start the candidate behind closed ingress. Verify health, tenant routing,
   account/client lookup, JWKS, login, token issuance, refresh/revocation and
   required audit persistence. Keep ingress closed until strictly after the
   receipt's `not_before` deadline, which covers outstanding stateless-token
   lifetimes and clock skew.

See the [state-epoch recovery boundary](ha-operations.md#state-epoch-and-restore-boundary)
for why restoring durable authentication data also requires invalidating
transient state and waiting out already-issued stateless tokens. A filesystem
rollback is a restore and must use the same boundary.

## Contract tests and performance comparison

The adapter tests open real RocksDB directories. Run the durable repository
suite and the optional launcher checks with:

```sh
cargo test -p nazo-rocksdb --all-targets
cargo test -p nazo-server --features rocksdb --lib launchers::rocksdb::tests
```

The tests cover concurrent authorization-code consumption, refresh reuse and
rotation, issuance versus revocation, required-audit rollback, tenant isolation,
bounded expiry cleanup and a child process killed before reopening the same
directory. That restart test verifies acknowledged consumption and the absence
of an uncommitted transaction. It is a process-crash test, not a hardware
power-loss simulation.

The comparative runner calls the same `TokenRepositoryPort` methods on both
backends. Each flow commits an authorization-code issuance and its required
audit, reads the current refresh and OIDC subject projection, then commits a
rotation and its required audit. Each worker has its own user and shares the
client, so concurrency does not accidentally exceed the ten-live-family limit
for a user/client pair. There is no HTTP transport, Valkey, signing or password
hashing in the measured flow.

Build the optimized example, then use an installed PostgreSQL 18.7 server and
client toolchain. Choose a new directory on a real local disk for `--work-dir`:

```sh
cargo build --release -p nazo-rocksdb --example token_repository_bench
python3 scripts/bench-rocksdb-postgres.py \
  --binary target/release/examples/token_repository_bench \
  --pg-bin /usr/lib/postgresql/18/bin \
  --work-dir /var/tmp/nazo-repository-bench \
  --flows 50000 --concurrency 1 8 32 --repetitions 3
```

The script starts an isolated local PostgreSQL instance with `fsync=on`,
`synchronous_commit=on` and `full_page_writes=on`; RocksDB retains synchronous
WAL commits. Every trial has fresh application data and parallel warmup.
Backend order alternates between trials. Do not run builds or unrelated load
while measuring.

JSON output reports successful flows and commits per second, errors, P95/P99/
P99.9 for the flow and each repository phase, CPU seconds and CPU percentage
(one fully occupied core is 100%), and sampled peak PSS. PostgreSQL totals
include both the Rust application and all database server processes. CPU/PSS
measurement ends before percentile sorting. PSS is sampled every 50 ms and
can miss shorter allocation peaks. The runner fails if any flow fails; failed
operations never count as successful throughput.

These results measure a small-dataset repository workload. They do not establish
end-to-end latency, sustained compaction behavior, large-dataset capacity or
production equivalence with PostgreSQL.
