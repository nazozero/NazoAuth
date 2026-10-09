# Blackbox and database evidence contract

`blackbox-db-v1` is an explicit new collection contract. The application has no
performance route, pool acquire/wait counters or audit-only statistics atomics.
Collection uses k6 traffic, task container process/cgroup snapshots, PostgreSQL
statistics and runtime-role state/wait groups, Valkey statistics and the existing
receiver journal. No runtime probes, tracing timers or diagnostic endpoint are
introduced into the business binary.

Pool checkouts, acquire waiting and best-effort process queue counts are
unavailable. Their JSON values are null and their status is UNAVAILABLE or
UNVERIFIED. Three legacy process queue gates are explicitly UNVERIFIED and are
not part of the external gate dictionary. A PASS is scoped to the declared
external evidence; it does not assert these internal gates passed. DB outbox
drainage cannot prove the process queue is empty.

Required security checks retain DB persisted chain head/hash continuity,
deployment binding, receiver checkpoint/ACK reconciliation, accepted-event
increments, contiguous nonduplicated receiver journal and the existing protocol,
token/replay and durability checks. Missing DB or receiver evidence continues to
fail or invalidate the point. No rates, VUs, latency/cohort/drop gates, CPU/pool
parameters, fsync or Required semantics are relaxed.

Historical records retain their source, collector hash and contract. New pairs
use the same collector, source/image/binary attestations and fresh state for
both arms. Do not combine old internal-collector points with the new pairs as a
single acceptance result. Retired residency and pool-size experiment tools fail
closed; old source remains available in repository history.
