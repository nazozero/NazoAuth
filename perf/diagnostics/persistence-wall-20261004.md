# Current-candidate persistence wall timing diagnostic

This branch is a temporary diagnostic derived from PR230 `19dfd5b`, not a
performance fix or a replacement acceptance candidate. Enable only on a fresh
task fixture with `NAZO_PG_TIMING=1`. A bounded, nonblocking channel writes
numeric PID, sequence, time and fixed event labels to the create-new private
file `/tmp/nazo-pg-timing.jsonl`; SQL, binds, URLs, keys and errors are never
formatted. Buffer losses have explicit `buffer_dropped` records.

Only diagnostic connection setup adds one `SELECT pg_backend_pid()` to associate
the actual server PID before measurement; a zero PID makes the trace invalid.

Events measure Diesel query/COMMIT callback wall time, gaps between SQL within
one checkout, pool acquisition, confirmed DiscardOnDrop connection hold, and
spawn-to-first-poll / operation-finish-to-HTTP-join-resume. Ordinary read-only
connection drops are not covered by the confirmed-guard hold event. SQL stream
finish callbacks are not independently a universal ReadyForQuery guarantee;
explicit COMMIT batch execution is measured through its actual finish event.

JoinSet cancellation, discard-on-unknown-outcome, query order, SQL, transaction
and response semantics are preserved. Cancelled guards are not introspected.
The extra writer thread and timing work invalidate formal performance comparisons.
Use one original-rate 30-second diagnostic and the same pool, CPU placement,
durability and original gates; retain all prior failures.
