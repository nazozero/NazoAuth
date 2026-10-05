# Connection holding diagnostic on 779d251e

This independent diagnostic branch is not a production PR change or acceptance run. Enable `NAZO_CONNECTION_DIAG=1` only with a fresh task-owned `/diagnostic` volume writable by the app UID. It records static source locations, bounded operation tags, diagnostic IDs and PG backend PIDs. It never records SQL text, parameters, tokens, subjects, tenant values or connection URLs.

A single PID query runs after each physical driver is established. RAII records normal Object return, explicit physical discard and cancellation; original transaction/result ordering stays unchanged. Checkout timestamps precede Object return/discard. Bridge enqueue, first poll, completion and join resumption share a monotonic timeline anchored to wall time.

Only actual awaited principal SQL and the fully drained authorization function load are labeled SQL completion. Diesel FinishQuery is ignored. Token transaction body Drop and the completed outer transaction await delimit commit/rollback plus resumption; this is not claimed to be pure COMMIT latency. Untimed SQL remains visible in PG sampling and total hold time.

All stages have fixed 12-bucket histograms. Individual records require at least 10ms or a non-ok outcome, are limited to 128 per stage per second, use an 8192-slot nonblocking queue and a 64MiB file cap. There are no overwrites. A separate bounded health file reports cumulative queue/rate/file drops, PID failures, write errors, measured producer emit time and writer busy wall time; producer allocation/setup overhead is outside the emit measurement and must be assessed from the diagnostic run. The observer is not zero overhead.

Use one unchanged S21 recipe diagnostic point and a low-frequency read-only PG PID-state sampler. Keep every outcome and cleanup proof. This point provides attribution only and cannot supply acceptance or compensate for earlier FAIL results.
