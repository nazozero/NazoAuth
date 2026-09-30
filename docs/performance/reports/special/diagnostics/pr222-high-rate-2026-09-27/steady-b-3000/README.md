PR #222 B3000 steady-state evidence bundle.
Production source B and shared harness H are fixed at 462626b29be202c04f2e4482ade6ab5f5f6267c5. Diagnostic patch: dc72cf469a2c5465cbb8a8185e0cff7d9999ad96. Common profile SHA-256: e459bfe9e77c2bbd043cd1f9ed31627345b0450cbcd77e160298691e9667ef0b.

The raw per-second load histogram and exact measurement window are retained. WAL pre/post snapshots provide PG18 pg_stat_wal and pg_stat_io deltas. The detailed analysis contains 31 UTC-minute complete-iteration P99 histogram brackets, sampled WAL/checkpoint/wait deltas, relation counter deltas, process CPU/RSS summaries, and strict PGSS baseline coverage. Issuance-maintenance output was produced by the existing helper with the predeclared 360 s retention and 120 s maximum expiry age.

Raw PGSS snapshots are excluded because they contain normalized SQL text. Raw soak rows and audit journals are excluded because they include audit-chain material; only sanitized counts/counters are retained. The diagnostic stream itself is not included. Docker stats returned 0/0 and is not treated as a real measurement.
