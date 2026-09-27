PR #222 A3200 steady-state evidence bundle

Test: 120 s warmup + 1800 s effective measurement at target 3200 successful logical operations/s. The point is a valid performance FAIL under the fixed evaluator. No load profile or threshold was changed.

Production A/main: 0c70d7464576138af0b3f8a39530d6615ee7a363. Shared harness H and production B/candidate: 462626b29be202c04f2e4482ade6ab5f5f6267c5. Diagnostic patch: dc72cf469a2c5465cbb8a8185e0cff7d9999ad96. Common frozen profile SHA-256: e459bfe9e77c2bbd043cd1f9ed31627345b0450cbcd77e160298691e9667ef0b.

The bundle contains the exact per-second complete-iteration histogram series/window, sanitized full-point metrics and minute correlation, PG18 WAL snapshots, refresh evaluator output, issuance-maintenance sample summary, and source/image provenance. It excludes raw PGSS SQL rows, raw audit/journal contents, request diagnostics, and unsanitized soak rows.

PGSS attribution is INVALID/INCOMPLETE: only 3 rows match full identity and unchanged stats_since across pre/post; 169 post-only rows are excluded. No SQL Top10 is claimed. pg_stat_io identifies client-backend WAL writes as the dominant broad category across a 2003.634 s full snapshot interval, not an exact 1800 s SQL attribution.

WAL write and fsync timing deltas are raw zero in this runtime and are reported N/A, not as zero wait. WAL write bytes are not disk net growth or SSD media writes. The bundle does not establish causation between WAL/checkpoint activity and the observed queue/P99 regression.
