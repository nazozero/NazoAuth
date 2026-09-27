PG18 PGSS baseline validation for the A3200 and B3200 600-second short points.

The fixed taskbook requires subtraction only for the same full identity (dbid, userid, toplevel, queryid) and identical stats_since. stats_reset was unchanged and pg_stat_statements dealloc remained 0. Each pre snapshot had 3 rows and each post snapshot had 172/171. Only 3 rows per point matched identity and stats_since; their WAL-bytes delta was 0. The 169/168 post-only rows are excluded, never imputed as zero. No valid Top10 statement delta is available; status is INVALID/INCOMPLETE.

The previous interim ranking based on post-only counters is withdrawn. Do not use it as a validated WAL attribution. No normalized SQL text or SQL literals are included here. Raw pre/post snapshots remain with their respective point results in the CNB task directory and are identified by SHA-256 in the JSON.

wait-checkpoint-short-3200.json separately summarizes the existing wait-event-type snapshots and checkpointer boundary counters. It cannot distinguish WALWrite from WALSync and cannot correlate whole-window P99 with a specific time bucket.