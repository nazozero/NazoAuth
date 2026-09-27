This sanitized attribution checkpoint summarizes PG18 pg_stat_statements deltas for the A3200 and B3200 600-second short points, plus task-local wait/checkpoint samples from the same effective windows.

The PGSS snapshots use full identity (dbid, userid, toplevel, queryid). stats_reset was unchanged, pg_stat_statements dealloc was 0 across each interval, and stats_since was after reset for every included row. Statement text is deliberately excluded; only safe operation categories, function/table targets, numeric identity and deltas are included. Top-level and nested rows can overlap and must not be summed. PGSS total_exec_time is not CPU time.

Wait samples record wait_event_type only, not event names such as WALWrite or WALSync. They are instantaneous snapshots, not event duration. Whole-window P95/P99 are not time-bucketed, so these files cannot prove point-in-time latency correlation.

Raw source snapshots remain with the corresponding point directories in the CNB task results. They include normalized PGSS statement text and are intentionally excluded from this sanitized archive; source file hashes and exact PGSS timestamps are recorded in pgss-top10-short-3200.json.