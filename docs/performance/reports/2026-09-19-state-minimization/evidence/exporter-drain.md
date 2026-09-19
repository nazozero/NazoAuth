# Exporter drain measurements (2026-09-19, perf DB, stub TLS anchor @172.17.0.4:8902)

Topology: 6 × `nzanchor*` workers on `nazoauth-perf_perf_net`, `AUDIT_ANCHOR_BATCH_SIZE`, `AUDIT_ANCHOR_POLL_INTERVAL_SECONDS=1`, `DEPLOYMENT_ID=maint-dep`, `SSL_CERT_FILE=/etc/ssl/cert.pem` (self-signed stub CA). Stub accepts any POST → 200.

## Batch-size sweep, idle DB

| Injection | batch | observed drain | note |
|---|---|---|---|
| 3,000 events | 256 | ≤30 s to zero | lower bound ≥100/s |
| 10,000 events | 64 | 10,000→8,336 in 28 s ≈ **59–126/s** | uneven worker split (claim convoy): per-worker anchored 2624/2944/192/1383/3576/2 |
| 20,000 events | 256 | 20,000→1,237 in ~34 s ≈ **290–470/s** | rate accelerates as backlog shrinks |

## Under load

- short @2500 soak window: outbox 1,622,770→1,683,908 (+61,138/24 s ≈ **2,547/s net growth**); per-worker anchored in 60 s: 512/1024/768 → aggregate ≈ **230/s**
- 2 h soak @2000: `security_audit_chain_entries` 154,427→279,541 (+125 K/7,200 s ≈ **17.6/s**) — drain collapses further as backlog deepens (claim `ORDER BY chain.sequence NULLS LAST` + singleton chain-head lock); `temp_bytes` cumulative 8.57 TB (sort spill).

## Event rate (for contrast)

- ~2,780 events/s @2500 ops/s; ~2,400–2,500 events/s @2000 ops/s ⇒ ~1.08 durable events/op.

## Conclusion

Outbox is **export-flow-controlled**: bound = exporter throughput ≪ event rate under load. Protocol needs batched checkpoints and/or sharded chain head; claim ordering needs an index-aligned predicate for deep backlogs.
