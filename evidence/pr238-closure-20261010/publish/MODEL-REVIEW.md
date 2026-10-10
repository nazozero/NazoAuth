# Final model and reclamation review

Source: `667060893661dae2c2e31289d5d86ca6474132c3`.

This review continues the merged model review rather than treating a declaration scan as an audit. The prior 1,716-model inventory exactly matches the merged `4b4fdc33` source: zero shape mismatches. File hashes identify 39 changed production files out of 562; the current inventory contains 1,716 models and 7,173 members, with zero parser errors. `model-review-ledger.json` maps declarations and members to that provenance. `review-provenance.json` records which files retained the previous review and which required current call-chain review. Textual reference counts are navigation, not type-resolved reachability evidence.

The actual migrated PostgreSQL catalog contains 58 tables and 598 live columns. Every table appears in `docs/project/state-storage-lifecycle.md`; `catalog-coverage.json` has no unclassified table. SQL columns, constraints and indexes are in `postgres-catalog.json`. Rust declarations are not substituted for the catalog, JSON codecs or Lua state transitions.

## Corrections closed in the current source

| Finding | Final ownership and proof |
| --- | --- |
| Unread revocation UUID and its unique index | Existing tenant/JTI digest identity is the primary key. Existing reads, conflict handling and cleanup already use it. Tenant/client predicates, first revocation time and monotonic expiry remain. Migration round-trip preserves same-JTI records in two tenants and uniqueness; access-token retention tests check the real identity. |
| Write-only receipt/history timestamps | Administrator provisioning operation/tenant/user identity and all previously used recovery keys remain. Only unread creation/first-seen timestamps disappear. These histories are not given artificial TTLs. Round-trip tests preserve their facts and used-key uniqueness. |
| Excess audit health projection | Absent, active/retryable and blocked batch states are represented directly. Full persisted lease and retry information remains at the exporter claim boundary. Real PG regression traverses these states, rejects stale ACK and verifies successful completion. Required admission still rejects blocked state. |
| Unused local checkpoint timestamps | Local identity is sequence/hash. Durable snapshot must still contain both timestamps before the checkpoint is constructed. Tests remove each required snapshot component independently. |
| Unread mTLS expiry flag | Real certificate DER validity parsing and trust/key matching remain. Only the copied boolean with no policy consumer is removed. Existing future/expired certificate tests still run. |
| Earlier PR238 reclamation and model findings | Hourly expired remembered-device/approval reclamation, atomic backup-verifier deletion, TOTP metadata removal, single original refresh SID authority, composed refresh contract, reused DCR create command and consumed-offer payload clearing remain. Their earlier negative/positive evidence is retained; final workspace executes the resulting regressions again. |

The current shape delta has 13 entries, including removal of the 9-member `SecurityAuditBatchLease`, narrowing of the health SQL row from 21 to 13 fields, and checkpoint from 4 to 2. Added cleanup-result counters identify actual reclaimed categories; they are observations, not stored duplicate business state. Field counts alone are not a storage or safety metric.

## Cross-layer cases deliberately retained

- Raw registration and token forms must represent absence, invalid values and independent endpoint choices so they can be rejected or negotiated. They are not persisted as additional domain authorities. Create and patch have different absence/default semantics.
- Original refresh grant, current generation and signed access-token audience/binding are separate facts. A narrowed access token must not silently narrow the original refresh grant. Comparison at commit remains necessary.
- Consent presentation snapshots and redeemable code state serve different phases. Neither is copied wholesale into the durable single-use receipt. Both retain their original absolute deadlines.
- Serialized response fields, ASN.1 sequence fields, JWT-required deserialization fields and Lua-consumed generation/version fields can have no Rust `.field` reader and still be necessary. The low-reference pass explicitly checked these classes. Compact JWE carries five protocol parts; this is not an unused-field deletion opportunity. DCQL wallet-facing retention intent is not a new server retention timer.
- Account/profile and client SQL rows are adapter projections. Domain groupings and narrow hot-path queries already separate their consumers; splitting these into more queries solely to reduce declaration width would add work.
- Tenant-directory cache overwrites the fixed snapshot key and replaces its in-process validated projection; it does not retain a key for every revision. CIBA's due sorted set is an index whose orphan members are removed by the claim script; independently expiring payloads retain TTL and generation fences.
- Local request inputs, signing preparation, service handles and connection leases stay in memory. Shared one-use, revocation and acknowledged transaction facts cannot be replaced by process-local memory merely because their lifespan is short.
- Recovery allocation challenges bind allocation proof and completed idempotent results. Used-key history rejects A-to-B-to-A key reuse. These have consumers unlike expired random approval tokens; no speculative purge is introduced.
- Replay markers retain their receiving window and existing key namespace. Changing digest encoding while accepted markers or mixed versions remain live would make evidence invisible. There is no new dual namespace just to reduce bytes.

## Reclamation and storage acceptance

Expiration is enforced on use; a background worker does not change an object into an expired state. Physical reclamation removes eligible rows only after their distinct safety/ACK obligations. Ordinary long history, expired remembered devices and approvals use the hourly path; high-rate protocol receipts retain the existing 60-second bounded collector. A batch of 256 is a transaction limit, not a total quota: saturated categories continue within the existing catch-up budget, and unfinished work retries rather than waiting an hour.

Decision recovery is measured with a cohort declared before load. The final mixed run keeps generating requests after that cohort reaches its original business deadline, and observes the real application instance's subsequent maintenance cycle and cohort count. Late legal state is not required to vanish. See REPORT.md for the actual result, not this design description.

Physical footprint experiments preserve actual column order, dropped slots, defaults, constraints and indexes for 10,000 new rows. No manual vacuum or application-row deletion is used. Dropping a column does not immediately rewrite old heap tuples; live rows, eligible backlog, dead tuples, reusable physical high water and Valkey TTL state are separate quantities. Optional/Disabled audit under an indefinitely unavailable receiver remains subject to its existing unbounded retention semantics; this PR does not pretend otherwise.

No known actionable redundant fact or missing reclamation owner remains from this reviewed scope. This statement depends on the protocol, recovery contracts and supported upgrade path above. The measured workload results and any remaining execution failures are reported separately; declaration coverage is not a substitute for performance validation.

References: [RFC 8705](https://www.rfc-editor.org/rfc/rfc8705.html), [RFC 7516](https://www.rfc-editor.org/rfc/rfc7516.html), and the normative links in `docs/project/state-model-review.md`. These specify behavior and wire contracts, not a required database product.
