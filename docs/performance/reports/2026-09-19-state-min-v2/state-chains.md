# State-chain inventory (A6)

One line per durable/transient state chain: what creates it, what bounds it,
and which mechanism reclaims it. This is the living inventory the B-phase
report validates against; per-statement evidence is in `evidence/`.

Retention classes: **durable** (business/security fact, reclaimed by policy),
**evidence** (audit; exported then archived), **transient** (Valkey, TTL-bound).

## PostgreSQL

| Table | Created by | Bound | Reclaimed by |
| --- | --- | --- | --- |
| `security_audit_events` | `nazo_persist_security_audit_event` (transactional producers + queued sink) | online window 1 h after delivery | `nazo_archive_security_audit_prefix` → archive table (bounded, 256/call) |
| `security_audit_chain_entries` | exporter claim (`nazo_open_security_audit_batch`) | same window | same archival pass |
| `security_audit_event_outbox` | persist function | delivered+acked | ACK deletes member rows in the anchor transaction |
| `security_audit_chain_state` | singleton row | fixed 1 row + in-flight batch fields | never (control plane) |
| `security_audit_archive` | archival pass | operator retention policy (immutable evidence) | external lifecycle, not in-code |
| `security_audit_archive_state` | singleton watermark | fixed 1 row | never |
| `oauth_token_issuances` | committed token issuance (incl. auth-code single-use fence) | `retain_until` = access-token horizon or family grant deadline | `nazo_oauth_cleanup_expired_security_state` (≤256/batch) |
| `oauth_tokens` | refresh-family members | live while any member unexpired | terminal sparsify (payload tombstone, ≥60 s post-revocation) + whole-family bounded reclaim under family advisory lock |
| `access_token_revocations` | revocation events | `expires_at` = token expiry | generic cleanup (≤256/batch) |
| `scim_audit_events` | SCIM writes | 180 d | generic cleanup |
| `scim_security_events` | SET outbox | `expires_at` | generic cleanup |
| `scim_security_event_receipts` | SET receipts | parent row | FK cascade |
| `backchannel_logout_deliveries` | logout fan-out | `expires_at` | generic cleanup |
| `openid4vp_transactions` | VP requests | `expires_at` | `nazo_openid4vp_cleanup_expired_transactions` (≤256/batch) |
| `client_access_requests` | dynamic registration approvals | business state | admin action |
| `user_client_grants` | consent grants | business state | user/admin revoke |
| `identity_security_events` | auth telemetry | 90 d class retention | generic cleanup |
| `recovery_invalidations` | recovery events | append-only policy | operator policy |
| `tenant_resource_*`, `runtime_module_*` | control plane | desired-state model | superseded rows by design |
| `tenants`/`realms`/`organizations`/`users`/`oauth_clients`/credentials | admin provisioning | business state | admin lifecycle |

## Valkey (all keys TTL-bound; nothing is written without expiry)

| Prefix | Holds | Lifetime |
| --- | --- | --- |
| `oauth:auth_code:` | pending/consuming/failed authorization-code state | code TTL (~minutes); **deleted on durable issuance commit** — no consumed marker is retained (A3) |
| `oauth:session:` | login session | session TTL |
| `oauth:consent:` | consent request | request TTL |
| `oauth:par:` | pushed authorization request | request TTL (≤ minutes) |
| `oauth:ciba:*` | CIBA request state + ping queue | request TTL |
| `oauth:device:*` | device flow codes | code TTL |
| `oauth:dpop:jti:`, `oauth:client_assertion:jti:`, `oauth:jar:jti:`, `oauth:jwt_bearer:jti:`, `oauth:ciba:request_object:jti:`, `fapi_http_signature_replay:` | replay fences | assertion/proof validity window |
| `oauth:dpop:nonce:` | DPoP nonce | nonce TTL |
| `oauth:rate:`, `oauth:login_failure:`, `oauth:mfa_failure:` | throttle counters | window TTL |
| `oauth:federation:*:state`, `oauth:federation:saml:replay` | federation handoff state | handshake TTL |
| `oauth:authorization:reauth:` | re-auth nonce | nonce TTL |
| `oauth:email_verify:*` | verification codes/send throttles | code TTL |
| `oauth:passkey:{registration,authentication}:` | ceremonies | ceremony TTL |
| `oauth:client_delivery:` | client-side delivery token | delivery TTL |
| `oauth:native_sso:device_secret:` | native-SSO secret handle | secret TTL |
| `oauth:avatar:upload:` | pending avatar upload | upload TTL |

## In-process

| State | Bound |
| --- | --- |
| audit queue (`PERSISTENT_AUDIT_SINK`) | 4,096 entries; saturation logged `not_queued`/`dropped_required` |
| JWKS/metadata caches | TTL + bounded size |
| maintenance catch-up | ≤512 batches or ≤30 s per 60 s cycle |

## Explicitly bounded knobs

`CLEANUP_BATCH_LIMIT=256` per category · `FAMILY_LIMIT_PER_ROUND=256` ·
audit batch ≤256 events / ≤1 MiB envelope · online audit window 3600 s ·
lost-response window `LOST_REFRESH_TOKEN_RETRY_SECONDS=60`.
