# State storage ownership and expiry

Expiry is checked at use. Physical reclamation must not grant or revoke authority.

This guide describes persistent and transient state ownership. PostgreSQL and
Valkey are the default adapters; the optional native Kevy adapter follows the
same port contracts with the single-process lifecycle below.

## PostgreSQL ownership

A pooled connection used for an explicit transaction stays owned by
`DiscardOnDrop` until its outcome is confirmed. Cancellation drops the physical
connection so PostgreSQL can roll back and release locks without waiting for
another pool checkout. Helpers borrowing a connection share the caller's guard;
migration transactions own an unpooled connection. A single-statement write
uses PostgreSQL's implicit transaction, without an extra BEGIN/COMMIT pair.

After a transaction finishes, the connection's driver/transaction state decides
whether it can return to the pool. A business rejection after a successful
rollback reuses the connection; an open or broken transaction is discarded.

|责任|模型|保留原因 / 回收边界|源码|
|---|---|---|---|
|身份与组织的权威事实|`tenants`, `realms`, `organizations`, `users`, `external_identity_links`, `oauth_subject_bindings`, `user_client_grants`, `oauth_clients`, `client_access_requests`|长期 PG；按业务变更或所有者删除，不因 TTL 自动丢失。|`crates/persistence-postgres/src/repositories/authorization.rs`|
|长期凭据与管理授权|`user_totp_credentials`, `user_mfa_backup_codes`, `user_mfa_remembered_devices`, `user_passkey_credentials`, `scim_tokens`|PG；MFA 代际、防重放消费、凭据撤销及用户/租户关系。remembered expiry 在使用时校验，不能绕开凭据代际；过期记录由小时历史回收，不再依赖该用户再次登录。记录以 tenant/token digest 为身份，不另存无消费者 UUID/创建时间。|`crates/persistence-postgres/src/repositories/mfa.rs`|
|控制与恢复工作流|`controller_registry_slots`, `controller_identity_approvals`, `controller_recovery_roots`, `controller_recovery_root_key_history`, `controller_recovery_challenges`, `admin_provision_receipts`, `recovery_invalidations`|PG；审批消费与管理变更共同提交；审批原十分钟到期后按小时回收，独立 Required 审计不受影响。恢复挑战另有分配 nonce 防重放及已完成回执重试契约，不能按审批 TTL 一并删除。|`crates/persistence-postgres/src/repositories/recovery_root.rs`|
|租户、配置、密钥与运行时事实|`tenant_directory_control_operations`, `tenant_resource_states`, `tenant_resource_control_operations`, `tenant_resource_bindings`, `tenant_runtime_bindings`, `tenant_runtime_directory_state`, `tenant_signing_keysets`, `runtime_module_desired_states`, `runtime_module_instance_states`, `runtime_module_state_events`|PG；版本、控制操作回执与签名密钥跨重启保留。失活/过期判定不由清理触发。|`crates/persistence-postgres/src/repositories/runtime_modules.rs`|
|信任配置与凭据数据集|`openid4vc_trust_policies`, `openid4vc_trust_policy_clients`, `openid4vci_credential_datasets`, `openid4vci_credential_dataset_events`, `oauth_client_mtls_trust_anchor_events`, `oauth_client_mtls_trust_anchor_requests`|PG；配置/审批/事件是权威事实，依租户和版本约束。|`crates/persistence-postgres/src/repositories/openid4vc.rs`|
|有限保留的事务安全凭据|`oauth_refresh_contracts`, `oauth_refresh_families`, `oauth_refresh_spent_tokens`, `oauth_token_issuances`, `access_token_revocations`|PG 例外；保留窗口可能短，但与原子发行、刷新、撤销、重放处理同事务。不是长期业务档案，也不是可丢缓存。不得迁移消费标记单独跨库提交。|`crates/persistence-postgres/src/repositories/token_issuance.rs`|
|VCI offer 的单次消费|`openid4vci_offers`|30–600 秒的流程材料与消费事实；offer 消费和后续 grant 写入是两个提交，不是共同事务。当前保留 PG 的已确认消费，不直接迁移到可能恢复旧快照的 KV：grant 没有 offer 身份，旧值复活后没有另一条持久防线。消费时在原 UPDATE 内清空不再读取的 grants 密文和 TX-code verifier，保留原截止、消费事实及另一授权入口所需元数据。|`crates/persistence-postgres/src/repositories/openid4vc_issuance_store/offer.rs`|
|VCI 原子完成与可恢复签发|`openid4vci_nonces`, `openid4vci_access_grants`, `openid4vci_deferred_transactions`, `openid4vci_notifications`, `openid4vci_issuance_responses`|PG 有限保留工作流；nonce 最终消费与结果/通知创建确实共同提交，grant 所有权和撤销仍须校验。期限在读写时判断，子记录/所有权不能独立 TTL 删除。|`crates/persistence-postgres/src/repositories/openid4vc_issuance_store/`|
|VP 创建幂等与结果|`openid4vp_transactions`|PG 有限保留工作流；保存操作签名请求的幂等身份、原始加密密钥和已完成结果。状态须支持跨重启恢复。|`crates/persistence-postgres/src/repositories/openid4vc_presentation.rs`|
|安全审计与投递事实|`identity_security_events`, `scim_audit_events`, `scim_security_events`, `scim_security_event_receipts`, `backchannel_logout_deliveries`, `security_audit_events`, `security_audit_chain_entries`, `security_audit_chain_state`|PG；普通审计事件/链条目 ACK 后释放；decision 的审计载荷确认后压缩，消费凭据仍留到安全截止。SCIM 有独立保留/订阅回执，投递有重试/租约。checkpoint 不按业务 TTL 删除。|`crates/persistence-postgres/src/repositories/audit_ledger.rs`|
|适配器版本元数据|`__diesel_schema_migrations`|PG；schema 版本，不是业务模型。|`migrations/`|

## Valkey transient state

Valkey owns the following transient state and expires it independently of the SQL maintenance worker.

|模型|TTL/消费所有者|
|---|---|
|PAR、consent、authorization code、reauth nonce|`state-store-valkey/src/authorization.rs`；绝对业务期限与原始 TTL，原子版本比较/消费|
|Device、CIBA、ping delivery|`device.rs` / `ciba.rs`；原始期限与原子状态转换。due sorted set 是投递索引，不能给整个集合套一个会删除所有主体的 TTL|
|Session、Native SSO、client delivery|`session.rs` / `token_state.rs` / `delivery.rs`；原始期限、轮换/主体绑定|
|邮箱验证码及冷却、Passkey ceremony、OIDC/social federation state|`authentication.rs`；一次消费、发送所有权和 TTL|
|DPoP nonce/replay、JAR、JWT assertion、client attestation、CIBA request replay、HTTP/SAML signatures|`replay.rs`；原子 NX 与完整接收窗口。KV 也需要符合安全状态保留约束，不能视为任意可丢缓存|
|Avatar upload stages|`avatar_upload_state.rs`；绝对到期与 generation fence|
|Rate/login/MFA failure counters|`rate_limit.rs`；原子计数、固定窗口 TTL|
|Tenant-directory snapshot|`tenant_directory.rs`；PG 权威的可重建版本化投影，不是按 TTL 消费的授权事实|

## Optional embedded transient state

`nazo-kevy` keeps pending workflows, sessions, nonces, delivery stages and counters
in one in-process Kevy store. Native operations share one shard lock for compound
changes. Logical deadlines are preserved when mutable records are replaced;
physical expiry never extends a grant. Restart discards these records, so callers
must restart pending flows and log in again.

Externally supplied proof-consumption markers use a separate, exclusively locked
Kevy replay directory with synchronous AOF writes and no eviction. These markers
retain their original acceptance deadline across process restarts. They do not
include the configurable state epoch in their keys: changing that epoch cannot
make an already accepted signed proof fresh. Durable authorization decisions,
token issuance, refresh rotation, receipts and required audit keep their existing
persistence owner and transaction boundaries.

Only one process may serve a deployment using this adapter. Recovery after
directory loss, corruption or snapshot rollback requires the proof-window/trust
procedure in [embedded state operations](../operations/kevy.md).

## Models that must not become durable rows

HTTP inputs/outputs, validation results, normalized requests, request-local principal snapshots, prepared signatures, connection leases and runtime service handles stay in request/process memory unless a specifically documented business fact is committed. Derived names, counts and validity booleans must not become another mutable authority beside their original facts.

## Physical reclamation cadence

No worker writes an “expired” status to make a credential invalid. Every use must enforce its timestamp and security predicates even when the row still exists. The single maintenance worker selects `ProtocolState` on its normal 60-second interval and `IncludingHistory` initially and after an hour has elapsed since a completed history cycle. The latter additionally reclaims SCIM audit history only after its unchanged 180-day retention, expired MFA remembered devices, and expired controller identity approvals. Both retain the existing bounded batches, database cutoff, lock rules, cancellation behavior and catch-up budget. Failures or incomplete catch-up do not defer unfinished history for an hour.

High-rate protocol receipts use the 60-second cycle to limit expired resident rows. Required evidence is never discarded by a timer before acknowledgement. Optional/Disabled audit exports can accumulate retained records throughout a receiver outage.

TTL moves physical expiry into Valkey; it does not remove the logical live-state cost or make asynchronous replication durable. Local memory is appropriate for request values and reconstructible projections, not a replacement for shared one-use or revocation authority. At rate λ and necessary retention T, approximately λ×T records can be legitimate live state. Expired eligible backlog, retained live records, dead tuples waiting for vacuum and reusable physical high-water space must be measured separately.

## Compact retained state

The v0.3.2 baseline stores only current authority and retention fields. Existing
databases first complete v0.3.2, then adopt the baseline without rewriting rows.
Historical compaction SQL remains in that release's Git history.

Remembered devices use the tenant/token key and an expiry index for the global
sweep. They retain the token, owner, user-agent binding and deadline; unused
adapter UUIDs and creation/last-used metadata are absent. Upgraded tables may retain
reusable space from the old layout.

Expired identity approvals have an hourly reclamation path. Both unused and
consumed approvals remain through their original expiry. Reclaimed tokens return
unknown-token rejection; retained expired tokens return expired or replayed.
Independent Required events and signed checkpoints keep their own lifecycle.

256 is a per-category transaction batch limit, not an hourly quota. Saturated
batches continue inside the existing 30-second catch-up budget; locked rows
remain eligible for later passes. Monitor eligible backlog and oldest expiry age.

Backup-code consumption conditionally deletes the verifier in the same
transaction as its audit append. Absence rejects reuse and failed audit append
rolls back deletion. TOTP retains its protected secret, key identity, credential
generation, confirmation and replay step. Enrollment labels come from the
issuer/account rather than stored display metadata.

Administrator provisioning receipts and recovery used-key history retain their
operation/key identities without unused timestamps. Revocations use
`(tenant_id, access_token_jti_blake3)` as the primary key, with tenant/client
binding, first revocation time and monotonic retention through verifier skew.

## PostgreSQL index ownership

Primary keys identify durable facts. Unique indexes also enforce tenant-bound
references, one-use grants, request identity and active-resource ownership.
Their purpose remains even when ordinary queries do not scan them.

Client references use the unique `(id, tenant_id)` constraint. A second unique
index on the same pair in reverse order adds no constraint; the retained
`(tenant_id, id, client_id)` index serves its lookup prefix. The reverse-pair
index is removed without changing those references.

Lookup indexes follow the predicates of their repository and maintenance
queries. A composite B-tree also serves its leading columns; the schema does
not keep a separate single-column index for the same access path. PostgreSQL
explains these rules in [multicolumn indexes](https://www.postgresql.org/docs/18/indexes-multicolumn.html).

| Lookup or operation | Retained index |
| --- | --- |
| Token JTI revocation and tenant membership | `access_token_revocations_pkey` on `(tenant_id, access_token_jti_blake3)` |
| Access requests by status or requester | `ix_client_access_requests_status_created_at`, `ix_client_access_requests_user_created_at` |
| Clients within a tenant | `ux_oauth_clients_tenant_client_id` and tenant-bound reference indexes |
| Realms and organizations within a tenant | `ux_realms_tenant_slug_lower`, `ux_organizations_tenant_slug_lower` |
| Authorization grants by tenant, user and client | `uq_user_client_grants_tenant_user_client` |
| A user's authorized applications, newest first | `ix_user_client_grants_user_last_authorized` |
| Accounts by tenant, creation time and stable page key | `ix_users_tenant_created_at_id`, scanned in either direction |
| Desired module state; instance reconciliation | `runtime_module_desired_states_pkey`, `runtime_module_instance_states_pkey` |
| VCI nonce/deferred claim and dataset validity | Nonce primary key, deferred transaction hash, and `(tenant_id, subject_id, credential_configuration_id)` primary key; expiry is checked on that row |
| SCIM credential authentication and event subscriptions | `uq_scim_tokens_token_hash` and `scim_tokens_pkey` |
| TOTP enrollment and verification | `ux_user_totp_credentials_tenant_user`; key rotation uses `ix_totp_key_rewrap` |
| Module event history | `idx_runtime_module_state_events_occurred_at`; actor references retain `idx_runtime_module_state_events_actor_time` |
| Pending audit delivery, in order | `idx_security_audit_events_pending_order` |
| Authorization request/PAR replay fences | `idx_authorization_decision_request`, `idx_authorization_decision_par` |
| Acknowledged authorization receipts past retention | `idx_authorization_decision_reclaim` |
| Token receipts, refresh families/spent members, VCI/VP workflows and device/MFA approval expiry | Each table's deadline index, consumed by `security_state.rs` and its SQL cleanup functions |

Runtime desired/instance updates do not maintain timestamp or state-search
indexes: their reads use the same primary-key identities as their writes.
This permits [heap-only updates](https://www.postgresql.org/docs/18/storage-hot.html)
when an updated row fits on the same page and no indexed column changes.

Index scan counters alone do not establish redundancy. An empty partial index
can enforce uniqueness on the next insert; an audit delivery index can remain
idle until a receiver is configured. Check its predicate, constraints, foreign
key references and maintenance consumer before removing it. Measure live rows,
dead tuples and relation sizes separately: a relation can retain reusable pages
after rows are deleted, so its disk size is not a count of live credentials.

## Transient authorization wire changes

Authorization-code payloads are stored as opaque JSON bytes. Lua changes only
the surrounding state/CAS fields and never decodes and re-encodes application
claims, preserving JSON integers, decimals and nested arrays.

Session keys use `oauth:session:v2:` and require the login authorization epoch.
Upgrading from the unversioned session namespace requires a fresh login; old
records expire under their existing TTL and are never reinterpreted with a
fabricated epoch. PostgreSQL accepts authorization decisions only through the
epoch-bearing function; the older signature that read a new epoch from the
account is removed. Drain old server instances before applying this migration
and switching traffic. Pending
authorization transactions from the earlier code-payload format must expire or
restart during this rollout; do not run mixed writers against the same state.

Consent transactions have a ten-minute lifetime capped by the originating PAR
expiry. The authorization-code lifetime starts when the code is issued.

Each active controller dataset binding owns exactly one physical
`(tenant, subject, credential configuration)` dataset. A second logical resource
for that tuple is rejected atomically. The ownership-index migration rejects
existing aliases; reconcile the signed resource inventory before applying it.
Reapplying a revoked managed user restores its retained owned UUID, preserves
its revocation epoch and enrolled factors, and does not resurrect old grants.

Avatar selection carries a monotonic revision, including changes back to no
avatar. Upload authorizations retain that revision; CAS retries of the same
selected candidate are idempotent. A confirmed revision-fenced miss permits
candidate deletion, while unknown database outcomes retain the object. Successful
direct replacements delete the former final object before recording completion;
a cleanup failure remains retryable under the existing upload authorization.
This does not provide inventory-based garbage collection after abandoned uploads
or process loss. Object-store staging expiration remains provider-owned.

The avatar revision migration requires stopping older server binaries before
starting the updated version: older writers do not carry the revision fence.
In-flight authorizations without a revision must expire and be restarted; their
missing revision is never guessed from the current account.
