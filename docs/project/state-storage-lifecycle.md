# State storage ownership and expiry

Expiry is checked at use. Physical reclamation must not grant or revoke authority.

This inventory classifies all 58 tables in the merged-source catalog and the active Valkey families. A retention deadline alone does not decide storage: atomic mutation and evidence ownership do. It does not authorize shortening retention or losing replay evidence.

## PostgreSQL ownership

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
|VP 创建幂等与结果|`openid4vp_transactions`|PG 有限保留工作流；保存操作签名请求的幂等身份、原始加密密钥和已完成结果。不是普通浏览器准备缓存；本轮保留既有跨重启可恢复契约，没有以 TTL 为由改成可能丢失的状态。|`crates/persistence-postgres/src/repositories/openid4vc_presentation.rs`|
|安全审计与投递事实|`identity_security_events`, `scim_audit_events`, `scim_security_events`, `scim_security_event_receipts`, `backchannel_logout_deliveries`, `security_audit_events`, `security_audit_chain_entries`, `security_audit_chain_state`|PG；普通审计事件/链条目 ACK 后释放；decision 的审计载荷确认后压缩，消费凭据仍留到安全截止。SCIM 有独立保留/订阅回执，投递有重试/租约。checkpoint 不按业务 TTL 删除。|`crates/persistence-postgres/src/repositories/audit_ledger.rs`|
|适配器版本元数据|`__diesel_schema_migrations`|PG；schema 版本，不是业务模型。|`migrations/`|

## Valkey transient state

These existing models remain Valkey-owned; no PostgreSQL copy or replacement namespace is introduced. TTL expiry is independent of the SQL maintenance worker.

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

## Models that must not become durable rows

HTTP inputs/outputs, validation results, normalized requests, request-local principal snapshots, prepared signatures, connection leases and runtime service handles stay in request/process memory unless a specifically documented business fact is committed. Derived names, counts and validity booleans must not become another mutable authority beside their original facts.

## Validation boundary

Model placement is not changed merely to satisfy a storage label. The existing independently expiring request state is already in Valkey. PG short-window security receipts are explicitly separated from long-lived business facts; their physical reclamation policy must be reported separately, including retention cost. No new cache authority, cross-store transaction or recovery queue is introduced.

## Physical reclamation cadence

No worker writes an “expired” status to make a credential invalid. Every use must enforce its timestamp and security predicates even when the row still exists. The single maintenance worker selects `ProtocolState` on its normal 60-second interval and `IncludingHistory` initially and after an hour has elapsed since a completed history cycle. The latter additionally reclaims SCIM audit history only after its unchanged 180-day retention, expired MFA remembered devices, and expired controller identity approvals. Both retain the existing bounded batches, database cutoff, lock rules, cancellation behavior and catch-up budget. Failures or incomplete catch-up do not defer unfinished history for an hour.

The earlier 10-second interval experiment is not used. Conversely, a one-hour interval is not applied to high-rate protocol receipts: it would increase their expired resident population without shortening any safety obligation. Required evidence is never discarded by a timer before acknowledgement. Optional/Disabled audit exports are not promised bounded disk use during an indefinite receiver outage.

TTL moves physical expiry into Valkey; it does not remove the logical live-state cost or make asynchronous replication durable. Local memory is appropriate for request values and reconstructible projections, not a replacement for shared one-use or revocation authority. At rate λ and necessary retention T, approximately λ×T records can be legitimate live state. Expired eligible backlog, retained live records, dead tuples waiting for vacuum and reusable physical high-water space must be measured separately.


## Compact retention migration

`20261010000100_compact_remembered_device_retention` removes only the unused
remembered-device UUID and creation timestamp, promotes the existing tenant/token
unique key, and adds an expiry index for the global sweep. The number of indexes
is not reduced: the unused UUID index is replaced by the useful expiry index.
Existing heap tuples are not rewritten merely by dropping columns; no immediate
filesystem shrink is promised. The reverse migration regenerates only unused adapter UUID/timestamp metadata;
it preserves the original token, owner, user-agent binding and deadline without
requiring deletion of usable credentials. Regenerated metadata is not represented
as the original history.
Apply the schema and matching application together.

`20261010000200_reclaim_expired_identity_approvals` gives expired approval bodies
an hourly reclamation path. Both unused and consumed approvals remain through their
original expiry. A reclaimed token returns the existing unknown-token rejection;
before reclamation it may return expired or replayed. Neither path authorizes a
mutation. This is not a new audit-retention policy: independent Required events and
signed checkpoints retain their original lifecycle.

256 is a per-category transaction batch limit, not an hourly quota. Saturated
batches continue inside the existing 30-second catch-up budget; unfinished history
is retried after elapsed work time rather than waiting a fresh hour. Locked rows
are skipped and remain eligible for later passes. These limits do not by themselves
prove the collector keeps pace at every workload.


`20261010000300_compact_mfa_credentials` removes already-used backup verifiers
and their unused creation/consumption columns. New consumption is a conditional
DELETE in the existing transaction with its audit append; an absent candidate
rejects reuse, and failed audit append rolls the deletion back. Live candidate
IDs and tenant/user ownership are unchanged. This needs no cleanup queue or TTL.
TOTP's unread persisted label and generic creation/update timestamps are removed;
the enrollment response still renders its label directly from issuer/account.
Protected secret, key identity, credential generation, confirmation and replay
step remain. Rollback reconstructs only unused metadata and never resurrects
consumed backup verifiers.


`20261010000400_compact_control_receipt_metadata` removes the unread creation
time from administrator provisioning receipts and unread first-seen time from
recovery used-key history. Neither timestamp participates in validity, retention,
ordering, a wire response, a foreign key or replay rejection. The operation and
used-key identities retain their original lifetime. Downgrade recreates only
unused timestamp metadata, not its original historical values. No data row is
removed. Apply the schema with the matching adapter; existing heap tuples may
retain dropped-column space until normal row replacement.


Revocation rows use their existing `(tenant_id, access_token_jti_blake3)`
authority key as the primary key. The unread independent UUID and its index are
removed by `20261010000500_compact_revocation_identity`; no foreign key points
to that UUID. Lookup, conflict handling and bounded cleanup already use the
composite identity. Tenant/client binding, first revocation time and monotonic
retention through the original verifier skew remain unchanged. Upgrade/down/up
tests preserve these facts for the same JTI in different tenants; downgrade
regenerates only unused adapter UUIDs. This removes one index write per newly
revoked token without changing the transaction or acknowledgement boundary.
