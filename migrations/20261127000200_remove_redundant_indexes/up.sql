-- Retain all primary keys, uniqueness constraints, replay fences and reclamation paths.

-- Existing B-tree leading keys serve these lookups.
DROP INDEX public.ix_access_token_revocations_tenant_id;
DROP INDEX public.ix_client_access_requests_status;
DROP INDEX public.ix_client_access_requests_user_id;
DROP INDEX public.ix_oauth_clients_tenant_id;
DROP INDEX public.ix_organizations_tenant_id;
DROP INDEX public.ix_realms_tenant_id;
DROP INDEX public.ix_user_client_grants_tenant_id;
DROP INDEX public.ix_user_client_grants_user_id;
DROP INDEX public.ix_users_tenant_id;

-- Account pagination is tenant-scoped and uses (tenant_id, created_at, id).
DROP INDEX public.ix_users_created_at_desc;

-- Module reads use tenant/module or tenant/instance/module identities; event pages use tenant/time.
DROP INDEX public.idx_runtime_module_desired_states_updated_at;
DROP INDEX public.idx_runtime_module_instance_states_module_state;
DROP INDEX public.idx_runtime_module_instance_states_updated_at;
DROP INDEX public.idx_runtime_module_state_events_module_time;

-- These operations locate one row by its primary/unique key; no expiry sweep uses the auxiliary predicates.
DROP INDEX public.ix_openid4vci_credential_datasets_validity;
DROP INDEX public.ix_openid4vci_deferred_claim_expiry;
DROP INDEX public.ix_openid4vci_nonce_claim_expiry;
DROP INDEX public.ix_scim_tokens_expires_at;
DROP INDEX public.ix_scim_tokens_tenant_active;
DROP INDEX public.ix_user_totp_credentials_user;

-- The (id, tenant_id) unique constraint supports the tenant-bound references.
-- The retained (tenant_id, id, client_id) index also serves this lookup prefix.
DROP INDEX public.uq_oauth_clients_tenant_internal_id;
