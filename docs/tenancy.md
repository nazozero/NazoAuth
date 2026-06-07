# Tenant, Realm, and Organization Boundaries

The authorization server now has explicit tenant, realm, and organization boundaries. Existing deployments are migrated into a fixed default boundary so current OIDC and FAPI conformance clients keep their behavior while enterprise identity features get a real isolation model.

## Default Boundary

- Default tenant: `00000000-0000-0000-0000-000000000001`
- Default realm: `00000000-0000-0000-0000-000000000002`
- Default organization: `00000000-0000-0000-0000-000000000003`

Local registration, admin-created clients, access tokens, refresh tokens, grants, and revocation records are written into the default boundary unless a future tenant resolver explicitly selects another boundary.

## Database Invariants

The migration `20260607000400_tenant_realm_organization_boundaries` adds:

- `tenants`, `realms`, and `organizations` tables.
- `tenant_id`, `realm_id`, and `organization_id` columns on users and OAuth clients.
- `tenant_id` columns on refresh tokens, grants, access-token revocations, and client access requests.
- Tenant-scoped uniqueness for user email/username, `client_id`, refresh-token hashes, access-token revocation JTIs, and pending access requests.
- Composite foreign keys that reject cross-tenant links between users, clients, tokens, grants, revocations, realms, and organizations.

## Token Boundary

JWT access tokens include a private `tenant_id` claim. Resource endpoints and token introspection use that claim to scope access-token revocation checks. Malformed or mismatched tenant claims fail closed instead of falling back to the default tenant.

## Product Boundaries

The current runtime remains single-tenant by default. External OIDC/SAML federation and SCIM provisioning must bind inbound identities, groups, and client metadata to an explicit tenant, realm, and organization before creating users, sessions, grants, or clients.
