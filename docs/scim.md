# SCIM 2.0 Provisioning

SCIM support is a default-tenant provisioning implementation with database-backed
SCIM credentials. It is a product identity-platform feature, not part of
OAuth/OIDC or FAPI normative conformance.

## Configuration

Preferred configuration is a row in `scim_tokens`:

- Store only `blake3` hex in `token_hash`.
- Bind the credential to a `tenant_id`.
- Set `scopes` to an array containing `scim:read`, `scim:write`, or `scim:*`.
- Use `expires_at` for planned rotation windows.
- Set `revoked_at` to retire a credential.
- Use `label` for operator-facing rotation notes; do not store the raw token.

`SCIM_BEARER_TOKEN` remains a compatibility fallback for self-hosted deployments. It is compared in constant time against the `Authorization: Bearer` header and is treated as a legacy full-access credential with `scim:read` and `scim:write`. Prefer database tokens for new deployments.

Security properties:

- Raw SCIM bearer tokens are not stored in the database.
- Multiple database tokens can be valid concurrently for rotation.
- Database tokens can expire or be revoked independently.
- Read endpoints require `scim:read` or `scim:*`.
- Create, replace, patch, and delete endpoints require `scim:write` or `scim:*`.
- Successful database-token use updates `last_used_at` and inserts `scim_audit_events`.
- Successful and denied SCIM token checks emit structured audit events without raw token material.

Remaining non-core extension:

- OAuth client-credentials or introspection-backed SCIM authorization.
- Per-tenant SCIM credential routing after dynamic tenant resolution exists. The schema stores `tenant_id`, but the current provisioning data path still uses the default tenant boundary.

## Endpoints

- `GET /scim/v2/ServiceProviderConfig`
- `GET /scim/v2/Schemas`
- `GET /scim/v2/ResourceTypes`
- `GET /scim/v2/Users`
- `POST /scim/v2/Users`
- `GET /scim/v2/Users/{user_id}`
- `PUT /scim/v2/Users/{user_id}`
- `PATCH /scim/v2/Users/{user_id}`
- `DELETE /scim/v2/Users/{user_id}`

`DELETE` is a soft delete: it sets `active=false` and keeps the user record for audit and token-revocation continuity.

## Identity Mapping

The current implementation maps SCIM `userName` to the local `users.email` login identifier. The primary email must match `userName`; create, replace, and patch requests that try to split these identities are rejected.

Provisioned users are created in the default tenant, realm, and organization. Future multi-tenant resolvers must select the tenant boundary before creating, listing, updating, or deleting users.

## Supported Operations

Listing supports pagination with `startIndex` and `count`, and supports only `userName eq "email@example.com"` filters.

PATCH supports `replace` for:

- `userName`
- `active`
- `name.formatted`
- `name.givenName`
- `name.familyName`
- `emails`

Bulk operations, sorting, password changes, groups, and SCIM enterprise-user extensions are intentionally not advertised.
