# SCIM 2.0 Provisioning

SCIM support provides tenant-bound enterprise user provisioning for the default deployment boundary. It is a product identity-platform feature, not part of OAuth/OIDC or FAPI normative conformance.

## Configuration

Set `SCIM_BEARER_TOKEN` to enable the endpoints. If it is empty or unset, SCIM endpoints return a SCIM `disabled` error.

The token is a deployment secret and is compared in constant time against the `Authorization: Bearer` header. Put SCIM behind HTTPS, keep proxy header stripping enabled, and rotate the token through normal deployment-secret management.

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

Provisioned users are created in the default tenant, realm, and organization. Future multi-tenant resolvers must select the tenant boundary before creating or updating users.

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
