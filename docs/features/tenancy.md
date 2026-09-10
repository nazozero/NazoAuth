# Tenant, Realm, and Organization Boundaries

## Scope

The runtime is directory-managed and routes each request to an active tenant by
canonical request host. PostgreSQL is the authority for the complete tenant
directory. Each binding contains a tenant, realm, organization, canonical
external host, HTTPS issuer, and positive tenant runtime revision. A process
builds one complete immutable service graph for every active binding and
publishes the graphs together in a host index.

This is request-level tenant and issuer routing. It is not a path header, a
client-supplied tenant selector, or a fallback to the former system tenant.
Realm and organization remain placement and data-integrity boundaries; they are
not independently selected per request.

## Request Resolution

Before an application handler receives tenant-scoped data, the server:

1. canonicalizes the request Host;
2. in Direct TLS, requires the accepted SNI to equal that canonical Host;
3. loads one immutable `TenantHostIndex` snapshot;
4. resolves the Host to exactly one published tenant graph and injects only
   that graph's app data.

An unknown or invalid Host returns `404`; a Direct TLS SNI/Host mismatch returns
`421 Misdirected Request`. There is no `X-Tenant-ID` input, no database or
Valkey directory lookup on the request path, and no default-tenant fallback.
The resolved `TenantContext` also scopes request audit data.

A directory update first validates and builds every changed candidate graph.
Only then does the process atomically replace the host index; an invalid
candidate leaves the last good index in place. The refresher also retires
replaced lifecycle work after the new snapshot is visible. The directory cache
can accelerate convergence, but PostgreSQL remains authoritative and is read
on startup and during reconciliation.

## Per-Tenant Graph

Each graph validates the active tenant boundary, receives a tenant-bound
persistence view and Valkey namespace, loads that tenant's signing-key manager,
and derives its public issuer, UI URL, CORS default, and other issuer-dependent
settings from the directory binding. Tenant-local runtime-module state and
lifecycle work stay with the same graph.

The server-wide transport owner, database and Valkey connections, global policy
configuration, and static route shape are process resources. They never supply
a request tenant. A directory binding supplies the routing identity and issuer;
all non-routing policy still comes from the deployment configuration.

## Realm and Organization Placement

The default system binding uses these initial identifiers:

- Default tenant: `00000000-0000-0000-0000-000000000001`
- Default realm: `00000000-0000-0000-0000-000000000002`
- Default organization: `00000000-0000-0000-0000-000000000003`

Those identifiers seed the first directory binding. They do not make later
requests system-tenant requests. Every binding validates that its realm and
organization are active and belong to its tenant before its graph is published.

Realm and organization are not independent request authorization partitions in
this stage. Session, user, client, grant, and trust lookups enforce the resolved
tenant boundary; they do not treat realm or organization placement as a second
per-request authorization selector.

## Database and Token Invariants

The migration `20260607000400_tenant_realm_organization_boundaries` adds:

- `tenants`, `realms`, and `organizations` tables.
- `tenant_id`, `realm_id`, and `organization_id` columns on users and OAuth clients.
- `tenant_id` columns on refresh tokens, grants, access-token revocations, and client access requests.
- Tenant-scoped uniqueness for user email/username, `client_id`, refresh-token hashes, access-token revocation JTIs, and pending access requests.
- Composite foreign keys that reject cross-tenant links between users, clients, tokens, grants, revocations, realms, and organizations.

JWT access tokens include a private `tenant_id` claim. Resource endpoints and
token introspection use that claim to scope access-token revocation checks.
Malformed or mismatched tenant claims fail closed instead of falling back to the
system tenant.

FAPI HTTP-signature replay markers use the same validated access-token tenant.
The replay fingerprint is stored under that tenant namespace, so an identical
signature fingerprint in another tenant does not create a false replay, while a
second use in the same tenant is rejected. The storage adapter does not infer or
default this tenant.

## Tenant-Bound Services

OAuth client lookup by protocol identifier or internal identifier,
administrative pagination, registration-secret verification, and user-authorized
application listing all use the resolved tenant context. The persistence adapter
applies that tenant to every participating client and grant predicate; a missing
or incorrect tenant returns no client, secret material, or authorized
application.

Authorization and device-flow services use immutable tenant-bound repository
instances instead of accepting tenant input on every domain-port method. The
adapter supplies its owned tenant to the same explicit client queries and
rejects writes for any other tenant.

The local registration service supplies its validated tenant to every email
verification state operation. Verification codes, per-email send cooldowns, and
per-peer send cooldowns use independent tenant namespaces in Valkey. The same
normalized email or peer in another tenant therefore cannot load, consume,
release, or suppress state owned by the first tenant. Email and peer subjects
are stored as digests in key names rather than raw identifiers.

Federation account lookup, linking, provisioning, session creation, and state
consumption run through the same resolved tenant graph. The provider registry
is deployment configuration, but it never changes which tenant owns an external
identity or federation state.

## Operational Boundary

Every Valkey business key is scoped by deployment ID and UUIDv7 state epoch.
Startup rejects an unmarked nonempty logical database; it never claims or reads
unscoped state. A recovered deployment receives a new epoch and waits for the
signed token-invalidation deadline before public activation. Do not flush a
shared Valkey database as an install, update, rollback, or recovery shortcut.

Directory administration and the control-tenant-only control routes are
separate from request routing. A normal tenant administrator does not obtain
control-plane authority by selecting a host. See the [runtime directory
lifecycle](../project/multitenancy/runtime-directory-lifecycle.md) and [control
plane and admin boundary](../project/multitenancy/control-plane-and-admin.md)
for the signed mutation and convergence contract.
