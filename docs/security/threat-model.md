# Threat Model

## Scope and invariants

This model covers the authorization server, tenant runtime, operator protocol,
and their persistence and transport boundaries. PostgreSQL and Valkey are the
current adapters; domain and persistence ports define ownership independently
of those products. The controller has its own repository and release boundary.

The central invariants are tenant-bound authority, client-bound credentials,
atomic acceptance of security state, verified release and operation identity,
and an explicit distinction between local evidence and external observation.
Update this model when one of those invariants or its implementation changes.

## Assets

- Authorization codes, PAR handles, request objects, client assertions, DPoP
  proofs and nonces, access/refresh/ID tokens, and encrypted issuance responses.
- User credentials, password hashes, MFA and passkey material, browser sessions,
  consent, federation links, and tenant-scoped SCIM and OpenID4VC records.
- Tenant signing and mdoc authority keysets, their independent wrapping roots,
  external signer credentials, public keys, and discovery metadata.
- Durable security state, transient replay/session/rate state, state epochs,
  database backups, and recovery metadata.
- Signed Release manifests, exact artifact digests, registered Controller keys,
  Recovery Roots and offline Recovery Secrets, and instance TLS identities.
- Signed ControlOperation requests, application journals, typed outcomes,
  local audit events, outbox entries, and externally retained checkpoints.

## Trust boundaries

| Boundary | Required control and residual boundary |
| --- | --- |
| Browser or OAuth client to server | HTTPS issuer, exact redirect validation, client authentication, PKCE, CSRF/session protections, and profile-specific request validation. A registered client remains untrusted input. |
| Request to tenant runtime | Canonical authority selects an immutable tenant context before tenant data access; unknown authorities fail closed. Direct TLS binds SNI and request authority. Directory revisions replace validated runtime state; failed reloads retain the last valid snapshot, without falling back to a different tenant. |
| Reverse proxy to server | Only configured trusted proxy CIDRs can supply forwarding or mTLS facts. The proxy strips incoming copies and protects its connection to the server. Direct TLS obtains certificate facts from the verified TLS session. |
| Server to remote metadata, JWKS, or federation peer | HTTPS and URI/DNS address policy, validated redirects, bounded concurrency, response size, and end-to-end deadlines. Cached data and unknown-key refreshes cannot bypass trust validation. |
| Server to durable and transient stores | Application ports enforce ownership; deployment credentials, tenant predicates, atomic repository operations, least privilege, network isolation, and supported restore procedures enforce the adapter boundary. Store owners can exceed application-role restrictions. |
| Encrypted keysets to wrapping roots | Tenant-bound authenticated encryption protects persisted keysets. Wrapping roots are backed up and held separately from the database. Missing roots fail closed; generating a replacement root does not recover old keys. External signer results are checked against the expected public key. |
| AS to resource server | Exact issuer/audience, algorithm/key and sender-binding validation, with revocation or introspection according to the resource policy. Successful signature verification alone is insufficient authorization. |
| Release producer to deployment | Verified workflow identity, signed manifest, exact binary/OCI digest, accepted release state, anti-downgrade policy, and operator-protocol/schema checks. Mutable image names are not artifact identity. |
| Controller to runtime task | Signed closed ControlOperation claims bind deployment, target, operation ID, and request hash. First admission requires an active valid Controller key; the durable journal owns retries of an already accepted exact request. Key retirement does not erase that accepted operation. |
| Controller to host or container engine | Typed lifecycle operations, verified artifacts, bounded mounts/network and secret delivery, protected host configuration, and restricted task execution. Host root, kernel, and a compromised engine remain privileged over the task. |
| Recovery Secret to Controller Registry | Explicit challenge, derived proof, bounded attempts, and atomic replacement of the Controller slot with Recovery Root rotation. This does not rotate independent database, wrapping-root, or TLS credentials. |
| Security event to ledger and external receiver | Queueing, required append, transactional append, and external delivery have different durability guarantees. Writer/exporter role separation and an independently retained receiver checkpoint are required for external evidence; see [Security Events](security-events.md) and [audit anchoring](audit-anchor.md). |

## Threats and controls

| Threat | Current control | Limit or operational responsibility |
| --- | --- | --- |
| Authorization code theft and replay | Client/redirect binding, PKCE S256, short pending-code lifetime, atomic transient-state transitions, and durable issuance identity with consumed-code revocation. | Consumed-code evidence lasts for the issued access-token or initial refresh-token lifetime, not every future extension of a refresh family. |
| Principal disabled or changed during issuance | The durable issuance transaction locks and checks the relevant principal before commit. | A preceding HTTP or cache check does not replace that transaction boundary. |
| Lost token response or refresh reuse | Encrypted durable issuance response, exact issuance identity, token-family state, and reuse handling. | Follow the selected profile's rotation policy and [refresh-token contract](../protocol/refresh-token-rotation.md); FAPI2 does not imply routine rotation. |
| Redirect mix-up or signed-request replay | Exact redirect and issuer validation, signed request validation, and replay checks for supported request-object and assertion claims. | Required claims depend on the selected profile; do not infer a universal mandatory JAR `jti` policy. |
| DPoP or mTLS bypass | Method/URI/token binding, nonce and replay state, key thumbprint, and trusted transport certificate evidence. | Cached certificate facts are request-scoped and created only after trust checks. Resource servers must enforce sender constraints too. |
| Cross-tenant data, keys, or audit attribution | Immutable request tenant, tenant-scoped repositories and keysets, signed management bindings, and tenant capture before audit queueing. | Database ownership and arbitrary host code execution are outside row-level application isolation. |
| CSRF, session theft, or identity-link confusion | CSRF validation, secure HTTPOnly session cookies, consent and explicit identity-link policy, and MFA/passkey verification. | Browser and relying-party policy remain part of the deployment's security boundary. |
| Password or remote-I/O resource exhaustion | Password-hash permits live through blocking work; remote DNS/HTTP work uses bounded admission, deadlines and body limits. Unknown-key refreshes are coalesced and failure results cached. | Capacity and timeout settings need deployment measurements; bounded work is not a throughput guarantee. |
| Signing or mdoc key compromise | Encrypted shared keyset state, validated lifecycle transitions, tenant binding, expected-public-key verification, and coordinated runtime refresh. | Rotation needs the matching wrapping roots and, for external signers, provider-specific recovery and hardware evidence. |
| Durable or replay-store outage | Sensitive paths propagate dependency failures instead of weakening security checks. | Availability depends on dependency topology and restore discipline; see [HA operations](../operations/ha-operations.md). |
| Inconsistent database/transient-state restore | A new state epoch, refresh invalidation, and ingress lifetime/deadline controls form the supported recovery procedure. | Restoring an old pending-code snapshot beside newer issuance records under the same epoch is not a supported recovery mode. |
| Operator replay, response loss, or key retirement | Exact operation-ID/request-hash journal and durable typed result recovery. | An uncertain executing operation cannot be blindly rerun; only its owning operation's idempotent recovery can resolve it. New requests signed by a retired key are rejected. |
| Secret leakage through orchestration or audit | Secret files/FD/stdin/provider inputs, explicit field schemas, sanitized child errors, and no raw bearer material in audit payloads. | Audit redaction removes a small set of top-level names only. Producers must not supply nested or renamed credentials. |
| Audit loss or privileged rewriting | Required/transactional appends where owned, durable export outbox, ordered hash chain, retry fencing, and optional required-mode freshness checks. | In-process queued events can be lost. A chain held only by the local operator is not immutable; a 2xx delivery is not a signed receiver receipt or proof of WORM retention. |
| Target substitution or unsafe rollback | Measured artifact identity and signed operation target; recorded migration and recovery boundaries fence artifact rollback. | Database recovery needs an independently verified snapshot. Current pre-0.5 formats reject unsupported historical state rather than converting it implicitly. |
| Metadata overclaim | Runtime-generated capabilities and explicit profile/standards matrices. | Tests, external suite results, and formal certification are separate evidence levels. |

## Deployment and residual risk

Managed production uses `nazoauthctl` and the fixed `nazoauth operator-task`
entry point for mutations. The runtime database role has no DDL or temporary
table privilege. Source-tree Compose is a development sandbox with an ephemeral
operator identity. External dependency owners retain backup/PITR and network
policy responsibility.

Controller signing keys, Recovery Secrets, wrapping roots, TLS identities, and
exporter credentials are separate authorities. Losing one is not repaired by
rotating another. Root/engine compromise can read mounted secrets and alter
local state; compromise of both the writer host and the independent receiver
also defeats that external evidence boundary. The implemented exporter requires
a real configured receiver and verified retention policy. Local root is an
actor category, not proof of a natural person's identity or online approval.

## Review triggers

Review this model when profiles or discovery claims change; tenant routing,
key custody, signing algorithms, token formats, replay/rotation behavior,
proxy/TLS topology, remote network access, operator admission, persistence,
audit delivery, release/recovery formats, or deployment ownership changes;
or an incident, security report, or conformance failure reveals a missing case.
