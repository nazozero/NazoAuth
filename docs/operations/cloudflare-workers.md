# Cloudflare Workers

The Workers host runs the production `nazoauth` facade and its portable domain
and application crates. `nazo-http-worker` converts transport values;
`nazo-oauth-server-d1` implements the existing persistence and transient-state
ports. `nazo-server-worker` owns bindings, configuration, key refresh and the
prepared application graph. Protocol parsing, grants, DPoP validation,
redirects and response policy stay in the shared implementation.

## Deployment profile

Each deployment serves one issuer and one tenant through one primary D1 binding.
There are two Workers Free profiles. The checked-in template starts
`machine_only: true` for confidential Client Credentials clients. Set
`machine_only: false` and `passkey_only: true` in the **private bootstrap input**
to enable interactive WebAuthn (Passkey) login without in-request password hashing.
The offline provisioner creates one initial user with an unknown random password,
and hands the operator a single-use, 24-hour setup ticket; the ticket grants a
five-minute registration session on the issuer's HTTPS origin. The full-password
profile (`machine_only: false`, `passkey_only: false`) requires Workers Paid
for Argon2id's CPU budget. In Passkey-only mode, set `frontend_base_url` to
the issuer origin to use the built-in login and consent pages at `/auth`
and `/consent`. When Device Authorization is selected, `/device` serves the
same-origin approval page and returns through Passkey login when needed.
The password profile requires a separately hosted frontend.

| Capability | Workers profile |
| --- | --- |
| Discovery and JWKS | Shared metadata and key lifecycle |
| Authorization | Authorization code with PKCE and interactive consent |
| Tokens | Code redemption, refresh, Client Credentials, revocation and UserInfo |
| Client authentication and sender constraints | Client secret, `private_key_jwt`, DPoP proof, nonce and replay state |
| Identity | Machine-only, password-enabled full profile, or Passkey-only with offline initial setup; passkey credentials, single-use challenges, sessions and logout share existing services |
| Account profile | Current account, authorized-client count and validated profile updates; identity and authorization epochs are preserved |
| Optional modules | Explicit deployment selection; see the module matrix below |
| Keys | Encrypted persistent key generations; `nazo-crypto` uses Worker WebCrypto for signing and verification |
| Audit | Required evidence commits with the accepting mutation; append-only D1 audit rows |

Configuration rejects unavailable modules and unknown native fields. Persisted
module selection must match the deployment. Discovery uses that selected
snapshot. Unavailable storage/network operations return explicit failures.
Client provisioning rejects unsupported grants, remote documents, mTLS and
backchannel logout. Front-channel logout uses registered RP endpoints and does
not require an outbound delivery worker. Cloudflare Workflows are not required.

### Optional module matrix

These are all 16 shared runtime modules. An available module still needs explicit
selection in `NAZO_CONFIG.modules` and the corresponding client grants, scopes
and security policy. Availability describes the adapter boundary; public edge
acceptance and protocol conformance remain separate verification activities.

| Module | Workers binding and conditions |
| --- | --- |
| `device_authorization` | D1 device/user-code mappings, compare-and-set polling state, durable user decision and single-use redemption. Clients must allow `urn:ietf:params:oauth:grant-type:device_code` and set `security_policy.allow_cross_device_flows: true`. |
| `token_exchange` | Shared local-token exchange with D1 token state, scope/target checks and revocation. Clients must allow the token-exchange grant. External issuer trust and delegated remote tokens are not implicitly enabled. |
| `jwt_bearer_grant` | Shared JWT bearer grant with client subject binding and atomic assertion replay state. Clients register inline verification keys and the JWT bearer grant. |
| `ciba` | Unavailable: D1 account lookup, CIBA state/decision contracts and ping delivery are not implemented. A verification UI and delivery configuration are also needed. |
| `dynamic_client_registration` | Shared RFC 7591/7592 registration with D1 management-token authority, atomic required audit, credential rotation, compare-and-set updates and deactivation. Requires the separate `NAZO_DCR_INITIAL_ACCESS_TOKEN` secret. Deployment capability policy rejects unsupported metadata before resolution or persistence. |
| `request_objects` | Inline signed Request Objects and PAR use shared validation and D1 one-use state. Remote `request_uri`, `jwks_uri` and sector documents are not bound. |
| `jarm` | Shared signed authorization responses use persisted issuer keys. The client selects a supported response algorithm. |
| `authorization_details` | Shared RAR parsing, consent, access-token and refresh handling; D1 persists the accepted details with the grant. |
| `http_message_signatures` | Shared request verification, response signing and replay state for the signed resource endpoint. Client verification keys must be available inline. |
| `scim` | Unavailable: SCIM repository and credential ports lack D1 implementations. |
| `scim_security_events` | Unavailable: requires SCIM plus durable event-store and bounded remote polling adapters. |
| `native_sso` | Shared device-secret exchange and D1 source refresh-family checks. Requires `token_exchange`, allowed `device_sso` scope, the issuer audience and the code/refresh/exchange grants on participating clients. Revoking the source family prevents later exchange. |
| `frontchannel_logout` | Registered RP iframe URLs and session identifiers are generated by the shared logout flow. Delivery is performed by the browser. Back-channel delivery remains unavailable. |
| `session_management` | Shared session state, check-session iframe/status and RP-initiated logout; participating clients enable `security_policy.session_management`. |
| `openid4vci_issuer` | Unavailable: offer, dataset, subject, nonce, credential, deferred-response and trust-policy persistence contracts need D1 adapters and issuer policy. |
| `openid4vp_verifier` | Unavailable: presentation state, trust-policy and credential-status resolution need adapters and verifier policy. |

The machine-only profile permits `token_exchange`, `jwt_bearer_grant`,
`http_message_signatures` and `dynamic_client_registration`; its registration
policy permits service grants only. The interactive profiles permit the available
browser modules as well. Selecting a module never grants a client permission
to use it. Configuration and registration enforce both boundaries.

When selecting dynamic registration, supply `NAZO_DCR_INITIAL_ACCESS_TOKEN`
as a secret of at least 32 bytes before deploying that module selection.
Keep it separate from the client-secret pepper and signing wrapping key.
The graph refuses to start with the module enabled and a missing/short token.
The default bootstrap input does not enable this module or generate this secret;
configure it through the deployment's existing secret management when needed.
Registered clients receive their own management token. A successful configuration
replacement rotates that token and any client secret; stale management tokens
cannot update or delete the client. Client-owned updates cannot increase
administrator-limited scopes or change administrator-owned audiences/policy.

### Remaining host and service boundaries

| Area | Current boundary and work required |
| --- | --- |
| mTLS | The HTTP adapter does not supply verified client certificates. Supporting Cloudflare-terminated mTLS requires trusted platform certificate facts, certificate/trust adapters and hostname policy. Forwarded headers cannot supply this authority. This is an ingress integration gap, not a general prohibition on Workers cryptography. |
| Remote documents and federation | The Worker does not bind outbound document or federation clients, federation-link storage or federation replay state. A bounded HTTP adapter must retain shared URL, redirect, size, expiry and SSRF policy; enabling arbitrary `fetch` would not satisfy the contracts. |
| Email registration and verification | Registration accounts, code reservation/consumption and email delivery are unbound. An email service binding alone does not provide the missing atomic identity operations. |
| MFA | TOTP enrollment/consumption, backup codes, remembered devices and their required audit mutations need D1 adapters. Password-based backup-code hashing also needs an appropriate CPU budget. |
| Authorized-application list | `/auth/me` counts persisted grants. The detailed application list is unavailable because D1 does not retain the native authorization-history fields needed for exact counts and last-authorization data. A list must not fabricate them from current grants. |
| Avatars and object storage | Avatar revision/claim state and the object-storage port are unbound. An R2 adapter is feasible, provided object publication and database selection retain the existing lifecycle. |
| Administration and recovery | Native administration, controller registry, recovery roots, role management and native audit anchors are unbound. The server must not absorb the separate controller's recovery authority. |
| Native process signers and files | Worker isolates cannot run the native host's subprocess/OS integration. Provisioning stays in a native offline tool; request signing uses the shared `nazo-crypto` Worker backend. Persistent files require an explicit storage adapter. |
| Password authentication | Argon2id remains the shared password verifier. The Free profile disables password routes to avoid its CPU cost; the password-enabled profile requires a suitable Paid CPU budget and separate frontend. |

Missing D1/service adapters above are implementation work, not evidence that
the protocol cannot run on Workers. Durable state must continue to satisfy the
same tenant isolation, atomic consume, replay, audit and recovery contracts.

## Storage semantics

Authorization decisions atomically commit the single-use fence, grant change and
required audit record. Token issuance checks current principal epochs and commits
redemption fences, subject binding, refresh changes and required audit together.
Session replacement and rotation span old and new identifiers.

Prepared, parameterized statements execute through
[`D1Database.batch`](https://developers.cloudflare.com/d1/worker-api/d1-database/).
Each batch is a transaction: failure rolls back the whole batch. Conditional SQL
accepts the state change at the primary. Reads use the primary binding, without
opening replicated Sessions for authorization state.

Workers KV's eventual consistency does not satisfy these contracts. Separating
sessions into Durable Objects by session ID splits the transaction that replaces
one session with another. A global Durable Object would add another serial
authority without removing the relational transaction.

SQL checks expiry against the database clock. Expired rows are never accepted
while awaiting physical cleanup. The scheduled host operation deletes bounded
indexed batches outside request handling. Durable fences retain their
contract-specific retention deadlines. No isolate cache owns sessions,
authorization codes, revocations or replay decisions.

The full profile's minute cron starts up to 64 cleanup passes of 1,000 rows
each, stopping after 20 seconds or a short pass. The Workers Free machine-only
and Passkey-only profiles make a single pass of at most 500 rows; cleanup does not run a
multi-pass loop against Free's 10 ms Cron CPU budget. The limit bounds each
transaction and scheduled invocation; deployed CPU and backlog measurements
determine whether cleanup keeps up with the actual traffic.

## Build

The repository pins Rust 1.100.0. Worker bindings and `worker-build` use 0.9.0.
The npm lockfile pins Wrangler, Miniflare and workerd.

Worker 0.9.0 unconditionally depends on `chrono`, which has the informational
[RUSTSEC-2026-0543 maintenance advisory](https://rustsec.org/advisories/RUSTSEC-2026-0543.html)
and no patched release. The dependency policy permits only `worker@0.9.0` to
introduce that advisory until **2026-12-19**. Replacing the SDK's date dependency
removes this exception; other introducers or an expired deadline fail the gate.

```sh
rustup target add wasm32-unknown-unknown
cargo install worker-build --version 0.9.0 --locked
npm ci --prefix deploy/cloudflare
python3 scripts/check_worker_portability.py
npm run bundle --prefix deploy/cloudflare
```

The bundle command runs `worker-build --release --locked` and Wrangler's dry run.
It does not publish a Worker. The module graph is under
`crates/server-worker/build`; Wrangler's bundle is under
`deploy/cloudflare/bundled`.

The WASM production graph excludes Actix, native HTTP servers, PostgreSQL/Valkey
drivers, native TLS and native Tokio execution features. The SDK's Tokio library
dependency does not enable a runtime. `local-sqlite` enables the same adapter SQL
for native offline provisioning and contract tests; its driver is selected only
on non-WASM targets.

## Deploy to Cloudflare button

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/nazozero/NazoAuth)

Use the repository **root**. Cloudflare's button cannot clone only `deploy/cloudflare`:
the Rust workspace and its dependencies live outside that directory.

The button creates a Git copy, provisions the `NAZO_DB` D1 binding, deploys
the private Worker and runs its SQL migrations. The D1 ID is intentionally
omitted: Wrangler can resolve the provisioned database by binding name. The application is intentionally
**not reachable** yet (`workers_dev = false`, no public route). Never expose an
unprovisioned identity server or install a public bootstrap endpoint.

Cloudflare [removed the gzip size cap in September 2026](https://developers.cloudflare.com/changelog/post/2026-09-04-increased-worker-size-limit/):
Free and Paid now accept up to 64 MiB uncompressed. Use the current dry-run
artifact size when checking that limit. **Workers Free** has 100,000 requests/day, 10 ms CPU per HTTP request
and 10 ms per Cron invocation; D1 has separate daily row-read/write quotas.

The deployment template starts in `machine_only: true` (service clients with
Client Credentials, token management, OAuth metadata and JWKS). During offline
initialization choose `passkey_only: true` and `machine_only: false` for a
**passwordless, interactive** OAuth/OIDC deployment with Passkey login and
Authorization Code/PKCE. Browser password login is then explicitly blocked.
Password-enabled `passkey_only: false` requires **Workers Paid**. All Free
profiles still require **real edge CPU measurements** before production SLO
acceptance. The template cannot be called a complete single-click installation
because issuer domain, first credentials, secrets and ingress policy must be set.
Cloudflare Workers Builds has a 20-minute timeout and does not preinstall Rust:
the repository-root `build` script installs Rust 1.100.0, `worker-build`
0.9.0 and `wasm-bindgen-cli` 0.2.130. Confirm build completion in the Cloudflare dashboard.

To initialize a fresh D1 deployment, clone the repository associated with the
button, install local dependencies (Rust 1.100, Node, curl, Python 3, Wrangler),
and create a private JSON input **outside the Git repository** from
`deploy/cloudflare/bootstrap.example.json`. Set the issuer to the intended HTTPS
origin, the frontend to that same origin for the built-in Passkey flow,
and real OAuth clients.
The example selects `passkey_only: true`, `machine_only: false` with **one**
initial user containing only `email` and `username`, no password. Its
WebAuthn enrollment is authorized by the generated single-use ticket. Machine
service-only deployments use `machine_only: true`, `passkey_only: false`,
`users: []`, and confidential `client_credentials` clients. Password-enabled
full-profile deployments may provide users with original strong passwords but
must use Paid CPU. Then run:

```sh
npm run bootstrap -- /private/bootstrap.json /private/nazoauth-credentials.json
```

This command creates unique tenant IDs and two independent 32-byte secrets,
runs the native NazoAuth provisioner offline, saves the signing wrapping key
and issued client credentials to a new private `0600` file, checks that D1
contains no existing keys/clients/users/modules, imports the seed rows, writes
the non-secret issuer configuration into root `wrangler.toml`, then deploys
the Worker with three secret bindings and, for Passkey-only setup, three
additional **temporary bootstrap secret bindings** via `--secrets-file`.
After offline bootstrap, read the output file's `passkey_setup.url` and
`passkey_setup.token` **only on the deployer's device**. Once the custom HTTPS
route and direct-ingress WAF protections are configured, open the issuer's
`/auth/setup`, enter the ticket in the page (not in a URL), and approve the
browser's platform Passkey creation dialog. The issued setup session expires
after five minutes and the ticket is consumed exactly once. Do not reload
during enrollment. A lost or expired claim without a registered credential
requires an authenticated offline recovery procedure, not an open HTTP reset.
Remove the bootstrap bindings from the deployment after successful enrollment.
All temporary SQL and secret files are deleted when bootstrap exits. It refuses to provision a
nonempty D1. Preserve the private output offline: losing the wrapping key
prevents recovering persisted signing keys. If import or deploy fails, retain
the recovery file and investigate the remote D1 state; do not reinitialize it.

Before accepting live requests, install the direct-ingress zone WAF rule in
[Authenticated ingress](#authenticated-ingress), set the intended HTTPS
`routes` custom domain in root `wrangler.toml`, and deploy again:

```sh
npm run deploy
```

The issuer hostname must match `NAZO_CONFIG.issuer`. Passkey browser
registration must run on that exact secure origin (RP ID derives from the issuer
hostname). With `frontend_base_url` set to that origin, the Passkey profile
serves its own login and consent pages. A separately hosted frontend can instead
use the same protocol endpoints.
For unmerged PR acceptance select the actual `feat/cloudflare-workers-206`
branch in Cloudflare Builds; the public one-click button defaults to `main`
until the PR is merged. Later Git pushes build/deploy via Workers
Builds; `npm run deploy` remains idempotent for D1 schema migrations and
preserves existing Worker secrets. Do not publish the private bootstrap JSON
or credentials in a Git repository or CI log.

## Provision a fresh deployment

Manual installations: create a D1 database or let Wrangler auto-provision it.
Use repository-root `wrangler.toml` and the `NAZO_DB` binding. No placeholder
database UUID is used. Set a public custom domain only after initialization.
Configure the ingress rule below before exposing the route. Use Workers Paid to
budget password hashing and the full application module.

For a custom domain, uncomment the top-level `routes` example and replace
`auth.example.com` with the configured issuer's hostname. Keep `NAZO_VERSION`
as a platform `version_metadata` binding; it is not a manually supplied variable.

`NAZO_CONFIG` is a JSON object with these fields:

| Field | Meaning |
| --- | --- |
| `tenant` | Non-nil `tenant_id`, `realm_id`, `organization_id` UUIDs |
| `issuer` | Canonical HTTPS issuer at the origin root; request authority must match |
| `frontend_base_url` | Issuer origin for the built-in Passkey UI or the origin of a separately hosted login/consent UI |
| `ingress` | `direct_cloudflare`; `local` requires a loopback issuer |
| `cors_allowed_origins` | Optional browser origins; defaults to issuer origin |
| `modules` | Optional array of available module identifiers from the module matrix; persisted selection must match |
| `machine_only` | Service-client-only profile; exclusive with `passkey_only` |
| `passkey_only` | Worker Free interactive Passkey profile; password routes are disabled |

Generate a 32-byte random signing wrapping key, encode it with standard Base64,
and select its non-secret ID. Generate an independent client-secret pepper of
at least 32 bytes. The wrapping key encrypts persisted private signing material;
it is separate from signing keys and client credentials.

The native provisioner accepts one JSON document on stdin:

```json
{
  "configuration": {
    "tenant": {
      "tenant_id": "00000000-0000-0000-0000-000000000001",
      "realm_id": "00000000-0000-0000-0000-000000000002",
      "organization_id": "00000000-0000-0000-0000-000000000003"
    },
    "issuer": "https://auth.example.com",
    "frontend_base_url": "https://app.example.com",
    "ingress": "direct_cloudflare",
    "cors_allowed_origins": ["https://app.example.com"],
    "modules": ["session_management"]
  },
  "signing_key_id": "primary",
  "signing_key_base64": "REPLACE_WITH_BASE64_OF_32_RANDOM_BYTES",
  "client_secret_pepper": "REPLACE_WITH_INDEPENDENT_RANDOM_SECRET",
  "clients": [{
    "client_name": "Web application",
    "client_type": "public",
    "redirect_uris": ["https://app.example.com/callback"],
    "scopes": ["openid", "profile", "email", "offline_access"],
    "allowed_audiences": ["resource://default"],
    "grant_types": ["authorization_code", "refresh_token"],
    "token_endpoint_auth_method": "none",
    "security_policy": { "version": 1 }
  }],
  "users": [{
    "email": "operator@example.com",
    "username": "operator",
    "password": "REPLACE_WITH_A_LONG_RANDOM_PASSWORD"
  }]
}
```

Client input is validated by the existing administrative registration policy;
identifiers and any client secrets are generated there. Passwords use the native
host's Argon2id policy (19,456 KiB, two passes, one lane). Provisioned accounts are
ordinary users with unverified email.

```sh
umask 077
cargo run --locked --release -p nazo-server-worker --features provisioning \
  --bin nazo-worker-provision -- seed.sqlite < provisioning.json > credentials.json
python3 deploy/cloudflare/export-seed.py seed.sqlite > seed.sql
cd deploy/cloudflare
npm run db:migrate
npx wrangler d1 execute NAZO_DB --remote --config ../../wrangler.toml --file ../../seed.sql
npx wrangler secret put NAZO_SIGNING_KEY --config ../../wrangler.toml
npx wrangler secret put NAZO_CLIENT_SECRET_PEPPER --config ../../wrangler.toml
npx wrangler secret put NAZO_DUMMY_PASSWORD_HASH --config ../../wrangler.toml
```

Set `NAZO_DUMMY_PASSWORD_HASH` from the generated `dummy_password_hash`,
`NAZO_SIGNING_KEY` from the original Base64 wrapping key, and
`NAZO_CLIENT_SECRET_PEPPER` from the original pepper. Set `NAZO_SIGNING_KEY_ID`
and copy the exact provisioned configuration into `NAZO_CONFIG` in the root
`wrangler.toml`. Input, SQLite,
SQL and credential output are private deployment material. Import seed rows only
into a fresh migrated database. The command refuses to overwrite an existing file.

```sh
npm run deploy
```

The Worker refuses to create missing keys in a request. The Free machine-only
profile allows OAuth server metadata, JWKS, service token issuance and token
management, and does not expose interactive authorization or password endpoints.
The password-enabled profile admits the shared HTTP routes; operations still
require the available adapters and selected modules described above.

Parsed keys and the
completed application graph are reused within an isolate. The shared key manager
advances persisted lifecycle state; a request refreshes its snapshot at most once
per minute. Changing wrapping keys requires retaining access to the old
generation and resealing it through key-management tooling before switching the
deployed secret.

## Authenticated ingress

`direct_cloudflare` requires the SDK's platform `Cf` extension and exactly one
valid `CF-Connecting-IP`; it rejects `CF-Worker` and the cross-zone Worker source
placeholder. Install a zone WAF rule blocking `cf.worker.upstream_zone ne ""`
as described in [Cloudflare's Worker-subrequest rule](https://developers.cloudflare.com/waf/custom-rules/use-cases/block-worker-subrequests/).
Do not expose this Worker through service bindings or another Worker. Keep Pseudo
IPv4 in `Off` or `Add Header` mode.

Same-zone Worker scripts can change `x-real-ip`, which can change
`CF-Connecting-IP`; header presence alone does not prove direct ingress.
[Cloudflare's request-header documentation](https://developers.cloudflare.com/fundamentals/reference/http-headers/)
defines these facts. Zone-rule and same-zone Worker administrators belong to the
trusted deployment boundary.

The adapter supplies `ConnectionFacts.authenticated_client_ip`, leaving socket
peer, direct TLS SNI and client certificates absent. The neutral facade uses this
explicit source for source-based policy. Ordinary forwarding/certificate headers
cannot override it or grant mTLS authentication. Tenant admission uses the
original URI authority.

## Concurrency and memory

Completed graphs are reused without a per-request lock. In-flight initialization
I/O is not shared across Worker request contexts; concurrent cold requests may
prepare independently and then reuse the completed graph.

The cache checks the platform-generated `NAZO_VERSION.id` and compares the
consumed binding values in JavaScript before reuse. The version ID also covers resource
rebinding that preserves a JavaScript object's identity; no manual deployment
counter is needed. Secret values are not copied into Rust strings on
the cache-hit path. A changed binding rebuilds the graph; an initialization
failure never falls back to another environment's graph. This handles
[binding-only deployments that can retain an isolate](https://developers.cloudflare.com/workers/runtime-apis/bindings/#making-changes-to-bindings).

Body admission precedes stream polling. The adapter checks the manifest's budget
before copying a JavaScript chunk into WASM, then moves the owned chunk into
`Bytes` without another copy. Single-chunk buffered bodies retain that allocation;
multi-chunk buffered bodies require aggregation copies in the shared facade.
Multipart chunks remain incremental.
Gzip/deflate uses platform decoding only for body modes requesting it; unsupported
or invalid encodings take the shared body-error path. Fetch headers may already
have normalized repeated values, a separate platform constraint from the repeated
values retained by the Rust HTTP contract.

JS/WASM transfer and response serialization still copy bytes. The boundary is
not completely zero-copy across heaps. Password verification holds one
memory-hard workspace at a time per isolate because it never suspends while the
workspace is allocated.

One D1 database processes queries one at a time. Independent issuers/tenants can
use independent deployments; never split one authority's transaction across
databases. Measure the actual region, crypto algorithms, login/token mix and D1
latency. The [D1 FAQ](https://developers.cloudflare.com/d1/reference/faq/) describes
throughput/overload behavior; [Workers limits](https://developers.cloudflare.com/workers/platform/limits/)
cover isolate memory, CPU and bundle/startup limits. Local workerd throughput
does not establish production edge capacity.

## Verification

```sh
cargo test --locked -p nazo-http-worker -p nazo-oauth-server-d1 \
  -p nazo-server-worker \
  --features nazo-oauth-server-d1/local-sqlite,nazo-server-worker/provisioning
python3 scripts/check_worker_portability.py
npm run bundle --prefix deploy/cloudflare
npm test --prefix deploy/cloudflare
```

The integration suite loads the actual WASM in workerd and provisions an actual
D1 binding. It exercises the selected modules along with discovery/JWKS,
login/session cookies, authorization code and PKCE, refresh, UserInfo, revocation,
DPoP nonce/replay, concurrent one-time consumption, binding changes, isolate
restart and storage failure. It prints local cold-start and concurrent Client
Credentials timings. SQL tests execute production statements for rollback,
isolation, expiry and CAS. Transport tests use the shared facade conformance kit.

The local workerd suite deliberately creates and destroys isolated databases.
Do not reuse that fixture against a deployed D1 binding. Public acceptance has
a separate opt-in runner and uses only dedicated test identities and clients:

```sh
NAZO_WORKER_ACCEPTANCE_INPUT=/private/worker-acceptance.json \
NAZO_WORKER_ACCEPTANCE_OUTPUT=/private/worker-acceptance-result.json \
NAZO_WORKER_ACCEPTANCE_AUTHENTICATOR=/private/worker-acceptance-passkey.json \
node --test deploy/cloudflare/test/public-acceptance.mjs
```

Ordinary `npm test` skips this test when `NAZO_WORKER_ACCEPTANCE_INPUT` is absent.
The input is a private JSON object with the following fields. All clients must
already belong to the selected tenant and allow the grants exercised by the run.
The runner never provisions a database or replaces an existing account.

| Input | Required content |
| --- | --- |
| `issuer` | Canonical public HTTPS issuer; redirects are inspected without following them to RPs |
| `tenant_id`, `user` | Dedicated tenant/user identifiers and `user.email`; needed for browser flows |
| `enrollment.token` | One-use setup ticket for that dedicated user on the first run |
| `browser_client` | `client_id`, `redirect_uri`, optional `scope`, `post_logout_redirect_uri`, `frontchannel_logout_uri`; `request_private_key_jwk` enables inline JAR when its public key and signing algorithm are registered |
| `private_key_client` | `client_id`, `private_key_jwk`, `algorithm`, `scope` and `resource`; private key is never copied into the result |
| `service_client` | Optional `client_id`, `client_secret`, `scope`; otherwise the private-key client exercises Client Credentials |
| `dpop_client` | Optional browser client registered with DPoP required |
| `device_client` | Client with the Device grant, cross-device policy and requested scopes/resource |
| `native_sso` | `source_client` and `destination_client` browser-client objects with the Native SSO permissions above |
| `dcr_initial_access_token` | Dedicated initial access token when dynamic registration is selected; kept out of results |
| `modules` | Enabled module names to include in the run |
| `race_concurrency` | Optional one-use race width, bounded to 2–16; defaults to 4 |
| `workload` | Optional `{ "requests": 128, "concurrency": 8 }` adds private-key Client Credentials samples after protocol tests; capped at 256 requests and concurrency 16 |

The result contains paths, timestamps, HTTP statuses, durations and fixed failure
descriptions. It excludes tokens, cookies, assertion bodies and private keys.
The optional authenticator file is a separate private `0600` file containing only
the dedicated synthetic credential and counter. Reusing that path lets later runs
authenticate without consuming another setup ticket. Never use a real user's
credential or a general registration ticket for this test.

The optional service workload sends up to 16 serial warm-up requests, then runs
the remainder through a bounded concurrent pool. Every successful response has
its JWT signature verified independently. The `x-nazo-acceptance-phase` header
labels `protocol`, `warm_serial` and `concurrent` invocations; client results and
the telemetry summary keep these phases separate. Workload durations are client
wall time. The run never converts them into CPU estimates.

Synthetic P-256 WebAuthn messages exercise server-side ceremony validation and
one-use state. They do not test a browser's credential UI, authenticator hardware,
biometrics, cross-device transport or account recovery. Accept the real-device
Passkey flow separately on the issuer origin, including the setup/login pages
and an authorization-code redirect through consent.

### Public CPU and failure measurements

Enable [Workers Logs](https://developers.cloudflare.com/workers/observability/logs/workers-logs/)
invocation logging for the acceptance deployment and record its sampling policy.
Each runner request carries an `x-nazo-acceptance` run identifier. Export the
matching invocation records, bounded by run, deployment version and time range.
Keep HTTP and scheduled events separate and exclude unrelated scanner traffic.
Retain request ID, path, response status, CPU/wall time, outcome and version;
never export authorization headers, cookies or request bodies.

```sh
NAZO_WORKER_ACCEPTANCE_RUN_ID=nazo-acceptance-REPLACE \
NAZO_WORKER_ACCEPTANCE_VERSION=REPLACE \
node deploy/cloudflare/summarize-worker-logs.mjs \
  /private/invocations.json /private/worker-acceptance-result.json
```

The summarizer accepts the Cloudflare telemetry `result.events.events` shape
or normalized records with `timestamp`, `request_id`, `path`, `cpu_ms`, `wall_ms`,
`outcome`, `status`, `version`, `event_type`, `run_id` and optional `phase`. It deduplicates console
and invocation records by request, reports missing CPU samples, and compares
observed fetch counts with the client run. Preserve run/version fields when
normalizing; only use a prefiltered export without the corresponding filter.

Report CPU sample count, median, p90/p95/p99, maximum and count above 10 ms,
with HTTP statuses and `exceededCpu`/`exceededMemory` outcomes separately.
Report the client's actual Cloudflare 1102 pages as another independent count.
Missing or sampled telemetry is not proof of zero rejections.
Cloudflare's [CPU limit documentation](https://developers.cloudflare.com/workers/platform/limits/#cpu-time)
excludes network/database waiting from CPU time and allows occasional over-limit
execution. A log above 10 ms therefore does not by itself establish a platform
rejection. Error 1102 can represent CPU or memory exhaustion; the invocation
outcome distinguishes them. Local timings and HTTPS wall time cannot replace
platform CPU measurements.

Production acceptance also needs the applicable OAuth/OIDC conformance plans
against the deployed HTTPS issuer, direct-ingress WAF verification and target
region concurrency/latency measurements. Existing native OIDF records apply to
their recorded deployment/version.
