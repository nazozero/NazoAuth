# Cloudflare Workers

The Workers host runs the production `nazoauth` facade and its portable domain
and application crates. `nazo-http-worker` converts transport values;
`nazo-oauth-server-d1` implements the existing persistence and transient-state
ports. `nazo-server-worker` owns bindings, configuration, key refresh and the
prepared application graph. Protocol parsing, grants, DPoP validation,
redirects, discovery metadata and response policy stay in the shared
implementation. Hosts select the shared `DeploymentProfile`; endpoint admission,
grant availability, dynamic registration and metadata use that same profile.

## Deployment profile

Each deployment serves one issuer and one tenant through one primary D1 binding.
The host rejects other request authorities before selecting an application graph.
Dynamic tenant directories, per-host runtime replacement and cross-tenant
control are currently available in the native host. A multi-issuer Worker
would need its own directory and graph-replacement adapters.

The checked-in template starts `machine_only: true` for confidential service
clients. Set `machine_only: false` and `passkey_only: true` in the **private bootstrap input**
to enable interactive WebAuthn (Passkey) login with password login disabled.
The bootstrap helper creates one initial user with an unknown random password,
and hands the operator a single-use, 24-hour setup ticket; the ticket grants a
five-minute registration session on the issuer's HTTPS origin. The password-enabled
profile (`machine_only: false`, `passkey_only: false`) retains the shared Argon2id
verifier on either Free or Paid. Password checks and backup-code operations
retain the native Argon2id work factors and can exceed Free's per-request CPU
budget. Size the deployment using CPU measurements and platform outcomes at
the intended sustained load.

Both interactive profiles can serve the bundled NazoAuthWeb application from
the issuer's `/ui/` path. Set `frontend_base_url` to `https://<issuer-host>/ui/`.
The Worker redirects `/auth`, `/consent` and `/device` to their Web routes;
the Device route also requires its module. The pinned Web build includes a
Worker overlay for Passkey login, MFA challenges after password or Passkey
authentication, pending-session handling, account Passkey registration/listing/
deletion, and TOTP/backup-code management. It calls the shared server endpoints.
“Sign in again” confirms logout before opening the login page and preserves the
return path. OIDC `prompt=login` and expired `max_age` requests keep the login
form open until new authentication and any required MFA finish.
The operator's single-use `/auth/setup` enrollment page remains separate from
ordinary account registration. A separately hosted frontend is also possible.

`passkey_only` admits Passkey/MFA account operations and selected
authorization/token flows. For the complete administrator, federation, SCIM,
CIBA and digital-credential APIs, use
`machine_only: false`, `passkey_only: false` for the full Web and all adapted
service routes; that profile offers both password and Passkey authentication.
The flags map to the shared `Full`, `PasskeyOnly` and `MachineToMachine` profiles.
The facade applies their endpoint policy after normalizing the request path.

| Capability | Workers profile |
| --- | --- |
| Discovery and JWKS | Shared metadata and key lifecycle |
| Authorization | Authorization code with PKCE and interactive consent |
| Tokens | Code redemption, refresh, Client Credentials, revocation and UserInfo |
| Client authentication and sender constraints | Client secret, `private_key_jwt`, DPoP proof/nonce/replay state, and mTLS with trusted Cloudflare certificate metadata and client trust policy |
| Identity | Machine-only, password-enabled full profile, or Passkey-only with offline initial setup; shared registration, Passkey ceremonies, MFA, sessions and logout use D1 adapters |
| Account profile | Current account, validated updates, authorized-application history, MFA and Passkey management, and authenticated avatar upload/read/delete |
| Tenant administration | User/client administration, application-access requests and approvals, one-use client delivery, grant revocation, and configured trust-policy/dataset management |
| Optional modules | Deployment capability ceiling with persistent runtime enable/disable, revision-safe administration and resumable drain |
| Keys | Encrypted persistent key generations; shared `nazo-crypto` uses Workers WebCrypto for asynchronous Ed25519, ES256, RS256 and PS256 signing, and portable Rust backends for verification |
| Audit | Required evidence commits with the accepting mutation; append-only D1 audit rows |

All 16 shared protocol modules have Worker host adapters for the full profile.
Configuration rejects unknown native fields and invalid profile/module combinations.
`NAZO_CONFIG.modules` identifies the capabilities constructed by the deployment
and supplies the initial desired state during provisioning. D1 subsequently owns
mutable desired state; it need not equal the initial deployment selection.
Administrators use the shared runtime module API and Web workflow with the same
MFA, CSRF, dependency policy and expected-revision checks as the native host.
Discovery follows the current admission snapshot. Unconfigured external services
return explicit failures.

Shared client preparation checks the deployment's enabled grants and service
capabilities before persistence. Remote documents and outbound notifications
require explicitly admitted HTTPS origins; mTLS requires trusted ingress facts
and a configured trust policy. Front-channel logout uses registered RP endpoints
and does not require an outbound delivery worker. Cloudflare Workflows are not required.

### Optional module matrix

These are all 16 shared runtime modules. An available module still needs explicit
construction in `NAZO_CONFIG.modules`, enabled durable intent and the corresponding
client grants, scopes and security policy. Runtime administration cannot construct
a capability omitted from the deployment.

| Module | Workers binding and conditions |
| --- | --- |
| `device_authorization` | D1 device/user-code mappings, compare-and-set polling state, durable user decision and single-use redemption. Clients must allow `urn:ietf:params:oauth:grant-type:device_code` and set `security_policy.allow_cross_device_flows: true`. |
| `token_exchange` | Shared local-token exchange with D1 token state, scope/target checks and revocation. Clients must allow the token-exchange grant. External issuer trust and delegated remote tokens are not implicitly enabled. |
| `jwt_bearer_grant` | Shared JWT bearer grant with client subject binding and atomic assertion replay state. Clients register verification keys and the JWT bearer grant; remote JWKS additionally requires an admitted origin. |
| `ciba` | Shared account lookup, poll/decision rules and token issuance with D1 compare-and-set state, deadlines and one-use redemption. The native `FapiCibaId1` policy remains in force: confidential clients, supported asymmetric client authentication, ES256/PS256 ID tokens, a signed request with a binding message, and mTLS-bound access tokens. The client also needs the CIBA grant and administrator-owned cross-device permission. Ping mode uses leased D1 deliveries, the shared retry worker and an admitted notification origin. |
| `dynamic_client_registration` | Shared RFC 7591/7592 registration with D1 management-token authority, atomic required audit, credential rotation, compare-and-set updates and deactivation. Requires the separate `NAZO_DCR_INITIAL_ACCESS_TOKEN` secret. Deployment capability policy rejects unsupported metadata before resolution or persistence. |
| `request_objects` | Signed Request Objects and PAR use shared validation and D1 one-use state. Inline objects work without outbound access; remote `request_uri`, `jwks_uri` and sector documents use bounded fetch to explicitly admitted HTTPS origins. |
| `jarm` | Shared signed authorization responses use persisted issuer keys. The client selects a supported response algorithm. |
| `authorization_details` | Shared RAR parsing, consent, access-token and refresh handling; D1 persists the accepted details with the grant. |
| `http_message_signatures` | Shared request verification, response signing and replay state for the signed resource endpoint. Verification uses the client's persisted JWK set; this resource path does not refresh remote JWKS on each request. |
| `scim` | Shared SCIM validation with tenant-bound D1 credentials, filtered/paginated user CRUD, soft deletion, and required audit. Deactivation retires authorization epochs, refresh families and grants in the same transaction. Provision a scoped SCIM bearer credential separately from OAuth clients. |
| `scim_security_events` | Requires SCIM. User mutation, shared SET event creation and required audit commit together. D1 retains events and receiver-specific acknowledgements/errors; the shared publisher signs the local polling response, with a bounded Worker delay for long polling. This endpoint does not poll a remote service. |
| `native_sso` | Shared device-secret exchange and D1 source refresh-family checks. Requires `token_exchange`, allowed `device_sso` scope, the issuer audience and the code/refresh/exchange grants on participating clients. Revoking the source family prevents later exchange. |
| `frontchannel_logout` | Registered RP iframe URLs and session identifiers are generated by the shared logout flow. Delivery is performed by the browser; back-channel delivery has its own D1 outbox and outbound configuration. |
| `session_management` | Shared session state, check-session iframe/status and RP-initiated logout; participating clients enable `security_policy.session_management`. |
| `openid4vci_issuer` | Shared issuance with D1 offers, managed datasets, subject policy, access grants, proof nonces, exact response retries, deferred responses and notifications. Requires credential configurations, management authority, encrypted state and suitable issuer signing/certificate material. Shared format, proof, attestation and holder-binding policy remains authoritative. |
| `openid4vp_verifier` | Shared signed authorization requests, encrypted presentation responses, holder/issuer validation and result retrieval with D1 idempotency, replay state and trust policy. Requires verifier management authority, wallet origins, certificate/trust material, and admitted remote status-list origins where applicable. The Worker selects the shared required-revocation policy. |

The machine-only profile permits `token_exchange`, `jwt_bearer_grant`,
`http_message_signatures` and `dynamic_client_registration`; discovery,
registration and token dispatch allow service grants only. Switching an existing
deployment to this profile also rejects redemption of outstanding authorization
codes and refresh tokens. Token Exchange accepts service subjects and actors;
requests carrying a user subject or actor are rejected.

Passkey-only accepts the remaining interactive OAuth modules but rejects
`ciba`, `scim`, `scim_security_events`, `openid4vci_issuer` and
`openid4vp_verifier` during configuration. Use the full profile for those modules.
Each client still needs its own grants, scopes and security policy to use an
enabled module.

When selecting dynamic registration, supply `NAZO_DCR_INITIAL_ACCESS_TOKEN`
as a secret of at least 32 bytes before deploying that module selection.
Keep it separate from the client-secret pepper and signing wrapping key.
The graph refuses to start with the module enabled and a missing/short token.
The default bootstrap input does not enable this module. If the bootstrap input
selects it, the helper generates and saves a separate initial access token;
manual installations supply it through existing secret management.
Registered clients receive their own management token. A successful configuration
replacement rotates that token and any client secret; stale management tokens
cannot update or delete the client. Client-owned updates cannot increase
administrator-limited scopes or change administrator-owned audiences/policy.

### Service prerequisites and remaining host boundaries

| Area | Current boundary and work required |
| --- | --- |
| mTLS | Enable `services.mtls` only with direct Cloudflare ingress and client-certificate collection configured for the issuer hostname. Facts come from platform `request.cf.tlsClientAuth`, including bounded RFC 9440 certificate data, revocation flags and a matching fingerprint. A platform-verified chain or the shared portable X.509 verifier with approved D1 trust anchors supplies trust; registered client selectors still apply. Ordinary request headers cannot confer certificate authority. |
| Remote documents | A bounded Worker fetch adapter resolves JWKS, Request Objects, sector documents and credential status lists. `services.outbound_origins` admits exact HTTPS origins; redirects are not followed, credentials are not inherited, and time/body/media limits apply. Fetch does not expose native DNS resolution or IP pinning: the operator-controlled origin list is this host's network authority. |
| Federation | D1 account/link and replay adapters reuse the shared OIDC/social provider flows, with bounded outbound HTTP. Configure the provider application, credentials and endpoints in service secrets, register its callback and admit its origins. SAML uses the shared authenticated gateway contract. |
| Back-channel logout | The shared logout service writes a D1 outbox; leased claims, retry/expiry and completion state drive bounded Worker HTTP delivery on scheduled events. Admit each RP notification origin. Discovery support is enabled only when outbound origins are configured; front-channel delivery remains browser-driven. |
| Email registration and verification | Shared registration uses D1 account creation, owner-bound send reservations, a fixed verification-attempt budget and single-use challenge consumption. Delivery requires the configured HTTPS email relay, its admitted origin and secret. Concurrent sends and cleanup cannot overwrite or delete a later owner's challenge. |
| MFA | D1 stores encrypted TOTP seeds, one-use counters, hashed backup codes, remembered-device bindings and required audit mutations. Configure the service data-encryption key. Shared recent-MFA and interactive-proof requirements apply to administration; a remembered device does not grant recent-MFA authority. Backup-code hashing retains the native Argon2id policy and needs measured CPU capacity. |
| Authorized-application list | The shared profile lists current grants with canonical authorization audit history for counts and last authorization. Legacy grants explicitly marked as having unknown history return `null` for these fields; the Web interface shows “History unavailable” / “历史未记录” rather than inventing timestamps or counts. Administrator grant revocation retires the associated token families and credential access in the same D1 transaction. |
| Avatars and object storage | Authenticated multipart upload, binary proxy read and deletion use the shared account-revision compare-and-set lifecycle. A private `NAZO_AVATARS` R2 binding stores new image bytes in R2, and D1 retains avatar metadata and existing D1-backed images. Browser-direct uploads are unsupported on Workers. |
| Tenant administration | User/client listing, creation and updates use shared preparation and hierarchy policy. D1 rechecks current actor context and prepared target metadata at transaction admission; mutations, dependent-token retirement and canonical required audit commit together. Client downgrade to public authentication retires its refresh families and secret. |
| Deployment administration and recovery | The Worker builds without `deployment-control`, so `DeploymentCapabilities` and its control routes are absent. Controller-registry and recovery-root ports belong to that optional host capability. Dynamic hostname/tenant registry replacement and independent audit anchoring need additional adapters. The D1 user port supports transactional administrator updates across tenant rows; the current single-issuer host exposes only tenant-local administration. |
| Runtime module lifecycle | The shared registry owns dependency policy and transitions. D1 persists revision CAS, per-instance state and append-only events. Each protocol request synchronizes current intent before admission; bounded steps retain existing-transaction admission during the drain window and never wait for a whole session/refresh lifetime inside one invocation. |
| Native process signers and files | Worker isolates cannot run the native host's subprocess/OS integration. Provisioning stays in a native offline tool; request signing uses the shared `nazo-crypto` Worker backend. Persistent files require an explicit storage adapter. |
| mdoc CRL publication | Configure an offline-signed public CRL for the current DS/IACA pair. Every CRL request reads the authoritative D1 public material and verifies its exact digest, issuer/certificate binding, signature, publication interval and current DS revocation status. Expired or changed authority material fails closed; the IACA private key stays offline. |
| Password authentication | Argon2id remains the shared password verifier on either plan. Machine-only and Passkey-only profiles disable password routes; the password-enabled profile can use the bundled Web application. Size password and backup-code workloads against the plan's CPU budget while retaining the shared work factors. |

### Runtime module administration

The Web uses NazoAuthWeb's existing module review, expected-revision CAS, MFA
step-up and status/event polling interface. A successful desired-state update
persists the requested state. Each isolate reports its own actual state and
finishes existing requests under the shared drain policy. Every subsequent protocol request first reads
authoritative D1 state and applies the shared bounded reconcile operation.
Stable state needs a coherent read without repeated transition writes. An
unavailable or continuously changing authority fails closed.
Each invocation advances at most one module transition, including across
snapshot retries. Unfinished modules rotate so a long drain does not starve
other changes. This bounds D1 calls while leaving room for the actual protocol
request; a D1 batch counts as one binding query, not one per SQL statement.

For stored transactions the shared deadline is the accepted desired state's
timestamp plus the catalog's maximum lifetime. The store preserves timestamp
and revision for a same-mode update, so repeated disable requests cannot extend
the window. Cold isolates recover that same deadline; they do not start a new
timer. At expiry, stored admission closes before existing local request leases
are checked. Transitions remain pending until both drain and local leases
complete. Native hosts use the waiting reconcile entrypoint; Workers use the
resumable one.

This profile uses the fixed shared lifetime settings and does not expose per-tenant
TTL overrides. Do not change those catalog durations in a deployment while an
affected module is draining: a future configurable duration requires persistent
policy/version binding to preserve the same deadline across different builds.
Disable and finish draining a module before removing its constructed capability
from deployment configuration. Removing code/services through a deployment is
not a substitute for the runtime drain operation.

Desired-state, instance-state and canonical event mutations preserve their
atomic audit contract. Old instance observations may be pruned after seven days
when they have no live drain deadline; desired intent and append-only events
are retained. An observation row's absence never proves that all isolates have
stopped; local leases and the authoritative desired revision remain decisive.

Migration `0015_runtime_modules.sql` imports the old provisioned selection as
revision 1 with an unknown-history epoch timestamp and no actor. It does not
invent historical transitions or audit events. A verified cold projection may
acknowledge its applied revision in a management response without manufacturing
a persistent instance record.

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

The minute cron runs one cleanup pass on every deployment profile, with at most
500 candidates/deletions per state category. This is a per-category limit, not
a total limit of 500 rows. Child state is reclaimed before parents to avoid
unbounded foreign-key cascades. When outbound origins are configured, the same
scheduled invocation also drives bounded CIBA ping and back-channel logout
delivery batches. Password-route selection does not change the plan's Cron
budget. Measure scheduled CPU, outcomes and backlog separately to establish
whether maintenance and delivery keep up with traffic.

Scheduled invocations also advance bounded module reconciliation. Requests do
not rely on Cron having run: synchronization before protocol admission prevents
a hot isolate from accepting new work using an obsolete module snapshot.

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
node deploy/cloudflare/build-web.mjs
npm run bundle --prefix deploy/cloudflare
```

The bundle command runs the dedicated `build-worker.sh` entry with
`worker-build --release --locked --no-default-features`, release pruning and
Wrangler's dry run.
It does not publish a Worker. The module graph is under
`crates/server-worker/build`; Wrangler's bundle is under
`deploy/cloudflare/bundled`. A successful dry run replaces the complete bundle
directory, removing historical hashed WASM modules; a failed build preserves the
previous bundle. The final JavaScript/WASM pair is checked before replacement:
it must reference its single current WASM module, expose only the application's
default entrypoint and retain every WASM export referenced by JavaScript.

`prune-worker.mjs` builds a joint JavaScript/WASM reachability graph with
Binaryen 133 `wasm-metadce`, then removes unreachable generated SDK bindings and
reoptimizes with `wasm-opt`. It obtains these tools from worker-build's complete
Binaryen distribution, or the distribution selected by `WASM_OPT_BIN` or
`WASM_METADCE_BIN`. Unknown SDK initialization effects, escaped export objects
and dynamic WASM export access fail the build instead of guessing what is live.
Memory, globals and tables are retained; SDK helpers reached through indirect
function-table calls also remain. Recognized SDK wrapper shapes are eligible
for analysis; runtime reachability decides removal. The generated
`build/prune-report.json` records raw/gzip sizes and export changes.

The WASM production graph excludes Actix, native HTTP servers, PostgreSQL/Valkey
drivers, native TLS and native Tokio execution features. The SDK's Tokio library
dependency does not enable a runtime. `local-sqlite` enables the same adapter SQL
for native offline provisioning and contract tests; its driver is selected only
on non-WASM targets.

The facade is compiled without `deployment-control`: deployment identity,
controller registry, independent recovery and cross-tenant administrator routes
are not part of the Worker. Tenant user/client administration and the shared
protocol modules remain compiled. `check_worker_portability.py` checks both
production graphs: the native server cannot acquire Workers/D1/JavaScript runtime
dependencies, and the Worker cannot acquire native execution adapters,
certificate provisioning or deployment controls. Native image build contexts
retain Worker crate Rust sources and manifests needed to resolve the workspace,
while excluding Worker/Web assets and generated output. They do not run frontend
or Worker build steps. The native runtime image copies only the executable and
source identity from the product build; release packaging uses the prebuilt
native executable. Worker artifacts do not enter either runtime image.

### Bundled Web application

`deploy/cloudflare/web-source.json` pins the NazoAuthWeb repository revision,
application version and Node/npm versions. `build-web.mjs` checks out that exact
revision into generated build output, applies only the local
`deploy/cloudflare/web-adapter` overlay, runs its browser-component tests and
the upstream source/distribution security checks, and builds with `/ui/` as
the base path. The upstream repository is not changed. Build output includes
`/ui/source.json` with source provenance and a generated `_headers` file whose
script hashes match the final HTML. The asset policy includes HSTS, framing,
referrer and content-type protections. Host responses use the shared security
header policy while retaining each page's more specific CSP.

Wrangler binds `deploy/cloudflare/web-dist` as `ASSETS`. Hashed asset/icon paths
are served by the asset service; the Worker owns the application shell and
selected UI redirects. SPA fallback is restricted to `/ui/`, so an unknown
protocol route never turns into a successful HTML page. Rebuild the Web assets
before a local deployment when the pinned revision or overlay changes. The
repository-root cloud build performs this step automatically.

### Optional R2 avatar storage

Apply D1 migrations before deploying a Worker that uses avatar storage. Bind a
private bucket only to the intended deployment, using the fixed binding name:

```toml
[[r2_buckets]]
binding = "NAZO_AVATARS"
bucket_name = "your-private-avatar-bucket"
```

The same authenticated multipart endpoint validates and uploads each avatar.
D1 owns its account reference, version, content type, and length. New image
bytes go to R2, while avatars already stored in D1 remain readable and can be
replaced or deleted through the same API. Each bucket object key is scoped to
the tenant, user, and immutable avatar version. The scheduled Worker reclaims
unreferenced R2 candidates in bounded batches. Keep the binding attached while
D1 references avatar objects in that bucket. Back up D1 and R2 together. To
roll back to a version without R2 avatar support, first move referenced avatar
bytes back to storage that version can read.

An unbound deployment stores new avatars as bounded D1 chunks. R2 bindings
require neither a public bucket nor S3 credentials. Browser-direct uploads
remain a [native S3 capability](avatar-direct-upload.md).

## Deploy to Cloudflare button

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/nazozero/NazoAuth)

Use the repository **root**. Cloudflare's button cannot clone only `deploy/cloudflare`:
the Rust workspace and its dependencies live outside that directory.

The button creates a Git copy, provisions the `NAZO_DB` D1 binding, deploys
the private Worker and runs its SQL migrations. Wrangler resolves the provisioned
database by binding name. The application stays private (`workers_dev = false`,
no public route) until provisioning and ingress configuration are complete.

Cloudflare [removed the gzip size cap in September 2026](https://developers.cloudflare.com/changelog/post/2026-09-04-increased-worker-size-limit/):
Free and Paid now accept up to 64 MiB uncompressed. Use the current dry-run
artifact size when checking that limit. **Workers Free** has 100,000 requests/day, 10 ms CPU per HTTP request
and 10 ms per Cron invocation; D1 has separate daily row-read/write quotas.

The deployment template starts in `machine_only: true` (service clients with
Client Credentials, token management, OAuth metadata and JWKS). During offline
initialization choose `passkey_only: true` and `machine_only: false` for a
**passwordless, interactive** OAuth/OIDC deployment with Passkey login and
Authorization Code/PKCE. Browser password login is then explicitly blocked.
The password-enabled profile is also selectable on Free and retains the shared
Argon2id work factors. Measure password login, MFA enrollment and backup-code
operations at the intended sustained load; use the platform's invocation outcome
to identify CPU rejections. See [public CPU and failure measurements](#public-cpu-and-failure-measurements).
After using the button, configure the issuer domain, initial credentials,
secrets and ingress policy.
Cloudflare Workers Builds has a 20-minute timeout and does not preinstall Rust:
the repository-root `build` script installs Rust 1.100.0, `worker-build`
0.9.0 and `wasm-bindgen-cli` 0.2.130. Confirm build completion in the Cloudflare dashboard.

To initialize a fresh D1 deployment, clone the repository associated with the
button, install local dependencies (Rust 1.100, Node, curl, Python 3, Wrangler),
and create a private JSON input **outside the Git repository** from
`deploy/cloudflare/bootstrap.example.json`. Set the issuer to the intended HTTPS
origin, the frontend to that origin's `/ui/` path for the bundled Web application,
and real OAuth clients.
The example selects `passkey_only: true`, `machine_only: false` with **one**
initial user containing only `email` and `username`, no password. Its
WebAuthn enrollment is authorized by the generated single-use ticket. Machine
service-only deployments use `machine_only: true`, `passkey_only: false`,
`users: []`, and confidential `client_credentials` clients. Password-enabled
full-profile deployments may provide users with original strong passwords. Then run:

```sh
npm run bootstrap -- /private/bootstrap.json /private/nazoauth-credentials.json
```

This command creates unique tenant IDs and independent signing-wrap,
client-secret-pepper and service-data secrets,
runs the native NazoAuth provisioner offline, saves the signing wrapping key
and issued client credentials to a new private `0600` file, checks that D1
contains no existing keys/clients/users/modules, imports the seed rows, writes
the non-secret issuer configuration into root `wrangler.toml`, then deploys
the Worker with `NAZO_SIGNING_KEY`, `NAZO_CLIENT_SECRET_PEPPER`,
`NAZO_DUMMY_PASSWORD_HASH` and `NAZO_SERVICE_SECRETS`. Selecting dynamic
registration additionally creates `NAZO_DCR_INITIAL_ACCESS_TOKEN`. Passkey-only
setup adds three **temporary bootstrap secret bindings**, all supplied through
`--secrets-file`.
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
hostname). With `frontend_base_url` set to that origin's `/ui/` path, both
interactive profiles use the bundled Web application. A separately hosted frontend can instead
use the same protocol endpoints.
The public one-click button uses `main`. Later Git pushes build/deploy via Workers
Builds. Repository-root `npm run deploy` reads the Wrangler configuration: the
private template deploys first to provision D1, while configured public endpoints
run migrations before deployment. Keep public routes in root `wrangler.toml`;
`route`, `routes` arrays and TOML arrays of route tables are supported. A failed
migration stops the public deployment. Existing Worker secrets are preserved.
Do not publish the private bootstrap JSON
or credentials in a Git repository or CI log.

Migration `0013_access_request_pending.sql` enforces the native rule of at most
one pending access request per tenant and user. If an existing database contains
duplicate pending requests, the migration fails explicitly. An authorized
administrator must resolve them through the normal approval or rejection flow
before retrying; the migration does not reject or delete applications itself.

## Provision a fresh deployment

Manual installations: create a D1 database or let Wrangler auto-provision it.
Use repository-root `wrangler.toml` and the `NAZO_DB` binding. No placeholder
database UUID is used. Set a public custom domain only after initialization.
Configure the ingress rule below before exposing the route. Select a CPU budget
using the deployed profile's measured CPU distribution and actual platform
outcomes under the intended sustained load.

For a custom domain, uncomment the top-level `routes` example and replace
`auth.example.com` with the configured issuer's hostname. Keep `NAZO_VERSION`
as a platform `version_metadata` binding; it is not a manually supplied variable.

`NAZO_CONFIG` is a JSON object with these fields:

| Field | Meaning |
| --- | --- |
| `tenant` | Non-nil `tenant_id`, `realm_id`, `organization_id` UUIDs |
| `issuer` | Canonical HTTPS issuer at the origin root; request authority must match |
| `frontend_base_url` | `https://<issuer-host>/ui/` for the bundled Web application, or the base URL of a separately hosted frontend |
| `ingress` | `direct_cloudflare`; `local` requires a loopback issuer |
| `cors_allowed_origins` | Optional browser origins; defaults to issuer origin |
| `modules` | Optional array of constructed capabilities from the module matrix; initializes desired state during provisioning and bounds later runtime enablement |
| `machine_only` | Service-client-only profile; exclusive with `passkey_only` |
| `passkey_only` | Restricted interactive route profile with Passkey/MFA and selected OAuth flows; broader administration/service APIs and password routes are excluded. Use the full profile for all adapted routes. |
| `services` | Non-secret configuration for admitted outbound origins, mTLS, email and digital credentials; fields below |

The `services` object contains only declared host capabilities and public policy:

| Field | Meaning |
| --- | --- |
| `outbound_origins` | Exact HTTPS origins admitted for remote documents, federation, email relay, logout/ping notifications and credential status lists; defaults to none |
| `mtls` | Admit direct Cloudflare certificate metadata; requires `ingress: "direct_cloudflare"` and hostname certificate configuration |
| `email_relay` | Optional `{ "endpoint": "https://mail.example/api/send", "from": "auth@example.com" }`; the endpoint's origin must also be admitted |
| `credential_configurations` | Shared OpenID4VCI configuration map, keyed by credential configuration ID |
| `deferred_credential_configurations` | Configuration IDs using the shared deferred-issuance flow |
| `wallet_authorization_origins` | Allowed wallet authorization origins for presentation requests |
| `client_attestation_jwks`, `key_attestation_jwks`, `client_attestation_issuer` | Optional shared attestation-verification policy |
| `mdoc_crls` | Public map from the 64-character issuer publication ID to `{ "der_base64": "...", "public_material_blake3": "..." }`; each CRL is standard Base64 DER, at most 128 KiB |

`NAZO_SERVICE_SECRETS` is a separate secret binding containing a JSON object:

| Field | Meaning |
| --- | --- |
| `previous_signing_wrapping_key` | Optional `{ "id": "previous-key-id" }` for a wrapping-key transition. Key bytes are supplied only through the fixed private `NAZO_PREVIOUS_SIGNING_KEY` binding, as standard Base64 encoding of exactly 32 bytes. Both the identifier and binding must be present, or both absent. |
| `data_encryption_key` | Standard Base64 encoding of an independent 32-byte key for MFA seeds and protected service state; required when enabling OpenID4VC and needed for MFA enrollment |
| `issuer_management_token`, `verifier_management_token` | Separate OpenID4VC issuer/verifier management credentials, each at least 32 bytes; enabling a role requires its token |
| `email_relay_token` | Bearer credential for the configured HTTPS relay; at least 16 bytes |
| `federation_provider_configs` | The shared provider-registry JSON array, including provider IDs, adapter types, endpoints, callback URLs and client credentials |
| `saml_gateway` | Optional shared gateway `{ "issuer": "...", "audience": "...", "secret": "..." }` configuration |
| `openid4vc_import` | Temporary operator import described below; remove after its generation is persisted |

The email relay receives a JSON POST containing `from`, `to`, `subject` and
`text` with a bearer authorization header; a successful HTTP response acknowledges
delivery. Supply a relay implementing that contract. Credentials for a real mail
provider or federation provider are external prerequisites, not generated by
enabling the corresponding routes.

OpenID4VC certificate provisioning remains an operator operation. Import a
prepared key/certificate generation using `openid4vc_import` with
`expected_revision`, `material` and optional `signing_key_pem`. `material` has
`public` certificate/trust material (`signing_kid`, `certificate_chain_pem`,
`trust_anchors_pem`, optional `revocation_snapshot`) and an empty
`iaca_private_materials` map. The Worker rejects imports containing IACA private
keys; retain those keys in the offline native provisioning environment. The shared key manager
validates and commits that generation to the encrypted D1 key repository with
compare-and-set semantics. Repeated initialization can acknowledge the identical
material, but cannot overwrite another generation by changing the expected
revision. After a successful import, remove `openid4vc_import` from the secret
binding and retain the normal encrypted key lifecycle. The Worker does not invoke
native certificate-provisioning tools or generate a new trust root at startup.

For mdoc CRL publication, sign the CRL offline and configure its public artifact
under `services.mdoc_crls`. Compute `public_material_blake3` from
`blake3(serde_json::to_vec(&Openid4vcPublicMaterial))`, using the shared Rust type
and its timestamp serialization. A generic JSON object serializer can change
field order and produces a different digest. The issuer ID and both DS/IACA
distribution points must identify
`{issuer}/.well-known/mdoc/{issuer_id}.crl`. The CRL must be a complete v2 list
with its IACA authority-key identifier and positive CRL number; its publication
window must fit inside the authoritative revocation snapshot. The current DS
must appear exactly when that snapshot records it revoked, with the same
revocation time. Update the public artifact together with any authority or
revocation change. Unknown publication IDs return 404; a configured artifact
that no longer matches, is invalid or has expired returns 503. The operator owns
CRL renewal and increasing publication numbers. Migration
`0014_mdoc_crl_publications.sql` records the highest accepted publication for
each tenant and IACA public-key issuer ID. Signed artifacts must encode the
number as a complete canonical positive DER INTEGER with at most 20 content
octets, including any positive-sign padding. The receipt stores its magnitude as
fixed-width hexadecimal text so values above `u64` and JavaScript's exact integer
range remain exact. A lower number, or the same number
with different CRL bytes, authority, issuer or timestamps, fails closed. Higher
numbers cannot move `thisUpdate` backwards. Exact republication is idempotent.

The receipt and final stored-state check use the same D1 transaction as a fresh
comparison of the authoritative OpenID4VC public projection and database time.
Changing the DS or revocation snapshot under the same IACA requires a higher
number; it does not reset the fence. A different IACA public key starts a
different issuer-ID namespace. Ordinary JWT key rotation and signing-key
wrapping changes leave this public-authority binding intact. Receipts remain
after CRL expiration so renewal cannot reset the counter. The Worker does not
automatically renew or sign CRLs; the IACA signing key remains offline.

Renew before `nextUpdate` using the current D1 key generation and highest CRL
number. Prepare a fresh revocation snapshot from the current certificate status
and sign a higher-numbered CRL offline. Stage the public artifact and matching
one-shot `openid4vc_import` in the same version. Publish that version, query the
public CRL, and verify the DER digest and persisted publication number. Then
deploy the same public artifact with the one-shot import removed. Retain the
latest public artifact in subsequent deployments. Worker version rollback
cannot revert a committed D1 generation or publication fence.

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
    "frontend_base_url": "https://auth.example.com/ui/",
    "ingress": "direct_cloudflare",
    "cors_allowed_origins": ["https://auth.example.com"],
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
host's Argon2id policy (19,456 KiB, two passes, one lane). Provisioned accounts
default to ordinary users with unverified email and MFA disabled. The offline
operator may explicitly assign `"role": { "Admin": { "level": 2 } }` to an
initial administrator; the level must be positive. This field is not accepted
by public registration. Enroll MFA on that administrator before operations that
require recent interactive MFA.

The native provisioning document also accepts `scim_credentials`, an array of
objects with `token`, `scopes`, optional `event_audience` and optional RFC 3339
`expires_at`. Use a separately generated token of at least 32 bytes, the shared
`scim:read` / `scim:write` / `scim:events` scopes as appropriate, and an event
receiver audience when polling SETs. D1 receives only the token digest; the
provisioner returns credential IDs and does not return those input tokens.
Preserve the private input or its credential-manager copy.

The higher-level bootstrap input forwards `users[].role`, `scim_credentials`,
`services` and `service_secrets` into this process. It generates a service
data-encryption key unless one is explicitly provided and saves the service
secrets with the other recovery material. Machine-only bootstrap intentionally
starts with the minimal service-client configuration; additional service modules
and advanced client registrations can use the native provisioner and a
coordinated deployment.

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
npx wrangler secret put NAZO_SERVICE_SECRETS --config ../../wrangler.toml
```

Set `NAZO_DUMMY_PASSWORD_HASH` from the generated `dummy_password_hash`,
`NAZO_SIGNING_KEY` from the original Base64 wrapping key, and
`NAZO_CLIENT_SECRET_PEPPER` from the original pepper. Supply the service-secrets
JSON separately, and set `NAZO_DCR_INITIAL_ACCESS_TOKEN` when selecting dynamic
registration. Set `NAZO_SIGNING_KEY_ID`
and copy the exact provisioned configuration into `NAZO_CONFIG` in the root
`wrangler.toml`. Input, SQLite,
SQL and credential output are private deployment material. Import seed rows only
into a fresh migrated database. The command refuses to overwrite an existing file.

```sh
npm run deploy
```

The Worker refuses to create missing issuer signing keys in a request. The machine-only
profile allows OAuth server metadata, JWKS, service token issuance and token
management, and does not expose interactive authorization or password endpoints.
The password-enabled profile admits the shared HTTP routes; operations still
require the available adapters and selected modules described above.

Parsed keys and the
completed application graph are reused within an isolate. The shared key manager
advances persisted lifecycle state; a request refreshes its snapshot at most once
per minute. Automatic signing-key generation, prepublication, activation and
retirement follow the shared 30-day policy with 24-hour prepublication and
verification-grace windows. Include replacement RSA key generation in the
selected plan's CPU measurements.

To change the signing wrapping key, prepare one coordinated deployment with a
new `NAZO_SIGNING_KEY_ID` and `NAZO_SIGNING_KEY`, the old identifier in
`NAZO_SERVICE_SECRETS.previous_signing_wrapping_key.id`, and the old key in the
private `NAZO_PREVIOUS_SIGNING_KEY` binding. The current and previous identifiers
must differ. The previous key is accepted only for reading; shared key management
authenticates the existing generation and atomically reseals it under the current
key during startup or refresh. This transition preserves the signing material
and its public JWKS. Missing, malformed or incorrect old-key material fails
closed; it does not initialize a replacement keyset.

Cloudflare version settings can inherit the existing secret binding under the
fixed previous-key name without exporting its value. Preserve all other service
secret fields when preparing the transition. Direct key bytes in the
`previous_signing_wrapping_key` JSON object are rejected, so there is only one
source of previous-key material. Changes to either secret invalidate the
isolate's prepared graph.

After the authoritative D1 generation is sealed with the new identifier and all
serving versions can read it, remove the previous-key identifier and binding
together in a subsequent deployment. An old version with only the former current
key cannot read the resealed generation; coordinate traffic and any rollback
accordingly. Public token/JWKS checks and the D1 generation's wrapping-key
identifier establish the transition outcome independently of the longer
signing-key rotation lifecycle.

## Authenticated ingress

`direct_cloudflare` requires the SDK's platform `Cf` extension and exactly one
valid `CF-Connecting-IP`; it rejects `CF-Worker` and the cross-zone Worker source
placeholder. Install a zone WAF rule blocking `cf.worker.upstream_zone ne ""`
as described in [Cloudflare's Worker-subrequest rule](https://developers.cloudflare.com/waf/custom-rules/use-cases/block-worker-subrequests/).
Do not expose this Worker through service bindings or another Worker. Keep Pseudo
IPv4 in `Off` or `Add Header` mode.

Same-zone Worker scripts can change `x-real-ip`, which can change
`CF-Connecting-IP`. Enforce the WAF restriction above before trusting that header.
[Cloudflare's request-header documentation](https://developers.cloudflare.com/fundamentals/reference/http-headers/)
defines these facts. Zone-rule and same-zone Worker administrators belong to the
trusted deployment boundary.

The adapter supplies `ConnectionFacts.authenticated_client_ip`, leaving native
socket-peer and TLS-SNI values absent. The neutral facade uses this explicit
source for source-based policy. With `services.mtls` enabled, the host separately
captures Cloudflare's platform client-certificate metadata before HTTP conversion
and supplies the parsed, fingerprint-matched certificate facts. Managed/approved
certificate trust and registered client selectors remain independent checks.
Ordinary forwarding/certificate headers cannot override either source of
authority. Tenant admission uses the original URI authority.

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

JS/WASM transfer and response serialization copy bytes across heaps.
Password verification holds one
memory-hard workspace at a time per isolate because it never suspends while the
workspace is allocated.

One D1 database processes queries one at a time. Independent issuers/tenants can
use independent deployments; never split one authority's transaction across
databases. Measure the actual region, crypto algorithms, login/token mix and D1
latency. The [D1 FAQ](https://developers.cloudflare.com/d1/reference/faq/) describes
throughput/overload behavior; [Workers limits](https://developers.cloudflare.com/workers/platform/limits/)
cover isolate memory, CPU and bundle/startup limits. Measure production capacity
on the selected Cloudflare plan and regions.

## Verification

```sh
cargo test --locked -p nazo-http-worker -p nazo-oauth-server-d1 \
  -p nazo-server-worker \
  --features nazo-oauth-server-d1/local-sqlite,nazo-server-worker/provisioning
python3 scripts/check_worker_portability.py
cargo test --locked -p nazoauth --test deployment_profile
cargo test --locked -p nazoauth --no-default-features --test deployment_profile
node deploy/cloudflare/build-web.mjs
npm run bundle --prefix deploy/cloudflare
npm test --prefix deploy/cloudflare
```

The integration suite loads the actual WASM in local workerd with a locally
provisioned D1 binding. It exercises the selected modules along with discovery/JWKS,
login/session cookies, authorization code and PKCE, refresh, UserInfo, revocation,
DPoP nonce/replay, concurrent one-time consumption, binding changes, isolate
restart and storage failure. It prints local cold-start and concurrent Client
Credentials timings. SQL tests execute production statements for rollback,
isolation, expiry, required effects and CAS, including the identity and credential
adapters. Transport tests use the shared facade conformance kit. The Web build
runs its overlay tests, TypeScript build and source/distribution security checks.
Test configured providers and public ingress against the deployed HTTPS issuer.

The local workerd suite creates and destroys isolated databases.
Do not reuse that fixture against a deployed D1 binding. Public acceptance has
a separate opt-in runner and uses only dedicated test identities and clients:

```sh
NAZO_WORKER_ACCEPTANCE_INPUT=/private/worker-acceptance.json \
NAZO_WORKER_ACCEPTANCE_OUTPUT=/private/worker-acceptance-result.json \
NAZO_WORKER_ACCEPTANCE_AUTHENTICATOR=/private/worker-acceptance-passkey.json \
node --test deploy/cloudflare/test/public-acceptance.mjs
```

Ordinary `npm test` skips this test when `NAZO_WORKER_ACCEPTANCE_INPUT` is absent.
The input is a private JSON object with the following fields. Provisioned fixture
clients must belong to the selected tenant and allow the grants exercised by the
run. When explicitly supplied with administrator, SCIM or DCR authority, the
runner creates its own uniquely named users/clients and retires them afterward.
It never initializes a database or replaces a real user's account. The dedicated
administrator fixture is separate from the synthetic Passkey user.

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
| `full_profile` | Set to `true` for the password-enabled deployment; used to check password-route admission |
| `administrator` | Dedicated `{ user_id, email, password }` for an offline-provisioned administrator of level 2 or above, initially without MFA. The runner enrolls and exercises MFA, uses recent interactive MFA for its synthetic management targets, then disables MFA and logs out during cleanup. Requires the full profile. |
| `scim` | Dedicated `{ token, audience }` with the scopes required for SCIM mutations and SET polling |
| `mtls` | Private actual-TLS fixture: `certificate_pem`, `private_key_pem`, `subject_dn`, `public_jwk`, and base64url SHA-256 `thumbprint`. The issuer hostname must collect and trust the certificate. CIBA requests opt into this certificate-bearing transport; caller certificate headers are never used. |
| `digital_credentials` | Explicit issuer/verifier management tokens, subject/configuration IDs, credential type/claims, accepted wallet endpoint and pinned trust-anchor certificate for the wallet acceptance flow |
| `modules` | Enabled module names to include in the run |
| `race_concurrency` | Optional one-use race width, bounded to 2–16; defaults to 4 |
| `workload` | Optional `{ "requests": 128, "concurrency": 8 }` adds private-key Client Credentials samples after protocol tests; capped at 256 requests and concurrency 16 |
| `runtime_modules` | Optional `{ "expected_issuer": "https://your-issuer.example" }` explicitly enables temporary Device/JWT Bearer runtime changes using the dedicated administrator's interactive MFA session. Both targets must initially be enabled, fully applied and have no enabled dependents. The runner checks revision CAS, canonical events, stored-transaction drain, metadata, rejection of new work and restoration. It uses current revision ownership for cleanup and reports any need for operator intervention instead of overwriting another administrator's change. |

The result contains normalized paths, timestamps, HTTP statuses, durations and
fixed failure descriptions. Secret transaction identifiers in CIBA/credential
paths are redacted. It excludes tokens, cookies, assertion bodies, MFA material,
credential bodies and private keys.
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
one-use state. Test browser enrollment and login with a real authenticator on
the issuer origin, including the setup/login pages and an authorization-code
redirect through consent. Include biometrics, cross-device transport and recovery
when those paths are used by the deployment.

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
Report the client's actual Cloudflare 1102 pages and telemetry coverage as
separate counts. Keep password/MFA phases identifiable, and retain each run's
outcomes for both mixed workloads and isolated protocol tests. Classify a
platform error during a negative security test as a platform failure; rerun
that case to check the expected application rejection.
Cloudflare's [CPU limit documentation](https://developers.cloudflare.com/workers/platform/limits/#cpu-time)
excludes network/database waiting from CPU time and allows occasional over-limit
execution. Use the invocation outcome to identify CPU rejection. Error 1102 can
represent CPU or memory exhaustion; the outcome distinguishes them. Report
platform CPU and HTTPS wall time separately.

Production acceptance also needs the applicable OAuth/OIDC conformance plans
against the deployed HTTPS issuer, direct-ingress WAF verification and target
region concurrency/latency measurements. Existing native OIDF records apply to
their recorded deployment/version.
