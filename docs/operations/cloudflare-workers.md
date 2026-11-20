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
and `/consent`. The password profile requires a separately hosted frontend.

| Capability | Workers profile |
| --- | --- |
| Discovery and JWKS | Shared metadata and key lifecycle |
| Authorization | Authorization code with PKCE and interactive consent |
| Tokens | Code redemption, refresh, Client Credentials, revocation and UserInfo |
| Sender constraints | DPoP proof, nonce and replay state |
| Identity | Machine-only, password-enabled full profile, or Passkey-only with offline initial setup; passkey credentials, single-use challenges, sessions and logout share existing services |
| Optional modules | Inline Request Objects/PAR, JARM and Session Management, explicitly selected at provisioning |
| Keys | Encrypted persistent key generations; portable signing and verification |
| Audit | Required evidence commits with the accepting mutation; append-only D1 audit rows |
| Unavailable | Native administration/process signers, mTLS, remote documents, federation, device/CIBA, Token Exchange, Native SSO, DCR, SCIM, OpenID4VC, MFA, email registration, profile editing/application lists, avatar/object storage and native audit anchors/roles |

Configuration rejects unavailable modules and unknown native fields. Persisted
module selection must match the deployment. Discovery uses that selected
snapshot. Unavailable storage/network operations return explicit failures.
Client provisioning rejects unsupported grants, remote documents, mTLS and
frontchannel/backchannel logout. Cloudflare Workflows are not required.

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
profile makes a single pass of at most 500 rows; cleanup does not run a
multi-pass loop against Free's 10 ms Cron CPU budget. This lets cleanup catch up with replay traffic while
bounding each transaction and the scheduled work.

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
Free and Paid now accept up to 64 MiB uncompressed (this Worker is approximately
8.5 MiB). **Workers Free** has 100,000 requests/day, 10 ms CPU per HTTP request
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
hostname). A separately hosted normal login/consent frontend remains required.
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
| `modules` | Optional array of `request_objects`, `jarm`, `session_management` |
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
management, and does not expose any interactive authorization or password
endpoints. The full profile retains the complete endpoint set documented above.

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

The cache checks the platform-generated `NAZO_VERSION.id` and compares the six
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
D1 binding. It covers discovery/JWKS, login/session cookies, authorization code
and PKCE, refresh, UserInfo, revocation, DPoP nonce/replay, concurrent one-time
consumption, binding changes, isolate restart and storage failure. It prints local cold-start and
concurrent Client Credentials timings. SQL tests execute production statements
for rollback, isolation, expiry and CAS. Transport tests use the shared facade
conformance kit.

Production acceptance also needs the applicable OAuth/OIDC conformance plans
against the deployed HTTPS issuer, direct-ingress WAF verification and target
region concurrency/latency measurements. Existing native OIDF records apply to
their recorded deployment/version.
