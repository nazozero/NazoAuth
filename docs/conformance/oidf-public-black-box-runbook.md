# Public Black-Box Conformance Runbook

This runbook defines the only supported process for OIDF conformance runs. The
system under test is the normal public production deployment. Conformance tools
must not receive database access, private service-network addresses, privileged
runtime mounts, or alternate protocol behavior.

## Standards and control-plane boundary

| Surface | Authority | Required boundary |
|---|---|---|
| OAuth client registration and management | [RFC 7591](https://www.rfc-editor.org/rfc/rfc7591.html), [RFC 7592](https://www.rfc-editor.org/rfc/rfc7592.html) | A conformance client follows the same application, approval, credential-delivery, registration, and management rules as any other client. |
| CIBA token lifecycle | [OpenID Connect CIBA Core 1.0](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html) | A successful CIBA token response can include a refresh token. Client registration therefore permits `ciba + refresh_token` without inventing an authorization-code dependency; runtime issuance still requires the registered grant and `offline_access` policy. |
| Logout client metadata | [OpenID Connect Front-Channel Logout 1.0](https://openid.net/specs/openid-connect-frontchannel-1_0.html), [OpenID Connect Back-Channel Logout 1.0](https://openid.net/specs/openid-connect-backchannel-1_0.html) | Both `*_logout_session_required` values default to `false`. A client that needs `sid` explicitly registers the corresponding URI and opts in. |
| mTLS client authentication and certificate-bound access tokens | [RFC 8705](https://www.rfc-editor.org/rfc/rfc8705.html), [RFC 4514](https://www.rfc-editor.org/rfc/rfc4514.html), [RFC 4517](https://www.rfc-editor.org/rfc/rfc4517.html) | `tls_client_auth` and certificate-bound tokens remain independent capabilities. The authorization server requires one subject selector, canonical DN matching, and type-aware SAN matching. RFC 8705 Section 7.4's cross-CA spoofing boundary is enforced on the public CA-approval path by also requiring a narrowing leaf-certificate pin for `tls_client_auth`. |
| X.509 validation | [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280.html) | Only a current CA certificate with a supported public key, critical CA basic constraint, and critical `keyCertSign` use may enter a trust request. |
| Trust-anchor administration | [RFC 6024](https://www.rfc-editor.org/rfc/rfc6024.html) | RFC 6024 supplies the trust-anchor-management security model: authenticate and authorize the source, protect integrity, detect replay, constrain trust purposes, and retain recovery. The product control plane additionally requires a distinct approver, bounded reasons, append-only audit, and revocation. |
| OpenID4VC issuance and presentation | [OpenID4VCI 1.0](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html), [OpenID4VP 1.0](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html) | Protocol endpoints implement the specifications. Issuer dataset administration is not defined by OpenID4VCI and therefore remains an authenticated, CSRF-protected admin control plane; it is never advertised as a protocol endpoint. |

The absence of a standards-defined operator API is not permission to create an
unbounded endpoint. Non-standard control-plane operations must be least
privilege, same-origin, authenticated, CSRF-protected, size/depth bounded,
tenant-bound, fail closed, and durably audited.

Deployment safety policy limits a tenant to 128 distinct current trust anchors
and a client to 8 current trust anchors. A client may have 4 pending requests,
and one user may have 16 pending requests per tenant. Creation and approval take
a tenant-scoped database advisory lock, so concurrent requests cannot bypass
these limits. These numbers are product resource limits, not requirements
claimed by RFC 8705 or RFC 6024.

## Invariants

- The operator supplies the public HTTPS issuer and public HTTPS suite origin.
  The repository has no default deployment host.
- The public issuer in Discovery must equal the configured target origin.
- The suite reaches only public HTTPS endpoints. Private DNS names, raw IPs,
  loopback addresses, service-network aliases, and disabled TLS verification are
  forbidden.
- Product behavior cannot branch on plan names, suite aliases, callback paths,
  test headers, or a conformance build flag.
- Conformance preparation cannot execute SQL or load production server crates.
- Applicant and approver are distinct active accounts. The approver has a
  positive admin level. Automated identities follow the deployment's normal
  account lifecycle and do not bypass MFA policy.
- Every generated client has a dedicated run namespace and is deactivated after
  the run. Every approved test trust anchor is revoked after the run.
- Expected skips and reviews are exact tuples of configuration, plan, variant,
  and module. An unlisted skip, review, warning, or failure fails the run.
- A public suite runs with development-mode identity injection disabled. Its
  `/api/*` routes return `401` without a suite API token.

## 0. Secure the public suite operator

Register the suite's OIDC operator client through the same application and
approval flow used by other confidential clients. Its redirect URI is the
public HTTPS login callback supplied by the suite; internal ports, raw IPs, and
container hostnames are not registered as alternatives. The complete proxy
chain must preserve the public scheme, host, and port so Spring generates the
same callback and post-login origin seen by the browser.

Disable the suite's development profile before exposing it. A normal,
non-administrator user then signs in through OIDC and creates a short-lived API
token through the suite's `/api/token` endpoint. Store that token in a
root-readable runtime secret file and verify both boundaries before scheduling
plans: bearer access returns `200`, while the same API request without the
token returns `401`. Do not create suite tokens in MongoDB, reuse a product
administrator session as a suite bearer token, or depend on a source-control
provider account.

## 1. Prepare immutable runner material

Check out the exact commit to be deployed and require a clean worktree. Set
caller-supplied values:

```sh
export OIDF_TARGET_ISSUER=https://issuer.example
export OIDF_MTLS_TARGET_ISSUER=https://mtls.issuer.example
export OIDF_SUITE_BASE_URL=https://suite.example
export OIDF_APPLICANT_EMAIL=conformance-applicant@example.com
export OIDF_APPLICANT_PASSWORD=...
export OIDF_ADMIN_EMAIL=conformance-approver@example.com
export OIDF_ADMIN_PASSWORD=...
export OIDF_DYNAMIC_REGISTRATION_INITIAL_ACCESS_TOKEN=...
export OIDF_CIBA_AUTOMATED_DECISION_TOKEN=...
python scripts/prepare_oidf_black_box.py
```

The command generates runner configurations, keys, certificates, an onboarding
manifest, and exact plan/skip/review registries under `runtime/oidf`. These are
test-runner inputs, not production records. They contain no authority to mutate
the target database.

When the official runner configuration is stored in the repository's encrypted
material, export it without creating suite plans:

```sh
gh workflow run oidf-conformance-full.yml \
  --ref <exact-branch> \
  -f target_issuer=https://issuer.example \
  -f onboarding_material_only=true
```

This mode calls the reusable onboarding-material workflow, validates the bundle,
and uploads the private artifact. Both conformance jobs are skipped. Download and
verify that artifact at the same source commit before step 3. The artifact still
has no production authority: client creation and CA approval remain separate
applicant and administrator operations through the public control plane.

Convert the verified official artifact into production applications without
generating replacement clients, keys, or certificates:

```sh
python scripts/prepare_official_oidf_public_onboarding.py \
  --artifact-directory runtime/official-onboarding \
  --expected-source-commit <deployed-sha> \
  --target-issuer "$OIDF_TARGET_ISSUER" \
  --suite-base-url "$OIDF_SUITE_BASE_URL" \
  --applicant-email "$OIDF_APPLICANT_EMAIL" \
  --output-dir runtime/official-onboarding-apply
```

The converter verifies the artifact manifest and certificate bundle again,
checks the applicant-email commitment, and emits exactly 53 unique applications
for the current full OIDC/FAPI/CIBA/OpenID4VC matrix. It does not contact the
database or create a client.

Keep the official OpenID4VC mTLS identities in the dedicated
`OPENID4VC_OIDF_MTLS_CONFIG_JSON` repository secret. Its schema is one `ca`
certificate plus `mtls` and `mtls2` objects containing `cert` and `key`. The
base protocol configuration must not duplicate that rotating identity material.
Both the onboarding export and the official runner overlay the same secret, so
the approved CA, exported leaf certificates, and the private keys actually used
by the suite cannot drift. The public artifact strips every private key and
cryptographically verifies each leaf against its declared CA before upload.

Keep the OIDC/FAPI mTLS identities in the age-encrypted repository asset
`docs/conformance/oidf-mtls-material.json.age`; keep only its decryption
identity in the `OIDF_MTLS_MATERIAL_AGE_IDENTITY` repository secret. The public
plan template contains no environment certificate or private key. Both the
onboarding exporter and official runner must apply this same material after all
derived FAPI-CIBA configurations exist. The material has one dedicated CA and
one client certificate/private key per logical mTLS client, so client IDs,
certificates, and private keys rotate as one source-bound set.

Use `scripts/generate_oidf_mtls_material.py` only as an operator-controlled
identity rotation step. It creates an RSA-3072 CA with critical `CA:TRUE` and
critical `keyCertSign`, and RSA-2048 end-entity certificates restricted to
`clientAuth`. Encrypt the output immediately and remove the plaintext plus CA
private key. This creates external client cryptographic identities; it does not
create production client records or grant trust. The latter actions still go
through the applicant/approver flow. Artifact export rejects a CA whose Basic
Constraints or Key Usage would be rejected by the production trust-request
endpoint, including a missing or non-critical `keyCertSign` extension.

Generate OpenID4VC material from the checked-out product commit for every run.
Do not copy a prior run's `openid4vc-plan-configs.json`, driver, or expected
result registries into a new run directory. Public onboarding replaces logical
wallet identifiers with approved client identifiers, so an already-applied
configuration is an output, not a reusable source. Before installing a
credential dataset or creating a suite plan, the OpenID4VC wrapper now requires
the current 17-plan registry, the same 17 configuration files, the exact driver
alias set, seven bounded skips, and four bounded HAIP warnings to agree. Any
cross-run or stale combination fails before a production mutation.

## 2. Deploy the exact product commit

Deploy the normal runtime image and UI for the exact commit. Do not install
clients, credential datasets, or CA material by SQL, a migration, a server-side
provisioning binary, or a special container entrypoint. Verify the running OCI revision,
health endpoint, Discovery issuer, JWKS, UI assets, and rollback record.

## 3. Onboard clients through the production control plane

Run:

```sh
python scripts/apply_public_conformance_onboarding.py apply \
  --target-issuer "$OIDF_TARGET_ISSUER" \
  --manifest runtime/official-onboarding-apply/oidf-onboarding-manifest.json \
  --plan-configs runtime/official-onboarding-apply/oidf-plan-configs.json \
  --delivered-client-material runtime/official-onboarding-apply/oidf-delivered-client-material.json \
  --state-file runtime/official-onboarding-apply/oidf-onboarding-state.json \
  --trust-bundle runtime/official-onboarding-apply/approved-mtls-trust-anchors.pem \
  --no-runner-env
```

For every client, the tool performs the same public operations available to an
operator:

1. applicant login;
2. client-access application;
3. review by a distinct administrator;
4. one-time credential delivery to the applicant;
5. replacement of logical runner identifiers with delivered identifiers;
6. CA trust application for clients that need mTLS;
7. review by the distinct administrator;
8. export of the currently approved tenant trust bundle.

All requests are exact-origin HTTPS requests with normal certificate
verification, redirects disabled, response-size limits, JSON content checks,
and CSRF tokens on mutations. The resulting state and bundle are private files.
After a successful apply, install the delivered-client material as the private
`OIDF_DELIVERED_CLIENT_MATERIAL_JSON` repository secret through standard input.
The official OIDC and OpenID4VC workflows refuse to start without it and bind it
to both the selected target issuer and suite origin. This mapping contains the
actual client identifiers and the few generated client secrets; it replaces
only exact `client_id` fields in private runner configuration. It is never a
server seed and is removed after cleanup.
The state file is created before the first public mutation and atomically
updated after every application, approval, credential delivery, and trust
decision. A failed or interrupted apply must be cleaned up before another apply;
cleanup rejects journaled pending applications, revokes approved trust anchors,
and deactivates delivered clients through the same public control plane.

## 4. Install only the approved trust bundle

Install `runtime/oidf/approved-mtls-trust-anchors.pem` into the public reverse
proxy's client-certificate trust store using the deployment's normal atomic
configuration procedure. Record the bundle SHA-256, create a rollback copy,
validate the complete proxy configuration, reload, and confirm the public mTLS
alias. Do not install CA material directly from generated runner files.

The proxy validates the certificate chain. The authorization server still
enforces the registered RFC 8705 client subject selector and client policy.
PKI clients admitted through the public CA-approval path must also match their
administrator-registered leaf-certificate pin. Accepting a CA at the proxy does
not authorize every certificate issued by it at the OAuth layer.

## 5. Install dedicated OpenID4VC evidence through the admin API

OpenID4VC runner datasets use a dedicated, explicitly marked conformance user.
The driver logs in to the same public issuer as an administrator and writes only
the configured subject's bounded dataset through
`/admin/openid4vci/credential-datasets/{subject}/{configuration}`. The endpoint
requires an admin session and CSRF token, validates the configured credential
format and validity window, rejects reserved claims and structural abuse, and
records mutation and audit events in one transaction.

The dataset endpoint is an issuer administration surface, not an OpenID4VCI
protocol endpoint. The driver deletes the dataset in `finally`; cleanup failure
fails the run.

## 6. Run the complete public matrix

Run the complete repository matrix against the public issuer. Concurrency-safe
plans may run concurrently. Logout, session-management, and other browser-state
sensitive plans run in isolated jobs. A longer terminal wait absorbs legitimate
suite completion latency; it does not relax protocol assertions.

Do not substitute targeted plans for full-matrix evidence. Targeted plans are
diagnostic only. Preserve the exact target commit, public origins, plan IDs,
module results, expected-skip/review match, and runner version.

## 7. Run the official suite

Request the official OIDF run only after the complete public black-box matrix
passes on the exact deployed commit. Official configuration material must be
onboarded through the same production control plane. Do not overwrite existing
client credentials or trust records by replaying local runner material.

Observe module status directly in the official suite. CI is useful delivery
evidence but is not a substitute for the suite's terminal module results.

## 8. Cleanup and evidence

Always run:

```sh
python scripts/apply_public_conformance_onboarding.py cleanup \
  --target-issuer "$OIDF_TARGET_ISSUER"
```

Cleanup revokes approved trust requests and deactivates created clients through
the public admin API. Remove installed CA bytes only after the proxy rollback
procedure confirms the previous trust configuration. Retain redacted results,
the exact commit, plan manifest, bundle digest, approval/revocation audit IDs,
and official run IDs. Never retain passwords, private keys, session cookies,
CSRF tokens, client secrets, or one-time delivery tokens in documentation.
