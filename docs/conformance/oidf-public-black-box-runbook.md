# Public Black-Box Conformance Runbook

This runbook defines the only supported process for OIDF conformance runs. The
system under test is the normal public production deployment. Conformance tools
must not receive database access, private service-network addresses, privileged
runtime mounts, or alternate protocol behavior.

## Standards and control-plane boundary

| Surface | Authority | Required boundary |
|---|---|---|
| OAuth client registration and management | [RFC 7591](https://www.rfc-editor.org/rfc/rfc7591.html), [RFC 7592](https://www.rfc-editor.org/rfc/rfc7592.html) | A conformance client follows the same application, approval, credential-delivery, registration, and management rules as any other client. |
| mTLS client authentication and certificate-bound access tokens | [RFC 8705](https://www.rfc-editor.org/rfc/rfc8705.html), [RFC 4514](https://www.rfc-editor.org/rfc/rfc4514.html), [RFC 4517](https://www.rfc-editor.org/rfc/rfc4517.html) | `tls_client_auth` and certificate-bound tokens remain independent capabilities. The authorization server requires one subject selector, canonical DN matching, type-aware SAN matching, and an optional narrowing certificate pin. |
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

## 2. Deploy the exact product commit

Deploy the normal runtime image and UI for the exact commit. Do not install
clients, credential datasets, or CA material by SQL, a migration, a server-side
provisioning binary, or a special container entrypoint. Verify the running OCI revision,
health endpoint, Discovery issuer, JWKS, UI assets, and rollback record.

## 3. Onboard clients through the production control plane

Run:

```sh
python scripts/apply_public_conformance_onboarding.py apply \
  --target-issuer "$OIDF_TARGET_ISSUER"
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

## 4. Install only the approved trust bundle

Install `runtime/oidf/approved-mtls-trust-anchors.pem` into the public reverse
proxy's client-certificate trust store using the deployment's normal atomic
configuration procedure. Record the bundle SHA-256, create a rollback copy,
validate the complete proxy configuration, reload, and confirm the public mTLS
alias. Do not install CA material directly from generated runner files.

The proxy validates the certificate chain. The authorization server still
enforces the registered RFC 8705 client subject selector and client policy.
Accepting a CA at the proxy does not authorize every certificate issued by it.

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
