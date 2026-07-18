# OIDF Public Black-Box Conformance Runbook

## Purpose

This runbook defines the required process for OpenID Foundation conformance
regressions. The suite is verification evidence only. Implementation decisions
must come from the applicable RFC, OpenID, FAPI, OpenID4VC, HAIP, or security BCP
text, not from the behavior of one suite module.

## Non-Negotiable Boundaries

| Boundary | Requirement |
|---|---|
| Specification authority | Implement the normative protocol and security profile first. If a suite result conflicts with a current specification or documented security policy, fix the implementation only when the implementation is wrong. Otherwise update the matrix, expected-skip record, or documentation. |
| Public black-box target | The tested issuer must be an operator-provided public HTTPS origin. Repository workflows and generated runtime files must not default to a repository-owned production issuer. |
| No private target leakage | Generated plan configs and committed docs must not contain private suite hostnames, internal reverse-proxy names, localhost issuer URLs, or private trust-root endpoints as the tested issuer. |
| Control plane separation | A local conformance-suite control plane may be used to drive the tests, but the issuer under test must remain the public HTTPS origin. The control plane address is not conformance evidence. |
| No test-only product behavior | Product code must not branch on suite aliases, suite hostnames, test plan names, or conformance-specific request shapes. |
| Deterministic seeding only | The runner may seed clients, public keys, certificate bindings, redirect URIs, scopes, and test users only from the same generated material family used by the executed plan configs. It must not manually edit protocol state to manufacture a pass. |
| Seed verification | Deployment must verify that seeded client JWKS public members, mTLS certificate bindings, redirect URIs, scopes, grants, authentication methods, and CIBA delivery metadata match the executed runner material before the issuer is tested. |
| Exact evidence | Record the commit SHA, deployed runtime revision, target-issuer placeholder, suite version, plan set, expected skips, review allowances, artifact digests when available, and run URLs. |

## Correct Flow

1. Confirm the implementation boundary.

   - Read the relevant specification sections and security BCPs.
   - Identify mandatory behavior, optional behavior, unsupported behavior, and
     explicit security-policy refusals.
   - Add local positive, negative, metadata-truth, and security-boundary tests
     before using suite output as evidence.

2. Generate runtime conformance material for the target issuer.

   - The operator must supply the public issuer and one primary suite base
     origin.
   - `OIDF_SUITE_BASE_URL` is a single HTTPS origin. It is not a comma-separated
     list. Additional callback origins must use
     `OIDF_LOCAL_EXTRA_SUITE_BASE_URLS` and must be validated as separate HTTPS
     origins.
   - The generated configs must use only public HTTPS URLs for protocol-visible
     issuer, redirect, logout, notification, credential, and verifier endpoints.
   - Scan generated configs before running the suite. Internal hostnames,
     localhost issuer URLs, and private reverse-proxy names are failures.

3. Seed from material derived from the executed runner configs.

   - Local/public dry runs must seed from the same generated runner configs
     that will execute the run. For private-key clients, the runner config
     contains the private key and the seed process must derive and store only
     the public JWK members.
   - A public seed artifact that omits private key members is a deployment
     artifact, not an executable runner config. It must not overwrite runner
     private JWKS, client secrets, initial access tokens, server metadata, or
     browser automation fields.
   - Official runs must seed from the official workflow material for that run.
     If an official artifact is intentionally public-only, use it only for
     production seeding and keep the official runner's executable private
     material separate.
   - Do not mix local suite keys, certificates, callback URLs, client JWKS, or
     CIBA notification metadata with official-suite material.
   - FAPI-CIBA ID1 has two independent dimensions: client authentication
     (`private_key_jwt` or mTLS) and access-token sender constraint. All four
     supported FAPI-CIBA ID1 combinations (`private_key_jwt / mTLS` x
     `poll / ping`) must seed mTLS holder-of-key access-token policy. Do not
     treat `private_key_jwt` client authentication as a bearer-token profile.
   - Do not treat a successful artifact copy or CA installation as sufficient.
     The deployment must run the seeding binary from the exact candidate image
     and fail closed if the database state does not match the runner-derived
     public material.

4. Run the public black-box matrix.

   - Run concurrency-safe plans in parallel.
   - Split plans that share browser session state, polling state, callback
     aliases, or CIBA transaction state into isolated batches.
   - OpenID4VC issuer/verifier driver plans must use bounded plan groups for
     official-suite execution. Each group must receive only the expected
     skip/warning records whose `configuration-filename` belongs to that group.
     Grouping is allowed only as runner scheduling; it must not remove plan
     expressions or change product behavior.
   - Front-channel logout and session-management plans remain isolated from the
     main parallel matrix.
   - FAPI-CIBA poll and ping variants must not share one mutable CIBA transaction
     alias in the same batch.

5. Interpret suite output.

   - `FAILURE` or unexpected `WARNING` is not acceptable.
   - Expected-warning allowlists are not a substitute for protocol behavior. An
     expected warning is acceptable only when the suite condition text itself
     permits the deployed policy and the allowlist binds the exact plan,
     configuration, variant, block, and condition. OpenID4VC/HAIP refresh-token
     advisories follow this rule: the policy is client-specific refresh-token
     issuance, not a wildcard warning waiver. If the official runner marks that
     same advisory module as `SKIPPED`, the expected skip must bind the same
     configuration and variant; it must not use a wildcard.
   - `SKIPPED` is acceptable only when it matches the committed expected-skip
     allowlist for the exact configuration and module.
   - `REVIEW` is acceptable only when the committed review allowlist identifies
     the exact plan, configuration, alias, and module.
   - A new skip, review, warning, or module interruption requires diagnosis.

6. Run the official suite only after the public black-box matrix passes.

   - Restore or seed the official client material from the official artifact.
   - Reconfirm the deployed runtime revision and public issuer health.
   - Start the official matrix and keep local/public evidence separate from
     official evidence.

7. Merge only after all gates are satisfied.

   - PR checks must pass, except checks explicitly declared out of scope for the
     change by the repository owner.
   - The public black-box matrix must pass.
   - The official suite matrix must pass.
   - The conformance record must be updated with the final evidence.

## Required Artifact Hygiene

Before any public or official run, verify:

- generated plan files contain the intended public issuer placeholder or
  operator-supplied public issuer only;
- no generated plan file uses an internal hostname as the tested issuer;
- expected skips are generated per batch, not reused as a broad global bypass;
- OpenID4VC expected warnings are generated per batch, not reused as a broad
  global bypass;
- review allowances are bound to exact plan/config/module triples;
- seed inputs and executed plan configs come from the same material generation;
- executable runner configs retain required private key material, client
  secrets, initial access tokens, server metadata, browser automation fields,
  and hosted-UI login fields;
- public-only seed artifacts are never used as executable runner configs;
- no seeded redirect URI, post-logout redirect URI, front-channel URI, CIBA
  notification URI, credential URI, or verifier URI contains a comma-joined
  origin;
- the deployed service reports the commit SHA being tested.

## Cheating Definition

The following are prohibited:

- adding product behavior that recognizes a suite plan, alias, hostname, or
  module name;
- weakening validation only for conformance clients;
- using local or private issuer URLs as the test target while claiming public
  conformance evidence;
- editing database protocol state to bypass authentication, consent, polling,
  issuance, revocation, or callback behavior;
- accepting unexpected skips, reviews, warnings, or interruptions without a
  committed, bounded rationale;
- mixing official-suite client material with local-suite material in the same
  evidence run.

## Failure Handling

When a suite failure appears:

1. Identify the first protocol-visible failure, not only the final runner exit
   code.
2. Compare the observed behavior with the relevant specification.
3. If implementation behavior is wrong, fix the implementation and add a local
   regression test at the protocol boundary.
4. If the suite input or matrix is wrong, fix generation, seeding, batching, or
   expected-skip/review metadata without changing product protocol behavior.
5. Re-run the affected public black-box batch first, then the full public
   matrix, then the official matrix.

## Recording Results

A conformance result record must include:

- implementation commit SHA;
- deployed runtime revision;
- suite version or source commit;
- sanitized target issuer;
- plan set and batching mode;
- expected skip count and exact reason;
- review count and exact reason;
- condition success, warning, and failure counts;
- artifact names and digests when available;
- official run URLs when official evidence is claimed.
