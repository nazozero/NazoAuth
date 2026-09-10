# Protocol Source Freshness

Mutable-source review: 2026-09-09. The inventory contains 104 sources, including
six immutable RFC references added for the integration guides on 2026-09-10;
four expired individual drafts remain on the watchlist and intentionally fail
the online freshness gate. This date does not claim an implementation audit.

NazoAuth tracks official protocol sources in
`requirements/spec-freshness.json`. Search indexes and previously cloned test
suites are not version authorities.

## Current official baseline

| Source | Current official baseline |
| --- | --- |
| OAuth 2.1 | `draft-ietf-oauth-v2-1-16` |
| Browser-Based Applications | `RFC 10017` |
| Attestation-Based Client Authentication | `draft-ietf-oauth-attestation-based-client-auth-11` |
| Transaction Tokens | `draft-ietf-oauth-transaction-tokens-11` |
| Client ID Metadata Document | `draft-ietf-oauth-client-id-metadata-document-02` |
| Security BCP Update | `draft-ietf-oauth-security-topics-update-03` |
| Refresh Token and Authorization Expiration | `draft-ietf-oauth-refresh-token-expiration-03` |
| First-Party Applications | `draft-ietf-oauth-first-party-apps-04` |
| Identity and Authorization Chaining Across Domains | `draft-ietf-oauth-identity-chaining-17` |
| Token Status List | `draft-ietf-oauth-status-list-21` |
| JWT Best Current Practices bis | `draft-ietf-oauth-rfc8725bis-10` |
| SPIFFE Client Authentication | `draft-ietf-oauth-spiffe-client-auth-02` |
| Identity Assertion JWT Authorization Grant | `draft-ietf-oauth-identity-assertion-authz-grant-04` |
| JWT Client Authentication and Assertion-Based Grants bis | `draft-ietf-oauth-rfc7523bis-11` |
| Cross-Device Flows Security BCP | `RFC 10027` |
| SD-JWT VC | `draft-ietf-oauth-sd-jwt-vc-19` |
| Agent Authorization Profile | `draft-aap-oauth-profile-01`; expired 2026-08-11, watch only |
| Delegated Authorization | `draft-li-oauth-delegated-authorization-03` |
| Mission-Bound Authorization | `draft-mcguinness-oauth-mission-00` |
| Client Instance Assertion | `draft-mcguinness-oauth-client-instance-assertion-01` |
| Actor Profile / Proofs / Receipts | `draft-mcguinness-oauth-actor-profile-00`, `draft-mcguinness-oauth-actor-proofs-00`, `draft-mcguinness-oauth-actor-receipts-00` |
| Actor Chain | `draft-mw-oauth-actor-chain-01` |
| Authorization Evidence | `draft-liu-oauth-authorization-evidence-01` |
| Global Token Revocation | `draft-parecki-oauth-global-token-revocation-06`; expired 2026-08-29, watch only |
| RAR Metadata and Error Remediation | `draft-ietf-oauth-rar-metadata-remediation-00`; OAuth WG successor to the individual RAR metadata draft |
| Resource Metadata watchlist | `draft-skokan-oauth-resource-response-02` expired 2026-09-03; `draft-mcguinness-oauth-rfc9728bis-01` expired 2026-08-28 |
| Sender-Constraint watchlist | `draft-mw-oauth-tls-session-bound-tokens-07`, `draft-richer-oauth-httpsig-03` |
| Browser Session Handoff | `draft-moros-oauth-browser-session-handoff-00` |
| Layered Cookies | `draft-ietf-httpbis-layered-cookies-02` |
| FAPI 2.0 HTTP Signatures | working draft dated 2026-06-26 |
| FAPI-CIBA | working draft `fapi-ciba-03` dated 2026-06-26; implemented compatibility target remains stable `ID1` / draft 02 |
| Grant Management | working draft `oauth-v2-grant-management-03` built 2026-06-26; approved stable snapshot `ID1` |
| OpenID Connect Native SSO | draft 07 / Second Implementer's Draft |

The inventory also verifies the canonical pages and status markers for OIDC,
FAPI 2.0, OpenID4VC, OpenID Federation, and every immutable RFC used by active
protocol and integration documentation, including both integration translations.
The fixed OpenID4VCI draft-07 contract is an explicit profile pin in each guide;
it does not replace the separately tracked current draft.

## September source changes and implementation boundaries

The official draft texts and document histories were reviewed for adoption
consequences. Runtime behavior, metadata, and conformance claims are unchanged.

| Source change | Consequence |
| --- | --- |
| [OAuth 2.1, 15 to 16](https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-16.txt) | Adds value-size, PKCE plain-method and consent-phishing guidance. Existing draft-15 evidence does not establish draft-16 compliance; review request limits, client registration, consent and grant revocation before extending the claim. |
| [Browser-Based Applications, RFC 10017](https://www.rfc-editor.org/info/rfc10017) | Published August 2026. Retain the earlier draft-27 audit as historical evidence; final-RFC implementation review is pending. |
| [Cross-Device Security, RFC 10027](https://www.rfc-editor.org/info/rfc10027) | Published August 2026. Device Grant, CIBA, and Native SSO still need a requirement-by-requirement audit; publication alone does not establish support. |
| [Client Attestation, 10 to 11](https://www.ietf.org/archive/id/draft-ietf-oauth-attestation-based-client-auth-11.txt) | Changes challenge/DPoP nonce handling and client metadata. Keep the OpenID4VCI Final profile pinned to draft 07; adopting draft 11 requires a separate protocol and metadata audit. |
| [Transaction Tokens, 09 to 11](https://www.ietf.org/archive/id/draft-ietf-oauth-transaction-tokens-11.txt) | Document history identifies claim-text edits and a history typo fix. No TTS implementation or metadata is added. |
| [JWT BCP bis, 07 to 10](https://www.ietf.org/archive/id/draft-ietf-oauth-rfc8725bis-10.txt) | Clarifies nested-JWT handling, decompression limits, and deprecated algorithms. Algorithm/key/confusion and resource-limit audits remain pending; existing JWT support is not a bis-conformance claim. |
| [SD-JWT VC, 17 to 19](https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-19.txt) | Adds optional type aliases and revises HTTP retrieval, integrity, rendering-resource and SSRF rules; clarifies non-disclosable subclaims and removes transitional legacy media-type guidance. Existing credential-profile evidence remains scoped to the prior baseline pending a delta audit. |
| [Delegated Authorization, 02 to 03](https://www.ietf.org/archive/id/draft-li-oauth-delegated-authorization-03.txt) | Expands local delegation-chain restrictions and validation rules. Remains watch only; local Token Exchange does not establish this profile's support. |
| [RAR metadata WG adoption](https://datatracker.ietf.org/doc/draft-ietf-oauth-rar-metadata-remediation/) | Track the WG draft 00 in place of the replaced individual draft. This is a source transition, not a new runtime commitment. |
| [HTTP-signature PoP, 02 to 03](https://www.ietf.org/archive/id/draft-richer-oauth-httpsig-03.txt) | Changes runtime key presentation, asymmetric-key requirements and algorithm selection. Remains watch only and separate from the experimental FAPI HTTP Signatures implementation. |

The four expired watch entries are retained to detect future revisions, not
treated as active standards. The gate must continue reporting their expiry;
do not refresh dates, drop sources, or disable expiry checks to obtain a pass.
The existing OpenID working-draft markers, including the June 26 FAPI build
dates, still match their official pages.

## Checks

Offline schema and active-document validation:

```powershell
python scripts/check_spec_freshness.py --offline
```

Online validation against IETF Datatracker, RFC Editor, and upstream specification publishers:

```powershell
python scripts/check_spec_freshness.py
```

Pull requests touching protocol sources run the offline gate. A weekly and
manual workflow runs the online gate. When it reports drift, update the
inventory only after reviewing the normative delta and its implementation,
metadata, documentation, and conformance consequences.
