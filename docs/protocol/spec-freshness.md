# Protocol Source Freshness

Mutable-source review: 2026-11-11. Four expired watch entries remain in the
inventory: AAP, Global Token Revocation, Resource Response and Browser Session
Handoff. The online gate reports their reviewed expiry and fails if the
revision, expiry or publication status changes. Implementation support is
listed separately in the profile matrix.

NazoAuth tracks official protocol sources in
`requirements/spec-freshness.json`. Search indexes and previously cloned test
suites are not version authorities.

## Current official baseline

| Source | Current official baseline |
| --- | --- |
| OAuth 2.1 | `draft-ietf-oauth-v2-1-17` |
| Browser-Based Applications | `RFC 10017` |
| Attestation-Based Client Authentication | `draft-ietf-oauth-attestation-based-client-auth-12` |
| Transaction Tokens | `draft-ietf-oauth-transaction-tokens-11` |
| Client ID Metadata Document | `draft-ietf-oauth-client-id-metadata-document-03` |
| Security BCP Update | `draft-ietf-oauth-security-topics-update-03` |
| Refresh Token and Authorization Expiration | `draft-ietf-oauth-refresh-token-expiration-03` |
| First-Party Applications | `draft-ietf-oauth-first-party-apps-04` |
| Identity and Authorization Chaining Across Domains | `draft-ietf-oauth-identity-chaining-17` |
| Token Status List | `draft-ietf-oauth-status-list-21` |
| JWT Best Current Practices bis | `draft-ietf-oauth-rfc8725bis-10` |
| SPIFFE Client Authentication | `draft-ietf-oauth-spiffe-client-auth-03` |
| Identity Assertion JWT Authorization Grant | `draft-ietf-oauth-identity-assertion-authz-grant-06` |
| JWT Client Authentication and Assertion-Based Grants bis | `RFC 10070` |
| Cross-Device Flows Security BCP | `RFC 10027` |
| SD-JWT VC | `draft-ietf-oauth-sd-jwt-vc-26` |
| Agent Authorization Profile | `draft-aap-oauth-profile-01`; expired 2026-08-11, watch only |
| Delegated Authorization | `draft-li-oauth-delegated-authorization-04` |
| Mission-Bound Authorization | `draft-mcguinness-oauth-mission-02` |
| Client Instance Identification | `draft-mcguinness-oauth-client-instance-id-01`; watch only |
| Actor Profile / Proofs / Receipts | `draft-mcguinness-oauth-actor-profile-01`, `draft-mcguinness-oauth-actor-proofs-01`, `draft-mcguinness-oauth-actor-receipts-01` |
| Actor Chain | `draft-mw-oauth-actor-chain-03` |
| Authorization Evidence | `draft-liu-oauth-authorization-evidence-02` |
| Global Token Revocation | `draft-parecki-oauth-global-token-revocation-06`; expired 2026-08-29, watch only |
| RAR Metadata and Error Remediation | `draft-ietf-oauth-rar-metadata-remediation-00`; OAuth WG successor to the individual RAR metadata draft |
| Resource Metadata watchlist | `draft-skokan-oauth-resource-response-02` expired 2026-09-03; `draft-mcguinness-oauth-rfc9728bis-02` renewed |
| Sender-Constraint watchlist | `draft-mw-oauth-tls-session-bound-tokens-07`, `draft-richer-oauth-httpsig-03` |
| Browser Session Handoff | `draft-moros-oauth-browser-session-handoff-00`; expired 2026-10-19 |
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

## November source changes and implementation boundaries

| Source | Consequence for NazoAuth |
| --- | --- |
| OAuth 2.1, revision 17 | Authorization redirect URIs reject query parameters reserved for authorization responses, including for previously registered clients. The authorization endpoint is derived from the query-free issuer. When an authorization request includes `redirect_uri`, the token request must repeat it; OAuth 2.1-only clients that omit it cannot use this flow. A token request containing a verifier without an original challenge is rejected as `invalid_request`. Draft 17 also clarifies input validation and active resource-owner interaction; full draft conformance is not claimed. |
| Browser-based applications, RFC 10017 | Compared the final text with draft 27; the server-side normative requirements did not materially change. The review found and corrected public refresh rotation extending the initial expiry. Existing public refresh families must reauthorize at the migration cutover. Browser application and deployment responsibilities remain separate. |
| Cross-device security, RFC 10027 | Requires deployment-specific risk assessment and mitigations, with proximity considered where possible. Device and CIBA authorization gates and lifecycle protections are available controls, not proof of proximity or of a user's intent; see the cross-device deployment guidance. |
| Client Attestation, revision 12 | Requires attestation `iat` and changes HTTP field syntax to Structured Fields. The OpenID4VCI Final profile still requires revision 07. |
| Client ID Metadata, 02–03 | Adds client URL normalization guidance, exact server-side comparison, loopback redirect exceptions, and transient-fetch and rate-limit guidance. This profile is not implemented. |
| SPIFFE Client Authentication, 02–03 | Revises client identification, trust-bundle discovery, and X.509 SVID validation. This profile is not implemented. |
| Identity Assertion JWT Authorization Grant, 04–06 | Adds resource governance, target authorization and metadata-validation guidance and changes the invalid subject-token error. Third-party assertion issuers and subject mapping are not implemented. |
| [JWT assertion updates](https://www.rfc-editor.org/info/rfc10070) | Client authentication requires issuer-only audiences, including untyped assertions and clients with legacy compatibility settings. Existing clients using endpoint or multiple audiences must migrate to the issuer. JWT bearer grants have separate audience rules. |
| SD-JWT VC, revisions 20–26 | DCQL type matching includes authenticated `aka_vcts` values. Issuer verification uses a configured certificate trust anchor and issuer binding; it does not perform issuer or type-metadata URL retrieval. The verifier requires `iss`, `exp`, and holder binding under its current policy. |
| Delegated Authorization, 03–04 | Describes key-bound root and delegated tokens, restriction inheritance and per-hop proof. This delegated-token profile is not implemented. |
| Mission, 00–02 | Changes the mission lifecycle and approval governance, including standing consent and recorded activation. Mission records are not implemented. |
| Client Instance Identification, 00–01 | Aligns instance claims, required attestation `iat`, error handling, and temporal-claim privacy with client-attestation draft 12. The OpenID4VCI Final draft 07 profile remains separate. |
| Authorization Evidence, 01–02 | Defines signed evidence for approval decisions carried as rich authorization details. Evidence issuance is not implemented. |
| Actor Profile, Proofs, Receipts and Chain | The new revisions refine actor identification, proof and receipt instance binding, lifetimes, and selective chain disclosure. These provenance profiles are not implemented or advertised. |
| Resource metadata and handoff | The rfc9728bis renewal reports no technical changes. Browser Session Handoff expired in October. |

## September source changes and implementation boundaries

The official draft texts and document histories were reviewed for adoption
consequences. Runtime behavior, metadata, and conformance claims are unchanged.

| Source change | Consequence |
| --- | --- |
| [OAuth 2.1, 15 to 16](https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/16/) | Adds value-size, PKCE plain-method and consent-phishing guidance. Review request limits, client registration, consent and grant revocation against draft 16. |
| [Browser-Based Applications, RFC 10017](https://www.rfc-editor.org/info/rfc10017) | Published August 2026. The November review above compares the final text and corrects the refresh-deadline gap in the earlier draft-27 audit. |
| [Cross-Device Security, RFC 10027](https://www.rfc-editor.org/info/rfc10027) | Published August 2026. The November review above records the deployment-specific risk assessment and mitigation boundary. |
| [Client Attestation, 10 to 11](https://datatracker.ietf.org/doc/draft-ietf-oauth-attestation-based-client-auth/11/) | Changes challenge/DPoP nonce handling and client metadata. Keep the OpenID4VCI Final profile pinned to draft 07; adopting draft 11 requires a separate protocol and metadata audit. |
| [Transaction Tokens, 09 to 11](https://www.ietf.org/archive/id/draft-ietf-oauth-transaction-tokens-11.txt) | Document history identifies claim-text edits and a history typo fix. No TTS implementation or metadata is added. |
| [JWT BCP bis, 07 to 10](https://www.ietf.org/archive/id/draft-ietf-oauth-rfc8725bis-10.txt) | Clarifies nested-JWT handling, decompression limits, and deprecated algorithms. Algorithm, key, token-confusion and resource-limit changes need review before adopting the bis draft. |
| [SD-JWT VC, 17 to 19](https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/19/) | Adds optional type aliases and revises HTTP retrieval, integrity, rendering-resource and SSRF rules; clarifies non-disclosable subclaims and removes transitional legacy media-type guidance. Existing credential-profile evidence remains scoped to the prior baseline pending a delta audit. |
| [Delegated Authorization, 02 to 03](https://datatracker.ietf.org/doc/draft-li-oauth-delegated-authorization/03/) | Expands local delegation-chain restrictions and validation rules. Watch only; this delegated-authorization profile is not supported. |
| [RAR metadata WG adoption](https://datatracker.ietf.org/doc/draft-ietf-oauth-rar-metadata-remediation/) | Track the WG draft 00 in place of the replaced individual draft. This is a source transition, not a new runtime commitment. |
| [HTTP-signature PoP, 02 to 03](https://www.ietf.org/archive/id/draft-richer-oauth-httpsig-03.txt) | Changes runtime key presentation, asymmetric-key requirements and algorithm selection. Remains watch only and separate from the experimental FAPI HTTP Signatures implementation. |

The four reviewed expired watch entries remain in the inventory. Their exact
expiry is recorded so renewed, replaced, or newly revised sources trigger a
fresh review; other expired drafts still fail the gate.
The September review matched the OpenID working-draft markers, including the
June 26 FAPI build dates, against their official pages.

## Checks

Offline schema and active-document validation:

```powershell
python scripts/check_spec_freshness.py --offline
```

Online validation against IETF Datatracker, RFC Editor, and upstream specification publishers:

```powershell
python scripts/check_spec_freshness.py --report-json target/spec-freshness-online.json
```

Pull requests touching protocol sources run the offline gate. A weekly and
manual workflow runs the online gate and uploads a JSON result for every
checked source, including when checks fail. The report identifies official
source status and marker changes. Runtime support is tracked in the profile matrix.
The gate continues to fail on expired or replaced drafts. When it reports
drift, update the inventory only after reviewing the normative delta and its implementation,
metadata, documentation, and conformance consequences.
