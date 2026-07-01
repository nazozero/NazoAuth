# OIDF Full Matrix

This document describes the repository-owned OpenID Foundation Conformance Suite matrix. The matrix remains a 16-plan suite. New TP/PS checks are mapped onto these plans instead of being added as a separate temporary matrix.

The execution entry point is still `runtime/oidf/oidf-plan-set.json`. `scripts/setup_local_oidf_podman.py` also writes `runtime/oidf/oidf-plan-set-manifest.json` with a title, description, and coverage focus for every plan.

## Plan Index

| # | Title | Description |
| --- | --- | --- |
| 1 | OIDC Basic OP | Validates discovery, static client registration, and OIDC authorization-code interoperability for ID Token, UserInfo, and common login parameters. |
| 2 | OIDC Config OP | Validates provider metadata truth for the public issuer, including endpoint, algorithm, and session-capability advertisement. |
| 3 | FAPI2 Message Signing / private_key_jwt / DPoP / OpenID Connect / authorization code / JARM | Uses `private_key_jwt` client authentication and DPoP sender constraint to cover signed Request Objects, PAR, JAR/JARM, PKCE, authorization-code replay, and OpenID Connect responses. |
| 4 | FAPI2 Message Signing / private_key_jwt / DPoP / OpenID Connect / authorization code / plain response | Keeps the signed-request boundary from the JARM plan while using a plain code response, separating request-side message signing from response-mode behavior. |
| 5 | FAPI2 Security / mTLS client auth / DPoP / OpenID Connect / authorization code | Uses mTLS client authentication and DPoP-bound access tokens for OIDC authorization-code coverage, including PAR, PKCE, code replay, refresh tokens, and discovery. |
| 6 | FAPI2 Security / mTLS client auth / DPoP / plain OAuth / client credentials | Uses mTLS client authentication and DPoP-bound access tokens for client credentials, token endpoint, audience, and resource-access checks. |
| 7 | FAPI2 Security / mTLS client auth / DPoP / plain OAuth / authorization code | Uses mTLS client authentication and DPoP sender constraint for non-OIDC authorization-code coverage, including PAR, PKCE, code replay, and resource access. |
| 8 | FAPI2 Security / mTLS client auth / mTLS sender / OpenID Connect / authorization code | Covers mTLS client authentication plus mTLS sender-constrained tokens for OIDC authorization code and holder-bound resource access. |
| 9 | FAPI2 Security / mTLS client auth / mTLS sender / plain OAuth / client credentials | Uses mTLS for both client authentication and sender constraint in client credentials token issuance and resource access. |
| 10 | FAPI2 Security / mTLS client auth / mTLS sender / plain OAuth / authorization code | Uses mTLS for both client authentication and sender constraint in non-OIDC authorization-code, PAR, PKCE, code replay, and resource-access checks. |
| 11 | FAPI2 Security / private_key_jwt / DPoP / OpenID Connect / authorization code | Uses `private_key_jwt` and DPoP for OIDC authorization code. This is the primary single-plan regression for PAR `request_uri`, outer authorization parameters, and refresh-token behavior. |
| 12 | FAPI2 Security / private_key_jwt / DPoP / plain OAuth / client credentials | Uses `private_key_jwt` and DPoP for client credentials token endpoint, audience, and resource-access checks. |
| 13 | FAPI2 Security / private_key_jwt / DPoP / plain OAuth / authorization code | Uses `private_key_jwt` and DPoP for non-OIDC authorization-code coverage, including PAR, PKCE, code replay, and resource access. |
| 14 | FAPI2 Security / private_key_jwt / mTLS sender / OpenID Connect / authorization code | Uses `private_key_jwt` client authentication and mTLS sender-constrained tokens for OIDC authorization code and certificate-bound resource access. |
| 15 | FAPI2 Security / private_key_jwt / mTLS sender / plain OAuth / client credentials | Uses `private_key_jwt` client authentication and mTLS sender constraint for client credentials token issuance and certificate-bound resource access. |
| 16 | FAPI2 Security / private_key_jwt / mTLS sender / plain OAuth / authorization code | Uses `private_key_jwt` client authentication and mTLS sender constraint for non-OIDC authorization-code, PAR, PKCE, code replay, and resource-access checks. |

## TP/PS Coverage Boundary

The matrix covers the current TP/PS work through these paths:

- `OIDC Config OP` covers metadata truth and prevents discovery from advertising unsupported capabilities.
- FAPI2 Security and Message Signing plans cover PAR enforcement, `request_uri` expiry, `request_uri` replay, cross-client `request_uri` use, outer authorization request parameters, PKCE, redirect URI, audience, and client assertions.
- `private_key_jwt / DPoP / OpenID Connect / authorization code` is the closest single-plan regression for this TP/PS change set; full evidence still comes from the 16-plan matrix.

Targeted plan-sets are useful for development triage. Durable regression evidence should cite the full 16-plan matrix.
