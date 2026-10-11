# OIDF retained-evidence review, 2026-10-11

This review covers **all 41 REVIEW and 14 WARNING modules** in the composite
1,173-module ledger. It checks the retained official logs, actual screenshot
bytes, module/transaction evidence, current source and primary specifications.
It does not rerun tests, change deployed code, rewrite Suite outcomes or grant
OpenID Foundation certification.

Server source: `8abe4fe33891621ce2659f78d6bc2c224f042e17`.
Controller source: `dbd8b0647731dcf4fa3d725cd8269fc745f9e5ee`.
Original report heads: NazoAuth `6177b290f87f88f515a78ea2abd41f0003a338c4`,
NazoAuthCtl `75f272f9f406089f4dc02ef6537867dbfa99b318`.
Official service version: 5.3.2. Original and corrected run identities remain
separate; the composite is not a full final-source rerun.

## Review decision

| Local disposition | Count | Meaning |
| --- | ---: | --- |
| PASS | 24 | VP screenshot obligation is supported by actual verified-result images and per-module evidence. |
| ACCEPTABLE | 12 | Unadvertised scopes are actually granted; the specification permits omission from discovery. |
| INCOMPLETE | 17 | OIDC page-source evidence exists, but required real screenshots are absent. |
| OPEN | 2 | Precise mdoc certificate-boundary timestamps are explained, but the batch privacy warning is not waived. |

The review itself is complete. **Certification evidence is not complete.**
The earlier statement that only unspecified human review remained was too broad:
17 modules have a concrete screenshot gap, and two privacy warnings remain open.
The official 1,107 PASS / 41 REVIEW / 14 WARNING / 11 expected SKIPPED totals,
`suite_pass=false` and `acceptance_pass=false` are unchanged. The 36 locally
accepted dispositions are not added to the official PASS count.

## VP: 24 screenshot obligations accepted locally

Every official `ExpectVerifierSuccessfulVerificationPage` image was decoded and
compared byte-for-byte with its retained WebDriver PNG. All match their manifest
SHA-256. There are 24 distinct module bindings, receipt hashes and completion
paths. All 24 files have identical bytes because the target intentionally uses
the same minimal success page without exposing credential contents. Visual
inspection of that common image confirms the heading **Presentation verified**
and an explicit successful-verification message; it is not a deferred placeholder
or the Suite wallet's result page.

The success endpoint is gated by an existing completed presentation result:
`crates/openid4vc-http-actix/src/vp.rs:112` calls the domain operation, and
`crates/authorization-server/src/domain/openid4vc_endpoints/openid4vp.rs:797`
returns 404 for an absent/uncompleted result. The retained source regression and
negative official modules provide the independent rejection evidence; identical
success pixels alone do not establish cryptographic verification.

The image hash is
`a9656b6cd7e0f2c7c98be2898c84483523da68fe360c059a36bb85ab967c9a03`.
One byte-identical original is retained publicly, rather than duplicating 24 PNGs:
[reviewed result image](../../../evidence/deployment-upgrade-20261010/reviewed-vp-result.png).
Per-module receipt and image hashes are in the review ledger. This satisfies the
observed Suite screenshot request locally; official reviewer approval remains
outside this document. See [OpenID4VP 1.0](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.2).

## Discovery: 12 warnings accepted locally

Eight original FAPI modules request `accounts`; four corrected HAIP modules
request `eu.europa.ec.eudi.pid.1` or `org.iso.18013.5.1.mDL`. The discovery document
lists built-in scopes and omits these application/credential scopes. For each of
the 12 modules, successful token-response JSON actually grants the omitted scope.
The scope is therefore not merely misspelled in a test configuration.
[RFC 8414 section 2](https://www.rfc-editor.org/rfc/rfc8414.html#section-2)
permits supported scopes to be omitted from discovery. No protocol repair or
expansion of publicly advertised tenant scope names is necessary for this warning.
The raw WARNING results remain unchanged.

## OIDC: 17 screenshot gaps remain

Six reauthentication modules record the second login form; the corresponding
auth-time conditions are retained in the ledger. Three invalid-redirect modules
record `invalid_request` with a redirect-registration rejection. Eight logout
modules record the local signed-out page. These are useful observed DOM/HTTP
facts, but neither the initial manifest nor the relevant official REVIEW entry
contains a PNG. A scripted-browser message saying the placeholder was filled is
not proof that a real image was captured.

Seven of the eight logout modules also record the confirmation form in the
actual browser HTTP response; the remaining no-post-logout-redirect case has a
valid hint and does not require that fallback. The five invalid/missing-hint or
invalid-redirect review prompts request an error page, while the recorded final
page says the user is signed out. This is not sufficient to diagnose a protocol
violation: [RP-Initiated Logout sections 3, 4 and 6](https://openid.net/specs/openid-connect-rpinitiated-1_0.html)
require redirect validation and permit local confirmation instead of an error
page. The source rejects untrusted redirect data, requires POST plus CSRF for
confirmation, and drops invalid request fields before rendering that form
(`crates/http-actix/src/oidc_logout.rs`). The observed confirmation and success
pages are consistent with that path. They do not replace missing visual evidence
or provide a complete independent network trace of every confirmation POST.

Closure requires real browser captures of the relevant second-login,
redirect-error, and logout confirmation/result stages, attached to their actual
module identities. For the error-hint scenarios, retain the local confirmation
and no-RP-redirect trace with the standards explanation. The cleaned historical
tenant cannot be revisited to reproduce its original screenshots. Rendering old
HTML now would be a reconstruction, not historical evidence. A targeted fresh
run is needed after the capture path handles these 17 obligations; no whole
matrix rerun is implied. No browser, tenant or official plan was created by
this review.

## mdoc: two privacy warnings remain open

The two warning modules each contain ten issued credentials. All twenty use
the same signer certificate (PEM SHA-256
`21802fb37fcd31efb4c8db4a0516cdbe46a2402ca3dc2443aa8023c6c2601e17`).
Every checked MSO has `signed == certificate.notBefore == 2026-10-10T17:02:59Z`;
`validFrom` has the same value and `validUntil` remains rounded. The certificate
and MSO validity checks pass. This confirms a shared signer boundary rather than
a unique timestamp sampled for each request, consistent with
`crates/authorization-server/src/domain/openid4vc/credential_crypto/mdoc.rs`.

However, shared does not automatically mean sufficiently anonymous. Two test
batches do not establish a suitably large independent-holder signer cohort, and
a precisely dated small cohort can still be correlated. [RFC 9901 section 10.1](https://www.rfc-editor.org/rfc/rfc9901.html#section-10.1)
requires randomized or rounded time claims for its SD-JWT batch privacy model;
the Suite also applies this concern to mdoc. The observed mdoc clamping is not
itself a rounded/randomized value or a formal exception. The evidence explains
the warning but does not justify marking privacy PASS.

A future resolution must reconcile the original certificate-validity constraint
with batch privacy, or obtain the applicable profile's explicit acceptance of a
supported shared-cohort design. It must not backdate certificates, extend
credential expiry, disable the check or rely solely on waiting for the freshness
heuristic to stop triggering. This review makes no code or deployment change.

## Evidence and validation

- [Per-module review ledger](../../../evidence/deployment-upgrade-20261010/oidf-review-20261011.json): all 55 identities, immutable source hashes, conditions, local decisions and supporting facts.
- Initial manifest: `218b6d8b48e10b2b65738e650f1c0a641a2335d0ed707a07d1af1dd19faacf1f`.
- Corrected manifest: `1f1cc9ec8b9ac1800bf302f13d3c68b4a23e6a5a621a118c91fcf4155564ceb3`.
- Both manifests and all selected module files were re-hashed. All 24 official PNGs match the retained images. Scope-grant inclusion and both ten-credential certificate comparisons were asserted, not sampled.
- The private `review-20261011/extract-review.py` evidence extraction completed with exit 0. The private `review-20261011/validate-docs.py` also exited 0, checking all 55 ledger identities, counts, distinct bindings, the PNG hash and local links; `git diff --check` passed.
- Prior final-source CI remains recorded: NazoAuth quality run `38071310443` and controller run `38071315296` passed. This documentation/evidence-only revision needs no new Rust build or protocol test claim.

## Individual dispositions

Each row retains its official outcome; the local disposition explains the review.

| Module | Plan | Official | Local | Condition |
| --- | --- | --- | --- | --- |
| `g0VRVNR1BVkVh82` | oidc-core-p001 | REVIEW | INCOMPLETE | ExpectSecondLoginPage |
| `zfie0hHnnvDbvRt` | oidc-core-p001 | REVIEW | INCOMPLETE | ExpectSecondLoginPage |
| `aeC3ADrgyu3yysU` | oidc-core-p001 | REVIEW | INCOMPLETE | ExpectRedirectUriErrorPage |
| `whmBoiMsx8X9TOG` | oidc-core-p002 | REVIEW | INCOMPLETE | ExpectSecondLoginPage |
| `Ti9KN5UnGz3Bs1h` | oidc-core-p002 | REVIEW | INCOMPLETE | ExpectSecondLoginPage |
| `iPpGw9IQsvB5dvk` | oidc-core-p002 | REVIEW | INCOMPLETE | ExpectRedirectUriErrorPage |
| `g9KWt0iX0fAoewF` | oidc-core-p003 | REVIEW | INCOMPLETE | ExpectSecondLoginPage |
| `rrPGvuc0xZtECd5` | oidc-core-p003 | REVIEW | INCOMPLETE | ExpectSecondLoginPage |
| `VCSzSUDHJgk02dX` | oidc-core-p003 | REVIEW | INCOMPLETE | ExpectRedirectUriErrorPage |
| `UtWMTiB6bvU0AfP` | oidc-logout-p006 | REVIEW | INCOMPLETE | ExpectPostLogoutRedirectUriNotRegisteredErrorPage |
| `wBr49nX58neOxie` | oidc-logout-p006 | REVIEW | INCOMPLETE | ExpectInvalidIdTokenHintErrorPage |
| `vFUjdKuDCnchuic` | oidc-logout-p006 | REVIEW | INCOMPLETE | ExpectIdTokenHintRequiredErrorPage |
| `wos71i6GpZR4xs0` | oidc-logout-p006 | REVIEW | INCOMPLETE | ExpectSuccessfulLogoutPage |
| `Aa5R13JUGNOKdN2` | oidc-logout-p006 | REVIEW | INCOMPLETE | ExpectSuccessfulLogoutPage |
| `vVp3KeUdmbP9FWQ` | oidc-logout-p006 | REVIEW | INCOMPLETE | ExpectSuccessfulLogoutPage |
| `LofjRkt36q9yAPC` | oidc-logout-p006 | REVIEW | INCOMPLETE | ExpectPostLogoutRedirectUriNotRegisteredErrorPage |
| `SvpW8opQGXYoEsO` | oidc-logout-p006 | REVIEW | INCOMPLETE | ExpectInvalidIdTokenHintErrorPage |
| `ZRs9RPp7xJV6nG7` | fapi-security-code-p015 | WARNING | ACCEPTABLE | CheckDiscEndpointScopesSupportedContainsRequestedScopes |
| `Gd2ifBsIJg8iNrI` | fapi-security-code-p017 | WARNING | ACCEPTABLE | CheckDiscEndpointScopesSupportedContainsRequestedScopes |
| `bTIW2WEptGGmnAa` | fapi-security-code-p019 | WARNING | ACCEPTABLE | CheckDiscEndpointScopesSupportedContainsRequestedScopes |
| `DrjOtnqxVRqR05T` | fapi-security-code-p021 | WARNING | ACCEPTABLE | CheckDiscEndpointScopesSupportedContainsRequestedScopes |
| `yEONaGAigd687Ir` | fapi-security-credentials-p024 | WARNING | ACCEPTABLE | CheckDiscEndpointScopesSupportedContainsRequestedScopes |
| `0J4AttSdg4TVIiU` | fapi-security-credentials-p025 | WARNING | ACCEPTABLE | CheckDiscEndpointScopesSupportedContainsRequestedScopes |
| `qDkbfdxaEa6uC16` | fapi-security-credentials-p026 | WARNING | ACCEPTABLE | CheckDiscEndpointScopesSupportedContainsRequestedScopes |
| `XCWOSxArDWYHoYF` | fapi-security-credentials-p027 | WARNING | ACCEPTABLE | CheckDiscEndpointScopesSupportedContainsRequestedScopes |
| `Y2KOjLvgQ4JPYvu` | openid4vc-vci-p029 | WARNING | OPEN | VCIEnsureBatchTimeClaimsNotLinkable |
| `9hiEw9anfjuCAed` | openid4vc-vci-p031 | WARNING | OPEN | VCIEnsureBatchTimeClaimsNotLinkable |
| `ZGOAvXZvNSbqDGH` | openid4vc-vci-haip-p034 | WARNING | ACCEPTABLE | CheckDiscEndpointScopesSupportedContainsRequestedScopes |
| `7hEv1lMPURtzw8N` | openid4vc-vci-haip-p035 | WARNING | ACCEPTABLE | CheckDiscEndpointScopesSupportedContainsRequestedScopes |
| `z7OOHT87PAlHmnO` | openid4vc-vci-haip-p036 | WARNING | ACCEPTABLE | CheckDiscEndpointScopesSupportedContainsRequestedScopes |
| `TPpZ8TFZfdXl9NW` | openid4vc-vci-haip-p037 | WARNING | ACCEPTABLE | CheckDiscEndpointScopesSupportedContainsRequestedScopes |
| `F1zazWvVvSn3bCJ` | openid4vc-vp-p038 | REVIEW | PASS | ExpectVerifierSuccessfulVerificationPage |
| `oFFR8NT4DpTiePJ` | openid4vc-vp-p038 | REVIEW | PASS | ExpectVerifierSuccessfulVerificationPage |
| `mNOdpyb7rfJLKmx` | openid4vc-vp-p038 | REVIEW | PASS | ExpectVerifierSuccessfulVerificationPage |
| `Xlxj0BUURHb71ip` | openid4vc-vp-p039 | REVIEW | PASS | ExpectVerifierSuccessfulVerificationPage |
| `1ARDx0zRFQuxUFq` | openid4vc-vp-p039 | REVIEW | PASS | ExpectVerifierSuccessfulVerificationPage |
| `nuUUJ82Rua46xHt` | openid4vc-vp-p039 | REVIEW | PASS | ExpectVerifierSuccessfulVerificationPage |
| `U95E6cYS4EGYB56` | openid4vc-vp-p039 | REVIEW | PASS | ExpectVerifierSuccessfulVerificationPage |
| `jCAG5rolbU2Df9b` | openid4vc-vp-p040 | REVIEW | PASS | ExpectVerifierSuccessfulVerificationPage |
| `bQCrJEDNcluIXCq` | openid4vc-vp-p040 | REVIEW | PASS | ExpectVerifierSuccessfulVerificationPage |
| `UljIVC0RtW05qIL` | openid4vc-vp-p040 | REVIEW | PASS | ExpectVerifierSuccessfulVerificationPage |
| `6SKNK9gCKIwBvjk` | openid4vc-vp-p041 | REVIEW | PASS | ExpectVerifierSuccessfulVerificationPage |
| `o7WI7RSWkfNhBlt` | openid4vc-vp-p041 | REVIEW | PASS | ExpectVerifierSuccessfulVerificationPage |
| `cwmWlNmTNIIVNr2` | openid4vc-vp-p041 | REVIEW | PASS | ExpectVerifierSuccessfulVerificationPage |
| `XDnIBXhZMzbfzSi` | openid4vc-vp-p041 | REVIEW | PASS | ExpectVerifierSuccessfulVerificationPage |
| `MSIaxNtFxiR5EQG` | openid4vc-vp-p042 | REVIEW | PASS | ExpectVerifierSuccessfulVerificationPage |
| `AKjj28VHsAdW9al` | openid4vc-vp-p042 | REVIEW | PASS | ExpectVerifierSuccessfulVerificationPage |
| `9zLom4f0e1pf8Oa` | openid4vc-vp-p042 | REVIEW | PASS | ExpectVerifierSuccessfulVerificationPage |
| `ZyKgPRMIrdXneY5` | openid4vc-vp-haip-p043 | REVIEW | PASS | ExpectVerifierSuccessfulVerificationPage |
| `WEB1XxqEL1wmxY9` | openid4vc-vp-haip-p043 | REVIEW | PASS | ExpectVerifierSuccessfulVerificationPage |
| `qo6S0TBCUevVBMU` | openid4vc-vp-haip-p043 | REVIEW | PASS | ExpectVerifierSuccessfulVerificationPage |
| `3CymEfCDqYPs9wQ` | openid4vc-vp-haip-p043 | REVIEW | PASS | ExpectVerifierSuccessfulVerificationPage |
| `YW6RqmDvqZULTxP` | openid4vc-vp-haip-p044 | REVIEW | PASS | ExpectVerifierSuccessfulVerificationPage |
| `S0Ml1yBJXpac6d2` | openid4vc-vp-haip-p044 | REVIEW | PASS | ExpectVerifierSuccessfulVerificationPage |
| `rv6sKmfCb5ym70h` | openid4vc-vp-haip-p044 | REVIEW | PASS | ExpectVerifierSuccessfulVerificationPage |
