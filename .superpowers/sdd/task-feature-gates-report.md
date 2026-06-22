# Feature Gates — Implementation Report

## What was implemented

1. **settings.rs** — Added 5 bool fields: `enable_request_object`, `enable_request_uri_parameter`, `enable_par_request_object`, `enable_authorization_details`, `enable_legacy_audience_param`. All default false. Parsed via `config.bool("KEY", false)`.

2. **settings/profile.rs** — Added `requires_par()` (true for Fapi2Security, Fapi2MessageSigningAuthzRequest) and `requires_signed_request_object_at_par()` (true only for Fapi2MessageSigningAuthzRequest).

3. **config.rs** — Added 5 env var allowlist entries.

4. **http/authorization/request.rs** — Gate checks for `request` (enable_request_object), `request_uri` (enable_request_uri_parameter), `authorization_details` (enable_authorization_details). Early rejection before any deep parsing.

5. **http/authorization/par.rs** — Gate checks for request object (enable_par_request_object || requires_signed_request_object_at_par()) and authorization_details (enable_authorization_details).

6. **http/token/forms.rs + dispatch.rs** — `has_audience_param` boolean added to TokenForm. Check against `enable_legacy_audience_param` in token dispatch before audience processing.

7. **http/well_known.rs** — Gate-dependent discovery metadata:
   - request_object_signing_alg_values_supported: exposed when any relevant gate enables it; "none" removed from array
   - request_parameter_supported: exposed only when enable_request_object
   - request_uri_parameter_supported: always explicit (false when disabled, true + require_request_uri_registration when enabled)
   - authorization_details_types_supported: exposed only when enable_authorization_details

8. **env.yaml.example** — 5 gate config keys added.

## Test results

Build fails due to missing OpenSSL/NASM dev environment — pre-existing issue unrelated to changes.

## Files changed
- .env.yaml.example
- src/config.rs
- src/http/authorization/par.rs
- src/http/authorization/request.rs
- src/http/token/dispatch.rs
- src/http/token/forms.rs
- src/http/well_known.rs
- src/settings.rs
- src/settings/profile.rs

## Self-review findings
- SUPPORTED_AUTHORIZATION_DETAILS_TYPES import correctly removed from well_known.rs (constant is `["account_information", "payment_initiation"]` — same as hardcoded replacement)
- All gate checks follow "early rejection" principle
- Discovery metadata correctly uses OIDC Discovery defaults (request_uri_parameter_supported must be explicit)
