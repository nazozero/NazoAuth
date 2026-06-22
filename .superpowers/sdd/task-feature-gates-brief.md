# Feature Gates — Implementation Brief

## Scope
Implement P0 Feature Gates across configuration, authorization endpoint, PAR endpoint, token endpoint, and discovery metadata.

## Files to Modify

| File | Change |
|---|---|
| `src/settings.rs` | Add 5 bool fields `enable_request_object`, `enable_request_uri_parameter`, `enable_par_request_object`, `enable_authorization_details`, `enable_legacy_audience_param`. Default all to false. |
| `src/settings/profile.rs` | Add `requires_par()` returning true for Fapi2Security and Fapi2MessageSigningAuthzRequest. Add `requires_signed_request_object_at_par()` returning true only for Fapi2MessageSigningAuthzRequest. |
| `src/config.rs` | Add 5 env var allowlist entries matching the settings names. |
| `src/http/authorization/request.rs` | After parameter deduplication, before request object processing: add gate checks for `request` (enable_request_object), `request_uri` (enable_request_uri_parameter), `authorization_details` (enable_authorization_details). Return oauth error 400 on rejection. |
| `src/http/authorization/par.rs` | After PAR body parsing, add gate checks. Request object in PAR body gated by `enable_par_request_object \|\| requires_signed_request_object_at_par()`. authorization_details gated by `enable_authorization_details`. Return oauth error 400 on rejection. |
| `src/http/token/forms.rs` or `dispatch.rs` | Gate legacy `audience` parameter by `enable_legacy_audience_param`. |
| `src/http/well_known.rs` | Gate each discovery field: `request_parameter_supported` (omit if false), `request_uri_parameter_supported` (always explicit — omit defaults to true in OIDC, so expose false explicitly, expose true + require_request_uri_registration when enabled), `request_object_signing_alg_values_supported` (expose when enable_request_object \|\| enable_request_uri_parameter \|\| enable_par_request_object \|\| requires_signed_request_object_at_par(), never include "none"), `authorization_details_types_supported` (omit if false). |
| `.env.yaml.example` | Add 5 gate config keys with comments. |

## Global Constraints
- All gates default false (closed).
- FAPI2 Message Signing auto-enables PAR request object via profile method, NOT via enable_request_object.
- /authorize ?request=... is controlled by enable_request_object only (never auto-enabled by profile).
- /authorize ?request_uri=... is separately controlled by enable_request_uri_parameter.
- /par body request object gated by enable_par_request_object || requires_signed_request_object_at_par().
- Early rejection: detect parameter presence, reject before any deep parsing.
- Discovery: request_uri_parameter_supported MUST be explicit (omit defaults true). request_object_signing_alg_values_supported never includes "none".
