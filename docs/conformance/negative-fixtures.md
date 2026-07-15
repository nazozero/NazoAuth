# Negative Conformance Fixtures

## Scope

High-risk negative conformance cases map to durable local tests here. OIDF
results remain the authority for official suite status; local tests keep
security-profile regressions visible in `cargo test`.

| Fixture | Local evidence |
| --- | --- |
| Overclaimed metadata | `http::well_known::tests::discovery_does_not_advertise_mtls_when_no_trusted_proxy_is_configured`, `http::well_known::tests::discovery_fapi2_security_metadata_is_profile_scoped`, `http::well_known::tests::discovery_message_signing_profile_requires_signed_request_object_algs` |
| Unsupported or malformed RAR authorization details | `domain::authorization_details::tests::authorization_details_require_array_of_typed_objects`, `http::authorization::request::tests::stored_grant_requires_transaction_binding_for_authorization_details`, `http::well_known::tests::discovery_advertises_supported_rar_types` |
| Weak client auth in FAPI2 Security | `http::token::dispatch::tests::fapi2_profile_requires_confidential_client_auth_and_sender_constraint` |
| Unsigned JAR for every client profile | `authorization_request::tests::unsigned_request_objects_are_rejected_for_every_client_profile`, `http::authorization::par::tests::par_rejects_unsigned_request_object_without_outer_client_id_as_request_object_error` |
| Missing DPoP proof | `http::token::authorization_code::tests::authorization_code_dpop_missing_proof_uses_invalid_grant`, `support::dpop::tests::token_endpoint_missing_proof_uses_bad_request` |
| DPoP proof without nonce where required | `support::dpop::tests::dpop_nonce_policy_controls_missing_nonce_requirement`, `http::token::authorization_code::tests::authorization_code_dpop_nonce_challenge_keeps_dpop_error` |
| Bearer token at sender-constrained resource servers | `http::fapi_resource::tests::access_token_rejects_multiple_transport_methods`, `http::token::userinfo::tests::access_token_rejects_multiple_transport_methods`, `http::token::introspect::tests::access_token_introspection_type_matches_issued_dpop_token_type` |
| Query-token use at resource endpoints | `http::fapi_resource::tests::query_access_token_is_not_accepted`, `http::token::userinfo::tests::query_access_token_is_not_accepted` |
| Redirect URI mismatch | `support::oauth::tests::redirect_uri_requires_exact_match`, `http::authorization::request::tests::request_uri_allows_outer_parameters_only_when_equal_to_pushed_values`, `http::token::authorization_code::tests::token_redirect_uri_is_required_when_authorize_request_supplied_it` |
| OIDC logout redirect mismatch | `http::profile::oidc_logout::tests::post_logout_redirect_requires_exact_registered_uri_and_preserves_state` |
| OIDC logout ambiguous client identity | `http::profile::oidc_logout::tests::logout_client_id_must_match_id_token_hint_audience`, `http::profile::oidc_logout::tests::multi_audience_id_token_hint_requires_explicit_matching_client_id` |
| Back-channel logout token shape | `support::security::tests::backchannel_logout_token_claims_follow_oidc_shape_without_nonce` |
| Stale JWKS or retired key use | `support::security::tests::private_key_jwt_rejects_assertions_after_key_retirement`, `support::keyset::tests::retired_active_key_entry_is_rejected`, `support::keyset::tests::retired_previous_key_entry_is_skipped` |

## Maintenance

Fixture names are specific by design. When discovery or profile behavior
changes, update the corresponding row in the same commit as runtime behavior and
metadata.
