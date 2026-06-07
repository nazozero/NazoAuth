# Negative Conformance Fixtures

This index maps high-risk negative conformance cases to durable local tests. It is not a replacement for OIDF results, but it keeps security-profile regressions visible in `cargo test`.

| Fixture | Local evidence |
| --- | --- |
| Overclaimed metadata | `http::well_known::tests::discovery_does_not_advertise_mtls_when_no_trusted_proxy_is_configured`, `http::well_known::tests::discovery_fapi2_security_metadata_is_profile_scoped`, `http::well_known::tests::discovery_message_signing_profile_requires_signed_request_object_algs` |
| Unsupported or malformed RAR authorization details | `domain::authorization_details::tests::authorization_details_require_array_of_typed_objects`, `http::authorization::request::tests::stored_grant_requires_transaction_binding_for_authorization_details`, `http::well_known::tests::discovery_advertises_supported_rar_types` |
| Weak client auth in FAPI2 Security | `http::token::dispatch::tests::fapi2_profile_requires_confidential_client_auth_and_sender_constraint` |
| Unsigned JAR in hardened profiles | `http::authorization::par::tests::message_signing_profile_requires_request_object_at_par`, `http::authorization::jar::tests::par_request_object_policy_rejects_unsigned_request_objects` |
| Missing DPoP proof | `http::token::authorization_code::tests::authorization_code_dpop_missing_proof_uses_invalid_grant`, `support::dpop::tests::token_endpoint_missing_proof_uses_bad_request` |
| DPoP proof without nonce where required | `support::dpop::tests::dpop_nonce_policy_controls_missing_nonce_requirement`, `http::token::authorization_code::tests::authorization_code_dpop_nonce_challenge_keeps_dpop_error` |
| Bearer token at sender-constrained resource servers | `http::fapi_resource::tests::access_token_rejects_multiple_transport_methods`, `http::token::userinfo::tests::access_token_rejects_multiple_transport_methods`, `http::token::introspect::tests::access_token_introspection_type_matches_issued_dpop_token_type` |
| Query-token use at resource endpoints | `http::fapi_resource::tests::query_access_token_is_not_accepted`, `http::token::userinfo::tests::query_access_token_is_not_accepted` |
| Redirect URI mismatch | `support::oauth::tests::redirect_uri_requires_exact_match`, `http::authorization::request::tests::request_uri_allows_outer_parameters_only_when_equal_to_pushed_values`, `http::token::authorization_code::tests::token_redirect_uri_is_required_when_authorize_request_supplied_it` |
| Stale JWKS or retired key use | `support::security::tests::private_key_jwt_rejects_assertions_after_key_retirement`, `support::keyset::tests::retired_active_key_entry_is_rejected`, `support::keyset::tests::retired_previous_key_entry_is_skipped` |

The fixture names are intentionally specific: when discovery or profile behavior changes, the corresponding row should be updated in the same commit as the runtime behavior and metadata.
