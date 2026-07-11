use nazo_fapi_http_signatures::{
    RequestInput, RequestPolicy, SignatureFields, VerificationPolicy, VerifyError,
    parse_request_for_verification, prepare_request,
};

const CREATED: i64 = 1_720_000_000;
const BODY: &[u8] = br#"{"amount":10}"#;

fn headers() -> [(&'static str, &'static str); 3] {
    [
        ("Authorization", "DPoP opaque"),
        ("DPoP", "opaque-proof"),
        (
            "Content-Digest",
            "sha-256=:qLiLgv6QoWBI64hR/jgkBTlc05Xa+qfKm+kOwA+Cpys=:",
        ),
    ]
}

fn request<'a>(
    method: &'a str,
    target_uri: &'a str,
    headers: &'a [(&'a str, &'a str)],
    body: &'a [u8],
) -> RequestInput<'a> {
    RequestInput {
        method,
        target_uri,
        headers,
        body,
    }
}

fn policy() -> VerificationPolicy {
    VerificationPolicy {
        now: CREATED + 30,
        max_age_seconds: 60,
        future_skew_seconds: 5,
    }
}

fn fixture() -> (Vec<u8>, SignatureFields) {
    let headers = headers();
    let prepared = prepare_request(
        request("POST", "https://api.example/fapi/resource", &headers, BODY),
        RequestPolicy {
            created: CREATED,
            keyid: "client-ed25519",
            algorithm: "ed25519",
        },
    )
    .unwrap();
    let base = prepared.signature_base().to_vec();
    (base, prepared.finish(&[0xde, 0xad, 0xbe, 0xef]))
}

fn parse(fields: SignatureFields) -> Result<nazo_fapi_http_signatures::VerifiedInput, VerifyError> {
    let headers = headers();
    parse_request_for_verification(
        request("POST", "https://api.example/fapi/resource", &headers, BODY),
        fields,
        policy(),
    )
}

#[test]
fn parses_a_valid_strict_request_signature() {
    let (base, fields) = fixture();
    let parsed = parse(fields).unwrap();

    assert_eq!(parsed.keyid(), "client-ed25519");
    assert_eq!(parsed.algorithm(), "ed25519");
    assert_eq!(parsed.created(), CREATED);
    assert_eq!(parsed.signature(), &[0xde, 0xad, 0xbe, 0xef]);
    assert_eq!(parsed.signature_base(), base);
    assert_eq!(parsed.replay_fingerprint().len(), 32);
}

#[test]
fn rejects_mismatched_labels() {
    let (_, mut fields) = fixture();
    fields.signature = fields.signature.replacen("sig1=", "other=", 1);
    assert_eq!(parse(fields).unwrap_err(), VerifyError::MissingSignature);
}

#[test]
fn rejects_missing_signature_label() {
    let (_, mut fields) = fixture();
    fields.signature.clear();
    assert_eq!(parse(fields).unwrap_err(), VerifyError::MissingSignature);
}

#[test]
fn rejects_multiple_signature_labels() {
    let (_, mut fields) = fixture();
    fields.signature_input = format!(
        "{}, sig2={}",
        fields.signature_input,
        fields.signature_input.strip_prefix("sig1=").unwrap()
    );
    fields.signature = format!("{}, sig2=:AQ==:", fields.signature);
    assert_eq!(parse(fields).unwrap_err(), VerifyError::AmbiguousSignature);
}

#[test]
fn rejects_a_duplicate_signature_label() {
    let (_, mut fields) = fixture();
    fields.signature = format!("{}, {}", fields.signature, fields.signature);
    assert_eq!(parse(fields).unwrap_err(), VerifyError::AmbiguousSignature);
}

#[test]
fn rejects_wrong_tag() {
    let (_, mut fields) = fixture();
    fields.signature_input = fields
        .signature_input
        .replace("tag=\"fapi-2-request\"", "tag=\"other\"");
    assert_eq!(parse(fields).unwrap_err(), VerifyError::InvalidTag);
}

fn remove_component(fields: &mut SignatureFields, component: &str) {
    fields.signature_input = fields
        .signature_input
        .replace(&format!("\"{component}\" "), "")
        .replace(&format!(" \"{component}\""), "");
}

#[test]
fn rejects_missing_method_coverage() {
    let (_, mut fields) = fixture();
    remove_component(&mut fields, "@method");
    assert_eq!(parse(fields).unwrap_err(), VerifyError::MissingComponent);
}

#[test]
fn rejects_missing_target_uri_coverage() {
    let (_, mut fields) = fixture();
    remove_component(&mut fields, "@target-uri");
    assert_eq!(parse(fields).unwrap_err(), VerifyError::MissingComponent);
}

#[test]
fn rejects_missing_authorization_coverage() {
    let (_, mut fields) = fixture();
    remove_component(&mut fields, "authorization");
    assert_eq!(parse(fields).unwrap_err(), VerifyError::MissingComponent);
}

#[test]
fn rejects_missing_dpop_coverage() {
    let (_, mut fields) = fixture();
    remove_component(&mut fields, "dpop");
    assert_eq!(parse(fields).unwrap_err(), VerifyError::MissingComponent);
}

#[test]
fn rejects_missing_digest_coverage() {
    let (_, mut fields) = fixture();
    remove_component(&mut fields, "content-digest");
    assert_eq!(parse(fields).unwrap_err(), VerifyError::MissingComponent);
}

#[test]
fn rejects_stale_created_time() {
    let (_, fields) = fixture();
    assert_eq!(
        parse_request_for_verification(
            request(
                "POST",
                "https://api.example/fapi/resource",
                &headers(),
                BODY,
            ),
            fields,
            VerificationPolicy {
                now: CREATED + 61,
                ..policy()
            },
        )
        .unwrap_err(),
        VerifyError::InvalidCreated
    );
}

#[test]
fn rejects_created_too_far_in_the_future() {
    let (_, fields) = fixture();
    assert_eq!(
        parse_request_for_verification(
            request(
                "POST",
                "https://api.example/fapi/resource",
                &headers(),
                BODY,
            ),
            fields,
            VerificationPolicy {
                now: CREATED - 6,
                ..policy()
            },
        )
        .unwrap_err(),
        VerifyError::InvalidCreated
    );
}

#[test]
fn rejects_expires_before_created() {
    let (_, mut fields) = fixture();
    fields.signature_input = fields.signature_input.replace(
        ";created=1720000000",
        ";created=1720000000;expires=1719999999",
    );
    assert_eq!(parse(fields).unwrap_err(), VerifyError::InvalidCreated);
}

#[test]
fn rejects_a_duplicate_signature_parameter() {
    let (_, mut fields) = fixture();
    fields.signature_input = fields.signature_input.replace(
        ";created=1720000000",
        ";created=1720000000;created=1720000000",
    );
    assert_eq!(parse(fields).unwrap_err(), VerifyError::MalformedSignature);
}

#[test]
fn rejects_wrong_content_digest() {
    let (_, fields) = fixture();
    let wrong_headers = [
        ("Authorization", "DPoP opaque"),
        ("DPoP", "opaque-proof"),
        (
            "Content-Digest",
            "sha-256=:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=:",
        ),
    ];
    assert_eq!(
        parse_request_for_verification(
            request(
                "POST",
                "https://api.example/fapi/resource",
                &wrong_headers,
                BODY,
            ),
            fields,
            policy(),
        )
        .unwrap_err(),
        VerifyError::DigestMismatch
    );
}

#[test]
fn rejects_an_altered_body_without_a_matching_digest() {
    let (_, fields) = fixture();
    assert_eq!(
        parse_request_for_verification(
            request(
                "POST",
                "https://api.example/fapi/resource",
                &headers(),
                br#"{"amount":11}"#,
            ),
            fields,
            policy(),
        )
        .unwrap_err(),
        VerifyError::DigestMismatch
    );
}

fn assert_altered_base(method: &str, target_uri: &str, request_headers: &[(&str, &str)]) {
    let (base, fields) = fixture();
    let parsed = parse_request_for_verification(
        request(method, target_uri, request_headers, BODY),
        fields,
        policy(),
    )
    .unwrap();

    assert_ne!(parsed.signature_base(), base);
}

#[test]
fn reconstructs_a_different_base_for_an_altered_method() {
    assert_altered_base("PATCH", "https://api.example/fapi/resource", &headers());
}

#[test]
fn reconstructs_a_different_base_for_an_altered_target_uri() {
    assert_altered_base("POST", "https://api.example/fapi/other", &headers());
}

#[test]
fn reconstructs_a_different_base_for_an_altered_authorization() {
    let altered_headers = [
        ("Authorization", "DPoP altered"),
        ("DPoP", "opaque-proof"),
        headers()[2],
    ];
    assert_altered_base(
        "POST",
        "https://api.example/fapi/resource",
        &altered_headers,
    );
}

#[test]
fn reconstructs_a_different_base_for_an_altered_dpop_proof() {
    let altered_headers = [
        ("Authorization", "DPoP opaque"),
        ("DPoP", "altered-proof"),
        headers()[2],
    ];
    assert_altered_base(
        "POST",
        "https://api.example/fapi/resource",
        &altered_headers,
    );
}

#[test]
fn replay_fingerprint_changes_with_authenticated_request_context() {
    let (_, first_fields) = fixture();
    let first = parse(first_fields).unwrap();
    let (_, second_fields) = fixture();
    let altered_headers = [
        ("Authorization", "DPoP another-token"),
        ("DPoP", "opaque-proof"),
        headers()[2],
    ];
    let second = parse_request_for_verification(
        request(
            "POST",
            "https://api.example/fapi/resource",
            &altered_headers,
            BODY,
        ),
        second_fields,
        policy(),
    )
    .unwrap();

    assert_ne!(first.replay_fingerprint(), second.replay_fingerprint());
}

#[test]
fn preserves_custom_method_case_when_reconstructing_the_base() {
    let custom_headers = headers();
    let prepared = prepare_request(
        request(
            "m-search",
            "https://api.example/fapi/resource",
            &custom_headers,
            BODY,
        ),
        RequestPolicy {
            created: CREATED,
            keyid: "client-ed25519",
            algorithm: "ed25519",
        },
    )
    .unwrap();
    let base = prepared.signature_base().to_vec();
    let fields = prepared.finish(&[1, 2, 3]);
    let parsed = parse_request_for_verification(
        request(
            "m-search",
            "https://api.example/fapi/resource",
            &custom_headers,
            BODY,
        ),
        fields,
        policy(),
    )
    .unwrap();

    assert_eq!(parsed.signature_base(), base);
}

#[test]
fn rejects_unknown_algorithm() {
    let (_, mut fields) = fixture();
    fields.signature_input = fields
        .signature_input
        .replace("alg=\"ed25519\"", "alg=\"hmac-sha256\"");
    assert_eq!(
        parse(fields).unwrap_err(),
        VerifyError::UnsupportedAlgorithm
    );
}

#[test]
fn rejects_malformed_signature_input_structured_field() {
    let (_, mut fields) = fixture();
    fields.signature_input = "sig1=(\"@method\"".into();
    assert_eq!(parse(fields).unwrap_err(), VerifyError::MalformedSignature);
}

#[test]
fn rejects_malformed_signature_structured_field() {
    let (_, mut fields) = fixture();
    fields.signature = "sig1=:not base64!:".into();
    assert_eq!(parse(fields).unwrap_err(), VerifyError::MalformedSignature);
}

#[test]
fn rejects_target_uri_userinfo_and_non_ascii_covered_values() {
    let (_, fields) = fixture();
    assert_eq!(
        parse_request_for_verification(
            request(
                "POST",
                "https://user@api.example/fapi/resource",
                &headers(),
                BODY,
            ),
            fields,
            policy(),
        )
        .unwrap_err(),
        VerifyError::MissingComponent
    );

    let (_, fields) = fixture();
    let non_ascii = [
        ("Authorization", "DPoP opaqué"),
        ("DPoP", "opaque-proof"),
        headers()[2],
    ];
    assert_eq!(
        parse_request_for_verification(
            request(
                "POST",
                "https://api.example/fapi/resource",
                &non_ascii,
                BODY,
            ),
            fields,
            policy(),
        )
        .unwrap_err(),
        VerifyError::MissingComponent
    );
}
