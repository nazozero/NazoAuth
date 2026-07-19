use nazo_identity::{
    AccessRequestValidationError, NewAccessRequestInput, validate_access_request_input,
};

fn input() -> NewAccessRequestInput {
    NewAccessRequestInput {
        site_name: " Example application ".to_owned(),
        site_url: " https://client.example/apply ".to_owned(),
        request_description: " Production client onboarding ".to_owned(),
    }
}

#[test]
fn access_request_fields_are_trimmed_and_https_site_is_accepted() {
    let validated = validate_access_request_input(input()).expect("valid request");

    assert_eq!(validated.site_name, "Example application");
    assert_eq!(validated.site_url, "https://client.example/apply");
    assert_eq!(
        validated.request_description,
        "Production client onboarding"
    );
}

#[test]
fn access_request_database_boundaries_are_enforced_before_persistence() {
    let cases = [
        (
            NewAccessRequestInput {
                site_name: "a".repeat(121),
                ..input()
            },
            AccessRequestValidationError::TooLong("site_name"),
        ),
        (
            NewAccessRequestInput {
                site_url: format!("https://client.example/{}", "a".repeat(500)),
                ..input()
            },
            AccessRequestValidationError::TooLong("site_url"),
        ),
        (
            NewAccessRequestInput {
                request_description: "a".repeat(2_001),
                ..input()
            },
            AccessRequestValidationError::TooLong("request_description"),
        ),
    ];

    for (request, expected) in cases {
        assert_eq!(validate_access_request_input(request), Err(expected));
    }
}

#[test]
fn access_request_rejects_empty_fields_and_unsafe_site_urls() {
    for (request, expected) in [
        (
            NewAccessRequestInput {
                site_name: "  ".to_owned(),
                ..input()
            },
            AccessRequestValidationError::Empty("site_name"),
        ),
        (
            NewAccessRequestInput {
                site_url: "http://client.example".to_owned(),
                ..input()
            },
            AccessRequestValidationError::InvalidSiteUrl,
        ),
        (
            NewAccessRequestInput {
                site_url: "https://user:password@client.example".to_owned(),
                ..input()
            },
            AccessRequestValidationError::InvalidSiteUrl,
        ),
    ] {
        assert_eq!(validate_access_request_input(request), Err(expected));
    }
}
