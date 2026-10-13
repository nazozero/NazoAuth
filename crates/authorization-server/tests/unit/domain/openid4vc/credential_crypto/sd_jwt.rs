use super::*;

fn disclosure(value: Value) -> (String, String) {
    let encoded = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&value).unwrap());
    let digest = URL_SAFE_NO_PAD.encode(Sha256::digest(encoded.as_bytes()));
    (encoded, digest)
}

#[test]
fn reconstructs_plaintext_nested_objects_and_array_disclosures() {
    let (city, city_hash) = disclosure(json!(["city-salt", "city", "Paris"]));
    let (address, address_hash) =
        disclosure(json!(["address-salt", "address", {"_sd": [city_hash]}]));
    let (nationality, nationality_hash) = disclosure(json!(["nationality-salt", "FR"]));
    let payload = json!({"iss": "issuer", "name": "Ada", "_sd_alg": "sha-256",
        "_sd": [address_hash, "unrevealed-decoy"],
        "nationalities": ["GB", {"...": nationality_hash}, {"...": "array-decoy"}]});
    assert_eq!(
        process_disclosures(payload, &[&city, &nationality, &address]).unwrap(),
        json!({"iss": "issuer", "name": "Ada", "address": {"city": "Paris"}, "nationalities": ["GB", "FR"]})
    );
    assert_eq!(
        process_disclosures(json!({"plain": true}), &[]).unwrap(),
        json!({"plain": true})
    );
}

#[test]
fn rejects_malformed_disclosures_and_conflicting_names() {
    for value in [
        json!([1, "name", "Ada"]),
        json!(["salt", 1, true]),
        json!(["salt", "_sd", []]),
        json!(["salt", "...", "x"]),
        json!(["salt", "_sd_alg", "sha-256"]),
        json!(["salt"]),
        json!(["salt", 1, 2, 3]),
    ] {
        let (encoded, digest) = disclosure(value);
        assert!(process_disclosures(json!({"_sd": [digest]}), &[&encoded]).is_err());
    }
    let (encoded, digest) = disclosure(json!(["salt", "name", "Ada"]));
    assert!(process_disclosures(json!({"name": "Grace", "_sd": [digest]}), &[&encoded]).is_err());
    let (other, other_digest) = disclosure(json!(["other-salt", "name", "Grace"]));
    assert!(
        process_disclosures(json!({"_sd": [digest, other_digest]}), &[&encoded, &other]).is_err()
    );
}

#[test]
fn rejects_duplicate_unused_and_misplaced_digests() {
    let (encoded, digest) = disclosure(json!(["salt", "name", "Ada"]));
    for payload in [
        json!({"_sd": [digest, digest]}),
        json!({"_sd": [digest], "nested": {"_sd": [digest]}}),
        json!({"_sd": ["decoy", "decoy"]}),
        json!({"_sd": [42]}),
        json!({"_sd": "bad"}),
        json!({"...": digest}),
        json!({"a": [{"...": digest, "extra": true}]}),
        json!({"a": [{"...": 123}]}),
        json!({"nested": {"_sd_alg": "sha-256"}}),
        json!({"_sd_alg": 1}),
        json!({"_sd_alg": "sha-512"}),
    ] {
        assert!(process_disclosures(payload, &[]).is_err());
    }
    assert!(process_disclosures(json!({}), &[&encoded]).is_err());
    assert!(process_disclosures(json!({"_sd": [digest]}), &[&encoded, &encoded]).is_err());
    assert!(process_disclosures(json!({"a": [{"...": digest}]}), &[&encoded]).is_err());
    let (encoded, digest) = disclosure(json!(["salt", "array value"]));
    assert!(process_disclosures(json!({"_sd": [digest]}), &[&encoded]).is_err());
}

#[test]
fn protects_vc_control_claims_and_their_subclaims() {
    for name in [
        "iss",
        "nbf",
        "exp",
        "cnf",
        "vct",
        "vct#integrity",
        "aka_vcts",
        "status",
    ] {
        let (encoded, digest) = disclosure(json!(["salt", name, "value"]));
        assert!(
            process_disclosures(json!({"_sd": [digest]}), &[&encoded]).is_err(),
            "{name}"
        );
        for value in [
            json!({"nested": {"_sd": ["decoy"]}}),
            json!([{"...": "decoy"}]),
        ] {
            assert!(
                process_disclosures(json!({name: value}), &[]).is_err(),
                "{name}"
            );
        }
    }
    for name in ["iat", "sub"] {
        let (encoded, digest) = disclosure(json!(["salt", name, "value"]));
        assert_eq!(
            process_disclosures(json!({"_sd": [digest]}), &[&encoded]).unwrap(),
            json!({name: "value"})
        );
    }
    let (encoded, digest) = disclosure(json!(["salt", "nbf", "business claim"]));
    assert_eq!(
        process_disclosures(json!({"nested": {"_sd": [digest]}}), &[&encoded]).unwrap(),
        json!({"nested": {"nbf": "business claim"}})
    );
}

#[test]
fn bounds_depth_across_individually_valid_disclosures() {
    let mut value = json!(true);
    let mut encoded = Vec::new();
    for i in 0..130 {
        let (disclosure, digest) = disclosure(json!([format!("salt-{i}"), "nested", value]));
        encoded.push(disclosure);
        value = json!({"_sd": [digest]});
    }
    let borrowed: Vec<_> = encoded.iter().map(String::as_str).collect();
    assert!(process_disclosures(value, &borrowed).is_err());
}
