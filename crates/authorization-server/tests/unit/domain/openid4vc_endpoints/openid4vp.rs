use super::*;
use std::collections::BTreeMap;

#[test]
fn query_parameters_preserve_request_fields_and_encoding() {
    for optional in [false, true] {
        for mode in [ResponseMode::DirectPost, ResponseMode::DirectPostJwt] {
            let mut request: AuthorizationRequest = serde_json::from_value(json!({
                "client_id": "redirect_uri:https://wallet.example/cb?a=1&b=中文",
                "response_type": "vp_token",
                "response_mode": "direct_post",
                "response_uri": "https://verifier.example/response?x=+ %",
                "nonce": "nonce+&=",
                "state": "state with spaces 🔑",
                "dcql_query": {"credentials": []},
                "client_metadata": {"vp_formats_supported":{"dc+sd-jwt":{"sd-jwt_alg_values":["ES256"]}}},
                "verifier_info": [{"format":"jwt", "data":{"text":"quote \" and slash \\"}}],
                "transaction_data": ["opaque+&=data"],
                "wallet_nonce": "wallet+nonce"
            })).unwrap();
            request.response_mode = mode;
            if !optional {
                request.client_metadata = None;
                request.verifier_info = None;
                request.transaction_data = None;
                request.wallet_nonce = None;
            }
            let serialized = serde_json::to_value(&request).unwrap();
            let expected = serialized.as_object().unwrap();
            let mut url =
                url::Url::parse("https://wallet.example/authorize?existing=kept%20value#fragment")
                    .unwrap();
            append_request_query(&mut url, &request).unwrap();
            let actual: BTreeMap<_, _> = url.query_pairs().into_owned().collect();
            assert_eq!(actual.get("existing").unwrap(), "kept value");
            for (name, value) in expected {
                let parameter = actual.get(name).unwrap();
                if let Some(text) = value.as_str() {
                    assert_eq!(parameter, text);
                } else {
                    assert_eq!(
                        &serde_json::from_str::<serde_json::Value>(parameter).unwrap(),
                        value
                    );
                }
            }
            assert_eq!(url.query_pairs().count(), expected.len() + 1);
            assert_eq!(url.fragment(), Some("fragment"));
        }
    }
}
