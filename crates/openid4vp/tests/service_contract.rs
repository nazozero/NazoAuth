use std::sync::{Arc, Mutex};

use chrono::{Duration, Utc};
use nazo_digital_credentials::{
    CredentialFormat, CredentialFuture, CredentialQuery, CredentialTrustError,
    CredentialVerifierPort, DcqlQuery, EphemeralEncryptionKey, PresentedCredential,
    VerifiedCredential,
};
use nazo_openid4vp::{
    AuthorizationRequest, AuthorizationResponse, ClientIdPrefix, ClientMetadata,
    PresentationResult, PresentationService, PresentationStoreError, PresentationStoreFuture,
    PresentationStorePort, PresentationTransaction, RequestMethod, ResponseMode,
    StoredPresentation,
};
use serde_json::json;
use uuid::Uuid;

#[derive(Clone, Default)]
struct RecordingStore;

impl PresentationStorePort for RecordingStore {
    fn create<'a>(
        &'a self,
        _transaction: &'a PresentationTransaction,
    ) -> PresentationStoreFuture<'a, Result<(), PresentationStoreError>> {
        Box::pin(async { Ok(()) })
    }

    fn request<'a>(
        &'a self,
        _transaction_id: Uuid,
        _now: chrono::DateTime<Utc>,
    ) -> PresentationStoreFuture<'a, Result<Option<PresentationTransaction>, PresentationStoreError>>
    {
        Box::pin(async { Ok(None) })
    }

    fn complete<'a>(
        &'a self,
        _transaction_id: Uuid,
        _state_hash: &'a str,
        _result: &'a PresentationResult,
        _now: chrono::DateTime<Utc>,
    ) -> PresentationStoreFuture<'a, Result<bool, PresentationStoreError>> {
        Box::pin(async { Ok(true) })
    }

    fn result<'a>(
        &'a self,
        _transaction_id: Uuid,
        _now: chrono::DateTime<Utc>,
    ) -> PresentationStoreFuture<'a, Result<Option<StoredPresentation>, PresentationStoreError>>
    {
        Box::pin(async { Ok(None) })
    }
}

#[derive(Clone)]
struct RecordingVerifier(Arc<Mutex<Option<Vec<u8>>>>);

impl CredentialVerifierPort for RecordingVerifier {
    fn verify<'a>(
        &'a self,
        presentation: &'a PresentedCredential,
    ) -> CredentialFuture<'a, Result<VerifiedCredential, CredentialTrustError>> {
        let transcript = presentation.mdoc_session_transcript.clone();
        let output = self.0.clone();
        Box::pin(async move {
            *output.lock().expect("recording verifier lock") = transcript;
            Ok(VerifiedCredential {
                format: CredentialFormat::MsoMdoc,
                issuer: "trusted-issuer".to_owned(),
                credential_type: "org.iso.18013.5.1.mDL".to_owned(),
                claims: json!({"org.iso.18013.5.1":{"family_name":"Doe"}}),
                holder_key: Some(json!({"kty":"EC"})),
                issued_at: None,
                expires_at: None,
                status: None,
            })
        })
    }
}

#[tokio::test]
async fn final_mdoc_handover_binds_verifier_key_and_request_context() {
    let response_key = EphemeralEncryptionKey::generate();
    let transaction_id = Uuid::now_v7();
    let now = Utc::now();
    let request = AuthorizationRequest {
        client_id: "x509_hash:verifier".to_owned(),
        response_type: "vp_token".to_owned(),
        response_mode: "direct_post.jwt".to_owned(),
        response_uri: format!("https://verifier.example/openid4vp/response/{transaction_id}"),
        nonce: "verifier-nonce".to_owned(),
        state: "state".to_owned(),
        dcql_query: DcqlQuery {
            credentials: vec![CredentialQuery {
                id: "mdl".to_owned(),
                format: CredentialFormat::MsoMdoc,
                meta: Some(json!({"doctype_value":"org.iso.18013.5.1.mDL"})),
                claims: None,
                claim_sets: None,
                trusted_authorities: None,
                require_cryptographic_holder_binding: Some(true),
            }],
            credential_sets: None,
        },
        client_metadata: Some(ClientMetadata {
            vp_formats_supported: json!({"mso_mdoc":{"issuerauth_alg_values":[-7]}}),
            jwks: Some(json!({"keys":[response_key.public_jwk()]})),
            encrypted_response_enc_values_supported: Some(vec![
                "A128GCM".to_owned(),
                "A256GCM".to_owned(),
            ]),
        }),
        verifier_info: None,
        transaction_data: None,
        wallet_nonce: None,
    };
    let transaction = PresentationTransaction {
        id: transaction_id,
        client_id_prefix: ClientIdPrefix::X509Hash,
        request_method: RequestMethod::RequestUriSignedPost,
        response_mode: ResponseMode::DirectPostJwt,
        wallet_authorization_endpoint: "https://wallet.example/authorize".to_owned(),
        request,
        request_object: None,
        request_uri: None,
        response_encryption_private_key: None,
        created_at: now,
        expires_at: now + Duration::minutes(5),
    };
    let recorded = Arc::new(Mutex::new(None));
    let service = PresentationService::new(RecordingStore, RecordingVerifier(recorded.clone()));

    service
        .verify_response(
            &transaction,
            &AuthorizationResponse {
                vp_token: Some(json!({"mdl":["base64url-mdoc"]})),
                state: Some("state".to_owned()),
                error: None,
                error_description: None,
            },
            now,
        )
        .await
        .expect("valid mdoc presentation");

    let transcript = recorded
        .lock()
        .expect("recording verifier lock")
        .clone()
        .expect("mdoc transcript");
    let decoded: ciborium::Value =
        ciborium::from_reader(transcript.as_slice()).expect("decode session transcript");
    let values = decoded.as_array().expect("session transcript array");
    assert_eq!(values.len(), 3);
    assert!(values[0].is_null() && values[1].is_null());
    let handover = values[2].as_array().expect("OpenID4VPHandover");
    assert_eq!(handover[0].as_text(), Some("OpenID4VPHandover"));
    assert_eq!(handover[1].as_bytes().map(Vec::len), Some(32));
}
