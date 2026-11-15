use super::super::tests::{CertificateFixture, certificate_fixture, real_crypto_fixture};
use super::*;
use coset::{CborSerializable, CoseSign1Builder, HeaderBuilder, TaggedCborSerializable, iana};
use nazo_crypto::jwt::Header;
use nazo_crypto::signature::PreparedSigningKey;
use std::io::Write;

const URI: &str = "https://issuer.example/status/1";

struct ListResolver {
    bytes: Vec<u8>,
    format: CredentialFormat,
}
impl crate::ports::credential_status::CredentialStatusResolver for ListResolver {
    fn fetch<'a>(
        &'a self,
        uri: &'a str,
        format: CredentialFormat,
    ) -> nazo_digital_credentials::CredentialFuture<'a, Result<Vec<u8>, CredentialTrustError>> {
        assert_eq!(uri, URI);
        assert_eq!(format, self.format);
        Box::pin(async { Ok(self.bytes.clone()) })
    }
}

#[test]
fn credential_verifier_resolves_signed_status_after_authentication() {
    use super::super::tests::{
        resign_sd_fixture_with_claims, sd_presentation_fixture, valid_mdoc_presentation,
    };
    use nazo_digital_credentials::CredentialVerifierPort;
    use std::sync::Arc;
    futures_executor::block_on(async {
        let (crypto, original, _, certs) = sd_presentation_fixture();
        let mut credential_claims: Value = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(original.encoded.split('.').nth(1).unwrap())
                .unwrap(),
        )
        .unwrap();
        let resolver = Arc::new(ListResolver {
            bytes: jwt(&certs, &claims(), "statuslist+jwt"),
            format: CredentialFormat::SdJwtVc,
        });
        let crypto = crypto.with_status_resolver(resolver);
        for (index, accepted) in [(0, true), (1, false), (2, false), (4, false)] {
            credential_claims["status"] =
                serde_json::json!({"status_list":{"idx":index,"uri":URI}});
            let p = resign_sd_fixture_with_claims(
                &original,
                &certs,
                vec![STANDARD.encode(&certs.leaf_der)],
                &original.expected_nonce,
                &credential_claims,
            );
            assert_eq!(crypto.verify(&p).await.is_ok(), accepted);
            let bad = PresentedCredential {
                expected_nonce: "wrong".into(),
                ..p
            };
            assert_eq!(
                crypto.verify(&bad).await,
                Err(CredentialTrustError::InvalidNonce)
            );
        }
        let (crypto, certs, _) = real_crypto_fixture().await;
        let crypto = crypto.with_status_resolver(Arc::new(ListResolver {
            bytes: cwt(
                &certs,
                URI,
                Utc::now().timestamp() + 300,
                "application/statuslist+cwt",
            ),
            format: CredentialFormat::MsoMdoc,
        }));
        for (index, accepted) in [(0, true), (1, false), (8, false)] {
            let reference = serde_json::json!({"status_list":{"idx":index,"uri":URI}});
            let reference = super::super::super::crypto_helpers::json_to_cbor(&reference).unwrap();
            let (encoded, transcript) =
                valid_mdoc_presentation(&certs, Utc::now(), Some(reference));
            let p = PresentedCredential {
                encoded: encoded.into(),
                expected_nonce: "verifier-nonce".into(),
                expected_audience: "https://verifier.example".into(),
                mdoc_session_transcript: Some(transcript.into()),
                ..presentation(CredentialFormat::MsoMdoc)
            };
            assert_eq!(crypto.verify(&p).await.is_ok(), accepted);
        }
    });
}

#[test]
fn mdoc_status_signer_must_belong_to_the_credential_iaca() {
    use rcgen::{
        BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair, KeyUsagePurpose,
    };
    futures_executor::block_on(async {
        let (crypto, _, _) = real_crypto_fixture().await;
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let ca = CertifiedIssuer::self_signed(params, KeyPair::generate().unwrap()).unwrap();
        let make_leaf = || {
            let key = KeyPair::generate().unwrap();
            let mut params = CertificateParams::new(vec!["issuer.example".into()]).unwrap();
            params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
            params
                .distinguished_name
                .push(rcgen::DnType::CommonName, "Status signer");
            let cert = params.signed_by(&key, &ca).unwrap();
            CertificateFixture {
                ca_der: ca.der().to_vec(),
                ca_pem: ca.pem(),
                leaf_der: cert.der().to_vec(),
                leaf_pem: cert.pem(),
                leaf_key: key,
            }
        };
        let credential = make_leaf();
        let signer = make_leaf();
        let p = PresentedCredential {
            additional_trust_anchors: vec![ca.der().to_vec()].into(),
            ..presentation(CredentialFormat::MsoMdoc)
        };
        let token = cwt(
            &signer,
            URI,
            Utc::now().timestamp() + 300,
            "application/statuslist+cwt",
        );
        assert!(verify_cwt(&crypto, &p, &[credential.leaf_der], URI, 0, &token).is_ok());
        let unrelated = certificate_fixture("issuer.example");
        assert!(verify_cwt(&crypto, &p, &[unrelated.leaf_der], URI, 0, &token).is_err());
    });
}

fn compressed(bytes: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(bytes).unwrap();
    encoder.finish().unwrap()
}
fn claims() -> Value {
    let now = Utc::now().timestamp();
    serde_json::json!({"sub":URI,"iat":now,"exp":now+300,"ttl":60,
        "status_list":{"bits":2,"lst":URL_SAFE_NO_PAD.encode(compressed(&[0b11100100]))}})
}
fn jwt(certs: &CertificateFixture, claims: &Value, typ: &str) -> Vec<u8> {
    let mut header = Header::new(Algorithm::ES256);
    header.typ = Some(typ.into());
    header.x5c = Some(vec![STANDARD.encode(&certs.leaf_der)]);
    let message = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap()),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).unwrap())
    );
    let key = PreparedSigningKey::new(Algorithm::ES256, &certs.leaf_key.serialize_der()).unwrap();
    format!(
        "{message}.{}",
        URL_SAFE_NO_PAD.encode(key.sign(message.as_bytes()).unwrap())
    )
    .into_bytes()
}
fn presentation(format: CredentialFormat) -> PresentedCredential<'static> {
    PresentedCredential {
        format,
        encoded: "".into(),
        expected_nonce: "nonce".into(),
        expected_audience: "verifier".into(),
        mdoc_session_transcript: None,
        additional_trust_anchors: Vec::new().into(),
    }
}

#[test]
fn specification_bit_order_bounds_and_compression_are_enforced() {
    // draft-21 section 4.1 published 2-bit vector: [0xc9, 0x44, 0xf9].
    let bytes = URL_SAFE_NO_PAD.decode("eNo76fITAAPfAgc").unwrap();
    let expected = [1, 2, 0, 3, 0, 1, 0, 1, 1, 2, 3, 3];
    for (index, status) in expected.into_iter().enumerate() {
        assert_eq!(validate_index(2, index as u64, &bytes).is_ok(), status == 0);
    }
    for bits in [1, 2, 4, 8] {
        let bytes = compressed(&[0, 255]);
        assert!(validate_index(bits, 0, &bytes).is_ok());
        assert!(validate_index(bits, 8 / bits, &bytes).is_err());
        assert!(validate_index(bits, 16 / bits, &bytes).is_err());
        assert!(validate_index(bits, u64::MAX, &bytes).is_err());
    }
    assert!(validate_index(3, 0, &compressed(&[0])).is_err());
    let mut truncated = compressed(&[0; 100]);
    truncated.pop();
    assert!(validate_index(1, 0, &truncated).is_err());
    let mut trailing = compressed(&[0]);
    trailing.push(0);
    assert!(validate_index(1, 0, &trailing).is_err());
    assert!(validate_index(1, 0, &compressed(&vec![0; MAX_LIST_BYTES + 1])).is_err());
}

#[test]
fn signed_jwt_lists_bind_issuer_uri_time_and_status() {
    futures_executor::block_on(async {
        let (crypto, certs, _) = real_crypto_fixture().await;
        let issuer = vec![certs.leaf_der.clone()];
        let p = presentation(CredentialFormat::SdJwtVc);
        let token = jwt(&certs, &claims(), "statuslist+jwt");
        assert!(
            verify_jwt(
                &crypto,
                &p,
                &issuer,
                "https://issuer.example",
                URI,
                0,
                &token
            )
            .is_ok()
        );
        for index in [1, 2, 3, 4, u64::MAX] {
            assert!(
                verify_jwt(
                    &crypto,
                    &p,
                    &issuer,
                    "https://issuer.example",
                    URI,
                    index,
                    &token
                )
                .is_err()
            );
        }
        assert!(
            verify_jwt(
                &crypto,
                &p,
                &issuer,
                "https://issuer.example",
                "https://issuer.example/other",
                0,
                &token
            )
            .is_err()
        );
        assert!(
            verify_jwt(
                &crypto,
                &p,
                &issuer,
                "https://issuer.example",
                URI,
                0,
                &jwt(&certs, &claims(), "dc+sd-jwt")
            )
            .is_err()
        );
        for (key, value) in [
            ("exp", serde_json::json!(Utc::now().timestamp() - 1)),
            ("iat", serde_json::json!(Utc::now().timestamp() + 100)),
            ("nbf", serde_json::json!(Utc::now().timestamp() + 100)),
            ("ttl", serde_json::json!(0)),
            ("aud", serde_json::json!("another verifier")),
            ("iat", Value::Null),
        ] {
            let mut c = claims();
            c[key] = value;
            assert!(
                verify_jwt(
                    &crypto,
                    &p,
                    &issuer,
                    "https://issuer.example",
                    URI,
                    0,
                    &jwt(&certs, &c, "statuslist+jwt")
                )
                .is_err(),
                "{key}"
            );
        }
        let rogue = certificate_fixture("issuer.example");
        assert!(
            verify_jwt(
                &crypto,
                &p,
                &issuer,
                "https://issuer.example",
                URI,
                0,
                &jwt(&rogue, &claims(), "statuslist+jwt")
            )
            .is_err()
        );
        let mut corrupted = token;
        let len = corrupted.len();
        corrupted[len - 5] = if corrupted[len - 5] == b'A' {
            b'B'
        } else {
            b'A'
        };
        assert!(
            verify_jwt(
                &crypto,
                &p,
                &issuer,
                "https://issuer.example",
                URI,
                0,
                &corrupted
            )
            .is_err()
        );
    });
}

fn cwt(certs: &CertificateFixture, uri: &str, exp: i64, typ: &str) -> Vec<u8> {
    let now = Utc::now().timestamp();
    let payload = Cbor::Map(vec![
        (Cbor::Integer(2.into()), Cbor::Text(uri.into())),
        (Cbor::Integer(6.into()), Cbor::Integer(now.into())),
        (Cbor::Integer(4.into()), Cbor::Integer(exp.into())),
        (Cbor::Integer(65534.into()), Cbor::Integer(60.into())),
        (
            Cbor::Integer(65533.into()),
            Cbor::Map(vec![
                (Cbor::Text("bits".into()), Cbor::Integer(1.into())),
                (Cbor::Text("lst".into()), Cbor::Bytes(compressed(&[2]))),
            ]),
        ),
    ]);
    let mut body = Vec::new();
    ciborium::into_writer(&payload, &mut body).unwrap();
    let header = HeaderBuilder::new()
        .algorithm(iana::Algorithm::ES256)
        .value(16, Cbor::Text(typ.into()))
        .value(33, Cbor::Bytes(certs.leaf_der.clone()))
        .build();
    let key = PreparedSigningKey::new(Algorithm::ES256, &certs.leaf_key.serialize_der()).unwrap();
    CoseSign1Builder::new()
        .protected(header)
        .payload(body)
        .create_signature(&[], |data| key.sign(data).unwrap())
        .build()
        .to_tagged_vec()
        .unwrap()
}

#[test]
fn signed_cwt_lists_validate_cose_and_fail_closed() {
    futures_executor::block_on(async {
        let (crypto, certs, _) = real_crypto_fixture().await;
        let issuer = vec![certs.leaf_der.clone()];
        let p = presentation(CredentialFormat::MsoMdoc);
        let token = cwt(
            &certs,
            URI,
            Utc::now().timestamp() + 300,
            "application/statuslist+cwt",
        );
        assert!(verify_cwt(&crypto, &p, &issuer, URI, 0, &token).is_ok());
        assert!(verify_cwt(&crypto, &p, &issuer, URI, 1, &token).is_err());
        assert!(verify_cwt(&crypto, &p, &issuer, URI, 8, &token).is_err());
        for (uri, exp, typ) in [
            (
                "https://issuer.example/other",
                Utc::now().timestamp() + 300,
                "application/statuslist+cwt",
            ),
            (
                URI,
                Utc::now().timestamp() - 1,
                "application/statuslist+cwt",
            ),
            (URI, Utc::now().timestamp() + 300, "application/cwt"),
        ] {
            assert!(verify_cwt(&crypto, &p, &issuer, URI, 0, &cwt(&certs, uri, exp, typ)).is_err());
        }
        let rogue = certificate_fixture("issuer.example");
        assert!(
            verify_cwt(
                &crypto,
                &p,
                &issuer,
                URI,
                0,
                &cwt(
                    &rogue,
                    URI,
                    Utc::now().timestamp() + 300,
                    "application/statuslist+cwt"
                )
            )
            .is_err()
        );
        let untagged = coset::CoseSign1::from_tagged_slice(&token)
            .unwrap()
            .to_vec()
            .unwrap();
        assert!(verify_cwt(&crypto, &p, &issuer, URI, 0, &untagged).is_err());
        let cwt_tagged = [vec![0xd8, 61], token.clone()].concat();
        assert!(verify_cwt(&crypto, &p, &issuer, URI, 0, &cwt_tagged).is_err());
        let mut corrupted = token;
        let last = corrupted.len() - 1;
        corrupted[last] ^= 1;
        assert!(verify_cwt(&crypto, &p, &issuer, URI, 0, &corrupted).is_err());
    });
}
