use super::super::tests::{CertificateFixture, certificate_fixture, real_crypto_fixture};
use super::*;
use coset::{CborSerializable, CoseSign1Builder, HeaderBuilder, TaggedCborSerializable, iana};
use nazo_crypto::jwt::Header;
use nazo_crypto::signature::PreparedSigningKey;
use nazo_digital_credentials::PresentedCredential;
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

struct UnreachableListResolver;

impl crate::ports::credential_status::CredentialStatusResolver for UnreachableListResolver {
    fn fetch<'a>(
        &'a self,
        _uri: &'a str,
        _format: CredentialFormat,
    ) -> nazo_digital_credentials::CredentialFuture<'a, Result<Vec<u8>, CredentialTrustError>> {
        Box::pin(async { Err(CredentialTrustError::Unavailable) })
    }
}

#[test]
fn mdoc_issuance_requires_explicit_policy_and_an_authenticated_published_list() {
    use super::super::MdocStatusIssuancePolicy;
    use nazo_digital_credentials::{
        CredentialPayload, CredentialSignInput, CredentialSignerPort, HolderBinding,
    };
    use std::sync::Arc;
    futures_executor::block_on(async {
        let (crypto, certs, _) = real_crypto_fixture().await;
        let key = nazo_digital_credentials::EphemeralEncryptionKey::generate().public_jwk();
        let now = Timestamp::now();
        let mut input = CredentialSignInput {
            payload: CredentialPayload {
                issuer: "https://issuer.example".into(),
                configuration_id: "example-mdoc".into(),
                format: CredentialFormat::MsoMdoc,
                credential_type: "org.example.credential".into(),
                subject_claims: serde_json::json!({"org.example.namespace":{"name":"Ada"}}),
                holder_binding: Some(HolderBinding::Jwk { jwk: key }),
            },
            issued_at: now,
            expires_at: now + jiff::SignedDuration::from_hours(1),
            status: Some(serde_json::json!({"status_list":{"idx":0,"uri":URI}})),
        };
        assert_eq!(
            crypto.sign(&input).await,
            Err(CredentialTrustError::InvalidStatus)
        );
        let enabled = crypto
            .clone()
            .with_mdoc_status_issuance(MdocStatusIssuancePolicy::PublishedTokenStatusList);
        assert_eq!(
            enabled.sign(&input).await,
            Err(CredentialTrustError::InvalidStatus)
        );
        assert_eq!(
            enabled
                .clone()
                .with_status_resolver(Arc::new(UnreachableListResolver))
                .sign(&input)
                .await,
            Err(CredentialTrustError::Unavailable)
        );
        let token = cwt(
            &certs,
            URI,
            now.as_second() + 300,
            "application/statuslist+cwt",
        );
        let enabled = enabled.with_status_resolver(Arc::new(ListResolver {
            bytes: token.clone(),
            format: CredentialFormat::MsoMdoc,
        }));
        let encoded = enabled
            .sign(&input)
            .await
            .expect("published good status entry");
        let bytes = URL_SAFE_NO_PAD.decode(encoded).unwrap();
        let issued = nazo_mdoc::parser::parse_issued_borrowed(&bytes).unwrap();
        let mso = issued.issuer_auth.mso().unwrap();
        assert_eq!(
            mdoc_reference_to_json(mso.status.unwrap().raw).unwrap(),
            input.status.clone().unwrap()
        );
        // The same resolver does not authorize issuance without the explicit policy.
        assert_eq!(
            crypto
                .clone()
                .with_status_resolver(Arc::new(ListResolver {
                    bytes: token,
                    format: CredentialFormat::MsoMdoc,
                }))
                .sign(&input)
                .await,
            Err(CredentialTrustError::InvalidStatus)
        );

        for reference in [
            serde_json::json!({"status_list":{"idx":1,"uri":URI}}),
            serde_json::json!({"status_list":{"idx":2,"uri":URI}}),
            serde_json::json!({"status_list":{"idx":3,"uri":URI}}),
            serde_json::json!({"status_list":{"idx":4,"uri":URI}}),
            serde_json::json!({"status_list":{"idx":8,"uri":URI}}),
            serde_json::json!({"status_list":{"idx":u64::MAX,"uri":URI}}),
            serde_json::json!({"status_list":{"idx":-1,"uri":URI}}),
            serde_json::json!({"status_list":{"idx":0.5,"uri":URI}}),
            serde_json::json!({"status_list":{"idx":0,"uri":"http://issuer.example/status/1"}}),
            serde_json::json!({"status_list":{"idx":0,"uri":"https://user@issuer.example/status/1"}}),
            serde_json::json!({"status_list":{"idx":0,"uri":"https://issuer.example/status/1#fragment"}}),
            serde_json::json!({"status_list":{"idx":0,"uri":URI,"certificate":"delegation"}}),
            serde_json::json!({"status_list":{"idx":0,"uri":URI},"future_status":{}}),
            serde_json::json!({"future_status":{"uri":URI}}),
        ] {
            input.status = Some(reference);
            assert_eq!(
                enabled.sign(&input).await,
                Err(CredentialTrustError::InvalidStatus)
            );
        }
        input.status = None;
        assert!(
            crypto
                .with_status_resolver(Arc::new(UnreachableListResolver))
                .sign(&input)
                .await
                .is_ok(),
            "no status reference must not initiate a status request"
        );
    });
}

fn project_mdoc_status(raw: Cbor) -> Result<Value, CredentialTrustError> {
    let mut encoded = Vec::new();
    ciborium::into_writer(&raw, &mut encoded).unwrap();
    let borrowed = nazo_mdoc::model::borrowed::CborValueRef::parse(&encoded)
        .map_err(|_| CredentialTrustError::InvalidStatus)?;
    mdoc_reference_to_json(borrowed)
}

#[test]
fn mdoc_status_projection_preserves_presence_and_rejects_unknown_semantics() {
    let good = Cbor::Map(vec![(
        Cbor::Text("status_list".into()),
        Cbor::Map(vec![
            (Cbor::Text("idx".into()), Cbor::Integer(0.into())),
            (Cbor::Text("uri".into()), Cbor::Text(URI.into())),
        ]),
    )]);
    assert_eq!(
        project_mdoc_status(good.clone()).unwrap(),
        serde_json::json!({"status_list":{"idx":0,"uri":URI}})
    );
    let mut tagged_index = good.clone();
    let Cbor::Map(mechanisms) = &mut tagged_index else {
        unreachable!()
    };
    let Cbor::Map(reference) = &mut mechanisms[0].1 else {
        unreachable!()
    };
    reference[0].1 = Cbor::Tag(1, Box::new(Cbor::Integer(0.into())));
    let mut duplicate = good.clone();
    let Cbor::Map(mechanisms) = &mut duplicate else {
        unreachable!()
    };
    mechanisms.push(mechanisms[0].clone());
    for raw in [
        Cbor::Null,
        Cbor::Map(vec![]),
        Cbor::Tag(24, Box::new(good)),
        Cbor::Map(vec![(
            Cbor::Text("future_status".into()),
            Cbor::Map(vec![]),
        )]),
        tagged_index,
        duplicate,
    ] {
        assert_eq!(
            project_mdoc_status(raw),
            Err(CredentialTrustError::InvalidStatus)
        );
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
                Timestamp::now().as_second() + 300,
                "application/statuslist+cwt",
            ),
            format: CredentialFormat::MsoMdoc,
        }));
        for (index, accepted) in [(0, true), (1, false), (2, false), (3, false), (4, false)] {
            let reference = serde_json::json!({"status_list":{"idx":index,"uri":URI}});
            let reference = super::super::super::crypto_helpers::json_to_cbor(&reference).unwrap();
            let (encoded, transcript) =
                valid_mdoc_presentation(&certs, Timestamp::now(), Some(reference));
            let p = PresentedCredential {
                encoded: encoded.into(),
                expected_nonce: "verifier-nonce".into(),
                expected_audience: "https://verifier.example".into(),
                mdoc_session_transcript: Some(transcript.into()),
                ..presentation(CredentialFormat::MsoMdoc)
            };
            assert_eq!(crypto.verify(&p).await.is_ok(), accepted);
            if accepted {
                assert_eq!(
                    crypto
                        .clone()
                        .with_status_resolver(Arc::new(UnreachableListResolver))
                        .verify(&p)
                        .await,
                    Err(CredentialTrustError::Unavailable),
                    "a valid signature does not bypass an unavailable status server",
                );
            }
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
            Timestamp::now().as_second() + 300,
            "application/statuslist+cwt",
        );
        assert!(
            verify_cwt(
                &crypto,
                &p.additional_trust_anchors,
                &[credential.leaf_der],
                URI,
                0,
                &token
            )
            .is_ok()
        );
        let unrelated = certificate_fixture("issuer.example");
        assert!(
            verify_cwt(
                &crypto,
                &p.additional_trust_anchors,
                &[unrelated.leaf_der],
                URI,
                0,
                &token
            )
            .is_err()
        );
    });
}

fn compressed(bytes: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(bytes).unwrap();
    encoder.finish().unwrap()
}
fn claims() -> Value {
    let now = Timestamp::now().as_second();
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
                &p.additional_trust_anchors,
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
                    &p.additional_trust_anchors,
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
                &p.additional_trust_anchors,
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
                &p.additional_trust_anchors,
                &issuer,
                "https://issuer.example",
                URI,
                0,
                &jwt(&certs, &claims(), "dc+sd-jwt")
            )
            .is_err()
        );
        for (key, value) in [
            ("exp", serde_json::json!(Timestamp::now().as_second() - 1)),
            ("iat", serde_json::json!(Timestamp::now().as_second() + 100)),
            ("nbf", serde_json::json!(Timestamp::now().as_second() + 100)),
            ("ttl", serde_json::json!(0)),
            ("aud", serde_json::json!("another verifier")),
            ("iat", Value::Null),
        ] {
            let mut c = claims();
            c[key] = value;
            assert!(
                verify_jwt(
                    &crypto,
                    &p.additional_trust_anchors,
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
                &p.additional_trust_anchors,
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
                &p.additional_trust_anchors,
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
    let now = Timestamp::now().as_second();
    let payload = Cbor::Map(vec![
        (Cbor::Integer(2.into()), Cbor::Text(uri.into())),
        (Cbor::Integer(6.into()), Cbor::Integer(now.into())),
        (Cbor::Integer(4.into()), Cbor::Integer(exp.into())),
        (Cbor::Integer(65534.into()), Cbor::Integer(60.into())),
        (
            Cbor::Integer(65533.into()),
            Cbor::Map(vec![
                (Cbor::Text("bits".into()), Cbor::Integer(2.into())),
                (
                    Cbor::Text("lst".into()),
                    Cbor::Bytes(compressed(&[0b11100100])),
                ),
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
fn signed_cwt_lists_preserve_wire_types_and_header_presence() {
    futures_executor::block_on(async {
        let (crypto, certs, _) = real_crypto_fixture().await;
        let original = cwt(
            &certs,
            URI,
            jiff::Timestamp::now().as_second() + 300,
            "application/statuslist+cwt",
        );
        let key =
            PreparedSigningKey::new(Algorithm::ES256, &certs.leaf_key.serialize_der()).unwrap();
        let (_, certificate) = x509_parser::parse_x509_certificate(&certs.leaf_der).unwrap();
        let verification = VerificationKey::from_ec_sec1(
            certificate.public_key().subject_public_key.data.as_ref(),
        );
        let encode = |value: &Cbor| {
            let mut bytes = Vec::new();
            // These are deliberately non-preferred tagged-integer wire inputs.
            // Do not let a canonical encoder repair them before authentication.
            ciborium::into_writer(value, &mut bytes).unwrap();
            bytes
        };
        let mut unexpectedly_accepted = Vec::new();
        for case in [
            "valid",
            "bits_tag2",
            "ttl_tag2",
            "subject_label_tag2",
            "list_label_tag2",
            "alg_label_tag2",
            "alg_tag3",
            "type_label_tag2",
            "chain_label_tag2",
            "empty_protected_crit",
            "empty_unprotected_crit",
            "duplicate_kid_buckets",
        ] {
            let mut outer: Cbor = ciborium::from_reader(original.as_slice()).unwrap();
            let Cbor::Tag(18, body) = &mut outer else {
                unreachable!()
            };
            let fields = body.as_array_mut().unwrap();
            let mut protected: Cbor =
                ciborium::from_reader(fields[0].as_bytes().unwrap().as_slice()).unwrap();
            let mut claims: Cbor =
                ciborium::from_reader(fields[2].as_bytes().unwrap().as_slice()).unwrap();
            let tagged = |n: u16| {
                let bytes = if n <= 255 {
                    vec![n as u8]
                } else {
                    n.to_be_bytes().to_vec()
                };
                Cbor::Tag(2, Box::new(Cbor::Bytes(bytes)))
            };
            match case {
                "valid" => {}
                "bits_tag2" => {
                    let (_, list) = claims
                        .as_map_mut()
                        .unwrap()
                        .iter_mut()
                        .find(|(key, _)| key.as_integer().map(i128::from) == Some(65533))
                        .unwrap();
                    list.as_map_mut()
                        .unwrap()
                        .iter_mut()
                        .find(|(key, _)| key.as_text() == Some("bits"))
                        .unwrap()
                        .1 = tagged(2);
                }
                "ttl_tag2" => {
                    claims
                        .as_map_mut()
                        .unwrap()
                        .iter_mut()
                        .find(|(key, _)| key.as_integer().map(i128::from) == Some(65534))
                        .unwrap()
                        .1 = tagged(60)
                }
                "subject_label_tag2" | "list_label_tag2" => {
                    let label = if case == "subject_label_tag2" {
                        2
                    } else {
                        65533
                    };
                    claims
                        .as_map_mut()
                        .unwrap()
                        .iter_mut()
                        .find(|(key, _)| key.as_integer().map(i128::from) == Some(label))
                        .unwrap()
                        .0 = tagged(label as u16);
                }
                "alg_label_tag2" | "type_label_tag2" | "chain_label_tag2" => {
                    let label = match case {
                        "alg_label_tag2" => 1,
                        "type_label_tag2" => 16,
                        _ => 33,
                    };
                    protected
                        .as_map_mut()
                        .unwrap()
                        .iter_mut()
                        .find(|(key, _)| key.as_integer().map(i128::from) == Some(label))
                        .unwrap()
                        .0 = tagged(label as u16);
                }
                "alg_tag3" => {
                    protected
                        .as_map_mut()
                        .unwrap()
                        .iter_mut()
                        .find(|(key, _)| key.as_integer().map(i128::from) == Some(1))
                        .unwrap()
                        .1 = Cbor::Tag(3, Box::new(Cbor::Bytes(vec![6])))
                }
                "empty_protected_crit" => protected
                    .as_map_mut()
                    .unwrap()
                    .push((Cbor::Integer(2.into()), Cbor::Array(vec![]))),
                "empty_unprotected_crit" => fields[1]
                    .as_map_mut()
                    .unwrap()
                    .push((Cbor::Integer(2.into()), Cbor::Array(vec![]))),
                "duplicate_kid_buckets" => {
                    protected
                        .as_map_mut()
                        .unwrap()
                        .push((Cbor::Integer(4.into()), Cbor::Bytes(vec![1])));
                    fields[1]
                        .as_map_mut()
                        .unwrap()
                        .push((Cbor::Integer(4.into()), Cbor::Bytes(vec![2])));
                }
                _ => unreachable!(),
            }
            let protected = encode(&protected);
            let payload = encode(&claims);
            let signature_input = encode(&Cbor::Array(vec![
                Cbor::Text("Signature1".into()),
                Cbor::Bytes(protected.clone()),
                Cbor::Bytes(vec![]),
                Cbor::Bytes(payload.clone()),
            ]));
            let signature = key.sign(&signature_input).unwrap();
            nazo_crypto::signature::verify(Algorithm::ES256, &verification, &signature_input, &signature)
                .expect("every malformed field is covered by a real valid signature over its original bytes");
            fields[0] = Cbor::Bytes(protected);
            fields[2] = Cbor::Bytes(payload);
            fields[3] = Cbor::Bytes(signature);
            let token = encode(&outer);
            let result = verify_cwt(
                &crypto,
                &[],
                std::slice::from_ref(&certs.leaf_der),
                URI,
                0,
                &token,
            );
            if case == "valid" {
                result.expect("correctly signed, active status entry");
            } else if result.is_ok() {
                unexpectedly_accepted.push(case);
            } else {
                assert_eq!(result, Err(CredentialTrustError::InvalidStatus), "{case}");
            }
        }
        assert!(
            unexpectedly_accepted.is_empty(),
            "accepted altered wire types/headers: {unexpectedly_accepted:?}"
        );
    });
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
            Timestamp::now().as_second() + 300,
            "application/statuslist+cwt",
        );
        assert!(
            verify_cwt(
                &crypto,
                &p.additional_trust_anchors,
                &issuer,
                URI,
                0,
                &token
            )
            .is_ok()
        );
        assert!(
            verify_cwt(
                &crypto,
                &p.additional_trust_anchors,
                &issuer,
                URI,
                1,
                &token
            )
            .is_err()
        );
        assert!(
            verify_cwt(
                &crypto,
                &p.additional_trust_anchors,
                &issuer,
                URI,
                8,
                &token
            )
            .is_err()
        );
        for (uri, exp, typ) in [
            (
                "https://issuer.example/other",
                Timestamp::now().as_second() + 300,
                "application/statuslist+cwt",
            ),
            (
                URI,
                Timestamp::now().as_second() - 1,
                "application/statuslist+cwt",
            ),
            (URI, Timestamp::now().as_second() + 300, "application/cwt"),
        ] {
            assert!(
                verify_cwt(
                    &crypto,
                    &p.additional_trust_anchors,
                    &issuer,
                    URI,
                    0,
                    &cwt(&certs, uri, exp, typ)
                )
                .is_err()
            );
        }
        let rogue = certificate_fixture("issuer.example");
        assert!(
            verify_cwt(
                &crypto,
                &p.additional_trust_anchors,
                &issuer,
                URI,
                0,
                &cwt(
                    &rogue,
                    URI,
                    Timestamp::now().as_second() + 300,
                    "application/statuslist+cwt"
                )
            )
            .is_err()
        );
        let untagged = coset::CoseSign1::from_tagged_slice(&token)
            .unwrap()
            .to_vec()
            .unwrap();
        assert!(
            verify_cwt(
                &crypto,
                &p.additional_trust_anchors,
                &issuer,
                URI,
                0,
                &untagged
            )
            .is_err()
        );
        let mut critical_unprotected = coset::CoseSign1::from_tagged_slice(&token).unwrap();
        critical_unprotected.unprotected = HeaderBuilder::new()
            .add_critical(iana::HeaderParameter::Alg)
            .build();
        assert!(
            verify_cwt(
                &crypto,
                &p.additional_trust_anchors,
                &issuer,
                URI,
                0,
                &critical_unprotected.to_tagged_vec().unwrap(),
            )
            .is_err(),
            "a critical header cannot be accepted from the unprotected bucket",
        );
        let cwt_tagged = [vec![0xd8, 61], token.clone()].concat();
        assert!(
            verify_cwt(
                &crypto,
                &p.additional_trust_anchors,
                &issuer,
                URI,
                0,
                &cwt_tagged
            )
            .is_err()
        );
        let mut corrupted = token;
        let last = corrupted.len() - 1;
        corrupted[last] ^= 1;
        assert!(
            verify_cwt(
                &crypto,
                &p.additional_trust_anchors,
                &issuer,
                URI,
                0,
                &corrupted
            )
            .is_err()
        );
    });
}
