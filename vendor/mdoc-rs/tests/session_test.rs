use mdoc_rs::session::SessionTranscript;

#[test]
fn raw_transcript_encoding_borrows_both_owned_and_borrowed_storage() {
    use std::borrow::Cow;
    let bytes = vec![0x81, 0xf6];
    let pointer = bytes.as_ptr();
    let transcript = SessionTranscript::Raw(Cow::Borrowed(&bytes));
    let encoded = transcript.to_cbor_bytes().unwrap();
    assert!(matches!(encoded, Cow::Borrowed(_)));
    assert_eq!(encoded.as_ptr(), pointer);
    assert_eq!(encoded.as_ref(), bytes);
    let transcript = SessionTranscript::Raw(Cow::Owned(bytes));
    let encoded = transcript.to_cbor_bytes().unwrap();
    assert!(matches!(encoded, Cow::Borrowed(_)));
    assert_eq!(encoded.as_ptr(), pointer);
}
