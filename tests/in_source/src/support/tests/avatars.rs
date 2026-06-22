use super::*;

#[test]
fn avatar_content_type_accepts_only_supported_magic_numbers() {
    assert_eq!(
        detect_avatar_content_type(b"\x89PNG\r\n\x1a\nrest"),
        Some("image/png")
    );
    assert_eq!(
        detect_avatar_content_type(b"\xff\xd8\xffrest"),
        Some("image/jpeg")
    );
    assert_eq!(
        detect_avatar_content_type(b"RIFF1234WEBPrest"),
        Some("image/webp")
    );

    for bytes in [
        &b""[..],
        &b"not-an-image"[..],
        &b"\x89PNG\r\n"[..],
        &b"RIFF1234JPEG"[..],
    ] {
        assert_eq!(
            detect_avatar_content_type(bytes),
            None,
            "avatar upload must fail closed for unsupported or truncated content"
        );
    }
}
