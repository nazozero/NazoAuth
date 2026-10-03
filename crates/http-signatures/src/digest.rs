use sfv::{BareItem, Dictionary, ItemSerializer, ListEntry, Parser, Version};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// Computes an RFC 9530 SHA-256 `Content-Digest` field value.
pub fn content_digest(body: &[u8]) -> String {
    let digest = Sha256::digest(body);
    format!(
        "sha-256={}",
        ItemSerializer::new().bare_item(digest.as_slice()).finish()
    )
}

/// Validates an RFC 9530 digest dictionary and its unique SHA-256 member.
pub fn content_digest_field_matches(field_value: &str, body: &[u8]) -> bool {
    let field_value = field_value.trim_matches([' ', '\t']);
    let Ok(dictionary): Result<Dictionary, _> = Parser::new(field_value)
        .with_version(Version::Rfc8941)
        .parse()
    else {
        return false;
    };
    if crate::verify::top_level_member_count(field_value) != dictionary.len()
        || raw_dictionary_key_count(field_value, "sha-256") != 1
        || dictionary.values().any(|entry| {
            !matches!(
                entry,
                ListEntry::Item(item)
                    if item.params.is_empty()
                        && matches!(item.bare_item, BareItem::ByteSequence(_))
            )
        })
    {
        return false;
    }
    let digest: [u8; 32] = match dictionary.get("sha-256") {
        Some(ListEntry::Item(item)) if item.params.is_empty() => match &item.bare_item {
            BareItem::ByteSequence(bytes) => match bytes.as_slice().try_into() {
                Ok(digest) => digest,
                Err(_) => return false,
            },
            _ => return false,
        },
        _ => return false,
    };
    let computed: [u8; 32] = Sha256::digest(body).into();
    bool::from(digest.ct_eq(&computed))
}

fn raw_dictionary_key_count(field: &str, wanted: &str) -> usize {
    field
        .split(',')
        .filter_map(|member| {
            member
                .trim_start()
                .split_once(['=', ';'])
                .map(|(key, _)| key)
                .or_else(|| Some(member.trim()))
        })
        .filter(|key| *key == wanted)
        .count()
}

/// A digest established for one borrowed, immutable body.
///
/// The private body borrow keeps the bytes alive and immutable for the evidence's
/// lifetime. Reuse requires the same slice and the same field value; neither body
/// length nor an externally supplied boolean can establish this evidence.
pub struct BodyDigest<'body> {
    body: &'body [u8],
    field_value: String,
}

impl<'body> BodyDigest<'body> {
    /// Computes the field for an outgoing body once.
    pub fn for_body(body: &'body [u8]) -> Self {
        Self {
            body,
            field_value: content_digest(body),
        }
    }

    /// Checks a received field against the actual body before retaining evidence.
    pub fn from_field(field_value: &str, body: &'body [u8]) -> Option<Self> {
        content_digest_field_matches(field_value, body).then(|| Self {
            body,
            field_value: field_value.trim_matches([' ', '\t']).to_owned(),
        })
    }

    pub fn field_value(&self) -> &str {
        &self.field_value
    }

    pub(crate) fn matches(&self, field_value: &str, body: &[u8]) -> bool {
        std::ptr::eq(self.body, body) && field_value.trim_matches([' ', '\t']) == self.field_value
    }
}

pub(crate) fn digest_matches(
    field_value: &str,
    body: &[u8],
    evidence: Option<&BodyDigest<'_>>,
) -> bool {
    match evidence {
        Some(evidence) => evidence.matches(field_value, body),
        None => content_digest_field_matches(field_value, body),
    }
}
