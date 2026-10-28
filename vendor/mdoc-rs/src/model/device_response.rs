//! DeviceResponse and DeviceRequest types (ISO 18013-5 §8.3.2.1.2).

use std::collections::HashMap;

/// Device response (ISO 18013-5 §8.3.2.1.2.2).
///
/// Wraps one or more documents in a response to a reader's request.
#[derive(Clone, Debug)]
pub struct DeviceResponse {
    /// Version (must be "1.0").
    pub version: String,
    /// Documents in the response.
    pub documents: Option<Vec<super::document::IssuerSignedDocument>>,
    /// Status code.
    pub status: u8,
}

/// Device request (ISO 18013-5 §8.3.2.1.2.1).
#[derive(Clone, Debug)]
pub struct DeviceRequest {
    /// Version (must be "1.0").
    pub version: String,
    /// Per-document requests.
    pub doc_requests: Vec<DocRequest>,
}

/// Per-document request.
#[derive(Clone, Debug)]
pub struct DocRequest {
    /// Requested items.
    pub items_request: ItemsRequest,
    /// Optional reader authentication (COSE_Sign1).
    pub reader_auth: Option<coset::CoseSign1>,
}

/// Items request (specifies which data elements to request).
#[derive(Clone, Debug)]
pub struct ItemsRequest {
    /// Document type.
    pub doc_type: String,
    /// Requested namespaces and elements.
    /// namespace → (element_identifier → intent_to_retain).
    pub name_spaces: HashMap<String, HashMap<String, bool>>,
}
