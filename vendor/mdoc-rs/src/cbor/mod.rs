//! CBOR utilities for mdoc.
//!
//! Handles ISO 18013-5 specific CBOR tags:
//! - Tag 24: Encoded CBOR data item (for independently verifiable items)
//! - Tag 1004: Full-date string (RFC 8943, for birth_date, expiry_date, etc.)

pub mod data_item;
pub mod date;

pub use data_item::{decode_cbor, encode_cbor, unwrap_tag24, wrap_tag24};
pub use date::FullDate;
