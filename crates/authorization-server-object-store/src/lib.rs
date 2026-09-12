#![forbid(unsafe_code)]

//! Concrete S3-compatible avatar object storage adapter.
//!
//! S3 credentials, bucket topology, and signing live here.  The identity
//! crate receives only its provider-neutral object-store port.

mod s3;

pub use s3::{S3AvatarObjectStore, S3AvatarObjectStoreConfig};
