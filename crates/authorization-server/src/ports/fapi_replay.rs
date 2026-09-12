//! Atomic replay reservations for FAPI HTTP Message Signatures.

use std::{future::Future, pin::Pin};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FapiHttpSignatureReplayConsumption {
    Accepted,
    Replay,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FapiHttpSignatureReplayStoreError;

/// Atomic replay-fingerprint consumption for FAPI HTTP Message Signatures.
///
/// Implementations must reserve a fingerprint at most once within the
/// requested validity window. Backend failures are distinct from replay so
/// the protocol adapter can fail closed with `ReplayUnavailable`.
pub trait FapiHttpSignatureReplayStore: Send + Sync {
    fn consume<'a>(
        &'a self,
        tenant_id: nazo_identity::TenantId,
        fingerprint: &'a [u8],
        ttl_seconds: i64,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        FapiHttpSignatureReplayConsumption,
                        FapiHttpSignatureReplayStoreError,
                    >,
                > + Send
                + 'a,
        >,
    >;
}
