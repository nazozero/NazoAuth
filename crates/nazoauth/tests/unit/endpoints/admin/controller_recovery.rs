use super::*;

#[test]
fn unauthenticated_challenge_hides_root_presence() {
    let missing = challenge_error_response(
        crate::control::recovery_root::RecoveryRootServiceError::Root(
            nazo_persistence::control_plane::RecoveryRootError::RootMissing,
        ),
    );
    let invalid = challenge_error_response(
        crate::control::recovery_root::RecoveryRootServiceError::Root(
            nazo_persistence::control_plane::RecoveryRootError::InvalidAllocationProof,
        ),
    );
    assert_eq!(missing.status(), StatusCode::BAD_REQUEST);
    assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);
    assert_eq!(missing.into_body(), invalid.into_body());
}
