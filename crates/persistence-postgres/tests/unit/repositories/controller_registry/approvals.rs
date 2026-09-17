//! Pure-logic pins for the fresh-2FA identity approval boundary (D05).

use super::ControllerIdentityAction;

#[test]
fn identity_action_catalog_is_closed() {
    for action in [
        ControllerIdentityAction::Bind,
        ControllerIdentityAction::Add,
        ControllerIdentityAction::Rotate,
        ControllerIdentityAction::Revoke,
        // D12 rotates the recovery root through the same approval machinery
        // under its own action value (04A).
        ControllerIdentityAction::RecoveryRootRotate,
    ] {
        assert_eq!(
            ControllerIdentityAction::parse(action.as_str()),
            Some(action)
        );
    }
    assert_eq!(ControllerIdentityAction::parse("recovery"), None);
    assert_eq!(ControllerIdentityAction::parse("recovery-root"), None);
    assert_eq!(ControllerIdentityAction::parse(""), None);
    assert_eq!(ControllerIdentityAction::parse("BIND"), None);
}
