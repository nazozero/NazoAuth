use super::{
    AuthorizationCodeBegin, parse_authorization_code_begin_reply,
    parse_decision_material_discard_reply,
};
use crate::ErrorKind;
use nazo_auth::{DecisionMaterialDiscardError, DecisionMaterialDiscardOutcome};

#[test]
fn decision_cleanup_reply_preserves_all_three_outcomes() {
    for (reply, expected) in [
        ("discarded", DecisionMaterialDiscardOutcome::Discarded),
        (
            "consent_missing_or_changed",
            DecisionMaterialDiscardOutcome::ConsentMissingOrChanged,
        ),
        (
            "par_missing_or_changed",
            DecisionMaterialDiscardOutcome::ParMissingOrChanged,
        ),
    ] {
        assert_eq!(
            parse_decision_material_discard_reply(reply).unwrap(),
            expected
        );
    }
}

#[test]
fn decision_cleanup_errors_and_unknown_replies_never_become_success() {
    assert!(matches!(
        parse_decision_material_discard_reply("consent_error"),
        Err(DecisionMaterialDiscardError::ConsentOrUnknown(error))
            if error.kind() == ErrorKind::Protocol
    ));
    assert!(matches!(
        parse_decision_material_discard_reply("par_error"),
        Err(DecisionMaterialDiscardError::PushedRequest(error))
            if error.kind() == ErrorKind::Protocol
    ));
    for reply in ["", "missing", "discarded|unknown", "error"] {
        assert!(matches!(
            parse_decision_material_discard_reply(reply),
            Err(DecisionMaterialDiscardError::ConsentOrUnknown(error))
                if error.kind() == ErrorKind::UnexpectedResult
        ));
    }
}

#[test]
fn authorization_code_begin_reply_maps_terminal_states_exactly() {
    assert!(matches!(
        parse_authorization_code_begin_reply("busy"),
        Ok(AuthorizationCodeBegin::Busy)
    ));
    assert!(matches!(
        parse_authorization_code_begin_reply("failed"),
        Ok(AuthorizationCodeBegin::Failed)
    ));
    assert!(matches!(
        parse_authorization_code_begin_reply("missing"),
        Ok(AuthorizationCodeBegin::Missing)
    ));
    assert!(matches!(
        parse_authorization_code_begin_reply("malformed"),
        Ok(AuthorizationCodeBegin::Malformed)
    ));
    assert!(parse_authorization_code_begin_reply("unknown").is_err());
}

#[test]
fn authorization_code_begin_reply_rejects_malformed_structured_states() {
    assert!(parse_authorization_code_begin_reply("consuming|not-json").is_err());
    assert!(parse_authorization_code_begin_reply("consuming|[]").is_err());
    assert!(parse_authorization_code_begin_reply("consumed|not-json").is_err());
    assert!(parse_authorization_code_begin_reply("consumed|{\"status\":\"pending\"}").is_err());
}
