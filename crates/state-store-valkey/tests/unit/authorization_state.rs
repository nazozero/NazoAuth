use super::{map_error, map_preparation_write};
use crate::{AuthorizationPreparationWrite, Error};
use fred::error::{Error as FredError, ErrorKind as FredErrorKind};
use nazo_auth::AuthorizationPortError;

#[test]
fn preparation_write_outcomes_preserve_conflict_semantics() {
    assert_eq!(
        map_preparation_write(AuthorizationPreparationWrite::Stored),
        Ok(())
    );
    assert_eq!(
        map_preparation_write(AuthorizationPreparationWrite::Conflict),
        Err(AuthorizationPortError::Conflict)
    );
}

#[test]
fn preparation_dependency_errors_do_not_become_conflicts() {
    for kind in [FredErrorKind::Timeout, FredErrorKind::IO] {
        assert_eq!(
            map_error(Error::from_fred(FredError::new(kind, "dependency failure"))),
            AuthorizationPortError::Unavailable
        );
    }
    assert_eq!(
        map_error(Error::protocol("invalid expiration")),
        AuthorizationPortError::Unexpected
    );
    assert_eq!(
        map_error(Error::unexpected("invalid SET NX reply")),
        AuthorizationPortError::Unexpected
    );
    assert_eq!(
        map_error(Error::corrupt_data("malformed stored JSON")),
        AuthorizationPortError::CorruptData
    );
}
