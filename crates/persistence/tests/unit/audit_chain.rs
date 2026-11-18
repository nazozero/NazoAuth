use super::security_audit_event_hash;
use jiff::Timestamp;

fn hash(at: Timestamp) -> [u8; 32] {
    security_audit_event_hash(
        1,
        &[0; 32],
        uuid::Uuid::nil(),
        "event",
        "security",
        at,
        b"{}",
    )
}

#[test]
fn v1_chain_floors_submicrosecond_instants_on_both_sides_of_epoch() {
    for (nanos, micros) in [
        (0, 0),
        (1, 0),
        (999, 0),
        (1000, 1),
        (1001, 1),
        (-1, -1),
        (-999, -1),
        (-1000, -1),
        (-1001, -2),
        (-1_000_000_001, -1_000_001),
    ] {
        assert_eq!(
            hash(Timestamp::from_nanosecond(nanos).unwrap()),
            hash(Timestamp::from_microsecond(micros).unwrap()),
            "nanosecond input {nanos}",
        );
    }
    assert_ne!(
        hash(Timestamp::UNIX_EPOCH),
        hash(Timestamp::from_microsecond(-1).unwrap())
    );
    assert_ne!(
        hash(Timestamp::UNIX_EPOCH),
        hash(Timestamp::from_microsecond(1).unwrap())
    );
}
