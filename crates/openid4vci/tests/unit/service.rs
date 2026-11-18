use super::batch_privacy_claim_time;
use jiff::Timestamp;

#[test]
fn privacy_time_floors_to_the_same_utc_day_without_extending_a_deadline() {
    for (input, expected) in [
        ("1969-12-30T23:59:59.999999999Z", "1969-12-30T00:00:00Z"),
        ("1969-12-31T23:59:59.999999999Z", "1969-12-31T00:00:00Z"),
        ("1970-01-01T00:00:00Z", "1970-01-01T00:00:00Z"),
        ("1970-01-01T00:00:00.000000001Z", "1970-01-01T00:00:00Z"),
        ("2026-11-17T23:59:59.999999999Z", "2026-11-17T00:00:00Z"),
        ("2026-11-18T01:00:00+09:00", "2026-11-17T00:00:00Z"),
    ] {
        let input: Timestamp = input.parse().unwrap();
        let rounded = batch_privacy_claim_time(input);
        assert_eq!(rounded, expected.parse::<Timestamp>().unwrap());
        assert!(rounded <= input);
        assert_eq!(batch_privacy_claim_time(rounded), rounded);
    }
    // If midnight is outside the type's range, retain the original instant.
    assert_eq!(batch_privacy_claim_time(Timestamp::MIN), Timestamp::MIN);
    assert!(batch_privacy_claim_time(Timestamp::MAX) <= Timestamp::MAX);
}
