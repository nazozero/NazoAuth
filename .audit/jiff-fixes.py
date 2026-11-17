#!/usr/bin/env python3
"""Apply reviewed, idempotent semantic changes to the Jiff validation branch."""
from pathlib import Path
import re
import sys

root = Path(sys.argv[1]).resolve()


def edit(name, operation):
    path = root / name
    before = path.read_text()
    after = operation(before)
    if after != before:
        path.write_text(after)


bridge = '''pub(super) fn to_protocol_time(value: Timestamp) -> Result<MdocTimestamp, CredentialTrustError> {
    MdocTimestamp::from_unix_nanos(value.as_nanosecond())
        .map_err(|_| CredentialTrustError::InvalidValidity)
}

pub(super) fn from_protocol_time(value: MdocTimestamp) -> Result<Timestamp, CredentialTrustError> {
    // The protocol type preserves leap seconds, whereas application deadlines
    // are POSIX instants. Reject an unrepresentable instant at this boundary;
    // never silently fold a signed leap second into an adjacent second.
    let nanos = value.unix_nanos().ok_or(CredentialTrustError::InvalidValidity)?;
    Timestamp::from_nanosecond(nanos).map_err(|_| CredentialTrustError::InvalidValidity)
}

'''
edit('crates/authorization-server/src/domain/openid4vc/credential_crypto/mdoc.rs', lambda s: re.sub(
    r'pub\(super\) fn to_protocol_time\(.*?(?=pub\(super\) async fn sign\()', bridge, s, flags=re.S))
# Both inputs to max() now come from POSIX instants, so the old issuance-only
# leap guard is unreachable. Incoming protocol instants remain checked above.
edit('crates/authorization-server/src/domain/openid4vc/credential_crypto/mdoc.rs', lambda s: re.sub(
    r'    // The application\'s certificate path engine consumes ordinary Unix seconds\.\n.*?    if signed\.is_leap_second\(\) \{\n        return Err\(CredentialTrustError::InvalidValidity\);\n    }\n', '', s, flags=re.S))

serializer = '''
// Anchor v2 has a frozen byte representation: fractional precision is 0, 3,
// 6 or 9 digits. Jiff's default minimal precision would change old batches.
// collect_str writes directly into the serializer without a temporary String.
fn serialize_audit_timestamp<S: Serializer>(value: &jiff::Timestamp, serializer: S) -> Result<S::Ok, S::Error> {
    let nanos = value.subsec_nanosecond();
    let precision = if nanos == 0 {
        0
    } else if nanos % 1_000_000 == 0 {
        3
    } else if nanos % 1_000 == 0 {
        6
    } else {
        9
    };
    serializer.collect_str(&format_args!("{value:.precision$}"))
}
'''
def wire(s):
    if 'fn serialize_audit_timestamp' not in s:
        s = s.replace('    occurred_at: jiff::Timestamp,', '    #[serde(serialize_with = "serialize_audit_timestamp")]\n    occurred_at: jiff::Timestamp,')
        s = s.replace('\nstruct Events<', serializer + '\nstruct Events<', 1)
    return s
edit('crates/persistence/src/audit_wire.rs', wire)
edit('crates/persistence/src/audit_chain.rs', lambda s: s.replace(
    '    hasher.update(&occurred_at.as_microsecond().to_be_bytes());',
    '    // The v1 chain uses floor-rounded Unix microseconds, including dates\n'
    '    // before 1970. Jiff as_microsecond() truncates toward zero instead.\n'
    '    // Every Jiff timestamp fits in i64 when expressed in microseconds.\n'
    '    let micros = occurred_at.as_nanosecond().div_euclid(1_000) as i64;\n'
    '    hasher.update(&micros.to_be_bytes());'))

wire_tests = '''
#[test]
fn fractional_anchor_timestamps_preserve_the_frozen_v2_precision() {
    #[derive(serde::Serialize)]
    struct Wire {
        #[serde(serialize_with = "serialize_audit_timestamp")]
        timestamp: jiff::Timestamp,
    }
    for expected in [
        "2026-10-01T00:00:00Z",
        "2026-10-01T00:00:00.100Z",
        "2026-10-01T00:00:00.123400Z",
        "2026-10-01T00:00:00.123456Z",
        "2026-10-01T00:00:00.123456700Z",
        "2026-10-01T00:00:00.123456789Z",
        "1969-12-31T23:59:59.900Z",
        "1969-12-31T23:59:59.999999Z",
    ] {
        let value = serde_json::to_string(&Wire { timestamp: expected.parse().unwrap() }).unwrap();
        assert_eq!(value, format!(r#"{{"timestamp":"{expected}"}}"#));
    }
}
'''
edit('crates/persistence/tests/unit/audit_wire.rs', lambda s: s if 'fn fractional_anchor_timestamps_preserve_the_frozen_v2_precision' in s else s + wire_tests)

chain_tests = '''
#[cfg(test)]
mod timestamp_regressions {
    use super::security_audit_event_hash;
    use jiff::Timestamp;

    fn hash(at: Timestamp) -> [u8; 32] {
        security_audit_event_hash(1, &[0; 32], uuid::Uuid::nil(), "event", "security", at, b"{}")
    }

    #[test]
    fn v1_chain_floors_submicrosecond_instants_on_both_sides_of_epoch() {
        for (nanos, micros) in [
            (0, 0), (1, 0), (999, 0), (1000, 1), (1001, 1),
            (-1, -1), (-999, -1), (-1000, -1), (-1001, -2),
            (-1_000_000_001, -1_000_001),
        ] {
            assert_eq!(
                hash(Timestamp::from_nanosecond(nanos).unwrap()),
                hash(Timestamp::from_microsecond(micros).unwrap()),
                "nanosecond input {nanos}",
            );
        }
        assert_ne!(hash(Timestamp::UNIX_EPOCH), hash(Timestamp::from_microsecond(-1).unwrap()));
        assert_ne!(hash(Timestamp::UNIX_EPOCH), hash(Timestamp::from_microsecond(1).unwrap()));
    }
}
'''
edit('crates/persistence/src/audit_chain.rs', lambda s: s if 'mod timestamp_regressions' in s else s + chain_tests)
print('Applied audit-wire, audit-chain and mdoc time-boundary regressions.')
