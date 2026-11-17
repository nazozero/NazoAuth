from pathlib import Path
import sys

root = Path(sys.argv[1])
path = root / 'crates/persistence-postgres/tests/unit/repositories/access_token_revocation.rs'
text = path.read_text()
addition = '''

#[tokio::test]
async fn jiff_postgres_timestamp_wire_roundtrips_preserve_epoch_precision() {
    use jiff_diesel::ToDiesel as _;
    let Some(mut connection) = temp_connection().await else { return; };
    #[derive(QueryableByName)]
    struct Row {
        #[diesel(sql_type = sql_types::Timestamptz)]
        #[diesel(deserialize_as = jiff_diesel::Timestamp)]
        value: Timestamp,
    }
    // The adapter truncates the signed duration from PostgreSQL's 2000 epoch,
    // not the signed duration from the Unix epoch. These literal expectations
    // catch an accidental change to floor rounding or Unix-epoch truncation.
    for (input, expected) in [
        ("2000-01-01T00:00:00Z", "2000-01-01T00:00:00Z"),
        ("2000-01-01T00:00:00.000000001Z", "2000-01-01T00:00:00Z"),
        ("1999-12-31T23:59:59.999999999Z", "2000-01-01T00:00:00Z"),
        ("2000-01-01T00:00:00.000001001Z", "2000-01-01T00:00:00.000001Z"),
        ("1999-12-31T23:59:59.999998999Z", "1999-12-31T23:59:59.999999Z"),
        ("1970-01-01T00:00:00.000000001Z", "1970-01-01T00:00:00.000001Z"),
        ("1969-12-31T23:59:59.999999999Z", "1970-01-01T00:00:00Z"),
        ("1969-12-31T23:59:59.123456Z", "1969-12-31T23:59:59.123456Z"),
        ("2026-11-18T00:00:00.123456789Z", "2026-11-18T00:00:00.123456Z"),
        ("2026-11-18T08:00:00+08:00", "2026-11-18T00:00:00Z"),
    ] {
        let input: Timestamp = input.parse().unwrap();
        let row = sql_query("SELECT $1::timestamptz AS value")
            .bind::<sql_types::Timestamptz, _>(input.to_diesel())
            .get_result::<Row>(&mut connection).await.unwrap();
        assert_eq!(row.value, expected.parse::<Timestamp>().unwrap(), "input {input}");
    }
}

#[tokio::test]
async fn jiff_postgres_nullable_and_array_bindings_roundtrip_without_timestamp_strings() {
    use jiff_diesel::ToDiesel as _;
    let Some(mut connection) = temp_connection().await else { return; };
    #[derive(QueryableByName)]
    struct Row {
        #[diesel(sql_type = sql_types::Nullable<sql_types::Timestamptz>)]
        #[diesel(deserialize_as = jiff_diesel::NullableTimestamp)]
        optional: Option<Timestamp>,
        #[diesel(sql_type = sql_types::Array<sql_types::Timestamptz>)]
        values: Vec<jiff_diesel::Timestamp>,
    }
    let instants: Vec<Timestamp> = [
        "1969-12-31T23:59:59.123456Z", "1970-01-01T00:00:00Z",
        "1999-12-31T23:59:59.999999Z", "2000-01-01T00:00:00Z",
        "2026-11-18T00:00:00.123456Z",
    ].into_iter().map(|value| value.parse().unwrap()).collect();
    let bindings: Vec<_> = instants.iter().map(ToDiesel::to_diesel).collect();
    for optional in [None, Some(instants[0]), Some(instants[4])] {
        let row = sql_query("SELECT $1::timestamptz AS optional, $2::timestamptz[] AS values")
            .bind::<sql_types::Nullable<sql_types::Timestamptz>, _>(optional.to_diesel())
            .bind::<sql_types::Array<sql_types::Timestamptz>, _>(&bindings)
            .get_result::<Row>(&mut connection).await.unwrap();
        assert_eq!(row.optional, optional);
        let restored: Vec<Timestamp> = row.values.into_iter().map(Into::into).collect();
        assert_eq!(restored, instants);
    }
}
'''
# The local trait import is anonymous, so use a method call in the iterator.
addition = addition.replace('instants.iter().map(ToDiesel::to_diesel)', 'instants.iter().map(|value| value.to_diesel())')
if 'fn jiff_postgres_timestamp_wire_roundtrips_preserve_epoch_precision' not in text:
    path.write_text(text + addition)
