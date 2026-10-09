use diesel::{QueryableByName, sql_query, sql_types};
use diesel_async::{AsyncConnection, AsyncPgConnection, RunQueryDsl, SimpleAsyncConnection};

const UP: &str =
    include_str!("../../../migrations/20261009000400_single_presentation_response_mode/up.sql");
const DOWN: &str =
    include_str!("../../../migrations/20261009000400_single_presentation_response_mode/down.sql");

#[derive(QueryableByName)]
struct Mode {
    #[diesel(sql_type = sql_types::Text)]
    mode: String,
}

#[tokio::test]
async fn presentation_mode_migration_preserves_requests_and_refuses_conflicting_history() {
    let url = std::env::var("NAZO_TEST_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .expect("this migration regression requires isolated PostgreSQL");
    let mut connection = AsyncPgConnection::establish(&url).await.unwrap();
    // Temporary table shadows the real relation only on this independent connection.
    // Neither case changes live fixture rows or their safety retention deadlines.
    for (stored, request, accepted) in [
        ("direct_post", "direct_post.jwt", false),
        ("direct_post.jwt", "direct_post.jwt", true),
        ("direct_post", "direct_post", true),
    ] {
        connection.batch_execute("BEGIN; CREATE TEMP TABLE openid4vp_transactions (response_mode VARCHAR(32) NOT NULL, request JSONB NOT NULL) ON COMMIT DROP;").await.unwrap();
        sql_query("INSERT INTO openid4vp_transactions VALUES ($1, jsonb_build_object('response_mode', $2::text))")
            .bind::<sql_types::Text,_>(stored).bind::<sql_types::Text,_>(request)
            .execute(&mut connection).await.unwrap();
        let result = connection.batch_execute(UP).await;
        assert_eq!(result.is_ok(), accepted);
        if accepted {
            let mode =
                sql_query("SELECT request ->> 'response_mode' AS mode FROM openid4vp_transactions")
                    .get_result::<Mode>(&mut connection)
                    .await
                    .unwrap();
            assert_eq!(mode.mode, request);
            connection.batch_execute(DOWN).await.unwrap();
            let mode = sql_query("SELECT response_mode AS mode FROM openid4vp_transactions")
                .get_result::<Mode>(&mut connection)
                .await
                .unwrap();
            assert_eq!(mode.mode, request);
        } else {
            assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains("disagrees with retained request")
            );
        }
        connection.batch_execute("ROLLBACK").await.unwrap();
    }
}
