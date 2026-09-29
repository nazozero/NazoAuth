use diesel::sql_query;
use diesel_async::RunQueryDsl;
use nazo_postgres::{create_pool, get_conn};
use tokio::io::AsyncReadExt;
use tokio::time::{Duration, timeout};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shared_pool_connection_outlives_the_borrowers_runtime() {
    let database_url =
        std::env::var("NAZO_TEST_DATABASE_URL").or_else(|_| std::env::var("DATABASE_URL"));
    let Ok(database_url) = database_url else {
        assert!(
            std::env::var_os("CI").is_none(),
            "CI pool runtime tests require NAZO_TEST_DATABASE_URL or DATABASE_URL"
        );
        eprintln!("skipping PostgreSQL regression: no test database configured");
        return;
    };
    let pool = create_pool(database_url, 1).expect("pool owner runtime is available");
    let mut connection = tokio::task::spawn_blocking(move || {
        let borrower = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("borrower runtime");
        // Return the same physical connection, then destroy the runtime that
        // borrowed it. Reacquiring could hide a dead driver by reconnecting.
        borrower.block_on(async move { get_conn(&pool).await.expect("connection") })
    })
    .await
    .expect("borrower task");

    timeout(
        Duration::from_secs(2),
        sql_query("SELECT 1").execute(&mut connection),
    )
    .await
    .expect("the pool owner must continue driving I/O")
    .expect("the physical connection must survive its borrower runtime");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelling_pool_acquisition_aborts_pending_connection_setup() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("local handshake fixture");
    let addr = listener.local_addr().unwrap();
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let peer = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut header = [0_u8; 4];
        socket.read_exact(&mut header).await.unwrap();
        let length = u32::from_be_bytes(header) as usize;
        assert!((8..1024).contains(&length));
        let mut startup = vec![0_u8; length - 4];
        socket.read_exact(&mut startup).await.unwrap();
        started_tx.send(()).unwrap();
        let mut next = [0_u8; 1];
        let bytes = timeout(Duration::from_secs(2), socket.read(&mut next))
            .await
            .expect("cancelled setup must release its socket")
            .expect("socket read");
        assert_eq!(bytes, 0);
    });
    let pool = create_pool(format!("postgres://probe@{addr}/probe?sslmode=disable"), 1).unwrap();
    let acquisition = tokio::spawn(async move { get_conn(&pool).await });
    timeout(Duration::from_secs(2), started_rx)
        .await
        .expect("setup must begin")
        .expect("fixture acknowledgement");
    acquisition.abort();
    assert!(matches!(acquisition.await, Err(error) if error.is_cancelled()));
    peer.await.expect("handshake fixture");
}
