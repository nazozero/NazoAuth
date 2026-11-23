"""Instrument only the separate HTTP diagnostic build of the control."""

from pathlib import Path
import sys

root = Path(sys.argv[1])
pg = root / "crates/persistence-postgres/src"
with (pg / "lib.rs").open("a") as f:
    f.write("""
tokio::task_local! {
    pub static BENCH_HTTP_ACK: std::cell::Cell<Option<std::time::Instant>>;
}
""")


def replace(path, old, new):
    source = path.read_text()
    assert source.count(old) == 1, path
    path.write_text(source.replace(old, new))


replace(
    pg / "repositories/token_issuance.rs",
    "crate::bench_count_audit(1);",
    """
                                let _ = crate::BENCH_HTTP_ACK.try_with(|v| v.set(Some(std::time::Instant::now())));
                                crate::bench_count_audit(1);""",
)
factory = root / "crates/server/src/bootstrap/startup/services/factory.rs"
replace(
    factory,
    "let future = next.call(req);\n    async move {",
    "let future = next.call(req);\n    let observed = async move {",
)
replace(
    factory,
    "    .instrument(span)\n    .await\n}",
    """    .instrument(span);
    static SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    if SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % 16 != 0 {
        return observed.await;
    }
    nazo_postgres::BENCH_HTTP_ACK.scope(std::cell::Cell::new(None), async {
        let mut result = observed.await;
        if let (Ok(response), Some(ack)) = (&mut result, nazo_postgres::BENCH_HTTP_ACK.with(|v| v.get())) {
            let nanos = ack.elapsed().as_nanos().to_string();
            use actix_web::http::header::{HeaderName, HeaderValue};
            response.headers_mut().insert(HeaderName::from_static("x-bench-after-commit-ns"),
                HeaderValue::from_bytes(nanos.as_bytes()).expect("integer duration"));
        }
        result
    }).await
}""",
)
