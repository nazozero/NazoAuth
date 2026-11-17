#[path = "support/http_probe.rs"]
mod http_probe;

#[test]
fn accepted_connection_without_response_cannot_outlive_probe_budget() {
    use std::{
        io::Read,
        net::TcpListener,
        sync::mpsc,
        time::{Duration, Instant},
    };
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let (release, wait) = mpsc::channel();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = [0; 1024];
        assert!(stream.read(&mut request).unwrap() > 0);
        wait.recv().unwrap();
    });
    let started = Instant::now();
    let result = http_probe::exchange(
        address,
        b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
        Duration::from_millis(100),
    );
    release.send(()).unwrap();
    server.join().unwrap();
    assert!(matches!(
        result.unwrap_err().kind(),
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
    ));
    assert!(started.elapsed() < Duration::from_secs(2));
}
