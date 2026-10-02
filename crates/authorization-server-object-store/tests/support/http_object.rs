use std::{
    io::{Read as _, Write as _},
    net::{SocketAddr, TcpListener, TcpStream},
    sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}},
    thread::{self, JoinHandle},
    time::Duration,
};

pub struct ObjectServer {
    address: SocketAddr,
    requests: Arc<Mutex<Vec<String>>>,
    stopping: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl ObjectServer {
    pub fn new(status: u16, content_type: Option<&str>, body: Vec<u8>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stopping = Arc::new(AtomicBool::new(false));
        let received = Arc::clone(&requests);
        let shutdown = Arc::clone(&stopping);
        let content_type = content_type.map(str::to_owned);
        let thread = thread::spawn(move || {
            for stream in listener.incoming() {
                if shutdown.load(Ordering::Acquire) {
                    break;
                }
                let mut stream = stream.unwrap();
                stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                let mut raw = Vec::new();
                let mut buffer = [0; 1024];
                while !raw.windows(4).any(|window| window == b"\r\n\r\n") {
                    let count = stream.read(&mut buffer).unwrap();
                    if count == 0 {
                        break;
                    }
                    raw.extend_from_slice(&buffer[..count]);
                }
                let request = String::from_utf8(raw).unwrap();
                let head = request.starts_with("HEAD ");
                received.lock().unwrap().push(request);
                let mime = content_type.as_deref().map(|value|
                    format!("Content-Type: {value}\r\n")).unwrap_or_default();
                let response = format!(
                    "HTTP/1.1 {status} Fixture\r\nContent-Length: {}\r\n{mime}Connection: close\r\n\r\n",
                    body.len());
                let _ = stream.write_all(response.as_bytes());
                if !head {
                    let _ = stream.write_all(&body);
                }
            }
        });
        Self { address, requests, stopping, thread: Some(thread) }
    }

    pub fn endpoint(&self) -> String {
        format!("http://{}", self.address)
    }

    pub fn requests(&self) -> Vec<String> {
        self.requests.lock().unwrap().clone()
    }
}

impl Drop for ObjectServer {
    fn drop(&mut self) {
        self.stopping.store(true, Ordering::Release);
        let _ = TcpStream::connect(self.address);
        self.thread.take().unwrap().join().unwrap();
    }
}
