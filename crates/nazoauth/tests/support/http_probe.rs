use std::{
    io::{self, Read, Write},
    net::{SocketAddr, TcpStream},
    time::{Duration, Instant},
};

/// A raw fixture exchange with one deadline covering connect, write and read.
pub fn exchange(address: SocketAddr, request: &[u8], budget: Duration) -> io::Result<Vec<u8>> {
    let deadline = Instant::now() + budget;
    let remaining = || {
        deadline
            .checked_duration_since(Instant::now())
            .filter(|duration| !duration.is_zero())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "HTTP probe deadline expired"))
    };
    let mut stream = TcpStream::connect_timeout(&address, remaining()?)?;
    let mut pending = request;
    while !pending.is_empty() {
        stream.set_write_timeout(Some(remaining()?))?;
        let written = stream.write(pending)?;
        if written == 0 {
            return Err(io::ErrorKind::WriteZero.into());
        }
        pending = &pending[written..];
    }
    let mut response = Vec::new();
    let mut buffer = [0; 4096];
    loop {
        stream.set_read_timeout(Some(remaining()?))?;
        let count = stream.read(&mut buffer)?;
        if count == 0 {
            return Ok(response);
        }
        response.extend_from_slice(&buffer[..count]);
    }
}
