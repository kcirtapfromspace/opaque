//! Standalone std-only test peer, compiled into isolated Human/Agent paths.
//! Framed credentials arrive over stdin, never argv or the environment.
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;
fn main() {
    if run().is_err() {
        eprintln!("synthetic peer transport unavailable");
        std::process::exit(1);
    }
}
fn run() -> std::io::Result<()> {
    let path = std::env::args()
        .nth(1)
        .ok_or_else(|| std::io::Error::other("socket missing"))?;
    let mut bytes = Vec::new();
    std::io::stdin()
        .take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 1024 * 1024 {
        return Err(std::io::Error::other("input bound"));
    }
    let mut socket = UnixStream::connect(path)?;
    socket.set_read_timeout(Some(Duration::from_secs(30)))?;
    socket.set_write_timeout(Some(Duration::from_secs(30)))?;
    socket.write_all(&bytes)?;
    let mut length = [0; 4];
    socket.read_exact(&mut length)?;
    let size = u32::from_be_bytes(length) as usize;
    if size > 1024 * 1024 {
        return Err(std::io::Error::other("response bound"));
    }
    let mut response = vec![0; size];
    socket.read_exact(&mut response)?;
    std::io::stdout().write_all(&response)?;
    Ok(())
}
