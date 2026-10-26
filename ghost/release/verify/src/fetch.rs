//! `fetch` of `ghost-verify`: one HTTP/1.1 GET over a SOCKS5 proxy (a local Tor at
//! `127.0.0.1:9050` or `9150`), the mirror's browser listener. Blocking and small — the
//! verifier is a tool, not the app. The body is cut at `bound + 1`: an answer longer than its
//! bound is refused (§4.8), never buffered whole.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

pub const DEFAULT_BOUND: usize = 1_048_576;

fn io_err(e: std::io::Error) -> String {
    format!("io: {e}")
}

/// One GET of `path` from `host:port` through the SOCKS5 proxy at `socks` (`host:port`).
/// `range` adds a `Range: bytes=a-b` header (APK chunks). The body must be at most `bound`
/// bytes; the status must be 200 (or 206 when a range was asked).
pub fn socks_fetch(
    socks: &str,
    host: &str,
    port: u16,
    path: &str,
    range: Option<(u64, u64)>,
    bound: usize,
) -> Result<Vec<u8>, String> {
    let mut proxy = TcpStream::connect(socks).map_err(io_err)?;
    proxy.set_read_timeout(Some(Duration::from_secs(120))).map_err(io_err)?;
    proxy.set_write_timeout(Some(Duration::from_secs(30))).map_err(io_err)?;
    // Greeting: version 5, one method, "no authentication required".
    proxy.write_all(&[0x05, 0x01, 0x00]).map_err(io_err)?;
    let mut greeting = [0u8; 2];
    proxy.read_exact(&mut greeting).map_err(io_err)?;
    if greeting != [0x05, 0x00] {
        return Err(format!("SOCKS5 greeting refused: {}", greeting[1]));
    }
    // CONNECT with a domain-name address (the onion hostname stays with the proxy: the verifier
    // never resolves it, which is the point of fetching over Tor).
    if host.len() > 255 {
        return Err("hostname too long for SOCKS5".into());
    }
    let mut req = Vec::with_capacity(7 + host.len());
    req.extend_from_slice(&[0x05, 0x01, 0x00, 0x03, host.len() as u8]);
    req.extend_from_slice(host.as_bytes());
    req.extend_from_slice(&port.to_be_bytes());
    proxy.write_all(&req).map_err(io_err)?;
    let mut head = [0u8; 4];
    proxy.read_exact(&mut head).map_err(io_err)?;
    if head[0] != 0x05 {
        return Err("SOCKS5 reply has a wrong version".into());
    }
    if head[1] != 0x00 {
        return Err(format!("SOCKS5 connect failed: {}", head[1]));
    }
    match head[3] {
        0x01 => {
            let mut b = [0u8; 4 + 2];
            proxy.read_exact(&mut b).map_err(io_err)?;
        }
        0x03 => {
            let mut len = [0u8; 1];
            proxy.read_exact(&mut len).map_err(io_err)?;
            let mut b = vec![0u8; len[0] as usize + 2];
            proxy.read_exact(&mut b).map_err(io_err)?;
        }
        0x04 => {
            let mut b = [0u8; 16 + 2];
            proxy.read_exact(&mut b).map_err(io_err)?;
        }
        atyp => return Err(format!("SOCKS5 reply has a wrong address type {atyp}")),
    }
    // The stream is now the end-to-end connection: plain HTTP/1.1, one GET, close-delimited.
    let authority = if port == 80 { host.to_string() } else { format!("{host}:{port}") };
    let mut request = format!(
        "GET {path} HTTP/1.1\r\nHost: {authority}\r\nAccept: */*\r\nConnection: close\r\n"
    )
    .into_bytes();
    if let Some((a, b)) = range {
        request.extend_from_slice(format!("Range: bytes={a}-{b}\r\n").as_bytes());
    }
    request.extend_from_slice(b"\r\n");
    proxy.write_all(&request).map_err(io_err)?;
    let mut raw: Vec<u8> = Vec::with_capacity(bound / 4 + 1024);
    let mut chunk = [0u8; 8192];
    loop {
        let n = proxy.read(&mut chunk).map_err(io_err)?;
        if n == 0 {
            break;
        }
        raw.extend_from_slice(&chunk[..n]);
        if raw.len() > bound + 4096 {
            return Err(format!("answer exceeds the bound of {bound} bytes"));
        }
    }
    // Split head and body at the first empty line.
    let split = find(&raw, b"\r\n\r\n").ok_or("response has no header terminator")?;
    let head = String::from_utf8_lossy(&raw[..split]).to_string();
    let mut lines = head.split("\r\n");
    let status = lines.next().ok_or("empty status line")?;
    let code: u32 = status
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| format!("status line does not parse: {status}"))?;
    let expected = if range.is_some() { 206 } else { 200 };
    if code != expected {
        return Err(format!("unexpected HTTP status {code}, wanted {expected}"));
    }
    let body = raw[split + 4..].to_vec();
    if body.len() > bound {
        return Err(format!("body of {} bytes exceeds the bound of {bound}", body.len()));
    }
    Ok(body)
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|w| w == needle)
}
