//! The `fetch` primitive over a SOCKS5 proxy: a localhost mini-proxy plus a mini HTTP server
//! stand in for Tor and the mirror's browser listener. Proves the handshake, the CONNECT with a
//! domain-name address, the status check and the bound.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

use ghost_verify::fetch::socks_fetch;

/// Serves `body` for GET /p (200), or 206 with bytes [a..=b] when a Range arrives.
fn mini_http() -> (u16, Vec<u8>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let body = b"ghost-verify-fetch-test-body".to_vec();
    let want = body.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let mut s = stream.unwrap();
            let mut buf = Vec::new();
            let mut tmp = [0u8; 1024];
            while !buf.ends_with(b"\r\n\r\n") {
                let n = s.read(&mut tmp).unwrap();
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&tmp[..n]);
            }
            let head = String::from_utf8_lossy(&buf).to_string();
            let mut status = "200 OK";
            let mut payload: &[u8] = &want;
            if let Some(line) = head.lines().find(|l| l.starts_with("Range: bytes=")) {
                let v = line.trim_start_matches("Range: bytes=").trim_end_matches('\r');
                let (a, b) = v.split_once('-').unwrap();
                let a: usize = a.parse().unwrap();
                let b: usize = b.parse().unwrap();
                payload = &want[a..=b];
                status = "206 Partial Content";
            }
            let response = format!(
                "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                payload.len()
            );
            s.write_all(response.as_bytes()).unwrap();
            s.write_all(payload).unwrap();
        }
    });
    (port, body)
}

/// A SOCKS5 proxy that accepts no-auth greetings and CONNECTs to 127.0.0.1 (only — this is a
/// test double, and the fetch under test asks for a domain name, which the double resolves to
/// the loopback HTTP server).
fn mini_socks(http_port: u16) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let mut client = stream.unwrap();
            let mut http = None;
            // Greeting.
            let mut g = [0u8; 3];
            client.read_exact(&mut g).unwrap();
            client.write_all(&[0x05, 0x00]).unwrap();
            // CONNECT.
            let mut h = [0u8; 4];
            client.read_exact(&mut h).unwrap();
            assert_eq!(h[0], 0x05);
            assert_eq!(h[3], 0x03);
            let mut len = [0u8; 1];
            client.read_exact(&mut len).unwrap();
            let mut host = vec![0u8; len[0] as usize];
            client.read_exact(&mut host).unwrap();
            let mut p = [0u8; 2];
            client.read_exact(&mut p).unwrap();
            let upstream = TcpStream::connect(("127.0.0.1", http_port)).unwrap();
            // Reply: success, bound address 0.0.0.0:0.
            client.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).unwrap();
            http = Some(upstream);
            let mut upstream = http.unwrap();
            // Blind relay both ways until close.
            let mut c2 = client.try_clone().unwrap();
            let mut u2 = upstream.try_clone().unwrap();
            let t = std::thread::spawn(move || {
                let mut b = [0u8; 4096];
                loop {
                    match u2.read(&mut b) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if c2.write_all(&b[..n]).is_err() {
                                break;
                            }
                        }
                    }
                }
                // The HTTP server closes after its answer: the client must see EOF, or it waits
                // for a close this relay never sends.
                let _ = c2.shutdown(std::net::Shutdown::Both);
            });
            let mut b = [0u8; 4096];
            loop {
                match client.read(&mut b) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if upstream.write_all(&b[..n]).is_err() {
                            break;
                        }
                    }
                }
            }
            let _ = t.join();
        }
    });
    port
}

#[test]
fn fetches_over_socks5_with_status_and_bound() {
    let (http_port, body) = mini_http();
    let socks_port = mini_socks(http_port);
    let socks = format!("127.0.0.1:{socks_port}");

    // The GET: the onion hostname is handed to the proxy as a domain name, never resolved here.
    let got = socks_fetch(&socks, "tfhsac26mfhbq6dm5rctfkjnll74xag6p7ehumcr7keqsnkqhp7no4id.onion", 80, "/ghost/v1/stagenet/current.ghrb", None, 1024).unwrap();
    assert_eq!(got, body);

    // The range: 206 with exactly the slice.
    let got = socks_fetch(&socks, "x.onion", 80, "/ghost/v1/stagenet/apk/ab", Some((0, 5)), 1024).unwrap();
    assert_eq!(got, body[..=5]);

    // A bound below the body refuses rather than buffers the oversized answer.
    assert!(socks_fetch(&socks, "x.onion", 80, "/p", None, 8).is_err());

    // A dead proxy refuses with an io message, not a panic.
    assert!(socks_fetch("127.0.0.1:1", "x.onion", 80, "/p", None, 1024).is_err());
}
