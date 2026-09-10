//! Live network test (ignored by default; needs internet and a few minutes to bootstrap Tor).
//! Proves the fail-closed transport end to end: Arti bootstraps, and a stream to a public v3 onion
//! service can be opened with an isolation token. Run with:
//! `GHOST_LIVE_LOG=info cargo test -p ghost-client-net --test live_tor -- --ignored --nocapture`

use ghost_client_net::{IsolationScope, OnionAddress, TorTransport, TransportConfig};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// DuckDuckGo's onion service, port 80 (plain HTTP inside the onion tunnel).
const PUBLIC_ONION: &str = "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion:80";

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires network access and a live Tor bootstrap"]
async fn bootstraps_and_opens_isolated_onion_stream() {
    if let Ok(level) = std::env::var("GHOST_LIVE_LOG") {
        let _ = tracing_subscriber::fmt().with_env_filter(level).try_init();
    }
    let dir = std::env::temp_dir().join("ghost-live-tor-test");
    let cfg = TransportConfig {
        state_dir: dir.join("state"),
        cache_dir: dir.join("cache"),
        bridge_lines: vec![],
    };
    let transport = tokio::time::timeout(Duration::from_secs(240), TorTransport::bootstrap(&cfg))
        .await
        .expect("tor bootstrap must finish within 4 minutes")
        .expect("tor bootstrap");
    let addr = OnionAddress::parse(PUBLIC_ONION).unwrap();
    let mut stream = tokio::time::timeout(
        Duration::from_secs(120),
        transport.connect(&addr, &IsolationScope::Namespace([7; 32])),
    )
    .await
    .expect("onion connect must finish within 2 minutes")
    .expect("onion connect");
    stream
        .write_all(b"HEAD / HTTP/1.0\r\nHost: duckduckgo.com\r\n\r\n")
        .await
        .unwrap();
    stream.flush().await.unwrap();
    let mut buf = vec![0u8; 64];
    let n = tokio::time::timeout(Duration::from_secs(60), stream.read(&mut buf))
        .await
        .expect("response within 1 minute")
        .unwrap();
    assert!(n > 0, "expected an HTTP status line over the onion stream");
    assert!(
        buf.starts_with(b"HTTP/"),
        "got {:?}",
        String::from_utf8_lossy(&buf[..n])
    );
    // Two different scopes hold two different isolation tokens.
    let iso = transport.isolations();
    assert_ne!(
        iso.token_for(&IsolationScope::Namespace([7; 32])),
        iso.token_for(&IsolationScope::Issuer)
    );
}
