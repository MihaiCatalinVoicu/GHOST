//! Live network test (ignored by default; needs internet and a few minutes to bootstrap Tor).
//! Proves end to end that Arti bootstraps with this crate's configuration, that a stream to a
//! public v3 onion service works, and that two isolation scopes really get two different circuits
//! (a relay cannot link them by arrival circuit). Run with:
//! `GHOST_LIVE_LOG=info cargo test -p ghost-client-net --test live_tor -- --ignored --nocapture`

use ghost_client_net::{IsolationScope, OnionAddress, TorTransport, TransportConfig};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tor_proto::client::stream::ClientStreamCtrl as _;

// DuckDuckGo's onion service, port 80 (plain HTTP inside the onion tunnel).
const PUBLIC_ONION: &str = "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion:80";

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires network access and a live Tor bootstrap"]
async fn bootstraps_and_isolates_onion_streams() {
    if let Ok(level) = std::env::var("GHOST_LIVE_LOG") {
        let _ = tracing_subscriber::fmt().with_env_filter(level).try_init();
    }
    let dir = std::env::temp_dir().join("ghost-live-tor-test");
    let cfg = TransportConfig {
        state_dir: dir.join("state"),
        cache_dir: dir.join("cache"),
        bridge_lines: vec![],
    };
    let transport = TorTransport::create(&cfg).expect("create tor client");
    transport.bootstrap().await.expect("tor bootstrap");
    let addr = OnionAddress::parse(PUBLIC_ONION).unwrap();

    let connect = |scope| {
        let t = &transport;
        let a = &addr;
        async move {
            tokio::time::timeout(Duration::from_secs(120), t.connect(a, &scope))
                .await
                .expect("onion connect within 2 minutes")
                .expect("onion connect")
        }
    };
    let mut first = connect(IsolationScope::Namespace([7; 32])).await;
    let second = connect(IsolationScope::Namespace([8; 32])).await;

    first
        .write_all(b"HEAD / HTTP/1.0\r\nHost: duckduckgo.com\r\n\r\n")
        .await
        .unwrap();
    first.flush().await.unwrap();
    let mut buf = vec![0u8; 64];
    let n = tokio::time::timeout(Duration::from_secs(60), first.read(&mut buf))
        .await
        .expect("response within 1 minute")
        .unwrap();
    assert!(
        n > 0 && buf.starts_with(b"HTTP/"),
        "got {:?}",
        String::from_utf8_lossy(&buf[..n])
    );

    // The privacy property itself: different scopes ride different circuits.
    let tunnel = |s: &arti_client::DataStream| {
        s.client_stream_ctrl()
            .and_then(|c| c.tunnel())
            .expect("stream is attached to a tunnel")
    };
    assert!(
        !Arc::ptr_eq(&tunnel(&first), &tunnel(&second)),
        "two isolation scopes must not share a circuit"
    );

    // After a real bootstrap and onion connections, the keystore Arti opened holds no key
    // (basis of the RUSTSEC-2023-0071 acceptance in deny.toml).
    assert_eq!(
        TorTransport::keystore_files_for_tests(&cfg.state_dir),
        Vec::<std::path::PathBuf>::new()
    );
}
