//! Phase 12 §12.4: the recorded live run through a real public bridge (manual, OA-1).
//!
//! This is distribution-day evidence, not a CI gate (public bridges are flaky and unbounded —
//! the same reason `live_tor.rs` is ignored). One run bootstraps arti through a real obfs4
//! line, proves a public onion stream, and records the numbers the exit checklist wants:
//! bootstrap time, the public-onion HEAD probe, and the PT-hop byte shape.
//!
//! Inputs (environment, never committed — §6.1's canary forbids shipped lines):
//!   GHOST_PT_LIVE_LINE   one or more real bridge lines, `\n`-separated (obfs4 or webtunnel)
//!   GHOST_PT_LYREBIRD    the extraction dir layout: a directory whose `lyrebird` file ptmgr
//!                        execs (hash-verified out-of-band before the run)
//!   GHOST_LIVE_LOG       optional tracing level for the client (e.g. info)
//!
//! Run with:
//! `GHOST_PT_LIVE_LINE='obfs4 …' GHOST_PT_LYREBIRD=/path/to/pt/dir \
//!   cargo test -p ghost-client-net --test live_pt -- --ignored --nocapture`

use ghost_client_net::{IsolationScope, OnionAddress, TorTransport, TransportConfig};
use std::path::PathBuf;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// DuckDuckGo's onion service, port 80 (plain HTTP inside the onion tunnel).
const PUBLIC_ONION: &str = "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion:80";

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "manual live run (OA-1): needs a real public bridge line in GHOST_PT_LIVE_LINE"]
async fn live_pt_bootstrap_recorded() {
    if let Ok(level) = std::env::var("GHOST_LIVE_LOG") {
        let _ = tracing_subscriber::fmt().with_env_filter(level).try_init();
    }
    let lines: Vec<String> = std::env::var("GHOST_PT_LIVE_LINE")
        .expect("GHOST_PT_LIVE_LINE holds the real bridge line(s)")
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_owned)
        .collect();
    assert!(!lines.is_empty(), "GHOST_PT_LIVE_LINE is empty");
    let pt_dir = std::env::var("GHOST_PT_LYREBIRD")
        .map(PathBuf::from)
        .expect("GHOST_PT_LYREBIRD names the directory holding the verified lyrebird");
    assert!(
        pt_dir.join("lyrebird").is_file(),
        "GHOST_PT_LYREBIRD/lyrebird is not a file"
    );
    let dir = std::env::temp_dir().join("ghost-live-pt-test");
    let cfg = TransportConfig {
        state_dir: dir.join("state"),
        cache_dir: dir.join("cache"),
        bridge_lines: lines.clone(),
        pt_dir: Some(pt_dir),
    };
    let t0 = Instant::now();
    let transport = TorTransport::create(&cfg).expect("create the PT client");
    transport
        .bootstrap()
        .await
        .expect("bootstrap through the public bridge");
    eprintln!(
        "live-pt: bootstrap through the public bridge: {:?} ({} line(s), transport {})",
        t0.elapsed(),
        lines.len(),
        lines[0].split_whitespace().next().unwrap_or("?"),
    );

    let addr = OnionAddress::parse(PUBLIC_ONION).unwrap();
    let mut stream = tokio::time::timeout(
        Duration::from_secs(120),
        transport.connect(&addr, &IsolationScope::Namespace([9; 32])),
    )
    .await
    .expect("onion connect within 2 minutes")
    .expect("public onion connect through the PT");
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
    assert!(
        n > 0 && buf.starts_with(b"HTTP/"),
        "got {:?}",
        String::from_utf8_lossy(&buf[..n])
    );
    eprintln!("live-pt: public onion answered through the PT");
    assert_eq!(
        TorTransport::keystore_files_for_tests(&cfg.state_dir),
        Vec::<std::path::PathBuf>::new()
    );
}
