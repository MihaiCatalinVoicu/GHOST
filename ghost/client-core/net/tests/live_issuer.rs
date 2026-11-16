//! Live issuer dial reproducer (ignored by default; needs internet for Tor bootstrap and a live
//! issuer). Mirrors the Android JNI path 1:1 — `TorTransport` → `IssuerClient::over_tor` →
//! `issuer_flow::request_invoice` — but on a host with tracing enabled, to see exactly where a
//! device-side "transport" failure happens (consensus, descriptor fetch, intro, rendezvous,
//! TLS, HTTP/2). Run with:
//! `GHOST_LIVE_LOG=arti_client=debug,ghost_client_net=debug,tor_proto=debug,h2=debug cargo test -p ghost-client-net --test live_issuer -- --ignored --nocapture`

use ghost_client_net::entitlement::embedded_schedule;
use ghost_client_net::issuer_flow;
use ghost_client_net::{IssuerClient, TorTransport, TransportConfig};
use ghost_entitlement::grid::week;
use std::time::{SystemTime, UNIX_EPOCH};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires network access, a live Tor bootstrap and the issuer of the embedded schedule"]
async fn dials_the_embedded_issuer_and_requests_an_invoice() {
    if let Ok(level) = std::env::var("GHOST_LIVE_LOG") {
        let _ = tracing_subscriber::fmt().with_env_filter(level).try_init();
    }
    let dir = std::env::temp_dir().join("ghost-live-issuer-test");
    let cfg = TransportConfig {
        state_dir: dir.join("state"),
        cache_dir: dir.join("cache"),
        bridge_lines: vec![],
        pt_dir: None,
    };
    let transport = TorTransport::create(&cfg).expect("create tor client");
    transport.bootstrap().await.expect("tor bootstrap");

    let schedule = embedded_schedule().expect("the embedded ES verifies");
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let base_week = week(now);
    eprintln!("issuer onion: {}", schedule.content().issuer_onion);
    eprintln!("base_week: {base_week}");

    let mut client = IssuerClient::over_tor(&transport, [0x42; 16]).expect("issuer client");
    let claim_hash = [7u8; ghost_issuer_api::CLAIM_BYTES];
    match issuer_flow::request_invoice(&mut client, schedule, &claim_hash, &[], base_week).await {
        Ok(answer) => eprintln!("INVOICE ANSWER (privacy-safe debug): {answer:?}"),
        Err(e) => eprintln!("ISSUER ERROR: {e}"),
    }
}
