//! `dm_restore`: the **host re-store tool** of Phase 9 design §15.10 step 4 and §21.13 point 4
//! (slice S12). A `client-core` test binary — an example of `ghost-client-net`, never part of the
//! shipped library — that stores captured DM blobs, byte for byte, over Tor, with a deposit
//! credential, so the gate phone that already received them sees an identical-bytes replay (D1).
//!
//! ```text
//! cargo run -p ghost-client-net --example dm_restore --locked -- \
//!     --onion <relay onion:port> --capture <file> --state-dir <dir>
//! ```
//!
//! The capture file is what `scripts/device/dm-gate.sh replay` exports from the sending gate phone:
//! the recipient's inbox namespace, the sender's deposit credential for it at one relay, the TTL
//! bucket and five delivered ciphertexts (see `restore.rs`). The output is one line per blob — the
//! first 8 bytes of its SHA-256 and the outcome — and the summary line
//! `dm-restore: <n> blobs, <n> stored identical bytes`. Nothing else is printed: no blob, no
//! credential, no namespace (§15.10: "records digests, never content").
//!
//! Its self-test is `client-core/net/tests/dm_restore.rs`, which runs the same core against a real
//! `ghost_relay_node::Relay` in-process with a registered deposit verifier.

mod restore;

use ghost_client_net::relay_client::OnionConnector;
use ghost_client_net::{NamespaceClient, OnionAddress, TorTransport, TransportConfig};
use restore::{parse_capture, report, restore_all, Depositor};
use std::path::PathBuf;

/// [`Depositor`] over Tor: the namespace client the app uses, on the namespace's own circuits.
struct TorDepositor(NamespaceClient<OnionConnector>);

impl Depositor for TorDepositor {
    async fn deposit(
        &mut self,
        credential: &[u8],
        blob: &[u8],
        ttl_seconds: u32,
    ) -> Result<[u8; 32], String> {
        self.0
            .store(credential.to_vec(), blob.to_vec(), ttl_seconds)
            .await
            .map(|receipt| receipt.blob_hash)
            .map_err(|error| format!("refused: {error}"))
    }
}

fn usage() -> ! {
    eprintln!("usage: dm_restore --onion <onion:port> --capture <file> --state-dir <dir>");
    std::process::exit(2)
}

#[tokio::main]
async fn main() {
    let mut onion = None;
    let mut capture = None;
    let mut state = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--onion" => onion = args.next(),
            "--capture" => capture = args.next(),
            "--state-dir" => state = args.next(),
            _ => usage(),
        }
    }
    let (Some(onion), Some(capture), Some(state)) = (onion, capture, state) else {
        usage()
    };
    let relay = OnionAddress::parse(&onion).unwrap_or_else(|_| usage());
    let text = std::fs::read_to_string(&capture).unwrap_or_else(|e| {
        eprintln!("dm_restore: cannot read the capture: {e}");
        std::process::exit(2)
    });
    let capture = parse_capture(&text).unwrap_or_else(|e| {
        eprintln!("dm_restore: capture refused: {e}");
        std::process::exit(2)
    });

    TorTransport::install_crypto_provider();
    let state = PathBuf::from(state);
    let transport = TorTransport::create(&TransportConfig {
        state_dir: state.join("state"),
        cache_dir: state.join("cache"),
        bridge_lines: vec![],
    })
    .unwrap_or_else(|e| {
        eprintln!("dm_restore: {e}");
        std::process::exit(1)
    });
    if let Err(e) = transport.bootstrap().await {
        eprintln!("dm_restore: {e}");
        std::process::exit(1);
    }
    let mut depositor = TorDepositor(NamespaceClient::over_tor(
        &transport,
        &relay,
        capture.namespace,
    ));
    let outcomes = restore_all(&mut depositor, &capture).await;
    print!("{}", report(&outcomes));
    let all = outcomes.iter().all(|o| o.result == "stored");
    std::process::exit(if all { 0 } else { 1 });
}
