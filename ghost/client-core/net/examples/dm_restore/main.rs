//! `dm_restore`: the **host re-store tool** of Phase 9 design §15.10 step 4 and §21.13 point 4
//! (slice S12). A `client-core` test binary — an example of `ghost-client-net`, never part of the
//! shipped library — that stores captured DM blobs, byte for byte, over Tor, with a deposit
//! credential, so the gate phone that already received them sees an identical-bytes replay (D1).
//!
//! ```text
//! cargo run -p ghost-client-net --example dm_restore --locked -- \
//!     --onion <relay onion:port> --capture <file> --state-dir <dir> [--check-only]
//! ```
//!
//! The capture file is what `scripts/device/dm-gate.sh replay` exports from the sending gate phone:
//! the recipient's inbox namespace, the sender's deposit credential for it at one relay, the TTL
//! bucket and five delivered ciphertexts (see `restore.rs`). Every blob is checked at the relay
//! first: one it still holds is `still-live` and is not stored (a re-store would be a no-op the
//! recipient never sees), one it no longer holds is stored again as a new listing (`re-stored`).
//! `--check-only` stores nothing and reports `still-live` or `gone` per blob. The output is one line
//! per blob — the first 8 bytes of its SHA-256 and the outcome — and the summary line
//! `dm-restore: <n> blobs, <r> re-stored as new listings, <l> still live at the relay`. Nothing else
//! is printed: no blob, no credential, no namespace (§15.10: "records digests, never content").
//! The exit status is 0 only when every blob was re-stored (or, with `--check-only`, checked).
//!
//! Its self-test is `client-core/net/tests/dm_restore.rs`, which runs the same core against a real
//! `ghost_relay_node::Relay` in-process with a registered deposit verifier.

mod restore;

use ghost_client_net::relay_client::OnionConnector;
use ghost_client_net::{NamespaceClient, OnionAddress, TorTransport, TransportConfig};
use restore::{
    check_all, parse_capture, report, restore_all, RelayPort, GONE, RESTORED, STILL_LIVE,
};
use std::path::PathBuf;

/// [`RelayPort`] over Tor: the namespace client the app uses, on the namespace's own circuits.
struct TorRelay(NamespaceClient<OnionConnector>);

impl RelayPort for TorRelay {
    async fn held(
        &mut self,
        credential: &[u8],
        hashes: &[[u8; 32]],
    ) -> Result<Vec<[u8; 32]>, String> {
        self.0
            .check(credential.to_vec(), hashes.to_vec())
            .await
            .map_err(|error| format!("refused: {error}"))
    }

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
    eprintln!(
        "usage: dm_restore --onion <onion:port> --capture <file> --state-dir <dir> [--check-only]"
    );
    std::process::exit(2)
}

#[tokio::main]
async fn main() {
    let mut onion = None;
    let mut capture = None;
    let mut state = None;
    let mut check_only = false;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--onion" => onion = args.next(),
            "--capture" => capture = args.next(),
            "--state-dir" => state = args.next(),
            "--check-only" => check_only = true,
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
    let mut relay = TorRelay(NamespaceClient::over_tor(
        &transport,
        &relay,
        capture.namespace,
    ));
    let outcomes = if check_only {
        check_all(&mut relay, &capture).await
    } else {
        restore_all(&mut relay, &capture).await
    };
    print!("{}", report(&outcomes));
    let ok = if check_only {
        outcomes
            .iter()
            .all(|o| o.result == STILL_LIVE || o.result == GONE)
    } else {
        outcomes.iter().all(|o| o.result == RESTORED)
    };
    std::process::exit(if ok { 0 } else { 1 });
}
