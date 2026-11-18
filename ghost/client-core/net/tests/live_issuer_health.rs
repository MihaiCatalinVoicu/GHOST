//! Live, read-only external healthcheck: Tor directory/descriptor/introduction/rendezvous plus gRPC.
//! The all-zero invoice cannot authorize; PERMISSION_DENIED is therefore the expected healthy reply.
//! Run: cargo test -p ghost-client-net --test live_issuer_health -- --ignored --nocapture

use ghost_client_net::{IssuerClient, IssuerError, IssuerRpc, TorTransport, TransportConfig};
use ghost_issuer_api::proto::InvoiceStatusRequest;
use std::time::{SystemTime, UNIX_EPOCH};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires network access and the live issuer of the embedded schedule"]
async fn external_descriptor_rendezvous_and_grpc_are_reachable() {
    let dir = std::env::var_os("GHOST_LIVE_ISSUER_CACHE")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| {
            let unique = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock after epoch")
                .as_nanos();
            std::env::temp_dir().join(format!("ghost-live-health-{}-{unique}", std::process::id()))
        });
    eprintln!("Tor state/cache directory: {}", dir.display());
    let transport = TorTransport::create(&TransportConfig {
        state_dir: dir.join("state"),
        cache_dir: dir.join("cache"),
        bridge_lines: vec![],
        pt_dir: None,
    })
    .expect("create tor client");
    transport.bootstrap().await.expect("tor bootstrap");

    let mut client = IssuerClient::over_tor(&transport, [0x48; 16]).expect("issuer client");
    let request = InvoiceStatusRequest {
        version: ghost_issuer_api::PROTOCOL_VERSION,
        invoice_id: vec![0; 16],
        claim_key: vec![0; 32],
    };
    match client.invoice_status(request).await {
        Ok(_) | Err(IssuerError::Rpc(tonic::Code::PermissionDenied)) => {
            eprintln!("EXTERNAL_ONION_GRPC reachable")
        }
        Err(e) => panic!("EXTERNAL_ONION_GRPC unreachable: {e}"),
    }
}
