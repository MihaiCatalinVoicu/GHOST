//! `ghost-relay` binary.
//!
//! ```text
//! ghost-relay serve --data-dir <dir> --listen 127.0.0.1:7443 [--capture <file>] [--gossip]
//! ghost-relay mint  --data-dir <dir> --namespace <hex32> (--write --quota <bytes> | --read) --expiry <unix>
//! ```
//! The listener binds to loopback only: reachability comes from the onion service configured in
//! `infra/relay/torrc` (ADR-01). The relay key lives in `<data-dir>/relay.key` (32 bytes).

use ghost_relay_api::proto::relay_service_server::RelayServiceServer;
use ghost_relay_capability::{Capability, Kind, RelayKey};
use ghost_relay_node::{Relay, RelayConfig, RelayServer};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

fn parse_args(args: &[String]) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if let Some(name) = a.strip_prefix("--") {
            let flag_only = matches!(name, "gossip" | "write" | "read");
            if flag_only {
                out.insert(name.to_string(), "true".to_string());
                i += 1;
            } else if i + 1 < args.len() {
                out.insert(name.to_string(), args[i + 1].clone());
                i += 2;
            } else {
                i += 1;
            }
        } else {
            i += 1;
        }
    }
    out
}

fn load_or_create_key(data_dir: &Path) -> std::io::Result<RelayKey> {
    std::fs::create_dir_all(data_dir)?;
    let path = data_dir.join("relay.key");
    if let Ok(bytes) = std::fs::read(&path) {
        if bytes.len() == 32 {
            let mut k = [0u8; 32];
            k.copy_from_slice(&bytes);
            return Ok(RelayKey::from_bytes(k));
        }
    }
    let k = rand::random::<[u8; 32]>();
    std::fs::write(&path, k)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(RelayKey::from_bytes(k))
}

fn usage() -> ExitCode {
    eprintln!(
        "usage: ghost-relay serve --data-dir <dir> --listen <addr> [--capture <file>] [--gossip]"
    );
    eprintln!("       ghost-relay mint  --data-dir <dir> --namespace <hex32> (--write --quota <bytes> | --read) --expiry <unix>");
    ExitCode::from(2)
}

#[tokio::main]
async fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let Some(cmd) = argv.first() else {
        return usage();
    };
    let opts = parse_args(&argv[1..]);
    let Some(data_dir) = opts.get("data-dir").map(PathBuf::from) else {
        return usage();
    };
    let key = match load_or_create_key(&data_dir) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("relay key: {e}");
            return ExitCode::from(2);
        }
    };

    match cmd.as_str() {
        "mint" => {
            let Some(ns_hex) = opts.get("namespace") else {
                return usage();
            };
            let Ok(ns) = hex::decode(ns_hex) else {
                return usage();
            };
            let Ok(namespace) = <[u8; 32]>::try_from(ns.as_slice()) else {
                return usage();
            };
            let Some(expiry) = opts.get("expiry").and_then(|e| e.parse::<u64>().ok()) else {
                return usage();
            };
            let cap = if opts.contains_key("write") {
                let Some(quota) = opts.get("quota").and_then(|q| q.parse::<u64>().ok()) else {
                    return usage();
                };
                Capability {
                    kind: Kind::Write,
                    namespace,
                    quota_bytes: quota,
                    expiry_unix: expiry,
                }
            } else if opts.contains_key("read") {
                Capability {
                    kind: Kind::Read,
                    namespace,
                    quota_bytes: 0,
                    expiry_unix: expiry,
                }
            } else {
                return usage();
            };
            println!("{}", hex::encode(key.mint(&cap)));
            ExitCode::SUCCESS
        }
        "serve" => {
            let listen: SocketAddr = match opts.get("listen").and_then(|l| l.parse().ok()) {
                Some(a) => a,
                None => return usage(),
            };
            let config = RelayConfig {
                gossip_enabled: opts.contains_key("gossip"),
                ..RelayConfig::default()
            };
            let relay =
                match Relay::open(&data_dir, key, config, opts.get("capture").map(Path::new)) {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("open: {e}");
                        return ExitCode::from(2);
                    }
                };
            let pruner = std::sync::Arc::clone(&relay);
            tokio::spawn(async move {
                let mut tick = tokio::time::interval(Duration::from_secs(60));
                loop {
                    tick.tick().await;
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0);
                    let _ = pruner.sweep(now);
                }
            });
            eprintln!("ghost-relay listening on {listen} (protocol v1)");
            match tonic::transport::Server::builder()
                .add_service(RelayServiceServer::new(RelayServer(relay)))
                .serve(listen)
                .await
            {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("serve: {e}");
                    ExitCode::from(1)
                }
            }
        }
        _ => usage(),
    }
}
