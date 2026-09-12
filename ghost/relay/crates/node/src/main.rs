//! `ghost-relay` binary.
//!
//! ```text
//! ghost-relay serve --data-dir <dir> --listen 127.0.0.1:7443 [--capture <file>] [--gossip]
//!                   [--schedule <file> --slot <n> --onion-hostname-file <path>
//!                    [--nullifiers-reset | --nullifiers-init]]
//! ghost-relay mint  --data-dir <dir> --namespace <hex32> (--write --quota <bytes> | --read) --expiry <unix>
//! ```
//! The listener binds to loopback only: reachability comes from the onion service configured in
//! `infra/relay/torrc` (ADR-01). The relay key lives in `<data-dir>/relay.key` (32 bytes).
//!
//! Token redemption (Phase 8 design §10.5) is enabled by `--schedule`, `--slot` and
//! `--onion-hostname-file` together. The schedule is verified under the pinned schedule key; the
//! relay's onion, read from Tor's `HiddenServiceDir/hostname` (the binary cannot learn it
//! otherwise), must be listed for the slot in the current week; the schedule must be append-only
//! against the relay's memory in `<data-dir>/nullifiers.redb` (rule 5). Otherwise the relay refuses
//! to start. A data directory whose `relay.key` exists but whose `nullifiers.redb` is missing
//! refuses to start unless `--nullifiers-reset` (runbook O1, after losing the store) or the
//! one-time `--nullifiers-init` (the Phase 8 upgrade of a relay that never redeemed) is given. An
//! ES update is a restart; persisted nullifiers survive it.

use ghost_entitlement::Schedule;
use ghost_relay_api::proto::relay_service_server::RelayServiceServer;
use ghost_relay_capability::{Capability, Kind, RelayKey};
use ghost_relay_node::redeem::onion_from_hostname_file;
use ghost_relay_node::{EntitlementPolicy, NullifierMode, Relay, RelayConfig, RelayServer};
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
            let flag_only = matches!(
                name,
                "gossip" | "write" | "read" | "nullifiers-reset" | "nullifiers-init"
            );
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
    eprintln!("                         [--schedule <file> --slot <n> --onion-hostname-file <path> [--nullifiers-reset | --nullifiers-init]]");
    eprintln!("       ghost-relay mint  --data-dir <dir> --namespace <hex32> (--write --quota <bytes> | --read) --expiry <unix>");
    ExitCode::from(2)
}

/// Why the redemption flags were refused (printed as a constant with the relay's refusal).
enum FlagError {
    Usage,
    Refused(String),
}

/// The redemption policy of the `serve` flags: `None` without `--schedule`, `--slot` and
/// `--onion-hostname-file`; all three (or none) must be given.
fn entitlement(
    opts: &HashMap<String, String>,
    key_existed: bool,
) -> Result<Option<EntitlementPolicy>, FlagError> {
    let reset = opts.contains_key("nullifiers-reset");
    let init = opts.contains_key("nullifiers-init");
    let (schedule_path, slot, hostname_path) = match (
        opts.get("schedule"),
        opts.get("slot"),
        opts.get("onion-hostname-file"),
    ) {
        (None, None, None) if !reset && !init => return Ok(None),
        (Some(s), Some(n), Some(h)) if !(reset && init) => (s, n, h),
        _ => return Err(FlagError::Usage),
    };
    let slot: u8 = slot.parse().map_err(|_| FlagError::Usage)?;
    let bytes = std::fs::read(schedule_path)
        .map_err(|e| FlagError::Refused(format!("schedule file: {e}")))?;
    let schedule =
        Schedule::verify(&bytes).map_err(|e| FlagError::Refused(format!("schedule: {e}")))?;
    let hostname = std::fs::read_to_string(hostname_path)
        .map_err(|e| FlagError::Refused(format!("onion hostname file: {e}")))?;
    let onion =
        onion_from_hostname_file(&hostname).map_err(|e| FlagError::Refused(e.to_string()))?;
    let mut policy = EntitlementPolicy::new(schedule, slot, onion)
        .map_err(|e| FlagError::Refused(e.to_string()))?;
    policy.nullifiers = if reset {
        NullifierMode::Reset
    } else if init || !key_existed {
        NullifierMode::Create
    } else {
        NullifierMode::Existing
    };
    Ok(Some(policy))
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
    // Whether this data directory existed before (a relay that may have redeemed), read before
    // the key is created.
    let key_existed = data_dir.join("relay.key").exists();
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
            let entitlement = match entitlement(&opts, key_existed) {
                Ok(e) => e,
                Err(FlagError::Usage) => return usage(),
                Err(FlagError::Refused(why)) => {
                    eprintln!("refusing to start: {why}");
                    return ExitCode::from(2);
                }
            };
            let config = RelayConfig {
                gossip_enabled: opts.contains_key("gossip"),
                entitlement,
                ..RelayConfig::default()
            };
            let relay =
                match Relay::open(&data_dir, key, config, opts.get("capture").map(Path::new)) {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("refusing to start: {e}");
                        return ExitCode::from(2);
                    }
                };
            let pruner = std::sync::Arc::clone(&relay);
            tokio::spawn(async move {
                let mut tick = tokio::time::interval(Duration::from_secs(60));
                loop {
                    tick.tick().await;
                    let _ = pruner.sweep(pruner.now());
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
