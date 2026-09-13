//! The committed stagenet deployment agrees with the issuer (Phase 8 design §6.6, §6.7, §7.1):
//! `infra/issuer/config.stagenet.toml` holds no treasury address and no restore height, so it is
//! refused as it is and accepted once the operator's two keys are appended (the host copy of
//! RUNBOOK.md); its listener is the target of the issuer onion's `HiddenServicePort` in
//! `infra/issuer/torrc`; its wallet and daemon endpoints are the loopback ports `entrypoint.sh`
//! gives monero-wallet-rpc and monerod; every secret it names is a copy on the entrypoint's tmpfs.

use std::path::Path;

use ghost_entitlement::monero::MoneroNetwork;
use ghost_issuer::config::{Config, ConfigError};

const TEMPLATE: &str = include_str!("../../../../infra/issuer/config.stagenet.toml");
const TORRC: &str = include_str!("../../../../infra/issuer/torrc");
const ENTRYPOINT: &str = include_str!("../../../../infra/issuer/entrypoint.sh");
const COMPOSE: &str = include_str!("../../../../infra/issuer/docker-compose.stagenet.yml");
const ADDRESSES: &str = include_str!("../../../../protocol/test-vectors/monero_addresses.txt");

/// The entrypoint's tmpfs, where the copies of secrets and read-only mounts live.
const RUN_DIR: &str = "/run/ghost/";

fn stagenet_standard_address() -> &'static str {
    ADDRESSES
        .lines()
        .find_map(|l| l.strip_prefix("valid|stagenet|payout|standard|"))
        .and_then(|rest| rest.split('|').next())
        .expect("a standard stagenet address in monero_addresses.txt")
}

/// The template with the two keys the operator appends to the host copy.
fn host_copy() -> Config {
    let text = format!(
        "{TEMPLATE}\ntreasury_address = \"{}\"\nrestore_height = 1500000\n",
        stagenet_standard_address()
    );
    Config::parse(&text).expect("the host copy is a valid configuration")
}

fn code_lines(text: &str) -> impl Iterator<Item = &str> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
}

#[test]
fn the_template_holds_no_operator_value() {
    assert_eq!(Config::parse(TEMPLATE), Err(ConfigError::Syntax));
    for key in ["treasury_address", "restore_height"] {
        assert!(
            !code_lines(TEMPLATE).any(|l| l.starts_with(key)),
            "the template sets {key}"
        );
    }
}

#[test]
fn the_host_copy_is_the_stagenet_deployment() {
    let c = host_copy();
    assert_eq!(c.network, MoneroNetwork::Stagenet);
    assert!(c.listen.ip().is_loopback());
    assert_eq!(c.schedule_file, Path::new("/etc/ghost/schedule.ghes"));
    assert!(
        COMPOSE.contains("- ../../protocol/entitlement/schedule.ghes:/etc/ghost/schedule.ghes:ro")
    );
    for (key, path) in [
        ("sealed_keys_dir", &c.sealed_keys_dir),
        ("key_load_file", &c.key_load_file),
        ("wallet_rpc_login_file", &c.wallet_rpc_login_file),
        ("daemon_rpc_login_file", &c.daemon_rpc_login_file),
        ("ops_key_file", &c.ops_key_file),
    ] {
        let p = path.to_str().unwrap();
        assert!(p.starts_with(RUN_DIR), "{key} is not on the tmpfs: {p}");
        assert!(
            ENTRYPOINT.contains(p.strip_prefix(RUN_DIR).unwrap()),
            "{key}: {p}"
        );
    }
    assert!(COMPOSE.contains("- /run/ghost:mode=0700"));
}

#[test]
fn tor_forwards_the_issuer_onion_to_the_listener() {
    let c = host_copy();
    let ports: Vec<&str> = code_lines(TORRC)
        .filter_map(|l| l.strip_prefix("HiddenServicePort "))
        .collect();
    assert_eq!(ports, vec![format!("443 {}", c.listen)]);
}

#[test]
fn the_monero_endpoints_are_the_ports_the_entrypoint_binds() {
    let c = host_copy();
    let (wallet, daemon) = (c.wallet_rpc.addr(), c.daemon_rpc.addr());
    assert!(wallet.ip().is_loopback() && daemon.ip().is_loopback());
    for needle in [
        format!("--rpc-bind-port {}", wallet.port()),
        format!("--rpc-bind-port {}", daemon.port()),
        format!("--daemon-address {daemon}"),
        "--wallet-file ".to_string(),
    ] {
        assert!(ENTRYPOINT.contains(&needle), "entrypoint.sh lacks {needle}");
    }
    assert!(
        !ENTRYPOINT.contains("--wallet-dir"),
        "never --wallet-dir (§7.1)"
    );
    assert!(!ENTRYPOINT.contains("--restricted-rpc"));
    assert!(!ENTRYPOINT.contains("--disable-rpc-login"));
}
