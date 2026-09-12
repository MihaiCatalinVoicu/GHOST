//! The issuer's configuration file (Phase 8 design §6.6; TOML). An unknown key, a missing required
//! key, a value out of range, a non-loopback address or a treasury address that is not a standard
//! address of the configured network refuses the start (exit status 2, [`crate::server`]).
//!
//! | key | meaning |
//! |---|---|
//! | `listen` | the gRPC listener: a loopback socket address (the onion service forwards to it) |
//! | `data_dir` | `issuer.redb`, the `journal/` directory and `status.json` |
//! | `schedule_file` | the Entitlement Schedule, verified under the pinned schedule key |
//! | `sealed_keys_dir` | the sealed per-epoch key files (`<kind>-<epoch>.ghks`) |
//! | `key_load_file` | the runbook K3 load file of `k_seal` values (`GHKL`) |
//! | `wallet_rpc_url`, `wallet_rpc_login_file` | `http://<loopback>:<port>` of the view-only wallet-rpc; `user:password` |
//! | `daemon_rpc_url`, `daemon_rpc_login_file` | the same for its monerod |
//! | `network` | `mainnet`, `stagenet` or `regtest`; must equal the schedule's network |
//! | `treasury_address` | the treasury's primary (standard) address; the wallet's primary address must equal it |
//! | `restore_height` | the treasury wallet's restore height (runbook R5), recorded in `meta` at the first start |
//! | `max_open_invoices` | open unpaid invoices at most (default and ceiling 20 000, §5.9) |
//! | `scan_interval_seconds` | scanner period, 15…90 (default 30; ±10 s jitter keeps a tick younger than 120 s) |
//! | `pool_target` | subaddress pool target, 1…1024 (default 32) |
//! | `reply_quantum_ms` | reply quantum of `BlindSign`, `RedeemInvite` and `RefreshCredit`, 100…10 000 (default 2 000) |
//! | `ops_key_file` | the 32-byte Ed25519 seed of the ops key that signs payout batch files (§9.5) |
//! | `export_dir` | where payout batch files are written and acknowledgement files are read (§9.5) |
//!
//! Recorded additions to the §6.6 key list, each needed to start the process: `key_load_file`
//! (K3 hands the `k_seal` values over in a file next to the sealed ones), `daemon_rpc_url` and
//! `daemon_rpc_login_file` (the synced-view rule of §5.4 and §19.6 needs the daemon's height and
//! synchronization state, which wallet-rpc does not expose), `treasury_address` (the §6.6 startup
//! check) and `restore_height` (R5 reads it from `meta`).

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use ghost_entitlement::monero::{AddressPurpose, AddressType, MoneroAddress, MoneroNetwork};
use serde::Deserialize;

use crate::rail::monero::Endpoint;
use crate::service::{IssuerParams, MAX_OPEN_INVOICES, POOL_TARGET};

pub const DEFAULT_SCAN_INTERVAL_SECS: u64 = 30;
pub const MIN_SCAN_INTERVAL_SECS: u64 = 15;
pub const MAX_SCAN_INTERVAL_SECS: u64 = 90;
pub const MAX_POOL_TARGET: u32 = 1_024;
pub const DEFAULT_REPLY_QUANTUM_MS: u64 = 2_000;
pub const MIN_REPLY_QUANTUM_MS: u64 = 100;
pub const MAX_REPLY_QUANTUM_MS: u64 = 10_000;

/// Why the configuration was refused. The text names the key, never a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConfigError {
    /// Not TOML, an unknown key, a missing required key or a value of the wrong type.
    Syntax,
    /// A key whose value is out of range or not an accepted address.
    Value(&'static str),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::Syntax => f.write_str("configuration is not the issuer's TOML key set"),
            ConfigError::Value(key) => write!(f, "configuration value refused: {key}"),
        }
    }
}

impl std::error::Error for ConfigError {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    listen: String,
    data_dir: PathBuf,
    schedule_file: PathBuf,
    sealed_keys_dir: PathBuf,
    key_load_file: PathBuf,
    wallet_rpc_url: String,
    wallet_rpc_login_file: PathBuf,
    daemon_rpc_url: String,
    daemon_rpc_login_file: PathBuf,
    network: String,
    treasury_address: String,
    restore_height: u64,
    #[serde(default = "default_max_open_invoices")]
    max_open_invoices: u64,
    #[serde(default = "default_scan_interval")]
    scan_interval_seconds: u64,
    #[serde(default = "default_pool_target")]
    pool_target: u32,
    #[serde(default = "default_reply_quantum")]
    reply_quantum_ms: u64,
    ops_key_file: PathBuf,
    export_dir: PathBuf,
}

fn default_max_open_invoices() -> u64 {
    MAX_OPEN_INVOICES
}

fn default_scan_interval() -> u64 {
    DEFAULT_SCAN_INTERVAL_SECS
}

fn default_pool_target() -> u32 {
    POOL_TARGET
}

fn default_reply_quantum() -> u64 {
    DEFAULT_REPLY_QUANTUM_MS
}

/// A validated configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub listen: SocketAddr,
    pub data_dir: PathBuf,
    pub schedule_file: PathBuf,
    pub sealed_keys_dir: PathBuf,
    pub key_load_file: PathBuf,
    pub wallet_rpc: Endpoint,
    pub wallet_rpc_login_file: PathBuf,
    pub daemon_rpc: Endpoint,
    pub daemon_rpc_login_file: PathBuf,
    pub network: MoneroNetwork,
    pub treasury_address: MoneroAddress,
    pub restore_height: u64,
    pub max_open_invoices: u64,
    pub scan_interval: Duration,
    pub pool_target: u32,
    pub reply_quantum: Duration,
    pub ops_key_file: PathBuf,
    pub export_dir: PathBuf,
}

fn network(name: &str) -> Option<MoneroNetwork> {
    match name {
        "mainnet" => Some(MoneroNetwork::Mainnet),
        "stagenet" => Some(MoneroNetwork::Stagenet),
        "regtest" => Some(MoneroNetwork::Regtest),
        _ => None,
    }
}

impl Config {
    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        let f: FileConfig = toml::from_str(text).map_err(|_| ConfigError::Syntax)?;
        let listen: SocketAddr = f
            .listen
            .parse()
            .ok()
            .filter(|a: &SocketAddr| a.ip().is_loopback())
            .ok_or(ConfigError::Value("listen"))?;
        let wallet_rpc = Endpoint::parse_url(&f.wallet_rpc_url)
            .map_err(|_| ConfigError::Value("wallet_rpc_url"))?;
        let daemon_rpc = Endpoint::parse_url(&f.daemon_rpc_url)
            .map_err(|_| ConfigError::Value("daemon_rpc_url"))?;
        let network = network(&f.network).ok_or(ConfigError::Value("network"))?;
        let treasury_address =
            MoneroAddress::parse(&f.treasury_address, network, AddressPurpose::Payout)
                .ok()
                .filter(|a| a.kind() == AddressType::Standard)
                .ok_or(ConfigError::Value("treasury_address"))?;
        if !(1..=MAX_OPEN_INVOICES).contains(&f.max_open_invoices) {
            return Err(ConfigError::Value("max_open_invoices"));
        }
        if !(MIN_SCAN_INTERVAL_SECS..=MAX_SCAN_INTERVAL_SECS).contains(&f.scan_interval_seconds) {
            return Err(ConfigError::Value("scan_interval_seconds"));
        }
        if !(1..=MAX_POOL_TARGET).contains(&f.pool_target) {
            return Err(ConfigError::Value("pool_target"));
        }
        if !(MIN_REPLY_QUANTUM_MS..=MAX_REPLY_QUANTUM_MS).contains(&f.reply_quantum_ms) {
            return Err(ConfigError::Value("reply_quantum_ms"));
        }
        Ok(Self {
            listen,
            data_dir: f.data_dir,
            schedule_file: f.schedule_file,
            sealed_keys_dir: f.sealed_keys_dir,
            key_load_file: f.key_load_file,
            wallet_rpc,
            wallet_rpc_login_file: f.wallet_rpc_login_file,
            daemon_rpc,
            daemon_rpc_login_file: f.daemon_rpc_login_file,
            network,
            treasury_address,
            restore_height: f.restore_height,
            max_open_invoices: f.max_open_invoices,
            scan_interval: Duration::from_secs(f.scan_interval_seconds),
            pool_target: f.pool_target,
            reply_quantum: Duration::from_millis(f.reply_quantum_ms),
            ops_key_file: f.ops_key_file,
            export_dir: f.export_dir,
        })
    }

    /// The issuer's operating limits from this configuration (the rate limit stays §5.9's).
    pub fn params(&self) -> IssuerParams {
        IssuerParams {
            max_open_invoices: self.max_open_invoices,
            pool_target: self.pool_target,
            ..IssuerParams::default()
        }
    }
}
