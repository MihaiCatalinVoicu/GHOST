//! The issuer process (Phase 8 design §5.1, §6.5–§6.7; ADR-26): the configuration file, the
//! startup steps and their refusal classes (the exit status), and the gRPC server with its
//! periodic jobs on an injected clock over the `ChainPort` wallet.

mod common;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::chain_port::{encode_address, ChainPort, RailHandle};
use common::epee::{self, Emulator, Options, Reply};
use common::fixture;
use common::world::{claim_key, seed, BASE, BASE_WEEK, PRICE, START_BLOCKS};
use ghost_entitlement::batch::{self, Layout};
use ghost_entitlement::monero::MoneroNetwork;
use ghost_entitlement::Kind;
use ghost_issuer::config::{Config, ConfigError};
use ghost_issuer::custody::{CustodySecret, SealLoad};
use ghost_issuer::payout::OpsKey;
use ghost_issuer::quantum::{Clock, ReplyQuantum};
use ghost_issuer::rail::digest::Credentials;
use ghost_issuer::rail::monero::{MoneroWalletRpc, RpcClient, Timeouts};
use ghost_issuer::server::{self, Invocation, Refusal, ServeSettings};
use ghost_issuer::service::OpenMode;
use ghost_issuer::store::{self, MetaKey};
use ghost_issuer_api::proto as wire;
use ghost_issuer_api::proto::issuer_service_client::IssuerServiceClient;
use serde_json::json;
use tonic::Code;

/// The committed stagenet Entitlement Schedule (slice S2b), verified under the pinned key.
fn stagenet_schedule_file() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../protocol/entitlement/schedule.ghes")
}

fn regtest_treasury() -> String {
    encode_address(18, 7, 8)
}

fn stagenet_treasury() -> String {
    encode_address(24, 7, 8)
}

/// A TOML literal string (no escapes: Windows paths stay as they are).
fn lit(s: impl std::fmt::Display) -> String {
    format!("'{s}'")
}

/// A configuration file with every key, then `changes` (`None` leaves the key out).
fn config_text(dir: &Path, changes: &[(&str, Option<&str>)]) -> String {
    let mut keys: Vec<(String, String)> = vec![
        ("listen", lit("127.0.0.1:7444")),
        ("data_dir", lit(dir.join("data").display())),
        ("schedule_file", lit(dir.join("schedule.ghes").display())),
        ("sealed_keys_dir", lit(fixture::sealed_dir().display())),
        ("key_load_file", lit(dir.join("keys.ghkl").display())),
        ("wallet_rpc_url", lit("http://127.0.0.1:18083")),
        (
            "wallet_rpc_login_file",
            lit(dir.join("wallet.login").display()),
        ),
        ("daemon_rpc_url", lit("http://127.0.0.1:18081")),
        (
            "daemon_rpc_login_file",
            lit(dir.join("daemon.login").display()),
        ),
        ("network", lit("regtest")),
        ("treasury_address", lit(regtest_treasury())),
        ("restore_height", "1".to_string()),
        ("ops_key_file", lit(dir.join("ops.key").display())),
        ("export_dir", lit(dir.join("export").display())),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v))
    .collect();
    for (k, v) in changes {
        keys.retain(|(name, _)| name != k);
        if let Some(v) = v {
            keys.push((k.to_string(), v.to_string()));
        }
    }
    keys.iter().map(|(k, v)| format!("{k} = {v}\n")).collect()
}

/// Configuration changes: a key and its new value (`None` leaves it out).
type Changes<'a> = Vec<(&'a str, Option<&'a str>)>;
/// A load-file entry: the (kind, epoch) listed and the (kind, epoch) whose `k_seal` it carries.
type LoadEntry = ((Kind, u64), (Kind, u64));

fn args(a: &[&str]) -> Vec<String> {
    a.iter().map(|s| s.to_string()).collect()
}

#[test]
fn the_configuration_takes_the_key_set_with_its_defaults() {
    let dir = tempfile::tempdir().unwrap();
    let c = Config::parse(&config_text(dir.path(), &[])).unwrap();
    assert_eq!(c.listen, "127.0.0.1:7444".parse().unwrap());
    assert_eq!(c.network, MoneroNetwork::Regtest);
    assert_eq!(c.treasury_address.as_str(), regtest_treasury());
    assert_eq!(c.wallet_rpc.addr(), "127.0.0.1:18083".parse().unwrap());
    assert_eq!(c.daemon_rpc.addr(), "127.0.0.1:18081".parse().unwrap());
    assert_eq!(c.restore_height, 1);
    assert_eq!(
        (
            c.max_open_invoices,
            c.scan_interval,
            c.pool_target,
            c.reply_quantum
        ),
        (
            20_000,
            Duration::from_secs(30),
            32,
            Duration::from_millis(2_000)
        )
    );
    let p = c.params();
    assert_eq!((p.max_open_invoices, p.pool_target), (20_000, 32));

    let c = Config::parse(&config_text(
        dir.path(),
        &[
            ("listen", Some("'[::1]:7444'")),
            ("scan_interval_seconds", Some("15")),
            ("pool_target", Some("1")),
            ("reply_quantum_ms", Some("100")),
            ("max_open_invoices", Some("1")),
        ],
    ))
    .unwrap();
    assert_eq!(
        (
            c.scan_interval,
            c.pool_target,
            c.reply_quantum,
            c.max_open_invoices
        ),
        (Duration::from_secs(15), 1, Duration::from_millis(100), 1)
    );
}

#[test]
fn the_configuration_refuses_unknown_keys_ranges_and_addresses_off_loopback() {
    let dir = tempfile::tempdir().unwrap();
    let subaddress = lit(encode_address(42, 7, 8));
    let stagenet = lit(stagenet_treasury());
    let cases: Vec<(Changes, ConfigError)> = vec![
        (vec![("unknown_key", Some("1"))], ConfigError::Syntax),
        // The payout export's keys are required (§6.6, §9.5).
        (vec![("export_dir", None)], ConfigError::Syntax),
        (vec![("ops_key_file", None)], ConfigError::Syntax),
        (vec![("restore_height", None)], ConfigError::Syntax),
        (vec![("restore_height", Some("1.5"))], ConfigError::Syntax),
        (vec![("restore_height", Some("-1"))], ConfigError::Syntax),
        (vec![("pool_target", Some("'32'"))], ConfigError::Syntax),
        (
            vec![("listen", Some("'0.0.0.0:7444'"))],
            ConfigError::Value("listen"),
        ),
        (
            vec![("listen", Some("'[::]:7444'"))],
            ConfigError::Value("listen"),
        ),
        (
            vec![("listen", Some("'localhost:7444'"))],
            ConfigError::Value("listen"),
        ),
        (
            vec![("wallet_rpc_url", Some("'http://localhost:18083'"))],
            ConfigError::Value("wallet_rpc_url"),
        ),
        (
            vec![("wallet_rpc_url", Some("'https://127.0.0.1:18083'"))],
            ConfigError::Value("wallet_rpc_url"),
        ),
        (
            vec![("daemon_rpc_url", Some("'http://192.168.1.2:18081'"))],
            ConfigError::Value("daemon_rpc_url"),
        ),
        (
            vec![("network", Some("'testnet'"))],
            ConfigError::Value("network"),
        ),
        (
            vec![("treasury_address", Some(subaddress.as_str()))],
            ConfigError::Value("treasury_address"),
        ),
        (
            vec![("treasury_address", Some(stagenet.as_str()))],
            ConfigError::Value("treasury_address"),
        ),
        (
            vec![("scan_interval_seconds", Some("14"))],
            ConfigError::Value("scan_interval_seconds"),
        ),
        (
            vec![("scan_interval_seconds", Some("91"))],
            ConfigError::Value("scan_interval_seconds"),
        ),
        (
            vec![("pool_target", Some("0"))],
            ConfigError::Value("pool_target"),
        ),
        (
            vec![("pool_target", Some("1025"))],
            ConfigError::Value("pool_target"),
        ),
        (
            vec![("reply_quantum_ms", Some("99"))],
            ConfigError::Value("reply_quantum_ms"),
        ),
        (
            vec![("reply_quantum_ms", Some("10001"))],
            ConfigError::Value("reply_quantum_ms"),
        ),
        (
            vec![("max_open_invoices", Some("0"))],
            ConfigError::Value("max_open_invoices"),
        ),
        (
            vec![("max_open_invoices", Some("20001"))],
            ConfigError::Value("max_open_invoices"),
        ),
    ];
    for (changes, want) in cases {
        assert_eq!(
            Config::parse(&config_text(dir.path(), &changes)),
            Err(want),
            "{changes:?}"
        );
    }
}

#[test]
fn arguments_and_exit_status() {
    let normal = Invocation {
        config: "c.toml".into(),
        mode: OpenMode::Normal,
        restore_wallet: false,
    };
    assert_eq!(
        server::parse_args(&args(&["--config", "c.toml"])),
        Ok(normal)
    );
    for restore in [
        &["--config", "c.toml", "--restore"][..],
        &["--restore", "--config", "c.toml"],
    ] {
        assert_eq!(
            server::parse_args(&args(restore)).map(|i| (i.mode, i.restore_wallet)),
            Ok((OpenMode::Restore, false))
        );
    }
    // Runbook R5 (review finding S5-MON-1), alone or with a B1 restore.
    assert_eq!(
        server::parse_args(&args(&["--restore-wallet", "--config", "c.toml"]))
            .map(|i| (i.mode, i.restore_wallet)),
        Ok((OpenMode::Normal, true))
    );
    assert_eq!(
        server::parse_args(&args(&["--config", "c", "--restore", "--restore-wallet"]))
            .map(|i| (i.mode, i.restore_wallet)),
        Ok((OpenMode::Restore, true))
    );
    for bad in [
        &[][..],
        &["--config"],
        &["--restore"],
        &["--restore-wallet"],
        &["--config", "a", "--config", "b"],
        &["--config", "a", "--restore", "--restore"],
        &["--config", "a", "--restore-wallet", "--restore-wallet"],
        &["--config", "a", "--verbose"],
    ] {
        assert_eq!(
            server::parse_args(&args(bad)),
            Err(Refusal::Usage),
            "{bad:?}"
        );
    }
    assert_eq!(
        [
            Refusal::Serve,
            Refusal::Usage,
            Refusal::Config,
            Refusal::Schedule,
            Refusal::Keys,
            Refusal::Wallet,
            Refusal::State
        ]
        .map(Refusal::exit_code),
        [1, 2, 2, 3, 4, 5, 6]
    );

    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("issuer.toml");
    assert_eq!(server::run_cli(&args(&[])), ExitCode::from(2));
    let path = config.display().to_string();
    assert_eq!(
        server::run_cli(&args(&["--config", &path])),
        ExitCode::from(2),
        "no configuration file"
    );
    std::fs::write(&config, config_text(dir.path(), &[])).unwrap();
    assert_eq!(
        server::run_cli(&args(&["--config", &path])),
        ExitCode::from(3),
        "no schedule file"
    );
    let stagenet_file = lit(stagenet_schedule_file().display());
    std::fs::write(
        &config,
        config_text(
            dir.path(),
            &[("schedule_file", Some(stagenet_file.as_str()))],
        ),
    )
    .unwrap();
    assert_eq!(
        server::run_cli(&args(&["--config", &path])),
        ExitCode::from(3),
        "a stagenet schedule on a regtest configuration"
    );
    let stagenet_treasury = lit(stagenet_treasury());
    std::fs::write(
        &config,
        config_text(
            dir.path(),
            &[
                ("schedule_file", Some(stagenet_file.as_str())),
                ("network", Some("'stagenet'")),
                ("treasury_address", Some(stagenet_treasury.as_str())),
            ],
        ),
    )
    .unwrap();
    assert_eq!(
        server::run_cli(&args(&["--config", &path])),
        ExitCode::from(4),
        "no key load file"
    );
}

#[test]
fn the_ops_key_is_a_32_byte_seed() {
    let dir = tempfile::tempdir().unwrap();
    let config = Config::parse(&config_text(dir.path(), &[])).unwrap();
    assert_eq!(
        server::load_ops_key(&config).err(),
        Some(Refusal::Keys),
        "missing"
    );
    std::fs::write(&config.ops_key_file, [7u8; 31]).unwrap();
    assert_eq!(
        server::load_ops_key(&config).err(),
        Some(Refusal::Keys),
        "short"
    );
    std::fs::write(&config.ops_key_file, [7u8; 33]).unwrap();
    assert_eq!(
        server::load_ops_key(&config).err(),
        Some(Refusal::Keys),
        "long"
    );
    std::fs::write(&config.ops_key_file, [7u8; 32]).unwrap();
    let key = server::load_ops_key(&config).unwrap();
    assert_eq!(key.public(), OpsKey::from_seed(&[7; 32]).public());
    assert_eq!(format!("{key:?}"), "OpsKey(redacted)");
}

#[test]
fn the_schedule_is_verified_under_the_pinned_key_on_the_configured_network() {
    let dir = tempfile::tempdir().unwrap();
    let stagenet_file = lit(stagenet_schedule_file().display());
    let stagenet_treasury = lit(stagenet_treasury());
    let stagenet = Config::parse(&config_text(
        dir.path(),
        &[
            ("schedule_file", Some(stagenet_file.as_str())),
            ("network", Some("'stagenet'")),
            ("treasury_address", Some(stagenet_treasury.as_str())),
        ],
    ))
    .unwrap();
    let schedule = server::load_schedule(&stagenet).unwrap();
    assert_eq!(schedule.network(), MoneroNetwork::Stagenet);

    let regtest = Config::parse(&config_text(
        dir.path(),
        &[("schedule_file", Some(stagenet_file.as_str()))],
    ))
    .unwrap();
    assert_eq!(
        server::load_schedule(&regtest).err(),
        Some(Refusal::Schedule)
    );
    assert_eq!(
        server::check_network(&stagenet, &fixture::small().0),
        Err(Refusal::Schedule)
    );
    // The test schedule is signed by the test key, never the pinned one.
    std::fs::write(dir.path().join("schedule.ghes"), fixture::schedule_bytes()).unwrap();
    let test = Config::parse(&config_text(dir.path(), &[])).unwrap();
    assert_eq!(server::load_schedule(&test).err(), Some(Refusal::Schedule));
}

#[test]
fn keys_load_from_the_sealed_files_through_the_k3_load_file() {
    let dir = tempfile::tempdir().unwrap();
    let config = Config::parse(&config_text(dir.path(), &[])).unwrap();
    let schedule = fixture::schedule();
    let secret = CustodySecret::from_bytes(fixture::custody_secret_bytes());
    let load_file = |entries: &[LoadEntry]| {
        let mut load = SealLoad::new();
        for &((kind, epoch), (seal_kind, seal_epoch)) in entries {
            load.insert(kind, epoch, secret.seal_key(seal_kind, seal_epoch))
                .unwrap();
        }
        std::fs::write(dir.path().join("keys.ghkl"), load.encode().unwrap()).unwrap();
    };
    let wanted = [
        (Kind::Access, 2960),
        (Kind::Invite, 740),
        (Kind::Credit, 227),
    ];
    load_file(&wanted.map(|k| (k, k)));
    let window = server::load_keys(&config, &schedule).unwrap();
    assert_eq!(
        window.held().into_iter().collect::<BTreeSet<_>>(),
        wanted.into_iter().collect::<BTreeSet<_>>()
    );
    // A k_seal of another epoch opens nothing; a key the schedule does not list; no load file.
    load_file(&[((Kind::Access, 2960), (Kind::Access, 2961))]);
    assert_eq!(
        server::load_keys(&config, &schedule).err(),
        Some(Refusal::Keys)
    );
    load_file(&[((Kind::Access, 3100), (Kind::Access, 3100))]);
    assert_eq!(
        server::load_keys(&config, &schedule).err(),
        Some(Refusal::Keys)
    );
    std::fs::remove_file(dir.path().join("keys.ghkl")).unwrap();
    assert_eq!(
        server::load_keys(&config, &schedule).err(),
        Some(Refusal::Keys)
    );
}

#[test]
fn the_wallet_must_be_watch_only_and_the_treasury() {
    let dir = tempfile::tempdir().unwrap();
    let treasury = regtest_treasury();
    let answering = |spend_key_answer: bool, primary: String| {
        Emulator::start(Options::default(), move |c| match c.method.as_str() {
            "query_key" if spend_key_answer => Reply::Result(json!({"key": "ab".repeat(32)})),
            "query_key" => {
                Reply::Error(-29, "The wallet is watch-only. Cannot retrieve spend key.")
            }
            "get_address" => Reply::Result(json!({
                "address": primary,
                "addresses": [{"address": primary, "address_index": 0, "label": "Primary account", "used": true}]
            })),
            _ => Reply::Error(-32601, "Method not found"),
        })
    };
    let watch_only = answering(false, treasury.clone());
    let full = answering(true, treasury.clone());
    let other = answering(false, encode_address(18, 9, 10));
    let daemon_on = |nettype: &'static str| {
        Emulator::start(Options::default(), move |c| match c.method.as_str() {
            "get_info" => Reply::Result(json!({"height": 5, "synchronized": true,
                                               "busy_syncing": false, "status": "OK",
                                               "nettype": nettype})),
            _ => Reply::Error(-32601, "Method not found"),
        })
    };
    let daemon = daemon_on("fakechain");
    let stagenet_daemon = daemon_on("stagenet");
    let login = format!("{}:{}\n", epee::USER, epee::PASSWORD);
    std::fs::write(dir.path().join("wallet.login"), &login).unwrap();
    std::fs::write(dir.path().join("daemon.login"), &login).unwrap();
    let config_with = |wallet: &Emulator, daemon: &Emulator| {
        let w = lit(format!("http://{}", wallet.endpoint().addr()));
        let d = lit(format!("http://{}", daemon.endpoint().addr()));
        Config::parse(&config_text(
            dir.path(),
            &[
                ("wallet_rpc_url", Some(w.as_str())),
                ("daemon_rpc_url", Some(d.as_str())),
            ],
        ))
        .unwrap()
    };
    let config_for = |wallet: &Emulator| config_with(wallet, &daemon);
    assert!(server::connect_wallet(&config_for(&watch_only)).is_ok());
    assert_eq!(
        server::connect_wallet(&config_with(&watch_only, &stagenet_daemon)).err(),
        Some(Refusal::Wallet),
        "a regtest configuration over a stagenet daemon (review finding S5-MON-5)"
    );
    assert_eq!(
        server::connect_wallet(&config_for(&full)).err(),
        Some(Refusal::Wallet),
        "a wallet holding the spend key"
    );
    assert_eq!(
        server::connect_wallet(&config_for(&other)).err(),
        Some(Refusal::Wallet),
        "another treasury"
    );
    std::fs::write(dir.path().join("wallet.login"), "ci:wrong\n").unwrap();
    assert_eq!(
        server::connect_wallet(&config_for(&watch_only)).err(),
        Some(Refusal::Wallet),
        "wrong credentials"
    );
    std::fs::remove_file(dir.path().join("wallet.login")).unwrap();
    assert_eq!(
        server::connect_wallet(&config_for(&watch_only)).err(),
        Some(Refusal::Wallet),
        "no login file"
    );
}

#[test]
fn the_state_opens_in_the_data_directory_and_keeps_the_restore_height() {
    let dir = tempfile::tempdir().unwrap();
    let config = Config::parse(&config_text(dir.path(), &[])).unwrap();
    let (schedule, keys) = fixture::small().clone();
    let chain = ChainPort::new(START_BLOCKS);
    let open = || {
        server::open_issuer(
            &config,
            schedule.clone(),
            keys.clone(),
            Box::new(RailHandle(Arc::clone(&chain))),
            OpenMode::Normal,
            BASE,
        )
    };
    assert_eq!(open().err(), Some(Refusal::State), "no data directory");
    std::fs::create_dir(dir.path().join("data")).unwrap();
    let issuer = open().unwrap();
    assert!(dir
        .path()
        .join("data")
        .join(server::DATABASE_FILE_NAME)
        .is_file());
    assert!(dir
        .path()
        .join("data")
        .join(server::JOURNAL_DIR_NAME)
        .is_dir());
    assert_eq!(server::record_restore_height(&issuer, 5), Ok(()));
    assert_eq!(server::record_restore_height(&issuer, 5), Ok(()));
    assert_eq!(
        server::record_restore_height(&issuer, 6),
        Err(Refusal::State)
    );
    drop(issuer);
    let issuer = open().unwrap();
    assert_eq!(
        server::record_restore_height(&issuer, 6),
        Err(Refusal::State)
    );
    assert_eq!(server::record_restore_height(&issuer, 5), Ok(()));
}

/// Runbook R5 steps 2–3 as `--restore-wallet` runs them (review finding S5-MON-1): the operator
/// gives no number; the replay reaches the database's `highest_minor`, then the chain is rescanned
/// once, after the last `create_address`.
#[test]
fn restore_wallet_replays_through_the_highest_minor_then_rescans() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("data")).unwrap();
    let config = Config::parse(&config_text(dir.path(), &[])).unwrap();
    let (schedule, keys) = fixture::small().clone();
    let issuer = server::open_issuer(
        &config,
        schedule,
        keys,
        Box::new(RailHandle(ChainPort::new(START_BLOCKS))),
        OpenMode::Normal,
        BASE,
    )
    .unwrap();
    {
        let mut tx = issuer.store().write().unwrap();
        store::set_meta(&mut *tx, MetaKey::HighestMinor, 70_000).unwrap();
        tx.commit().unwrap();
    }
    let rescan_fails = Arc::new(AtomicBool::new(false));
    let fails = Arc::clone(&rescan_fails);
    let count = Arc::new(AtomicU64::new(3));
    let n = Arc::clone(&count);
    let wallet = Emulator::start(Options::default(), move |c| match c.method.as_str() {
        "get_address" => epee::get_address_reply(c, n.load(Ordering::SeqCst)),
        "create_address" => {
            let k = c.params["count"].as_u64().unwrap();
            let first = n.fetch_add(k, Ordering::SeqCst);
            Reply::Result(json!({
                "address": epee::SUBADDRESS,
                "address_index": first,
                "address_indices": (first..first + k).collect::<Vec<u64>>(),
                "addresses": vec![epee::SUBADDRESS; k as usize],
            }))
        }
        "rescan_blockchain" if fails.load(Ordering::SeqCst) => Reply::Error(-1, "refused"),
        "rescan_blockchain" => Reply::Result(json!({})),
        _ => Reply::Error(-32601, "Method not found"),
    });
    let daemon = Emulator::start(Options::default(), |_| {
        Reply::Error(-32601, "Method not found")
    });
    let client = |e: &Emulator| {
        let credentials = Credentials::new(epee::USER, epee::PASSWORD).unwrap();
        RpcClient::new(e.endpoint(), credentials, Timeouts::default()).unwrap()
    };
    let rail = MoneroWalletRpc::new(client(&wallet), client(&daemon));
    assert_eq!(server::restore_wallet(&issuer, &rail), Ok(70_001));
    let calls = wallet.calls();
    let created: Vec<u64> = calls
        .iter()
        .filter(|c| c.method == "create_address")
        .map(|c| c.params["count"].as_u64().unwrap())
        .collect();
    assert_eq!(created, [65_536, 70_001 - 3 - 65_536]);
    let last_create = calls
        .iter()
        .rposition(|c| c.method == "create_address")
        .unwrap();
    let rescans: Vec<usize> = calls
        .iter()
        .enumerate()
        .filter(|(_, c)| c.method == "rescan_blockchain")
        .map(|(i, _)| i)
        .collect();
    assert_eq!(rescans.len(), 1);
    assert!(rescans[0] > last_create, "the rescan follows the replay");
    assert_eq!(calls[rescans[0]].params, json!({"hard": false}));
    // A failed rescan refuses the start (exit status 5): the issuer never serves a wallet whose
    // view may miss payments.
    rescan_fails.store(true, Ordering::SeqCst);
    assert_eq!(server::restore_wallet(&issuer, &rail), Err(Refusal::Wallet));
}

#[test]
fn serves_on_loopback_with_its_jobs_on_the_injected_clock() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("data")).unwrap();
    let config = Config::parse(&config_text(dir.path(), &[("pool_target", Some("4"))])).unwrap();
    let (schedule, keys) = fixture::small().clone();
    let chain = ChainPort::new(START_BLOCKS);
    let issuer = Arc::new(
        server::open_issuer(
            &config,
            schedule.clone(),
            keys,
            Box::new(RailHandle(Arc::clone(&chain))),
            OpenMode::Normal,
            BASE,
        )
        .unwrap(),
    );
    // The injected clock stays in week 2960, whatever the wall clock says: the handlers and the
    // jobs see only it (a wall-clock handler would answer WRONG_PERIOD or refuse a stale tick).
    let now = Arc::new(AtomicU64::new(BASE));
    let clock: Clock = {
        let now = Arc::clone(&now);
        Arc::new(move || now.load(Ordering::SeqCst))
    };
    let status_file = dir.path().join("data").join("status.json");
    let settings = ServeSettings {
        quantum: ReplyQuantum::new(Duration::from_millis(50)),
        signing_permits: 2,
        scan_interval: Duration::from_millis(100),
        scan_jitter: Duration::ZERO,
        refill_interval: Duration::from_millis(100),
        sweep_interval: Duration::from_secs(3_600),
        status_interval: Duration::from_millis(100),
        status_file: status_file.clone(),
        payout_interval: Duration::from_secs(3_600),
        ops_key: Arc::new(OpsKey::from_seed(&[5; 32])),
        export_dir: dir.path().join("export"),
    };
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async move {
        let open = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
        assert_eq!(
            server::serve(
                Arc::clone(&issuer),
                open,
                settings.clone(),
                Arc::clone(&clock)
            )
            .await,
            Err(Refusal::Config),
            "any listener but a loopback one is refused before anything is served"
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(server::serve(
            Arc::clone(&issuer),
            listener,
            settings,
            clock,
        ));

        let deadline = Instant::now() + Duration::from_secs(30);
        let status = loop {
            if let Ok(s) = std::fs::read_to_string(&status_file) {
                break s;
            }
            assert!(Instant::now() < deadline, "no status file");
            tokio::time::sleep(Duration::from_millis(50)).await;
        };
        assert!(status.contains("\"SCANNER\":\"SCANNER_OK\""), "{status}");

        let channel = tonic::transport::Endpoint::from_shared(format!("http://{addr}"))
            .unwrap()
            .connect()
            .await
            .unwrap();
        let mut client = IssuerServiceClient::new(channel);
        let label = "served";
        let invoice = client
            .request_invoice(wire::RequestInvoiceRequest {
                version: 1,
                rail: wire::Rail::Monero as i32,
                product: wire::Product::Pack as i32,
                claim_hash: batch::claim_hash(&claim_key(label)).to_vec(),
                credits: Vec::new(),
                base_week: BASE_WEEK,
            })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(invoice.result, wire::RequestInvoiceResult::Ok as i32);
        assert_eq!(invoice.amount_atomic, PRICE);
        chain.pay(chain.minor_of(&invoice.subaddress), PRICE);
        chain.mine(10);

        // The scanner job, not the request, sees the payment.
        let layout = Layout::pack(&schedule, BASE_WEEK, true).unwrap();
        let blinded = batch::blind(&schedule, &seed(label), &layout).unwrap();
        let request = wire::BlindSignRequest {
            version: 1,
            invoice_id: invoice.invoice_id.clone(),
            claim_key: claim_key(label).to_vec(),
            blinded: blinded.clone(),
        };
        let signed = loop {
            let r = client
                .blind_sign(request.clone())
                .await
                .unwrap()
                .into_inner();
            if r.state == wire::InvoiceState::Signed as i32 {
                break r;
            }
            assert!(Instant::now() < deadline, "the scanner job never ticked");
            tokio::time::sleep(Duration::from_millis(100)).await;
        };
        assert_eq!(signed.blind_signatures.len(), blinded.len());
        let status = client
            .invoice_status(wire::InvoiceStatusRequest {
                version: 1,
                invoice_id: invoice.invoice_id.clone(),
                claim_key: claim_key(label).to_vec(),
            })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(status.state, wire::InvoiceState::Signed as i32);
        let refresh = client
            .refresh_credit(wire::RefreshCreditRequest {
                version: 1,
                credit: vec![0; 354],
                blinded: vec![1; 256],
            })
            .await
            .unwrap_err();
        assert_eq!(
            refresh.code(),
            Code::PermissionDenied,
            "RefreshCredit is served (§19.8): a credit of zeros is no token"
        );

        // The clock the handlers see is the injected one: two weeks later the same base week is
        // refused.
        now.store(BASE + 14 * 86_400, Ordering::SeqCst);
        let late = client
            .request_invoice(wire::RequestInvoiceRequest {
                version: 1,
                rail: wire::Rail::Monero as i32,
                product: wire::Product::Pack as i32,
                claim_hash: batch::claim_hash(&claim_key("late")).to_vec(),
                credits: Vec::new(),
                base_week: BASE_WEEK,
            })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(late.result, wire::RequestInvoiceResult::WrongPeriod as i32);
    });
}
