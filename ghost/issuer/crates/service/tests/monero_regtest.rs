//! The live Monero scenario (Phase 8 design §13.3; RM §9.3; slice S5 runs steps 1–10, 12, 13, 17
//! and 18): the production rail ([`MoneroWalletRpc`], JSON-RPC with digest authentication) and the
//! real issuer (redb store, journal, handlers, scanner, pool) against `monerod --regtest --offline
//! --fixed-difficulty 1` and three `monero-wallet-rpc` processes with digest authentication on:
//! the payer (a full wallet), the issuer's view-only wallet (its process also hosts the payout
//! workstation's view wallet in step 10), and the treasury as the cold signer (`--offline`).
//!
//! Ignored by default. `GHOST_MONERO_BIN` names the directory of the pinned binaries
//! (`ghost/infra/issuer/monero-release.pin`; the `monero-regtest` workflow downloads and checks
//! them); a run without it fails:
//!
//! ```text
//! GHOST_MONERO_BIN=<dir> cargo test -p ghost-issuer --release --test monero_regtest -- --ignored
//! ```
//!
//! `daemon_digest_authentication` needs `monerod` only. The scenario uses the test Entitlement
//! Schedule re-signed with 30 invoice blocks and 20 grace blocks (an expiry takes 60 blocks, not
//! 2 890) and one access and trial position per slot. Not here: step 11 (the workstation's cap
//! guard is `payout-check`) and steps 14–16b, slice S6.

mod common;

use std::collections::BTreeSet;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use common::chain_port::encode_address;
use common::fixture;
use common::world::{claim_key, seed, BASE, BASE_WEEK, PRICE};
use ghost_entitlement::batch::{self, Layout};
use ghost_entitlement::monero::{
    base58_decode, base58_encode, AddressPurpose, AddressType, MoneroAddress, MoneroNetwork,
};
use ghost_entitlement::Schedule;
use ghost_issuer::custody::KeyWindow;
use ghost_issuer::journal::FileJournal;
use ghost_issuer::rail::digest::Credentials;
use ghost_issuer::rail::monero::{
    Endpoint, MoneroWalletRpc, RpcClient, Timeouts, WalletCheckError, TRANSFER_FIELDS,
};
use ghost_issuer::rail::{PaymentRail, RailError};
use ghost_issuer::reconcile::{self, CounterId, Counters};
use ghost_issuer::scanner::TickReport;
use ghost_issuer::service::{Issuer, IssuerParams, OpenMode, OsRandom, Ports};
use ghost_issuer::store::{self, MetaKey, RedbStore};
use ghost_issuer_api::proto as wire;
use serde_json::{json, Value};
use sha3::{Digest, Keccak256};
use tonic::Code;

const USER: &str = "ci";
const DAEMON_PASSWORD: &str = "regtest-daemon-login";
const WALLET_PASSWORD: &str = "regtest-wallet-login";
const CONFIRMATIONS: u64 = 10;
const SIGNED: i32 = wire::InvoiceState::Signed as i32;
const AWAITING_PAYMENT: i32 = wire::InvoiceState::AwaitingPayment as i32;
const AWAITING_CONFIRMATIONS: i32 = wire::InvoiceState::AwaitingConfirmations as i32;
const UNDERPAID: i32 = wire::InvoiceState::Underpaid as i32;
const EXPIRED: i32 = wire::InvoiceState::Expired as i32;
const OVERPAID_BY: u64 = 12_345;
const PAYOUT: u64 = 50_000_000_000;

fn exe(bin: &Path, name: &str) -> PathBuf {
    bin.join(format!("{name}{}", std::env::consts::EXE_SUFFIX))
}

fn bin_dir() -> PathBuf {
    let dir = PathBuf::from(std::env::var_os("GHOST_MONERO_BIN").expect(
        "GHOST_MONERO_BIN: the directory of the pinned monerod and monero-wallet-rpc \
         (ghost/infra/issuer/monero-release.pin)",
    ));
    assert!(
        exe(&dir, "monerod").is_file(),
        "no monerod in {}",
        dir.display()
    );
    dir
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A child process, killed when dropped.
struct Proc(Child);

impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn endpoint(port: u16) -> Endpoint {
    Endpoint::new(([127, 0, 0, 1], port).into()).unwrap()
}

/// A test client: long limits (mining and wallet scans).
fn client(port: u16, password: &str) -> RpcClient {
    let timeouts = Timeouts {
        connect: Duration::from_secs(5),
        call: Duration::from_secs(300),
        long: Duration::from_secs(900),
    };
    RpcClient::new(
        endpoint(port),
        Credentials::new(USER, password).unwrap(),
        timeouts,
    )
    .unwrap()
}

fn rpc(c: &RpcClient, method: &str, params: Value) -> Value {
    c.call_with(method, params, Duration::from_secs(900), 64 << 20)
        .unwrap_or_else(|e| panic!("{method}: {e}"))
}

fn wait_ready(c: &RpcClient, method: &str) {
    let deadline = Instant::now() + Duration::from_secs(120);
    while c.call(method, json!({})).is_err() {
        assert!(Instant::now() < deadline, "{method} never answered");
        std::thread::sleep(Duration::from_millis(250));
    }
}

fn start_daemon(bin: &Path, dir: &Path) -> (Proc, u16, RpcClient) {
    let (port, p2p) = (free_port(), free_port());
    let child = Command::new(exe(bin, "monerod"))
        .args([
            "--regtest",
            "--offline",
            "--fixed-difficulty",
            "1",
            "--non-interactive",
            "--no-zmq",
            "--disable-dns-checkpoints",
            "--check-updates",
            "disabled",
            "--rpc-ssl",
            "disabled",
            "--log-level",
            "0",
            "--max-log-files",
            "1",
            "--rpc-bind-ip",
            "127.0.0.1",
            "--p2p-bind-ip",
            "127.0.0.1",
        ])
        .arg("--data-dir")
        .arg(dir.join("daemon"))
        .arg("--log-file")
        .arg(dir.join("monerod.log"))
        .arg("--rpc-bind-port")
        .arg(port.to_string())
        .arg("--p2p-bind-port")
        .arg(p2p.to_string())
        .arg("--rpc-login")
        .arg(format!("{USER}:{DAEMON_PASSWORD}"))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("monerod starts");
    let proc = Proc(child);
    let rpc = client(port, DAEMON_PASSWORD);
    wait_ready(&rpc, "get_info");
    (proc, port, rpc)
}

/// `monero-wallet-rpc` with digest authentication (`RPC_LOGIN`), on `daemon` or `--offline`.
fn spawn_wallet(bin: &Path, dir: &Path, port: u16, daemon: Option<u16>) -> Proc {
    std::fs::create_dir_all(dir).unwrap();
    let mut cmd = Command::new(exe(bin, "monero-wallet-rpc"));
    cmd.arg("--wallet-dir")
        .arg(dir)
        .args([
            "--rpc-bind-ip",
            "127.0.0.1",
            "--rpc-ssl",
            "disabled",
            "--log-level",
            "0",
            "--max-log-files",
            "1",
            "--allow-mismatched-daemon-version",
        ])
        .arg("--rpc-bind-port")
        .arg(port.to_string())
        .arg("--log-file")
        .arg(dir.with_extension("log"))
        .env("RPC_LOGIN", format!("{USER}:{WALLET_PASSWORD}"));
    match daemon {
        Some(p) => {
            cmd.args(["--daemon-ssl", "disabled", "--trusted-daemon"])
                .arg("--daemon-address")
                .arg(format!("127.0.0.1:{p}"))
                .arg("--daemon-login")
                .arg(format!("{USER}:{DAEMON_PASSWORD}"));
        }
        None => {
            cmd.arg("--offline");
        }
    }
    Proc(
        cmd.stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("monero-wallet-rpc starts"),
    )
}

struct Wallet {
    proc: Option<Proc>,
    port: u16,
    dir: PathBuf,
    rpc: RpcClient,
}

impl Wallet {
    fn start(bin: &Path, dir: PathBuf, daemon: Option<u16>) -> Self {
        let port = free_port();
        let proc = spawn_wallet(bin, &dir, port, daemon);
        let rpc = client(port, WALLET_PASSWORD);
        wait_ready(&rpc, "get_version");
        Self {
            proc: Some(proc),
            port,
            dir,
            rpc,
        }
    }
}

/// The test schedule with 30 invoice blocks and 20 grace blocks and one access and trial position
/// per slot, re-signed with the test key.
fn regtest_schedule() -> (Schedule, KeyWindow) {
    let mut content = fixture::schedule().content().clone();
    content.constants.access_per_slot = 1;
    content.constants.trial_per_slot = 1;
    content.constants.invoice_blocks = 30;
    content.constants.grace_blocks = 20;
    let schedule = Schedule::verify_with_key(
        &fixture::sign_content(&content),
        &fixture::schedule_public_key(),
    )
    .unwrap();
    let mut keys = KeyWindow::new();
    for (_, signer) in fixture::signers(&schedule) {
        keys.insert(signer);
    }
    (schedule, keys)
}

fn request_for(label: &str) -> wire::RequestInvoiceRequest {
    wire::RequestInvoiceRequest {
        version: 1,
        rail: wire::Rail::Monero as i32,
        product: wire::Product::Pack as i32,
        claim_hash: batch::claim_hash(&claim_key(label)).to_vec(),
        credits: Vec::new(),
        base_week: BASE_WEEK,
    }
}

fn total(counters: &Counters, id: CounterId) -> u64 {
    counters
        .iter()
        .filter(|((c, _), _)| *c == id)
        .map(|(_, v)| *v)
        .sum()
}

fn hex32(text: &str) -> [u8; 32] {
    hex::decode(text).unwrap().try_into().unwrap()
}

#[derive(Clone)]
struct Invoice {
    label: String,
    id: [u8; 16],
    minor: u32,
    subaddress: String,
    grace_height: u64,
}

struct Regtest {
    issuer: Option<Issuer>,
    payer: Wallet,
    issuer_wallet: Wallet,
    treasury: Wallet,
    daemon: RpcClient,
    _daemon_proc: Proc,
    daemon_port: u16,
    bin: PathBuf,
    payer_address: String,
    treasury_address: String,
    view_key: String,
    restore_height: u64,
    schedule: Schedule,
    keys: KeyWindow,
    params: IssuerParams,
    /// Last: removed after every process is gone.
    dir: tempfile::TempDir,
}

impl Regtest {
    fn start() -> Self {
        let bin = bin_dir();
        let dir = tempfile::tempdir().unwrap();
        let (daemon_proc, daemon_port, daemon) = start_daemon(&bin, dir.path());
        let payer = Wallet::start(&bin, dir.path().join("payer"), Some(daemon_port));
        let issuer_wallet = Wallet::start(&bin, dir.path().join("issuer"), Some(daemon_port));
        let treasury = Wallet::start(&bin, dir.path().join("treasury"), None);
        let new_wallet = json!({"filename": "wallet", "password": "", "language": "English"});
        rpc(&payer.rpc, "create_wallet", new_wallet.clone());
        rpc(&treasury.rpc, "create_wallet", new_wallet);
        let address = |w: &Wallet| {
            rpc(&w.rpc, "get_address", json!({"account_index": 0}))["address"]
                .as_str()
                .unwrap()
                .to_string()
        };
        let payer_address = address(&payer);
        let treasury_address = address(&treasury);
        let view_key = rpc(&treasury.rpc, "query_key", json!({"key_type": "view_key"}))["key"]
            .as_str()
            .unwrap()
            .to_string();
        let restore_height = rpc(&daemon, "get_info", json!({}))["height"]
            .as_u64()
            .unwrap();
        let (schedule, keys) = regtest_schedule();
        let t = Self {
            issuer: None,
            payer,
            issuer_wallet,
            treasury,
            daemon,
            _daemon_proc: daemon_proc,
            daemon_port,
            bin,
            payer_address,
            treasury_address,
            view_key,
            restore_height,
            schedule,
            keys,
            params: IssuerParams {
                pool_target: 8,
                rate_per_sec: 1_000,
                rate_burst: 1_000,
                ..IssuerParams::default()
            },
            dir,
        };
        t.generate_view_wallet("issuer-view");
        t
    }

    /// `generate_from_keys` without a spend key (RM §3.1): a view-only wallet of the treasury, in
    /// the issuer's wallet process.
    fn generate_view_wallet(&self, filename: &str) {
        rpc(
            &self.issuer_wallet.rpc,
            "generate_from_keys",
            json!({
                "restore_height": self.restore_height,
                "filename": filename,
                "address": self.treasury_address,
                "viewkey": self.view_key,
                "password": "",
                "autosave_current": true,
            }),
        );
    }

    fn height(&self) -> u64 {
        rpc(&self.daemon, "get_info", json!({}))["height"]
            .as_u64()
            .unwrap()
    }

    fn mine(&self, n: u64) {
        let mut left = n;
        while left > 0 {
            let k = left.min(250);
            rpc(
                &self.daemon,
                "generateblocks",
                json!({"amount_of_blocks": k, "wallet_address": self.payer_address}),
            );
            left -= k;
        }
    }

    /// The production rail with the production time limits, over the issuer's wallet.
    fn rail(&self) -> MoneroWalletRpc {
        let credentials = |p: &str| Credentials::new(USER, p).unwrap();
        MoneroWalletRpc::new(
            RpcClient::new(
                endpoint(self.issuer_wallet.port),
                credentials(WALLET_PASSWORD),
                Timeouts::default(),
            )
            .unwrap(),
            RpcClient::new(
                endpoint(self.daemon_port),
                credentials(DAEMON_PASSWORD),
                Timeouts::default(),
            )
            .unwrap(),
        )
    }

    /// Opens (or, after a crash, reopens) the issuer over the same files.
    fn open_issuer(&mut self) {
        self.issuer = None;
        let ports = Ports {
            store: Box::new(RedbStore::open(&self.dir.path().join("issuer.redb")).unwrap()),
            journal: Box::new(FileJournal::open(&self.dir.path().join("journal")).unwrap()),
            rail: Box::new(self.rail()),
            random: Box::new(OsRandom::new()),
        };
        self.issuer = Some(
            Issuer::open(
                self.schedule.clone(),
                self.keys.clone(),
                ports,
                self.params,
                OpenMode::Normal,
                BASE,
            )
            .unwrap(),
        );
    }

    fn issuer(&self) -> &Issuer {
        self.issuer.as_ref().expect("issuer open")
    }

    fn tick(&self) -> TickReport {
        self.issuer()
            .scan_tick_at(BASE)
            .unwrap_or_else(|e| panic!("scanner tick: {e:?}"))
    }

    fn refill(&self) {
        self.issuer().pool_refill_at(BASE).unwrap();
    }

    fn request(&self, label: &str) -> Invoice {
        let r = self
            .issuer()
            .request_invoice_at(request_for(label), BASE)
            .unwrap();
        assert_eq!(r.result, wire::RequestInvoiceResult::Ok as i32, "{label}");
        assert_eq!(r.amount_atomic, PRICE, "the ES price");
        let address = MoneroAddress::parse(
            &r.subaddress,
            MoneroNetwork::Regtest,
            AddressPurpose::Invoice,
        )
        .expect("the wallet's subaddress validates for invoices");
        let id: [u8; 16] = r.invoice_id.as_slice().try_into().unwrap();
        let row = store::invoice(&*self.issuer().store().read().unwrap(), &id)
            .unwrap()
            .unwrap();
        Invoice {
            label: label.to_string(),
            id,
            minor: row.minor,
            subaddress: address.as_str().to_string(),
            grace_height: row.grace_height,
        }
    }

    fn blind_sign(&self, inv: &Invoice) -> wire::BlindSignResponse {
        let layout = Layout::pack(&self.schedule, BASE_WEEK, true).unwrap();
        let blinded = batch::blind(&self.schedule, &seed(&inv.label), &layout).unwrap();
        self.issuer()
            .blind_sign_at(
                wire::BlindSignRequest {
                    version: 1,
                    invoice_id: inv.id.to_vec(),
                    claim_key: claim_key(&inv.label).to_vec(),
                    blinded,
                },
                BASE,
            )
            .unwrap()
    }

    fn status(&self, inv: &Invoice) -> Result<wire::InvoiceStatusResponse, tonic::Status> {
        self.issuer().invoice_status_at(
            wire::InvoiceStatusRequest {
                version: 1,
                invoice_id: inv.id.to_vec(),
                claim_key: claim_key(&inv.label).to_vec(),
            },
            BASE,
        )
    }

    fn pay(&self, address: &str, amount: u64) -> String {
        self.pay_locked(address, amount, 0)
    }

    fn pay_locked(&self, address: &str, amount: u64, unlock_time: u64) -> String {
        rpc(&self.payer.rpc, "refresh", json!({}));
        let mut params = json!({
            "destinations": [{"amount": amount, "address": address}],
            "account_index": 0,
            "priority": 0,
            "ring_size": 16,
            "get_tx_key": false,
        });
        if unlock_time != 0 {
            params["unlock_time"] = json!(unlock_time);
        }
        rpc(&self.payer.rpc, "transfer", params)["tx_hash"]
            .as_str()
            .unwrap()
            .to_string()
    }

    fn counters(&self) -> Counters {
        reconcile::all(&*self.issuer().store().read().unwrap()).unwrap()
    }

    /// Stops the issuer's wallet process (the wallet saved) and starts it again on `daemon_port`.
    fn restart_issuer_wallet(&mut self, daemon_port: u16) {
        rpc(&self.issuer_wallet.rpc, "close_wallet", json!({}));
        self.issuer_wallet.proc = None;
        self.issuer_wallet.proc = Some(spawn_wallet(
            &self.bin,
            &self.issuer_wallet.dir,
            self.issuer_wallet.port,
            Some(daemon_port),
        ));
        wait_ready(&self.issuer_wallet.rpc, "get_version");
        rpc(
            &self.issuer_wallet.rpc,
            "open_wallet",
            json!({"filename": "issuer-view", "password": ""}),
        );
    }
}

#[test]
#[ignore = "needs the pinned monerod: GHOST_MONERO_BIN=<dir> (ghost/infra/issuer/monero-release.pin)"]
fn daemon_digest_authentication() {
    let bin = bin_dir();
    let dir = tempfile::tempdir().unwrap();
    let (_proc, port, daemon) = start_daemon(&bin, dir.path());
    // Twenty calls on one connection: `nc` counts on it (the server refuses a desynchronised one).
    for _ in 0..20 {
        let info = daemon.call("get_info", json!({})).unwrap();
        assert_eq!(info["status"], "OK");
        assert_eq!(info["nettype"], "fakechain");
        assert_eq!(
            info["synchronized"], true,
            "an offline regtest daemon reports itself synchronized"
        );
    }
    // An endpoint outside JSON-RPC: the digest covers its path.
    assert_eq!(
        daemon.post("/get_height", &json!({})).unwrap()["status"],
        "OK"
    );
    let before = daemon.call("get_info", json!({})).unwrap()["height"]
        .as_u64()
        .unwrap();
    rpc(
        &daemon,
        "generateblocks",
        json!({"amount_of_blocks": 5, "wallet_address": encode_address(18, 11, 12)}),
    );
    assert_eq!(
        daemon.call("get_info", json!({})).unwrap()["height"].as_u64(),
        Some(before + 5)
    );
    // Wrong credentials: Auth, on JSON-RPC and on a path.
    let wrong = client(port, "not-the-login");
    assert_eq!(wrong.call("get_info", json!({})), Err(RailError::Auth));
    assert_eq!(wrong.post("/get_height", &json!({})), Err(RailError::Auth));
    // The production rail with this daemon and no wallet: Transport, never a height.
    let rail = MoneroWalletRpc::new(
        client(free_port(), WALLET_PASSWORD),
        client(port, DAEMON_PASSWORD),
    );
    assert_eq!(rail.height(), Err(RailError::Transport));
}

#[test]
#[ignore = "needs the pinned Monero binaries: GHOST_MONERO_BIN=<dir> (ghost/infra/issuer/monero-release.pin)"]
fn regtest_scenario() {
    let mut t = Regtest::start();
    let rail = t.rail();

    // Step 1: the issuer's wallet is view-only; the check tells a full wallet apart.
    assert_eq!(rail.check_watch_only(), Ok(()));
    assert_eq!(
        rail.wallet()
            .call("sign_transfer", json!({"unsigned_txset": "00"})),
        Err(RailError::Rpc { code: -29 })
    );
    assert_eq!(rail.check_treasury(&t.treasury_address), Ok(()));
    assert_eq!(
        rail.check_treasury(&t.payer_address),
        Err(WalletCheckError::TreasuryMismatch)
    );
    let cold = MoneroWalletRpc::new(
        client(t.treasury.port, WALLET_PASSWORD),
        client(t.daemon_port, DAEMON_PASSWORD),
    );
    assert_eq!(cold.check_watch_only(), Err(WalletCheckError::NotWatchOnly));

    // Step 13: digest authentication with wrong credentials is Auth, at the wallet and the daemon.
    let wrong = MoneroWalletRpc::new(
        client(t.issuer_wallet.port, "not-the-login"),
        client(t.daemon_port, "not-the-login"),
    );
    assert_eq!(wrong.height(), Err(RailError::Auth));
    assert_eq!(
        wrong.daemon().call("get_info", json!({})),
        Err(RailError::Auth)
    );

    // Step 2: 80 blocks to the payer (a coinbase unlocks after 60).
    t.mine(80);
    rpc(&t.payer.rpc, "refresh", json!({}));
    let balance = rpc(&t.payer.rpc, "get_balance", json!({"account_index": 0}));
    assert!(balance["unlocked_balance"].as_u64().unwrap() > 20 * PRICE);
    let h = rail.height().unwrap();
    assert!(h.synced_view(), "{h:?}");

    t.open_issuer();
    t.refill();
    let pool = store::pool(&*t.issuer().store().read().unwrap()).unwrap();
    assert_eq!(pool.len(), 8);
    for (minor, text) in &pool {
        assert!(*minor >= 1, "minor 0 is never handed out");
        MoneroAddress::parse(
            std::str::from_utf8(text).unwrap(),
            MoneroNetwork::Regtest,
            AddressPurpose::Invoice,
        )
        .expect("a subaddress of the wallet validates");
    }
    t.tick();
    let mut paid_minors = Vec::new();

    // Step 3: happy path. Seen in the pool; still waiting at 9 confirmations; confirmed at
    // exactly 10; the second BlindSign re-serves the same bytes.
    let happy = t.request("happy");
    t.pay(&happy.subaddress, PRICE);
    t.tick();
    let s = t.blind_sign(&happy);
    assert_eq!(
        (s.state, s.credited_atomic, s.seen_atomic),
        (AWAITING_CONFIRMATIONS, 0, PRICE),
        "seen in the pool"
    );
    t.mine(CONFIRMATIONS - 1);
    t.tick();
    let s = t.blind_sign(&happy);
    assert_eq!(
        (s.state, s.credited_atomic, s.seen_atomic),
        (AWAITING_CONFIRMATIONS, 0, PRICE),
        "9 confirmations"
    );
    t.mine(1);
    t.tick();
    let first = t.blind_sign(&happy);
    assert_eq!((first.state, first.credited_atomic), (SIGNED, PRICE));
    let again = t.blind_sign(&happy);
    assert_eq!(
        again.blind_signatures, first.blind_signatures,
        "MS-1: the identical re-serve"
    );
    paid_minors.push(happy.minor);

    // Step 4: an underpayment stays UNDERPAID; the top-up to the same subaddress confirms.
    let under = t.request("under");
    t.pay(&under.subaddress, PRICE - 1);
    t.mine(CONFIRMATIONS);
    t.tick();
    let s = t.blind_sign(&under);
    assert_eq!((s.state, s.credited_atomic), (UNDERPAID, PRICE - 1));
    t.pay(&under.subaddress, 1);
    t.tick();
    assert_eq!(t.blind_sign(&under).state, AWAITING_CONFIRMATIONS);
    t.mine(CONFIRMATIONS);
    t.tick();
    let s = t.blind_sign(&under);
    assert_eq!((s.state, s.credited_atomic), (SIGNED, PRICE));
    paid_minors.push(under.minor);

    // Step 5: an overpayment confirms; the excess is counted only in aggregate (at the purge).
    let over = t.request("over");
    t.pay(&over.subaddress, PRICE + OVERPAID_BY);
    t.mine(CONFIRMATIONS);
    t.tick();
    let s = t.blind_sign(&over);
    assert_eq!((s.state, s.credited_atomic), (SIGNED, PRICE + OVERPAID_BY));
    paid_minors.push(over.minor);

    // Step 6: a payment with a lock time is neither credited nor seen.
    let locked = t.request("locked");
    let unlock = t.height() + 100;
    let locked_tx = t.pay_locked(&locked.subaddress, PRICE, unlock);
    t.mine(CONFIRMATIONS);
    t.tick();
    let entry = rail
        .transfer_by_txid(&hex32(&locked_tx))
        .unwrap()
        .expect("the issuer's wallet sees the locked transfer");
    assert_eq!(
        entry.unlock_time, unlock,
        "wallet-rpc made a locked transfer"
    );
    let s = t.blind_sign(&locked);
    assert_eq!(
        (s.state, s.credited_atomic, s.seen_atomic),
        (AWAITING_PAYMENT, 0, 0)
    );
    paid_minors.push(locked.minor);

    // Step 7: a payment mined above grace_height: the invoice expires (from a synced view), the
    // funds are unattributed revenue, and step 18's purge removes the mapping.
    let late = t.request("late");
    let next_block_index = t.height();
    t.mine((late.grace_height + 1).saturating_sub(next_block_index));
    assert!(t.height() > late.grace_height);
    let unattributed_before = total(&t.counters(), CounterId::UnattributedAtomic);
    t.pay(&late.subaddress, PRICE);
    t.mine(CONFIRMATIONS);
    t.tick();
    assert_eq!(t.blind_sign(&late).state, EXPIRED);
    assert_eq!(
        total(&t.counters(), CounterId::UnattributedAtomic),
        unattributed_before + PRICE
    );
    paid_minors.push(late.minor);

    // Step 8: a reorganisation below 10 confirmations reverts the payment; the invoice never
    // confirms.
    let reorg = t.request("reorg");
    t.pay(&reorg.subaddress, PRICE);
    t.mine(5);
    t.tick();
    assert_eq!(t.blind_sign(&reorg).seen_atomic, PRICE);
    let popped = t
        .daemon
        .post("/pop_blocks", &json!({"nblocks": 5}))
        .unwrap();
    assert_eq!(popped["status"], "OK");
    rpc(&t.daemon, "flush_txpool", json!({"txids": []}));
    t.mine(6);
    t.tick();
    let s = t.blind_sign(&reorg);
    assert_eq!(
        (s.state, s.credited_atomic, s.seen_atomic),
        (AWAITING_PAYMENT, 0, 0)
    );
    t.mine(CONFIRMATIONS);
    t.tick();
    assert_eq!(t.blind_sign(&reorg).state, AWAITING_PAYMENT);

    // Step 9: a restored wallet scans only minors below its lookahead (200 above the highest one
    // it received on). Without runbook R5's create_address replay the payment to invoice #240 is
    // missed (the negative control); with it, found.
    let mut batch_invoices = Vec::new();
    for i in 0..250 {
        t.refill();
        batch_invoices.push(t.request(&format!("batch-{i}")));
    }
    let target = batch_invoices[239].clone();
    let window = paid_minors.iter().max().unwrap() + 200;
    assert!(
        target.minor >= window,
        "invoice #240 (minor {}) lies beyond a restored wallet's lookahead ({window})",
        target.minor
    );
    t.pay(&target.subaddress, PRICE);
    t.mine(CONFIRMATIONS);
    t.tick();
    let s = t.status(&target).unwrap();
    assert_eq!(
        (s.state, s.credited_atomic),
        (AWAITING_CONFIRMATIONS, PRICE),
        "confirmed, not signed yet"
    );
    rpc(&t.issuer_wallet.rpc, "close_wallet", json!({}));
    for name in ["issuer-view", "issuer-view.keys"] {
        std::fs::remove_file(t.issuer_wallet.dir.join(name)).unwrap();
    }
    t.generate_view_wallet("issuer-view");
    t.tick();
    assert!(
        rail.transfers(t.restore_height, t.height())
            .unwrap()
            .iter()
            .all(|e| e.minor != target.minor),
        "negative control: the restored wallet misses #240"
    );
    let s = t.status(&target).unwrap();
    assert_eq!(
        (s.state, s.credited_atomic),
        (AWAITING_PAYMENT, 0),
        "negative control"
    );
    let highest = store::meta(&*t.issuer().store().read().unwrap(), MetaKey::HighestMinor)
        .unwrap()
        .unwrap();
    let count = rail
        .replay_subaddresses(u32::try_from(highest).unwrap())
        .unwrap();
    assert!(u64::from(count) > highest);
    rail.rescan().unwrap();
    t.tick();
    let s = t.status(&target).unwrap();
    assert_eq!(
        (s.state, s.credited_atomic),
        (AWAITING_CONFIRMATIONS, PRICE),
        "found after the replay"
    );
    assert_eq!(t.blind_sign(&target).state, SIGNED);

    // Step 10: the option-B payout. The workstation's own view wallet builds the transaction, the
    // offline treasury describes and signs it, the workstation submits it, the payee receives it.
    // One recipient; the change returns to the treasury's minor 0.
    rpc(&t.issuer_wallet.rpc, "close_wallet", json!({}));
    t.generate_view_wallet("workstation-view");
    let ws = &t.issuer_wallet.rpc;
    rpc(ws, "refresh", json!({}));
    let outputs = rpc(ws, "export_outputs", json!({"all": true}))["outputs_data_hex"].clone();
    let imported = rpc(
        &t.treasury.rpc,
        "import_outputs",
        json!({"outputs_data_hex": outputs}),
    );
    assert!(imported["num_imported"].as_u64().unwrap() > 0);
    let images = rpc(&t.treasury.rpc, "export_key_images", json!({"all": true}));
    rpc(
        ws,
        "import_key_images",
        json!({"offset": images["offset"], "signed_key_images": images["signed_key_images"]}),
    );
    let payee = rpc(&t.payer.rpc, "create_address", json!({"account_index": 0}))["address"]
        .as_str()
        .unwrap()
        .to_string();
    let unsigned = rpc(
        ws,
        "transfer",
        json!({
            "destinations": [{"amount": PAYOUT, "address": payee}],
            "account_index": 0,
            "priority": 0,
            "ring_size": 16,
            "get_tx_key": false,
        }),
    )["unsigned_txset"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(
        !unsigned.is_empty(),
        "a view-only wallet builds an unsigned transaction"
    );
    let desc = rpc(
        &t.treasury.rpc,
        "describe_transfer",
        json!({"unsigned_txset": unsigned}),
    );
    let d = &desc["desc"][0];
    assert_eq!(d["recipients"].as_array().unwrap().len(), 1);
    assert_eq!(d["recipients"][0]["address"], json!(payee));
    assert_eq!(d["recipients"][0]["amount"], json!(PAYOUT));
    assert_eq!(d["change_address"], json!(t.treasury_address));
    let signed = rpc(
        &t.treasury.rpc,
        "sign_transfer",
        json!({"unsigned_txset": unsigned, "export_raw": false, "get_tx_keys": false}),
    );
    let submitted = rpc(
        ws,
        "submit_transfer",
        json!({"tx_data_hex": signed["signed_txset"]}),
    );
    assert_eq!(submitted["tx_hash_list"], signed["tx_hash_list"]);
    let payout_tx = signed["tx_hash_list"][0].as_str().unwrap().to_string();
    t.mine(1);
    rpc(&t.payer.rpc, "refresh", json!({}));
    let received = rpc(
        &t.payer.rpc,
        "get_transfer_by_txid",
        json!({"txid": payout_tx}),
    )["transfer"]
        .clone();
    assert_eq!(received["type"], "in");
    assert_eq!(received["amount"], json!(PAYOUT));
    rpc(ws, "close_wallet", json!({}));
    rpc(
        &t.issuer_wallet.rpc,
        "open_wallet",
        json!({"filename": "issuer-view", "password": ""}),
    );
    t.mine(CONFIRMATIONS);
    t.tick();

    // Step 12: 1 000 verdicts of the Rust validator equal wallet-rpc's validate_address.
    differential(&t);

    // Step 17: an issuer restart after a pool refill whose create_address was never committed:
    // the startup reconciliation raises highest_minor above the burned minor, and no minor is
    // handed out twice.
    let (burned, _) = t.rail().new_address().unwrap();
    t.open_issuer();
    let report = t.issuer().pool_refill_at(BASE).unwrap();
    assert!(report.reconciled && report.added >= 1, "{report:?}");
    t.tick();
    let after = t.request("after-restart");
    {
        let tx = t.issuer().store().read().unwrap();
        let pool = store::pool(&*tx).unwrap();
        assert!(pool.iter().all(|(m, _)| *m != burned));
        assert!(
            pool.iter().any(|(m, _)| *m > burned),
            "refilled above the burned minor"
        );
        let minors: Vec<u32> = store::invoices(&*tx)
            .unwrap()
            .iter()
            .map(|(_, r)| r.minor)
            .collect();
        let distinct: BTreeSet<u32> = minors.iter().copied().collect();
        assert_eq!(distinct.len(), minors.len(), "no minor handed out twice");
        assert!(!distinct.contains(&burned));
        assert!(pool.iter().all(|(m, _)| !distinct.contains(m)));
    }
    assert_ne!(after.minor, burned);

    // Step 17b: the wallet lags the daemon (it cannot reach it): no synced tick, so a new XMR
    // invoice is UNAVAILABLE; once it follows the daemon again, the invoice is created.
    t.restart_issuer_wallet(free_port());
    t.mine(3);
    assert!(t.issuer().scan_tick_at(BASE).is_err());
    let wallet_height = rpc(&t.issuer_wallet.rpc, "get_height", json!({}))["height"]
        .as_u64()
        .unwrap();
    assert!(wallet_height + 1 < t.height(), "the wallet lags the daemon");
    t.refill();
    let refused = t
        .issuer()
        .request_invoice_at(request_for("lagging"), BASE)
        .unwrap_err();
    assert_eq!(refused.code(), Code::Unavailable);
    let daemon_port = t.daemon_port;
    t.restart_issuer_wallet(daemon_port);
    t.tick();
    let lagging = t.request("lagging");
    assert_ne!(lagging.minor, burned);

    // Step 18: everything open expires and everything expired or issued is purged; the counters
    // then satisfy the reconciliation invariants, the incoming value to minors >= 1 equals
    // credited + overpaid + unattributed, and the payout change to minor 0 is counted nowhere.
    let c = t.schedule.constants();
    t.mine(u64::from(c.invoice_blocks) + u64::from(c.grace_blocks) + CONFIRMATIONS + 1);
    t.tick();
    t.mine(5_041);
    t.tick();
    assert!(
        store::invoices(&*t.issuer().store().read().unwrap())
            .unwrap()
            .is_empty(),
        "every invoice purged"
    );
    assert_eq!(
        t.status(&late).unwrap_err().code(),
        Code::PermissionDenied,
        "the expired invoice's mapping is gone"
    );
    let counters = t.counters();
    assert_eq!(reconcile::check(&counters, &t.schedule, BASE), Vec::new());
    let credited = total(&counters, CounterId::XmrCreditedAtomic);
    let overpaid = total(&counters, CounterId::OverpaidAtomic);
    let unattributed = total(&counters, CounterId::UnattributedAtomic);
    assert_eq!(
        (credited, overpaid, unattributed),
        (4 * PRICE, OVERPAID_BY, PRICE)
    );
    let all_in = rpc(
        &t.issuer_wallet.rpc,
        "get_transfers",
        json!({"in": true, "account_index": 0}),
    );
    let entries = all_in["in"].as_array().unwrap();
    let minor = |e: &Value| e["subaddr_index"]["minor"].as_u64().unwrap();
    let incoming: u64 = entries
        .iter()
        .filter(|e| minor(e) >= 1 && e["unlock_time"] == 0 && e["double_spend_seen"] == false)
        .map(|e| e["amount"].as_u64().unwrap())
        .sum();
    assert_eq!(incoming, credited + overpaid + unattributed);
    assert!(
        entries.iter().any(|e| minor(e) == 0),
        "the payout change reached minor 0"
    );
    // RP §6.8: every field the issuer reads is in every entry of the real wallet.
    for e in entries {
        for f in TRANSFER_FIELDS {
            assert!(e.get(f).is_some(), "{f} missing in {e}");
        }
    }
}

/// A deterministic generator for the mutated addresses.
struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0 >> 33
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

/// Decodes, edits and re-encodes an address with a recomputed Keccak-256 checksum.
fn reencode(text: &str, edit: impl FnOnce(&mut [u8])) -> String {
    let mut data = base58_decode(text).expect("a valid address");
    edit(&mut data);
    let n = data.len() - 4;
    let check = Keccak256::digest(&data[..n]);
    data[n..].copy_from_slice(&check[..4]);
    base58_encode(&data)
}

/// Step 12 (§7.7, RM §7.1): the payer's subaddresses, both primary addresses and the pool's
/// subaddresses, each with five mutations (a character replaced, another network byte, a random
/// spend key, truncated, extended), and integrated addresses. The Rust validator accepts an
/// address for a payout exactly when wallet-rpc calls it valid and not integrated, and agrees on
/// its type and network.
fn differential(t: &Regtest) {
    const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let payer = &t.payer.rpc;
    let mut rng = Lcg(0x9e37_79b9_7f4a_7c15);
    let created = rpc(
        payer,
        "create_address",
        json!({"account_index": 0, "count": 150}),
    );
    let mut bases: Vec<String> = created["addresses"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a.as_str().unwrap().to_string())
        .collect();
    bases.push(t.payer_address.clone());
    bases.push(t.treasury_address.clone());
    bases.extend(
        store::pool(&*t.issuer().store().read().unwrap())
            .unwrap()
            .iter()
            .map(|(_, a)| String::from_utf8(a.to_vec()).unwrap()),
    );
    let mut cases = Vec::new();
    for (i, base) in bases.iter().enumerate() {
        cases.push(base.clone());
        let mut flipped = base.clone().into_bytes();
        let p = rng.below(flipped.len());
        let old = flipped[p];
        while flipped[p] == old {
            flipped[p] = ALPHABET[rng.below(ALPHABET.len())];
        }
        cases.push(String::from_utf8(flipped).unwrap());
        let prefix = [18u8, 19, 24, 25, 36, 42, 53, 63, 99][i % 9];
        cases.push(reencode(base, |d| d[0] = prefix));
        cases.push(reencode(base, |d| {
            for b in &mut d[1..33] {
                *b = rng.next() as u8;
            }
        }));
        cases.push(base[..base.len() - 1].to_string());
        cases.push(format!("{base}1"));
    }
    for _ in 0..60 {
        let integrated = rpc(
            payer,
            "make_integrated_address",
            json!({"standard_address": t.payer_address}),
        );
        cases.push(
            integrated["integrated_address"]
                .as_str()
                .unwrap()
                .to_string(),
        );
    }
    assert!(cases.len() >= 1_000, "{} cases", cases.len());
    let (mut accepted, mut refused) = (0, 0);
    for a in &cases {
        let answer = rpc(
            payer,
            "validate_address",
            json!({"address": a, "any_net_type": false}),
        );
        let wallet_accepts = answer["valid"] == true && answer["integrated"] == false;
        let ours = MoneroAddress::parse(a, MoneroNetwork::Regtest, AddressPurpose::Payout);
        assert_eq!(
            ours.is_ok(),
            wallet_accepts,
            "{a}: wallet {answer}, ours {ours:?}"
        );
        match ours {
            Ok(address) => {
                accepted += 1;
                assert_eq!(
                    address.kind() == AddressType::Subaddress,
                    answer["subaddress"] == true,
                    "{a}"
                );
                assert_eq!(answer["nettype"], "mainnet", "{a}");
            }
            Err(_) => refused += 1,
        }
    }
    assert!(
        accepted >= 150 && refused >= 500,
        "{accepted} accepted, {refused} refused"
    );
}
