//! The `ghost-issuer` process (Phase 8 design §5.1, §5.9, §6.2, §6.5–§6.7; ADR-26):
//!
//! ```text
//! ghost-issuer --config <file> [--restore]
//! ```
//!
//! **Startup** refuses to run on the first failure, in this order (§6.6): the configuration
//! ([`crate::config`]); the Entitlement Schedule under the pinned schedule key and its network
//! against the configuration; the key load (every held key is its ES entry); the wallet (both
//! login files, `query_key spend_key` must fail with −29, the primary address must be the
//! treasury); the database and the journal (ES rule 5 against `es_memory`, journal replay without
//! a gap; `--restore` is runbook B1: the address pool is emptied after the replay); the treasury
//! restore height against the one recorded in `meta` (recorded at the first start). The wallet is
//! checked before the database is opened, so a refused start writes nothing.
//!
//! **Serving.** The gRPC listener binds a loopback address only; the onion service forwards to it
//! (§6.7). Before the first request the pool is refilled, the scanner ticks once and `status.json`
//! is written. Periodic jobs run on the blocking pool with `now` from the injected clock: the
//! scanner every `scan_interval_seconds` ± 10 s (independent of client calls, §7.3), the pool
//! refill every 60 s, the sweep (closed epochs, retention, key destruction) hourly and the status
//! file every 60 s. A job's failure is visible in `status.json` (the scanner's outcome, the pool
//! size, a halt) and retried at its next run. `RefreshCredit` (§19.8) is served from slice S6 on;
//! until then it answers `UNIMPLEMENTED`, which the client treats as transient (§5.7).
//!
//! **Exit status.** The issuer keeps no logs and prints nothing (ADR-26): a refusal is its exit
//! status, and a running issuer reports through `status.json`.
//!
//! | status | refusal |
//! |---|---|
//! | 1 | the listener or the gRPC server failed |
//! | 2 | usage, or the configuration file |
//! | 3 | the Entitlement Schedule: its signature, its network, rule 5 against the database's memory |
//! | 4 | the keys: the load file, a sealed file, a key that is not its ES entry |
//! | 5 | the wallet: a login file, unreachable, not watch-only, primary address not the treasury |
//! | 6 | the state: database, journal, replay, restore height other than the recorded one |

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use ghost_entitlement::Schedule;
use ghost_issuer_api::proto as wire;
use ghost_issuer_api::proto::issuer_service_server::{IssuerService, IssuerServiceServer};
use ring::rand::{SecureRandom, SystemRandom};
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::{Request, Response, Status};

use crate::config::Config;
use crate::custody::{KeyWindow, SealLoad};
use crate::journal::FileJournal;
use crate::quantum::{wall_clock, Clock, ReplyQuantum, TimedIssuer};
use crate::rail::digest::Credentials;
use crate::rail::monero::{MoneroWalletRpc, RpcClient, Timeouts};
use crate::rail::PaymentRail;
use crate::service::{Issuer, OpenMode, OsRandom, Ports, StartupError};
use crate::status::{self, STATUS_FILE_NAME};
use crate::store::{self, MetaKey, RedbStore};

/// The database file in `data_dir`.
pub const DATABASE_FILE_NAME: &str = "issuer.redb";
/// The journal directory in `data_dir`.
pub const JOURNAL_DIR_NAME: &str = "journal";
/// The scanner period's jitter (§7.3: every 30 s ± 10 s).
pub const SCAN_JITTER: Duration = Duration::from_secs(10);
/// The pool refill period (§7.2).
pub const REFILL_INTERVAL: Duration = Duration::from_secs(60);
/// The sweep period (closed epochs, retention, key destruction K4).
pub const SWEEP_INTERVAL: Duration = Duration::from_secs(3_600);
/// The status file period (§6.5).
pub const STATUS_INTERVAL: Duration = Duration::from_secs(60);
/// tonic's decoding bound (§5.9): the largest `BlindSign` is 2 563 × 256 bytes ≈ 641 KiB.
pub const MAX_MESSAGE_BYTES: usize = 1 << 20;

/// Why the process refused to start or stopped; the exit status names the class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Refusal {
    Serve,
    Usage,
    Config,
    Schedule,
    Keys,
    Wallet,
    State,
}

impl Refusal {
    pub fn exit_code(self) -> u8 {
        match self {
            Refusal::Serve => 1,
            Refusal::Usage | Refusal::Config => 2,
            Refusal::Schedule => 3,
            Refusal::Keys => 4,
            Refusal::Wallet => 5,
            Refusal::State => 6,
        }
    }
}

/// The command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invocation {
    pub config: PathBuf,
    pub mode: OpenMode,
}

/// `--config <file>` exactly once, `--restore` at most once, nothing else.
pub fn parse_args(args: &[String]) -> Result<Invocation, Refusal> {
    let mut config = None;
    let mut mode = OpenMode::Normal;
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--config" if config.is_none() => {
                config = Some(PathBuf::from(it.next().ok_or(Refusal::Usage)?));
            }
            "--restore" if mode == OpenMode::Normal => mode = OpenMode::Restore,
            _ => return Err(Refusal::Usage),
        }
    }
    Ok(Invocation {
        config: config.ok_or(Refusal::Usage)?,
        mode,
    })
}

pub fn load_config(path: &Path) -> Result<Config, Refusal> {
    let text = std::fs::read_to_string(path).map_err(|_| Refusal::Config)?;
    Config::parse(&text).map_err(|_| Refusal::Config)
}

/// The schedule file under the pinned schedule key, on the configured network.
pub fn load_schedule(config: &Config) -> Result<Schedule, Refusal> {
    let bytes = std::fs::read(&config.schedule_file).map_err(|_| Refusal::Schedule)?;
    let schedule = Schedule::verify(&bytes).map_err(|_| Refusal::Schedule)?;
    check_network(config, &schedule)?;
    Ok(schedule)
}

/// `network` must equal the schedule's network (§6.6).
pub fn check_network(config: &Config, schedule: &Schedule) -> Result<(), Refusal> {
    if schedule.network() == config.network {
        Ok(())
    } else {
        Err(Refusal::Schedule)
    }
}

/// Runbook K3: the load file's `k_seal` values open the sealed files of `sealed_keys_dir`, each
/// proven to be its ES key.
pub fn load_keys(config: &Config, schedule: &Schedule) -> Result<KeyWindow, Refusal> {
    let bytes = std::fs::read(&config.key_load_file).map_err(|_| Refusal::Keys)?;
    let load = SealLoad::parse(&bytes).map_err(|_| Refusal::Keys)?;
    KeyWindow::load(schedule, &load, &config.sealed_keys_dir).map_err(|_| Refusal::Keys)
}

fn read_login(path: &Path) -> Result<Credentials, Refusal> {
    let text = std::fs::read_to_string(path).map_err(|_| Refusal::Wallet)?;
    Credentials::parse_login(&text).map_err(|_| Refusal::Wallet)
}

/// The wallet and daemon clients, after the §6.6 checks: watch-only, primary address = treasury.
pub fn connect_wallet(config: &Config) -> Result<MoneroWalletRpc, Refusal> {
    let wallet = RpcClient::new(
        config.wallet_rpc,
        read_login(&config.wallet_rpc_login_file)?,
        Timeouts::default(),
    )
    .map_err(|_| Refusal::Wallet)?;
    let daemon = RpcClient::new(
        config.daemon_rpc,
        read_login(&config.daemon_rpc_login_file)?,
        Timeouts::default(),
    )
    .map_err(|_| Refusal::Wallet)?;
    let rail = MoneroWalletRpc::new(wallet, daemon);
    rail.check_watch_only().map_err(|_| Refusal::Wallet)?;
    rail.check_treasury(config.treasury_address.as_str())
        .map_err(|_| Refusal::Wallet)?;
    Ok(rail)
}

/// Opens `issuer.redb` and the journal in `data_dir` and starts the issuer over `rail`.
pub fn open_issuer(
    config: &Config,
    schedule: Schedule,
    keys: KeyWindow,
    rail: Box<dyn PaymentRail>,
    mode: OpenMode,
    now: u64,
) -> Result<Issuer, Refusal> {
    let store =
        RedbStore::open(&config.data_dir.join(DATABASE_FILE_NAME)).map_err(|_| Refusal::State)?;
    let journal =
        FileJournal::open(&config.data_dir.join(JOURNAL_DIR_NAME)).map_err(|_| Refusal::State)?;
    let ports = Ports {
        store: Box::new(store),
        journal: Box::new(journal),
        rail,
        random: Box::new(OsRandom::new()),
    };
    Issuer::open(schedule, keys, ports, config.params(), mode, now).map_err(|e| match e {
        StartupError::Schedule(_) => Refusal::Schedule,
        StartupError::Keys(_) => Refusal::Keys,
        StartupError::Store(_) | StartupError::Journal(_) | StartupError::Replay(_) => {
            Refusal::State
        }
    })
}

/// Records the treasury's restore height in `meta` at the first start; a later start with another
/// one is refused (runbook R5 restores with the original height).
pub fn record_restore_height(issuer: &Issuer, height: u64) -> Result<(), Refusal> {
    let mut tx = issuer.store().write().map_err(|_| Refusal::State)?;
    match store::meta(&*tx, MetaKey::RestoreHeight).map_err(|_| Refusal::State)? {
        Some(recorded) if recorded == height => Ok(()),
        Some(_) => Err(Refusal::State),
        None => {
            store::set_meta(&mut *tx, MetaKey::RestoreHeight, height)
                .map_err(|_| Refusal::State)?;
            tx.commit().map_err(|_| Refusal::State)
        }
    }
}

/// How the server runs its jobs and answers.
#[derive(Debug, Clone)]
pub struct ServeSettings {
    pub quantum: ReplyQuantum,
    /// Concurrent signing calls (§5.9: the core count).
    pub signing_permits: usize,
    pub scan_interval: Duration,
    pub scan_jitter: Duration,
    pub refill_interval: Duration,
    pub sweep_interval: Duration,
    pub status_interval: Duration,
    pub status_file: PathBuf,
}

impl ServeSettings {
    pub fn from_config(config: &Config) -> Self {
        Self {
            quantum: ReplyQuantum::new(config.reply_quantum),
            signing_permits: std::thread::available_parallelism().map_or(1, |n| n.get()),
            scan_interval: config.scan_interval,
            scan_jitter: SCAN_JITTER,
            refill_interval: REFILL_INTERVAL,
            sweep_interval: SWEEP_INTERVAL,
            status_interval: STATUS_INTERVAL,
            status_file: config.data_dir.join(STATUS_FILE_NAME),
        }
    }
}

/// One periodic job.
enum Job {
    Scan,
    Refill,
    Sweep,
    Status(PathBuf),
}

fn work(issuer: &Issuer, job: &Job, now: u64) {
    // Outcomes reach the operator through status.json and the next run retries.
    match job {
        Job::Scan => {
            let _ = issuer.scan_tick_at(now);
        }
        Job::Refill => {
            let _ = issuer.pool_refill_at(now);
        }
        Job::Sweep => {
            let _ = issuer.sweep_at(now);
        }
        Job::Status(path) => {
            if let Ok(report) = issuer.status_at(now) {
                let _ = status::write_status_file(path, &report);
            }
        }
    }
}

/// Runs a job on the blocking pool (redb, signing and the rail are synchronous).
async fn run_job(issuer: &Arc<Issuer>, clock: &Clock, job: &Arc<Job>) {
    let (issuer, clock, job) = (Arc::clone(issuer), Arc::clone(clock), Arc::clone(job));
    let _ = tokio::task::spawn_blocking(move || work(&issuer, &job, clock())).await;
}

fn spawn_job(issuer: &Arc<Issuer>, clock: &Clock, job: Job, period: Duration, jitter: Duration) {
    let (issuer, clock, job) = (Arc::clone(issuer), Arc::clone(clock), Arc::new(job));
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(jittered(period, jitter)).await;
            run_job(&issuer, &clock, &job).await;
        }
    });
}

/// `period − jitter + U[0, 2·jitter]` (whole milliseconds), from the operating system's random
/// source; the bare period if it fails.
fn jittered(period: Duration, jitter: Duration) -> Duration {
    let span = u64::try_from(jitter.as_millis())
        .unwrap_or(u64::MAX / 4)
        .saturating_mul(2);
    let mut bytes = [0u8; 8];
    if span == 0 || SystemRandom::new().fill(&mut bytes).is_err() {
        return period;
    }
    let offset = u64::from_le_bytes(bytes) % (span + 1);
    period.saturating_sub(jitter) + Duration::from_millis(offset)
}

/// The gRPC service over the wall-clock facade.
pub struct IssuerGrpc(TimedIssuer);

impl IssuerGrpc {
    pub fn new(timed: TimedIssuer) -> Self {
        Self(timed)
    }
}

#[tonic::async_trait]
impl IssuerService for IssuerGrpc {
    async fn request_invoice(
        &self,
        request: Request<wire::RequestInvoiceRequest>,
    ) -> Result<Response<wire::RequestInvoiceResponse>, Status> {
        self.0
            .request_invoice(request.into_inner())
            .await
            .map(Response::new)
    }

    async fn blind_sign(
        &self,
        request: Request<wire::BlindSignRequest>,
    ) -> Result<Response<wire::BlindSignResponse>, Status> {
        self.0
            .blind_sign(request.into_inner())
            .await
            .map(Response::new)
    }

    async fn invoice_status(
        &self,
        request: Request<wire::InvoiceStatusRequest>,
    ) -> Result<Response<wire::InvoiceStatusResponse>, Status> {
        self.0
            .invoice_status(request.into_inner())
            .await
            .map(Response::new)
    }

    async fn redeem_invite(
        &self,
        request: Request<wire::RedeemInviteRequest>,
    ) -> Result<Response<wire::RedeemInviteResponse>, Status> {
        self.0
            .redeem_invite(request.into_inner())
            .await
            .map(Response::new)
    }

    async fn claim_payout(
        &self,
        request: Request<wire::ClaimPayoutRequest>,
    ) -> Result<Response<wire::ClaimPayoutResponse>, Status> {
        self.0
            .claim_payout(request.into_inner())
            .await
            .map(Response::new)
    }

    async fn refresh_credit(
        &self,
        _request: Request<wire::RefreshCreditRequest>,
    ) -> Result<Response<wire::RefreshCreditResponse>, Status> {
        // Slice S6 (§19.8, §15.1). A constant message, as every issuer status.
        Err(Status::unimplemented("unimplemented"))
    }
}

/// Serves on `listener` (a loopback address) until the server fails: first one pool refill, one
/// scanner tick and the first status file, then the periodic jobs and the gRPC service.
pub async fn serve(
    issuer: Arc<Issuer>,
    listener: TcpListener,
    settings: ServeSettings,
    clock: Clock,
) -> Result<(), Refusal> {
    let local = listener.local_addr().map_err(|_| Refusal::Serve)?;
    if !local.ip().is_loopback() {
        return Err(Refusal::Config);
    }
    for job in [
        Job::Refill,
        Job::Scan,
        Job::Status(settings.status_file.clone()),
    ] {
        run_job(&issuer, &clock, &Arc::new(job)).await;
    }
    spawn_job(
        &issuer,
        &clock,
        Job::Scan,
        settings.scan_interval,
        settings.scan_jitter,
    );
    spawn_job(
        &issuer,
        &clock,
        Job::Refill,
        settings.refill_interval,
        Duration::ZERO,
    );
    spawn_job(
        &issuer,
        &clock,
        Job::Sweep,
        settings.sweep_interval,
        Duration::ZERO,
    );
    spawn_job(
        &issuer,
        &clock,
        Job::Status(settings.status_file.clone()),
        settings.status_interval,
        Duration::ZERO,
    );
    let timed = TimedIssuer::with_clock(issuer, settings.quantum, settings.signing_permits, clock);
    let service = IssuerServiceServer::new(IssuerGrpc::new(timed))
        .max_decoding_message_size(MAX_MESSAGE_BYTES);
    tonic::transport::Server::builder()
        .add_service(service)
        .serve_with_incoming(TcpListenerStream::new(listener))
        .await
        .map_err(|_| Refusal::Serve)
}

fn run(args: &[String]) -> Result<(), Refusal> {
    let invocation = parse_args(args)?;
    let config = load_config(&invocation.config)?;
    let clock = wall_clock();
    let schedule = load_schedule(&config)?;
    let keys = load_keys(&config, &schedule)?;
    // The rail blocks on its own runtime: every startup call happens here, outside the server's.
    let rail = connect_wallet(&config)?;
    let issuer = open_issuer(
        &config,
        schedule,
        keys,
        Box::new(rail),
        invocation.mode,
        clock(),
    )?;
    record_restore_height(&issuer, config.restore_height)?;
    let settings = ServeSettings::from_config(&config);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|_| Refusal::Serve)?;
    runtime.block_on(async move {
        let listener = TcpListener::bind(config.listen)
            .await
            .map_err(|_| Refusal::Serve)?;
        serve(Arc::new(issuer), listener, settings, clock).await
    })
}

/// The process: runs until the server fails; the exit status names a refusal.
pub fn run_cli(args: &[String]) -> ExitCode {
    match run(args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(refusal) => ExitCode::from(refusal.exit_code()),
    }
}
