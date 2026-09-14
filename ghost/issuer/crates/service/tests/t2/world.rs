//! The T2 world (Phase 8 design §13.4 "World", §19.16): the real issuer (`Issuer::*_at` on the real
//! redb store and journal, the wallet of [`super::chain`]), three real relays (`Relay::*_at`
//! including `redeem_at`, capture on) and the reference clients of the population, driven by one
//! discrete-event loop on a virtual clock. Every call is recorded in the views ([`super::views`]).
//!
//! **Clients.** A periodic job every 15 minutes with a Doze-like mixture (a slot runs with the
//! client's probability while its user is awake, about every 3 hours while asleep); each run
//! independently draws **quiet** with q = 1/8 from a per-process PRF of the job index (§12.2,
//! §19.23 point 1), whether or not entitlement work is due. A quiet run touches no relay and makes
//! at most one issuer call (the most overdue item, `policy::pick`); a normal run is a background
//! relay session: its lanes sync every pair with a usable capability, on the pair's own circuit,
//! and the redeem lane's first step (`policy::plan`, §12.4) comes at READY + U[0, 30 s]; the step
//! runs if the lanes still run then or if the Q29 redeem hold, armed by the pending write needs at
//! the session's start, keeps the session open for it (E30, measured and reported). Foreground
//! sessions are drawn per user and day and redeem as each pair comes; onboarding, purchases,
//! payments (70 % from the payment screen, which closes the relay session and holds sessions off
//! for U[20, 60] min; 30 % during a relay session, §19.11), claims and writes are user actions
//! there. Issuer-facing decisions use the device wall clock only; relay-facing ones the
//! relay-corrected estimate (§19.4). A credit read from a drop is refreshed at one of the two times
//! its invite drew when the inviter started listening, never at a time the read sets (Q31, §19.26).

use std::cmp::Reverse;
use std::collections::{BTreeMap, BinaryHeap, HashSet};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use ghost_client_net::entitlement::Product;
use ghost_client_net::issuer_client::IssuerError;
use ghost_client_net::issuer_flow;
use ghost_client_net::namespace_client::redeem_with;
use ghost_client_net::{OnionAddress, RelayError};
use ghost_entitlement::batch::{self, Layout};
use ghost_entitlement::grid::{invite_epoch, week, week_start};
use ghost_entitlement::onion::Onion;
use ghost_entitlement::token::{self as tok, AUTHENTICATOR_LEN};
use ghost_entitlement::{Kind, Schedule, Token};
use ghost_issuer::custody::KeyWindow;
use ghost_issuer::journal::FileJournal;
use ghost_issuer::payout::{self, AckFile, BatchFile, EntryOutcome};
use ghost_issuer::service::{Issuer, IssuerParams, OpenMode, Ports, Random, RandomError};
use ghost_issuer::signer::{ReferenceSigner, Signer};
use ghost_issuer::store::{RedbStore, Table};
use ghost_issuer_api::proto as wire;
use ghost_relay_api::proto as rw;
use ghost_relay_capability::RelayKey;
use ghost_relay_node::{EntitlementPolicy, NullifierMode, RedeemRate, Relay, RelayConfig};
use ghost_t2_join::accumulate::Accumulator;
use ghost_t2_join::model::{
    ClientKind, ClientTruth, FlowKind, InvoiceTruth, IssuerTruth, PayMode, RelayTruth, Run, Truth,
    WalletCall, WalletEntry,
};
use sha2::{Digest, Sha256};

use super::chain::{ChainHandle, T2Chain};
use super::client::{
    Cap, ClaimFlow, Client, DropListen, DropOut, HeldCredit, HeldInvite, HeldToken, PState,
    Purchase, Received, Trial,
};
use super::config::{Config, Mutant};
use super::es;
use super::policy::{
    self, Decision, NeedKind, NeedReason, ReserveStep, SlotRow, WorkKind, DAY, HOUR,
};
use super::population::{self, ClientSpec, Spend, Timeline};
use super::rng::{derive32, prf_unit, Rng};
use super::transport::{self, IssuerFault, IssuerLink, Liar, RelayLink, RelayNode};
use super::views::Recorder;

const Q: f64 = 1.0 / 8.0;
const SLOT_SECS: u64 = 900;
const BLOB: usize = 1_024;
const LATENCY: u64 = 2;

/// What a world reports besides its views.
#[derive(Default, Debug, Clone)]
pub struct Log {
    /// Every `BlindSign` attempt: (client, flow, attempt, answered state or -1).
    pub sign_outcomes: Vec<(u32, u64, usize, i32)>,
    /// Need-triggered purchase starts (client, foreground start, device not-before).
    pub need_starts: Vec<(u32, u64, i64)>,
    /// Received credits: (inviter, invitee, true read time, refresh due device time).
    pub receipts: Vec<(u32, u32, u64, i64)>,
    /// Invite revocations answered with spare tokens: (client, flow, true answer time, device time
    /// the spares become eligible).
    pub revocations: Vec<(u32, u64, u64, i64)>,
    /// Background sessions the redeem hold kept open past their lanes (Q29, E30): (client, end of
    /// the lanes, end of the redeem lane's first step, redemptions in that step).
    pub holds: Vec<(u32, u64, u64, u32)>,
    /// Invites handed over: (inviter, the pack flow that produced the invite, invitee, time).
    pub takes: Vec<(u32, u64, u32, u64)>,
    /// Invites handed out: (inviter, the pack flow that produced the invite).
    pub given_invites: Vec<(u32, u64)>,
    /// First-pack-of-invitee flows (client, flow).
    pub first_packs: Vec<(u32, u64)>,
    pub counts: BTreeMap<&'static str, u64>,
    /// Wall-clock seconds spent per event kind (the budget measurement).
    pub timings: BTreeMap<&'static str, f64>,
    /// Requests the issuer's endpoint received, counted at the entry of each handler call (never
    /// by the recorder): the completeness check compares the issuer view with it.
    pub issuer_received: u64,
    /// Capture events the three relays wrote (one per handler call), counted in their capture
    /// files at the end: the completeness check compares the relay views with it.
    pub capture_lines: u64,
}

impl Log {
    fn count(&mut self, key: &'static str) {
        *self.counts.entry(key).or_insert(0) += 1;
    }
}

pub struct Outcome {
    pub name: String,
    pub rec: Recorder,
    pub truth: Truth,
    pub log: Log,
    pub seconds: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Event {
    Join(usize),
    Day(usize),
    Job(usize),
    Foreground(usize, u64),
    ForegroundSync(usize),
    Pay(usize, usize),
    IssuerDaily,
    IssuerWeekly,
    RelayDaily,
    RelayWeekly,
    RelayRestart(u8),
    Snapshot,
    Restore,
    End,
}

/// The issuer's random port: a seeded stream (issuer randomness of the world).
struct SeededRandom(Arc<Mutex<Rng>>);

impl Random for SeededRandom {
    fn fill(&self, out: &mut [u8]) -> Result<(), RandomError> {
        self.0.lock().unwrap().fill(out);
        Ok(())
    }
}

/// The rogue keys of mutant M2 (keys of the crash-suite schedule, which the T2 ES does not list).
fn rogue_signers() -> Vec<(ReferenceSigner, ghost_blind_rsa::PublicKey)> {
    let s = crate::common::fixture::schedule();
    let text =
        std::fs::read_to_string(crate::common::fixture::dir().join("test_keys.txt")).unwrap();
    text.lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .take(4)
        .map(|line| {
            let f: Vec<&str> = line.split(' ').collect();
            let kind = Kind::from_byte(f[0].parse().unwrap()).unwrap();
            let epoch: u64 = f[1].parse().unwrap();
            let signer =
                ReferenceSigner::from_pkcs8_der(kind, epoch, &hex::decode(f[2]).unwrap()).unwrap();
            (signer, s.key(kind, epoch).unwrap().public_key.clone())
        })
        .collect()
}

pub struct World {
    cfg: Config,
    tl: Timeline,
    schedule: &'static Schedule,
    slots: Vec<SlotRow>,
    dir: tempfile::TempDir,
    issuer: Option<Issuer>,
    window: KeyWindow,
    chain: Arc<T2Chain>,
    issuer_random: Arc<Mutex<Rng>>,
    relays: Vec<RelayNode>,
    relay_clock: Arc<AtomicU64>,
    clients: Vec<Client>,
    sched: Vec<Rng>,
    rec: Recorder,
    truth: Truth,
    log: Log,
    queue: BinaryHeap<Reverse<(u64, u64, Event)>>,
    seq: u64,
    now: u64,
    last_tick: u64,
    invite_pool: Vec<(usize, usize)>,
    liar: Liar,
    rogue: Vec<(ReferenceSigner, ghost_blind_rsa::PublicKey)>,
    issuer_rng: Rng,
    chain_rng: Rng,
    /// Drop blobs in flight: (drop namespace, blob hash) → the credit it carries.
    drop_blobs: BTreeMap<([u8; 32], Vec<u8>), Option<Token>>,
    /// Pending "pay during the next session" payments per client.
    session_pay: Vec<Vec<usize>>,
    processes: u64,
    /// Requests the issuer's endpoint received (the links count them at each handler's entry).
    issuer_received: u64,
    /// Every credit a world client finalized (a pack's credit or a refresh): the credits a
    /// scripted spend may present (§19.16 point 1).
    minted: HashSet<Vec<u8>>,
}

/// The credits of a scripted spend that no issuer of the world minted (design §19.16 point 1: every
/// scripted spend uses protocol-issued credits, a harness assertion).
pub fn unminted<'a>(
    minted: &HashSet<Vec<u8>>,
    credits: impl IntoIterator<Item = &'a [u8]>,
) -> usize {
    credits.into_iter().filter(|c| !minted.contains(*c)).count()
}

fn onion_pubkey(text: &str) -> [u8; 32] {
    Onion::parse(text).unwrap().pubkey
}

impl World {
    pub fn new(cfg: Config, cache: &Arc<es::SignCache>) -> Self {
        let schedule = es::schedule();
        let tl = Timeline::of(cfg.scale);
        let dir = tempfile::Builder::new()
            .prefix("ghost-t2-")
            .tempdir_in(
                std::env::var("GHOST_T2_TMP").map_or_else(|_| std::env::temp_dir(), Into::into),
            )
            .unwrap();
        let slots: Vec<SlotRow> = schedule
            .content()
            .slots
            .iter()
            .map(|s| {
                let o = Onion::parse(&s.onion).unwrap();
                SlotRow {
                    slot: s.slot,
                    from: s.valid_from_week as i64,
                    until: s.valid_until_week as i64,
                    onion: policy::Onion {
                        key: o.pubkey,
                        port: o.port,
                    },
                }
            })
            .collect();
        let chain = T2Chain::new(tl.t0 - 7 * DAY as u64, cfg.seeds.chain);
        let acc = cfg.analyze.then(|| {
            let public =
                ghost_t2_join::public::public_context(schedule, &[es::schedule_bytes().to_vec()]);
            Accumulator::new(schedule.clone(), public)
        });
        let rec = Recorder::new(acc, cfg.export.clone(), cfg.per_client);
        let specs = population::population(cfg.scale, cfg.seeds.user);
        let clients: Vec<Client> = specs
            .into_iter()
            .enumerate()
            .map(|(i, s)| Client::new(i as u32, s, &cfg.seeds))
            .collect();
        let sched = clients
            .iter()
            .map(|c| Rng::new(cfg.seeds.sched, &[b"client", &c.id.to_be_bytes(), b"jobs"]))
            .collect();
        let truth = Truth {
            clients: clients
                .iter()
                .map(|c| ClientTruth {
                    kind: c.spec.kind,
                    namespaces: 0,
                    user_calls: Vec::new(),
                    scripted: Vec::new(),
                    runs: Vec::new(),
                    skew: c
                        .spec
                        .skew
                        .map(|(o, until)| vec![(c.spec.join, until, o)])
                        .unwrap_or_default(),
                    processes: Vec::new(),
                })
                .collect(),
            window: (tl.tw, tl.te),
            ..Truth::default()
        };
        let relay_clock = Arc::new(AtomicU64::new(tl.t0));
        let n = clients.len();
        let mut w = World {
            issuer_random: Arc::new(Mutex::new(Rng::new(cfg.seeds.issuer, &[b"issuer"]))),
            issuer_rng: Rng::new(cfg.seeds.issuer, &[b"latency"]),
            chain_rng: Rng::new(cfg.seeds.chain, &[b"mining"]),
            liar: Liar {
                lies: cfg.liar,
                ..Liar::default()
            },
            rogue: if cfg.mutant == Mutant::M2PerInvoiceKey {
                rogue_signers()
            } else {
                Vec::new()
            },
            cfg,
            tl,
            schedule,
            slots,
            dir,
            issuer: None,
            window: es::key_window(cache),
            chain,
            relays: Vec::new(),
            relay_clock,
            clients,
            sched,
            rec,
            truth,
            log: Log::default(),
            queue: BinaryHeap::new(),
            seq: 0,
            now: tl.t0,
            last_tick: 0,
            invite_pool: Vec::new(),
            drop_blobs: BTreeMap::new(),
            session_pay: vec![Vec::new(); n],
            processes: 0,
            issuer_received: 0,
            minted: HashSet::new(),
        };
        w.chain.set_now(w.now);
        w.open_issuer(OpenMode::Normal);
        for k in 0..3u8 {
            let node = w.open_relay(k, NullifierMode::Create);
            w.relays.push(node);
        }
        w.schedule_initial();
        w
    }

    fn push(&mut self, t: u64, e: Event) {
        self.seq += 1;
        self.queue.push(Reverse((t, self.seq, e)));
    }

    fn schedule_initial(&mut self) {
        for c in 0..self.clients.len() {
            let join = self.clients[c].spec.join;
            self.push(join, Event::Join(c));
        }
        let day = DAY as u64;
        let first_day = (self.tl.t0 / day + 1) * day;
        self.push(first_day, Event::IssuerDaily);
        self.push(first_day + 3 * HOUR as u64, Event::RelayDaily);
        let first_week = week_start(week(self.tl.t0) + 1);
        self.push(first_week + 6 * HOUR as u64, Event::IssuerWeekly);
        self.push(first_week + 60, Event::RelayWeekly);
        let d = self.cfg.scale.window_days;
        for k in 0..3u8 {
            let at = self.tl.tw + (u64::from(k) + 1) * d * day / 4 + 5 * HOUR as u64;
            self.push(at, Event::RelayRestart(k));
        }
        for &(s, r) in &self.cfg.restores.clone() {
            self.push(self.tl.tw + s * day + 10 * HOUR as u64, Event::Snapshot);
            self.push(self.tl.tw + r * day + 10 * HOUR as u64, Event::Restore);
        }
        self.push(self.tl.te, Event::End);
    }

    fn open_issuer(&mut self, mode: OpenMode) {
        let ports = Ports {
            store: Box::new(RedbStore::open(&self.dir.path().join("issuer.redb")).unwrap()),
            journal: Box::new(FileJournal::open(&self.dir.path().join("journal")).unwrap()),
            rail: Box::new(ChainHandle(Arc::clone(&self.chain))),
            random: Box::new(SeededRandom(Arc::clone(&self.issuer_random))),
        };
        let params = IssuerParams {
            pool_target: self.cfg.pool_target,
            rate_per_sec: 1_000,
            rate_burst: 100_000,
            ..IssuerParams::default()
        };
        let issuer = Issuer::open(
            self.schedule.clone(),
            self.window.clone(),
            ports,
            params,
            mode,
            self.now,
        )
        .expect("the T2 issuer opens");
        self.issuer = Some(issuer);
        self.last_tick = 0;
    }

    fn open_relay(&mut self, k: u8, mode: NullifierMode) -> RelayNode {
        let dir = self.dir.path().join(format!("relay-{k}"));
        let onion = self
            .schedule
            .slot_onion(k, week(self.now))
            .expect("slot served")
            .to_string();
        let mut p = EntitlementPolicy::new(self.schedule.clone(), k, onion_pubkey(&onion)).unwrap();
        p.nullifiers = mode;
        p.rate = RedeemRate {
            per_second: 1_000_000,
            burst: 1_000_000,
        };
        let key = derive32(0x5452_454c, &[b"relay-key", &[k]]);
        self.relay_clock.store(self.now, Ordering::SeqCst);
        let clock = Arc::clone(&self.relay_clock);
        let capture_path = dir.join("capture.ndjson");
        std::fs::create_dir_all(&dir).unwrap();
        let relay = Relay::open(
            &dir,
            RelayKey::from_bytes(key),
            RelayConfig {
                entitlement: Some(p),
                clock: Arc::new(move || clock.load(Ordering::SeqCst)),
                ..RelayConfig::default()
            },
            Some(&capture_path),
        )
        .expect("a T2 relay opens");
        RelayNode {
            index: k,
            slot: k,
            relay,
            dir,
            key,
            address: OnionAddress::parse(&onion).unwrap(),
            onion,
            capture: transport::CaptureReader::open(&capture_path),
            capture_path,
        }
    }

    // ---------------------------------------------------------------------------------------------
    // The loop.
    // ---------------------------------------------------------------------------------------------

    pub fn run(mut self) -> Outcome {
        let started = std::time::Instant::now();
        while let Some(Reverse((t, _, e))) = self.queue.pop() {
            self.now = self.now.max(t);
            self.chain.set_now(self.now);
            self.relay_clock.store(self.now, Ordering::SeqCst);
            let tick = std::time::Instant::now();
            let kind: &'static str = match e {
                Event::End => "end",
                Event::Join(_) => "join",
                Event::Day(_) => "day",
                Event::Job(_) => "job",
                Event::Foreground(..) => "foreground",
                Event::ForegroundSync(_) => "foreground sync",
                Event::Pay(..) => "pay",
                Event::IssuerDaily => "issuer daily",
                Event::IssuerWeekly => "issuer weekly",
                Event::RelayDaily => "relay daily",
                Event::RelayWeekly => "relay weekly",
                Event::RelayRestart(_) => "relay restart",
                Event::Snapshot | Event::Restore => "issuer snapshot and restore",
            };
            let e_ = e;
            let _ = e_;
            match e {
                Event::End => break,
                Event::Join(c) => self.join(c),
                Event::Day(c) => self.day(c),
                Event::Job(c) => self.job(c),
                Event::Foreground(c, end) => self.foreground(c, end),
                Event::ForegroundSync(c) => self.foreground_sync(c),
                Event::Pay(c, p) => self.pay(c, p),
                Event::IssuerDaily => self.issuer_daily(),
                Event::IssuerWeekly => self.issuer_weekly(),
                Event::RelayDaily => self.relay_daily(),
                Event::RelayWeekly => self.relay_weekly(),
                Event::RelayRestart(k) => self.relay_restart(k),
                Event::Snapshot => self.snapshot(),
                Event::Restore => self.restore(),
            }
            *self.log.timings.entry(kind).or_insert(0.0) += tick.elapsed().as_secs_f64();
        }
        let tick = std::time::Instant::now();
        self.finish();
        *self.log.timings.entry("finish").or_insert(0.0) += tick.elapsed().as_secs_f64();
        let seconds = started.elapsed().as_secs_f64();
        let mut rec = self.rec;
        if let Some(acc) = &mut rec.acc {
            acc.close();
        }
        if let Some(e) = &mut rec.export {
            e.flush();
        }
        Outcome {
            name: self.cfg.name.clone(),
            rec,
            truth: self.truth,
            log: self.log,
            seconds,
        }
    }

    fn finish(&mut self) {
        self.issuer_snapshot_rows();
        self.relay_weekly();
        // The journal (append-only, never pruned in the world) and every payout batch file.
        let jdir = self.dir.path().join("journal");
        if let Ok(items) = std::fs::read_dir(&jdir) {
            let mut names: Vec<_> = items.map(|i| i.unwrap().path()).collect();
            names.sort();
            for p in names {
                let bytes = std::fs::read(&p).unwrap();
                let name = p.file_name().unwrap().to_string_lossy().to_string();
                self.rec.issuer_file("journal", &name, &bytes);
            }
        }
        for c in 0..self.clients.len() {
            self.truth.clients[c].namespaces = self.clients[c].namespaces.len();
        }
        // Completeness: the relays' own count of the calls they handled (one capture event each).
        for node in &self.relays {
            let bytes = std::fs::read(&node.capture_path).unwrap_or_default();
            self.log.capture_lines += bytes.iter().filter(|&&b| b == b'\n').count() as u64;
        }
        self.log.issuer_received = self.issuer_received;
        self.export_truth();
    }

    /// `public.json` (Z: the ES, the grid, every value of the public context) and
    /// `ground_truth.json` (clients with their namespaces, clocks, processes and drops; invoices
    /// with their plan seeds, receipts, finalizations and payments; every presented nullifier; the
    /// attacker's tokens) into `GHOST_T2_EXPORT` and `GHOST_T2_TRUTH` (design §13.4).
    fn export_truth(&self) {
        let dirs: Vec<PathBuf> = [self.cfg.export.clone(), self.cfg.export_truth.clone()]
            .into_iter()
            .flatten()
            .collect();
        if dirs.is_empty() {
            return;
        }
        let public =
            ghost_t2_join::public::public_context(self.schedule, &[es::schedule_bytes().to_vec()]);
        let mut p = String::new();
        let _ = write!(
            p,
            "{{\"schedule\":\"{}\",\"window\":[{},{}],\"scale\":{{\"packs\":{},\"window_days\":{},\"warmup_weeks\":{}}},\"grid\":{{\"week_origin\":{},\"week_seconds\":{}}},\"z\":[",
            hex::encode(es::schedule_bytes()),
            self.tl.tw,
            self.tl.te,
            self.cfg.scale.packs,
            self.cfg.scale.window_days,
            self.cfg.scale.warmup_weeks,
            policy::WEEK_ORIGIN,
            policy::WEEK
        );
        let z: Vec<String> = public
            .values
            .iter()
            .map(|v| format!("\"{}\"", hex::encode(v)))
            .collect();
        p.push_str(&z.join(","));
        p.push_str("]}\n");
        let mut g = String::from("{\"clients\":[");
        for (c, cl) in self.clients.iter().enumerate() {
            let ct = &self.truth.clients[c];
            if c > 0 {
                g.push(',');
            }
            let skew: Vec<String> = ct
                .skew
                .iter()
                .map(|s| format!("[{},{},{}]", s.0, s.1, s.2))
                .collect();
            let ns: Vec<String> = cl
                .namespaces
                .iter()
                .map(|n| format!("\"{}\"", hex::encode(n)))
                .collect();
            let drops: Vec<String> = cl
                .drops
                .iter()
                .map(|d| {
                    format!(
                        "{{\"ns\":\"{}\",\"invitee\":{}}}",
                        hex::encode(d.ns),
                        d.invitee
                    )
                })
                .collect();
            let processes: Vec<String> = ct.processes.iter().map(u64::to_string).collect();
            let _ = write!(
                g,
                "{{\"id\":{c},\"kind\":\"{:?}\",\"join\":{},\"skew\":[{}],\"processes\":[{}],\"namespaces\":[{}],\"drops\":[{}]}}",
                ct.kind,
                cl.spec.join,
                skew.join(","),
                processes.join(","),
                ns.join(","),
                drops.join(",")
            );
        }
        g.push_str("],\"invoices\":[");
        for (n, it) in self.truth.invoices.iter().enumerate() {
            if n > 0 {
                g.push(',');
            }
            let payments: Vec<String> = it
                .payments
                .iter()
                .map(|p| {
                    format!(
                        "{{\"txid\":\"{}\",\"first_seen\":{},\"mode\":\"{:?}\"}}",
                        hex::encode(p.0),
                        p.1,
                        p.2
                    )
                })
                .collect();
            let _ = write!(
                g,
                "{{\"invoice_id\":\"{}\",\"client\":{},\"instance\":{},\"xmr\":{},\"base_week\":{},\"need_triggered\":{},\"scored\":{},\"plan_seed\":\"{}\",\"receipt_minute\":{},\"finalized\":{},\"payments\":[{}]}}",
                hex::encode(it.invoice_id),
                it.client,
                it.instance,
                it.xmr,
                it.base_week,
                it.need_triggered,
                it.scored,
                hex::encode(it.seed),
                it.receipt_minute,
                it.finalized.map_or("null".to_string(), |f| f.to_string()),
                payments.join(",")
            );
        }
        let presented: Vec<String> = self
            .truth
            .presented
            .iter()
            .map(|n| format!("\"{}\"", hex::encode(n)))
            .collect();
        let attacker: Vec<String> = self
            .truth
            .attacker_tokens
            .iter()
            .map(|t| format!("\"{}\"", hex::encode(t)))
            .collect();
        let _ = writeln!(
            g,
            "],\"presented\":[{}],\"attacker_tokens\":[{}]}}",
            presented.join(","),
            attacker.join(",")
        );
        for d in dirs {
            std::fs::create_dir_all(&d).expect("export directory");
            std::fs::write(d.join("public.json"), &p).expect("public.json");
            std::fs::write(d.join("ground_truth.json"), &g).expect("ground_truth.json");
        }
    }

    // ---------------------------------------------------------------------------------------------
    // Housekeeping.
    // ---------------------------------------------------------------------------------------------

    fn issuer(&self) -> &Issuer {
        self.issuer.as_ref().expect("issuer open")
    }

    fn drain_wallet(&mut self) {
        for l in self.chain.drain_log() {
            let entries: Vec<WalletEntry> = l
                .entries
                .iter()
                .map(|e| WalletEntry {
                    txid: e.txid,
                    minor: e.minor,
                    amount: e.amount_atomic,
                    height: e.height,
                    confirmations: e.confirmations,
                    timestamp: e.timestamp,
                })
                .collect();
            let addr = l.address.clone().unwrap_or_default();
            let mut fields = Vec::new();
            if !addr.is_empty() {
                fields.push(ghost_t2_join::model::field("address", addr.as_bytes()));
            }
            let call = WalletCall {
                t: l.t,
                method: l.method,
                fields,
                entries,
            };
            self.rec.wallet(&call);
        }
    }

    /// The issuer's own jobs before a client call: pool refill and a scanner tick at most 60 s old.
    fn prepare_issuer(&mut self, t: u64) {
        self.chain.set_now(t);
        // The refill job keeps the pool at its target before every call (its size, which the NI-1
        // twin varies, then never refuses an invoice).
        let _ = self.issuer().pool_refill_at(t);
        if self.last_tick + 60 <= t {
            let _ = self.issuer().scan_tick_at(t);
            self.last_tick = t;
        }
        self.drain_wallet();
    }

    fn issuer_snapshot_rows(&mut self) {
        let rows: Vec<(&'static str, Vec<u8>, Vec<u8>)> = {
            let tx = self.issuer().store().read().unwrap();
            let mut out = Vec::new();
            for table in Table::ALL {
                for (k, v) in tx.range(table, &[], None).unwrap() {
                    out.push((table.name(), k, v));
                }
            }
            out
        };
        let now = self.now;
        self.rec.issuer_rows(now, &rows);
    }

    fn issuer_daily(&mut self) {
        let t = self.now;
        self.prepare_issuer(t);
        let _ = self.issuer().sweep_at(t);
        self.issuer_snapshot_rows();
        self.drain_wallet();
        self.push(t + DAY as u64, Event::IssuerDaily);
    }

    fn issuer_weekly(&mut self) {
        let t = self.now;
        let dir = self.dir.path().join("export");
        let key = crate::common::world::ops_key();
        let _ = self.issuer().payout_export_at(t, &key, &dir);
        if let Ok(items) = std::fs::read_dir(&dir) {
            let mut paths: Vec<_> = items.map(|i| i.unwrap().path()).collect();
            paths.sort();
            for p in paths {
                if p.extension().is_some_and(|x| x == "ghpb") {
                    let bytes = std::fs::read(&p).unwrap();
                    let name = p.file_name().unwrap().to_string_lossy().to_string();
                    self.rec.issuer_file("batch", &name, &bytes);
                    let file = BatchFile::verify(&bytes, &key.public()).unwrap();
                    let ack_path = dir.join(payout::ack_file_name(&file.batch_id));
                    if !ack_path.exists() {
                        let ack = AckFile {
                            batch_id: file.batch_id,
                            entries: file
                                .entries
                                .iter()
                                .map(|e| (e.claim_id, EntryOutcome::Paid))
                                .collect(),
                        };
                        std::fs::write(ack_path, ack.encode().unwrap()).unwrap();
                    }
                }
            }
        }
        self.push(t + policy::WEEK as u64, Event::IssuerWeekly);
    }

    fn relay_daily(&mut self) {
        let t = self.now;
        for node in &self.relays {
            let _ = node.relay.sweep(t);
        }
        self.push(t + DAY as u64, Event::RelayDaily);
    }

    /// Weekly relay snapshots: each relay is stopped, its databases are copied and read, and it
    /// starts again over the same data directory (a stop-copy-start, as the issuer's runbook B1;
    /// the databases lock their files while open).
    fn relay_weekly(&mut self) {
        let t = self.now;
        let w = week(t);
        for k in 0..self.relays.len() {
            let dir = self.relays[k].dir.clone();
            // The in-memory quota ledger (§13.4 relay_<k>_db), read before the relay stops.
            let (quota, pruned) = self.relays[k].relay.quota_snapshot();
            let mut rows = self.stop_relay_then(k as u8, |scratch| read_relay_rows(&dir, scratch));
            for (scope, used, expiry) in quota {
                let mut v = used.to_be_bytes().to_vec();
                v.extend_from_slice(&expiry.to_be_bytes());
                rows.push(("quota", scope.to_vec(), v));
            }
            rows.push((
                "quota_meta",
                b"pruned_through".to_vec(),
                pruned.to_be_bytes().to_vec(),
            ));
            self.rec.relay_rows(w, k as u8, &rows);
        }
        if t < self.tl.te {
            self.push(week_start(w + 1) + 60, Event::RelayWeekly);
        }
    }

    /// Stops relay `k`, runs `f` while it is down, and starts it again over the same directory;
    /// the capture reader keeps its place in the capture file.
    fn stop_relay_then<R>(&mut self, k: u8, f: impl FnOnce(&Path) -> R) -> R {
        let node = self.relays.remove(usize::from(k));
        let RelayNode { relay, capture, .. } = node;
        drop(relay);
        let r = f(self.dir.path());
        let mut fresh = self.open_relay(k, NullifierMode::Existing);
        fresh.capture = capture;
        self.relays.insert(usize::from(k), fresh);
        r
    }

    fn relay_restart(&mut self, k: u8) {
        self.stop_relay_then(k, |_| ());
        self.log.count("relay restarts");
    }

    fn snapshot(&mut self) {
        self.issuer = None;
        std::fs::copy(
            self.dir.path().join("issuer.redb"),
            self.dir.path().join("snapshot.redb"),
        )
        .unwrap();
        self.open_issuer(OpenMode::Normal);
    }

    fn restore(&mut self) {
        self.issuer = None;
        std::fs::copy(
            self.dir.path().join("snapshot.redb"),
            self.dir.path().join("issuer.redb"),
        )
        .unwrap();
        self.open_issuer(OpenMode::Restore);
        let t = self.now;
        self.prepare_issuer(t);
        self.log.count("issuer restores");
    }

    // ---------------------------------------------------------------------------------------------
    // Client lifecycle.
    // ---------------------------------------------------------------------------------------------

    fn join(&mut self, c: usize) {
        self.clients[c].installed = true;
        let t = self.now;
        let day = DAY as u64;
        self.push(t, Event::Day(c));
        let first = self.sched[c].range(60, SLOT_SECS);
        self.push(t + first, Event::Job(c));
        if self.clients[c].spec.spend == Spend::CreditsPack {
            self.clients[c].auto_renew_credits = false;
        }
        if self.clients[c].spec.spend == Spend::Claim {
            // In the second two thirds of the window (a claimant first collects its credits).
            let d = self.cfg.scale.window_days * day;
            let at = self.tl.tw
                + d / 3
                + (self.draw(c, b"claim-at", 0) * (d * 2 / 3 - 2 * day) as f64) as u64;
            self.clients[c].claim_at = Some(at);
        }
    }

    fn awake(&self, c: usize, t: u64) -> bool {
        let local = (t as i64 + self.clients[c].spec.tz).rem_euclid(DAY);
        (7 * HOUR..23 * HOUR).contains(&local)
    }

    fn day(&mut self, c: usize) {
        let t = self.now;
        let day = DAY as u64;
        let day_start = t / day * day;
        let n = {
            let cl = &mut self.clients[c];
            cl.user.poisson(cl.spec.foregrounds)
        };
        let mut starts: Vec<(u64, u64)> = Vec::new();
        for _ in 0..n {
            let cl = &mut self.clients[c];
            let local = cl.user.range(8 * HOUR as u64, 23 * HOUR as u64) as i64;
            let utc = (local - cl.spec.tz).rem_euclid(DAY) as u64;
            let dur = cl.user.range(60, 600);
            starts.push((day_start + utc, dur));
        }
        starts.sort();
        let mut last_end = 0;
        for (s, d) in starts {
            if s >= t && s > last_end + 120 {
                self.push(s, Event::Foreground(c, s + d));
                // The user script, drawn before any of the day's sessions happen: the only moments
                // a user action (a user-initiated issuer call) can come (J9).
                self.truth.clients[c].scripted.push(s);
                last_end = s + d;
            }
        }
        if t < self.tl.te {
            self.push(day_start + day, Event::Day(c));
        }
    }

    fn next_job(&mut self, c: usize, t: u64) -> u64 {
        let mut slot = t;
        loop {
            slot += SLOT_SECS + self.sched[c].range(0, 300);
            // The warm-up keeps a sparse cadence: its clients exist to mint credits through the
            // real system (§19.16 point 1); the scored window has the full one.
            let warm = slot < self.tl.tw;
            let p = match (self.awake(c, slot), warm) {
                (true, false) => self.clients[c].spec.run_probability,
                (false, false) => 1.0 / 12.0,
                (true, true) => 0.03,
                (false, true) => 1.0 / 36.0,
            };
            if self.sched[c].chance(p) {
                return slot;
            }
        }
    }

    fn new_process(&mut self, c: usize, t: u64) {
        self.processes += 1;
        let cl = &mut self.clients[c];
        cl.process_ordinal += 1;
        cl.process = (u64::from(cl.id) << 24) | cl.process_ordinal;
        let idb = cl.id.to_be_bytes();
        let ob = cl.process_ordinal.to_be_bytes();
        cl.process_key = derive32(cl.sched_seed, &[b"process", &idb, &ob]);
        cl.prf_key = derive32(cl.sched_seed, &[b"prf", &idb, &ob]);
        cl.job_in_process = 0;
        cl.clock = policy::ClockEstimate::default();
        cl.answered.clear();
        cl.first_seen.clear();
        cl.crash_pending = false;
        self.truth.clients[c].processes.push(t);
    }

    fn job(&mut self, c: usize) {
        let t = self.now;
        let next = self.next_job(c, t);
        if next < self.tl.te + DAY as u64 {
            self.push(next, Event::Job(c));
        }
        if !self.clients[c].onboarded || t < self.clients[c].foreground_until {
            return;
        }
        let idb = self.clients[c].id.to_be_bytes();
        let jb = self.clients[c].jobs.to_be_bytes();
        self.clients[c].jobs += 1;
        let kill = prf_unit(&derive32(self.cfg.seeds.sched, &[b"kill", &idb]), &jb) < 0.25;
        if self.clients[c].process == 0 || kill || self.clients[c].crash_pending {
            self.new_process(c, t);
        }
        let j = self.clients[c].job_in_process;
        self.clients[c].job_in_process += 1;
        let drawn = prf_unit(&self.clients[c].process_key, &j.to_be_bytes()) < Q;
        let mut quiet = drawn;
        if self.cfg.mutant == Mutant::M20QuietWhenWorkDue && self.sign_overdue(c, t) {
            quiet = true;
        }
        let run = self.next_run(c);
        if quiet {
            let tick = std::time::Instant::now();
            let calls = self.quiet_run(c, t + 5, run);
            *self.log.timings.entry("  quiet runs").or_insert(0.0) += tick.elapsed().as_secs_f64();
            self.truth.clients[c].runs.push(Run {
                id: run,
                start: t,
                end: t + 60,
                job: true,
                quiet: true,
                drawn,
                relay_calls: 0,
                issuer_calls: calls,
            });
        } else {
            let (relay_calls, issuer_calls) =
                if t < self.clients[c].hold_until || t < self.clients[c].screen_until {
                    (0, 0)
                } else {
                    let tick = std::time::Instant::now();
                    let r = self.relay_session(c, t + 3, run, u64::MAX, true);
                    *self
                        .log
                        .timings
                        .entry("  background relay sessions")
                        .or_insert(0.0) += tick.elapsed().as_secs_f64();
                    let i = if self.cfg.mutant == Mutant::M9SessionIssuerCalls {
                        self.session_sign(c, t + 8, run)
                    } else {
                        0
                    };
                    (r, i)
                };
            self.truth.clients[c].runs.push(Run {
                id: run,
                start: t,
                end: t + 120,
                job: true,
                quiet: false,
                drawn: false,
                relay_calls,
                issuer_calls,
            });
        }
    }

    fn sign_overdue(&self, c: usize, t: u64) -> bool {
        let cl = &self.clients[c];
        let w = cl.wall(t);
        cl.purchases.iter().any(|p| {
            p.state == PState::Invoiced
                && p.attempt < policy::BLIND_SIGN_ATTEMPTS
                && policy::blind_sign_due_minute(&p.plan_seed, p.receipt, p.attempt) <= w
        })
    }

    // ---------------------------------------------------------------------------------------------
    // Foreground sessions and user actions.
    // ---------------------------------------------------------------------------------------------

    fn foreground(&mut self, c: usize, end: u64) {
        let s = self.now;
        if !self.clients[c].installed || s < self.clients[c].screen_until {
            return;
        }
        self.clients[c].foreground_until = end;
        let run = self.next_run(c);
        let mut issuer_calls = 0;
        if !self.clients[c].onboarded {
            issuer_calls += self.onboard(c, s, run);
        }
        let mut relay_calls = 0;
        let held = s < self.clients[c].hold_until;
        let cutoff = if self.clients[c].onboarded {
            self.plan_payments(c, s, end)
        } else {
            u64::MAX
        };
        if self.clients[c].onboarded && !held {
            if self.clients[c].process == 0 {
                self.new_process(c, s);
            }
            relay_calls = self.relay_session(c, s + 1, run, cutoff, false);
        }
        if self.clients[c].onboarded {
            issuer_calls += self.user_actions(c, s, end, run);
        }
        if end > s + 90 && self.clients[c].screen_until <= s {
            self.push(s + 60, Event::ForegroundSync(c));
        }
        self.truth.clients[c].runs.push(Run {
            id: run,
            start: s,
            end,
            job: false,
            quiet: false,
            drawn: false,
            relay_calls,
            issuer_calls,
        });
    }

    fn foreground_sync(&mut self, c: usize) {
        let t = self.now;
        let cl = &self.clients[c];
        if t >= cl.foreground_until || t < cl.hold_until || t < cl.screen_until || !cl.onboarded {
            return;
        }
        let run = self.next_run(c);
        let n = self.relay_session(c, t, run, u64::MAX, false);
        self.truth.clients[c].runs.push(Run {
            id: run,
            start: t,
            end: t + 30,
            job: false,
            quiet: false,
            drawn: false,
            relay_calls: n,
            issuer_calls: 0,
        });
    }

    fn week_of(&self, c: usize, t: u64) -> i64 {
        policy::week(self.clients[c].wall(t))
    }

    /// The device time issuer-facing decisions use: the wall clock (M17: the relay-corrected one).
    fn issuer_wall(&self, c: usize, t: u64) -> i64 {
        let cl = &self.clients[c];
        let w = cl.wall(t);
        if self.cfg.mutant == Mutant::M17RelayClockDrivesBaseWeek {
            cl.clock.now(w)
        } else {
            w
        }
    }

    fn onboard(&mut self, c: usize, s: u64, run: u64) -> u32 {
        let kind = self.clients[c].spec.kind;
        let paid_onboarding = matches!(
            kind,
            ClientKind::Existing | ClientKind::Spender | ClientKind::Genesis
        ) || (self.cfg.mutant == Mutant::M13PaidOnboarding
            && matches!(kind, ClientKind::Invitee | ClientKind::Sybil));
        if paid_onboarding {
            self.activate_namespaces(c);
            let w = self.issuer_wall(c, s);
            self.start_purchase(c, s, w, true, false, w);
            self.clients[c].onboarded = true;
            if kind == ClientKind::Invitee || kind == ClientKind::Sybil {
                self.clients[c].first_pack_done = true;
                let inst = self.clients[c].purchases.last().unwrap().instance;
                self.log.first_packs.push((c as u32, inst));
            }
            return 0;
        }
        // An invite trial: the invite comes from an honest client holding an accepted invite.
        if self.clients[c].trial.is_none() {
            let Some((inviter, idx)) = self.take_invite(c, s) else {
                self.log.count("onboardings without an available invite");
                return 0;
            };
            let invite = self.clients[inviter].invites[idx].token.clone();
            // The drop namespace is a per-invite derivation both sides compute from the invite
            // (Invite v2, §19.12), never a draw at the time someone takes it: another client's
            // onboarding must not move the inviter's random stream.
            let drop_ns = derive32(
                self.clients[inviter].ns_seed,
                &[b"drop-ns", invite.as_bytes()],
            );
            let (epoch, source, ordinal) = {
                let inv = &self.clients[inviter].invites[idx];
                (inv.epoch, inv.source, inv.ordinal)
            };
            // The invite is usable on the days before the start of invite epoch + 2 (the latest
            // expiry, §8.2) and listened until 56 days later (§8.5).
            let expiry = week_start((epoch + 2) * 4);
            let until = expiry + 56 * DAY as u64;
            // The refresh times of a credit read from this drop, drawn as the listening starts
            // (Q31, §19.26): scheduling randomness keyed on the invite's identity, never on a read.
            let mut r = Rng::new(
                self.cfg.seeds.sched,
                &[
                    b"refresh-at",
                    &self.clients[inviter].id.to_be_bytes(),
                    &source.to_be_bytes(),
                    &[ordinal],
                ],
            );
            let refresh =
                policy::refresh_times(expiry as i64 / DAY, until as i64 / DAY, &mut || r.uniform());
            self.clients[inviter].drops.push(DropListen {
                ns: drop_ns,
                until,
                refresh,
                seen: Default::default(),
                invitee: c,
            });
            if self.rec.debug {
                let ns6: String = drop_ns[..6].iter().map(|b| format!("{b:02x}")).collect();
                self.rec.note(
                    inviter as u32,
                    s,
                    format!("listens on drop {ns6} of invitee {c}"),
                );
            }
            let instance = self.clients[c].next_flow(super::client::FlowSeq::Trial);
            let seed = derive32(
                self.cfg.seeds.token,
                &[
                    b"trial",
                    &self.clients[c].id.to_be_bytes(),
                    &instance.to_be_bytes(),
                ],
            );
            self.clients[c].trial = Some(Trial {
                instance,
                inviter,
                invite,
                drop_ns,
                seed,
                base: None,
                attempts: 0,
            });
        }
        self.trial_step(c, s, run)
    }

    fn take_invite(&mut self, c: usize, t: u64) -> Option<(usize, usize)> {
        let e_now = invite_epoch(week(t));
        let candidates: Vec<usize> = self
            .invite_pool
            .iter()
            .enumerate()
            .filter(|(_, &(i, k))| {
                let inv = &self.clients[i].invites[k];
                !inv.given
                    && inv.revoke.is_none()
                    && inv.eligible <= self.clients[i].wall(t)
                    && (inv.epoch == e_now || inv.epoch + 1 == e_now)
            })
            .map(|(n, _)| n)
            .collect();
        if candidates.is_empty() {
            return None;
        }
        // The attacker's Sybil invitees seek invites from heavy users: clients that will claim a
        // payout of their credits first, then other credit spenders (a Sybil ranks invites by that
        // tier; an honest invitee does not).
        let sybil = self.clients[c].spec.kind == ClientKind::Sybil;
        let tier = |n: usize| -> u8 {
            let inviter = &self.clients[self.invite_pool[n].0].spec;
            if !sybil || inviter.spend == Spend::Claim {
                0
            } else if inviter.kind == ClientKind::Spender {
                1
            } else {
                2
            }
        };
        // The invite with the least (tier, keyed hash): an invitee's choice changes only when that
        // very invite is missing, never with the size, order or tiers of the rest of the pool (a
        // tiered sub-pool would switch when another invite of the top tier is missing).
        let key = derive32(
            self.cfg.seeds.user,
            &[b"invite-choice", &self.clients[c].id.to_be_bytes()],
        );
        // Keyed on the invite's identity (inviter, pack flow, position in the pack): never on its
        // index in the inviter's list, which moves when the inviter's packs finalize in another
        // order (NI-1 across cells), nor on its bytes, which token randomness sets (NI-2).
        let h = |n: usize| {
            let (i, k) = self.invite_pool[n];
            let inv = &self.clients[i].invites[k];
            prf_unit(
                &key,
                &[
                    &(i as u64).to_be_bytes()[..],
                    &inv.source.to_be_bytes(),
                    &[inv.ordinal],
                ]
                .concat(),
            )
        };
        let pick = *candidates
            .iter()
            .min_by(|&&a, &&b| {
                tier(a)
                    .cmp(&tier(b))
                    .then_with(|| h(a).partial_cmp(&h(b)).unwrap())
            })
            .unwrap();
        let (i, k) = self.invite_pool.swap_remove(pick);
        self.clients[i].invites[k].given = true;
        let src = self.clients[i].invites[k].source;
        self.log.given_invites.push((i as u32, src));
        self.log.takes.push((i as u32, src, c as u32, t));
        if self.rec.debug {
            self.rec.note(
                c as u32,
                t,
                format!("took the invite of client {i} (pack {src:x})"),
            );
            self.rec.note(
                i as u32,
                t,
                format!("invite of pack {src:x} taken by client {c}"),
            );
        }
        Some((i, k))
    }

    fn activate_namespaces(&mut self, c: usize) {
        if !self.clients[c].namespaces.is_empty() {
            return;
        }
        // The namespace set (its size too) comes from the namespace seed: the NI-2 twin varies each
        // client's namespace set and relay activity (design §13.4), which M8 turns into counts.
        let cl = &mut self.clients[c];
        let n = (1 + cl.ns_rng.poisson(4.0)).min(16);
        for _ in 0..n {
            let ns: [u8; 32] = cl.ns_rng.bytes();
            cl.namespaces.push(ns);
        }
    }

    /// The trial's `RedeemInvite` (foreground, user-initiated, before any relay traffic).
    fn trial_step(&mut self, c: usize, s: u64, run: u64) -> u32 {
        let w = self.issuer_wall(c, s);
        let trial = self.clients[c].trial.as_mut().unwrap();
        trial.attempts += 1;
        if trial.attempts > 40 {
            return 0;
        }
        let base = *trial.base.get_or_insert(policy::week(w) as u64);
        let (instance, seed, invite) = (trial.instance, trial.seed, trial.invite.clone());
        let digest = Product::Trial.layout(self.schedule, base).unwrap().digest();
        let schedule = self.schedule;
        self.truth.clients[c]
            .user_calls
            .push((s, ghost_t2_join::model::IssuerOp::RedeemInvite));
        let fault = self.issuer_fault(c, instance, 0, b"trial");
        let (r, t_resp) = self.with_issuer(
            c,
            s,
            instance,
            0,
            FlowKind::Trial,
            false,
            run,
            fault,
            Vec::new(),
            |link| {
                transport::block_on(issuer_flow::redeem_invite(
                    link, schedule, &invite, &seed, base, &digest,
                ))
            },
        );
        match r {
            Ok(a) if a.result == wire::RedeemInviteResult::Ok => {
                let w_resp = self.clients[c].wall(t_resp);
                let eligible = self.trial_eligible(c, instance, base, w_resp);
                self.store_tokens(
                    c,
                    a.tokens,
                    &Layout::trial(self.schedule, base).unwrap(),
                    instance,
                    eligible,
                );
                let cl = &mut self.clients[c];
                cl.coverage_end = cl.coverage_end.max(base as i64 + 1);
                cl.onboarded = true;
                self.activate_namespaces(c);
                let trial = self.clients[c].trial.take().unwrap();
                let lo = week_start(base + 3) as i64;
                let hi = week_start(base + 8) as i64;
                let mut r = Rng::new(
                    self.cfg.seeds.sched,
                    &[b"drop", &self.clients[c].id.to_be_bytes()],
                );
                let due = lo + r.range(0, (hi - lo) as u64) as i64;
                let mut blob = vec![0u8; BLOB];
                self.clients[c].ns_rng.fill(&mut blob);
                self.clients[c].drop_out = Some(DropOut {
                    inviter: trial.inviter,
                    ns: trial.drop_ns,
                    due,
                    written: [false; 3],
                    credit: None,
                    blob,
                    done: false,
                });
                if let Some(delay) = self.clients[c].spec.first_pack_delay {
                    let mut at = s + delay;
                    if let Some((frac, shift)) = self.cfg.first_pack_shift {
                        let chosen = prf_unit(
                            &derive32(self.cfg.seeds.user, &[b"ni1d"]),
                            &self.clients[c].id.to_be_bytes(),
                        ) < frac;
                        if chosen {
                            at += shift;
                        }
                    }
                    self.clients[c].first_pack_at = Some(at);
                }
                self.log.count("trials");
            }
            Ok(a) if a.result == wire::RedeemInviteResult::WrongPeriod => {
                // A device more than 4 h off (E14): nothing recorded; the next foreground retries
                // with the base week of its (possibly corrected) clock.
                self.clients[c].trial.as_mut().unwrap().base = None;
                self.log.count("trials wrong_period");
            }
            Ok(_) => {
                self.log.count("trials refused");
                self.clients[c].trial = None;
            }
            Err(_) => {}
        }
        1
    }

    fn user_actions(&mut self, c: usize, s: u64, end: u64, run: u64) -> u32 {
        let mut calls = 0;
        let w = self.issuer_wall(c, s);
        let wk = policy::week(w);
        let in_window = s >= self.tl.tw;
        if in_window
            && self.clients[c].spec.spend == Spend::CreditsPack
            && !self.clients[c].auto_renew_credits
        {
            self.clients[c].auto_renew_credits = true;
        }
        // The invitee's first pack.
        if let Some(at) = self.clients[c].first_pack_at {
            if !self.clients[c].first_pack_done && s >= at {
                self.clients[c].first_pack_done = true;
                calls += self.start_purchase(c, s, w, true, false, w);
                let inst = self.clients[c].purchases.last().unwrap().instance;
                self.log.first_packs.push((c as u32, inst));
            }
        }
        // Renewal, lapse and resume. A future credit spender renews with two weeks left during the
        // warm-up (it exists to mint credits, §19.16 point 1), at the common cadence in the window.
        let threshold = if self.clients[c].spec.kind == ClientKind::Spender && !in_window {
            2
        } else {
            1
        };
        let cov = self.clients[c].coverage_end;
        let invitee_waiting = matches!(
            self.clients[c].spec.kind,
            ClientKind::Invitee | ClientKind::Sybil
        ) && !self.clients[c].first_pack_done;
        let trial_only = matches!(self.clients[c].spec.kind, ClientKind::Invitee)
            && self.clients[c].spec.first_pack_delay.is_none();
        if !self.clients[c].pack_in_flight()
            && cov >= 0
            && cov - wk <= threshold
            && !invitee_waiting
            && !trial_only
        {
            let credits_cover =
                self.clients[c].auto_renew_credits && self.covering(c, wk).is_some();
            if self.clients[c].spec.resume_gap.is_some() && in_window && !self.clients[c].lapse_done
            {
                self.clients[c].lapse_done = true;
                let gap = self.clients[c].spec.resume_gap.unwrap() as i64;
                self.clients[c].resume_at = Some(policy::week_start(cov + 1) + gap);
            } else if self.clients[c].resume_at.is_none() && !credits_cover {
                calls += self.start_purchase(c, s, w, true, false, w);
                self.log.count(if in_window {
                    "window renewals started"
                } else {
                    "warm-up renewals started"
                });
            }
        }
        if let Some(r) = self.clients[c].resume_at {
            if w >= r && !self.clients[c].pack_in_flight() {
                self.clients[c].resume_at = None;
                calls += self.start_purchase(c, s, w, true, false, w);
                self.log.count("resumes started");
            }
        }
        // ENTITLEMENT_NEEDED surfaced: the user may buy (5 % of extra packs, §19.13). A twin world
        // replays its base world's starts in the same foreground session.
        if let Some(script) = self.cfg.script.clone() {
            for &(sc, fs, nb) in &script.need_starts {
                if sc as usize == c && fs == s {
                    self.log.need_starts.push((c as u32, s, nb));
                    calls += self.start_purchase(c, s, w, true, true, nb);
                }
            }
        } else {
            if let (Some(_), Some(surf)) =
                (self.clients[c].needed_since, self.clients[c].need_surface)
            {
                if w >= surf {
                    self.clients[c].needed_since = None;
                    self.clients[c].need_surface = None;
                    // A need buyer (5 % of N, population::NEED_SHARE) buys one extra pack when its
                    // first need of the window surfaces (§13.4 "Other activity", §19.13).
                    let buy = self.clients[c].spec.need_buyer && !self.clients[c].need_bought;
                    let eligible_buyer = !self.clients[c].pack_in_flight()
                        && !invitee_waiting
                        && !trial_only
                        && self.clients[c].resume_at.is_none()
                        && in_window;
                    if buy && eligible_buyer {
                        self.clients[c].need_bought = true;
                        let delay = (self.draw(c, b"need-delay", s) * DAY as f64) as i64;
                        let nb = w + delay;
                        self.log.need_starts.push((c as u32, s, nb));
                        calls += self.start_purchase(c, s, w, true, true, nb);
                    }
                }
            }
        }
        // A payout claim.
        if let Some(at) = self.clients[c].claim_at {
            if s >= at && self.clients[c].claim.is_none() && self.clients[c].credits.len() >= 10 {
                self.clients[c].claim_at = None;
                let instance = self.clients[c].next_flow(super::client::FlowSeq::Claim);
                let idb = self.clients[c].id.to_be_bytes();
                let claim_id: [u8; 16] = derive32(
                    self.cfg.seeds.sched,
                    &[b"claim-id", &idb, &instance.to_be_bytes()],
                )[..16]
                    .try_into()
                    .unwrap();
                let spend = derive32(
                    self.cfg.seeds.sched,
                    &[b"payout", &idb, &instance.to_be_bytes()],
                );
                let address = crate::common::chain_port::encode_address(
                    18,
                    u64::from_be_bytes(spend[..8].try_into().unwrap()) >> 8,
                    u64::from_be_bytes(spend[8..16].try_into().unwrap()) >> 8,
                );
                // A claim presents every credit the client holds (10 to 50).
                let n = self.clients[c].credits.len().min(50);
                let credits: Vec<Token> = self.clients[c]
                    .credits
                    .drain(..n)
                    .map(|h| h.token)
                    .collect();
                self.clients[c].claim = Some(ClaimFlow {
                    instance,
                    claim_id,
                    credits,
                    address,
                    due: w,
                    attempt: 0,
                    done: false,
                });
                self.log.count("claims started");
            }
        }
        // A message written: outbox work on a random active namespace.
        if self.draw(c, b"write", s) < 0.25 {
            let act = self.active_namespaces(c, s);
            if !act.is_empty() {
                let i =
                    ((self.draw(c, b"write-ns", s) * act.len() as f64) as usize).min(act.len() - 1);
                let ns = act[i];
                let mut data = vec![0u8; BLOB];
                self.clients[c].ns_rng.fill(&mut data);
                let hash: [u8; 32] = Sha256::digest(&data).into();
                self.clients[c].outbox.push((ns, data, hash, [false; 3]));
            }
        }
        let _ = (run, end);
        calls
    }

    /// Payments at a foreground session (§19.11): PAYMENT_READY surfaces at the first foreground
    /// at least U[1 h, 6 h] after the receipt; the user pays from the payment screen (70 %), which
    /// opens 20 s into the session, closes its relay session and holds sessions off U[20, 60] min
    /// after it closes, or later during a relay session (30 %). Returns the time the relay session
    /// of this foreground must stop (the screen's opening), if any.
    fn plan_payments(&mut self, c: usize, s: u64, end: u64) -> u64 {
        let mut cutoff = u64::MAX;
        let due: Vec<usize> = {
            let cl = &mut self.clients[c];
            let (now_due, later): (Vec<_>, Vec<_>) =
                cl.pay_queue.drain(..).partition(|&(at, _)| at <= s);
            cl.pay_queue = later;
            now_due.into_iter().map(|(_, p)| p).collect()
        };
        let pending_session: Vec<usize> = std::mem::take(&mut self.session_pay[c]);
        for p in pending_session {
            let inst = self.clients[c].purchases[p].instance;
            let at = s + 30 + (self.draw(c, b"session-pay", inst) * 60.0) as u64;
            if at < end {
                self.push(at, Event::Pay(c, p));
                self.clients[c].purchases[p].paid = true;
                self.set_mode(c, p, PayMode::Session);
            } else {
                self.session_pay[c].push(p);
            }
        }
        for p in due {
            let inst = self.clients[c].purchases[p].instance;
            if self.draw(c, b"pay-mode", inst) < 0.7 {
                let at = s + 40 + (self.draw(c, b"pay-at", inst) * 140.0) as u64;
                self.push(at, Event::Pay(c, p));
                self.clients[c].purchases[p].paid = true;
                self.set_mode(c, p, PayMode::Screen);
                if self.cfg.mutant != Mutant::M19PayInsideSession {
                    let hold = 1_200 + (self.draw(c, b"hold", inst) * 2_400.0) as u64;
                    self.clients[c].screen_until = at + 10;
                    self.clients[c].hold_until = at + 10 + hold;
                    cutoff = cutoff.min(s + 20);
                }
            } else {
                self.session_pay[c].push(p);
            }
        }
        cutoff
    }

    /// A keyed draw of client `c`'s user behaviour, in [0, 1): independent of the order in which
    /// other draws happen, so a twin world that skips or adds a user action draws everything
    /// else identically.
    fn draw(&self, c: usize, tag: &[u8], k: u64) -> f64 {
        prf_unit(&self.clients[c].draw_key, &[tag, &k.to_be_bytes()].concat())
    }

    /// The next run id of client `c` (per client: one client's runs never shift another's).
    fn next_run(&mut self, c: usize) -> u64 {
        let cl = &mut self.clients[c];
        cl.runs += 1;
        (u64::from(cl.id) << 32) | cl.runs
    }

    fn set_mode(&mut self, c: usize, p: usize, mode: PayMode) {
        if let Some(ti) = self.clients[c].purchases[p].truth {
            self.truth.invoices[ti].payments.push(([0; 32], 0, mode));
        }
    }

    fn pay(&mut self, c: usize, p: usize) {
        let t = self.now;
        let (minor, amount, next_due) = {
            let cl = &self.clients[c];
            let pu = &cl.purchases[p];
            let minor = self
                .chain
                .minor_of(&pu.subaddress)
                .expect("an address of the wallet");
            let k = pu.attempt.min(policy::BLIND_SIGN_ATTEMPTS - 1);
            (
                minor,
                pu.amount,
                policy::blind_sign_due_minute(&pu.plan_seed, pu.receipt, k),
            )
        };
        let mut delay = 0;
        if self.cfg.chain_jitter {
            let d = self.chain_rng.range(0, 3);
            let conf = self.chain.confirmed_at(t, d, 10) as i64;
            // Keep the payment on the same side of the payer's next attempt.
            let wall_off = self.clients[c].wall(0);
            if conf + wall_off < next_due - 120 {
                delay = d;
            }
        }
        let txid = self.chain.pay(minor, amount, t, delay);
        if let Some(ti) = self.clients[c].purchases[p].truth {
            if let Some(last) = self.truth.invoices[ti].payments.last_mut() {
                if last.1 == 0 {
                    last.0 = txid;
                    last.1 = t;
                }
            }
        }
        self.log.count("payments");
    }

    // ---------------------------------------------------------------------------------------------
    // Purchases and the issuer calls of quiet runs.
    // ---------------------------------------------------------------------------------------------

    fn covering(&self, c: usize, wk: i64) -> Option<Vec<usize>> {
        let cl = &self.clients[c];
        let prices: BTreeMap<i64, i64> = self
            .schedule
            .content()
            .prices
            .iter()
            .map(|p| (p.price_epoch as i64, p.pack_price_atomic as i64))
            .collect();
        let epochs: Vec<i64> = cl.credits.iter().map(|h| h.epoch as i64).collect();
        policy::covering_set(&prices, &epochs, wk, wk, 10)
    }

    /// The user starts a pack purchase (XMR or, `xmr = false`, with credits).
    fn start_purchase(
        &mut self,
        c: usize,
        s: u64,
        w: i64,
        xmr: bool,
        need: bool,
        not_before: i64,
    ) -> u32 {
        let twice =
            self.cfg.mutant == Mutant::M8VariableCounts && self.clients[c].namespaces.len() >= 6;
        for _ in 0..if twice { 2 } else { 1 } {
            let instance = self.clients[c].next_flow(super::client::FlowSeq::Purchase);
            let idb = self.clients[c].id.to_be_bytes();
            let mut seed = derive32(
                self.cfg.seeds.token,
                &[b"seed", &idb, &instance.to_be_bytes()],
            );
            if self.cfg.mutant == Mutant::M15SeedReuseAcrossFlows {
                seed = derive32(self.cfg.seeds.token, &[b"seed", &idb, &1u64.to_be_bytes()]);
                if let Some(first) = self.clients[c].purchases.first() {
                    seed = first.seed;
                }
                if let Some(t) = &self.clients[c].trial {
                    seed = t.seed;
                }
            }
            // The attempt plan is HKDF(seed, "ghost/v1/attempt" ‖ k) (§19.11): scheduling randomness,
            // which the NI-2 twin shares with its base world while the blinding seed varies (under
            // the PRF security of HKDF the two are independent, as in the ideal world).
            let plan_seed = self
                .cfg
                .script
                .as_ref()
                .and_then(|s| {
                    s.plan_seeds
                        .iter()
                        .find(|p| p.0 == c as u32 && p.1 == instance)
                        .map(|p| p.2)
                })
                .unwrap_or(seed);
            let claim_key = derive32(
                self.cfg.seeds.sched,
                &[b"claim", &idb, &instance.to_be_bytes()],
            );
            let button = xmr
                && prf_unit(
                    &derive32(self.cfg.seeds.user, &[b"button"]),
                    &instance.to_be_bytes(),
                ) < 0.03;
            self.clients[c].purchases.push(Purchase {
                instance,
                xmr,
                state: PState::Prepared,
                created: w,
                not_before,
                seed,
                plan_seed,
                claim_key,
                base_week: None,
                credits: Vec::new(),
                invoice_id: [0; 16],
                amount: 0,
                subaddress: String::new(),
                receipt: 0,
                attempt: 0,
                req_attempt: 0,
                retry_due: None,
                need,
                button: button && !need,
                truth: None,
                rogue: None,
                hint: None,
                paid: false,
            });
        }
        let _ = s;
        0
    }

    fn issuer_fault(
        &mut self,
        c: usize,
        instance: u64,
        attempt: usize,
        what: &[u8],
    ) -> IssuerFault {
        let key = derive32(self.cfg.seeds.fault, &[b"unavailable", what]);
        let input = [
            self.clients[c].id.to_be_bytes().as_slice(),
            &instance.to_be_bytes(),
            &(attempt as u64).to_be_bytes(),
        ]
        .concat();
        if prf_unit(&key, &input) < 0.02 {
            IssuerFault::Unavailable
        } else {
            IssuerFault::None
        }
    }

    /// Runs one issuer call over a fresh flow scope, recording it; returns the answer time.
    #[allow(clippy::too_many_arguments)]
    fn with_issuer<R>(
        &mut self,
        c: usize,
        t: u64,
        instance: u64,
        attempt: usize,
        kind: FlowKind,
        automatic: bool,
        run: u64,
        fault: IssuerFault,
        extra_req: Vec<(&'static str, Vec<u8>)>,
        f: impl FnOnce(&mut IssuerLink<'_>) -> R,
    ) -> (R, u64) {
        self.prepare_issuer(t);
        let idb = self.clients[c].id.to_be_bytes();
        // The flow instance of this call (R5: one fresh `IssuerFlow` per call) and the isolation
        // token the client uses for it (M4: one per process, shared by every flow).
        let logical: [u8; 16] = derive32(
            self.cfg.seeds.sched,
            &[
                b"flow",
                &idb,
                &instance.to_be_bytes(),
                &(attempt as u64).to_be_bytes(),
                &run.to_be_bytes(),
            ],
        )[..16]
            .try_into()
            .unwrap();
        let flow: [u8; 16] = if self.cfg.mutant == Mutant::M4SharedIssuerScope {
            derive32(
                self.cfg.seeds.sched,
                &[b"shared-flow", &idb, &self.clients[c].process.to_be_bytes()],
            )[..16]
                .try_into()
                .unwrap()
        } else {
            logical
        };
        let label = transport::label(&flow, &self.schedule.content().issuer_onion);
        let mut latency = LATENCY;
        if self.cfg.latency_jitter {
            let w = self.clients[c].wall(t + LATENCY);
            let room = 59 - w.rem_euclid(60) as u64;
            latency += (self.issuer_rng.uniform() * room.min(30) as f64) as u64;
        }
        // NI-1: a signing answer up to 30 s later, across minute boundaries (the pack's finalization
        // moves inside its activation-slot cell).
        let sign_extra = if self.cfg.sign_jitter {
            (self.issuer_rng.uniform() * 30.0) as u64
        } else {
            0
        };
        let truth = IssuerTruth {
            client: c as u32,
            flow: u64::from_be_bytes(logical[..8].try_into().unwrap()),
            instance,
            kind,
            automatic,
            run,
        };
        let World {
            issuer,
            rec,
            liar,
            cfg,
            issuer_received,
            ..
        } = self;
        let mut link = IssuerLink {
            issuer: issuer.as_ref().unwrap(),
            rec,
            t,
            latency,
            label,
            truth,
            fault,
            liar: (cfg.liar > 0).then_some(liar),
            extra_req,
            extra_resp: Vec::new(),
            answered: None,
            received: issuer_received,
            sign_extra,
        };
        let tick = std::time::Instant::now();
        let r = f(&mut link);
        let answered = link.answered.unwrap_or(t + latency);
        *self
            .log
            .timings
            .entry("  issuer calls (handler and client crypto)")
            .or_insert(0.0) += tick.elapsed().as_secs_f64();
        self.drain_wallet();
        (r, answered)
    }

    fn quiet_run(&mut self, c: usize, t: u64, run: u64) -> u32 {
        let w = self.issuer_wall(c, t);
        let mut items: Vec<(WorkKind, i64, usize)> = Vec::new();
        {
            let cl = &self.clients[c];
            for (i, p) in cl.purchases.iter().enumerate() {
                match p.state {
                    PState::Prepared => {
                        let due = p.retry_due.unwrap_or(p.not_before.max(p.created));
                        items.push((WorkKind::Request, due, i));
                    }
                    PState::Invoiced => {
                        let capped = self.cfg.mutant != Mutant::M16IssuerForcesRetries;
                        if p.attempt < policy::BLIND_SIGN_ATTEMPTS {
                            items.push((
                                WorkKind::Sign,
                                policy::blind_sign_due_minute(&p.plan_seed, p.receipt, p.attempt),
                                i,
                            ));
                        } else if !capped {
                            let last = policy::blind_sign_due_minute(&p.plan_seed, p.receipt, 4);
                            items.push((WorkKind::Sign, last + (p.attempt as i64 - 4) * DAY, i));
                        }
                    }
                    _ => {}
                }
            }
            for (i, r) in cl.received.iter().enumerate() {
                items.push((WorkKind::Refresh, r.retry.unwrap_or(r.due), i));
            }
            for (i, inv) in cl.invites.iter().enumerate() {
                if let Some((due, _, _)) = inv.revoke {
                    items.push((WorkKind::Revocation, due, i));
                }
            }
            // M12 sends the claim only together with a purchase call (the same run and flow).
            if let Some(cf) = &cl.claim {
                if !cf.done && self.cfg.mutant != Mutant::M12ClaimInPurchaseRun {
                    items.push((WorkKind::Claim, cf.due, 0));
                }
            }
        }
        let wk = policy::week(w);
        let renewal = self.clients[c].auto_renew_credits
            && !self.clients[c].pack_in_flight()
            && self.clients[c].coverage_end - wk < 2
            && self.covering(c, wk).is_some();
        if renewal {
            items.push((WorkKind::Renewal, w, 0));
        }
        let list: Vec<(WorkKind, i64)> = items.iter().map(|&(k, d, _)| (k, d)).collect();
        let Some(pick) = policy::pick(&list, w) else {
            return 0;
        };
        let (kind, _, idx) = items[pick];
        let mut calls = 1;
        match kind {
            WorkKind::Request => self.request_invoice(c, idx, t, run, true),
            WorkKind::Sign => self.blind_sign(c, idx, t, run, true),
            WorkKind::Refresh => self.refresh(c, idx, t, run),
            WorkKind::Revocation => self.revoke(c, idx, t, run),
            WorkKind::Claim => self.claim(c, t, run),
            WorkKind::Renewal => {
                let set = self.covering(c, wk).unwrap();
                let mut chosen = Vec::new();
                let mut positions = set.clone();
                positions.sort_unstable();
                for &p in &set {
                    chosen.push(self.clients[c].credits[p].token.clone());
                }
                for p in positions.into_iter().rev() {
                    self.clients[c].credits.remove(p);
                }
                self.start_purchase(c, t, w, false, false, w);
                let i = self.clients[c].purchases.len() - 1;
                self.clients[c].purchases[i].credits = chosen;
                self.log.count("credits packs started");
                self.request_invoice(c, i, t, run, true);
            }
        }
        if self.cfg.mutant == Mutant::M12ClaimInPurchaseRun
            && matches!(kind, WorkKind::Request | WorkKind::Sign)
            && self.clients[c].claim.as_ref().is_some_and(|cf| !cf.done)
        {
            self.claim(c, t + 3, run);
            calls += 1;
        }
        calls
    }

    fn session_sign(&mut self, c: usize, t: u64, run: u64) -> u32 {
        let w = self.issuer_wall(c, t);
        let idx = self.clients[c].purchases.iter().position(|p| {
            p.state == PState::Invoiced
                && p.attempt < policy::BLIND_SIGN_ATTEMPTS
                && policy::blind_sign_due_minute(&p.plan_seed, p.receipt, p.attempt) <= w
        });
        match idx {
            Some(i) => {
                self.blind_sign(c, i, t, run, true);
                1
            }
            None => 0,
        }
    }

    fn request_invoice(&mut self, c: usize, idx: usize, t: u64, run: u64, automatic: bool) {
        let w = self.issuer_wall(c, t);
        let (instance, attempt) = {
            let p = &self.clients[c].purchases[idx];
            (p.instance, p.req_attempt)
        };
        let base = {
            let hint = if self.cfg.mutant == Mutant::M7IssuerBaseWeek {
                let bit = prf_unit(
                    &derive32(self.cfg.seeds.issuer, &[b"base-hint"]),
                    &[&(c as u64).to_be_bytes(), &instance.to_be_bytes()[..]].concat(),
                ) < 0.5;
                let h = if bit {
                    week(t.saturating_sub(4 * 3_600))
                } else {
                    week(t + 4 * 3_600)
                };
                Some(h)
            } else {
                None
            };
            let p = &mut self.clients[c].purchases[idx];
            if p.base_week.is_none() {
                p.base_week = Some(hint.unwrap_or(policy::week(w) as u64));
                p.hint = hint;
            }
            p.base_week.unwrap()
        };
        let mut fault = self.issuer_fault(c, instance, attempt, b"request");
        if attempt == 0 && self.cfg.fail_request.contains(&(c as u32, instance)) {
            fault = IssuerFault::Unavailable;
        }
        let (claim_key, credits, xmr, hint) = {
            let p = &self.clients[c].purchases[idx];
            (p.claim_key, p.credits.clone(), p.xmr, p.hint)
        };
        let foreign = unminted(&self.minted, credits.iter().map(|t| &t.as_bytes()[..]));
        assert_eq!(
            foreign, 0,
            "a credits-paid pack presents {foreign} credits no issuer of the world minted (§19.16 point 1)"
        );
        let mut extra_req = Vec::new();
        if let Some(h) = hint {
            extra_req.push(("base_week_hint", h.to_be_bytes().to_vec()));
        }
        if self.cfg.mutant == Mutant::M10ReferralIdAtIssuer {
            if let Some(d) = &self.clients[c].drop_out {
                extra_req.push(("referral_id", d.ns.to_vec()));
            }
        }
        let kind = if xmr {
            FlowKind::PackXmr
        } else {
            FlowKind::PackCredits
        };
        let schedule = self.schedule;
        let claim_hash = batch::claim_hash(&claim_key);
        let (r, t_resp) = self.with_issuer(
            c,
            t,
            instance,
            attempt,
            kind,
            automatic,
            run,
            fault,
            extra_req,
            |link| {
                transport::block_on(issuer_flow::request_invoice(
                    link,
                    schedule,
                    &claim_hash,
                    &credits,
                    base,
                ))
            },
        );
        let first_send = attempt == 0;
        {
            let u = Rng::new(
                self.cfg.seeds.sched,
                &[b"retry", &(c as u64).to_be_bytes(), &instance.to_be_bytes()],
            )
            .uniform();
            let p = &mut self.clients[c].purchases[idx];
            p.req_attempt += 1;
            if first_send {
                p.retry_due = policy::next_due_after_send(0, None, w, u);
            }
        }
        match r {
            Ok(a) if a.result == wire::RequestInvoiceResult::Ok => {
                let receipt = policy::floor_minute(self.clients[c].wall(t_resp));
                let rogue = (!self.rogue.is_empty())
                    .then(|| usize::from(a.invoice_id[0]) % self.rogue.len());
                let ti = self.truth.invoices.len();
                self.truth.invoices.push(InvoiceTruth {
                    invoice_id: a.invoice_id,
                    client: c as u32,
                    instance,
                    xmr,
                    base_week: base,
                    need_triggered: self.clients[c].purchases[idx].need,
                    scored: t >= self.tl.tw,
                    payments: Vec::new(),
                    seed: self.clients[c].purchases[idx].plan_seed,
                    receipt_minute: receipt as u64,
                    finalized: None,
                });
                let p = &mut self.clients[c].purchases[idx];
                p.state = PState::Invoiced;
                p.invoice_id = a.invoice_id;
                p.amount = a.amount_atomic;
                p.subaddress = a.subaddress.clone().unwrap_or_default();
                p.receipt = receipt;
                p.retry_due = None;
                p.truth = Some(ti);
                p.rogue = rogue;
                if xmr {
                    // PAYMENT_READY surfaces U[1 h, 6 h] after the recorded receipt minute (the
                    // device's minute of the answer; the true time of that minute here).
                    let offset = self.clients[c].wall(t_resp) - t_resp as i64;
                    let base = (receipt - offset).max(0) as u64;
                    let at = base
                        + HOUR as u64
                        + (self.draw(c, b"ready", instance) * (5 * HOUR) as f64) as u64;
                    self.clients[c].pay_queue.push((at, idx));
                }
                self.log.count(if t >= self.tl.tw {
                    "window invoices"
                } else {
                    "warm-up invoices"
                });
            }
            Ok(a) if a.result == wire::RequestInvoiceResult::WrongPeriod => {
                let p = &mut self.clients[c].purchases[idx];
                p.base_week = None;
                p.req_attempt = 0;
                p.retry_due = Some(w + DAY);
                self.log.count("request_invoice wrong_period");
            }
            Ok(_) => {
                self.clients[c].purchases[idx].state = PState::Failed;
                self.log.count("request_invoice refused");
            }
            Err(_) => {
                if self.clients[c].purchases[idx].req_attempt >= policy::CALL_ATTEMPTS {
                    let credits = std::mem::take(&mut self.clients[c].purchases[idx].credits);
                    self.clients[c].purchases[idx].state = PState::Failed;
                    for tk in credits {
                        // A credit whose key id is not an ES key (mutant M2b) is not kept.
                        let Some(e) = self.schedule.key_by_id(tk.key_id()).map(|k| k.epoch) else {
                            continue;
                        };
                        self.clients[c].credits.push(HeldCredit {
                            token: tk,
                            epoch: e,
                            source: instance,
                        });
                    }
                    self.log.count("request_invoice lost");
                }
            }
        }
    }

    fn blind_sign(&mut self, c: usize, idx: usize, t: u64, run: u64, automatic: bool) {
        let (instance, attempt, xmr, base, seed, invoice_id, claim_key, rogue) = {
            let p = &mut self.clients[c].purchases[idx];
            let a = p.attempt;
            p.attempt += 1;
            (
                p.instance,
                a,
                p.xmr,
                p.base_week.unwrap(),
                p.seed,
                p.invoice_id,
                p.claim_key,
                p.rogue,
            )
        };
        let idb = self.clients[c].id.to_be_bytes();
        let crash = prf_unit(
            &derive32(self.cfg.seeds.fault, &[b"crash"]),
            &[
                &idb[..],
                &instance.to_be_bytes(),
                &(attempt as u64).to_be_bytes(),
            ]
            .concat(),
        ) < 0.05;
        let mut fault = self.issuer_fault(c, instance, attempt, b"sign");
        if self.cfg.fail_sign.contains(&(c as u32, instance, attempt)) {
            fault = IssuerFault::Unavailable;
        }
        if crash && fault == IssuerFault::None {
            fault = IssuerFault::LoseAnswer;
        }
        let product = if xmr {
            Product::PackXmr
        } else {
            Product::PackCredits
        };
        let layout = product.layout(self.schedule, base).unwrap();
        let digest = layout.digest();
        let schedule = self.schedule;
        let kind = if xmr {
            FlowKind::PackXmr
        } else {
            FlowKind::PackCredits
        };
        let mutant = self.cfg.mutant;
        let custom = matches!(
            mutant,
            Mutant::M1NonceFromInvoice
                | Mutant::M1bNonceFromInvoiceLabel
                | Mutant::M2PerInvoiceKey
                | Mutant::M2bServerKeyId
                | Mutant::M5aNoBlinding
                | Mutant::M5bSquareBlinding
        );
        let (state, tokens, t_resp) = if custom {
            let rogue_pk = rogue.map(|i| self.rogue[i].1.clone());
            let prepared = mutant_blind(
                schedule,
                &seed,
                &layout,
                mutant,
                &invoice_id,
                rogue_pk.as_ref(),
            );
            let blinded: Vec<u8> = prepared.iter().flat_map(|p| p.blinded).collect();
            // The rogue signers are taken out of the world for the call and put back after it.
            let rogue_keys = std::mem::take(&mut self.rogue);
            let rogue_signer = rogue.map(|i| &rogue_keys[i].0);
            let mut extra_req = Vec::new();
            if mutant == Mutant::M2bServerKeyId {
                extra_req.push(("server_key_id", server_key_id(&invoice_id).to_vec()));
            }
            if let Some(pk) = &rogue_pk {
                extra_req.push(("accepted_key_spki", pk.to_spki()));
            }
            let (r, t_resp) = self.with_issuer(c, t, instance, attempt, kind, automatic, run, fault, extra_req, |link| {
                let req = wire::BlindSignRequest {
                    version: 1,
                    invoice_id: invoice_id.to_vec(),
                    claim_key: claim_key.to_vec(),
                    blinded: blinded.clone(),
                };
                match rogue_signer {
                    // M2: the issuer layer answers with signatures under its per-invoice key.
                    Some(signer) => {
                        let st = link.issuer.invoice_status_at(
                            wire::InvoiceStatusRequest { version: 1, invoice_id: invoice_id.to_vec(), claim_key: claim_key.to_vec() },
                            link.t,
                        );
                        let confirmed = st.as_ref().is_ok_and(|s| s.state == wire::InvoiceState::Signed as i32 || s.credited_atomic >= 1);
                        let resp = if confirmed {
                            let mut sigs = Vec::new();
                            for b in blinded.chunks(256) {
                                let block: [u8; 256] = b.try_into().unwrap();
                                sigs.extend_from_slice(&signer.blind_sign(&block).unwrap_or([0; 256]));
                            }
                            wire::BlindSignResponse { state: wire::InvoiceState::Signed as i32, blind_signatures: sigs, credited_atomic: 0, seen_atomic: 0 }
                        } else {
                            wire::BlindSignResponse { state: wire::InvoiceState::AwaitingPayment as i32, ..Default::default() }
                        };
                        record_mutant_sign(link, &req, &resp);
                        Ok(resp)
                    }
                    None => transport::block_on(<IssuerLink<'_> as ghost_client_net::issuer_client::IssuerRpc>::blind_sign(link, req)),
                }
            });
            self.rogue = rogue_keys;
            match r {
                Ok(resp) if resp.state == wire::InvoiceState::Signed as i32 => {
                    let toks = mutant_finalize(&prepared, &resp.blind_signatures);
                    (resp.state, toks, t_resp)
                }
                Ok(resp) => (resp.state, Vec::new(), t_resp),
                Err(_) => (-1, Vec::new(), t_resp),
            }
        } else {
            let (r, t_resp) = self.with_issuer(
                c,
                t,
                instance,
                attempt,
                kind,
                automatic,
                run,
                fault,
                Vec::new(),
                |link| {
                    transport::block_on(issuer_flow::blind_sign(
                        link,
                        schedule,
                        &invoice_id,
                        &claim_key,
                        &seed,
                        product,
                        base,
                        &digest,
                    ))
                },
            );
            match r {
                Ok(a) => (a.state as i32, a.tokens, t_resp),
                Err(IssuerError::Timeout) => (-1, Vec::new(), t_resp),
                Err(_) => (-1, Vec::new(), t_resp),
            }
        };
        if fault == IssuerFault::LoseAnswer {
            self.clients[c].crash_pending = true;
            self.log.count("client crashes after sending BlindSign");
        }
        self.log.sign_outcomes.push((
            c as u32,
            instance,
            attempt,
            if fault == IssuerFault::LoseAnswer {
                -1
            } else {
                state
            },
        ));
        if state == wire::InvoiceState::Signed as i32
            && !tokens.is_empty()
            && fault != IssuerFault::LoseAnswer
        {
            let w_resp = self.clients[c].wall(t_resp);
            let eligible = self.pack_eligible(c, instance, w_resp);
            self.store_tokens(c, tokens, &layout, instance, eligible);
            let p = &mut self.clients[c].purchases[idx];
            p.state = PState::Done;
            let ti = p.truth;
            let cl = &mut self.clients[c];
            cl.coverage_end = cl.coverage_end.max(base as i64 + 4);
            if let Some(ti) = ti {
                self.truth.invoices[ti].finalized = Some(t_resp);
            }
            if matches!(
                self.clients[c].spec.kind,
                ClientKind::Invitee | ClientKind::Sybil
            ) && self.clients[c].first_pack_eligible.is_none()
                && xmr
            {
                self.clients[c].first_pack_eligible = Some(eligible);
            }
            self.log.count(if t >= self.tl.tw {
                "window packs signed"
            } else {
                "warm-up packs signed"
            });
        } else if state == wire::InvoiceState::Expired as i32
            || state == wire::InvoiceState::OtherRequestIssued as i32
        {
            self.clients[c].purchases[idx].state = PState::Failed;
            self.log.count("packs expired or refused");
        } else if self.clients[c].purchases[idx].attempt >= policy::BLIND_SIGN_ATTEMPTS
            && mutant != Mutant::M16IssuerForcesRetries
        {
            self.clients[c].purchases[idx].state = PState::Failed;
            self.log.count("packs lost after the attempt cap");
        }
    }

    fn pack_eligible(&mut self, c: usize, instance: u64, w: i64) -> i64 {
        let first_invitee_pack = self.cfg.mutant == Mutant::M13PaidOnboarding
            && matches!(
                self.clients[c].spec.kind,
                ClientKind::Invitee | ClientKind::Sybil
            )
            && self.clients[c].first_pack_eligible.is_none();
        if self.cfg.mutant == Mutant::M3ImmediateEligible || first_invitee_pack {
            return policy::floor_minute(w);
        }
        let mut r = Rng::new(
            self.cfg.seeds.sched,
            &[
                b"activate",
                &self.clients[c].id.to_be_bytes(),
                &instance.to_be_bytes(),
            ],
        );
        policy::pack_eligible_minute(w, &mut || r.uniform(), self.clients[c].spec.high)
    }

    /// The slot of a revocation's spare tokens answered at `w`: the pack rule, uncapped, in both
    /// modes (§19.24 point 13, §19.26; `TrialSteps` through `Slots.revocationEligibleMinute`).
    fn revocation_eligible(&mut self, c: usize, instance: u64, w: i64) -> i64 {
        let mut r = Rng::new(
            self.cfg.seeds.sched,
            &[
                b"activate",
                &self.clients[c].id.to_be_bytes(),
                &instance.to_be_bytes(),
            ],
        );
        policy::revocation_eligible_minute(w, &mut || r.uniform(), self.clients[c].spec.high)
    }

    /// The slot of an onboarding trial of base week `base` finalized at `w` (Q30 caps its
    /// HIGH-mode extra days at the trial's last week).
    fn trial_eligible(&mut self, c: usize, instance: u64, base: u64, w: i64) -> i64 {
        let mut r = Rng::new(
            self.cfg.seeds.sched,
            &[
                b"activate",
                &self.clients[c].id.to_be_bytes(),
                &instance.to_be_bytes(),
            ],
        );
        policy::trial_eligible_minute(
            w,
            base as i64,
            &mut || r.uniform(),
            self.clients[c].spec.high,
        )
    }

    /// Stores finalized tokens in layout order: ACCESS as held tokens, INVITE as invites, CREDIT as
    /// own credits (a Sybil's credit is known to the attacker).
    fn store_tokens(
        &mut self,
        c: usize,
        tokens: Vec<Token>,
        layout: &Layout,
        source: u64,
        eligible: i64,
    ) {
        if self.rec.debug {
            let text = format!(
                "{} tokens from flow {source:x}, eligible {eligible}",
                tokens.len()
            );
            self.rec.note(c as u32, self.now, text);
        }
        for (pos, tk) in layout.positions().iter().zip(tokens) {
            match pos.kind {
                Kind::Access => self.clients[c].tokens.push(HeldToken {
                    week: pos.epoch,
                    slot: pos.slot.unwrap(),
                    token: tk,
                    eligible,
                    source,
                    reserved: None,
                    retry_after: None,
                }),
                Kind::Invite => {
                    let k = self.clients[c].invites.len();
                    // Draws keyed on the invite's identity (pack flow, position in the pack), never
                    // on its index in the list, which moves when packs finalize in another order.
                    let ordinal = self.clients[c]
                        .invites
                        .iter()
                        .filter(|h| h.source == source)
                        .count() as u8;
                    let key = source.wrapping_mul(8).wrapping_add(u64::from(ordinal));
                    let revoke = if self.draw(c, b"revoke", key) < 0.05 {
                        let w = policy::week_start(pos.epoch as i64 * 4 + 1)
                            + (self.draw(c, b"revoke-at", key) * (10 * DAY) as f64) as i64;
                        let inst = self.clients[c].next_flow(super::client::FlowSeq::Revocation);
                        Some((w.max(eligible), inst, 0))
                    } else {
                        None
                    };
                    let honest = self.clients[c].spec.kind != ClientKind::Sybil;
                    self.clients[c].invites.push(HeldInvite {
                        token: tk,
                        epoch: pos.epoch,
                        eligible,
                        source,
                        ordinal,
                        given: false,
                        revoke,
                    });
                    if honest && revoke.is_none() {
                        self.invite_pool.push((c, k));
                    }
                }
                Kind::Credit => {
                    self.minted.insert(tk.as_bytes().to_vec());
                    if self.clients[c].spec.kind == ClientKind::Sybil {
                        self.truth.attacker_tokens.push(tk.as_bytes().to_vec());
                    }
                    if let Some(d) = &mut self.clients[c].drop_out {
                        if d.credit.is_none() && !d.done {
                            d.credit = Some(tk.clone());
                            continue;
                        }
                    }
                    self.clients[c].credits.push(HeldCredit {
                        token: tk,
                        epoch: pos.epoch,
                        source,
                    });
                }
            }
        }
    }

    fn refresh(&mut self, c: usize, idx: usize, t: u64, run: u64) {
        let (token, epoch, instance, attempt) = {
            let r = &mut self.clients[c].received[idx];
            let a = r.attempt;
            r.attempt += 1;
            (r.token.clone(), r.epoch, r.instance, a)
        };
        let seed = derive32(
            self.cfg.seeds.token,
            &[
                b"refresh",
                &self.clients[c].id.to_be_bytes(),
                &instance.to_be_bytes(),
            ],
        );
        let digest = Product::Refresh
            .layout(self.schedule, epoch)
            .unwrap()
            .digest();
        let schedule = self.schedule;
        let fault = self.issuer_fault(c, instance, attempt, b"refresh");
        let (r, _) = self.with_issuer(
            c,
            t,
            instance,
            attempt,
            FlowKind::Refresh,
            true,
            run,
            fault,
            Vec::new(),
            |link| {
                transport::block_on(issuer_flow::refresh_credit(
                    link, schedule, &token, &seed, &digest,
                ))
            },
        );
        let w = self.issuer_wall(c, t);
        match r {
            Ok(a) => {
                self.clients[c].received.remove(idx);
                if let Some(fresh) = a.token {
                    self.minted.insert(fresh.as_bytes().to_vec());
                    self.clients[c].credits.push(HeldCredit {
                        token: fresh,
                        epoch,
                        source: instance,
                    });
                    self.log.count("credits refreshed");
                }
            }
            Err(_) => {
                if attempt + 1 >= policy::CALL_ATTEMPTS {
                    self.clients[c].received.remove(idx);
                    self.log.count("refreshes lost");
                } else {
                    let u = self.draw(c, b"refresh-retry", instance);
                    self.clients[c].received[idx].retry =
                        policy::next_due_after_send(0, None, w, u);
                }
            }
        }
    }

    fn revoke(&mut self, c: usize, idx: usize, t: u64, run: u64) {
        let (token, (_, instance, attempt)) = {
            let inv = &mut self.clients[c].invites[idx];
            let r = inv.revoke.unwrap();
            (inv.token.clone(), r)
        };
        let w = self.issuer_wall(c, t);
        let base = policy::week(w) as u64;
        let seed = derive32(
            self.cfg.seeds.token,
            &[
                b"revoke",
                &self.clients[c].id.to_be_bytes(),
                &instance.to_be_bytes(),
            ],
        );
        let digest = Product::Trial.layout(self.schedule, base).unwrap().digest();
        let schedule = self.schedule;
        let fault = self.issuer_fault(c, instance, attempt, b"revoke");
        let (r, t_resp) = self.with_issuer(
            c,
            t,
            instance,
            attempt,
            FlowKind::Revocation,
            true,
            run,
            fault,
            Vec::new(),
            |link| {
                transport::block_on(issuer_flow::redeem_invite(
                    link, schedule, &token, &seed, base, &digest,
                ))
            },
        );
        match r {
            Ok(a) => {
                self.clients[c].invites[idx].revoke = None;
                if a.result == wire::RedeemInviteResult::Ok {
                    let w_resp = self.clients[c].wall(t_resp);
                    let eligible = self.revocation_eligible(c, instance, w_resp);
                    self.store_tokens(
                        c,
                        a.tokens,
                        &Layout::trial(self.schedule, base).unwrap(),
                        instance,
                        eligible,
                    );
                    self.log
                        .revocations
                        .push((c as u32, instance, t_resp, eligible));
                    self.log.count("invites revoked");
                }
            }
            Err(_) => {
                let inv = &mut self.clients[c].invites[idx];
                if attempt + 1 >= policy::CALL_ATTEMPTS {
                    inv.revoke = None;
                } else {
                    inv.revoke = Some((w + DAY, instance, attempt + 1));
                }
            }
        }
    }

    fn claim(&mut self, c: usize, t: u64, run: u64) {
        let (instance, attempt, claim_id, credits, address) = {
            let cf = self.clients[c].claim.as_mut().unwrap();
            let a = cf.attempt;
            cf.attempt += 1;
            (
                cf.instance,
                a,
                cf.claim_id,
                cf.credits.clone(),
                cf.address.clone(),
            )
        };
        let foreign = unminted(&self.minted, credits.iter().map(|t| &t.as_bytes()[..]));
        assert_eq!(
            foreign, 0,
            "a claim presents {foreign} credits no issuer of the world minted (§19.16 point 1)"
        );
        let schedule = self.schedule;
        let fault = self.issuer_fault(c, instance, attempt, b"claim");
        // M12: the claim rides on the purchase's flow scope (the same instance's label).
        let flow_instance = if self.cfg.mutant == Mutant::M12ClaimInPurchaseRun {
            self.clients[c]
                .purchases
                .iter()
                .rev()
                .find(|p| matches!(p.state, PState::Prepared | PState::Invoiced | PState::Done))
                .map_or(instance, |p| p.instance)
        } else {
            instance
        };
        // The claim's own flow instance (R5, what J6a counts), whatever scope M12 makes it ride on;
        // an honest claim's scope is its own, so the two coincide.
        let own_flow = {
            let idb = self.clients[c].id.to_be_bytes();
            let l = derive32(
                self.cfg.seeds.sched,
                &[
                    b"flow",
                    &idb,
                    &instance.to_be_bytes(),
                    &(attempt as u64).to_be_bytes(),
                    &run.to_be_bytes(),
                ],
            );
            u64::from_be_bytes(l[..8].try_into().unwrap())
        };
        let (r, _) = self.with_issuer(
            c,
            t,
            flow_instance,
            attempt,
            FlowKind::Claim,
            true,
            run,
            fault,
            Vec::new(),
            |link| {
                link.truth.instance = instance;
                link.truth.flow = own_flow;
                transport::block_on(issuer_flow::claim_payout(
                    link, schedule, &claim_id, &credits, &address,
                ))
            },
        );
        let w = self.issuer_wall(c, t);
        let cf = self.clients[c].claim.as_mut().unwrap();
        match r {
            Ok(_) => {
                cf.done = true;
                self.log.count("claims answered");
            }
            Err(_) => {
                if attempt + 1 >= policy::CALL_ATTEMPTS {
                    cf.done = true;
                } else {
                    cf.due = w + DAY;
                }
            }
        }
    }

    // ---------------------------------------------------------------------------------------------
    // Relay sessions and the redeem lane.
    // ---------------------------------------------------------------------------------------------

    fn active_namespaces(&self, c: usize, t: u64) -> Vec<[u8; 32]> {
        let cl = &self.clients[c];
        let wk = week(t);
        cl.namespaces
            .iter()
            .enumerate()
            .filter(|(i, _)| {
                *i == 0
                    || prf_unit(
                        &cl.user_key,
                        &[&(*i as u64).to_be_bytes()[..], &wk.to_be_bytes()].concat(),
                    ) < 0.5
            })
            .map(|(_, ns)| *ns)
            .collect()
    }

    /// The wait from READY to the redeem lane's first step of a session, U[0, 30 s]
    /// (`RedeemLane.firstWait`): client randomness of the run.
    fn lane_first_wait(&self, c: usize, run: u64) -> u64 {
        let key = derive32(
            self.cfg.seeds.sched,
            &[b"lane-step", &self.clients[c].id.to_be_bytes()],
        );
        (prf_unit(&key, &run.to_be_bytes()) * 30.0) as u64
    }

    /// A relay session starting at `t` (READY), a background job's (`background`) or a foreground
    /// one; no call is made at or after `cutoff` (the payment screen closes the session, §19.11).
    fn relay_session(&mut self, c: usize, t: u64, run: u64, cutoff: u64, background: bool) -> u32 {
        if !self.clients[c].onboarded {
            return 0;
        }
        let mut pairs: Vec<([u8; 32], bool, u8)> = Vec::new();
        for ns in self.active_namespaces(c, t) {
            pairs.push((ns, false, 0));
        }
        let listens: Vec<[u8; 32]> = self.clients[c]
            .drops
            .iter()
            .filter(|d| d.until > t)
            .map(|d| d.ns)
            .collect();
        for ns in listens {
            pairs.push((ns, false, 1));
        }
        let w = self.clients[c].wall(t);
        let drop_due = self.clients[c].drop_out.as_ref().is_some_and(|d| {
            let due = if self.cfg.mutant == Mutant::M18DropAtEligibleMinute {
                self.clients[c].first_pack_eligible.unwrap_or(i64::MAX)
            } else {
                d.due
            };
            !d.done && due <= w
        });
        if drop_due {
            let ns = self.clients[c].drop_out.as_ref().unwrap().ns;
            pairs.push((ns, true, 2));
        }
        // A client-random order of pairs (circuit key, run).
        let key = self.clients[c].circuit_key;
        // (order key, namespace, drop write, pair tag, relay)
        type Ordered = ([u8; 32], [u8; 32], bool, u8, u8);
        let mut order: Vec<Ordered> = Vec::new();
        for (ns, write, tag) in pairs {
            for k in 0..3u8 {
                let h = derive32(0, &[&key, &run.to_be_bytes(), &ns, &[k]]);
                order.push((h, ns, write, tag, k));
            }
        }
        // Drop pairs first (the drop write and the listening on invite drops get tokens before
        // the client's own namespaces, so their times follow the session times only), then a
        // client-random order.
        order.sort_by_key(|&(h, _, _, tag, _)| (tag == 0, h));
        let mut calls = 0u32;
        // The relays that refused a period in this session (one lane step, `RedeemLane.step`).
        let mut refused = [false; 3];
        if !background {
            // A foreground session: every pair redeems as it comes (the lane steps every minute
            // while the user is there) and syncs.
            let mut tc = t;
            for &(_, ns, write_drop, tag, k) in &order {
                if tc + 3 >= cutoff {
                    break;
                }
                let n = self.pair_step(
                    c,
                    k,
                    ns,
                    tc,
                    run,
                    write_drop,
                    tag == 1,
                    &mut refused,
                    Pass::Both,
                );
                calls += n;
                // A pair with nothing to do takes no time: the client's invisible state (a drop
                // listen without a capability, a deferred redemption) must not move its visible calls.
                tc += u64::from(n);
            }
        } else {
            // A background session (§11.6, Q29, §19.23 point 5): the lanes sync every pair with a
            // usable capability from READY; the redeem lane's first step comes at READY + U[0, 30 s]
            // (`RedeemLane.firstWait`). It runs if the lanes still run then, or if the redeem hold
            // (`RedeemHold`) keeps the session open for it: armed by the pending WRITE needs at the
            // session's start, read before the lanes, and nothing else. A capability the step
            // installs is used from the next session.
            let w0 = self.clients[c].wall(t);
            let armed = order.iter().any(|&(_, ns, write_drop, _, k)| {
                let cl = &self.clients[c];
                let needs_write = write_drop
                    || cl
                        .outbox
                        .iter()
                        .any(|(n, _, _, wr)| *n == ns && !wr[usize::from(k)]);
                need_of(cl.caps.get(&(k, ns)), needs_write, w0)
                    .is_some_and(|(kind, _)| kind == NeedKind::Write)
            });
            let mut tc = t;
            for &(_, ns, write_drop, tag, k) in &order {
                let n = self.pair_step(
                    c,
                    k,
                    ns,
                    tc,
                    run,
                    write_drop,
                    tag == 1,
                    &mut refused,
                    Pass::Lanes,
                );
                calls += n;
                tc += u64::from(n);
            }
            let lanes_end = tc;
            let step_at = t + self.lane_first_wait(c, run);
            self.log.count("background sessions");
            if armed {
                self.log.count("background sessions armed");
            }
            if step_at < lanes_end || armed {
                // Held past its lanes when the step comes after them (E30); a step during the lanes
                // is placed after their calls (the world's calls of one session are sequential).
                let held = step_at >= lanes_end;
                let mut ts = step_at.max(lanes_end);
                let before = calls;
                for &(_, ns, write_drop, tag, k) in &order {
                    let n = self.pair_step(
                        c,
                        k,
                        ns,
                        ts,
                        run,
                        write_drop,
                        tag == 1,
                        &mut refused,
                        Pass::Step,
                    );
                    calls += n;
                    ts += u64::from(n);
                }
                if held {
                    self.log
                        .holds
                        .push((c as u32, lanes_end, ts, calls - before));
                }
            } else {
                self.log.count("background lane steps missed");
            }
        }
        if drop_due {
            let d = self.clients[c].drop_out.as_mut().unwrap();
            if d.written.iter().all(|&x| x) {
                d.done = true;
                self.log.count("drops written");
            } else if w > d.due + 7 * DAY {
                d.done = true;
                self.log.count("drops not written");
            }
        }
        calls
    }

    /// Drop pairs of relay `k` still needing a token of `week`: the invite drops the client
    /// listens to and its own pending drop write, without a capability reaching the week's end.
    fn drop_reserve(&self, c: usize, k: u8, week: i64, now_est: i64) -> usize {
        let cl = &self.clients[c];
        let end = policy::week_start(week + 1);
        let lacks = |ns: &[u8; 32]| {
            cl.caps
                .get(&(k, *ns))
                .is_none_or(|cp| (cp.expiry as i64) < end || (cp.expiry as i64) <= now_est)
        };
        let listens = cl
            .drops
            .iter()
            .filter(|d| d.until as i64 > now_est && lacks(&d.ns))
            .count();
        let write = cl
            .drop_out
            .as_ref()
            .is_some_and(|d| !d.done && !d.written[usize::from(k)] && lacks(&d.ns));
        listens + usize::from(write)
    }

    fn relay_truth(&self, c: usize, run: u64, source: u64, t: u64) -> RelayTruth {
        let cl = &self.clients[c];
        RelayTruth {
            client: c as u32,
            run,
            process: cl.process,
            // The client's state: two relays answered it since the device clock was last set, so
            // its relay-facing clock is corrected (M11 has the answers too and ignores them, which
            // is what J8 must see).
            corrected: cl.answered.len() >= 2 && cl.answered_epoch == cl.clock_epoch(t),
            source,
            skewed: cl.skewed(t),
            skew: cl.wall(t) - t as i64,
            retry: false,
        }
    }

    /// One pair of a session: the redeem lane's part, then the sync (`pass` selects them).
    #[allow(clippy::too_many_arguments)]
    fn pair_step(
        &mut self,
        c: usize,
        k: u8,
        ns: [u8; 32],
        t: u64,
        run: u64,
        drop_write: bool,
        listen: bool,
        refused: &mut [bool; 3],
        pass: Pass,
    ) -> u32 {
        let mut calls = 0;
        let label = transport::label(
            &derive32(0, &[&self.clients[c].circuit_key, &run.to_be_bytes(), &ns]),
            &self.relays[usize::from(k)].onion,
        );
        let w = self.clients[c].wall(t);
        let m11 = self.cfg.mutant == Mutant::M11DeviceClockPeriod;
        // A device clock set since the last observation makes the relay-facing offsets stale
        // (`ClockEstimate.observe`; the world's monotonic clock is true time).
        self.clients[c].clock.observe(w, t as i64 * 1_000);
        // This relay's decisions run on its own clock once it answered (§12.5, §19.24 point 1);
        // M11 decides on the raw device clock whatever the relays answered.
        let relay_now = if m11 {
            w
        } else {
            self.clients[c].clock.relay_now(u64::from(k), w)
        };
        let now_est = if m11 { w } else { self.clients[c].clock.now(w) };
        let cap_ok = |cl: &Client| {
            cl.caps
                .get(&(k, ns))
                .is_some_and(|cp| (cp.expiry as i64) > now_est)
        };
        let needs_write = drop_write
            || self.clients[c]
                .outbox
                .iter()
                .any(|(n, _, _, wr)| *n == ns && !wr[usize::from(k)]);
        let cap = self.clients[c].caps.get(&(k, ns)).cloned();
        let need = need_of(cap.as_ref(), needs_write, w);
        // A relay that refused a period in this session is planned again at the next one, on the
        // period and the clock its answer set (`RedeemLane.step`). A background session's lanes
        // redeem nothing: its redeem lane's step does (`Pass::Step`).
        if let Some((kind, reason)) =
            need.filter(|_| pass != Pass::Lanes && !refused[usize::from(k)])
        {
            {
                let rw_ = if m11 {
                    policy::week(w)
                } else {
                    self.clients[c].clock.week(u64::from(k), w)
                };
                let key = (k, ns, kind == NeedKind::Write, rw_);
                // `EngineMemory.firstSeen(need, now)`: the device wall clock.
                let first = *self.clients[c].first_seen.entry(key).or_insert(w);
                let prf = prf_unit(
                    &self.clients[c].prf_key,
                    &[&[k][..], &ns, &[kind as u8], &rw_.to_be_bytes()].concat(),
                );
                // `SyncTables.usableWriteExpiry`: the pair's write capability, whatever its time.
                let write_expiry = cap.as_ref().map(|cp| cp.expiry as i64);
                let relay_onion = {
                    let o = Onion::parse(&self.relays[usize::from(k)].onion).unwrap();
                    policy::Onion {
                        key: o.pubkey,
                        port: o.port,
                    }
                };
                let d = policy::plan(
                    kind,
                    reason,
                    relay_onion,
                    &self.slots,
                    relay_now,
                    rw_,
                    true,
                    first,
                    write_expiry,
                    prf,
                );
                if let Decision::Redeem {
                    week: target,
                    slots,
                    due,
                } = d
                {
                    if due <= relay_now {
                        // tx1 (`RedeemLane.reserve`): the pair's pending reservation of the week is
                        // retried identically (R8), never after its week.
                        let held = self.clients[c].tokens.iter().position(|tk| {
                            tk.week as i64 == target
                                && tk.reserved.is_some_and(|(rk, rns, _)| rk == k && rns == ns)
                        });
                        let retry_after = held.and_then(|i| self.clients[c].tokens[i].retry_after);
                        let step = policy::reserve_step(
                            held.is_some(),
                            retry_after,
                            target,
                            relay_now,
                            write_expiry,
                        );
                        let fresh = match (step, held) {
                            (ReserveStep::Retry, Some(i)) => {
                                calls += self.redeem(c, k, ns, i, t, run, label, refused);
                                false
                            }
                            (ReserveStep::Drop, Some(i)) => {
                                self.clients[c].tokens.remove(i);
                                self.log.count("reservations dropped after their week");
                                false
                            }
                            (ReserveStep::Fresh, _) => true,
                            _ => false,
                        };
                        let minute = policy::floor_minute(w);
                        let usable = |tk: &HeldToken| {
                            tk.reserved.is_none()
                                && tk.week as i64 == target
                                && slots.contains(&tk.slot)
                                && tk.eligible <= minute
                        };
                        // The client's own namespaces leave one token per pending drop pair (the
                        // drop write and the listening on invite drops) of this relay and week.
                        let drop_pair = drop_write || listen;
                        let reserve = if drop_pair || !fresh {
                            0
                        } else {
                            self.drop_reserve(c, k, target, now_est)
                        };
                        let free = self.clients[c]
                            .tokens
                            .iter()
                            .filter(|tk| usable(tk))
                            .count();
                        // `TokenStore.freshEligibleAccess`: the eligible token of the smallest
                        // nullifier (an order the issuer cannot know: the tokens are blind).
                        let pick = if free > reserve {
                            self.clients[c]
                                .tokens
                                .iter()
                                .enumerate()
                                .filter(|(_, tk)| usable(tk))
                                .min_by_key(|(_, tk)| tk.token.nullifier())
                                .map(|(i, _)| i)
                        } else {
                            None
                        };
                        match pick {
                            _ if !fresh => {}
                            Some(i) => {
                                calls += self.redeem(
                                    c,
                                    k,
                                    ns,
                                    i,
                                    t + u64::from(calls),
                                    run,
                                    label,
                                    refused,
                                )
                            }
                            None => {
                                let delay = (self.draw(c, b"need-surface", w as u64)
                                    * (12 * HOUR) as f64)
                                    as i64;
                                let cl = &mut self.clients[c];
                                if cl.needed_since.is_none() && cl.first_pack_done_or_paid() {
                                    cl.needed_since = Some(w);
                                    cl.need_surface = Some(w + delay);
                                }
                                self.log.count("entitlement needed");
                                if drop_pair && self.rec.debug {
                                    let ns6: String =
                                        ns[..6].iter().map(|b| format!("{b:02x}")).collect();
                                    let text = format!(
                                        "drop pair relay {k} ns {ns6}: no token of week {target} (free {free}, reserve {reserve})"
                                    );
                                    self.rec.note(c as u32, t, text);
                                }
                            }
                        }
                    }
                }
            }
        }
        if pass == Pass::Step {
            return calls;
        }
        let t2 = t + u64::from(calls);
        if !cap_ok(&self.clients[c]) {
            return calls;
        }
        let cap = self.clients[c].caps[&(k, ns)].token.clone();
        // Writes: outbox blobs and the drop blob.
        let pending: Vec<usize> = self.clients[c]
            .outbox
            .iter()
            .enumerate()
            .filter(|(_, (n, _, _, wr))| *n == ns && !wr[usize::from(k)])
            .map(|(i, _)| i)
            .collect();
        let mut tw_ = t2;
        for i in pending {
            let (data, hash) = {
                let o = &self.clients[c].outbox[i];
                (o.1.clone(), o.2)
            };
            let rid: [u8; 16] = self.clients[c].ns_rng.bytes();
            let req = rw::StoreBlobRequest {
                version: 1,
                blob_hash: hash.to_vec(),
                data,
                capability: Some(rw::Capability { token: cap.clone() }),
                ttl_seconds: 7 * 86_400,
                request_id: rid.to_vec(),
                namespace_id: ns.to_vec(),
            };
            let truth = self.relay_truth(c, run, 0, tw_);
            let World { relays, rec, .. } = self;
            let _ = transport::store(
                &mut relays[usize::from(k)],
                rec,
                tw_,
                label,
                truth,
                req,
                false,
            );
            self.clients[c].outbox[i].3[usize::from(k)] = true;
            self.clients[c].stores += 1;
            calls += 1;
            tw_ += 1;
        }
        self.clients[c].outbox.retain(|o| !o.3.iter().all(|&x| x));
        if drop_write {
            let (credit, inviter, data) = {
                let d = self.clients[c].drop_out.as_ref().unwrap();
                (d.credit.clone(), d.inviter, d.blob.clone())
            };
            let hash: Vec<u8> = Sha256::digest(&data).to_vec();
            let rid: [u8; 16] = self.clients[c].ns_rng.bytes();
            let req = rw::StoreBlobRequest {
                version: 1,
                blob_hash: hash.clone(),
                data,
                capability: Some(rw::Capability { token: cap.clone() }),
                ttl_seconds: 30 * 86_400,
                request_id: rid.to_vec(),
                namespace_id: ns.to_vec(),
            };
            let truth = self.relay_truth(c, run, 0, tw_);
            let World { relays, rec, .. } = self;
            let r = transport::store(
                &mut relays[usize::from(k)],
                rec,
                tw_,
                label,
                truth,
                req,
                true,
            );
            if r.is_ok() {
                self.clients[c].drop_out.as_mut().unwrap().written[usize::from(k)] = true;
                self.drop_blobs.insert((ns, hash), credit.clone());
                let _ = inviter;
            }
            calls += 1;
            tw_ += 1;
        }
        // The sync: list the pair (and, on a drop the client listens to, fetch new blobs).
        let cursor = self.clients[c]
            .cursors
            .get(&(k, ns))
            .cloned()
            .unwrap_or_default();
        let req = rw::ListNamespaceRequest {
            version: 1,
            namespace_id: ns.to_vec(),
            capability: Some(rw::Capability { token: cap.clone() }),
            cursor,
            limit: 64,
        };
        let truth = self.relay_truth(c, run, 0, tw_);
        let tick = std::time::Instant::now();
        let listed = {
            let World { relays, rec, .. } = self;
            transport::list(&mut relays[usize::from(k)], rec, tw_, label, truth, req)
        };
        *self.log.timings.entry("  lists").or_insert(0.0) += tick.elapsed().as_secs_f64();
        calls += 1;
        tw_ += 1;
        if let Ok(resp) = listed {
            if !resp.next_cursor.is_empty() {
                self.clients[c]
                    .cursors
                    .insert((k, ns), resp.next_cursor.clone());
            }
            if listen {
                for h in resp.blob_hashes {
                    let di = self.clients[c].drops.iter().position(|d| d.ns == ns);
                    let Some(di) = di else { continue };
                    if !self.clients[c].drops[di].seen.insert(h.clone()) {
                        continue;
                    }
                    let rid: [u8; 16] = self.clients[c].ns_rng.bytes();
                    let req = rw::GetBlobRequest {
                        version: 1,
                        blob_hash: h.clone(),
                        capability: Some(rw::Capability { token: cap.clone() }),
                        request_id: rid.to_vec(),
                    };
                    let truth = self.relay_truth(c, run, 0, tw_);
                    let got = {
                        let World { relays, rec, .. } = self;
                        transport::get(&mut relays[usize::from(k)], rec, tw_, label, truth, req)
                    };
                    calls += 1;
                    tw_ += 1;
                    if got.is_ok() {
                        // The drop's plaintext: the credit of the invitee's first XMR pack, or a
                        // dummy. Every replica carries the same blob; the first read delivers it,
                        // in every world at that world's own read time (relay activity).
                        if let Some(Some(credit)) = self.drop_blobs.remove(&(ns, h.clone())) {
                            let (invitee, refresh) = {
                                let d = &self.clients[c].drops[di];
                                (d.invitee, d.refresh)
                            };
                            self.deliver_credit(c, credit, w, invitee, tw_ - 1, refresh);
                        }
                    }
                }
            }
        }
        calls
    }

    /// The inviter's client `c` read `credit` from the drop of `invitee` at device time `w` (true
    /// time `t_read`): it becomes a refresh due at one of the drop's two pre-drawn times `refresh`
    /// (`DropSteps.credit`, `RefreshPlan.due`, Q31, §19.26), never at a time the read sets.
    fn deliver_credit(
        &mut self,
        c: usize,
        credit: Token,
        w: i64,
        invitee: usize,
        t_read: u64,
        refresh: (i64, i64),
    ) {
        // A credit whose key id is not an ES key (mutant M2b) is not kept.
        let Some(epoch) = self.schedule.key_by_id(credit.key_id()).map(|k| k.epoch) else {
            return;
        };
        if self.cfg.mutant == Mutant::M21SpendReceivedCredit {
            self.clients[c].credits.push(HeldCredit {
                token: credit,
                epoch,
                source: 0,
            });
            self.log.count("received credits kept without refresh");
            return;
        }
        // The read picks only which pre-drawn time applies; a credit whose due time would precede
        // its read (after the issuer's refresh cut) is dropped, never refreshed at the read.
        let Some(due) = policy::refresh_due(refresh.0, refresh.1, epoch as i64, w) else {
            self.log
                .count("received credits dropped after their refresh cut");
            return;
        };
        let drawn = if w <= refresh.0 { refresh.0 } else { refresh.1 };
        self.log.count(if due < drawn {
            "refreshes due at their cut"
        } else if w <= refresh.0 {
            "refreshes due at the first time"
        } else {
            "refreshes due at the second time"
        });
        let instance = self.clients[c].next_flow(super::client::FlowSeq::Refresh);
        let key = (c as u32, invitee as u32);
        self.log.receipts.push((key.0, key.1, t_read, due));
        self.clients[c].received.push(Received {
            token: credit,
            epoch,
            due,
            instance,
            attempt: 0,
            retry: None,
        });
        self.log.count("credits received");
    }

    #[allow(clippy::too_many_arguments)]
    fn redeem(
        &mut self,
        c: usize,
        k: u8,
        ns: [u8; 32],
        i: usize,
        t: u64,
        run: u64,
        label: [u8; 32],
        refused: &mut [bool; 3],
    ) -> u32 {
        let tick = std::time::Instant::now();
        let n = self.redeem_inner(c, k, ns, i, t, run, label, refused);
        *self.log.timings.entry("  redeems").or_insert(0.0) += tick.elapsed().as_secs_f64();
        n
    }

    #[allow(clippy::too_many_arguments)]
    fn redeem_inner(
        &mut self,
        c: usize,
        k: u8,
        ns: [u8; 32],
        i: usize,
        t: u64,
        run: u64,
        label: [u8; 32],
        refused: &mut [bool; 3],
    ) -> u32 {
        let (token, reserved, source) = {
            let tk = &self.clients[c].tokens[i];
            (tk.token.clone(), tk.reserved, tk.source)
        };
        // Ground truth for the completeness check: every presented token's nullifier must appear
        // in some relay view.
        self.truth.presented.push(token.nullifier());
        let request_id: [u8; 16] = match reserved {
            Some((_, _, rid)) => rid,
            None => {
                let cl = &mut self.clients[c];
                cl.redeems += 1;
                derive32(
                    cl.ns_seed,
                    &[b"redeem", &cl.id.to_be_bytes(), &cl.redeems.to_be_bytes()],
                )[..16]
                    .try_into()
                    .unwrap()
            }
        };
        let lose = prf_unit(
            &derive32(self.cfg.seeds.fault, &[b"redeem-timeout"]),
            &request_id,
        ) < 0.05;
        let w = self.clients[c].wall(t);
        let shift = self.shift_for(c);
        let mut truth = self.relay_truth(c, run, source, t);
        // An identical retry of an ambiguous redemption (R8); its first attempt may never have
        // reached the relay.
        truth.retry = reserved.is_some();
        // M2, M2b: the mutant client accepts keys from the issuer's answer, so it presents its
        // tokens whatever key id they carry (the production path refuses a key id the ES does not
        // list, R2): a raw redemption, which the relay refuses and records; the token is dropped.
        if matches!(
            self.cfg.mutant,
            Mutant::M2PerInvoiceKey | Mutant::M2bServerKeyId
        ) && self.schedule.key_by_id(token.key_id()).is_none()
        {
            let World { relays, rec, .. } = self;
            let node = &mut relays[usize::from(k)];
            let req = rw::RedeemTokenRequest {
                version: 1,
                token: token.as_bytes().to_vec(),
                namespace_id: ns.to_vec(),
                request_id: request_id.to_vec(),
            };
            let mut link = RelayLink {
                node,
                rec,
                t,
                label,
                truth,
                lose_answer: false,
                shift_minutes: shift,
                answered: false,
            };
            let _ = transport::block_on(
                <RelayLink<'_> as ghost_client_net::namespace_client::RedeemRpc>::redeem_token(
                    &mut link, req,
                ),
            );
            self.clients[c].tokens.remove(i);
            self.log.count("redemptions refused (mutant key)");
            return 1;
        }
        let schedule = self.schedule;
        let (r, answered) = {
            let World { relays, rec, .. } = self;
            let node = &mut relays[usize::from(k)];
            let address = node.address.clone();
            let mut link = RelayLink {
                node,
                rec,
                t,
                label,
                truth,
                lose_answer: lose && reserved.is_none(),
                shift_minutes: shift,
                answered: false,
            };
            let r = transport::block_on(redeem_with(
                &mut link,
                schedule,
                &address,
                ns,
                token.as_bytes(),
                request_id,
                w.max(0) as u64,
            ));
            (r, link.answered)
        };
        let _ = answered;
        match r {
            Ok(o) => {
                let wrong = o.result == rw::RedeemResult::WrongPeriod;
                self.clients[c].clock.record(
                    u64::from(k),
                    o.relay_minute as i64,
                    o.relay_period_id as i64,
                    w,
                    wrong,
                );
                // The relay-facing clock is corrected once two relays answered since the device
                // clock last changed: its offsets are taken against the wall clock
                // (`ClockEstimate.kt`), so a device clock set right mid-process makes them stale.
                let epoch = self.clients[c].clock_epoch(t);
                let cl = &mut self.clients[c];
                if cl.answered_epoch != epoch {
                    cl.answered.clear();
                    cl.answered_epoch = epoch;
                }
                cl.answered.insert(k);
                match o.result {
                    rw::RedeemResult::Ok => {
                        self.clients[c].caps.insert(
                            (k, ns),
                            Cap {
                                token: o.capability.unwrap(),
                                expiry: o.expiry_unix,
                            },
                        );
                        self.clients[c].tokens.remove(i);
                        self.log.count("redemptions ok");
                    }
                    rw::RedeemResult::Replayed => {
                        self.clients[c].tokens.remove(i);
                        self.log.count("redemptions replayed");
                    }
                    _ => {
                        // `RedeemLane.apply`: a token of a week after the relay's period keeps its
                        // reservation and is retried identically from start(week) − 23 h on the
                        // relay's clock; any other is deleted (R8: never shown elsewhere).
                        let token_week = self.clients[c].tokens[i].week as i64;
                        match policy::wrong_period_retry_after(token_week, o.relay_period_id as i64)
                        {
                            Some(after) => {
                                let tk = &mut self.clients[c].tokens[i];
                                tk.reserved = Some((k, ns, request_id));
                                tk.retry_after = Some(after);
                            }
                            None => {
                                self.clients[c].tokens.remove(i);
                            }
                        }
                        refused[usize::from(k)] = true;
                        self.log.count("redemptions wrong_period");
                    }
                }
            }
            Err(RelayError::Timeout) => {
                self.clients[c].tokens[i].reserved = Some((k, ns, request_id));
                self.log.count("redemptions timed out");
                if self.cfg.mutant == Mutant::M6CrossRelayRetry {
                    // M6: the ambiguous token is shown at another relay for another namespace.
                    let k2 = (k + 1) % 3;
                    let ns2 = self.clients[c].namespaces[0];
                    let rid2: [u8; 16] = self.clients[c].ns_rng.bytes();
                    let truth = self.relay_truth(c, run, source, t + 1);
                    let World { relays, rec, .. } = self;
                    let node = &mut relays[usize::from(k2)];
                    let label2 = transport::label(&rid2, &node.onion);
                    let req = rw::RedeemTokenRequest {
                        version: 1,
                        token: token.as_bytes().to_vec(),
                        namespace_id: ns2.to_vec(),
                        request_id: rid2.to_vec(),
                    };
                    let mut link = RelayLink {
                        node,
                        rec,
                        t: t + 1,
                        label: label2,
                        truth,
                        lose_answer: false,
                        shift_minutes: 0,
                        answered: false,
                    };
                    let _ = transport::block_on(<RelayLink<'_> as ghost_client_net::namespace_client::RedeemRpc>::redeem_token(&mut link, req));
                    return 2;
                }
            }
            Err(e) => {
                // `RetryPolicy.classify`: a transient failure keeps the reservation for the
                // identical retry; any other deletes the token (R8: never shown elsewhere).
                let transient = match &e {
                    RelayError::Transport(_) => true,
                    RelayError::Rpc(s) => matches!(
                        s.code(),
                        tonic::Code::Unavailable
                            | tonic::Code::DeadlineExceeded
                            | tonic::Code::ResourceExhausted
                    ),
                    _ => false,
                };
                if transient {
                    self.clients[c].tokens[i].reserved = Some((k, ns, request_id));
                } else {
                    self.clients[c].tokens.remove(i);
                }
                self.log.count("redemptions failed");
            }
        }
        1
    }

    /// NI-3: the minutes relays shift in what they tell this client (0 unless chosen).
    fn shift_for(&self, c: usize) -> i64 {
        if self.cfg.shift_fraction <= 0.0 {
            return 0;
        }
        let key = derive32(self.cfg.seeds.user, &[b"ni3"]);
        let idb = self.clients[c].id.to_be_bytes();
        if prf_unit(&key, &idb) >= self.cfg.shift_fraction {
            return 0;
        }
        let u = prf_unit(&key, &[&idb[..], b"shift"].concat());
        let m = 60 + (u * 1_320.0) as i64;
        if prf_unit(&key, &[&idb[..], b"sign"].concat()) < 0.5 {
            m
        } else {
            -m
        }
    }
}

/// Which part of a pair a session runs: both, the redemption as the pair comes and then the sync (a
/// foreground session); the sync only (a background session's lanes); the redemption only (a
/// background session's redeem-lane step).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pass {
    Both,
    Lanes,
    Step,
}

/// The need of a (relay, namespace) pair as `CapabilityStore.needed` computes it at device time
/// `w`: a capability is deleted a day after its expiry (`CapabilityStore.collect`); a pair holding
/// one that ends within 24 h (an expired one included) needs a WRITE EXPIRING (every redemption
/// installs a write capability, §10.7); one without a capability needs a WRITE MISSING when it has
/// something to write, else a READ MISSING (the world lists every pair it holds).
fn need_of(cap: Option<&Cap>, needs_write: bool, w: i64) -> Option<(NeedKind, NeedReason)> {
    match cap.filter(|cp| cp.expiry as i64 + DAY > w) {
        Some(cp) if (cp.expiry as i64) <= w + 24 * HOUR => {
            Some((NeedKind::Write, NeedReason::Expiring))
        }
        Some(_) => None,
        None if needs_write => Some((NeedKind::Write, NeedReason::Missing)),
        None => Some((NeedKind::Read, NeedReason::Missing)),
    }
}

impl Client {
    /// ENTITLEMENT_NEEDED is raised once the identity has paid or trial coverage.
    fn first_pack_done_or_paid(&self) -> bool {
        self.coverage_end >= 0
    }
}

/// The tables of the relay's two databases: (file tag, table, exported name, key and value types:
/// `B` bytes → bytes, `U` bytes → (), `N` bytes → u64, `S` str → u64, `W` u64 → u64).
const RELAY_TABLES: &[(&str, &str, &str, char)] = &[
    ("nullifiers", "nullifiers", "nullifiers", 'B'),
    ("nullifiers", "es_keys", "es_keys", 'B'),
    ("nullifiers", "es_revoked", "es_revoked", 'U'),
    ("nullifiers", "meta", "nullifiers_meta", 'S'),
    // Per closed week, the rows its sweep deleted (the R2 export, design §19.25 point 4).
    ("nullifiers", "redemption_counts", "redemption_counts", 'W'),
    ("blobs", "content", "content", 'B'),
    ("blobs", "members", "members", 'B'),
    ("blobs", "namespace_index", "namespace_index", 'B'),
    ("blobs", "expiry_index_v2", "expiry_index_v2", 'U'),
    ("blobs", "namespace_seq", "namespace_seq", 'N'),
    ("blobs", "meta", "blobs_meta", 'S'),
    // Schema-1 tables a migration leaves behind.
    ("blobs", "blobs", "blobs_v1", 'B'),
    ("blobs", "expiry_index", "expiry_index_v1", 'U'),
];

/// Every row of every table of relay `dir`'s databases (`nullifiers.redb`, `blobs.redb`; design
/// §13.4 `relay_<k>_db`), read through private copies. A table [`RELAY_TABLES`] does not know fails
/// the world instead of going unexported.
fn read_relay_rows(dir: &Path, scratch: &Path) -> Vec<(&'static str, Vec<u8>, Vec<u8>)> {
    use redb::{ReadableDatabase, ReadableTable, TableDefinition, TableHandle};
    let mut out = Vec::new();
    for (file, tag) in [("nullifiers.redb", "nullifiers"), ("blobs.redb", "blobs")] {
        let src = dir.join(file);
        if !src.exists() {
            continue;
        }
        let copy = scratch.join(format!("t2-copy-{tag}.redb"));
        std::fs::copy(&src, &copy).unwrap();
        {
            let db = redb::Database::open(&copy).expect("a relay database copy opens");
            let tx = db.begin_read().unwrap();
            let names: Vec<String> = tx
                .list_tables()
                .unwrap()
                .map(|h| h.name().to_string())
                .collect();
            for name in names {
                let &(_, _, exported, kind) = RELAY_TABLES
                    .iter()
                    .find(|t| t.0 == tag && t.1 == name)
                    .unwrap_or_else(|| {
                        panic!("relay table {name} of {file} is not exported (design §13.4)")
                    });
                match kind {
                    'B' => {
                        let def: TableDefinition<&[u8], &[u8]> = TableDefinition::new(&name);
                        for item in tx.open_table(def).unwrap().iter().unwrap() {
                            let (k, v) = item.unwrap();
                            out.push((exported, k.value().to_vec(), v.value().to_vec()));
                        }
                    }
                    'U' => {
                        let def: TableDefinition<&[u8], ()> = TableDefinition::new(&name);
                        for item in tx.open_table(def).unwrap().iter().unwrap() {
                            let (k, _) = item.unwrap();
                            out.push((exported, k.value().to_vec(), Vec::new()));
                        }
                    }
                    'N' => {
                        let def: TableDefinition<&[u8], u64> = TableDefinition::new(&name);
                        for item in tx.open_table(def).unwrap().iter().unwrap() {
                            let (k, v) = item.unwrap();
                            out.push((
                                exported,
                                k.value().to_vec(),
                                v.value().to_be_bytes().to_vec(),
                            ));
                        }
                    }
                    'W' => {
                        let def: TableDefinition<u64, u64> = TableDefinition::new(&name);
                        for item in tx.open_table(def).unwrap().iter().unwrap() {
                            let (k, v) = item.unwrap();
                            out.push((
                                exported,
                                k.value().to_be_bytes().to_vec(),
                                v.value().to_be_bytes().to_vec(),
                            ));
                        }
                    }
                    _ => {
                        let def: TableDefinition<&str, u64> = TableDefinition::new(&name);
                        for item in tx.open_table(def).unwrap().iter().unwrap() {
                            let (k, v) = item.unwrap();
                            out.push((
                                exported,
                                k.value().as_bytes().to_vec(),
                                v.value().to_be_bytes().to_vec(),
                            ));
                        }
                    }
                }
            }
        }
        let _ = std::fs::remove_file(&copy);
    }
    out
}

/// The key id mutant M2b's issuer hands out per invoice.
pub fn server_key_id(invoice_id: &[u8; 16]) -> [u8; 32] {
    Sha256::digest([b"ghost/t2/server-key-id".as_slice(), invoice_id].concat()).into()
}

/// One position blinded by a mutant client.
pub struct MutantPosition {
    pub pk: ghost_blind_rsa::PublicKey,
    pub input: [u8; tok::TOKEN_INPUT_LEN],
    pub inv: ghost_blind_rsa::BigUint,
    pub blinded: [u8; AUTHENTICATOR_LEN],
}

/// HKDF-SHA256(ikm = v, salt = none, info = "nonce" ‖ u8(j)), 32 bytes (mutant M1).
fn nonce_from_invoice(invoice_id: &[u8; 16], j: usize) -> [u8; 32] {
    use hmac::digest::KeyInit;
    use hmac::{Hmac, Mac};
    let mut ext = <Hmac<Sha256> as KeyInit>::new_from_slice(&[]).unwrap();
    ext.update(invoice_id);
    let prk = ext.finalize().into_bytes();
    let mut exp = <Hmac<Sha256> as KeyInit>::new_from_slice(&prk).unwrap();
    exp.update(b"nonce");
    exp.update(&[j as u8, 1]);
    exp.finalize().into_bytes().into()
}

/// HKDF-SHA256(ikm = v, salt = none, info = "ghost/v1/blind-batch" ‖ u8(j)), 32 bytes (mutant M1b:
/// a GHOST label and the position as info).
fn nonce_from_invoice_label(invoice_id: &[u8; 16], j: usize) -> [u8; 32] {
    use hmac::digest::KeyInit;
    use hmac::{Hmac, Mac};
    let mut ext = <Hmac<Sha256> as KeyInit>::new_from_slice(&[]).unwrap();
    ext.update(invoice_id);
    let prk = ext.finalize().into_bytes();
    let mut exp = <Hmac<Sha256> as KeyInit>::new_from_slice(&prk).unwrap();
    exp.update(b"ghost/v1/blind-batch");
    exp.update(&[j as u8, 1]);
    exp.finalize().into_bytes().into()
}

/// The blinded request of a mutant client (M1, M2, M2b, M5a, M5b); every other derivation is the
/// production one (`batch::derive`).
pub fn mutant_blind(
    schedule: &Schedule,
    seed: &[u8; 32],
    layout: &Layout,
    mutant: Mutant,
    invoice_id: &[u8; 16],
    rogue: Option<&ghost_blind_rsa::PublicKey>,
) -> Vec<MutantPosition> {
    let mut out = Vec::new();
    for j in 0..layout.len() {
        let d = batch::derive(schedule, seed, layout, j).unwrap();
        let key = schedule.key(d.position.kind, d.position.epoch).unwrap();
        let pk = rogue.cloned().unwrap_or_else(|| key.public_key.clone());
        let key_id = match mutant {
            Mutant::M2PerInvoiceKey => tok::key_id(&pk.to_spki()),
            Mutant::M2bServerKeyId => server_key_id(invoice_id),
            _ => key.key_id,
        };
        let nonce = match mutant {
            Mutant::M1NonceFromInvoice => nonce_from_invoice(invoice_id, j),
            Mutant::M1bNonceFromInvoiceLabel => nonce_from_invoice_label(invoice_id, j),
            _ => d.nonce,
        };
        let digest = schedule
            .challenge_digest(d.position.kind, d.position.epoch, d.position.slot)
            .unwrap();
        let input = tok::token_input(&nonce, &digest, &key_id);
        let mut r = match mutant {
            Mutant::M5aNoBlinding => ghost_blind_rsa::BigUint::from(1u32),
            Mutant::M5bSquareBlinding => (&d.r * &d.r) % pk.n(),
            _ => d.r.clone(),
        };
        if rogue.is_some() {
            r = &r % pk.n();
        }
        let (blinded, inv) = loop {
            match tok::blind_input(&pk, &input, &d.salt, &r) {
                Ok(x) => break x,
                // M2: a factor drawn for the ES key's modulus need not be a unit of the rogue one.
                Err(_) if rogue.is_some() => r += 1u32,
                Err(e) => panic!("blinding a mutant position: {e:?}"),
            }
        };
        out.push(MutantPosition {
            pk,
            input,
            inv,
            blinded,
        });
    }
    out
}

pub fn mutant_finalize(positions: &[MutantPosition], sigs: &[u8]) -> Vec<Token> {
    positions
        .iter()
        .zip(sigs.chunks(AUTHENTICATOR_LEN))
        .filter_map(|(p, s)| tok::finalize_input(&p.pk, &p.input, s, &p.inv).ok())
        .collect()
}

/// Records a `BlindSign` answered by the mutant issuer layer (M2).
fn record_mutant_sign(
    link: &mut IssuerLink<'_>,
    req: &wire::BlindSignRequest,
    resp: &wire::BlindSignResponse,
) {
    use ghost_t2_join::model::{Field, IssuerCall, IssuerOp};
    let mut request = vec![
        Field {
            name: "invoice_id",
            bytes: &req.invoice_id,
        },
        Field {
            name: "claim_key",
            bytes: &req.claim_key,
        },
    ];
    for b in req.blinded.chunks(256) {
        request.push(Field {
            name: "blinded",
            bytes: b,
        });
    }
    let extra = std::mem::take(&mut link.extra_req);
    for (n, v) in &extra {
        request.push(Field { name: n, bytes: v });
    }
    let response: Vec<Field<'_>> = resp
        .blind_signatures
        .chunks(256)
        .map(|b| Field {
            name: "blind_signatures",
            bytes: b,
        })
        .collect();
    let call = IssuerCall {
        t: link.t,
        t_resp: link.t + link.latency,
        label: link.label,
        op: IssuerOp::BlindSign,
        request,
        response,
        status: 0,
        truth: link.truth,
    };
    *link.received += 1;
    link.rec.issuer_call(&call, &[("state", resp.state as u64)]);
    link.answered = Some(link.t + link.latency);
}

/// Seeds used for a set of NI twin constructions.
pub fn non_final_attempts(log: &Log) -> HashSet<(u32, u64, usize)> {
    log.sign_outcomes
        .iter()
        .filter(|&&(_, _, _, s)| {
            s == wire::InvoiceState::AwaitingPayment as i32
                || s == wire::InvoiceState::AwaitingConfirmations as i32
                || s == wire::InvoiceState::Underpaid as i32
        })
        .map(|&(c, i, a, _)| (c, i, a))
        .collect()
}

pub fn spec_of(w: &World, c: usize) -> &ClientSpec {
    &w.clients[c].spec
}
