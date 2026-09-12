//! The issuer crash harness world (Phase 8 design §13.2): the real issuer on the real redb store and
//! journal (behind the fault wrappers), a `ChainPort` wallet and an honest client on the production
//! client crypto (`ghost-entitlement::batch`). A crash drops every in-memory object, reopens the
//! same redb file and journal, runs the startup (ES check, journal replay, restore pool reset),
//! the pool refill and a scanner tick, and the client retries its request. The wallet and the
//! client survive crashes.
//!
//! Invariants checked by [`World::check`] after every scenario: MS-1 (one digest and one signature
//! set per invoice over every answer ever produced, equal to the stored issued digest), MS-2 (the
//! first signature of an XMR invoice is backed by qualifying transfers on the chain), MS-3 (every
//! accepted invite and credit nullifier is still recorded, or its epoch is closed by the persisted
//! high-water mark, §19.10; one answer per refreshed credit), no minor handed out twice, no pool
//! entry assigned, `claim_index`/`minor_index` consistent, the payout invariants (a batch file is
//! the same bytes at every export, a claim never joins two batches, batch totals are the sums of
//! their claims, a paid claim keeps no address), and the reconciliation invariants.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use ghost_entitlement::batch::{self, Layout, Position};
use ghost_entitlement::grid::week;
use ghost_entitlement::{Kind, Schedule, Token};
use ghost_issuer::credit::refresh_digest;
use ghost_issuer::custody::KeyWindow;
use ghost_issuer::journal::{Entry, FileJournal, Journal};
use ghost_issuer::payout::{self, AckFile, BatchFile, EntryOutcome, OpsKey, PayoutReport};
use ghost_issuer::reconcile::{self, CounterId, Counters, Mismatch};
use ghost_issuer::scanner::TickReport;
use ghost_issuer::service::{
    Issuer, IssuerParams, OpenMode, Ports, Random, RandomError, StartupError,
};
use ghost_issuer::store::{
    self, ClaimState, CreditUse, InvoiceRow, InvoiceState, MetaKey, PayWith, ReadTx, RedbStore,
    Table, ADDRESS_LEN,
};
use ghost_issuer_api::proto as wire;
use sha2::{Digest, Sha256};
use tonic::Status;

use super::chain_port::{Chain, ChainPort, RailHandle};
use super::faults::{FaultPlan, FaultyJournal, FaultyRail, FaultyStore};
use super::fixture;
use super::race::{Gate, RaceStore};

/// Monday 2026-09-28 12:00 UTC: the middle of access week 2960 (invite epoch 740, credit 227).
pub const BASE: u64 = 1_790_596_800;
pub const BASE_WEEK: u64 = 2960;
pub const START_BLOCKS: u64 = 1_000;
/// Price of the test schedule's price epoch 227.
pub const PRICE: u64 = 200_000_000_000;

/// The harness runs with a pool target of 4 (the production 32 only multiplies identical refill
/// steps, and every refill step is a fault site).
pub fn harness_params() -> IssuerParams {
    IssuerParams {
        pool_target: 4,
        ..IssuerParams::default()
    }
}

/// Deterministic randomness for invoice ids: SHA-256 of a counter that survives crashes.
pub struct SeqRandom(Mutex<u64>);

struct RandomHandle(Arc<SeqRandom>);

impl Random for RandomHandle {
    fn fill(&self, out: &mut [u8]) -> Result<(), RandomError> {
        let mut c = self.0 .0.lock().unwrap();
        *c += 1;
        let mut stream = Vec::new();
        let mut block = 0u64;
        while stream.len() < out.len() {
            stream.extend_from_slice(&Sha256::digest(
                [c.to_be_bytes(), block.to_be_bytes()].concat(),
            ));
            block += 1;
        }
        out.copy_from_slice(&stream[..out.len()]);
        Ok(())
    }
}

pub fn claim_key(label: &str) -> [u8; 32] {
    Sha256::digest(format!("claim/{label}")).into()
}

pub fn seed(label: &str) -> [u8; 32] {
    Sha256::digest(format!("seed/{label}")).into()
}

pub fn claim_id(label: &str) -> [u8; 16] {
    Sha256::digest(format!("claim-id/{label}"))[..16]
        .try_into()
        .unwrap()
}

/// The test ops key (payout batch files): the Ed25519 seed SHA-256("ghost/test/ops-key").
pub fn ops_key() -> OpsKey {
    OpsKey::from_seed(&Sha256::digest(b"ghost/test/ops-key").into())
}

/// A purchase the client holds: its invoice and the flow's blinding seed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Purchase {
    pub id: [u8; 16],
    pub base_week: u64,
    pub xmr: bool,
    pub minor: u32,
    pub amount: u64,
    pub seed: [u8; 32],
}

#[derive(Debug, Clone, Default)]
pub struct Wallet {
    /// Credit tokens finalized from packs (and not spent by the scenario yet).
    pub credits: Vec<Token>,
    pub purchases: BTreeMap<String, Purchase>,
}

/// The distinct answers to one request key: (request digest, signature bytes).
pub type Answers = BTreeSet<([u8; 32], Vec<u8>)>;

/// Everything the issuer ever answered that the invariants look at.
#[derive(Debug, Clone, Default)]
pub struct Observed {
    pub signed: BTreeMap<[u8; 16], Answers>,
    pub trials: BTreeMap<(u64, [u8; 32]), Answers>,
    /// Refreshed credits: (epoch, N) → (refresh digest, blind signature).
    pub refreshes: BTreeMap<(u64, [u8; 32]), Answers>,
    pub spent: BTreeSet<(u64, [u8; 32])>,
    pub minors: BTreeMap<u32, [u8; 16]>,
    pub claims: BTreeMap<[u8; 16], u64>,
    /// Every batch file ever found in the export directory, per batch.
    pub batch_files: BTreeMap<[u8; 16], BTreeSet<Vec<u8>>>,
    /// The batch each exported claim was in.
    pub batch_of_claim: BTreeMap<[u8; 16], [u8; 16]>,
}

/// A prepared world, closed, from which every crash run starts.
pub struct Template {
    dir: tempfile::TempDir,
    chain: Chain,
    now: u64,
    wallet: Wallet,
    observed: Observed,
    small: bool,
    random: u64,
    external_credits: bool,
}

pub struct World {
    pub dir: tempfile::TempDir,
    pub schedule: Schedule,
    pub keys: KeyWindow,
    pub chain: Arc<ChainPort>,
    random: Arc<SeqRandom>,
    pub plan: Arc<FaultPlan>,
    issuer: Option<Issuer>,
    pub now: u64,
    pub crashes: usize,
    pub params: IssuerParams,
    pub wallet: Wallet,
    pub observed: Observed,
    pub small: bool,
    /// Credits were minted outside the issuer (the credits ≤ signed invariant does not apply).
    pub external_credits: bool,
    pending_restore: bool,
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for item in std::fs::read_dir(from).unwrap() {
        let item = item.unwrap();
        let target = to.join(item.file_name());
        if item.file_type().unwrap().is_dir() {
            copy_dir(&item.path(), &target);
        } else {
            std::fs::copy(item.path(), target).unwrap();
        }
    }
}

impl World {
    /// A fresh world at [`BASE`] with [`harness_params`].
    pub fn new(small: bool) -> Self {
        Self::with_params(small, harness_params())
    }

    /// A fresh world at [`BASE`]: open, pool refilled, one synced tick. No fault is armed.
    pub fn with_params(small: bool, params: IssuerParams) -> Self {
        let (schedule, keys) = if small {
            fixture::small()
        } else {
            fixture::full()
        };
        let mut w = Self {
            dir: tempfile::tempdir().unwrap(),
            schedule: schedule.clone(),
            keys: keys.clone(),
            chain: ChainPort::new(START_BLOCKS),
            random: Arc::new(SeqRandom(Mutex::new(0))),
            plan: FaultPlan::new(Vec::new()),
            issuer: None,
            now: BASE,
            crashes: 0,
            params,
            wallet: Wallet::default(),
            observed: Observed::default(),
            small,
            external_credits: false,
            pending_restore: false,
        };
        w.open(OpenMode::Normal);
        w.refill();
        w.tick();
        w
    }

    /// Closes the world into a template.
    pub fn template(mut self) -> Template {
        self.issuer = None;
        Template {
            dir: self.dir,
            chain: self.chain.state(),
            now: self.now,
            wallet: self.wallet,
            observed: self.observed,
            small: self.small,
            random: *self.random.0.lock().unwrap(),
            external_credits: self.external_credits,
        }
    }

    /// A copy of the template's files and state under `plan` (not armed yet), opened, refilled and
    /// ticked.
    pub fn from_template(t: &Template, plan: Arc<FaultPlan>) -> Self {
        let (schedule, keys) = if t.small {
            fixture::small()
        } else {
            fixture::full()
        };
        let dir = tempfile::tempdir().unwrap();
        copy_dir(t.dir.path(), dir.path());
        let mut w = Self {
            dir,
            schedule: schedule.clone(),
            keys: keys.clone(),
            chain: ChainPort::from_chain(t.chain.clone()),
            random: Arc::new(SeqRandom(Mutex::new(t.random))),
            plan,
            issuer: None,
            now: t.now,
            crashes: 0,
            params: harness_params(),
            wallet: t.wallet.clone(),
            observed: t.observed.clone(),
            small: t.small,
            external_credits: t.external_credits,
            pending_restore: false,
        };
        w.open(OpenMode::Normal);
        w.refill();
        w.tick();
        w
    }

    fn ports(&self) -> Ports {
        Ports {
            store: Box::new(FaultyStore {
                inner: RedbStore::open(&self.dir.path().join("issuer.redb")).unwrap(),
                plan: Arc::clone(&self.plan),
            }),
            journal: Box::new(FaultyJournal {
                inner: FileJournal::open(&self.dir.path().join("journal")).unwrap(),
                plan: Arc::clone(&self.plan),
            }),
            rail: Box::new(FaultyRail {
                inner: Arc::clone(&self.chain),
                plan: Arc::clone(&self.plan),
            }),
            random: Box::new(RandomHandle(Arc::clone(&self.random))),
        }
    }

    /// Opens the issuer; a fault during the startup is a crash during recovery: open again.
    pub fn open(&mut self, mode: OpenMode) {
        if mode == OpenMode::Restore {
            self.pending_restore = true;
        }
        loop {
            self.issuer = None;
            let mode = if self.pending_restore {
                OpenMode::Restore
            } else {
                OpenMode::Normal
            };
            match Issuer::open(
                self.schedule.clone(),
                self.keys.clone(),
                self.ports(),
                self.params,
                mode,
                self.now,
            ) {
                Ok(issuer) => {
                    self.issuer = Some(issuer);
                    self.pending_restore = false;
                    return;
                }
                Err(e) => {
                    assert!(self.plan.take_crash(), "startup refused after a crash: {e}");
                    self.crashes += 1;
                }
            }
        }
    }

    pub fn issuer(&self) -> &Issuer {
        self.issuer.as_ref().expect("issuer open")
    }

    /// A crash: every in-memory object is dropped; the files stay.
    pub fn crash(&mut self) {
        self.issuer = None;
        self.crashes += 1;
    }

    /// One startup attempt with the current schedule, keys and parameters (startup refusals).
    pub fn try_open(&mut self, mode: OpenMode) -> Result<(), StartupError> {
        self.issuer = None;
        let issuer = Issuer::open(
            self.schedule.clone(),
            self.keys.clone(),
            self.ports(),
            self.params,
            mode,
            self.now,
        )?;
        self.issuer = Some(issuer);
        Ok(())
    }

    /// A clean restart with the current schedule, keys and parameters: open, refill, tick.
    pub fn reopen(&mut self) {
        self.crash();
        self.open(OpenMode::Normal);
        self.refill();
        self.tick();
    }

    /// Hands the issuer over (the wall-clock facade tests).
    pub fn take_issuer(&mut self) -> Issuer {
        self.issuer.take().expect("issuer open")
    }

    /// After a crash: reopen, refill, tick; any further fault is a crash during recovery.
    fn recover(&mut self) {
        loop {
            self.crash();
            self.open(OpenMode::Normal);
            let _ = self.issuer().pool_refill_at(self.now);
            if self.plan.take_crash() {
                continue;
            }
            let _ = self.issuer().scan_tick_at(self.now);
            if self.plan.take_crash() {
                continue;
            }
            return;
        }
    }

    /// Calls the issuer; a crash during the call is followed by recovery and the identical retry.
    pub fn call<T>(&mut self, f: impl Fn(&Issuer, u64) -> Result<T, Status>) -> Result<T, Status> {
        self.run(f)
    }

    /// Runs an issuer call or job; a crash during it is followed by recovery and the identical
    /// call again.
    pub fn run<T>(&mut self, f: impl Fn(&Issuer, u64) -> T) -> T {
        for _ in 0..64 {
            let r = f(self.issuer(), self.now);
            if self.plan.take_crash() {
                self.recover();
                continue;
            }
            return r;
        }
        panic!("no progress after 64 crashes");
    }

    /// Crash scenario I-K: runs `a` and `b` concurrently on an issuer over the same files whose
    /// store lets the first writer commit only after the second asked for its transaction (both
    /// passed their checks). The issuer is dropped afterwards: the world is left crashed, and a
    /// restart, a template or a restore follows. No fault is injected during the race.
    pub fn race<A: Send, B: Send>(
        &mut self,
        a: impl FnOnce(&Issuer, u64) -> A + Send,
        b: impl FnOnce(&Issuer, u64) -> B + Send,
    ) -> (A, B) {
        self.issuer = None;
        let gate = Arc::new(Gate::default());
        let issuer = Issuer::open(
            self.schedule.clone(),
            self.keys.clone(),
            Ports {
                store: Box::new(RaceStore {
                    inner: RedbStore::open(&self.dir.path().join("issuer.redb")).unwrap(),
                    gate: Arc::clone(&gate),
                }),
                journal: Box::new(FileJournal::open(&self.dir.path().join("journal")).unwrap()),
                rail: Box::new(RailHandle(Arc::clone(&self.chain))),
                random: Box::new(RandomHandle(Arc::clone(&self.random))),
            },
            self.params,
            OpenMode::Normal,
            self.now,
        )
        .unwrap();
        gate.arm();
        let now = self.now;
        let answers = std::thread::scope(|scope| {
            let issuer = &issuer;
            let ha = scope.spawn(move || a(issuer, now));
            let hb = scope.spawn(move || b(issuer, now));
            (ha.join().unwrap(), hb.join().unwrap())
        });
        assert_eq!(gate.writers(), 2, "I-K: each request takes one transaction");
        assert!(!issuer.is_halted());
        drop(issuer);
        self.crashes += 1;
        answers
    }

    /// Rewrites the (closed) journal without the entries after sequence number `after` that
    /// `lost` selects: the decided outcomes an issuer that did not journal them would not have
    /// recorded (mutants MM3, MM15). Returns how many entries were removed.
    pub fn lose_journal_entries(&self, after: u64, lost: impl Fn(&Entry) -> bool) -> usize {
        let dir = self.dir.path().join("journal");
        let all = FileJournal::open(&dir).unwrap().entries().unwrap();
        let kept: Vec<Entry> = all
            .iter()
            .filter(|(seq, e)| *seq <= after || !lost(e))
            .map(|(_, e)| e.clone())
            .collect();
        std::fs::remove_dir_all(&dir).unwrap();
        let journal = FileJournal::open(&dir).unwrap();
        for e in &kept {
            journal.append(self.week(), e).unwrap();
        }
        all.len() - kept.len()
    }

    /// Appends `entry` to the (closed) journal: an outcome an issuer journaled without deciding
    /// it (mutant MM16, MM20).
    pub fn append_journal_entry(&self, entry: &Entry) {
        FileJournal::open(&self.dir.path().join("journal"))
            .unwrap()
            .append(self.week(), entry)
            .unwrap();
    }

    /// `journal_applied` of the current database.
    pub fn journal_applied(&self) -> u64 {
        let tx = self.issuer().store().read().unwrap();
        store::meta(&*tx, MetaKey::JournalApplied)
            .unwrap()
            .unwrap_or(0)
    }

    pub fn tick(&mut self) -> Option<TickReport> {
        for _ in 0..64 {
            let r = self.issuer().scan_tick_at(self.now);
            if self.plan.take_crash() {
                self.recover();
                continue;
            }
            return r.ok();
        }
        panic!("no progress after 64 crashes");
    }

    pub fn refill(&mut self) {
        for _ in 0..64 {
            let r = self.issuer().pool_refill_at(self.now);
            if self.plan.take_crash() {
                self.recover();
                continue;
            }
            r.unwrap();
            return;
        }
        panic!("no progress after 64 crashes");
    }

    pub fn sweep(&mut self) {
        for _ in 0..64 {
            let r = self.issuer().sweep_at(self.now);
            if self.plan.take_crash() {
                self.recover();
                continue;
            }
            r.unwrap();
            return;
        }
        panic!("no progress after 64 crashes");
    }

    pub fn advance(&mut self, secs: u64) {
        self.now += secs;
    }

    pub fn week(&self) -> u64 {
        week(self.now)
    }

    /// Mines `blocks` blocks and ticks.
    pub fn mine(&mut self, blocks: u64) {
        self.chain.mine(blocks);
        self.tick();
    }

    // -------------------------------------------------------------------------------------------
    // Snapshot and restore (runbook B1).
    // -------------------------------------------------------------------------------------------

    /// An hourly snapshot: `issuer.redb` copied while the issuer is stopped.
    pub fn snapshot(&mut self) {
        self.issuer = None;
        std::fs::copy(
            self.dir.path().join("issuer.redb"),
            self.dir.path().join("snapshot.redb"),
        )
        .unwrap();
        self.open(OpenMode::Normal);
        self.refill();
        self.tick();
    }

    /// Host loss: the snapshot replaces the database, the journal is kept; open in restore mode
    /// (replay, pool reset), refill above the wallet's subaddress count, tick.
    pub fn restore(&mut self) {
        self.restore_with(OpenMode::Restore);
    }

    /// [`World::restore`] opening in `mode` (`Normal` is mutant MM15 `PoolNotResetOnRestore`).
    pub fn restore_with(&mut self, mode: OpenMode) {
        self.issuer = None;
        std::fs::copy(
            self.dir.path().join("snapshot.redb"),
            self.dir.path().join("issuer.redb"),
        )
        .unwrap();
        self.open(mode);
        self.refill();
        self.tick();
    }

    // -------------------------------------------------------------------------------------------
    // The client.
    // -------------------------------------------------------------------------------------------

    pub fn purchase(&self, label: &str) -> Purchase {
        self.wallet.purchases[label].clone()
    }

    pub fn request(
        &mut self,
        label: &str,
        base_week: u64,
        credits: &[Token],
    ) -> Result<wire::RequestInvoiceResponse, Status> {
        let req = wire::RequestInvoiceRequest {
            version: 1,
            rail: wire::Rail::Monero as i32,
            product: wire::Product::Pack as i32,
            claim_hash: batch::claim_hash(&claim_key(label)).to_vec(),
            credits: credits.iter().map(|t| t.as_bytes().to_vec()).collect(),
            base_week,
        };
        let r = self.call(|i, now| i.request_invoice_at(req.clone(), now))?;
        if r.result == wire::RequestInvoiceResult::Ok as i32 {
            let id: [u8; 16] = r.invoice_id.as_slice().try_into().unwrap();
            let xmr = credits.is_empty();
            let minor = if xmr {
                self.chain.minor_of(&r.subaddress)
            } else {
                assert!(r.subaddress.is_empty() && r.amount_atomic == 0);
                0
            };
            let p = Purchase {
                id,
                base_week,
                xmr,
                minor,
                amount: r.amount_atomic,
                seed: seed(label),
            };
            if let Some(old) = self.wallet.purchases.get(label) {
                assert_eq!(old, &p, "a retried RequestInvoice answered another invoice");
            }
            if xmr {
                let previous = self.observed.minors.insert(minor, id);
                assert!(
                    previous.is_none_or(|p| p == id),
                    "minor {minor} handed out twice"
                );
            }
            for t in credits {
                let e = self.schedule.key_by_id(t.key_id()).unwrap().epoch;
                self.observed.spent.insert((e, t.nullifier()));
            }
            self.wallet.purchases.insert(label.to_string(), p);
        }
        Ok(r)
    }

    pub fn layout(&self, p: &Purchase) -> Layout {
        Layout::pack(&self.schedule, p.base_week, p.xmr).unwrap()
    }

    /// The client's blinded request of a purchase: recomputed from the seed, byte-identical on
    /// every retry.
    pub fn blinded(&self, label: &str) -> Vec<u8> {
        let p = self.purchase(label);
        batch::blind(&self.schedule, &p.seed, &self.layout(&p)).unwrap()
    }

    pub fn sign(&mut self, label: &str) -> Result<wire::BlindSignResponse, Status> {
        let blinded = self.blinded(label);
        self.sign_with(label, blinded)
    }

    pub fn sign_with(
        &mut self,
        label: &str,
        blinded: Vec<u8>,
    ) -> Result<wire::BlindSignResponse, Status> {
        let p = self.purchase(label);
        let req = wire::BlindSignRequest {
            version: 1,
            invoice_id: p.id.to_vec(),
            claim_key: claim_key(label).to_vec(),
            blinded: blinded.clone(),
        };
        let r = self.call(|i, now| i.blind_sign_at(req.clone(), now))?;
        if r.state == wire::InvoiceState::Signed as i32 {
            let digest = batch::request_digest(&p.id, &blinded);
            let first = self.observed.signed.get(&p.id).is_none_or(|s| s.is_empty());
            if first && p.xmr {
                self.assert_paid(&p);
            }
            self.observed
                .signed
                .entry(p.id)
                .or_default()
                .insert((digest, r.blind_signatures.clone()));
        }
        Ok(r)
    }

    /// MS-2: qualifying transfers (≥ C confirmations, unlock 0, not double-spent, mined before
    /// grace) to the invoice's minor cover its amount.
    fn assert_paid(&self, p: &Purchase) {
        let tx = self.issuer().store().read().unwrap();
        let row = store::invoice(&*tx, &p.id).unwrap().unwrap();
        let c = u64::from(self.schedule.constants().confirmations);
        let chain = self.chain.state();
        let credited: u64 = chain
            .txs
            .iter()
            .filter(|t| {
                t.minor == p.minor
                    && t.unlock_time == 0
                    && !t.double_spend_seen
                    && t.height
                        .is_some_and(|h| chain.blocks - h >= c && h <= row.grace_height + 100)
            })
            .map(|t| t.amount)
            .sum();
        assert!(credited >= p.amount, "MS-2: signed without value");
    }

    pub fn status(&mut self, label: &str) -> Result<wire::InvoiceStatusResponse, Status> {
        let p = self.purchase(label);
        let req = wire::InvoiceStatusRequest {
            version: 1,
            invoice_id: p.id.to_vec(),
            claim_key: claim_key(label).to_vec(),
        };
        self.call(|i, now| i.invoice_status_at(req.clone(), now))
    }

    pub fn finalize(&self, label: &str, sigs: &[u8]) -> Vec<Token> {
        let p = self.purchase(label);
        batch::finalize(&self.schedule, &p.seed, &self.layout(&p), sigs).expect("MS-6: tokens")
    }

    pub fn pay(&self, label: &str, amount: u64) -> [u8; 32] {
        self.chain.pay(self.purchase(label).minor, amount)
    }

    /// A whole XMR pack of the current week: request, pay, 10 confirmations, sign, finalize.
    /// Keeps the pack's credit token. The pool is refilled first, as the refill job does every
    /// 60 s in production (the harness pool holds 4 entries).
    pub fn buy_pack(&mut self, label: &str) -> Vec<Token> {
        self.refill();
        let w = self.week();
        let r = self.request(label, w, &[]).unwrap();
        assert_eq!(r.result, wire::RequestInvoiceResult::Ok as i32);
        self.pay(label, r.amount_atomic);
        self.mine(10);
        let s = self.sign(label).unwrap();
        assert_eq!(s.state, wire::InvoiceState::Signed as i32);
        let tokens = self.finalize(label, &s.blind_signatures);
        self.wallet.credits.push(tokens.last().unwrap().clone());
        tokens
    }

    /// A token minted directly with the test key of (kind, epoch) (negative tests; never through
    /// the issuer).
    pub fn mint(&self, kind: Kind, epoch: u64, label: &str) -> Token {
        let slot = (kind == Kind::Access).then(|| self.schedule.slots_in_week(epoch)[0]);
        let layout =
            Layout::from_positions(&self.schedule, vec![Position { kind, epoch, slot }]).unwrap();
        let s = seed(label);
        let blinded = batch::blind(&self.schedule, &s, &layout).unwrap();
        let block: [u8; 256] = blinded.as_slice().try_into().unwrap();
        let sig = self
            .keys
            .get(kind, epoch)
            .unwrap()
            .blind_sign(&block)
            .unwrap();
        batch::finalize(&self.schedule, &s, &layout, &sig)
            .unwrap()
            .remove(0)
    }

    pub fn trial_blinded(&self, label: &str, base_week: u64) -> Vec<u8> {
        let layout = Layout::trial(&self.schedule, base_week).unwrap();
        batch::blind(&self.schedule, &seed(label), &layout).unwrap()
    }

    pub fn redeem(
        &mut self,
        token: &Token,
        base_week: u64,
        blinded: Vec<u8>,
    ) -> Result<wire::RedeemInviteResponse, Status> {
        let req = wire::RedeemInviteRequest {
            version: 1,
            invite_token: token.as_bytes().to_vec(),
            base_week,
            blinded: blinded.clone(),
        };
        let r = self.call(|i, now| i.redeem_invite_at(req.clone(), now))?;
        if r.result == wire::RedeemInviteResult::Ok as i32 {
            let epoch = self.schedule.key_by_id(token.key_id()).unwrap().epoch;
            let n = token.nullifier();
            let d = batch::trial_digest(&n, base_week, &blinded);
            self.observed
                .trials
                .entry((epoch, n))
                .or_default()
                .insert((d, r.blind_signatures.clone()));
        }
        Ok(r)
    }

    /// The refresh request of `label` for a credit of `epoch`: one blinded CREDIT position.
    pub fn refresh_blinded(&self, label: &str, epoch: u64) -> Vec<u8> {
        let layout = Layout::refresh(&self.schedule, epoch).unwrap();
        batch::blind(&self.schedule, &seed(label), &layout).unwrap()
    }

    /// `RefreshCredit` of `credit` with `blinded`.
    pub fn refresh(
        &mut self,
        credit: &Token,
        blinded: Vec<u8>,
    ) -> Result<wire::RefreshCreditResponse, Status> {
        let req = wire::RefreshCreditRequest {
            version: 1,
            credit: credit.as_bytes().to_vec(),
            blinded: blinded.clone(),
        };
        let r = self.call(|i, now| i.refresh_credit_at(req.clone(), now))?;
        if r.result == wire::RefreshCreditResult::Ok as i32 {
            let epoch = self.schedule.key_by_id(credit.key_id()).unwrap().epoch;
            let n = credit.nullifier();
            self.observed
                .refreshes
                .entry((epoch, n))
                .or_default()
                .insert((refresh_digest(&n, &blinded), r.blind_signature.clone()));
            self.observed.spent.insert((epoch, n));
        }
        Ok(r)
    }

    /// The fresh credit of a refresh by `label` of a credit of `epoch`.
    pub fn finalize_refresh(&self, label: &str, epoch: u64, sig: &[u8]) -> Token {
        let layout = Layout::refresh(&self.schedule, epoch).unwrap();
        batch::finalize(&self.schedule, &seed(label), &layout, sig)
            .expect("MS-6: the fresh credit")
            .remove(0)
    }

    pub fn export_dir(&self) -> PathBuf {
        self.dir.path().join("export")
    }

    /// One payout export run (acknowledgements imported, batches created, files written); every
    /// batch file then in the export directory is recorded.
    pub fn export(&mut self) -> PayoutReport {
        let dir = self.export_dir();
        let key = ops_key();
        let report = self
            .run(|i, now| i.payout_export_at(now, &key, &dir))
            .expect("payout export");
        for file in self.batch_files() {
            let bytes = std::fs::read(dir.join(payout::batch_file_name(&file.batch_id))).unwrap();
            self.observed
                .batch_files
                .entry(file.batch_id)
                .or_default()
                .insert(bytes);
            for e in &file.entries {
                let previous = self
                    .observed
                    .batch_of_claim
                    .insert(e.claim_id, file.batch_id);
                assert!(
                    previous.is_none_or(|b| b == file.batch_id),
                    "a claim exported in two batches"
                );
            }
        }
        report
    }

    /// The batch files in the export directory, verified under the test ops key.
    pub fn batch_files(&self) -> Vec<BatchFile> {
        let Ok(items) = std::fs::read_dir(self.export_dir()) else {
            return Vec::new();
        };
        let mut out: Vec<BatchFile> = items
            .map(|i| i.unwrap().path())
            .filter(|p| p.extension().is_some_and(|x| x == "ghpb"))
            .map(|p| {
                BatchFile::verify(&std::fs::read(&p).unwrap(), &ops_key().public())
                    .expect("a batch file verifies under the ops key")
            })
            .collect();
        out.sort_by_key(|f| f.batch_id);
        out
    }

    /// The workstation's acknowledgement of `file`, every entry paid, in the export directory; the
    /// next export imports it.
    pub fn write_ack(&self, file: &BatchFile) -> AckFile {
        self.write_ack_refusing(file, &[])
    }

    /// [`World::write_ack`] with the entries of the claims `refused` refused (a payout address
    /// the workstation had seen before).
    pub fn write_ack_refusing(&self, file: &BatchFile, refused: &[[u8; 16]]) -> AckFile {
        let ack = AckFile {
            batch_id: file.batch_id,
            entries: file
                .entries
                .iter()
                .map(|e| {
                    let outcome = if refused.contains(&e.claim_id) {
                        EntryOutcome::Refused
                    } else {
                        EntryOutcome::Paid
                    };
                    (e.claim_id, outcome)
                })
                .collect(),
        };
        std::fs::write(
            self.export_dir()
                .join(payout::ack_file_name(&file.batch_id)),
            ack.encode().unwrap(),
        )
        .unwrap();
        ack
    }

    pub fn claim(
        &mut self,
        label: &str,
        credits: &[Token],
        address: &str,
    ) -> Result<wire::ClaimPayoutResponse, Status> {
        let id = claim_id(label);
        let req = wire::ClaimPayoutRequest {
            version: 1,
            claim_id: id.to_vec(),
            credits: credits.iter().map(|t| t.as_bytes().to_vec()).collect(),
            payout_address: address.to_string(),
        };
        let r = self.call(|i, now| i.claim_payout_at(req.clone(), now))?;
        if r.result == wire::ClaimPayoutResult::Queued as i32 {
            let previous = self.observed.claims.insert(id, r.queued_atomic);
            assert!(previous.is_none_or(|a| a == r.queued_atomic));
            for t in credits {
                let e = self.schedule.key_by_id(t.key_id()).unwrap().epoch;
                self.observed.spent.insert((e, t.nullifier()));
            }
        }
        Ok(r)
    }

    // -------------------------------------------------------------------------------------------
    // Invariants.
    // -------------------------------------------------------------------------------------------

    pub fn check(&self) {
        let issuer = self.issuer();
        assert!(!issuer.is_halted(), "issuer halted at quiescence");
        let tx = issuer.store().read().unwrap();
        let rows = store::invoices(&*tx).unwrap();
        let pool: BTreeSet<u32> = store::pool(&*tx)
            .unwrap()
            .into_iter()
            .map(|(m, _)| m)
            .collect();
        let mut minors = BTreeSet::new();
        for (id, row) in &rows {
            assert_eq!(
                store::claim_index(&*tx, &row.claim_hash).unwrap(),
                Some(*id),
                "claim_index"
            );
            if row.pay_with == PayWith::Monero {
                assert_eq!(
                    store::minor_index(&*tx, row.minor).unwrap(),
                    Some(*id),
                    "minor_index"
                );
                assert!(!pool.contains(&row.minor), "a pool entry is assigned");
                assert!(minors.insert(row.minor), "one minor on two invoices");
            }
        }
        for (id, set) in &self.observed.signed {
            assert_eq!(set.len(), 1, "MS-1: two answers for one invoice");
            let (digest, _) = set.iter().next().unwrap();
            if let Some((_, row)) = rows.iter().find(|(i, _)| i == id) {
                assert_eq!(
                    row.state,
                    InvoiceState::Issued,
                    "MS-1: signed but not issued"
                );
                assert_eq!(row.issued_digest, Some(*digest), "MS-1: another digest");
            }
        }
        // A nullifier row may be gone only once its epoch is closed by the persisted high-water
        // mark (§19.10): the mark then refuses the token whatever the clock says.
        let closed_invite = store::meta(&*tx, MetaKey::ClosedThroughInviteEpoch).unwrap();
        let closed_credit = store::meta(&*tx, MetaKey::ClosedThroughCreditEpoch).unwrap();
        for ((epoch, n), set) in &self.observed.trials {
            assert_eq!(set.len(), 1, "MS-3: two trial answers for one invite");
            let (digest, _) = set.iter().next().unwrap();
            match store::invite_nullifier(&*tx, *epoch, n).unwrap() {
                Some(stored) => assert_eq!(stored, *digest, "MS-3: invite nullifier changed"),
                None => assert!(
                    closed_invite.is_some_and(|m| *epoch <= m),
                    "MS-3: invite nullifier lost"
                ),
            }
        }
        for (epoch, n) in &self.observed.spent {
            if store::credit_nullifier(&*tx, *epoch, n).unwrap().is_none() {
                assert!(
                    closed_credit.is_some_and(|m| *epoch <= m),
                    "MS-3: credit nullifier lost"
                );
            }
        }
        for ((epoch, n), set) in &self.observed.refreshes {
            assert_eq!(set.len(), 1, "MS-3: two refresh answers for one credit");
            let (digest, _) = set.iter().next().unwrap();
            if let Some(used) = store::credit_nullifier(&*tx, *epoch, n).unwrap() {
                assert_eq!(
                    used,
                    CreditUse::Refresh(*digest),
                    "MS-3: a refreshed credit recorded otherwise"
                );
            }
        }
        // Payouts (§9.5, §19.5): a batch file never changes, a claim never joins a second batch,
        // a batch's total is the sum of its claims, a closed claim keeps no payout address, and
        // no two pending (queued or batched) claims share one (S6 review: no batch can hold an
        // address twice).
        for files in self.observed.batch_files.values() {
            assert_eq!(files.len(), 1, "a batch file changed on re-export");
        }
        let batches: BTreeMap<[u8; 16], _> = store::batches(&*tx).unwrap().into_iter().collect();
        let claims = store::claims(&*tx).unwrap();
        let mut sums: BTreeMap<[u8; 16], (u64, usize)> = BTreeMap::new();
        let mut pending = BTreeSet::new();
        for (id, c) in &claims {
            match c.state {
                ClaimState::Queued => assert_eq!(c.batch_id, [0; 16], "a queued claim in a batch"),
                ClaimState::Batched | ClaimState::Paid | ClaimState::Refused => {
                    assert!(batches.contains_key(&c.batch_id), "a claim of no batch");
                    let s = sums.entry(c.batch_id).or_default();
                    s.0 += c.amount;
                    s.1 += 1;
                }
            }
            match c.state {
                ClaimState::Paid | ClaimState::Refused => assert_eq!(
                    c.address, [0u8; ADDRESS_LEN],
                    "RET: a closed claim keeps its payout address"
                ),
                ClaimState::Queued | ClaimState::Batched => assert!(
                    pending.insert(c.address),
                    "two pending claims to one payout address"
                ),
            }
            if let Some(b) = self.observed.batch_of_claim.get(id) {
                assert_eq!(c.batch_id, *b, "a claim re-queued into another batch");
            }
        }
        for (id, b) in &batches {
            if let Some(&(sum, n)) = sums.get(id) {
                if n == usize::from(b.entries) {
                    assert_eq!(sum, b.total, "a batch total is not the sum of its claims");
                }
            }
        }
        // RET (§6.1, §19.1 rule 5): a credit spent for a discount (use 1) or a payout (use 2)
        // keeps no reference to its invoice or claim, which are deleted within weeks while the
        // nullifier stays for 52–65; only a refresh (use 3) keeps its request's digest, whole.
        for (_, value) in tx.range(Table::CreditNullifier, &[], None).unwrap() {
            assert_eq!(value.len(), 33, "credit_nullifier row length");
            if matches!(value[0], 1 | 2) {
                assert_eq!(
                    value[1..],
                    [0u8; 32],
                    "RET: a spent credit references its invoice or claim"
                );
            }
        }
        let counters = reconcile::all(&*tx).unwrap();
        let mismatches: Vec<Mismatch> = reconcile::check(&counters, &self.schedule, self.now)
            .into_iter()
            .filter(|m| {
                !(self.external_credits && matches!(m, Mismatch::CreditsExceedSigned { .. }))
            })
            .collect();
        assert!(mismatches.is_empty(), "reconciliation: {mismatches:?}");
        self.check_incoming(&*tx, &rows, &counters);
    }

    /// §6.9, §19.6 rule 2, computed from the `ChainPort`: every qualifying transfer to a minor ≥ 1
    /// mined at or below `scan_final_height` is counted exactly once, as credited revenue
    /// (`xmr_credited_atomic`), overpayment, unattributed revenue, or as the credited amount of an
    /// invoice that is not settled yet (for an ISSUED invoice the amount is already in
    /// `xmr_credited_atomic`, so only the excess is pending). Checked when the scanner's last
    /// synced tick saw the current chain (`scan_final_height = blocks − C`) and no reorg after
    /// issuance (a declared financial residue, §5.4) happened.
    fn check_incoming(
        &self,
        tx: &dyn ReadTx,
        rows: &[([u8; 16], InvoiceRow)],
        counters: &Counters,
    ) {
        let c = u64::from(self.schedule.constants().confirmations);
        let chain = self.chain.state();
        let Some(final_height) = store::meta(tx, MetaKey::ScanFinalHeight).unwrap() else {
            return;
        };
        let total = |id: CounterId| -> i128 {
            counters
                .iter()
                .filter(|((i, _), _)| *i == id)
                .map(|(_, v)| i128::from(*v))
                .sum()
        };
        if chain.blocks.saturating_sub(c) != final_height || total(CounterId::ReorgAfterIssue) > 0 {
            return;
        }
        let incoming: i128 = chain
            .txs
            .iter()
            .filter(|t| {
                t.minor >= 1
                    && t.unlock_time == 0
                    && !t.double_spend_seen
                    && t.height.is_some_and(|h| h <= final_height)
            })
            .map(|t| i128::from(t.amount))
            .sum();
        let counted = total(CounterId::XmrCreditedAtomic)
            + total(CounterId::OverpaidAtomic)
            + total(CounterId::UnattributedAtomic);
        let pending: i128 = rows
            .iter()
            .filter(|(_, r)| r.pay_with == PayWith::Monero)
            .map(|(_, r)| match r.state {
                InvoiceState::Created | InvoiceState::Seen | InvoiceState::Confirmed => {
                    i128::from(r.credited)
                }
                InvoiceState::Issued => i128::from(r.credited) - i128::from(r.amount),
                InvoiceState::Expired => 0,
            })
            .sum();
        assert_eq!(
            incoming,
            counted + pending,
            "§19.6: incoming to minors >= 1 != credited + overpaid + unattributed"
        );
    }
}

/// Counts of one enumeration.
#[derive(Debug, Clone, Copy, Default)]
pub struct Stats {
    pub sites: usize,
    pub runs: usize,
    pub crashes: usize,
}

/// Crashes every fault site of `body` once in each of its modes (single crashes) and, for each of
/// those, every site among the next `depth` ones reached after it (double crashes: a crash during
/// recovery or the first retry). Every run ends with [`World::check`].
pub fn enumerate(template: &Template, body: fn(&mut World), depth: usize) -> Stats {
    let depth = std::env::var("GHOST_ISSUER_CRASH_DEPTH")
        .ok()
        .and_then(|d| d.parse().ok())
        .unwrap_or(depth);
    let run = |targets: Vec<(usize, super::faults::Mode)>| -> World {
        let expected = targets.len();
        let plan = FaultPlan::new(targets);
        let mut w = World::from_template(template, Arc::clone(&plan));
        plan.arm();
        body(&mut w);
        w.check();
        assert_eq!(plan.fired(), expected, "a planned fault did not fire");
        w
    };
    let record = run(Vec::new());
    let sites = record.plan.sites();
    let mut stats = Stats {
        sites: sites.len(),
        ..Stats::default()
    };
    for (i, site) in sites.iter().enumerate() {
        for &mode in site.modes() {
            let w = run(vec![(i, mode)]);
            stats.runs += 1;
            stats.crashes += w.crashes;
            let after = w.plan.sites();
            for (j, next) in after.iter().enumerate().skip(i + 1).take(depth) {
                for &second in next.modes() {
                    let w2 = run(vec![(i, mode), (j, second)]);
                    stats.runs += 1;
                    stats.crashes += w2.crashes;
                }
            }
        }
    }
    stats
}
