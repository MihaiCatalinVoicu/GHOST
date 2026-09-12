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
//! accepted invite and credit nullifier is still recorded), no minor handed out twice, no pool
//! entry assigned, `claim_index`/`minor_index` consistent, and the reconciliation invariants.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::{Arc, Mutex};

use ghost_entitlement::batch::{self, Layout, Position};
use ghost_entitlement::grid::week;
use ghost_entitlement::{Kind, Schedule, Token};
use ghost_issuer::custody::KeyWindow;
use ghost_issuer::journal::FileJournal;
use ghost_issuer::reconcile::{self, Mismatch};
use ghost_issuer::scanner::TickReport;
use ghost_issuer::service::{
    Issuer, IssuerParams, OpenMode, Ports, Random, RandomError, StartupError,
};
use ghost_issuer::store::{self, InvoiceState, PayWith, RedbStore};
use ghost_issuer_api::proto as wire;
use sha2::{Digest, Sha256};
use tonic::Status;

use super::chain_port::{Chain, ChainPort};
use super::faults::{FaultPlan, FaultyJournal, FaultyRail, FaultyStore};
use super::fixture;

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
    pub spent: BTreeSet<(u64, [u8; 32])>,
    pub minors: BTreeMap<u32, [u8; 16]>,
    pub claims: BTreeMap<[u8; 16], u64>,
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
        self.issuer = None;
        std::fs::copy(
            self.dir.path().join("snapshot.redb"),
            self.dir.path().join("issuer.redb"),
        )
        .unwrap();
        self.open(OpenMode::Restore);
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
        for ((epoch, n), set) in &self.observed.trials {
            assert_eq!(set.len(), 1, "MS-3: two trial answers for one invite");
            let (digest, _) = set.iter().next().unwrap();
            assert_eq!(
                store::invite_nullifier(&*tx, *epoch, n).unwrap(),
                Some(*digest),
                "MS-3: invite nullifier lost"
            );
        }
        for (epoch, n) in &self.observed.spent {
            assert!(
                store::credit_nullifier(&*tx, *epoch, n).unwrap().is_some(),
                "MS-3: credit nullifier lost"
            );
        }
        let counters = reconcile::all(&*tx).unwrap();
        let mismatches: Vec<Mismatch> = reconcile::check(&counters, &self.schedule, self.now)
            .into_iter()
            .filter(|m| {
                !(self.external_credits && matches!(m, Mismatch::CreditsExceedSigned { .. }))
            })
            .collect();
        assert!(mismatches.is_empty(), "reconciliation: {mismatches:?}");
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
