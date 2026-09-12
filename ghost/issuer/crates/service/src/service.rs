//! The issuer (Phase 8 design §5, §6): startup, the client handlers `*_at(request, now)` with an
//! explicit clock (the relay precedent), and the decide-then-journal commit path shared by every
//! irreversible transition (§19.5).
//!
//! **Startup** ([`Issuer::open`]): every held key matches its ES entry; ES rule 5 against
//! `es_memory` (keys, slot sets, prices, revocations, seq), then the schedule's facts are
//! remembered; the journal is replayed from `meta.journal_applied` (a gap refuses the start); a
//! restore (runbook B1) empties the address pool, so the pool is refilled above the wallet's
//! subaddress count; keys past their destruction time with no open invoice are dropped.
//!
//! **Handlers** check sizes, then idempotency, then validity (§19.9), and answer with constant
//! messages only (a handler never echoes client input). Signing happens outside every transaction;
//! the transaction re-reads what it depends on (closed-through marks included, §19.10), appends
//! the journal entry, applies the transition through [`Issuer::apply`] (the same function replay
//! uses) and commits. A failed journal append, apply or commit halts the issuer (every call
//! answers `UNAVAILABLE`) until a restart replays the journal, so a decided outcome is never
//! contradicted in process. A handler that was already past its entry checks and queued on the
//! store's one writer decides nothing after a failure either: inside its transaction it finds the
//! halt (set before the failed writer released the transaction) or a journal holding one entry
//! more than the database applied (a failed commit), and answers `UNAVAILABLE`.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard, RwLock};

use ghost_blind_rsa::BigUint;
use ghost_entitlement::batch::{self, Layout};
use ghost_entitlement::grid::{invite_epoch, price_epoch, week};
use ghost_entitlement::token::{self, AUTHENTICATOR_LEN, TOKEN_INPUT_LEN, TOKEN_LEN};
use ghost_entitlement::{Kind, Schedule, ScheduleError, Token};
use ghost_issuer_api::proto as wire;
use ghost_issuer_api::{
    BLOCK_BYTES, CLAIM_BYTES, INVOICE_ID_BYTES, MAX_DISCOUNT_CREDITS, MAX_LAYOUT_POSITIONS,
};
use sha2::{Digest, Sha256};
use tonic::Status;

use crate::credit;
use crate::custody::{KeyWindow, LoadError};
use crate::invoice::{self, Reported};
use crate::journal::{Entry, InvoiceEntry, Journal, JournalError};
use crate::rail::{PaymentRail, RailError, RailHeight};
use crate::reconcile::{self, CounterId};
use crate::signer::SignError;
use crate::store::{
    self, ClaimRow, ClaimState, CreditUse, InvoiceRow, InvoiceState, MetaKey, PayWith, ReadTx,
    Store, StoreError, Table, WriteTx, ADDRESS_LEN,
};
use crate::PROTOCOL_VERSION;

/// `base_week` is accepted within ±4 h of the issuer's clock (§19.4).
pub const BASE_WEEK_TOLERANCE_SECS: u64 = 4 * 3_600;
/// How long after the start of invite epoch e + 2 the invite nullifiers of epoch e are kept
/// (§19.1 rule 2 over §6.4): a trial of an epoch-e invite has a base week of at most the first week
/// of epoch e + 2 (redeemed in the last 4 h of e + 1), and its re-serve must work until
/// `end(base + 1) + 8 d`, two weeks and 8 days after that start. The rows carry no base week, so
/// the whole epoch is kept that long; new redemptions of it are refused from the start of e + 2.
pub const TRIAL_RESERVE_HOLD_SECS: u64 = 22 * 86_400;
/// A new XMR invoice needs a synced scanner tick younger than this (§19.6).
pub const TICK_FRESH_SECS: u64 = 120;
/// Open unpaid invoices at most (§5.9).
pub const MAX_OPEN_INVOICES: u64 = 20_000;
/// Address pool target (§7.2).
pub const POOL_TARGET: u32 = 32;
/// Global `RequestInvoice` token bucket: 2 per second, burst 40 (§5.9).
pub const RATE_PER_SEC: u64 = 2;
pub const RATE_BURST: u64 = 40;

const REQUEST_INVOICE_DOMAIN: &[u8] = b"ghost/v1/request-invoice";
const CLAIM_PAYOUT_DOMAIN: &[u8] = b"ghost/v1/claim-payout";
/// Wire codes of the only rail and product of protocol version 1, as bytes of the digest R.
const RAIL_MONERO: u8 = 1;
const PRODUCT_PACK: u8 = 1;

// Status messages are constants: the issuer never echoes client input.
pub(crate) fn rejected() -> Status {
    Status::invalid_argument("rejected")
}

pub(crate) fn unauthorized() -> Status {
    Status::permission_denied("unauthorized")
}

pub(crate) fn unavailable() -> Status {
    Status::unavailable("unavailable")
}

pub(crate) fn exhausted() -> Status {
    Status::resource_exhausted("rate limited")
}

impl From<StoreError> for Status {
    fn from(_: StoreError) -> Self {
        unavailable()
    }
}

pub(crate) fn fixed<const N: usize>(bytes: &[u8]) -> Result<[u8; N], Status> {
    bytes.try_into().map_err(|_| rejected())
}

/// Constant-time equality of two 32-byte values (claim key check, §5.5 step 2).
pub(crate) fn ct_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// `base_week ∈ {week(now − 4 h), week(now + 4 h)}` (§19.4).
pub fn base_week_ok(base_week: u64, now: u64) -> bool {
    base_week == week(now.saturating_sub(BASE_WEEK_TOLERANCE_SECS))
        || base_week == week(now.saturating_add(BASE_WEEK_TOLERANCE_SECS))
}

/// `R = SHA-256("ghost/v1/request-invoice" || rail || product || base_week || nullifiers of the
/// credits in request order)` (§5.6 step 2; rail and product as one byte each).
pub fn request_invoice_digest(base_week: u64, nullifiers: &[[u8; 32]]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(REQUEST_INVOICE_DOMAIN);
    h.update([RAIL_MONERO, PRODUCT_PACK]);
    h.update(base_week.to_be_bytes());
    for n in nullifiers {
        h.update(n);
    }
    h.finalize().into()
}

/// The body digest of a `ClaimPayout` request: `SHA-256("ghost/v1/claim-payout" ||
/// u16 len(address) || address || u8 count || every credit token)` (§5.6 step 2).
pub fn claim_digest(address: &str, credits: &[Vec<u8>]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(CLAIM_PAYOUT_DOMAIN);
    h.update((address.len().min(usize::from(u16::MAX)) as u16).to_be_bytes());
    h.update(address.as_bytes());
    h.update([credits.len().min(255) as u8]);
    for c in credits {
        h.update(c);
    }
    h.finalize().into()
}

/// The operating-system random source (invoice ids).
pub trait Random: Send + Sync {
    fn fill(&self, out: &mut [u8]) -> Result<(), RandomError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RandomError;

/// `ring`'s system random source.
pub struct OsRandom(ring::rand::SystemRandom);

impl OsRandom {
    pub fn new() -> Self {
        Self(ring::rand::SystemRandom::new())
    }
}

impl Default for OsRandom {
    fn default() -> Self {
        Self::new()
    }
}

impl Random for OsRandom {
    fn fill(&self, out: &mut [u8]) -> Result<(), RandomError> {
        use ring::rand::SecureRandom;
        self.0.fill(out).map_err(|_| RandomError)
    }
}

/// Operating limits (§5.9, §6.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IssuerParams {
    pub max_open_invoices: u64,
    pub pool_target: u32,
    pub rate_per_sec: u64,
    pub rate_burst: u64,
}

impl Default for IssuerParams {
    fn default() -> Self {
        Self {
            max_open_invoices: MAX_OPEN_INVOICES,
            pool_target: POOL_TARGET,
            rate_per_sec: RATE_PER_SEC,
            rate_burst: RATE_BURST,
        }
    }
}

/// How the database was obtained.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OpenMode {
    /// The database of the last run.
    Normal,
    /// A snapshot restored by runbook B1: after the replay the address pool is emptied and
    /// refilled above the wallet's subaddress count, so no minor is handed out twice (§19.5).
    Restore,
}

/// The issuer's ports: state, journal, payment rail, randomness.
pub struct Ports {
    pub store: Box<dyn Store>,
    pub journal: Box<dyn Journal>,
    pub rail: Box<dyn PaymentRail>,
    pub random: Box<dyn Random>,
}

/// Why the issuer refused to start (§6.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StartupError {
    Store(StoreError),
    Journal(JournalError),
    /// ES rule 5 against `es_memory` (§3.1, §19.2, §19.20).
    Schedule(ScheduleError),
    Keys(LoadError),
    /// A journal entry contradicts the database (sequence number given).
    Replay(u64),
}

impl std::fmt::Display for StartupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StartupError::Store(e) => write!(f, "{e}"),
            StartupError::Journal(e) => write!(f, "{e}"),
            StartupError::Schedule(e) => write!(f, "entitlement schedule refused: {e}"),
            StartupError::Keys(e) => write!(f, "{e}"),
            StartupError::Replay(seq) => write!(f, "journal entry {seq} contradicts the database"),
        }
    }
}

impl std::error::Error for StartupError {}

impl From<StoreError> for StartupError {
    fn from(e: StoreError) -> Self {
        StartupError::Store(e)
    }
}

impl From<JournalError> for StartupError {
    fn from(e: JournalError) -> Self {
        StartupError::Journal(e)
    }
}

/// Outcome of the last scanner tick.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TickOutcome {
    /// The view was synced (daemon synchronized, wallet ≥ daemon − 1).
    Synced,
    /// The rail answered, but the view was not synced.
    Unsynced,
    /// The wallet holds fewer subaddresses than the issuer handed out (restored without runbook
    /// R5's replay): nothing was decided (review finding S5-MON-1).
    WalletIncomplete,
    Failed(RailError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LastTick {
    pub(crate) at: u64,
    pub(crate) outcome: TickOutcome,
    pub(crate) height: Option<RailHeight>,
}

/// Process state that a restart rightly forgets.
#[derive(Debug, Default)]
pub(crate) struct Volatile {
    pub(crate) last_tick: Option<LastTick>,
    /// Wallet height of the last tick that reached the rail.
    pub(crate) last_wallet_height: Option<u64>,
    /// `highest_minor` was reconciled with the wallet in this process (§7.2, §19.5).
    pub(crate) reconciled: bool,
    bucket_tokens: u64,
    bucket_at: Option<u64>,
    /// Alarm `KEYS_MISSING`: calls refused because a needed key is not held.
    pub(crate) keys_missing: u64,
    /// Alarm `SIGN_FAULT`: signatures withheld by the fault check.
    pub(crate) sign_faults: u64,
}

/// Why a batch of positions could not be signed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum SignFailure {
    KeysMissing,
    Fault,
    Input,
    Internal,
}

impl SignFailure {
    pub(crate) fn status(self) -> Status {
        match self {
            SignFailure::Input => rejected(),
            SignFailure::KeysMissing | SignFailure::Fault | SignFailure::Internal => unavailable(),
        }
    }
}

/// A replayed or live transition that could not be applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum ApplyError {
    Store(StoreError),
    /// The entry contradicts the database (a different digest, a nullifier used otherwise).
    Inconsistent,
}

impl From<StoreError> for ApplyError {
    fn from(e: StoreError) -> Self {
        ApplyError::Store(e)
    }
}

/// The entitlement issuer.
pub struct Issuer {
    pub(crate) schedule: Schedule,
    pub(crate) store: Box<dyn Store>,
    pub(crate) journal: Box<dyn Journal>,
    pub(crate) rail: Box<dyn PaymentRail>,
    pub(crate) random: Box<dyn Random>,
    pub(crate) keys: RwLock<KeyWindow>,
    pub(crate) params: IssuerParams,
    pub(crate) volatile: Mutex<Volatile>,
    halted: AtomicBool,
}

const FACT_KEY: u8 = 1;
const FACT_SLOTS: u8 = 2;
const FACT_PRICE: u8 = 3;
const FACT_REVOKED: u8 = 4;

fn fact_key(fact: u8, kind: Option<Kind>, epoch: u64) -> [u8; 10] {
    let mut k = [0u8; 10];
    k[0] = fact;
    k[1] = kind.map_or(0, Kind::byte);
    k[2..].copy_from_slice(&epoch.to_be_bytes());
    k
}

fn slot_digest(slots: &[u8]) -> [u8; 32] {
    Sha256::digest(slots).into()
}

fn price_digest(price: u64) -> [u8; 32] {
    Sha256::digest(price.to_be_bytes()).into()
}

fn signed_counter(kind: Kind) -> CounterId {
    match kind {
        Kind::Access => CounterId::SignedAccess,
        Kind::Invite => CounterId::SignedInvite,
        Kind::Credit => CounterId::SignedCredit,
    }
}

impl Issuer {
    /// Starts the issuer over its ports (§6.6 startup refusals that do not need the wallet: the
    /// ES, the held keys, the journal).
    pub fn open(
        schedule: Schedule,
        keys: KeyWindow,
        ports: Ports,
        params: IssuerParams,
        mode: OpenMode,
        now: u64,
    ) -> Result<Self, StartupError> {
        keys.check_against(&schedule).map_err(StartupError::Keys)?;
        let issuer = Self {
            schedule,
            store: ports.store,
            journal: ports.journal,
            rail: ports.rail,
            random: ports.random,
            keys: RwLock::new(keys),
            params,
            volatile: Mutex::new(Volatile::default()),
            halted: AtomicBool::new(false),
        };
        issuer.accept_schedule()?;
        issuer.replay(now)?;
        if mode == OpenMode::Restore {
            let mut tx = issuer.store.write()?;
            for (k, _) in tx.range(Table::AddressPool, &[], None)? {
                tx.delete(Table::AddressPool, &k)?;
            }
            tx.commit()?;
        }
        issuer.destroy_keys(now)?;
        Ok(issuer)
    }

    pub fn schedule(&self) -> &Schedule {
        &self.schedule
    }

    /// The store (read access for status, reconciliation and tests).
    pub fn store(&self) -> &dyn Store {
        self.store.as_ref()
    }

    /// The (kind, epoch) pairs whose private keys are held.
    pub fn keys_held(&self) -> Vec<(Kind, u64)> {
        self.keys().held()
    }

    /// True once a failure between a journal append and its commit halted the issuer.
    pub fn is_halted(&self) -> bool {
        self.halted.load(Ordering::SeqCst)
    }

    pub(crate) fn ensure_running(&self) -> Result<(), Status> {
        if self.is_halted() {
            Err(unavailable())
        } else {
            Ok(())
        }
    }

    fn halt(&self) -> Status {
        self.halted.store(true, Ordering::SeqCst);
        unavailable()
    }

    pub(crate) fn volatile(&self) -> MutexGuard<'_, Volatile> {
        self.volatile.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub(crate) fn keys(&self) -> std::sync::RwLockReadGuard<'_, KeyWindow> {
        self.keys.read().unwrap_or_else(|e| e.into_inner())
    }

    // -----------------------------------------------------------------------------------------
    // Startup.
    // -----------------------------------------------------------------------------------------

    /// ES rule 5 against `es_memory`, then the schedule's facts are remembered (§3.1, §19.2,
    /// §19.20 point 2).
    fn accept_schedule(&self) -> Result<(), StartupError> {
        let s = &self.schedule;
        let mut tx = self.store.write()?;
        if store::meta(&*tx, MetaKey::EsSeq)?.is_some_and(|seq| s.seq() < seq) {
            return Err(StartupError::Schedule(ScheduleError::Rollback));
        }
        let mut remembered_ids: BTreeMap<[u8; 32], (Kind, u64)> = BTreeMap::new();
        for (k, v) in tx.range(Table::EsMemory, &[], None)? {
            let key: [u8; 10] = store::array(&k)?;
            let value: [u8; 32] = store::array(&v)?;
            let kind = Kind::from_byte(key[1]);
            let epoch = u64::from_be_bytes(store::array(&key[2..])?);
            let refused = |e| Err(StartupError::Schedule(e));
            match (key[0], kind) {
                (FACT_KEY, Some(kind)) => {
                    if s.key(kind, epoch).map(|e| e.key_id) != Some(value) {
                        return refused(ScheduleError::KeyChanged);
                    }
                    remembered_ids.insert(value, (kind, epoch));
                }
                (FACT_SLOTS, None) => {
                    if slot_digest(&s.slots_in_week(epoch)) != value {
                        return refused(ScheduleError::SlotSetChanged);
                    }
                }
                (FACT_PRICE, None) => {
                    if s.pack_price(epoch).map(price_digest) != Some(value) {
                        return refused(ScheduleError::PriceChanged);
                    }
                }
                (FACT_REVOKED, Some(kind)) => {
                    if !s.is_revoked(kind, epoch) {
                        return refused(ScheduleError::RevocationDropped);
                    }
                }
                _ => return Err(StartupError::Store(StoreError::Corrupt)),
            }
        }
        // Rule 2 across schedules: a key id never reappears under another (kind, epoch).
        for entry in s.keys() {
            if remembered_ids
                .get(&entry.key_id)
                .is_some_and(|&ke| ke != (entry.kind, entry.epoch))
            {
                return Err(StartupError::Schedule(ScheduleError::DuplicateKey));
            }
        }
        for entry in s.keys() {
            tx.put(
                Table::EsMemory,
                &fact_key(FACT_KEY, Some(entry.kind), entry.epoch),
                &entry.key_id,
            )?;
        }
        for w in s.first_access_week()..=s.last_access_week() {
            tx.put(
                Table::EsMemory,
                &fact_key(FACT_SLOTS, None, w),
                &slot_digest(&s.slots_in_week(w)),
            )?;
        }
        for p in &s.content().prices {
            tx.put(
                Table::EsMemory,
                &fact_key(FACT_PRICE, None, p.price_epoch),
                &price_digest(p.pack_price_atomic),
            )?;
        }
        for (kind, epoch) in &s.content().revoked {
            tx.put(
                Table::EsMemory,
                &fact_key(FACT_REVOKED, Some(*kind), *epoch),
                &[0u8; 32],
            )?;
        }
        let seq = store::meta(&*tx, MetaKey::EsSeq)?.map_or(s.seq(), |m| m.max(s.seq()));
        store::set_meta(&mut *tx, MetaKey::EsSeq, seq)?;
        tx.commit()?;
        Ok(())
    }

    /// Replays every journal entry after `meta.journal_applied`, one transaction per entry
    /// (§6.3 startup). A gap refuses the start.
    fn replay(&self, now: u64) -> Result<(), StartupError> {
        let applied = {
            let tx = self.store.read()?;
            store::meta(&*tx, MetaKey::JournalApplied)?.unwrap_or(0)
        };
        let entries = self.journal.entries()?;
        match (entries.first(), entries.last()) {
            (Some((first, _)), Some((last, _))) => {
                if *first > applied.saturating_add(1) || *last < applied {
                    return Err(StartupError::Journal(JournalError::Gap));
                }
            }
            _ if applied > 0 => return Err(StartupError::Journal(JournalError::Gap)),
            _ => {}
        }
        for (seq, entry) in entries.iter().filter(|(seq, _)| *seq > applied) {
            let mut tx = self.store.write()?;
            self.apply(&mut *tx, entry, now, 0).map_err(|e| match e {
                ApplyError::Store(s) => StartupError::Store(s),
                ApplyError::Inconsistent => StartupError::Replay(*seq),
            })?;
            store::set_meta(&mut *tx, MetaKey::JournalApplied, *seq)?;
            tx.commit()?;
        }
        Ok(())
    }

    /// Runbook K4: drops every key past its destruction time that no open invoice references.
    pub(crate) fn destroy_keys(&self, now: u64) -> Result<Vec<(Kind, u64)>, StoreError> {
        let referenced: BTreeSet<(Kind, u64)> = {
            let tx = self.store.read()?;
            store::invoices(&*tx)?
                .into_iter()
                .filter(|(_, row)| row.state.is_open())
                .flat_map(|(_, row)| invoice::layout_keys(row.base_week, row.pay_with))
                .collect()
        };
        Ok(self
            .keys
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .destroy_due(now, &referenced))
    }

    // -----------------------------------------------------------------------------------------
    // Transitions (live and replay).
    // -----------------------------------------------------------------------------------------

    /// Decide, then journal (§19.5): the caller has re-checked, inside `tx`, the state the
    /// transition depends on. Appends and syncs the entry, applies it, records it as applied and
    /// commits. Any failure from the append on halts the issuer.
    ///
    /// Journal order equals commit order only if nothing is appended after an entry that was not
    /// committed, so inside the transaction, before the append: the issuer is not halted (a failed
    /// writer halts before it releases the transaction), and the journal's next sequence number is
    /// `journal_applied + 1` (a failed commit leaves its entry in the journal; it is replayed at the
    /// restart, never followed in process).
    pub(crate) fn decide(
        &self,
        mut tx: Box<dyn WriteTx + '_>,
        entry: &Entry,
        now: u64,
        height: u64,
    ) -> Result<(), Status> {
        if self.is_halted() {
            return Err(unavailable());
        }
        let applied = store::meta(&*tx, MetaKey::JournalApplied)?.unwrap_or(0);
        let expected = applied.checked_add(1).ok_or_else(unavailable)?;
        if self.journal.next_seq() != Ok(expected) {
            return Err(self.halt());
        }
        let seq = match self.journal.append(week(now), entry) {
            Ok(seq) if seq == expected => seq,
            _ => return Err(self.halt()),
        };
        if self.apply(&mut *tx, entry, now, height).is_err()
            || store::set_meta(&mut *tx, MetaKey::JournalApplied, seq).is_err()
        {
            return Err(self.halt());
        }
        tx.commit().map_err(|_| self.halt())
    }

    /// Applies one decided transition exactly as the handler does, counters included; an entry
    /// already applied changes nothing. `height` is the wallet height the live handler knows (0
    /// in a replay: the next scanner tick stamps it).
    pub(crate) fn apply(
        &self,
        tx: &mut dyn WriteTx,
        entry: &Entry,
        now: u64,
        height: u64,
    ) -> Result<(), ApplyError> {
        match entry {
            Entry::Invoice(e) => self.apply_invoice(tx, e),
            Entry::Issue { invoice_id, digest } => self.apply_issue(tx, invoice_id, digest, height),
            Entry::Invite {
                epoch,
                nullifier,
                digest,
                base_week,
            } => self.apply_invite(tx, *epoch, nullifier, digest, *base_week),
            Entry::Claim(e) => self.apply_claim(tx, e, now),
        }
    }

    fn apply_invoice(&self, tx: &mut dyn WriteTx, e: &InvoiceEntry) -> Result<(), ApplyError> {
        if store::invoice(tx, &e.invoice_id)?.is_some() {
            return Ok(());
        }
        if store::claim_index(tx, &e.claim_hash)?.is_some() {
            return Err(ApplyError::Inconsistent);
        }
        for (epoch, n) in &e.credits {
            if store::credit_nullifier(tx, *epoch, n)?.is_some() {
                return Err(ApplyError::Inconsistent);
            }
        }
        let c = self.schedule.constants();
        let xmr = e.pay_with == PayWith::Monero;
        let row = InvoiceRow {
            state: if xmr {
                InvoiceState::Created
            } else {
                InvoiceState::Confirmed
            },
            pay_with: e.pay_with,
            minor: e.minor,
            amount: e.amount,
            claim_hash: e.claim_hash,
            request_digest: e.request_digest,
            base_week: e.base_week,
            es_seq: self.schedule.seq(),
            created_height: e.created_height,
            seen_deadline: if xmr {
                e.created_height.saturating_add(u64::from(c.invoice_blocks))
            } else {
                0
            },
            grace_height: e.grace_height,
            confirmed_height: if xmr { 0 } else { e.created_height },
            credited: 0,
            seen: 0,
            issued_digest: None,
            issued_height: 0,
            purge_height: 0,
            subaddress: e.subaddress,
        };
        store::put_invoice(tx, &e.invoice_id, &row)?;
        tx.put(Table::ClaimIndex, &e.claim_hash, &e.invoice_id)?;
        if xmr {
            tx.put(Table::MinorIndex, &e.minor.to_be_bytes(), &e.invoice_id)?;
            tx.delete(Table::AddressPool, &e.minor.to_be_bytes())?;
            let highest = store::meta(tx, MetaKey::HighestMinor)?.unwrap_or(0);
            store::set_meta(tx, MetaKey::HighestMinor, highest.max(u64::from(e.minor)))?;
        } else {
            for (epoch, n) in &e.credits {
                tx.put(
                    Table::CreditNullifier,
                    &store::nullifier_key(*epoch, n),
                    &CreditUse::Discount.encode(),
                )?;
                reconcile::add(tx, CounterId::CreditsDiscount, *epoch, 1)?;
            }
            let pe = price_epoch(e.base_week);
            let price = self
                .schedule
                .pack_price(pe)
                .ok_or(ApplyError::Inconsistent)?;
            reconcile::add(tx, CounterId::CreditsDiscountAtomic, pe, price)?;
        }
        Ok(())
    }

    fn apply_issue(
        &self,
        tx: &mut dyn WriteTx,
        id: &[u8; 16],
        digest: &[u8; 32],
        height: u64,
    ) -> Result<(), ApplyError> {
        let mut row = store::invoice(tx, id)?.ok_or(ApplyError::Inconsistent)?;
        match row.state {
            InvoiceState::Issued if row.issued_digest == Some(*digest) => return Ok(()),
            InvoiceState::Issued | InvoiceState::Expired => return Err(ApplyError::Inconsistent),
            InvoiceState::Created | InvoiceState::Seen | InvoiceState::Confirmed => {}
        }
        let xmr = row.pay_with == PayWith::Monero;
        let layout = Layout::pack(&self.schedule, row.base_week, xmr)
            .map_err(|_| ApplyError::Inconsistent)?;
        row.state = InvoiceState::Issued;
        row.issued_digest = Some(*digest);
        row.issued_height = height;
        store::put_invoice(tx, id, &row)?;
        let mut signed: BTreeMap<(Kind, u64), u64> = BTreeMap::new();
        for p in layout.positions() {
            *signed.entry((p.kind, p.epoch)).or_default() += 1;
        }
        for ((kind, epoch), count) in signed {
            reconcile::add(tx, signed_counter(kind), epoch, count)?;
        }
        if xmr {
            reconcile::add(tx, CounterId::PacksXmr, row.base_week, 1)?;
            reconcile::add(tx, CounterId::XmrCreditedAtomic, row.base_week, row.amount)?;
        } else {
            reconcile::add(tx, CounterId::PacksCredit, row.base_week, 1)?;
        }
        Ok(())
    }

    fn apply_invite(
        &self,
        tx: &mut dyn WriteTx,
        epoch: u64,
        nullifier: &[u8; 32],
        digest: &[u8; 32],
        base_week: u64,
    ) -> Result<(), ApplyError> {
        match store::invite_nullifier(tx, epoch, nullifier)? {
            Some(stored) if stored == *digest => return Ok(()),
            Some(_) => return Err(ApplyError::Inconsistent),
            None => {}
        }
        let layout =
            Layout::trial(&self.schedule, base_week).map_err(|_| ApplyError::Inconsistent)?;
        tx.put(
            Table::InviteNullifier,
            &store::nullifier_key(epoch, nullifier),
            digest,
        )?;
        reconcile::add(tx, CounterId::Trials, base_week, 1)?;
        let mut signed: BTreeMap<u64, u64> = BTreeMap::new();
        for p in layout.positions() {
            *signed.entry(p.epoch).or_default() += 1;
        }
        for (w, count) in signed {
            reconcile::add(tx, CounterId::SignedAccess, w, count)?;
        }
        Ok(())
    }

    fn apply_claim(
        &self,
        tx: &mut dyn WriteTx,
        e: &crate::journal::ClaimEntry,
        now: u64,
    ) -> Result<(), ApplyError> {
        match store::claim(tx, &e.claim_id)? {
            Some(row) if row.digest == e.digest => return Ok(()),
            Some(_) => return Err(ApplyError::Inconsistent),
            None => {}
        }
        for (epoch, n) in &e.credits {
            if store::credit_nullifier(tx, *epoch, n)?.is_some() {
                return Err(ApplyError::Inconsistent);
            }
        }
        let row = ClaimRow {
            state: ClaimState::Queued,
            amount: e.amount,
            credits: u8::try_from(e.credits.len()).map_err(|_| ApplyError::Inconsistent)?,
            digest: e.digest,
            address: e.address,
            batch_id: [0; 16],
        };
        tx.put(Table::Claim, &e.claim_id, &row.encode())?;
        for (epoch, n) in &e.credits {
            tx.put(
                Table::CreditNullifier,
                &store::nullifier_key(*epoch, n),
                &CreditUse::Payout.encode(),
            )?;
            reconcile::add(tx, CounterId::CreditsPayout, *epoch, 1)?;
        }
        reconcile::add(tx, CounterId::PayoutQueuedAtomic, week(now), e.amount)?;
        Ok(())
    }

    // -----------------------------------------------------------------------------------------
    // Signing.
    // -----------------------------------------------------------------------------------------

    /// Step 4 of §5.5: `blinded` is exactly N blocks, each in `[1, n − 1]` under the ES key of
    /// its position.
    pub(crate) fn check_blocks(&self, layout: &Layout, blinded: &[u8]) -> Result<(), Status> {
        if blinded.len() != layout.len() * BLOCK_BYTES {
            return Err(rejected());
        }
        for (p, block) in layout
            .positions()
            .iter()
            .zip(blinded.as_chunks::<BLOCK_BYTES>().0)
        {
            let key = self.schedule.key(p.kind, p.epoch).ok_or_else(unavailable)?;
            let b = BigUint::from_bytes_be(block);
            if b.bits() == 0 || &b >= key.public_key.n() {
                return Err(rejected());
            }
        }
        Ok(())
    }

    /// Every key of the layout is held, else the alarm `KEYS_MISSING` counts and the call is
    /// refused (fail closed).
    pub(crate) fn require_keys(&self, layout: &Layout) -> Result<(), SignFailure> {
        let needed: BTreeSet<(Kind, u64)> = layout
            .positions()
            .iter()
            .map(|p| (p.kind, p.epoch))
            .collect();
        let keys = self.keys();
        if needed.iter().all(|&(k, e)| keys.contains(k, e)) {
            Ok(())
        } else {
            drop(keys);
            self.volatile().keys_missing += 1;
            Err(SignFailure::KeysMissing)
        }
    }

    /// Signs every position through its checked signer, outside any transaction. Deterministic
    /// in (key, blinded), so a re-serve reproduces the first answer byte for byte.
    pub(crate) fn sign_all(&self, layout: &Layout, blinded: &[u8]) -> Result<Vec<u8>, SignFailure> {
        self.require_keys(layout)?;
        let signers: Vec<_> = {
            let keys = self.keys();
            layout
                .positions()
                .iter()
                .map(|p| keys.get(p.kind, p.epoch))
                .collect::<Option<Vec<_>>>()
                .ok_or(SignFailure::KeysMissing)?
        };
        let mut out = Vec::with_capacity(blinded.len());
        let (blocks, rest) = blinded.as_chunks::<AUTHENTICATOR_LEN>();
        if !rest.is_empty() || blocks.len() != signers.len() {
            return Err(SignFailure::Input);
        }
        for (signer, block) in signers.iter().zip(blocks) {
            match signer.blind_sign(block) {
                Ok(sig) => out.extend_from_slice(&sig),
                Err(SignError::Fault) => {
                    self.volatile().sign_faults += 1;
                    return Err(SignFailure::Fault);
                }
                Err(SignError::InvalidInput) => return Err(SignFailure::Input),
                Err(SignError::Key | SignError::Internal) => return Err(SignFailure::Internal),
            }
        }
        Ok(out)
    }

    // -----------------------------------------------------------------------------------------
    // Helpers.
    // -----------------------------------------------------------------------------------------

    pub(crate) fn closed_through(&self, key: MetaKey) -> Result<Option<u64>, StoreError> {
        let tx = self.store.read()?;
        store::meta(&*tx, key)
    }

    /// Inside a decided transaction (§19.5 rule 2, §19.10): true when a sweep committed after the
    /// handler's checks closed the epoch of any credit, whose nullifiers may then be gone, so
    /// the spent check that follows could not be trusted.
    pub(crate) fn credits_closed(
        tx: &dyn ReadTx,
        credits: &[credit::PresentedCredit],
    ) -> Result<bool, StoreError> {
        let closed = store::meta(tx, MetaKey::ClosedThroughCreditEpoch)?;
        Ok(credits
            .iter()
            .any(|c| closed.is_some_and(|mark| c.epoch <= mark)))
    }

    /// The scanner's last tick if it was synced and is younger than [`TICK_FRESH_SECS`].
    pub(crate) fn fresh_synced_tick(&self, now: u64) -> Option<RailHeight> {
        let v = self.volatile();
        let t = v.last_tick?;
        (t.outcome == TickOutcome::Synced && t.at <= now && now - t.at < TICK_FRESH_SECS)
            .then_some(t.height)
            .flatten()
    }

    pub(crate) fn record_tick(&self, now: u64, outcome: TickOutcome, height: Option<RailHeight>) {
        let mut v = self.volatile();
        v.last_tick = Some(LastTick {
            at: now,
            outcome,
            height,
        });
        if let Some(h) = height {
            v.last_wallet_height = Some(h.wallet);
        }
    }

    /// The global token bucket of `RequestInvoice` (§5.9).
    fn take_rate_token(&self, now: u64) -> Result<(), Status> {
        let mut v = self.volatile();
        let refill = match v.bucket_at {
            None => self.params.rate_burst,
            Some(at) => now
                .saturating_sub(at)
                .saturating_mul(self.params.rate_per_sec),
        };
        v.bucket_tokens = v
            .bucket_tokens
            .saturating_add(refill)
            .min(self.params.rate_burst);
        if v.bucket_at.is_none_or(|at| now > at) {
            v.bucket_at = Some(now);
        }
        if v.bucket_tokens == 0 {
            return Err(exhausted());
        }
        v.bucket_tokens -= 1;
        Ok(())
    }

    fn fresh_invoice_id(&self, tx: &dyn ReadTx) -> Result<[u8; 16], Status> {
        for _ in 0..8 {
            let mut id = [0u8; INVOICE_ID_BYTES];
            self.random.fill(&mut id).map_err(|_| unavailable())?;
            if id != [0; 16] && store::invoice(tx, &id)?.is_none() {
                return Ok(id);
            }
        }
        Err(unavailable())
    }

    /// Invoices still waiting for payment (CREATED or SEEN).
    fn open_unpaid(tx: &dyn ReadTx) -> Result<u64, StoreError> {
        Ok(store::invoices(tx)?
            .iter()
            .filter(|(_, r)| matches!(r.state, InvoiceState::Created | InvoiceState::Seen))
            .count() as u64)
    }

    /// Step 2 of `RequestInvoice` (and its re-check in step 7): the answer for a known claim hash.
    fn known_claim(
        &self,
        tx: &dyn ReadTx,
        claim_hash: &[u8; 32],
        r: &[u8; 32],
    ) -> Result<Option<wire::RequestInvoiceResponse>, Status> {
        let Some(id) = store::claim_index(tx, claim_hash)? else {
            return Ok(None);
        };
        let row = store::invoice(tx, &id)?.ok_or_else(unavailable)?;
        Ok(Some(if row.request_digest == *r {
            wire::RequestInvoiceResponse {
                result: wire::RequestInvoiceResult::Ok as i32,
                invoice_id: id.to_vec(),
                amount_atomic: row.amount,
                subaddress: row.subaddress_text().to_string(),
                spent_mask: 0,
            }
        } else {
            wire::RequestInvoiceResponse {
                result: wire::RequestInvoiceResult::ClaimConflict as i32,
                ..Default::default()
            }
        }))
    }

    // -----------------------------------------------------------------------------------------
    // Handlers.
    // -----------------------------------------------------------------------------------------

    /// `RequestInvoice` (§5.6): sizes, idempotency by `claim_hash`, ES coverage and held keys,
    /// the base week, the credits, the XMR preconditions, then one decided transaction.
    pub fn request_invoice_at(
        &self,
        req: wire::RequestInvoiceRequest,
        now: u64,
    ) -> Result<wire::RequestInvoiceResponse, Status> {
        self.ensure_running()?;
        self.take_rate_token(now)?;
        // 1. Sizes and enum values (a credit is exactly 354 bytes; its content is a validity
        // question, step 5).
        if req.version != PROTOCOL_VERSION
            || wire::Rail::try_from(req.rail) != Ok(wire::Rail::Monero)
            || wire::Product::try_from(req.product) != Ok(wire::Product::Pack)
            || req.claim_hash.len() != CLAIM_BYTES
            || req.credits.len() > MAX_DISCOUNT_CREDITS
            || req.credits.iter().any(|c| c.len() != TOKEN_LEN)
        {
            return Err(rejected());
        }
        let claim_hash: [u8; 32] = fixed(&req.claim_hash)?;
        // The nullifier covers `token_input` whatever its `token_type`.
        let nullifiers = req
            .credits
            .iter()
            .map(|c| c[..TOKEN_INPUT_LEN].try_into().map(token::nullifier))
            .collect::<Result<Vec<[u8; 32]>, _>>()
            .map_err(|_| rejected())?;
        let r = request_invoice_digest(req.base_week, &nullifiers);
        // 2. Idempotency first: nothing else is checked for a known claim hash.
        if let Some(answer) = self.known_claim(&*self.store.read()?, &claim_hash, &r)? {
            return Ok(answer);
        }
        // 3. The ES covers the layout and every layout key is held.
        let paid_in_xmr = req.credits.is_empty();
        let layout =
            Layout::pack(&self.schedule, req.base_week, paid_in_xmr).map_err(|_| unavailable())?;
        self.require_keys(&layout).map_err(SignFailure::status)?;
        // 4. The base week.
        if !base_week_ok(req.base_week, now) {
            return Ok(wire::RequestInvoiceResponse {
                result: wire::RequestInvoiceResult::WrongPeriod as i32,
                ..Default::default()
            });
        }
        // 5. Credits.
        let price = self
            .schedule
            .pack_price(price_epoch(req.base_week))
            .ok_or_else(unavailable)?;
        let credits = if paid_in_xmr {
            Vec::new()
        } else {
            let tokens = req
                .credits
                .iter()
                .map(|c| Token::parse(c))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| unauthorized())?;
            let closed = self.closed_through(MetaKey::ClosedThroughCreditEpoch)?;
            let credits =
                credit::verify(&self.schedule, &tokens, now, closed).ok_or_else(unauthorized)?;
            let floor = self.schedule.constants().credits_per_free_pack;
            if !credit::covers(&credits, price, floor) {
                return Err(unauthorized());
            }
            let mask = credit::spent_mask(&*self.store.read()?, &credits)?;
            if mask != 0 {
                return Ok(credits_spent(mask));
            }
            credits
        };
        // 6. XMR: a fresh synced tick, a pool entry, room under the open-invoice cap.
        let height = if paid_in_xmr {
            let tick = self.fresh_synced_tick(now).ok_or_else(unavailable)?;
            let tx = self.store.read()?;
            if store::pool_first(&*tx)?.is_none()
                || Self::open_unpaid(&*tx)? >= self.params.max_open_invoices
            {
                return Err(unavailable());
            }
            tick.daemon
        } else {
            self.volatile().last_wallet_height.unwrap_or(0)
        };
        // 7. One decided transaction.
        let tx = self.store.write()?;
        if let Some(answer) = self.known_claim(&*tx, &claim_hash, &r)? {
            return Ok(answer);
        }
        if Self::credits_closed(&*tx, &credits)? {
            return Err(unauthorized());
        }
        let mask = credit::spent_mask(&*tx, &credits)?;
        if mask != 0 {
            return Ok(credits_spent(mask));
        }
        let (minor, subaddress) = if paid_in_xmr {
            store::pool_first(&*tx)?.ok_or_else(unavailable)?
        } else {
            (0, [0u8; ADDRESS_LEN])
        };
        let invoice_id = self.fresh_invoice_id(&*tx)?;
        let c = self.schedule.constants();
        let (amount, grace_height, pay_with) = if paid_in_xmr {
            let grace = height
                .saturating_add(u64::from(c.invoice_blocks))
                .saturating_add(u64::from(c.grace_blocks));
            (price, grace, PayWith::Monero)
        } else {
            (0, 0, PayWith::Credits)
        };
        let entry = Entry::Invoice(InvoiceEntry {
            invoice_id,
            claim_hash,
            request_digest: r,
            pay_with,
            minor,
            subaddress,
            amount,
            base_week: req.base_week,
            created_height: height,
            grace_height,
            credits: credits.iter().map(|c| (c.epoch, c.nullifier)).collect(),
        });
        self.decide(tx, &entry, now, height)?;
        let text = if paid_in_xmr {
            std::str::from_utf8(&subaddress).unwrap_or("").to_string()
        } else {
            String::new()
        };
        Ok(wire::RequestInvoiceResponse {
            result: wire::RequestInvoiceResult::Ok as i32,
            invoice_id: invoice_id.to_vec(),
            amount_atomic: amount,
            subaddress: text,
            spent_mask: 0,
        })
    }

    /// Steps 1–2 of §5.5 (shared with `InvoiceStatus`): sizes, then the invoice and its claim
    /// key; an unknown invoice and a wrong key give the same answer (no existence oracle).
    fn authorize(
        &self,
        version: u32,
        invoice_id: &[u8],
        claim_key: &[u8],
    ) -> Result<([u8; 16], InvoiceRow), Status> {
        if version != PROTOCOL_VERSION
            || invoice_id.len() != INVOICE_ID_BYTES
            || claim_key.len() != CLAIM_BYTES
        {
            return Err(rejected());
        }
        let id: [u8; 16] = fixed(invoice_id)?;
        let key: [u8; 32] = fixed(claim_key)?;
        let row = store::invoice(&*self.store.read()?, &id)?;
        let hash = batch::claim_hash(&key);
        match row {
            Some(row) if ct_eq(&hash, &row.claim_hash) => Ok((id, row)),
            _ => Err(unauthorized()),
        }
    }

    /// `BlindSign` (§5.5): the payment poll and the one issuance of a paid invoice (MS-1, MS-2).
    pub fn blind_sign_at(
        &self,
        req: wire::BlindSignRequest,
        now: u64,
    ) -> Result<wire::BlindSignResponse, Status> {
        self.ensure_running()?;
        if req.blinded.is_empty()
            || !req.blinded.len().is_multiple_of(BLOCK_BYTES)
            || req.blinded.len() > MAX_LAYOUT_POSITIONS * BLOCK_BYTES
        {
            return Err(rejected());
        }
        let (id, row) = self.authorize(req.version, &req.invoice_id, &req.claim_key)?;
        // 3. Not paid (yet): the state and the amounts, nothing signed, nothing recorded.
        if !matches!(row.state, InvoiceState::Confirmed | InvoiceState::Issued) {
            return Ok(state_answer(&row));
        }
        // 4. Layout and ranges.
        let layout = Layout::pack(
            &self.schedule,
            row.base_week,
            row.pay_with == PayWith::Monero,
        )
        .map_err(|_| unavailable())?;
        self.check_blocks(&layout, &req.blinded)?;
        // 5. The request digest.
        let digest = batch::request_digest(&id, &req.blinded);
        let mut row = row;
        loop {
            match row.state {
                // 6. Issued: only the identical request is served, byte for byte.
                InvoiceState::Issued => {
                    if row.issued_digest != Some(digest) {
                        return Ok(wire::BlindSignResponse {
                            state: wire::InvoiceState::OtherRequestIssued as i32,
                            blind_signatures: Vec::new(),
                            credited_atomic: row.credited,
                            seen_atomic: row.seen,
                        });
                    }
                    let sigs = self
                        .sign_all(&layout, &req.blinded)
                        .map_err(SignFailure::status)?;
                    return Ok(signed(&row, sigs));
                }
                // 7. Confirmed: sign outside the transaction, then compare-and-set.
                InvoiceState::Confirmed => {
                    let sigs = self
                        .sign_all(&layout, &req.blinded)
                        .map_err(SignFailure::status)?;
                    let tx = self.store.write()?;
                    let Some(fresh) = store::invoice(&*tx, &id)? else {
                        return Err(unauthorized());
                    };
                    if fresh.state != InvoiceState::Confirmed {
                        // Another request won the race, or a reorg reverted the payment: the
                        // computed signatures are dropped and never leave the process.
                        drop(tx);
                        drop(sigs);
                        row = fresh;
                        continue;
                    }
                    let height = self.volatile().last_wallet_height.unwrap_or(0);
                    self.decide(
                        tx,
                        &Entry::Issue {
                            invoice_id: id,
                            digest,
                        },
                        now,
                        height,
                    )?;
                    return Ok(signed(&fresh, sigs));
                }
                _ => return Ok(state_answer(&row)),
            }
        }
    }

    /// `InvoiceStatus` (§5.6): a database read; never signs.
    pub fn invoice_status_at(
        &self,
        req: wire::InvoiceStatusRequest,
        _now: u64,
    ) -> Result<wire::InvoiceStatusResponse, Status> {
        self.ensure_running()?;
        let (_, row) = self.authorize(req.version, &req.invoice_id, &req.claim_key)?;
        Ok(wire::InvoiceStatusResponse {
            state: reported_state(invoice::reported(&row)) as i32,
            credited_atomic: row.credited,
            seen_atomic: row.seen,
        })
    }

    /// Runbook housekeeping (§6.4, §19.1 rule 2, §19.10): closes invite epochs before
    /// `e_now − 1` and credit epochs before `c_now − 4` by raising the persisted closed-through
    /// high-water marks (a new redemption of a closed epoch is refused whatever the clock says
    /// later), deletes in the same transaction the credit nullifiers of the closed epochs and the
    /// invite nullifiers of epochs whose trials are all past their re-serve window
    /// ([`TRIAL_RESERVE_HOLD_SECS`]), deletes counters past retention, and destroys keys (K4).
    pub fn sweep_at(&self, now: u64) -> Result<SweepReport, StoreError> {
        if self.is_halted() {
            return Err(StoreError::Db);
        }
        let w = week(now);
        let mut report = SweepReport::default();
        let mut tx = self.store.write()?;
        if let Some(e) = invite_epoch(w).checked_sub(2) {
            let held = invite_epoch(week(now.saturating_sub(TRIAL_RESERVE_HOLD_SECS)));
            report.invite_nullifiers = close_through(
                &mut *tx,
                Table::InviteNullifier,
                MetaKey::ClosedThroughInviteEpoch,
                e,
                held.checked_sub(2),
            )?;
        }
        if let Some(c) = ghost_entitlement::grid::credit_epoch(w).checked_sub(5) {
            report.credit_nullifiers = close_through(
                &mut *tx,
                Table::CreditNullifier,
                MetaKey::ClosedThroughCreditEpoch,
                c,
                Some(c),
            )?;
        }
        reconcile::sweep(&mut *tx, now)?;
        tx.commit()?;
        report.keys_destroyed = self.destroy_keys(now)?;
        Ok(report)
    }
}

/// What one sweep removed.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SweepReport {
    pub invite_nullifiers: usize,
    pub credit_nullifiers: usize,
    pub keys_destroyed: Vec<(Kind, u64)>,
}

/// Raises the closed-through mark to `through` (never lowers it) and deletes every nullifier of
/// an epoch at or below `delete_through` (never above the mark; `None`: nothing is deleted).
fn close_through(
    tx: &mut dyn WriteTx,
    table: Table,
    key: MetaKey,
    through: u64,
    delete_through: Option<u64>,
) -> Result<usize, StoreError> {
    let mark = store::meta(tx, key)?.map_or(through, |old| old.max(through));
    store::set_meta(tx, key, mark)?;
    let Some(last) = delete_through.map(|d| d.min(mark)) else {
        return Ok(0);
    };
    let end = last.checked_add(1).map(u64::to_be_bytes);
    let rows = tx.range(table, &[], end.as_ref().map(|e| e.as_slice()))?;
    for (k, _) in &rows {
        tx.delete(table, k)?;
    }
    Ok(rows.len())
}

fn credits_spent(mask: u64) -> wire::RequestInvoiceResponse {
    wire::RequestInvoiceResponse {
        result: wire::RequestInvoiceResult::CreditsSpent as i32,
        spent_mask: mask as u32,
        ..Default::default()
    }
}

fn signed(row: &InvoiceRow, sigs: Vec<u8>) -> wire::BlindSignResponse {
    wire::BlindSignResponse {
        state: wire::InvoiceState::Signed as i32,
        blind_signatures: sigs,
        credited_atomic: row.credited,
        seen_atomic: row.seen,
    }
}

fn state_answer(row: &InvoiceRow) -> wire::BlindSignResponse {
    wire::BlindSignResponse {
        state: reported_state(invoice::reported(row)) as i32,
        blind_signatures: Vec::new(),
        credited_atomic: row.credited,
        seen_atomic: row.seen,
    }
}

/// The wire state of a stored invoice. A CONFIRMED invoice that is not issued yet is reported
/// as AWAITING_CONFIRMATIONS with `credited_atomic ≥ amount` (`BlindSign` signs it instead).
pub(crate) fn reported_state(r: Reported) -> wire::InvoiceState {
    match r {
        Reported::AwaitingPayment => wire::InvoiceState::AwaitingPayment,
        Reported::AwaitingConfirmations | Reported::Confirmed => {
            wire::InvoiceState::AwaitingConfirmations
        }
        Reported::Underpaid => wire::InvoiceState::Underpaid,
        Reported::Expired => wire::InvoiceState::Expired,
        Reported::Issued => wire::InvoiceState::Signed,
    }
}
