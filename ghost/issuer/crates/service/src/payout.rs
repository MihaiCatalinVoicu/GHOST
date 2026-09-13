//! The payout pipeline, issuer side (Phase 8 design §9.5, §19.5, §19.7; ADR-26): queued claims
//! are assigned to batches (journaled `BATCH`), each batch is exported as a file signed with the
//! Ed25519 ops key for the operator workstation, and the workstation's acknowledgement (every
//! entry paid or refused) closes the batch (journaled `BATCH_PAID`).
//!
//! ```text
//! batch file := "GHPB" || version u8 = 1 || network u8 (the ES byte) || batch_id 16 || week u64
//!               || count u16 (1..200) || count x (claim_id 16 || address 95 || amount u64)
//!               || total u64 || cumulative_credited u64
//!               || Ed25519(ops key, "ghost/v1/payout-batch" || every preceding byte) (64)
//! ack file   := "GHPA" || version u8 = 1 || batch_id 16 || count u16 (1..200)
//!               || count x (claim_id 16 || outcome u8: 1 paid, 2 refused)
//! ```
//! Big-endian fixed fields. The entries of a batch are ordered by
//! `SHA-256("ghost/v1/payout-order" || batch_id || claim_id)`: shuffled against the order the
//! claims arrived in, and the same at every export, so the file of an unacknowledged batch is
//! rewritten byte for byte (Ed25519 signatures are deterministic), also after a restore (the
//! `BATCH` entry carries every field). Files: `batch-<batch id hex>.ghpb` and
//! `ack-<batch id hex>.ghpa` in the export directory.
//!
//! **When** (§9.5 step 1). The server runs [`Issuer::payout_job_at`] hourly. The first run of a
//! week draws the week's export hour uniformly among its 168 hours ([`export_hour`]) and keeps it
//! in `meta`, so a restart does not draw again. The first run at or after that hour batches every
//! queued claim, and nothing more is batched that week, also when the queue was empty then: a claim
//! queued later waits for the next week's hour. When a batch is created therefore never depends on
//! when its claims arrived. A crash between that decision and the batches leaves the claims queued
//! for the next week. Every run imports acknowledgements, removes residues and rewrites the files
//! of unacknowledged batches.
//!
//! **Acknowledgement** (§9.5 step 4). An ack file names exactly the claims of an exported batch,
//! each paid or refused (`ghost-issuer-ops payout-ack` writes it once every entry is confirmed or
//! refused). The workstation refuses an entry whose payout address it has seen before (§9.5 step
//! 2); a claimant chooses that address, so it refuses the entry and never the batch, and one
//! address can never stall the other payouts of its batch. The issuer journals `BATCH_PAID` with
//! the refused claim ids, marks the claims paid or refused, deletes every payout address of the
//! batch, adds the paid amounts to `payout_paid_atomic` and the refused ones to
//! `payout_refused_atomic`, and deletes the batch and ack files. A refused claim's credits stay
//! spent: no refund path exists (§0.6), and the client refuses to reuse an address it paid to
//! (§9.4). The ack carries no payout txid: the issuer could not check one, and it would link a
//! claim to its on-chain transaction on the internet-facing host. Recorded: the ack file carries
//! no signature; it moves no value (the batch file does), and the export directory is on the
//! issuer's encrypted volume, where the operator who carries the ack file over already has write
//! access.
//!
//! **Residues** (§6.4). Every run deletes a temporary batch file a crash left behind, the file of a
//! batch that is no longer exported, and an ack file that can never apply (its batch is not
//! exported). It counts every refused ack ([`PayoutReport::acks_refused`], `PAYOUT_ACKS_REFUSED` in
//! status.json); an ack of an exported batch that does not match stays for the operator to replace.
//! An entry that cannot be read (a directory, a read error) is a refused ack, never a failed run.
//!
//! **Retention** (§6.1, §6.4). A closed batch's claims are deleted at the start of the week after
//! its acknowledgement ([`CLAIMS_KEEP_WEEKS`]) and its row four weeks after it
//! ([`BATCH_KEEP_WEEKS`]): never more than 7 and 30 days after the acknowledgement. Weeks are the
//! only clock (§19.15), so an acknowledgement late in its week keeps them for less; an identical
//! `ClaimPayout` retry after the deletion answers `CREDITS_SPENT` (its payout was made or refused).
//!
//! This module, `status.rs`, `store.rs` and `journal.rs` are the only service modules that write
//! files (`issuer-output.sh`).

use std::collections::{BTreeMap, BTreeSet};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use ghost_entitlement::grid::{week, week_start};
use ghost_entitlement::monero::MoneroNetwork;
use sha2::{Digest, Sha256};

use crate::journal::{BatchEntry, Entry, MAX_BATCH_CLAIMS};
use crate::rail::hex_encode;
use crate::reconcile::{self, CounterId};
use crate::service::{ApplyError, Issuer};
use crate::store::{
    self, BatchRow, BatchState, ClaimState, MetaKey, ReadTx, StoreError, Table, WriteTx,
    ADDRESS_LEN,
};

pub const BATCH_MAGIC: &[u8; 4] = b"GHPB";
pub const ACK_MAGIC: &[u8; 4] = b"GHPA";
pub const FORMAT_VERSION: u8 = 1;
/// Domain of the ops key's signature over a batch file.
pub const BATCH_SIGNATURE_DOMAIN: &[u8] = b"ghost/v1/payout-batch";
/// Length of the ops key's seed file and of its public key.
pub const OPS_SEED_LEN: usize = 32;
pub const SIGNATURE_LEN: usize = 64;
/// A closed batch's claims are deleted at the start of the week after the week of its
/// acknowledgement: at most the 7 days of §6.1 and §6.4 after it.
pub const CLAIMS_KEEP_WEEKS: u64 = 1;
/// A closed batch row is deleted this many weeks after the week of its acknowledgement: at most
/// the 30 days of §6.1 after it.
pub const BATCH_KEEP_WEEKS: u64 = 4;
/// Hours in an ISO week: the candidates of the weekly export hour.
pub const WEEK_HOURS: u64 = 168;

const ORDER_DOMAIN: &[u8] = b"ghost/v1/payout-order";
const BATCH_PREFIX: &str = "batch-";
const BATCH_SUFFIX: &str = ".ghpb";
/// A batch file is written as `batch-<id>.tmp` and renamed (see [`write_atomically`]).
const TMP_SUFFIX: &str = ".tmp";
const ACK_PREFIX: &str = "ack-";
const ACK_SUFFIX: &str = ".ghpa";
const LINE_LEN: usize = 16 + ADDRESS_LEN + 8;
const ACK_LINE_LEN: usize = 16 + 1;
const HOUR_SECS: u64 = 3_600;

/// The ops key: signs payout batch files (§9.5 step 1). `Debug` never shows it.
pub struct OpsKey(SigningKey);

impl OpsKey {
    pub fn from_seed(seed: &[u8; OPS_SEED_LEN]) -> Self {
        Self(SigningKey::from_bytes(seed))
    }

    /// The public key the workstation checks batch files with.
    pub fn public(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }
}

impl std::fmt::Debug for OpsKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("OpsKey(redacted)")
    }
}

/// Why a batch or ack file was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PayoutFileError {
    /// Not a file of this format (magic, version, lengths, counts, amounts, totals, duplicates).
    Format,
    /// The ops key's signature does not verify.
    Signature,
}

impl std::fmt::Display for PayoutFileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            PayoutFileError::Format => "not a payout file of version 1",
            PayoutFileError::Signature => "payout batch signature invalid",
        })
    }
}

impl std::error::Error for PayoutFileError {}

fn take<'a>(r: &mut &'a [u8], n: usize) -> Result<&'a [u8], PayoutFileError> {
    if r.len() < n {
        return Err(PayoutFileError::Format);
    }
    let (head, tail) = r.split_at(n);
    *r = tail;
    Ok(head)
}

fn take_array<const N: usize>(r: &mut &[u8]) -> Result<[u8; N], PayoutFileError> {
    take(r, N)?.try_into().map_err(|_| PayoutFileError::Format)
}

fn take_u64(r: &mut &[u8]) -> Result<u64, PayoutFileError> {
    Ok(u64::from_be_bytes(take_array(r)?))
}

/// A count u16 of 1 ..= [`MAX_BATCH_CLAIMS`].
fn take_count(r: &mut &[u8]) -> Result<usize, PayoutFileError> {
    let n = usize::from(u16::from_be_bytes(take_array(r)?));
    if n == 0 || n > MAX_BATCH_CLAIMS {
        return Err(PayoutFileError::Format);
    }
    Ok(n)
}

fn count_u16(n: usize) -> Result<[u8; 2], PayoutFileError> {
    if n == 0 || n > MAX_BATCH_CLAIMS {
        return Err(PayoutFileError::Format);
    }
    Ok((n as u16).to_be_bytes())
}

/// One payout: the claim, its payout address and its amount.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchLine {
    pub claim_id: [u8; 16],
    pub address: [u8; ADDRESS_LEN],
    pub amount: u64,
}

impl BatchLine {
    /// The payout address as text (Base58 is ASCII; the workstation validates it, §7.7).
    pub fn address_text(&self) -> &str {
        std::str::from_utf8(&self.address).unwrap_or("")
    }
}

/// A payout batch file (§9.5 step 1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchFile {
    pub network: MoneroNetwork,
    pub batch_id: [u8; 16],
    pub week: u64,
    pub entries: Vec<BatchLine>,
    pub total: u64,
    pub cumulative_credited: u64,
}

impl BatchFile {
    /// Every amount positive, their sum the total, claim ids distinct, addresses ASCII.
    fn check(&self) -> Result<(), PayoutFileError> {
        let mut sum = 0u64;
        let mut ids = BTreeSet::new();
        for e in &self.entries {
            sum = sum.checked_add(e.amount).ok_or(PayoutFileError::Format)?;
            if e.amount == 0 || !ids.insert(e.claim_id) || !e.address.is_ascii() {
                return Err(PayoutFileError::Format);
            }
        }
        if sum != self.total {
            return Err(PayoutFileError::Format);
        }
        Ok(())
    }

    fn body(&self) -> Result<Vec<u8>, PayoutFileError> {
        let count = count_u16(self.entries.len())?;
        let mut w = Vec::with_capacity(38 + self.entries.len() * LINE_LEN + 16);
        w.extend_from_slice(BATCH_MAGIC);
        w.push(FORMAT_VERSION);
        w.push(self.network.schedule_byte());
        w.extend_from_slice(&self.batch_id);
        w.extend_from_slice(&self.week.to_be_bytes());
        w.extend_from_slice(&count);
        for e in &self.entries {
            w.extend_from_slice(&e.claim_id);
            w.extend_from_slice(&e.address);
            w.extend_from_slice(&e.amount.to_be_bytes());
        }
        w.extend_from_slice(&self.total.to_be_bytes());
        w.extend_from_slice(&self.cumulative_credited.to_be_bytes());
        Ok(w)
    }

    /// The signed file.
    pub fn sign(&self, key: &OpsKey) -> Result<Vec<u8>, PayoutFileError> {
        self.check()?;
        let mut out = self.body()?;
        let signature = key.0.sign(&[BATCH_SIGNATURE_DOMAIN, &out].concat());
        out.extend_from_slice(&signature.to_bytes());
        Ok(out)
    }

    /// Verifies the ops key's signature first, then parses strictly.
    pub fn verify(bytes: &[u8], ops_public: &[u8; 32]) -> Result<Self, PayoutFileError> {
        if bytes.len() < SIGNATURE_LEN {
            return Err(PayoutFileError::Format);
        }
        let (body, signature) = bytes.split_at(bytes.len() - SIGNATURE_LEN);
        let key = VerifyingKey::from_bytes(ops_public).map_err(|_| PayoutFileError::Signature)?;
        let signature = Signature::from_slice(signature).map_err(|_| PayoutFileError::Signature)?;
        key.verify_strict(&[BATCH_SIGNATURE_DOMAIN, body].concat(), &signature)
            .map_err(|_| PayoutFileError::Signature)?;
        let file = Self::parse_body(body)?;
        file.check()?;
        Ok(file)
    }

    fn parse_body(mut r: &[u8]) -> Result<Self, PayoutFileError> {
        if take(&mut r, 4)? != BATCH_MAGIC || take(&mut r, 1)? != [FORMAT_VERSION] {
            return Err(PayoutFileError::Format);
        }
        let network = MoneroNetwork::from_schedule_byte(take(&mut r, 1)?[0])
            .ok_or(PayoutFileError::Format)?;
        let batch_id = take_array(&mut r)?;
        let week = take_u64(&mut r)?;
        let count = take_count(&mut r)?;
        let entries = (0..count)
            .map(|_| {
                Ok(BatchLine {
                    claim_id: take_array(&mut r)?,
                    address: take_array(&mut r)?,
                    amount: take_u64(&mut r)?,
                })
            })
            .collect::<Result<Vec<_>, PayoutFileError>>()?;
        let total = take_u64(&mut r)?;
        let cumulative_credited = take_u64(&mut r)?;
        if !r.is_empty() {
            return Err(PayoutFileError::Format);
        }
        Ok(Self {
            network,
            batch_id,
            week,
            entries,
            total,
            cumulative_credited,
        })
    }
}

/// What the workstation did with one entry of a batch (§9.5 steps 2–4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EntryOutcome {
    /// Paid, with at least 10 confirmations.
    Paid,
    /// Refused: its payout address was seen before (§9.5 step 2); never paid.
    Refused,
}

impl EntryOutcome {
    pub fn code(self) -> u8 {
        match self {
            EntryOutcome::Paid => 1,
            EntryOutcome::Refused => 2,
        }
    }

    pub fn from_code(c: u8) -> Option<Self> {
        match c {
            1 => Some(EntryOutcome::Paid),
            2 => Some(EntryOutcome::Refused),
            _ => None,
        }
    }
}

/// The workstation's acknowledgement of a closed batch (§9.5 step 4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AckFile {
    pub batch_id: [u8; 16],
    /// (claim id, its outcome), in the batch file's order.
    pub entries: Vec<([u8; 16], EntryOutcome)>,
}

impl AckFile {
    pub fn encode(&self) -> Result<Vec<u8>, PayoutFileError> {
        let count = count_u16(self.entries.len())?;
        let mut w = Vec::with_capacity(23 + self.entries.len() * ACK_LINE_LEN);
        w.extend_from_slice(ACK_MAGIC);
        w.push(FORMAT_VERSION);
        w.extend_from_slice(&self.batch_id);
        w.extend_from_slice(&count);
        for (claim, outcome) in &self.entries {
            w.extend_from_slice(claim);
            w.push(outcome.code());
        }
        Ok(w)
    }

    pub fn parse(mut r: &[u8]) -> Result<Self, PayoutFileError> {
        if take(&mut r, 4)? != ACK_MAGIC || take(&mut r, 1)? != [FORMAT_VERSION] {
            return Err(PayoutFileError::Format);
        }
        let batch_id = take_array(&mut r)?;
        let count = take_count(&mut r)?;
        let entries = (0..count)
            .map(|_| {
                let claim = take_array(&mut r)?;
                let outcome =
                    EntryOutcome::from_code(take(&mut r, 1)?[0]).ok_or(PayoutFileError::Format)?;
                Ok((claim, outcome))
            })
            .collect::<Result<Vec<_>, PayoutFileError>>()?;
        if !r.is_empty() {
            return Err(PayoutFileError::Format);
        }
        Ok(Self { batch_id, entries })
    }
}

/// `batch-<batch id hex>.ghpb`.
pub fn batch_file_name(batch_id: &[u8; 16]) -> String {
    format!("{BATCH_PREFIX}{}{BATCH_SUFFIX}", hex_encode(batch_id))
}

/// `ack-<batch id hex>.ghpa`.
pub fn ack_file_name(batch_id: &[u8; 16]) -> String {
    format!("{ACK_PREFIX}{}{ACK_SUFFIX}", hex_encode(batch_id))
}

/// The batch id a file name `<prefix><32 lowercase hex digits><suffix>` names, if it is one.
fn named_batch_id(name: &str, prefix: &str, suffix: &str) -> Option<[u8; 16]> {
    crate::rail::hex_decode(name.strip_prefix(prefix)?.strip_suffix(suffix)?)
}

/// The batch id an ack file name names.
fn ack_batch_id(name: &str) -> Option<[u8; 16]> {
    named_batch_id(name, ACK_PREFIX, ACK_SUFFIX)
}

/// The position key of a claim in its batch file.
fn order_key(batch_id: &[u8; 16], claim_id: &[u8; 16]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(ORDER_DOMAIN);
    h.update(batch_id);
    h.update(claim_id);
    h.finalize().into()
}

/// The export hour of week `w` for a uniform `draw`, as an absolute hour (Unix seconds / 3 600):
/// one of the week's 168 hours, uniformly (§9.5 step 1).
pub fn export_hour(w: u64, draw: u64) -> u64 {
    week_start(w) / HOUR_SECS + draw % WEEK_HOURS
}

/// What one payout run did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PayoutReport {
    /// Batches created (journaled `BATCH`).
    pub created: Vec<[u8; 16]>,
    /// Batch files written (new or rewritten because they differed).
    pub written: usize,
    /// Batches acknowledged in this run (journaled `BATCH_PAID`).
    pub acknowledged: Vec<[u8; 16]>,
    /// Ack files that do not match an exported batch or cannot be read.
    pub acks_refused: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PayoutError {
    Halted,
    Store(StoreError),
    /// A decided transition failed (the issuer is halted until a restart).
    Decide,
    Random,
    /// The export directory could not be read or written.
    Io,
    File(PayoutFileError),
}

impl From<StoreError> for PayoutError {
    fn from(e: StoreError) -> Self {
        PayoutError::Store(e)
    }
}

/// What an acknowledgement did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AckOutcome {
    Paid,
    AlreadyPaid,
    /// It does not name exactly the claims of an exported batch.
    Refused,
}

/// Writes a file atomically: a temporary file next to it, synced, then renamed over it.
fn write_atomically(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&tmp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    std::fs::rename(&tmp, path)
}

fn remove_if_present(path: &Path) -> Result<(), PayoutError> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(PayoutError::Io),
    }
}

/// What the export directory holds that a run looks at.
#[derive(Default)]
struct ExportFiles {
    acks: BTreeMap<[u8; 16], PathBuf>,
    batches: Vec<([u8; 16], PathBuf)>,
    temporary: Vec<PathBuf>,
}

/// Lists the export directory; entries that cannot be listed or named are skipped.
fn export_files(dir: &Path) -> Result<ExportFiles, PayoutError> {
    let mut files = ExportFiles::default();
    for item in std::fs::read_dir(dir)
        .map_err(|_| PayoutError::Io)?
        .flatten()
    {
        let name = item.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if let Some(id) = ack_batch_id(name) {
            files.acks.insert(id, item.path());
        } else if let Some(id) = named_batch_id(name, BATCH_PREFIX, BATCH_SUFFIX) {
            files.batches.push((id, item.path()));
        } else if named_batch_id(name, BATCH_PREFIX, TMP_SUFFIX).is_some() {
            files.temporary.push(item.path());
        }
    }
    Ok(files)
}

impl Issuer {
    fn ensure_payout_running(&self) -> Result<(), PayoutError> {
        if self.is_halted() {
            Err(PayoutError::Halted)
        } else {
            Ok(())
        }
    }

    fn fresh_batch_id(&self, tx: &dyn ReadTx) -> Result<[u8; 16], PayoutError> {
        for _ in 0..8 {
            let mut id = [0u8; 16];
            self.random.fill(&mut id).map_err(|_| PayoutError::Random)?;
            if id != [0; 16] && store::batch(tx, &id)?.is_none() {
                return Ok(id);
            }
        }
        Err(PayoutError::Random)
    }

    /// Assigns every queued claim to new batches of at most [`MAX_BATCH_CLAIMS`] claims, one
    /// decided transaction (`BATCH`) each (§9.5 step 1, §19.5).
    pub fn create_batches_at(&self, now: u64) -> Result<Vec<[u8; 16]>, PayoutError> {
        self.ensure_payout_running()?;
        let mut created = Vec::new();
        loop {
            let tx = self.store.write()?;
            let claims: Vec<[u8; 16]> = store::claims(&*tx)?
                .into_iter()
                .filter(|(_, c)| c.state == ClaimState::Queued)
                .map(|(id, _)| id)
                .take(MAX_BATCH_CLAIMS)
                .collect();
            if claims.is_empty() {
                return Ok(created);
            }
            let batch_id = self.fresh_batch_id(&*tx)?;
            let cumulative_credited =
                reconcile::get(&*tx, CounterId::XmrCreditedTotal, reconcile::TOTAL_INDEX)?;
            let entry = Entry::Batch(BatchEntry {
                batch_id,
                week: week(now),
                cumulative_credited,
                claims,
            });
            self.decide(tx, &entry, now, 0)
                .map_err(|_| PayoutError::Decide)?;
            created.push(batch_id);
        }
    }

    /// The signed file of an exported (unacknowledged) batch, from the database; `None` for an
    /// unknown or closed batch.
    pub fn batch_file(
        &self,
        batch_id: &[u8; 16],
        key: &OpsKey,
    ) -> Result<Option<Vec<u8>>, PayoutError> {
        let tx = self.store.read()?;
        let Some(row) = store::batch(&*tx, batch_id)? else {
            return Ok(None);
        };
        if row.state != BatchState::Exported {
            return Ok(None);
        }
        let mut entries: Vec<BatchLine> = store::claims(&*tx)?
            .into_iter()
            .filter(|(_, c)| c.batch_id == *batch_id && c.state == ClaimState::Batched)
            .map(|(claim_id, c)| BatchLine {
                claim_id,
                address: c.address,
                amount: c.amount,
            })
            .collect();
        if entries.len() != usize::from(row.entries) {
            return Err(PayoutError::Store(StoreError::Corrupt));
        }
        entries.sort_by_key(|e| order_key(batch_id, &e.claim_id));
        let file = BatchFile {
            network: self.schedule.network(),
            batch_id: *batch_id,
            week: row.week,
            entries,
            total: row.total,
            cumulative_credited: row.cumulative_credited,
        };
        file.sign(key).map(Some).map_err(PayoutError::File)
    }

    /// (Re)writes the file of every exported batch that is missing or differs.
    pub fn write_batch_files(&self, key: &OpsKey, dir: &Path) -> Result<usize, PayoutError> {
        std::fs::create_dir_all(dir).map_err(|_| PayoutError::Io)?;
        let exported: Vec<[u8; 16]> = store::batches(&*self.store.read()?)?
            .into_iter()
            .filter(|(_, b)| b.state == BatchState::Exported)
            .map(|(id, _)| id)
            .collect();
        let mut written = 0;
        for id in exported {
            let Some(bytes) = self.batch_file(&id, key)? else {
                continue;
            };
            let path = dir.join(batch_file_name(&id));
            if std::fs::read(&path).is_ok_and(|current| current == bytes) {
                continue;
            }
            write_atomically(&path, &bytes).map_err(|_| PayoutError::Io)?;
            written += 1;
        }
        Ok(written)
    }

    /// §9.5 step 4: the acknowledgement of every entry of an exported batch, each paid or refused;
    /// one decided transaction (`BATCH_PAID`).
    pub fn acknowledge_at(&self, ack: &AckFile, now: u64) -> Result<AckOutcome, PayoutError> {
        self.ensure_payout_running()?;
        let tx = self.store.write()?;
        let Some(row) = store::batch(&*tx, &ack.batch_id)? else {
            return Ok(AckOutcome::Refused);
        };
        if row.state == BatchState::Paid {
            return Ok(AckOutcome::AlreadyPaid);
        }
        let claims: BTreeSet<[u8; 16]> = store::claims(&*tx)?
            .into_iter()
            .filter(|(_, c)| c.batch_id == ack.batch_id && c.state == ClaimState::Batched)
            .map(|(id, _)| id)
            .collect();
        let acked: BTreeSet<[u8; 16]> = ack.entries.iter().map(|(c, _)| *c).collect();
        let n = ack.entries.len();
        if acked != claims || acked.len() != n || n != usize::from(row.entries) {
            return Ok(AckOutcome::Refused);
        }
        let refused: BTreeSet<[u8; 16]> = ack
            .entries
            .iter()
            .filter(|(_, o)| *o == EntryOutcome::Refused)
            .map(|(c, _)| *c)
            .collect();
        self.decide(
            tx,
            &Entry::BatchPaid {
                batch_id: ack.batch_id,
                week: week(now),
                refused: refused.into_iter().collect(),
            },
            now,
            0,
        )
        .map_err(|_| PayoutError::Decide)?;
        Ok(AckOutcome::Paid)
    }

    fn exported(&self, batch_id: &[u8; 16]) -> Result<bool, PayoutError> {
        Ok(store::batch(&*self.store.read()?, batch_id)?
            .is_some_and(|b| b.state == BatchState::Exported))
    }

    /// Reads every ack file of `dir`: a matching one (or one of a batch already closed) is applied
    /// and removed together with its batch file; one that does not match or cannot be read is
    /// refused (counted), and removed unless its batch is still exported. Then removes the
    /// residues of the export directory (§6.4): temporary batch files and the files of batches no
    /// longer exported. A file that cannot be removed is left for the next run.
    pub fn import_acks_at(
        &self,
        now: u64,
        dir: &Path,
        report: &mut PayoutReport,
    ) -> Result<(), PayoutError> {
        let files = export_files(dir)?;
        for path in &files.temporary {
            let _ = remove_if_present(path);
        }
        for (id, path) in files.acks {
            let ack = std::fs::read(&path)
                .ok()
                .and_then(|bytes| AckFile::parse(&bytes).ok());
            let outcome = match ack {
                Some(ack) if ack.batch_id == id => self.acknowledge_at(&ack, now)?,
                _ => AckOutcome::Refused,
            };
            match outcome {
                AckOutcome::Refused => {
                    report.acks_refused += 1;
                    if !self.exported(&id)? {
                        let _ = remove_if_present(&path);
                    }
                }
                AckOutcome::Paid | AckOutcome::AlreadyPaid => {
                    if remove_if_present(&dir.join(batch_file_name(&id))).is_ok() {
                        let _ = remove_if_present(&path);
                    }
                    if outcome == AckOutcome::Paid {
                        report.acknowledged.push(id);
                    }
                }
            }
        }
        for (id, path) in files.batches {
            if !self.exported(&id)? {
                let _ = remove_if_present(&path);
            }
        }
        self.volatile().payout_acks_refused = report.acks_refused as u64;
        Ok(())
    }

    /// Whether this week's export runs now (§9.5 step 1): the week's hour is drawn from `draw` at
    /// its first run and kept in `meta`; the export is due at the first run at or after it, once a
    /// week. A due export is recorded done in the same transaction, before any batch is created.
    fn export_due_at(&self, now: u64, draw: u64) -> Result<bool, PayoutError> {
        let w = week(now);
        let mut tx = self.store.write()?;
        let hour = match store::meta(&*tx, MetaKey::PayoutExportHour)? {
            Some(h) if week(h.saturating_mul(HOUR_SECS)) == w => h,
            _ => {
                let h = export_hour(w, draw);
                store::set_meta(&mut *tx, MetaKey::PayoutExportHour, h)?;
                h
            }
        };
        let done = store::meta(&*tx, MetaKey::PayoutDoneWeek)? == Some(w)
            || store::batches(&*tx)?.iter().any(|(_, b)| b.week == w);
        let due = !done && now / HOUR_SECS >= hour;
        if due {
            store::set_meta(&mut *tx, MetaKey::PayoutDoneWeek, w)?;
        }
        tx.commit()?;
        Ok(due)
    }

    /// One export run without the weekly hour (runbook P1 by hand, and the tests):
    /// acknowledgements and residues, new batches of every queued claim, batch files.
    pub fn payout_export_at(
        &self,
        now: u64,
        key: &OpsKey,
        dir: &Path,
    ) -> Result<PayoutReport, PayoutError> {
        self.ensure_payout_running()?;
        std::fs::create_dir_all(dir).map_err(|_| PayoutError::Io)?;
        let mut report = PayoutReport::default();
        self.import_acks_at(now, dir, &mut report)?;
        report.created = self.create_batches_at(now)?;
        report.written = self.write_batch_files(key, dir)?;
        Ok(report)
    }

    /// The hourly payout job of the server: acknowledgements, residues and batch files at every
    /// run, new batches once a week at the week's drawn hour (`draw` is used by the first run of a
    /// week only, [`export_hour`]).
    pub fn payout_job_at(
        &self,
        now: u64,
        key: &OpsKey,
        dir: &Path,
        draw: u64,
    ) -> Result<PayoutReport, PayoutError> {
        self.ensure_payout_running()?;
        std::fs::create_dir_all(dir).map_err(|_| PayoutError::Io)?;
        let mut report = PayoutReport::default();
        self.import_acks_at(now, dir, &mut report)?;
        if self.export_due_at(now, draw)? {
            report.created = self.create_batches_at(now)?;
        }
        report.written = self.write_batch_files(key, dir)?;
        Ok(report)
    }

    /// `BATCH` (live and replay): every claim moves from queued to batched; the batch row records
    /// the total. An entry already applied changes nothing.
    pub(crate) fn apply_batch(
        &self,
        tx: &mut dyn WriteTx,
        e: &BatchEntry,
    ) -> Result<(), ApplyError> {
        if let Some(row) = store::batch(tx, &e.batch_id)? {
            let mut all = usize::from(row.entries) == e.claims.len();
            for id in &e.claims {
                all &= store::claim(tx, id)?.is_some_and(|c| c.batch_id == e.batch_id);
            }
            return if all {
                Ok(())
            } else {
                Err(ApplyError::Inconsistent)
            };
        }
        let entries = u16::try_from(e.claims.len()).map_err(|_| ApplyError::Inconsistent)?;
        let mut total = 0u64;
        for id in &e.claims {
            let mut claim = store::claim(tx, id)?.ok_or(ApplyError::Inconsistent)?;
            if claim.state != ClaimState::Queued {
                return Err(ApplyError::Inconsistent);
            }
            claim.state = ClaimState::Batched;
            claim.batch_id = e.batch_id;
            total = total
                .checked_add(claim.amount)
                .ok_or(ApplyError::Inconsistent)?;
            store::put_claim(tx, id, &claim)?;
        }
        store::put_batch(
            tx,
            &e.batch_id,
            &BatchRow {
                state: BatchState::Exported,
                week: e.week,
                total,
                entries,
                cumulative_credited: e.cumulative_credited,
                paid_week: 0,
            },
        )?;
        Ok(())
    }

    /// `BATCH_PAID` (live and replay): the batch is closed, its claims paid or (`refused`)
    /// refused, every payout address of the batch deleted, `payout_paid_atomic` and
    /// `payout_refused_atomic` of the week counted. Already applied: nothing changes.
    pub(crate) fn apply_batch_paid(
        &self,
        tx: &mut dyn WriteTx,
        batch_id: &[u8; 16],
        w: u64,
        refused: &[[u8; 16]],
    ) -> Result<(), ApplyError> {
        let mut row = store::batch(tx, batch_id)?.ok_or(ApplyError::Inconsistent)?;
        if row.state == BatchState::Paid {
            return Ok(());
        }
        let refused: BTreeSet<[u8; 16]> = refused.iter().copied().collect();
        let (mut paid, mut closed, mut matched) = (0u64, 0u64, 0usize);
        for (id, mut claim) in store::claims(tx)? {
            if claim.batch_id != *batch_id {
                continue;
            }
            if claim.state != ClaimState::Batched {
                return Err(ApplyError::Inconsistent);
            }
            if refused.contains(&id) {
                claim.state = ClaimState::Refused;
                closed = closed.saturating_add(claim.amount);
                matched += 1;
            } else {
                claim.state = ClaimState::Paid;
                paid = paid.saturating_add(claim.amount);
            }
            claim.address = [0u8; ADDRESS_LEN];
            store::put_claim(tx, &id, &claim)?;
        }
        if matched != refused.len() {
            return Err(ApplyError::Inconsistent);
        }
        row.state = BatchState::Paid;
        row.paid_week = w;
        store::put_batch(tx, batch_id, &row)?;
        reconcile::add(tx, CounterId::PayoutPaidAtomic, w, paid)?;
        reconcile::add(tx, CounterId::PayoutRefusedAtomic, w, closed)?;
        Ok(())
    }
}

/// Retention of closed batches (§6.1, §6.4): their claims [`CLAIMS_KEEP_WEEKS`] and the batch row
/// [`BATCH_KEEP_WEEKS`] after the week of the acknowledgement. Returns the rows deleted.
pub(crate) fn sweep_paid(tx: &mut dyn WriteTx, w: u64) -> Result<usize, StoreError> {
    let paid: BTreeMap<[u8; 16], u64> = store::batches(tx)?
        .into_iter()
        .filter(|(_, b)| b.state == BatchState::Paid)
        .map(|(id, b)| (id, b.paid_week))
        .collect();
    let mut deleted = 0;
    for (id, claim) in store::claims(tx)? {
        let due = paid
            .get(&claim.batch_id)
            .is_some_and(|pw| w >= pw.saturating_add(CLAIMS_KEEP_WEEKS));
        if matches!(claim.state, ClaimState::Paid | ClaimState::Refused) && due {
            tx.delete(Table::Claim, &id)?;
            deleted += 1;
        }
    }
    for (id, pw) in paid {
        if w >= pw.saturating_add(BATCH_KEEP_WEEKS) {
            tx.delete(Table::Batch, &id)?;
            deleted += 1;
        }
    }
    Ok(deleted)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(i: u8, amount: u64) -> BatchLine {
        BatchLine {
            claim_id: [i; 16],
            address: [b'4'; ADDRESS_LEN],
            amount,
        }
    }

    fn file() -> BatchFile {
        BatchFile {
            network: MoneroNetwork::Regtest,
            batch_id: [7; 16],
            week: 2960,
            entries: vec![line(1, 5), line(2, 6)],
            total: 11,
            cumulative_credited: 400,
        }
    }

    #[test]
    fn a_batch_file_round_trips_under_its_ops_key_only() {
        let key = OpsKey::from_seed(&[3; 32]);
        let bytes = file().sign(&key).unwrap();
        assert_eq!(bytes, file().sign(&key).unwrap(), "deterministic");
        assert_eq!(BatchFile::verify(&bytes, &key.public()).unwrap(), file());
        let other = OpsKey::from_seed(&[4; 32]);
        assert_eq!(
            BatchFile::verify(&bytes, &other.public()),
            Err(PayoutFileError::Signature)
        );
        for i in [0, 5, 40, bytes.len() - 70, bytes.len() - 1] {
            let mut flipped = bytes.clone();
            flipped[i] ^= 1;
            assert!(BatchFile::verify(&flipped, &key.public()).is_err(), "{i}");
        }
    }

    #[test]
    fn a_batch_file_refuses_bad_totals_amounts_and_duplicates() {
        let key = OpsKey::from_seed(&[3; 32]);
        let mut f = file();
        f.total = 12;
        assert_eq!(f.sign(&key), Err(PayoutFileError::Format));
        let mut f = file();
        f.entries[1] = line(1, 6);
        assert_eq!(f.sign(&key), Err(PayoutFileError::Format));
        let mut f = file();
        f.entries = vec![line(1, 0)];
        f.total = 0;
        assert_eq!(f.sign(&key), Err(PayoutFileError::Format));
        let mut f = file();
        f.entries.clear();
        f.total = 0;
        assert_eq!(f.sign(&key), Err(PayoutFileError::Format));
    }

    #[test]
    fn an_ack_file_round_trips_and_names_parse() {
        let ack = AckFile {
            batch_id: [9; 16],
            entries: vec![
                ([1; 16], EntryOutcome::Paid),
                ([3; 16], EntryOutcome::Refused),
            ],
        };
        let bytes = ack.encode().unwrap();
        assert_eq!(bytes.len(), 23 + 2 * 17, "no payout txid");
        assert_eq!(AckFile::parse(&bytes).unwrap(), ack);
        assert!(AckFile::parse(&bytes[..bytes.len() - 1]).is_err());
        assert!(AckFile::parse(&[bytes.as_slice(), &[0]].concat()).is_err());
        for outcome in [0u8, 3, 0xff] {
            let mut bad = bytes.clone();
            let last = bad.len() - 1;
            bad[last] = outcome;
            assert_eq!(AckFile::parse(&bad), Err(PayoutFileError::Format));
        }
        let name = ack_file_name(&[0xab; 16]);
        assert_eq!(name, format!("ack-{}.ghpa", "ab".repeat(16)));
        assert_eq!(ack_batch_id(&name), Some([0xab; 16]));
        assert_eq!(ack_batch_id(&name.to_uppercase()), None);
        assert_eq!(ack_batch_id("ack-ab.ghpa"), None);
        assert_eq!(ack_batch_id(&batch_file_name(&[0xab; 16])), None);
        let tmp = Path::new(&batch_file_name(&[0xab; 16])).with_extension("tmp");
        assert_eq!(
            named_batch_id(tmp.to_str().unwrap(), BATCH_PREFIX, TMP_SUFFIX),
            Some([0xab; 16]),
            "the temporary name write_atomically uses"
        );
    }

    #[test]
    fn the_export_hour_is_one_of_the_weeks_hours() {
        let start = week_start(2960) / HOUR_SECS;
        assert_eq!(export_hour(2960, 0), start);
        assert_eq!(export_hour(2960, 167), start + 167);
        assert_eq!(export_hour(2960, 168), start);
        assert_eq!(week(export_hour(2960, u64::MAX) * HOUR_SECS), 2960);
    }
}
