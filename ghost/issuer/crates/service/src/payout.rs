//! The payout pipeline, issuer side (Phase 8 design §9.5, §19.5, §19.7; ADR-26): queued claims
//! are assigned to batches (journaled `BATCH`), each batch is exported as a file signed with the
//! Ed25519 ops key for the operator workstation, and the workstation's acknowledgement (every
//! entry paid, each with its own txid) marks the batch paid (journaled `BATCH_PAID`).
//!
//! ```text
//! batch file := "GHPB" || version u8 = 1 || network u8 (the ES byte) || batch_id 16 || week u64
//!               || count u16 (1..200) || count x (claim_id 16 || address 95 || amount u64)
//!               || total u64 || cumulative_credited u64
//!               || Ed25519(ops key, "ghost/v1/payout-batch" || every preceding byte) (64)
//! ack file   := "GHPA" || version u8 = 1 || batch_id 16 || count u16 (1..200)
//!               || count x (claim_id 16 || txid 32)
//! ```
//! Big-endian fixed fields. The entries of a batch are ordered by
//! `SHA-256("ghost/v1/payout-order" || batch_id || claim_id)`: shuffled against the order the
//! claims arrived in, and the same at every export, so the file of an unacknowledged batch is
//! rewritten byte for byte (Ed25519 signatures are deterministic), also after a restore (the
//! `BATCH` entry carries every field). Files: `batch-<batch id hex>.ghpb` and
//! `ack-<batch id hex>.ghpa` in the export directory.
//!
//! **When** (§9.5 step 1). The server runs [`Issuer::payout_job_at`] hourly. New batches are
//! created at most once a week, at the first run of the week whose draw succeeds with probability
//! 1 / (hours left in the week): a uniformly random hour, independent of when claims arrived.
//! Every run imports acknowledgements and rewrites the files of unacknowledged batches.
//!
//! **Acknowledgement** (§9.5 step 4). An ack file must name exactly the claims of an exported
//! batch, each with a distinct non-zero txid (`ghost-issuer-ops payout-ack` writes it once every
//! entry has its confirmations). The issuer journals `BATCH_PAID`, marks the claims paid, deletes
//! their payout addresses, adds the batch total to `payout_paid_atomic`, and deletes the batch and
//! ack files; a paid batch's claims are deleted two weeks and the batch row six weeks after the
//! week of its acknowledgement. An ack that does not match stays in place and is counted
//! ([`PayoutReport::acks_refused`]). Recorded: the ack file carries no signature; it moves no
//! value (the batch file does), and the export directory is on the issuer's encrypted volume,
//! where the operator who carries the ack file over already has write access.
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
    self, BatchRow, BatchState, ClaimState, ReadTx, StoreError, Table, WriteTx, ADDRESS_LEN,
};

pub const BATCH_MAGIC: &[u8; 4] = b"GHPB";
pub const ACK_MAGIC: &[u8; 4] = b"GHPA";
pub const FORMAT_VERSION: u8 = 1;
/// Domain of the ops key's signature over a batch file.
pub const BATCH_SIGNATURE_DOMAIN: &[u8] = b"ghost/v1/payout-batch";
/// Length of the ops key's seed file and of its public key.
pub const OPS_SEED_LEN: usize = 32;
pub const SIGNATURE_LEN: usize = 64;
/// A paid batch's claims are deleted this many weeks after the week of its acknowledgement
/// (at least the 7 days of §6.4).
pub const CLAIMS_KEEP_WEEKS: u64 = 2;
/// A paid batch row is deleted this many weeks after the week of its acknowledgement (at least
/// the 30 days of §6.1).
pub const BATCH_KEEP_WEEKS: u64 = 6;

const ORDER_DOMAIN: &[u8] = b"ghost/v1/payout-order";
const BATCH_PREFIX: &str = "batch-";
const BATCH_SUFFIX: &str = ".ghpb";
const ACK_PREFIX: &str = "ack-";
const ACK_SUFFIX: &str = ".ghpa";
const LINE_LEN: usize = 16 + ADDRESS_LEN + 8;
const ACK_LINE_LEN: usize = 16 + 32;
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

/// The workstation's acknowledgement of a paid batch (§9.5 step 4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AckFile {
    pub batch_id: [u8; 16],
    /// (claim id, txid of its payout), in the batch file's order.
    pub entries: Vec<([u8; 16], [u8; 32])>,
}

impl AckFile {
    pub fn encode(&self) -> Result<Vec<u8>, PayoutFileError> {
        let count = count_u16(self.entries.len())?;
        let mut w = Vec::with_capacity(23 + self.entries.len() * ACK_LINE_LEN);
        w.extend_from_slice(ACK_MAGIC);
        w.push(FORMAT_VERSION);
        w.extend_from_slice(&self.batch_id);
        w.extend_from_slice(&count);
        for (claim, txid) in &self.entries {
            w.extend_from_slice(claim);
            w.extend_from_slice(txid);
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
            .map(|_| Ok((take_array(&mut r)?, take_array(&mut r)?)))
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

/// The batch id an ack file name names (32 lowercase hex digits), if it is one.
fn ack_batch_id(name: &str) -> Option<[u8; 16]> {
    crate::rail::hex_decode(name.strip_prefix(ACK_PREFIX)?.strip_suffix(ACK_SUFFIX)?)
}

/// The position key of a claim in its batch file.
fn order_key(batch_id: &[u8; 16], claim_id: &[u8; 16]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(ORDER_DOMAIN);
    h.update(batch_id);
    h.update(claim_id);
    h.finalize().into()
}

/// True when the weekly export should run at `now` given a uniform `draw`: with probability
/// 1 / (hours left in the week), so the export hour is uniform over the week (§9.5 step 1).
pub fn export_due(now: u64, draw: u64) -> bool {
    let end = week_start(week(now).saturating_add(1));
    let hours_left = end.saturating_sub(now).div_ceil(HOUR_SECS).max(1);
    draw.is_multiple_of(hours_left)
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
    /// Ack files that do not match an exported batch (left in place).
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
    /// It does not name exactly the claims of an exported batch with distinct non-zero txids.
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
    /// unknown or paid batch.
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

    /// §9.5 step 4: the acknowledgement of every entry of an exported batch; one decided
    /// transaction (`BATCH_PAID`).
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
        let txids: BTreeSet<[u8; 32]> = ack.entries.iter().map(|(_, t)| *t).collect();
        let n = ack.entries.len();
        if acked != claims
            || acked.len() != n
            || txids.len() != n
            || txids.contains(&[0u8; 32])
            || n != usize::from(row.entries)
        {
            return Ok(AckOutcome::Refused);
        }
        self.decide(
            tx,
            &Entry::BatchPaid {
                batch_id: ack.batch_id,
                week: week(now),
            },
            now,
            0,
        )
        .map_err(|_| PayoutError::Decide)?;
        Ok(AckOutcome::Paid)
    }

    /// Reads every ack file of `dir`; a matching one (or one of a batch already paid) is applied
    /// and removed together with its batch file.
    pub fn import_acks_at(
        &self,
        now: u64,
        dir: &Path,
        report: &mut PayoutReport,
    ) -> Result<(), PayoutError> {
        let mut acks: BTreeMap<[u8; 16], PathBuf> = BTreeMap::new();
        for item in std::fs::read_dir(dir).map_err(|_| PayoutError::Io)? {
            let item = item.map_err(|_| PayoutError::Io)?;
            let name = item.file_name();
            if let Some(id) = name.to_str().and_then(ack_batch_id) {
                acks.insert(id, item.path());
            }
        }
        for (id, path) in acks {
            let bytes = std::fs::read(&path).map_err(|_| PayoutError::Io)?;
            let outcome = match AckFile::parse(&bytes) {
                Ok(ack) if ack.batch_id == id => self.acknowledge_at(&ack, now)?,
                _ => AckOutcome::Refused,
            };
            match outcome {
                AckOutcome::Refused => report.acks_refused += 1,
                AckOutcome::Paid | AckOutcome::AlreadyPaid => {
                    remove_if_present(&dir.join(batch_file_name(&id)))?;
                    remove_if_present(&path)?;
                    if outcome == AckOutcome::Paid {
                        report.acknowledged.push(id);
                    }
                }
            }
        }
        Ok(())
    }

    fn batch_created_in(&self, w: u64) -> Result<bool, StoreError> {
        Ok(store::batches(&*self.store.read()?)?
            .iter()
            .any(|(_, b)| b.week == w))
    }

    /// One export run: acknowledgements, new batches of every queued claim, batch files.
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

    /// The hourly payout job of the server: acknowledgements and batch files at every run, new
    /// batches at most once a week at a uniformly random hour ([`export_due`] with `draw`).
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
        if export_due(now, draw) && !self.batch_created_in(week(now))? {
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

    /// `BATCH_PAID` (live and replay): the batch and its claims are paid, the payout addresses
    /// deleted, `payout_paid_atomic` of the week counted. Already applied: nothing changes.
    pub(crate) fn apply_batch_paid(
        &self,
        tx: &mut dyn WriteTx,
        batch_id: &[u8; 16],
        w: u64,
    ) -> Result<(), ApplyError> {
        let mut row = store::batch(tx, batch_id)?.ok_or(ApplyError::Inconsistent)?;
        if row.state == BatchState::Paid {
            return Ok(());
        }
        for (id, mut claim) in store::claims(tx)? {
            if claim.batch_id == *batch_id {
                claim.state = ClaimState::Paid;
                claim.address = [0u8; ADDRESS_LEN];
                store::put_claim(tx, &id, &claim)?;
            }
        }
        row.state = BatchState::Paid;
        row.paid_week = w;
        store::put_batch(tx, batch_id, &row)?;
        reconcile::add(tx, CounterId::PayoutPaidAtomic, w, row.total)?;
        Ok(())
    }
}

/// Retention of paid batches (§6.1, §6.4): their claims [`CLAIMS_KEEP_WEEKS`] and the batch row
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
        if claim.state == ClaimState::Paid && due {
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
            entries: vec![([1; 16], [2; 32]), ([3; 16], [4; 32])],
        };
        let bytes = ack.encode().unwrap();
        assert_eq!(AckFile::parse(&bytes).unwrap(), ack);
        assert!(AckFile::parse(&bytes[..bytes.len() - 1]).is_err());
        assert!(AckFile::parse(&[bytes.as_slice(), &[0]].concat()).is_err());
        let name = ack_file_name(&[0xab; 16]);
        assert_eq!(name, format!("ack-{}.ghpa", "ab".repeat(16)));
        assert_eq!(ack_batch_id(&name), Some([0xab; 16]));
        assert_eq!(ack_batch_id(&name.to_uppercase()), None);
        assert_eq!(ack_batch_id("ack-ab.ghpa"), None);
        assert_eq!(ack_batch_id(&batch_file_name(&[0xab; 16])), None);
    }

    #[test]
    fn the_export_hour_is_drawn_over_the_hours_left_in_the_week() {
        let start = week_start(2960);
        // The last hour of the week always exports; the first one with probability 1/168.
        assert!(export_due(week_start(2961) - 1, 12_345));
        assert!(export_due(start, 168 * 7));
        assert!(!export_due(start, 168 * 7 + 1));
    }
}
