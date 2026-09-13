//! `issued.journal` (Phase 8 design §6.3, §19.5): the append-only record of every decided,
//! irreversible issuer transition, so that a restore from a database snapshot plus a replay of the
//! journal never re-opens a double issuance (MS-1) or a double spend (MS-3).
//!
//! ```text
//! frame := len u32 (= 9 + |body|) || seq u64 || tag u8 || body || SHA-256(len || seq || tag || body)
//! INVOICE    tag 1: invoice_id 16 || claim_hash 32 || R 32 || pay_with u8 || minor u32
//!                   || subaddress 95 (zero for credits) || amount u64 || base_week u64
//!                   || created_height u64 || grace_height u64 || count u8 (0..20)
//!                   || count x (credit epoch u64 || nullifier 32)
//! ISSUE      tag 2: invoice_id 16 || D 32
//! INVITE     tag 3: invite epoch u64 || N_inv 32 || D_t 32 || base_week u64
//! CLAIM      tag 4: claim_id 16 || digest 32 || amount u64 || address 95 || count u8 (1..64)
//!                   || count x (credit epoch u64 || nullifier 32)
//! REFRESH    tag 5: credit epoch u64 || N 32 || refresh digest 32
//! BATCH      tag 6: batch_id 16 || week u64 || cumulative_credited u64 || count u16 (1..200)
//!                   || count x claim_id 16
//! BATCH_PAID tag 7: batch_id 16 || week u64 || count u16 (0..200)
//!                   || count x claim_id 16 (the refused entries, strictly ascending)
//! (an unknown tag refuses the start, it is never skipped)
//! ```
//! Big-endian fixed fields; the checksum is SHA-256 from `sha2` (no CRC crate, §19.5).
//!
//! **Write rule (decide, then journal).** A handler appends an entry only inside its redb write
//! transaction, after re-checking the state it depends on, and commits after the append returned:
//! only decided outcomes are journaled and journal order equals commit order. An entry whose
//! commit never happened (a crash between fsync and commit) is the outcome that had already won.
//! The next entry is appended only while the journal holds exactly the entries the database has
//! applied ([`Journal::next_seq`] = `journal_applied + 1`, checked inside the transaction), and a
//! [`FileJournal`] whose write or sync failed refuses every later append until it is reopened
//! (the file may hold part of the failed frame).
//!
//! Recorded deviations from the §6.3 entry list, each needed to replay "exactly as the handler
//! would": INVOICE carries the subaddress (the idempotent re-serve returns it) and the epoch of each
//! credit nullifier (the nullifier table key and the per-epoch counters need it); INVITE carries
//! the trial's base week (the trial counters need it); BATCH carries the issuer's cumulative
//! credited revenue at the batch's creation (a field of the signed batch file, so the file of an
//! unacknowledged batch is re-exported byte for byte after a restore, §9.5 step 1); BATCH_PAID
//! carries the week of the acknowledgement (the `payout_paid_atomic` counter and the retention of
//! the paid batch's claims are per week, and a replay must not date them by the restart) and the
//! ids of the claims whose entries the workstation refused (a payout address it had seen before,
//! §9.5 step 2: those claims close unpaid, so one address cannot stall its whole batch).
//!
//! **Files.** Weekly segments `issued.journal.<week>` in one directory; a segment is never renamed.
//! Entries are numbered from 1 without gaps across segments. At open, a torn tail of the last
//! segment is discarded and the file truncated: its commit cannot have happened. A torn tail is
//! everything from the first frame that does not verify (short, a length out of range, a bad
//! checksum) to the end of the file, provided no valid frame starts anywhere after it: a partial
//! write, or a region a crash left zero-filled or with stale bytes after the file was extended.
//! Anything else that does not decode (damage followed by a valid frame, damage in an earlier
//! segment, a verified frame of an unknown format) refuses the start.
//!
//! **Pruning** (§6.3, §6.4; runbook B1). Segments are removed only by [`prune_dir`] (and
//! [`FileJournal::prune`] over it), which `ghost-issuer-ops journal-prune` runs hourly from the
//! host after verifying the newest snapshot. A segment goes when every entry in it is older than
//! the 7-day re-serve window and covered by that snapshot's `journal_applied`; the latest segment
//! is never removed. Segments go in ascending order, so a crash between two removals leaves a
//! contiguous suffix whose first entry is at most `journal_applied + 1` of the snapshot and of the
//! live database: the issuer restarts, and a restore from any snapshot B1 keeps (at most 7 days
//! old) replays. [`prune_dir`] never truncates or writes a segment, so it may run while the issuer
//! appends; a segment it removes between the listing and the read of an issuer that starts at that
//! moment is skipped, and the sequence checks refuse anything but a removed prefix.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use sha2::{Digest, Sha256};

use ghost_entitlement::grid::week_start;

use crate::store::{PayWith, ADDRESS_LEN};

/// File name prefix of a segment; the suffix is the decimal week index.
pub const SEGMENT_PREFIX: &str = "issued.journal.";
/// Largest `len` field a frame may carry (a CLAIM with 64 credits is about 2.8 KiB).
pub const MAX_FRAME_LEN: usize = 4_096;
/// Most credits one entry carries (a claim of up to `max_claim_credits`, capped at 64).
pub const MAX_ENTRY_CREDITS: usize = 64;
/// Most claims one payout batch carries (its BATCH entry stays within [`MAX_FRAME_LEN`]); more
/// queued claims go to further batches of the same export.
pub const MAX_BATCH_CLAIMS: usize = 200;
/// Segments are kept while any entry may still be needed for a re-serve (7 days, §6.3).
pub const RESERVE_WINDOW_SECS: u64 = 7 * 86_400;

const TAG_INVOICE: u8 = 1;
const TAG_ISSUE: u8 = 2;
const TAG_INVITE: u8 = 3;
const TAG_CLAIM: u8 = 4;
const TAG_REFRESH: u8 = 5;
const TAG_BATCH: u8 = 6;
const TAG_BATCH_PAID: u8 = 7;
const CHECKSUM_LEN: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum JournalError {
    /// A file could not be read, written, synced or truncated.
    Io,
    /// A frame that is not the torn tail of the last segment does not verify.
    Corrupt,
    /// A frame verifies but its tag or body is not an entry of this version.
    Format,
    /// Sequence numbers are not contiguous, or the journal is behind the database (§6.6).
    Gap,
}

impl std::fmt::Display for JournalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            JournalError::Io => "journal file operation failed",
            JournalError::Corrupt => "journal frame corrupt",
            JournalError::Format => "journal entry of an unknown format",
            JournalError::Gap => "journal sequence gap",
        })
    }
}

impl std::error::Error for JournalError {}

/// One credit spent by an entry: its key's credit epoch and its nullifier.
pub type CreditRef = (u64, [u8; 32]);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvoiceEntry {
    pub invoice_id: [u8; 16],
    pub claim_hash: [u8; 32],
    pub request_digest: [u8; 32],
    pub pay_with: PayWith,
    pub minor: u32,
    pub subaddress: [u8; ADDRESS_LEN],
    pub amount: u64,
    pub base_week: u64,
    pub created_height: u64,
    pub grace_height: u64,
    pub credits: Vec<CreditRef>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimEntry {
    pub claim_id: [u8; 16],
    pub digest: [u8; 32],
    pub amount: u64,
    pub address: [u8; ADDRESS_LEN],
    pub credits: Vec<CreditRef>,
}

/// Queued claims assigned to a new payout batch (§9.5 step 1, §19.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchEntry {
    pub batch_id: [u8; 16],
    /// The week the batch was created in.
    pub week: u64,
    /// The `xmr_credited_total` counter when the batch was created.
    pub cumulative_credited: u64,
    /// 1 ..= [`MAX_BATCH_CLAIMS`] distinct claim ids.
    pub claims: Vec<[u8; 16]>,
}

/// A decided transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Entry {
    Invoice(InvoiceEntry),
    Issue {
        invoice_id: [u8; 16],
        digest: [u8; 32],
    },
    Invite {
        epoch: u64,
        nullifier: [u8; 32],
        digest: [u8; 32],
        base_week: u64,
    },
    Claim(ClaimEntry),
    /// A received credit exchanged for a fresh one of the same epoch (`RefreshCredit`, §19.8).
    Refresh {
        epoch: u64,
        nullifier: [u8; 32],
        digest: [u8; 32],
    },
    Batch(BatchEntry),
    /// Every entry of the batch was acknowledged by the workstation (§9.5 step 4): paid, or
    /// refused (`refused`, strictly ascending claim ids).
    BatchPaid {
        batch_id: [u8; 16],
        week: u64,
        refused: Vec<[u8; 16]>,
    },
}

/// A list of claim ids: 0 ..= [`MAX_BATCH_CLAIMS`] of them, strictly ascending (distinct).
fn canonical_ids(ids: &[[u8; 16]]) -> bool {
    ids.len() <= MAX_BATCH_CLAIMS && ids.windows(2).all(|w| w[0] < w[1])
}

impl Entry {
    fn tag(&self) -> u8 {
        match self {
            Entry::Invoice(_) => TAG_INVOICE,
            Entry::Issue { .. } => TAG_ISSUE,
            Entry::Invite { .. } => TAG_INVITE,
            Entry::Claim(_) => TAG_CLAIM,
            Entry::Refresh { .. } => TAG_REFRESH,
            Entry::Batch(_) => TAG_BATCH,
            Entry::BatchPaid { .. } => TAG_BATCH_PAID,
        }
    }

    fn body(&self) -> Result<Vec<u8>, JournalError> {
        let mut w = Vec::new();
        match self {
            Entry::Invoice(e) => {
                w.extend_from_slice(&e.invoice_id);
                w.extend_from_slice(&e.claim_hash);
                w.extend_from_slice(&e.request_digest);
                w.push(e.pay_with.code());
                w.extend_from_slice(&e.minor.to_be_bytes());
                w.extend_from_slice(&e.subaddress);
                for v in [e.amount, e.base_week, e.created_height, e.grace_height] {
                    w.extend_from_slice(&v.to_be_bytes());
                }
                put_credits(&mut w, &e.credits)?;
            }
            Entry::Issue { invoice_id, digest } => {
                w.extend_from_slice(invoice_id);
                w.extend_from_slice(digest);
            }
            Entry::Invite {
                epoch,
                nullifier,
                digest,
                base_week,
            } => {
                w.extend_from_slice(&epoch.to_be_bytes());
                w.extend_from_slice(nullifier);
                w.extend_from_slice(digest);
                w.extend_from_slice(&base_week.to_be_bytes());
            }
            Entry::Claim(e) => {
                w.extend_from_slice(&e.claim_id);
                w.extend_from_slice(&e.digest);
                w.extend_from_slice(&e.amount.to_be_bytes());
                w.extend_from_slice(&e.address);
                put_credits(&mut w, &e.credits)?;
            }
            Entry::Refresh {
                epoch,
                nullifier,
                digest,
            } => {
                w.extend_from_slice(&epoch.to_be_bytes());
                w.extend_from_slice(nullifier);
                w.extend_from_slice(digest);
            }
            Entry::Batch(e) => {
                if e.claims.is_empty() || e.claims.len() > MAX_BATCH_CLAIMS {
                    return Err(JournalError::Format);
                }
                w.extend_from_slice(&e.batch_id);
                w.extend_from_slice(&e.week.to_be_bytes());
                w.extend_from_slice(&e.cumulative_credited.to_be_bytes());
                w.extend_from_slice(&(e.claims.len() as u16).to_be_bytes());
                for c in &e.claims {
                    w.extend_from_slice(c);
                }
            }
            Entry::BatchPaid {
                batch_id,
                week,
                refused,
            } => {
                if !canonical_ids(refused) {
                    return Err(JournalError::Format);
                }
                w.extend_from_slice(batch_id);
                w.extend_from_slice(&week.to_be_bytes());
                w.extend_from_slice(&(refused.len() as u16).to_be_bytes());
                for c in refused {
                    w.extend_from_slice(c);
                }
            }
        }
        Ok(w)
    }

    /// The complete frame of this entry under sequence number `seq`.
    pub fn encode(&self, seq: u64) -> Result<Vec<u8>, JournalError> {
        let body = self.body()?;
        let len = u32::try_from(9 + body.len()).map_err(|_| JournalError::Format)?;
        let mut frame = Vec::with_capacity(4 + len as usize + CHECKSUM_LEN);
        frame.extend_from_slice(&len.to_be_bytes());
        frame.extend_from_slice(&seq.to_be_bytes());
        frame.push(self.tag());
        frame.extend_from_slice(&body);
        let checksum = Sha256::digest(&frame);
        frame.extend_from_slice(&checksum);
        Ok(frame)
    }

    fn decode(tag: u8, body: &[u8]) -> Result<Self, JournalError> {
        let mut r = Reader(body);
        let entry = match tag {
            TAG_INVOICE => Entry::Invoice(InvoiceEntry {
                invoice_id: r.array()?,
                claim_hash: r.array()?,
                request_digest: r.array()?,
                pay_with: PayWith::from_code(r.u8()?).ok_or(JournalError::Format)?,
                minor: u32::from_be_bytes(r.array()?),
                subaddress: r.array()?,
                amount: r.u64()?,
                base_week: r.u64()?,
                created_height: r.u64()?,
                grace_height: r.u64()?,
                credits: r.credits()?,
            }),
            TAG_ISSUE => Entry::Issue {
                invoice_id: r.array()?,
                digest: r.array()?,
            },
            TAG_INVITE => Entry::Invite {
                epoch: r.u64()?,
                nullifier: r.array()?,
                digest: r.array()?,
                base_week: r.u64()?,
            },
            TAG_CLAIM => Entry::Claim(ClaimEntry {
                claim_id: r.array()?,
                digest: r.array()?,
                amount: r.u64()?,
                address: r.array()?,
                credits: r.credits()?,
            }),
            TAG_REFRESH => Entry::Refresh {
                epoch: r.u64()?,
                nullifier: r.array()?,
                digest: r.array()?,
            },
            TAG_BATCH => {
                let batch_id = r.array()?;
                let week = r.u64()?;
                let cumulative_credited = r.u64()?;
                let count = usize::from(u16::from_be_bytes(r.array()?));
                if count == 0 || count > MAX_BATCH_CLAIMS {
                    return Err(JournalError::Format);
                }
                let claims = (0..count)
                    .map(|_| r.array())
                    .collect::<Result<Vec<[u8; 16]>, _>>()?;
                Entry::Batch(BatchEntry {
                    batch_id,
                    week,
                    cumulative_credited,
                    claims,
                })
            }
            TAG_BATCH_PAID => {
                let batch_id = r.array()?;
                let week = r.u64()?;
                let count = usize::from(u16::from_be_bytes(r.array()?));
                if count > MAX_BATCH_CLAIMS {
                    return Err(JournalError::Format);
                }
                let refused = (0..count)
                    .map(|_| r.array())
                    .collect::<Result<Vec<[u8; 16]>, _>>()?;
                if !canonical_ids(&refused) {
                    return Err(JournalError::Format);
                }
                Entry::BatchPaid {
                    batch_id,
                    week,
                    refused,
                }
            }
            _ => return Err(JournalError::Format),
        };
        if !r.0.is_empty() {
            return Err(JournalError::Format);
        }
        Ok(entry)
    }
}

fn put_credits(w: &mut Vec<u8>, credits: &[CreditRef]) -> Result<(), JournalError> {
    if credits.len() > MAX_ENTRY_CREDITS {
        return Err(JournalError::Format);
    }
    w.push(credits.len() as u8);
    for (epoch, n) in credits {
        w.extend_from_slice(&epoch.to_be_bytes());
        w.extend_from_slice(n);
    }
    Ok(())
}

struct Reader<'a>(&'a [u8]);

impl Reader<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8], JournalError> {
        if self.0.len() < n {
            return Err(JournalError::Format);
        }
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        Ok(head)
    }

    fn u8(&mut self) -> Result<u8, JournalError> {
        Ok(self.take(1)?[0])
    }

    fn u64(&mut self) -> Result<u64, JournalError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], JournalError> {
        self.take(N)?.try_into().map_err(|_| JournalError::Format)
    }

    fn credits(&mut self) -> Result<Vec<CreditRef>, JournalError> {
        let count = usize::from(self.u8()?);
        if count > MAX_ENTRY_CREDITS {
            return Err(JournalError::Format);
        }
        (0..count)
            .map(|_| Ok((self.u64()?, self.array()?)))
            .collect()
    }
}

/// The issuer's journal.
pub trait Journal: Send + Sync {
    /// Every persisted entry in sequence order (contiguous, checksums verified).
    fn entries(&self) -> Result<Vec<(u64, Entry)>, JournalError>;
    /// Appends `entry` with the next sequence number to the segment of `week` (or of the latest
    /// segment, if that is later) and makes it durable before returning its sequence number.
    fn append(&self, week: u64, entry: &Entry) -> Result<u64, JournalError>;
    /// The sequence number the next append gets; an error while appends are refused.
    fn next_seq(&self) -> Result<u64, JournalError>;
}

struct Active {
    next_seq: u64,
    /// Week and handle of the segment the next entry goes to (the latest existing one).
    segment: Option<(u64, File)>,
    /// A write or sync failed: the segment may end in part of a frame, so nothing is appended
    /// after it until the journal is reopened (which truncates the torn tail).
    poisoned: bool,
}

/// The production journal: segment files in one directory.
pub struct FileJournal {
    dir: PathBuf,
    active: Mutex<Active>,
}

/// One segment as read at open: its week, its entries and where its valid bytes end.
struct Segment {
    week: u64,
    path: PathBuf,
    entries: Vec<(u64, Entry)>,
    valid_len: u64,
    file_len: u64,
}

impl FileJournal {
    /// Opens (creating the directory if needed) and validates every segment. A torn tail of the
    /// last segment (nothing valid after the first frame that does not verify) is truncated away;
    /// any other damage or a sequence gap refuses the open.
    pub fn open(dir: &Path) -> Result<Self, JournalError> {
        std::fs::create_dir_all(dir).map_err(|_| JournalError::Io)?;
        let segments = read_segments(dir)?;
        let mut next_seq = 1;
        let mut last_week = None;
        if let Some(last) = segments.last() {
            if last.valid_len < last.file_len {
                let file = OpenOptions::new()
                    .write(true)
                    .open(&last.path)
                    .map_err(|_| JournalError::Io)?;
                file.set_len(last.valid_len)
                    .and_then(|()| file.sync_all())
                    .map_err(|_| JournalError::Io)?;
            }
            last_week = Some(last.week);
        }
        if let Some((seq, _)) = segments.iter().flat_map(|s| s.entries.last()).last() {
            next_seq = seq + 1;
        }
        let segment = match last_week {
            Some(week) => Some((week, open_append(&segment_path(dir, week))?)),
            None => None,
        };
        Ok(Self {
            dir: dir.to_path_buf(),
            active: Mutex::new(Active {
                next_seq,
                segment,
                poisoned: false,
            }),
        })
    }

    /// The segment file of `week` in this journal's directory.
    pub fn segment_path(&self, week: u64) -> PathBuf {
        segment_path(&self.dir, week)
    }

    /// The segment the next entry of `week` goes to, and the sequence number it gets.
    pub fn next(&self, week: u64) -> (PathBuf, u64) {
        let active = self.lock();
        let target = active
            .segment
            .as_ref()
            .map_or(week, |(w, _)| (*w).max(week));
        (segment_path(&self.dir, target), active.next_seq)
    }

    /// [`prune_dir`] on this journal's directory, holding its append lock. A snapshot that does
    /// not fit the journal ([`PruneError::SnapshotAhead`], [`PruneError::SnapshotBehind`]) is
    /// [`JournalError::Gap`]. Returns the weeks deleted.
    pub fn prune(&self, now: u64, snapshot_journal_applied: u64) -> Result<Vec<u64>, JournalError> {
        let _active = self.lock();
        match prune_dir(&self.dir, now, snapshot_journal_applied) {
            Ok(pruned) => Ok(pruned.removed),
            Err(PruneError::Journal(e)) => Err(e),
            Err(PruneError::SnapshotAhead | PruneError::SnapshotBehind) => Err(JournalError::Gap),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Active> {
        self.active.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl Journal for FileJournal {
    fn entries(&self) -> Result<Vec<(u64, Entry)>, JournalError> {
        let _active = self.lock();
        Ok(read_segments(&self.dir)?
            .into_iter()
            .flat_map(|s| s.entries)
            .collect())
    }

    fn append(&self, week: u64, entry: &Entry) -> Result<u64, JournalError> {
        let mut active = self.lock();
        if active.poisoned {
            return Err(JournalError::Io);
        }
        let seq = active.next_seq;
        let frame = entry.encode(seq)?;
        if frame.len() > 4 + MAX_FRAME_LEN + CHECKSUM_LEN {
            return Err(JournalError::Format);
        }
        let target = active
            .segment
            .as_ref()
            .map_or(week, |(w, _)| (*w).max(week));
        if active.segment.as_ref().map(|(w, _)| *w) != Some(target) {
            let path = segment_path(&self.dir, target);
            let file = open_append(&path)?;
            sync_dir(&self.dir)?;
            active.segment = Some((target, file));
        }
        let (_, file) = active.segment.as_mut().ok_or(JournalError::Io)?;
        if file
            .write_all(&frame)
            .and_then(|()| file.sync_data())
            .is_err()
        {
            active.poisoned = true;
            return Err(JournalError::Io);
        }
        active.next_seq = seq + 1;
        Ok(seq)
    }

    fn next_seq(&self) -> Result<u64, JournalError> {
        let active = self.lock();
        if active.poisoned {
            Err(JournalError::Io)
        } else {
            Ok(active.next_seq)
        }
    }
}

/// Why [`prune_dir`] removed nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PruneError {
    /// The journal does not read (a file operation failed, a frame is corrupt or of an unknown
    /// format, sequence numbers are not contiguous).
    Journal(JournalError),
    /// The snapshot has applied entries the journal does not hold: it is not a snapshot of this
    /// journal's issuer, or the journal lost its end.
    SnapshotAhead,
    /// The journal no longer holds the entry after the snapshot's last applied one: a restore
    /// from this snapshot would refuse the start (a sequence gap).
    SnapshotBehind,
}

impl std::fmt::Display for PruneError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PruneError::Journal(e) => e.fmt(f),
            PruneError::SnapshotAhead => f.write_str("snapshot newer than the journal"),
            PruneError::SnapshotBehind => f.write_str("journal starts after the snapshot"),
        }
    }
}

impl std::error::Error for PruneError {}

/// What [`prune_dir`] found and removed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pruned {
    /// The weeks of the removed segments, ascending.
    pub removed: Vec<u64>,
    /// Segments left.
    pub kept: usize,
    /// Sequence number of the first entry left (0 in an empty journal).
    pub first_seq: u64,
    /// Sequence number of the last entry (0 in an empty journal).
    pub last_seq: u64,
}

/// Runbook B1 (§6.3, §6.4): removes, in ascending order, every segment of the journal in `dir`
/// except the latest whose entries are all older than the 7-day re-serve window (the segment's
/// week ended at least [`RESERVE_WINDOW_SECS`] before `now`) and covered by a verified snapshot
/// (`snapshot_journal_applied`, the snapshot's `journal_applied`, is at least the segment's last
/// sequence number); it stops at the first segment that is not both. Nothing is removed unless the
/// journal holds every entry after the snapshot: `first ≤ snapshot_journal_applied + 1` and
/// `snapshot_journal_applied ≤ last`, the conditions of the issuer's own replay (an empty journal
/// fits only a snapshot that applied nothing). No segment is opened for writing, so a torn tail
/// the issuer is writing is left as it is.
pub fn prune_dir(
    dir: &Path,
    now: u64,
    snapshot_journal_applied: u64,
) -> Result<Pruned, PruneError> {
    let segments = read_segments(dir).map_err(PruneError::Journal)?;
    let first_seq = segments
        .iter()
        .flat_map(|s| s.entries.first())
        .next()
        .map_or(0, |(seq, _)| *seq);
    let last_seq = segments
        .iter()
        .flat_map(|s| s.entries.last())
        .last()
        .map_or(0, |(seq, _)| *seq);
    if snapshot_journal_applied > last_seq {
        return Err(PruneError::SnapshotAhead);
    }
    if first_seq > snapshot_journal_applied.saturating_add(1) {
        return Err(PruneError::SnapshotBehind);
    }
    let latest = segments.last().map(|s| s.week);
    let mut removed = Vec::new();
    for s in &segments {
        let ended = week_start(s.week.saturating_add(1)).saturating_add(RESERVE_WINDOW_SECS);
        let covered = s
            .entries
            .last()
            .is_none_or(|(seq, _)| *seq <= snapshot_journal_applied);
        if Some(s.week) == latest || ended > now || !covered {
            break;
        }
        std::fs::remove_file(&s.path).map_err(|_| PruneError::Journal(JournalError::Io))?;
        removed.push(s.week);
    }
    if !removed.is_empty() {
        sync_dir(dir).map_err(PruneError::Journal)?;
    }
    let left: Vec<&Segment> = segments.iter().skip(removed.len()).collect();
    Ok(Pruned {
        kept: left.len(),
        first_seq: left
            .iter()
            .flat_map(|s| s.entries.first())
            .next()
            .map_or(0, |(seq, _)| *seq),
        last_seq,
        removed,
    })
}

fn segment_path(dir: &Path, week: u64) -> PathBuf {
    dir.join(format!("{SEGMENT_PREFIX}{week}"))
}

fn open_append(path: &Path) -> Result<File, JournalError> {
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|_| JournalError::Io)
}

/// Makes a new segment's directory entry durable (Unix; Windows persists it with the file).
fn sync_dir(dir: &Path) -> Result<(), JournalError> {
    #[cfg(unix)]
    {
        File::open(dir)
            .and_then(|d| d.sync_all())
            .map_err(|_| JournalError::Io)?;
    }
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
}

/// Reads and validates every segment, ascending by week. A segment listed but gone before it is
/// read was removed by a concurrent [`prune_dir`], which removes a prefix only: it is skipped, and
/// the sequence checks here and at the replay refuse any other missing entries.
fn read_segments(dir: &Path) -> Result<Vec<Segment>, JournalError> {
    let mut weeks = Vec::new();
    for item in std::fs::read_dir(dir).map_err(|_| JournalError::Io)? {
        let item = item.map_err(|_| JournalError::Io)?;
        let name = item.file_name();
        let Some(name) = name.to_str() else { continue };
        let Some(suffix) = name.strip_prefix(SEGMENT_PREFIX) else {
            continue;
        };
        // Only canonical decimal suffixes name a segment.
        let week: u64 = suffix.parse().map_err(|_| JournalError::Corrupt)?;
        if week.to_string() != suffix {
            return Err(JournalError::Corrupt);
        }
        weeks.push(week);
    }
    weeks.sort_unstable();
    let mut files = Vec::with_capacity(weeks.len());
    for week in weeks {
        match std::fs::read(segment_path(dir, week)) {
            Ok(bytes) => files.push((week, bytes)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(JournalError::Io),
        }
    }
    let count = files.len();
    let mut segments = Vec::with_capacity(count);
    let mut expected_seq: Option<u64> = None;
    for (i, (week, bytes)) in files.into_iter().enumerate() {
        let path = segment_path(dir, week);
        let is_last = i + 1 == count;
        let (entries, valid_len) = parse_segment(&bytes, is_last)?;
        for (seq, _) in &entries {
            if expected_seq.is_some_and(|e| e != *seq) {
                return Err(JournalError::Gap);
            }
            expected_seq = Some(seq + 1);
        }
        segments.push(Segment {
            week,
            path,
            entries,
            valid_len,
            file_len: bytes.len() as u64,
        });
    }
    Ok(segments)
}

/// Parses one segment: its entries and the length of its valid prefix. From the first frame that
/// does not verify, the rest of the last segment is a torn tail if no valid frame starts at any
/// later offset (a crash may leave a partial frame, zeros or stale bytes after the last durable
/// frame, but never a valid frame after a torn one: appends stop at the first failure). A valid
/// frame after the damage, or damage in an earlier segment, is corruption.
fn parse_segment(bytes: &[u8], is_last: bool) -> Result<(Vec<(u64, Entry)>, u64), JournalError> {
    let mut entries = Vec::new();
    let mut pos = 0usize;
    while pos < bytes.len() {
        let Some((seq, tag, body, next)) = frame_at(bytes, pos) else {
            if !is_last || (pos + 1..bytes.len()).any(|p| frame_at(bytes, p).is_some()) {
                return Err(JournalError::Corrupt);
            }
            break;
        };
        entries.push((seq, Entry::decode(tag, body)?));
        pos = next;
    }
    Ok((entries, pos as u64))
}

/// The frame starting at `pos`, if it is whole, its length in range and its checksum verified:
/// its sequence number, tag, body and the offset after it.
fn frame_at(bytes: &[u8], pos: usize) -> Option<(u64, u8, &[u8], usize)> {
    let rest = bytes.get(pos..)?;
    let len = u32::from_be_bytes(rest.get(..4)?.try_into().ok()?) as usize;
    if !(9..=MAX_FRAME_LEN).contains(&len) {
        return None;
    }
    let need = 4 + len + CHECKSUM_LEN;
    let (frame, checksum) = rest.get(..need)?.split_at(4 + len);
    if Sha256::digest(frame).as_slice() != checksum {
        return None;
    }
    let seq = u64::from_be_bytes(frame[4..12].try_into().ok()?);
    Some((seq, frame[12], &frame[13..], pos + need))
}
