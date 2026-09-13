//! Persisted redemption nullifiers (Phase 8 design §10.4, ADR-25, §19.10, §19.20 point 2), in their
//! own database file `<data-dir>/nullifiers.redb` (the blob store stays at its schema v2).
//!
//! ```text
//! nullifiers        : period(8, BE) || nullifier(32) -> binding tag(16)
//! redemption_counts : period u64                     -> rows the sweep deleted for it (u64)
//! es_keys           : kind(1) || epoch(8, BE)        -> key id(32)   (Entitlement Schedule rule 5
//!                                                                     memory)
//! es_revoked        : kind(1) || epoch(8, BE)        -> ()           (revocations are append-only
//!                                                                     too)
//! meta              : schema_version, relay_key_check, closed_through_period,
//!                     refuse_through_period, sweep_high_water_minute, es_max_seq
//! ```
//!
//! **Redemption counts** (runbook R2, design §6.9 check 2, §19.3; a recorded addition to the §10.4
//! table list). The sweep that closes a period deletes its rows and, in the same transaction, adds
//! their number to `redemption_counts[period]`: the final number of redemptions this relay
//! accepted in that week, the aggregate its operator reports for the reconciliation (and knows
//! anyway). Counts of the last [`REDEMPTION_COUNT_WEEKS`] closed periods are kept; older ones go
//! in the same transaction. A count is a number per week, nothing else: no nullifier, tag,
//! namespace or time finer than the week. A store written before the table existed gets it, empty,
//! at its next open (its periods closed before then have no count); the schema version stays 1.
//!
//! `relay_key_check` identifies the relay key the binding tags were computed under: a store opens
//! only under that key, or under a new one through a reset (review S3-MR-3).
//!
//! No time of any event, no namespace and no request id is stored; rows live in key order, so the
//! file shows the redemption count per week and nothing about the order of redemptions.
//!
//! Every write is one redb write transaction with immediate durability: [`NullifierStore::
//! record_or_get`] has committed (fsync) when it returns, which is what lets the relay mint only
//! after the nullifier is durable (design §10.2 step 9). redb admits one writer at a time, so two
//! concurrent redemptions of one token leave exactly one row.
//!
//! Periods are closed by a persisted high-water that is never lowered: the sweep raises
//! `closed_through_period` in the transaction that deletes those periods' rows, and a record for a
//! closed period is refused whatever the caller's clock says, so a clock stepped back never reopens
//! a swept period (§19.10 point 1). After the file was lost, the relay starts over with a
//! `refuse_through_period` covering every period that was open at the reset (§19.10 point 2).

use redb::{Database, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use crate::StoreError;

/// On-disk schema version of `nullifiers.redb`; any other version is refused.
pub const NULLIFIER_SCHEMA_VERSION: u64 = 1;
/// Length of a binding tag.
pub const TAG_BYTES: usize = 16;
/// Length of the relay key check value the store records.
pub const KEY_CHECK_BYTES: usize = 8;
/// Closed periods whose redemption counts are kept (one quarter of weekly reconciliations).
pub const REDEMPTION_COUNT_WEEKS: u64 = 13;

const NULLIFIERS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("nullifiers");
const REDEMPTION_COUNTS: TableDefinition<u64, u64> = TableDefinition::new("redemption_counts");
const ES_KEYS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("es_keys");
const ES_REVOKED: TableDefinition<&[u8], ()> = TableDefinition::new("es_revoked");
const META: TableDefinition<&str, u64> = TableDefinition::new("meta");

const SCHEMA_VERSION_KEY: &str = "schema_version";
const KEY_CHECK: &str = "relay_key_check";
const CLOSED_THROUGH: &str = "closed_through_period";
const REFUSE_THROUGH: &str = "refuse_through_period";
const SWEEP_HIGH_WATER: &str = "sweep_high_water_minute";
const ES_MAX_SEQ: &str = "es_max_seq";

const ROW_KEY: usize = 8 + 32;
const ES_KEY: usize = 1 + 8;

/// How a relay opens its nullifier store (design §10.5, runbook O1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NullifierStart {
    /// The store must exist: this data directory has redeemed before (its `relay.key` exists). A
    /// missing store is a refusal to start, never a silent empty set.
    Existing,
    /// A fresh data directory, or the one-time Phase 8 upgrade (`--nullifiers-init`): a missing
    /// store is created empty. The relay's redemption marker keeps a data directory that has had
    /// a store from ever getting here again.
    Create,
    /// `--nullifiers-reset` after the store was lost: the store is created (or kept) and refuses
    /// every period up to `refuse_through_period`, the last period whose acceptance window was
    /// open at the reset.
    Reset { refuse_through_period: u64 },
}

/// The persisted high-waters.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NullifierState {
    /// Every period up to this one is closed: its rows are gone and it is never accepted again.
    pub closed_through_period: Option<u64>,
    /// Every period up to this one is refused after a store reset.
    pub refuse_through_period: Option<u64>,
    /// The sweep never runs below this minute (a clock stepped back).
    pub sweep_high_water_minute: Option<u64>,
}

/// Outcome of [`NullifierStore::record_or_get`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Record {
    /// The nullifier was new; the row is committed.
    Inserted,
    /// The nullifier is bound to the same tag: an identical retry. Nothing was written.
    Identical,
    /// The nullifier is bound to another tag (a replay). Nothing was written.
    Bound,
    /// The period is closed. Nothing was written.
    Closed,
    /// The period is refused after a store reset. Nothing was written.
    Refused,
}

/// Outcome of [`NullifierStore::sweep`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NullifierSweep {
    /// False when the sweep did not run because the clock is below the high-water minute.
    pub ran: bool,
    /// Nullifier rows deleted.
    pub removed: usize,
    /// `closed_through_period` after the sweep.
    pub closed_through_period: Option<u64>,
}

/// The Entitlement Schedule facts a relay remembers (rule 5, §19.2 point 2, §19.20 point 2): the
/// key id of every (kind, epoch) it accepted, every revocation, and the highest `seq`. Kinds are
/// the ES kind bytes; the relay remembers neither prices nor other slots.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EsMemory {
    pub max_seq: Option<u64>,
    pub keys: BTreeMap<(u8, u64), [u8; 32]>,
    pub revoked: BTreeSet<(u8, u64)>,
}

/// The nullifier store of one relay.
pub struct NullifierStore {
    db: Database,
}

impl NullifierStore {
    /// Opens the store at `path` as `start` says, for the relay key whose check value is
    /// `key_check` (recorded when the store is created). A store recorded under another key is
    /// refused with [`StoreError::KeyMismatch`] unless `start` is a reset, which records the new
    /// key: every binding tag changes with the key, so only a reset, which refuses the open
    /// periods, may adopt one. A file written by another schema version (or one without a schema
    /// version or a key check, such as a creation interrupted by a crash) is refused with
    /// [`StoreError::IncompatibleSchema`]. A new file is written under a temporary name and
    /// renamed into place once initialized, so the store either exists complete or not at all.
    pub fn open(
        path: &Path,
        start: NullifierStart,
        key_check: &[u8; KEY_CHECK_BYTES],
    ) -> Result<Self, StoreError> {
        let check = u64::from_be_bytes(*key_check);
        if !path.exists() {
            let refuse = match start {
                NullifierStart::Existing => return Err(StoreError::Missing),
                NullifierStart::Create => None,
                NullifierStart::Reset {
                    refuse_through_period,
                } => Some(refuse_through_period),
            };
            let tmp = temporary_path(path);
            if tmp.exists() {
                std::fs::remove_file(&tmp).map_err(io_error)?;
            }
            {
                let db = Database::create(&tmp)?;
                let txn = db.begin_write()?;
                {
                    let mut meta = txn.open_table(META)?;
                    meta.insert(SCHEMA_VERSION_KEY, NULLIFIER_SCHEMA_VERSION)?;
                    meta.insert(KEY_CHECK, check)?;
                    if let Some(r) = refuse {
                        meta.insert(REFUSE_THROUGH, r)?;
                    }
                    txn.open_table(NULLIFIERS)?;
                    txn.open_table(REDEMPTION_COUNTS)?;
                    txn.open_table(ES_KEYS)?;
                    txn.open_table(ES_REVOKED)?;
                }
                txn.commit()?;
            }
            std::fs::rename(&tmp, path).map_err(io_error)?;
        }
        let db = Database::create(path)?;
        let txn = db.begin_write()?;
        {
            let mut meta = txn.open_table(META)?;
            let version = meta.get(SCHEMA_VERSION_KEY)?.map(|g| g.value());
            if version != Some(NULLIFIER_SCHEMA_VERSION) {
                return Err(StoreError::IncompatibleSchema);
            }
            let stored = meta.get(KEY_CHECK)?.map(|g| g.value());
            match stored {
                None => return Err(StoreError::IncompatibleSchema),
                Some(s) if s == check => {}
                Some(_) if matches!(start, NullifierStart::Reset { .. }) => {
                    meta.insert(KEY_CHECK, check)?;
                }
                Some(_) => return Err(StoreError::KeyMismatch),
            }
            if let NullifierStart::Reset {
                refuse_through_period,
            } = start
            {
                // A reset over an existing store only refuses more: it never lowers a high-water.
                let old = meta.get(REFUSE_THROUGH)?.map(|g| g.value());
                let raised = old.map_or(refuse_through_period, |o| o.max(refuse_through_period));
                meta.insert(REFUSE_THROUGH, raised)?;
            }
            txn.open_table(NULLIFIERS)?;
            txn.open_table(REDEMPTION_COUNTS)?;
            txn.open_table(ES_KEYS)?;
            txn.open_table(ES_REVOKED)?;
        }
        txn.commit()?;
        Ok(NullifierStore { db })
    }

    /// The persisted high-waters.
    pub fn state(&self) -> Result<NullifierState, StoreError> {
        let txn = self.db.begin_read()?;
        let meta = txn.open_table(META)?;
        let get = |key: &str| -> Result<Option<u64>, StoreError> {
            Ok(meta.get(key)?.map(|g| g.value()))
        };
        Ok(NullifierState {
            closed_through_period: get(CLOSED_THROUGH)?,
            refuse_through_period: get(REFUSE_THROUGH)?,
            sweep_high_water_minute: get(SWEEP_HIGH_WATER)?,
        })
    }

    /// Records `nullifier` of `period` with `tag`, or reports how it is already bound, in one write
    /// transaction. A closed or refused period is re-checked inside the transaction, so a sweep
    /// that closes the period concurrently can never leave a row behind in it.
    pub fn record_or_get(
        &self,
        period: u64,
        nullifier: &[u8; 32],
        tag: &[u8; TAG_BYTES],
    ) -> Result<Record, StoreError> {
        let txn = self.db.begin_write()?;
        let outcome = {
            let meta = txn.open_table(META)?;
            let closed = meta.get(CLOSED_THROUGH)?.map(|g| g.value());
            let refused = meta.get(REFUSE_THROUGH)?.map(|g| g.value());
            if closed.is_some_and(|c| period <= c) {
                Record::Closed
            } else if refused.is_some_and(|r| period <= r) {
                Record::Refused
            } else {
                let mut rows = txn.open_table(NULLIFIERS)?;
                let key = row_key(period, nullifier);
                let existing = rows.get(key.as_slice())?.map(|g| g.value().to_vec());
                match existing {
                    None => {
                        rows.insert(key.as_slice(), tag.as_slice())?;
                        Record::Inserted
                    }
                    Some(t) if t == tag.as_slice() => Record::Identical,
                    Some(_) => Record::Bound,
                }
            }
        };
        if outcome == Record::Inserted {
            txn.commit()?;
        } else {
            txn.abort()?;
        }
        Ok(outcome)
    }

    /// One sweep at `now_minute`: unless the clock is below the persisted high-water minute, in one
    /// write transaction it raises the high-water minute, raises `closed_through_period` to
    /// `closed_through` (never lowering it), deletes every row of a closed period, adds the number
    /// deleted per period to its redemption count and drops the counts of periods more than
    /// [`REDEMPTION_COUNT_WEEKS`] closed periods old.
    pub fn sweep(
        &self,
        now_minute: u64,
        closed_through: Option<u64>,
    ) -> Result<NullifierSweep, StoreError> {
        let txn = self.db.begin_write()?;
        let report = {
            let mut meta = txn.open_table(META)?;
            let high_water = meta.get(SWEEP_HIGH_WATER)?.map(|g| g.value());
            let old_closed = meta.get(CLOSED_THROUGH)?.map(|g| g.value());
            if high_water.is_some_and(|h| now_minute < h) {
                None
            } else {
                meta.insert(SWEEP_HIGH_WATER, now_minute)?;
                let closed = match (old_closed, closed_through) {
                    (Some(o), Some(c)) => Some(o.max(c)),
                    (o, c) => o.or(c),
                };
                if let Some(c) = closed {
                    meta.insert(CLOSED_THROUGH, c)?;
                }
                let mut removed = 0;
                if let Some(c) = closed {
                    let mut rows = txn.open_table(NULLIFIERS)?;
                    // Rows of periods <= c: every key below period c + 1 (all rows if c is the
                    // largest period).
                    let end = c.checked_add(1).map(|next| row_key(next, &[0; 32]));
                    let mut doomed: Vec<Vec<u8>> = Vec::new();
                    for row in rows.iter()? {
                        let (k, _) = row?;
                        let k = k.value();
                        if end.as_ref().is_some_and(|e| k >= e.as_slice()) {
                            break;
                        }
                        doomed.push(k.to_vec());
                    }
                    let mut per_period: BTreeMap<u64, u64> = BTreeMap::new();
                    for key in &doomed {
                        rows.remove(key.as_slice())?;
                        let period = key
                            .get(..8)
                            .and_then(|p| <[u8; 8]>::try_from(p).ok())
                            .map(u64::from_be_bytes)
                            .ok_or(StoreError::IncompatibleSchema)?;
                        *per_period.entry(period).or_default() += 1;
                    }
                    removed = doomed.len();
                    let mut counts = txn.open_table(REDEMPTION_COUNTS)?;
                    for (period, n) in per_period {
                        let old = counts.get(period)?.map(|g| g.value()).unwrap_or(0);
                        counts.insert(period, old.saturating_add(n))?;
                    }
                    // Keep periods c - 12 ..= c (13 weeks); every count below goes.
                    let oldest_kept = c.saturating_sub(REDEMPTION_COUNT_WEEKS - 1);
                    let stale: Vec<u64> = counts
                        .range(..oldest_kept)?
                        .map(|row| row.map(|(k, _)| k.value()))
                        .collect::<Result<_, _>>()?;
                    for period in stale {
                        counts.remove(period)?;
                    }
                }
                Some(NullifierSweep {
                    ran: true,
                    removed,
                    closed_through_period: closed,
                })
            }
        };
        match report {
            Some(r) => {
                txn.commit()?;
                Ok(r)
            }
            None => {
                txn.abort()?;
                Ok(NullifierSweep {
                    ran: false,
                    removed: 0,
                    closed_through_period: self.state()?.closed_through_period,
                })
            }
        }
    }

    /// The remembered Entitlement Schedule facts.
    pub fn es_memory(&self) -> Result<EsMemory, StoreError> {
        let txn = self.db.begin_read()?;
        let meta = txn.open_table(META)?;
        let keys_table = txn.open_table(ES_KEYS)?;
        let revoked_table = txn.open_table(ES_REVOKED)?;
        let mut memory = EsMemory {
            max_seq: meta.get(ES_MAX_SEQ)?.map(|g| g.value()),
            ..EsMemory::default()
        };
        for row in keys_table.iter()? {
            let (k, v) = row?;
            let kind_epoch = parse_es_key(k.value()).ok_or(StoreError::IncompatibleSchema)?;
            let id: [u8; 32] = v
                .value()
                .try_into()
                .map_err(|_| StoreError::IncompatibleSchema)?;
            memory.keys.insert(kind_epoch, id);
        }
        for row in revoked_table.iter()? {
            let (k, _) = row?;
            memory
                .revoked
                .insert(parse_es_key(k.value()).ok_or(StoreError::IncompatibleSchema)?);
        }
        Ok(memory)
    }

    /// Adds `memory` to the remembered facts (append-only: a remembered key id is never replaced,
    /// a revocation never removed, the highest `seq` never lowered). The caller has already
    /// checked the new schedule against [`NullifierStore::es_memory`] (rule 5); a conflicting key
    /// id is refused here as well.
    pub fn remember_es(&self, memory: &EsMemory) -> Result<(), StoreError> {
        let txn = self.db.begin_write()?;
        {
            let mut meta = txn.open_table(META)?;
            if let Some(seq) = memory.max_seq {
                let old = meta.get(ES_MAX_SEQ)?.map(|g| g.value());
                meta.insert(ES_MAX_SEQ, old.map_or(seq, |o| o.max(seq)))?;
            }
            let mut keys = txn.open_table(ES_KEYS)?;
            for (&(kind, epoch), id) in &memory.keys {
                let key = es_key(kind, epoch);
                let existing = keys.get(key.as_slice())?.map(|g| g.value().to_vec());
                match existing {
                    None => {
                        keys.insert(key.as_slice(), id.as_slice())?;
                    }
                    Some(e) if e == id.as_slice() => {}
                    Some(_) => return Err(StoreError::EsConflict),
                }
            }
            let mut revoked = txn.open_table(ES_REVOKED)?;
            for &(kind, epoch) in &memory.revoked {
                revoked.insert(es_key(kind, epoch).as_slice(), ())?;
            }
        }
        txn.commit()?;
        Ok(())
    }

    /// Number of nullifier rows (every live period).
    pub fn count(&self) -> Result<u64, StoreError> {
        let txn = self.db.begin_read()?;
        Ok(txn.open_table(NULLIFIERS)?.len()?)
    }

    /// The redemption count of every closed period the store still counts (the last
    /// [`REDEMPTION_COUNT_WEEKS`]), by period. A period closed without redemptions has no count.
    pub fn redemption_counts(&self) -> Result<BTreeMap<u64, u64>, StoreError> {
        let txn = self.db.begin_read()?;
        let counts = txn.open_table(REDEMPTION_COUNTS)?;
        let mut out = BTreeMap::new();
        for row in counts.iter()? {
            let (period, n) = row?;
            out.insert(period.value(), n.value());
        }
        Ok(out)
    }
}

fn row_key(period: u64, nullifier: &[u8; 32]) -> [u8; ROW_KEY] {
    let mut k = [0u8; ROW_KEY];
    k[..8].copy_from_slice(&period.to_be_bytes());
    k[8..].copy_from_slice(nullifier);
    k
}

fn es_key(kind: u8, epoch: u64) -> [u8; ES_KEY] {
    let mut k = [0u8; ES_KEY];
    k[0] = kind;
    k[1..].copy_from_slice(&epoch.to_be_bytes());
    k
}

fn parse_es_key(k: &[u8]) -> Option<(u8, u64)> {
    let k: [u8; ES_KEY] = k.try_into().ok()?;
    Some((k[0], u64::from_be_bytes(k[1..].try_into().ok()?)))
}

fn temporary_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".creating");
    path.with_file_name(name)
}

fn io_error(e: std::io::Error) -> StoreError {
    StoreError::Db(redb::Error::Io(e))
}

#[cfg(test)]
mod tests {
    use super::*;

    const CHECK: [u8; KEY_CHECK_BYTES] = [1; KEY_CHECK_BYTES];

    fn open(dir: &tempfile::TempDir, start: NullifierStart) -> Result<NullifierStore, StoreError> {
        NullifierStore::open(&dir.path().join("nullifiers.redb"), start, &CHECK)
    }

    #[test]
    fn a_store_opens_only_under_its_relay_key_until_a_reset() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nullifiers.redb");
        let other = [2u8; KEY_CHECK_BYTES];
        let store = NullifierStore::open(&path, NullifierStart::Create, &CHECK).unwrap();
        store.record_or_get(10, &[1; 32], &[7; 16]).unwrap();
        drop(store);
        for start in [NullifierStart::Existing, NullifierStart::Create] {
            assert!(matches!(
                NullifierStore::open(&path, start, &other),
                Err(StoreError::KeyMismatch)
            ));
        }
        // A reset adopts the new key, keeps the rows and refuses the open periods.
        let reset = NullifierStart::Reset {
            refuse_through_period: 10,
        };
        let store = NullifierStore::open(&path, reset, &other).unwrap();
        assert_eq!(store.count().unwrap(), 1);
        assert_eq!(store.state().unwrap().refuse_through_period, Some(10));
        drop(store);
        drop(NullifierStore::open(&path, NullifierStart::Existing, &other).unwrap());
        assert!(matches!(
            NullifierStore::open(&path, NullifierStart::Existing, &CHECK),
            Err(StoreError::KeyMismatch)
        ));
        // A file of this schema without a key check was not written by `open`: never opened.
        let bare = dir.path().join("bare.redb");
        {
            let db = Database::create(&bare).unwrap();
            let txn = db.begin_write().unwrap();
            txn.open_table(META)
                .unwrap()
                .insert(SCHEMA_VERSION_KEY, NULLIFIER_SCHEMA_VERSION)
                .unwrap();
            txn.commit().unwrap();
        }
        for start in [NullifierStart::Existing, reset] {
            assert!(matches!(
                NullifierStore::open(&bare, start, &CHECK),
                Err(StoreError::IncompatibleSchema)
            ));
        }
    }

    #[test]
    fn record_or_get_binds_each_nullifier_to_one_tag_across_reopens() {
        let dir = tempfile::tempdir().unwrap();
        let store = open(&dir, NullifierStart::Create).unwrap();
        let n = [1u8; 32];
        assert_eq!(
            store.record_or_get(10, &n, &[7; 16]).unwrap(),
            Record::Inserted
        );
        assert_eq!(
            store.record_or_get(10, &n, &[7; 16]).unwrap(),
            Record::Identical
        );
        assert_eq!(
            store.record_or_get(10, &n, &[8; 16]).unwrap(),
            Record::Bound
        );
        // Periods are separate key spaces.
        assert_eq!(
            store.record_or_get(11, &n, &[8; 16]).unwrap(),
            Record::Inserted
        );
        assert_eq!(store.count().unwrap(), 2);
        drop(store);
        let store = open(&dir, NullifierStart::Existing).unwrap();
        assert_eq!(
            store.record_or_get(10, &n, &[7; 16]).unwrap(),
            Record::Identical
        );
        assert_eq!(
            store.record_or_get(10, &n, &[9; 16]).unwrap(),
            Record::Bound
        );
        assert_eq!(store.count().unwrap(), 2);
    }

    #[test]
    fn a_missing_store_is_refused_unless_created_or_reset() {
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(
            open(&dir, NullifierStart::Existing),
            Err(StoreError::Missing)
        ));
        assert!(!dir.path().join("nullifiers.redb").exists());
        let store = open(
            &dir,
            NullifierStart::Reset {
                refuse_through_period: 20,
            },
        )
        .unwrap();
        assert_eq!(store.state().unwrap().refuse_through_period, Some(20));
        assert_eq!(
            store.record_or_get(20, &[1; 32], &[1; 16]).unwrap(),
            Record::Refused
        );
        assert_eq!(
            store.record_or_get(19, &[1; 32], &[1; 16]).unwrap(),
            Record::Refused
        );
        assert_eq!(
            store.record_or_get(21, &[1; 32], &[1; 16]).unwrap(),
            Record::Inserted
        );
        drop(store);
        // A second reset only refuses more; a lower one changes nothing.
        let store = open(
            &dir,
            NullifierStart::Reset {
                refuse_through_period: 15,
            },
        )
        .unwrap();
        assert_eq!(store.state().unwrap().refuse_through_period, Some(20));
        assert_eq!(store.count().unwrap(), 1);
        drop(store);
        // A leftover of an interrupted creation is discarded, never opened as a store.
        std::fs::write(dir.path().join("fresh.redb.creating"), b"torn").unwrap();
        let fresh = NullifierStore::open(
            &dir.path().join("fresh.redb"),
            NullifierStart::Create,
            &CHECK,
        );
        assert!(fresh.is_ok());
        assert!(!dir.path().join("fresh.redb.creating").exists());
    }

    #[test]
    fn a_file_of_another_schema_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nullifiers.redb");
        {
            let db = Database::create(&path).unwrap();
            let txn = db.begin_write().unwrap();
            txn.open_table(META)
                .unwrap()
                .insert(SCHEMA_VERSION_KEY, 2)
                .unwrap();
            txn.commit().unwrap();
        }
        assert!(matches!(
            NullifierStore::open(&path, NullifierStart::Existing, &CHECK),
            Err(StoreError::IncompatibleSchema)
        ));
        // A reset never reinterprets a file of another schema either.
        assert!(matches!(
            NullifierStore::open(
                &path,
                NullifierStart::Reset {
                    refuse_through_period: 1
                },
                &CHECK
            ),
            Err(StoreError::IncompatibleSchema)
        ));
        // A file without a nullifier schema version (an empty database, the blob store) is not a
        // nullifier store, whatever the start mode.
        let empty = dir.path().join("empty.redb");
        drop(Database::create(&empty).unwrap());
        let blobs = dir.path().join("blobs.redb");
        drop(crate::BlobStore::open(&blobs).unwrap());
        for file in [&empty, &blobs] {
            assert!(matches!(
                NullifierStore::open(file, NullifierStart::Create, &CHECK),
                Err(StoreError::IncompatibleSchema)
            ));
        }
    }

    #[test]
    fn the_sweep_closes_periods_for_good_and_never_runs_below_its_high_water() {
        let dir = tempfile::tempdir().unwrap();
        let store = open(&dir, NullifierStart::Create).unwrap();
        for p in [9u64, 10, 11] {
            store.record_or_get(p, &[p as u8; 32], &[1; 16]).unwrap();
        }
        let r = store.sweep(1_000, Some(10)).unwrap();
        assert_eq!(
            r,
            NullifierSweep {
                ran: true,
                removed: 2,
                closed_through_period: Some(10)
            }
        );
        assert_eq!(store.count().unwrap(), 1);
        // A closed period is refused whatever the caller believes.
        assert_eq!(
            store.record_or_get(10, &[10; 32], &[1; 16]).unwrap(),
            Record::Closed
        );
        assert_eq!(
            store.record_or_get(3, &[3; 32], &[1; 16]).unwrap(),
            Record::Closed
        );
        // Below the high-water minute nothing runs; a lower target never lowers the high-water.
        let back = store.sweep(999, Some(11)).unwrap();
        assert!(!back.ran);
        assert_eq!(back.closed_through_period, Some(10));
        assert_eq!(store.count().unwrap(), 1);
        let lower = store.sweep(1_001, Some(5)).unwrap();
        assert_eq!(lower.closed_through_period, Some(10));
        assert_eq!(lower.removed, 0);
        let none = store.sweep(1_002, None).unwrap();
        assert_eq!(none.closed_through_period, Some(10));
        // Persisted: after a reopen the same holds.
        drop(store);
        let store = open(&dir, NullifierStart::Existing).unwrap();
        let state = store.state().unwrap();
        assert_eq!(state.closed_through_period, Some(10));
        assert_eq!(state.sweep_high_water_minute, Some(1_002));
        assert!(!store.sweep(1_001, Some(11)).unwrap().ran);
        let all = store.sweep(1_003, Some(u64::MAX)).unwrap();
        assert_eq!(all.removed, 1);
        assert_eq!(store.count().unwrap(), 0);
    }

    /// Runbook R2: the sweep that closes a week counts its rows in the same transaction; live
    /// weeks are not counted, a count never changes once written, and only the last 13 closed
    /// weeks are kept.
    #[test]
    fn the_sweep_counts_each_closed_week_and_keeps_thirteen() {
        let dir = tempfile::tempdir().unwrap();
        let store = open(&dir, NullifierStart::Create).unwrap();
        for (p, n) in [(9u64, 2u8), (10, 3), (11, 1)] {
            for i in 0..n {
                store
                    .record_or_get(p, &[p as u8 * 16 + i; 32], &[1; 16])
                    .unwrap();
            }
        }
        assert!(store.redemption_counts().unwrap().is_empty());
        store.sweep(1_000, Some(10)).unwrap();
        let counted = BTreeMap::from([(9, 2), (10, 3)]);
        assert_eq!(store.redemption_counts().unwrap(), counted);
        // A repeated sweep, a lower target and a clock below the high-water change nothing.
        store.sweep(1_001, Some(10)).unwrap();
        store.sweep(1_002, Some(5)).unwrap();
        store.sweep(999, Some(11)).unwrap();
        assert_eq!(store.redemption_counts().unwrap(), counted);
        drop(store);
        let store = open(&dir, NullifierStart::Existing).unwrap();
        assert_eq!(store.redemption_counts().unwrap(), counted);
        store.sweep(1_003, Some(11)).unwrap();
        let all = BTreeMap::from([(9, 2), (10, 3), (11, 1)]);
        assert_eq!(store.redemption_counts().unwrap(), all);
        // Weeks 12..=21 close without redemptions: no count, and 9 is still one of the last 13.
        store.sweep(1_004, Some(21)).unwrap();
        assert_eq!(store.redemption_counts().unwrap(), all);
        store.sweep(1_005, Some(22)).unwrap();
        assert_eq!(
            store.redemption_counts().unwrap(),
            BTreeMap::from([(10, 3), (11, 1)])
        );
        store.sweep(1_006, Some(u64::MAX)).unwrap();
        assert!(store.redemption_counts().unwrap().is_empty());
        assert_eq!(store.count().unwrap(), 0);
    }

    /// A store written before the count table existed gets it at its next open.
    #[test]
    fn a_store_without_the_count_table_gains_it_at_open() {
        let dir = tempfile::tempdir().unwrap();
        let store = open(&dir, NullifierStart::Create).unwrap();
        store.record_or_get(7, &[7; 32], &[1; 16]).unwrap();
        drop(store);
        {
            let db = Database::create(dir.path().join("nullifiers.redb")).unwrap();
            let txn = db.begin_write().unwrap();
            assert!(txn.delete_table(REDEMPTION_COUNTS).unwrap());
            txn.commit().unwrap();
        }
        let store = open(&dir, NullifierStart::Existing).unwrap();
        assert!(store.redemption_counts().unwrap().is_empty());
        store.sweep(1_000, Some(7)).unwrap();
        assert_eq!(store.redemption_counts().unwrap(), BTreeMap::from([(7, 1)]));
    }

    #[test]
    fn schedule_memory_is_append_only() {
        let dir = tempfile::tempdir().unwrap();
        let store = open(&dir, NullifierStart::Create).unwrap();
        assert_eq!(store.es_memory().unwrap(), EsMemory::default());
        let mut m = EsMemory {
            max_seq: Some(2),
            ..EsMemory::default()
        };
        m.keys.insert((1, 2959), [1; 32]);
        m.keys.insert((2, 739), [2; 32]);
        m.revoked.insert((1, 2960));
        store.remember_es(&m).unwrap();
        // A lower seq, fewer keys and no revocations add nothing and remove nothing.
        let mut smaller = EsMemory {
            max_seq: Some(1),
            ..EsMemory::default()
        };
        smaller.keys.insert((1, 2959), [1; 32]);
        store.remember_es(&smaller).unwrap();
        drop(store);
        let store = open(&dir, NullifierStart::Existing).unwrap();
        assert_eq!(store.es_memory().unwrap(), m);
        let mut changed = m.clone();
        changed.keys.insert((1, 2959), [9; 32]);
        assert!(matches!(
            store.remember_es(&changed),
            Err(StoreError::EsConflict)
        ));
        assert_eq!(store.es_memory().unwrap(), m);
    }
}
