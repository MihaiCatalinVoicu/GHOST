//! Key registrations (Phase 9 design §4.4–§4.6, ADR-30), in their own database file
//! `<data-dir>/keys.redb`, schema version 1:
//!
//! ```text
//! bearer_keys : namespace(32) || period(8, BE) || kind(1) || verifier(32) -> valid_until(8, BE) || quota_bytes(8, BE) || n(1) || serial(16) × n
//! serial_use  : namespace(32) || period(8, BE) || kind(1) || serial(16)   -> verifier(32) || valid_until(8, BE)
//! meta        : schema_version, sweep_high_water_minute
//! ```
//!
//! A `bearer_keys` record says that a credential v3 whose verifier is `verifier` may use
//! `namespace` in the way `kind` allows while `now < valid_until`. Records **accumulate**: a
//! registration never replaces or removes one; a second write capability registering the same
//! verifier credits its quota to the record (at most [`MAX_SERIALS`] capabilities, so at most four
//! credits), and `serial_use` binds each capability to at most one verifier per (namespace,
//! period, kind).
//!
//! **Soft state.** Registrations are re-created by their owners, so this store has none of the
//! start-up rules of `nullifiers.redb`: a missing file is created empty at every start, and a
//! nullifier reset never touches it. A file of another schema (or holding any table not listed
//! above) is refused, never reinterpreted.
//!
//! **At rest** (AD-12): namespaces, periods, verifiers (hashes of secrets a seizer does not hold),
//! week-aligned validity instants, allowances and up to four capability serials per record; no
//! request history, no time finer than the week, no per-sender data.
//!
//! Every write is one redb write transaction with immediate durability. The sweep deletes every
//! row with `valid_until <= now` and never runs below its persisted high-water minute (the ADR-25
//! point 3 clock rule).

use redb::{
    Database, Durability, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition,
    TableHandle, WriteTransaction,
};
use std::ops::RangeInclusive;
use std::path::Path;

use crate::StoreError;

/// On-disk schema version of `keys.redb`; any other version is refused.
pub const KEYS_SCHEMA_VERSION: u64 = 1;
/// Capability serials (and quota credits) a record keeps at most (design §4.4 point 4). A card
/// holder knows the shared deposit secret and can credit the owner's record with its own
/// capability, so the four credits of a record need not be the owner's; every redeemed capability
/// carries the same `capability_quota_bytes`, so foreign credits raise the record's allowance and
/// never lower it, and what the owner loses when it registers fifth is its own credit, not
/// allowance (`protocol/test-vectors/register.txt` section 1).
pub const MAX_SERIALS: usize = 4;
/// Length of a capability serial.
pub const SERIAL_BYTES: usize = 16;

const BEARER_KEYS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("bearer_keys");
const SERIAL_USE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("serial_use");
const META: TableDefinition<&str, u64> = TableDefinition::new("meta");

/// The tables of schema version 1; any other table makes the file incompatible.
pub const KEYS_TABLES: [&str; 3] = ["bearer_keys", "serial_use", "meta"];

const SCHEMA_VERSION_KEY: &str = "schema_version";
const SWEEP_HIGH_WATER: &str = "sweep_high_water_minute";

const RECORD_KEY: usize = 32 + 8 + 1 + 32;
const USE_KEY: usize = 32 + 8 + 1 + SERIAL_BYTES;
const USE_VALUE: usize = 32 + 8;
const RECORD_HEAD: usize = 8 + 8 + 1;

/// One registration request, as the relay has verified it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Registration {
    pub namespace: [u8; 32],
    pub period: u64,
    /// The bearer kind byte (1 read, 3 deposit, 4 fetch).
    pub kind: u8,
    pub verifier: [u8; 32],
    /// The registering capability's serial.
    pub serial: [u8; SERIAL_BYTES],
    /// The registering capability's quota, credited to the record.
    pub quota_bytes: u64,
    /// `start(period + 2) + 3600`.
    pub valid_until: u64,
}

/// Outcome of [`KeyStore::register`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Registered {
    /// A new record was inserted.
    Inserted,
    /// The capability's serial and quota were added to an existing record.
    Credited,
    /// The record already names this capability, or already holds [`MAX_SERIALS`] credits (the
    /// capability is bound to the verifier all the same).
    Unchanged,
    /// The capability already registered another verifier for this (namespace, period, kind).
    /// Nothing was written.
    Conflict,
}

/// A `bearer_keys` record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BearerRecord {
    pub period: u64,
    pub valid_until: u64,
    pub quota_bytes: u64,
    pub serials: Vec<[u8; SERIAL_BYTES]>,
}

/// Outcome of [`KeyStore::sweep`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct KeySweep {
    /// False when the sweep did not run because the clock is below the high-water minute.
    pub ran: bool,
    /// `bearer_keys` rows deleted.
    pub records_removed: usize,
    /// `serial_use` rows deleted.
    pub serials_removed: usize,
}

/// The key registrations of one relay.
pub struct KeyStore {
    db: Database,
}

fn record_key(namespace: &[u8; 32], period: u64, kind: u8, verifier: &[u8; 32]) -> Vec<u8> {
    let mut k = Vec::with_capacity(RECORD_KEY);
    k.extend_from_slice(namespace);
    k.extend_from_slice(&period.to_be_bytes());
    k.push(kind);
    k.extend_from_slice(verifier);
    k
}

fn use_key(r: &Registration) -> Vec<u8> {
    let mut k = Vec::with_capacity(USE_KEY);
    k.extend_from_slice(&r.namespace);
    k.extend_from_slice(&r.period.to_be_bytes());
    k.push(r.kind);
    k.extend_from_slice(&r.serial);
    k
}

fn be64(b: &[u8]) -> u64 {
    u64::from_be_bytes(b[..8].try_into().expect("8-byte field"))
}

/// Parses a `bearer_keys` value; `None` for a malformed one.
fn parse_record(period: u64, v: &[u8]) -> Option<BearerRecord> {
    if v.len() < RECORD_HEAD {
        return None;
    }
    let n = usize::from(v[16]);
    if n == 0 || n > MAX_SERIALS || v.len() != RECORD_HEAD + n * SERIAL_BYTES {
        return None;
    }
    Some(BearerRecord {
        period,
        valid_until: be64(&v[..8]),
        quota_bytes: be64(&v[8..16]),
        serials: v[RECORD_HEAD..].as_chunks::<SERIAL_BYTES>().0.to_vec(),
    })
}

fn encode_record(r: &BearerRecord) -> Vec<u8> {
    let mut v = Vec::with_capacity(RECORD_HEAD + r.serials.len() * SERIAL_BYTES);
    v.extend_from_slice(&r.valid_until.to_be_bytes());
    v.extend_from_slice(&r.quota_bytes.to_be_bytes());
    v.push(u8::try_from(r.serials.len()).expect("at most four serials"));
    for s in &r.serials {
        v.extend_from_slice(s);
    }
    v
}

fn begin_write(db: &Database) -> Result<WriteTransaction, StoreError> {
    let mut txn = db.begin_write()?;
    txn.set_durability(Durability::Immediate)
        .map_err(|e| StoreError::Db(e.into()))?;
    Ok(txn)
}

impl KeyStore {
    /// Opens `path`, creating an empty store when it does not exist. A file of another schema
    /// version, or one holding a table this schema does not define, is refused with
    /// [`StoreError::IncompatibleSchema`].
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        let db = Database::create(path)?;
        let txn = begin_write(&db)?;
        {
            let tables: Vec<String> = txn.list_tables()?.map(|t| t.name().to_string()).collect();
            if tables.iter().any(|t| !KEYS_TABLES.contains(&t.as_str())) {
                return Err(StoreError::IncompatibleSchema);
            }
            let mut meta = txn.open_table(META)?;
            let version = meta.get(SCHEMA_VERSION_KEY)?.map(|g| g.value());
            match version {
                Some(KEYS_SCHEMA_VERSION) => {}
                // A file with no table at all is a store whose creation never committed.
                None if tables.iter().all(|t| t == "meta") => {
                    meta.insert(SCHEMA_VERSION_KEY, KEYS_SCHEMA_VERSION)?;
                }
                _ => return Err(StoreError::IncompatibleSchema),
            }
            txn.open_table(BEARER_KEYS)?;
            txn.open_table(SERIAL_USE)?;
        }
        txn.commit()?;
        Ok(KeyStore { db })
    }

    /// Records `r` in one write transaction (design §4.4 point 4): the capability's serial is
    /// bound to `r.verifier` in `serial_use` unless it is already bound to another verifier
    /// ([`Registered::Conflict`], nothing written); the record is inserted, or credited with the
    /// serial and its quota when it names fewer than [`MAX_SERIALS`] capabilities and not this one.
    pub fn register(&self, r: &Registration) -> Result<Registered, StoreError> {
        let txn = begin_write(&self.db)?;
        let (outcome, wrote) = {
            let mut uses = txn.open_table(SERIAL_USE)?;
            let ukey = use_key(r);
            let bound = uses.get(ukey.as_slice())?.map(|g| g.value().to_vec());
            let mut wrote = false;
            match bound {
                Some(v) if v.len() == USE_VALUE && v[..32] == r.verifier => {}
                // Bound to another verifier (or unreadable): refused, fail closed.
                Some(_) => {
                    drop(uses);
                    txn.abort()?;
                    return Ok(Registered::Conflict);
                }
                None => {
                    let mut v = Vec::with_capacity(USE_VALUE);
                    v.extend_from_slice(&r.verifier);
                    v.extend_from_slice(&r.valid_until.to_be_bytes());
                    uses.insert(ukey.as_slice(), v.as_slice())?;
                    wrote = true;
                }
            }
            let mut records = txn.open_table(BEARER_KEYS)?;
            let rkey = record_key(&r.namespace, r.period, r.kind, &r.verifier);
            let existing = records.get(rkey.as_slice())?.map(|g| g.value().to_vec());
            let outcome = match existing {
                None => {
                    let record = BearerRecord {
                        period: r.period,
                        valid_until: r.valid_until,
                        quota_bytes: r.quota_bytes,
                        serials: vec![r.serial],
                    };
                    records.insert(rkey.as_slice(), encode_record(&record).as_slice())?;
                    wrote = true;
                    Registered::Inserted
                }
                Some(v) => {
                    let mut record =
                        parse_record(r.period, &v).ok_or(StoreError::IncompatibleSchema)?;
                    if record.serials.contains(&r.serial) || record.serials.len() >= MAX_SERIALS {
                        Registered::Unchanged
                    } else {
                        record.serials.push(r.serial);
                        record.quota_bytes = record.quota_bytes.saturating_add(r.quota_bytes);
                        records.insert(rkey.as_slice(), encode_record(&record).as_slice())?;
                        wrote = true;
                        Registered::Credited
                    }
                }
            };
            (outcome, wrote)
        };
        if wrote {
            txn.commit()?;
        } else {
            txn.abort()?;
        }
        Ok(outcome)
    }

    /// The record of `(namespace, period, kind, verifier)`, live or not (`None` when absent or
    /// malformed).
    pub fn record(
        &self,
        namespace: &[u8; 32],
        period: u64,
        kind: u8,
        verifier: &[u8; 32],
    ) -> Result<Option<BearerRecord>, StoreError> {
        let txn = self.db.begin_read()?;
        let records = txn.open_table(BEARER_KEYS)?;
        let key = record_key(namespace, period, kind, verifier);
        Ok(records
            .get(key.as_slice())?
            .and_then(|g| parse_record(period, g.value())))
    }

    /// The records of `(namespace, p, kind, verifier)` for every `p` in `periods` that are live at
    /// `now` (`now < valid_until`), earliest `valid_until` first. A malformed row authorizes
    /// nothing.
    pub fn live_records(
        &self,
        namespace: &[u8; 32],
        kind: u8,
        verifier: &[u8; 32],
        periods: RangeInclusive<u64>,
        now: u64,
    ) -> Result<Vec<BearerRecord>, StoreError> {
        let txn = self.db.begin_read()?;
        let records = txn.open_table(BEARER_KEYS)?;
        let mut out = Vec::new();
        for period in periods {
            let key = record_key(namespace, period, kind, verifier);
            if let Some(record) = records
                .get(key.as_slice())?
                .and_then(|g| parse_record(period, g.value()))
            {
                if now < record.valid_until {
                    out.push(record);
                }
            }
        }
        out.sort_by_key(|r| (r.valid_until, r.period));
        Ok(out)
    }

    /// One sweep at `now` (unix seconds): unless `now / 60` is below the persisted high-water
    /// minute, in one write transaction it raises the high-water minute and deletes every
    /// `bearer_keys` and `serial_use` row with `valid_until <= now`, and every malformed row.
    pub fn sweep(&self, now: u64) -> Result<KeySweep, StoreError> {
        let minute = now / 60;
        let txn = begin_write(&self.db)?;
        let report = {
            let mut meta = txn.open_table(META)?;
            let high_water = meta.get(SWEEP_HIGH_WATER)?.map(|g| g.value());
            if high_water.is_some_and(|h| minute < h) {
                None
            } else {
                meta.insert(SWEEP_HIGH_WATER, minute)?;
                let mut records = txn.open_table(BEARER_KEYS)?;
                let mut doomed: Vec<Vec<u8>> = Vec::new();
                for row in records.iter()? {
                    let (k, v) = row?;
                    let k = k.value();
                    let expired = k.len() != RECORD_KEY
                        || parse_record(be64(&k[32..40]), v.value())
                            .is_none_or(|r| r.valid_until <= now);
                    if expired {
                        doomed.push(k.to_vec());
                    }
                }
                for key in &doomed {
                    records.remove(key.as_slice())?;
                }
                let mut uses = txn.open_table(SERIAL_USE)?;
                let mut stale: Vec<Vec<u8>> = Vec::new();
                for row in uses.iter()? {
                    let (k, v) = row?;
                    let v = v.value();
                    if k.value().len() != USE_KEY || v.len() != USE_VALUE || be64(&v[32..40]) <= now
                    {
                        stale.push(k.value().to_vec());
                    }
                }
                for key in &stale {
                    uses.remove(key.as_slice())?;
                }
                Some(KeySweep {
                    ran: true,
                    records_removed: doomed.len(),
                    serials_removed: stale.len(),
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
                Ok(KeySweep::default())
            }
        }
    }

    /// The persisted sweep high-water minute.
    pub fn sweep_high_water_minute(&self) -> Result<Option<u64>, StoreError> {
        let txn = self.db.begin_read()?;
        let meta = txn.open_table(META)?;
        Ok(meta.get(SWEEP_HIGH_WATER)?.map(|g| g.value()))
    }

    /// Number of `bearer_keys` and `serial_use` rows.
    pub fn counts(&self) -> Result<(u64, u64), StoreError> {
        let txn = self.db.begin_read()?;
        Ok((
            txn.open_table(BEARER_KEYS)?.len()?,
            txn.open_table(SERIAL_USE)?.len()?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NS: [u8; 32] = [1; 32];
    const V: [u8; 32] = [7; 32];

    fn open(dir: &tempfile::TempDir) -> KeyStore {
        KeyStore::open(&dir.path().join("keys.redb")).unwrap()
    }

    fn reg(verifier: [u8; 32], serial: u8) -> Registration {
        Registration {
            namespace: NS,
            period: 2959,
            kind: 3,
            verifier,
            serial: [serial; SERIAL_BYTES],
            quota_bytes: 1_000,
            valid_until: 10_000,
        }
    }

    #[test]
    fn registrations_accumulate_and_never_replace() {
        let dir = tempfile::tempdir().unwrap();
        let store = open(&dir);
        assert_eq!(store.register(&reg(V, 1)).unwrap(), Registered::Inserted);
        assert_eq!(store.register(&reg(V, 1)).unwrap(), Registered::Unchanged);
        assert_eq!(store.register(&reg(V, 2)).unwrap(), Registered::Credited);
        let r = store.record(&NS, 2959, 3, &V).unwrap().unwrap();
        assert_eq!(
            (r.quota_bytes, r.serials.len(), r.valid_until),
            (2_000, 2, 10_000)
        );
        // A capability binds one verifier: the same serial for another verifier is refused and
        // writes nothing; another capability adds its own record.
        let other = [8u8; 32];
        assert_eq!(
            store.register(&reg(other, 1)).unwrap(),
            Registered::Conflict
        );
        assert_eq!(store.record(&NS, 2959, 3, &other).unwrap(), None);
        assert_eq!(store.counts().unwrap(), (1, 2));
        assert_eq!(
            store.register(&reg(other, 9)).unwrap(),
            Registered::Inserted
        );
        // The same serial may register the same verifier for another kind or period.
        let read = Registration {
            kind: 1,
            ..reg(other, 1)
        };
        assert_eq!(store.register(&read).unwrap(), Registered::Inserted);
        let next = Registration {
            period: 2960,
            ..reg(other, 1)
        };
        assert_eq!(store.register(&next).unwrap(), Registered::Inserted);
        // At most four credits; a fifth capability is bound but credits nothing.
        for serial in 3..=4 {
            assert_eq!(
                store.register(&reg(V, serial)).unwrap(),
                Registered::Credited
            );
        }
        assert_eq!(store.register(&reg(V, 5)).unwrap(), Registered::Unchanged);
        let r = store.record(&NS, 2959, 3, &V).unwrap().unwrap();
        assert_eq!((r.quota_bytes, r.serials.len()), (4_000, 4));
        assert_eq!(
            store.register(&reg(other, 5)).unwrap(),
            Registered::Conflict
        );
        // Everything survives a reopen.
        drop(store);
        let store = open(&dir);
        assert_eq!(
            store.record(&NS, 2959, 3, &V).unwrap().unwrap().quota_bytes,
            4_000
        );
        assert_eq!(store.counts().unwrap(), (4, 8));
    }

    #[test]
    fn live_records_and_the_sweep_follow_valid_until() {
        let dir = tempfile::tempdir().unwrap();
        let store = open(&dir);
        store.register(&reg(V, 1)).unwrap();
        store
            .register(&Registration {
                period: 2960,
                valid_until: 20_000,
                ..reg(V, 1)
            })
            .unwrap();
        let live = |now| {
            store
                .live_records(&NS, 3, &V, 2956..=2960, now)
                .unwrap()
                .iter()
                .map(|r| r.period)
                .collect::<Vec<_>>()
        };
        assert_eq!(live(9_999), vec![2959, 2960]);
        assert_eq!(live(10_000), vec![2960]);
        assert_eq!(live(20_000), Vec::<u64>::new());
        assert!(store
            .live_records(&NS, 1, &V, 2956..=2960, 0)
            .unwrap()
            .is_empty());
        assert_eq!(
            store.sweep(9_999).unwrap(),
            KeySweep {
                ran: true,
                records_removed: 0,
                serials_removed: 0
            }
        );
        assert_eq!(
            store.sweep(10_020).unwrap(),
            KeySweep {
                ran: true,
                records_removed: 1,
                serials_removed: 1
            }
        );
        // Below the high-water minute nothing runs, also after a reopen.
        assert!(!store.sweep(9_000).unwrap().ran);
        drop(store);
        let store = open(&dir);
        assert_eq!(store.sweep_high_water_minute().unwrap(), Some(167));
        assert!(!store.sweep(9_000).unwrap().ran);
        assert_eq!(store.counts().unwrap(), (1, 1));
        assert_eq!(store.sweep(20_000).unwrap().records_removed, 1);
        assert_eq!(store.counts().unwrap(), (0, 0));
    }

    #[test]
    fn files_of_another_schema_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let versioned = dir.path().join("v2.redb");
        {
            let db = Database::create(&versioned).unwrap();
            let txn = db.begin_write().unwrap();
            txn.open_table(META)
                .unwrap()
                .insert(SCHEMA_VERSION_KEY, 2)
                .unwrap();
            txn.commit().unwrap();
        }
        let blobs = dir.path().join("blobs.redb");
        drop(crate::BlobStore::open(&blobs).unwrap());
        let extra = dir.path().join("extra.redb");
        {
            let db = Database::create(&extra).unwrap();
            let txn = db.begin_write().unwrap();
            let t: TableDefinition<&[u8], &[u8]> = TableDefinition::new("verifier_history");
            txn.open_table(t)
                .unwrap()
                .insert(&[1u8][..], &[2u8][..])
                .unwrap();
            txn.commit().unwrap();
        }
        for file in [&versioned, &blobs, &extra] {
            assert!(
                matches!(KeyStore::open(file), Err(StoreError::IncompatibleSchema)),
                "{file:?}"
            );
        }
        // A fresh file, and an empty redb file whose creation never committed, open as stores.
        let empty = dir.path().join("empty.redb");
        drop(Database::create(&empty).unwrap());
        drop(KeyStore::open(&empty).unwrap());
        drop(KeyStore::open(&empty).unwrap());
    }

    #[test]
    fn a_malformed_row_authorizes_nothing_and_is_swept() {
        let dir = tempfile::tempdir().unwrap();
        let store = open(&dir);
        {
            let txn = store.db.begin_write().unwrap();
            let key = record_key(&NS, 2959, 3, &V);
            txn.open_table(BEARER_KEYS)
                .unwrap()
                .insert(key.as_slice(), &[0xFFu8; 20][..])
                .unwrap();
            txn.commit().unwrap();
        }
        assert!(store
            .live_records(&NS, 3, &V, 2959..=2959, 0)
            .unwrap()
            .is_empty());
        assert!(matches!(
            store.register(&reg(V, 1)),
            Err(StoreError::IncompatibleSchema)
        ));
        assert_eq!(
            store.counts().unwrap(),
            (1, 0),
            "the failed registration wrote nothing"
        );
        assert_eq!(store.sweep(0).unwrap().records_removed, 1);
        assert_eq!(store.register(&reg(V, 1)).unwrap(), Registered::Inserted);
    }
}
