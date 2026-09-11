//! Content-addressed blob store (FR-5.1, FR-5.2, FR-5.5) on an embedded, pure-Rust,
//! transactional key-value database (ADR-18: redb instead of RocksDB to keep the relay's
//! dependency graph fully visible to cargo-audit/cargo-deny and reproducible without a C++
//! toolchain).
//!
//! Model (schema version 2): the ciphertext is stored once per hash (reference counted), and every
//! namespace that holds it has its own *membership* with its own expiry and upload minute. A blob
//! is served to a caller only through a live membership in the caller's namespace, so:
//! - the same ciphertext stored in two namespaces is retrievable from both (a copy placed in
//!   another namespace first cannot block a legitimate replica write, ADR-11);
//! - a store over an expired-but-not-yet-pruned membership renews it, and a store with a longer
//!   TTL extends a live one, instead of confirming a blob that would disappear early.
//!
//! Every store that creates, renews or extends a membership must be admitted by the caller's
//! quota check *inside the same write transaction*: a store that is not admitted persists nothing.
//!
//! List cursors are per-namespace sequence numbers, so a reader learns nothing about writes to
//! other namespaces. A namespace's sequence row is deleted together with its last index entry, so
//! nothing about a namespace outlives its blobs; a namespace that comes back starts from an
//! hour-based seed above any sequence it used before, so old cursors never skip new entries.
//!
//! Expiries are rounded up to [`EXPIRY_GRANULARITY`] (one hour): the stored and returned expiry
//! never reveals the upload second (TTLs are bucketed, so `expiry - ttl` would), and a retry of
//! the same store within that granularity is an idempotent no-op, not a second charge.
//!
//! What the store knows about a blob: its SHA-256, its bucket-sized ciphertext, the opaque
//! namespaces holding it, an upload minute and an hour-rounded expiry per namespace.

use ghost_relay_api::{is_bucket_size, time_bucket, HASH_BYTES, MAX_BATCH};
use redb::{
    Database, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition, TableHandle,
    WriteTransaction,
};
use sha2::{Digest, Sha256};
use std::path::Path;

/// On-disk schema version. A database written by another version is refused, never reinterpreted.
pub const SCHEMA_VERSION: u64 = 2;

/// hash(32) -> refcount(8) || data
const CONTENT: TableDefinition<&[u8], &[u8]> = TableDefinition::new("content");
/// namespace(32) || hash(32) -> expiry(8) || uploaded_minute(8) || seq(8)
const MEMBERS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("members");
/// namespace(32) || seq(8) -> hash(32)
const NAMESPACE_INDEX: TableDefinition<&[u8], &[u8]> = TableDefinition::new("namespace_index");
/// expiry(8) || namespace(32) || hash(32) -> ()
const EXPIRY_INDEX: TableDefinition<&[u8], ()> = TableDefinition::new("expiry_index_v2");
/// namespace(32) -> next per-namespace sequence number
const NS_SEQ: TableDefinition<&[u8], u64> = TableDefinition::new("namespace_seq");
/// "schema_version" -> SCHEMA_VERSION
const META: TableDefinition<&str, u64> = TableDefinition::new("meta");

/// Tables of the schema-1 (Phase 5) layout; their presence means an incompatible database.
const LEGACY_TABLES: [&str; 2] = ["blobs", "expiry_index"];

/// Granularity of stored expiries, in seconds (see the module docs).
pub const EXPIRY_GRANULARITY: u64 = 3_600;

/// Rounds an expiry up to [`EXPIRY_GRANULARITY`].
fn quantize_expiry(t: u64) -> u64 {
    t.div_ceil(EXPIRY_GRANULARITY)
        .saturating_mul(EXPIRY_GRANULARITY)
}

/// First sequence number of a namespace that has no sequence row: hours since the epoch, shifted
/// so a namespace that emptied (its last membership expired, at least one TTL bucket after its
/// last write) and comes back always starts above every sequence it used before.
fn seq_seed(now_unix: u64) -> u64 {
    (now_unix / 3_600) << 32
}

/// Upper bound on index entries examined by one `list` call, so expired entries awaiting prune
/// cannot turn a listing into an unbounded scan.
const MAX_LIST_SCAN: usize = 4 * MAX_BATCH;

const MEMBER_KEY: usize = 64;
const EXPIRY_KEY: usize = 72;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("blob length is not a padding bucket")]
    NotBucketSized,
    #[error("blob hash does not match content")]
    HashMismatch,
    #[error("identifier has wrong length")]
    BadIdentifier,
    #[error("batch too large")]
    BatchTooLarge,
    #[error("store not admitted by quota")]
    QuotaDenied,
    #[error("database was written by an incompatible schema version")]
    IncompatibleSchema,
    #[error("database error")]
    Db(#[from] redb::Error),
}

impl From<redb::DatabaseError> for StoreError {
    fn from(e: redb::DatabaseError) -> Self {
        StoreError::Db(e.into())
    }
}
impl From<redb::TransactionError> for StoreError {
    fn from(e: redb::TransactionError) -> Self {
        StoreError::Db(e.into())
    }
}
impl From<redb::TableError> for StoreError {
    fn from(e: redb::TableError) -> Self {
        StoreError::Db(e.into())
    }
}
impl From<redb::StorageError> for StoreError {
    fn from(e: redb::StorageError) -> Self {
        StoreError::Db(e.into())
    }
}
impl From<redb::CommitError> for StoreError {
    fn from(e: redb::CommitError) -> Self {
        StoreError::Db(e.into())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredBlob {
    pub data: Vec<u8>,
    pub uploaded_minute: u64,
    pub expiry_unix: u64,
    pub namespace: [u8; 32],
}

/// Result of [`BlobStore::put`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PutOutcome {
    pub hash: [u8; 32],
    /// Expiry of the membership after the call.
    pub expiry: u64,
    /// True if the membership was created, renewed or extended (the quota admission ran and
    /// accepted); false if an existing live membership already covered the request.
    pub changed: bool,
}

pub struct BlobStore {
    db: Database,
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let d = Sha256::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&d);
    out
}

fn be64(b: &[u8]) -> u64 {
    u64::from_be_bytes(b[..8].try_into().expect("8-byte field"))
}

fn member_key(namespace: &[u8], hash: &[u8]) -> Vec<u8> {
    let mut k = Vec::with_capacity(MEMBER_KEY);
    k.extend_from_slice(namespace);
    k.extend_from_slice(hash);
    k
}

fn ns_index_key(namespace: &[u8], seq: u64) -> Vec<u8> {
    let mut k = Vec::with_capacity(40);
    k.extend_from_slice(namespace);
    k.extend_from_slice(&seq.to_be_bytes());
    k
}

fn expiry_key(expiry: u64, namespace: &[u8], hash: &[u8]) -> Vec<u8> {
    let mut k = Vec::with_capacity(EXPIRY_KEY);
    k.extend_from_slice(&expiry.to_be_bytes());
    k.extend_from_slice(namespace);
    k.extend_from_slice(hash);
    k
}

struct Membership {
    expiry: u64,
    uploaded_minute: u64,
    seq: u64,
}

fn read_membership(
    txn: &WriteTransaction,
    namespace: &[u8],
    hash: &[u8],
) -> Result<Option<Membership>, StoreError> {
    let members = txn.open_table(MEMBERS)?;
    let v = members.get(member_key(namespace, hash).as_slice())?;
    Ok(v.map(|g| {
        let v = g.value();
        Membership {
            expiry: be64(&v[..8]),
            uploaded_minute: be64(&v[8..16]),
            seq: be64(&v[16..24]),
        }
    }))
}

fn write_membership(
    txn: &WriteTransaction,
    namespace: &[u8],
    hash: &[u8],
    m: &Membership,
) -> Result<(), StoreError> {
    let mut v = Vec::with_capacity(24);
    v.extend_from_slice(&m.expiry.to_be_bytes());
    v.extend_from_slice(&m.uploaded_minute.to_be_bytes());
    v.extend_from_slice(&m.seq.to_be_bytes());
    txn.open_table(MEMBERS)?
        .insert(member_key(namespace, hash).as_slice(), v.as_slice())?;
    txn.open_table(EXPIRY_INDEX)?
        .insert(expiry_key(m.expiry, namespace, hash).as_slice(), ())?;
    Ok(())
}

/// Removes one membership and its index entries, and drops the content when no membership is
/// left. Must run inside the caller's write transaction.
fn remove_membership(
    txn: &WriteTransaction,
    namespace: &[u8],
    hash: &[u8],
) -> Result<bool, StoreError> {
    let Some(m) = read_membership(txn, namespace, hash)? else {
        return Ok(false);
    };
    txn.open_table(MEMBERS)?
        .remove(member_key(namespace, hash).as_slice())?;
    let namespace_empty = {
        let mut index = txn.open_table(NAMESPACE_INDEX)?;
        index.remove(ns_index_key(namespace, m.seq).as_slice())?;
        let lo = ns_index_key(namespace, 0);
        let hi = ns_index_key(namespace, u64::MAX);
        let empty = index
            .range::<&[u8]>(lo.as_slice()..=hi.as_slice())?
            .next()
            .is_none();
        empty
    };
    if namespace_empty {
        // Nothing of the namespace is left: forget its sequence row too.
        txn.open_table(NS_SEQ)?.remove(namespace)?;
    }
    txn.open_table(EXPIRY_INDEX)?
        .remove(expiry_key(m.expiry, namespace, hash).as_slice())?;
    let mut content = txn.open_table(CONTENT)?;
    let current: Option<Vec<u8>> = content.get(hash)?.map(|g| g.value().to_vec());
    if let Some(mut value) = current {
        let refs = be64(&value).saturating_sub(1);
        if refs == 0 {
            content.remove(hash)?;
        } else {
            value[..8].copy_from_slice(&refs.to_be_bytes());
            content.insert(hash, value.as_slice())?;
        }
    }
    Ok(true)
}

fn next_seq(txn: &WriteTransaction, namespace: &[u8], now_unix: u64) -> Result<u64, StoreError> {
    let mut seqs = txn.open_table(NS_SEQ)?;
    let seq = seqs
        .get(namespace)?
        .map(|g| g.value())
        .unwrap_or_else(|| seq_seed(now_unix));
    seqs.insert(namespace, seq.saturating_add(1))?;
    Ok(seq)
}

impl BlobStore {
    /// Opens or creates the store. A database written by the schema-1 layout (Phase 5) or by any
    /// other schema version is refused with [`StoreError::IncompatibleSchema`]: its keys have a
    /// different shape and must never be reinterpreted.
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        let db = Database::create(path)?;
        let txn = db.begin_write()?;
        {
            let legacy = txn
                .list_tables()?
                .any(|t| LEGACY_TABLES.contains(&t.name()));
            let mut meta = txn.open_table(META)?;
            let version = meta.get("schema_version")?.map(|g| g.value());
            match version {
                Some(SCHEMA_VERSION) if !legacy => {}
                None if !legacy => {
                    meta.insert("schema_version", SCHEMA_VERSION)?;
                }
                _ => return Err(StoreError::IncompatibleSchema),
            }
            txn.open_table(CONTENT)?;
            txn.open_table(MEMBERS)?;
            txn.open_table(NAMESPACE_INDEX)?;
            txn.open_table(EXPIRY_INDEX)?;
            txn.open_table(NS_SEQ)?;
        }
        txn.commit()?;
        Ok(BlobStore { db })
    }

    /// Stores a blob in `namespace`. Recomputes and compares the hash (FR-5.2) and requires a
    /// bucket-sized body. The wanted expiry is `now + ttl` rounded up to the hour. Per
    /// (namespace, hash):
    /// - no membership, or an expired one: a fresh membership is created (renewal);
    /// - a live membership that reaches the wanted expiry within one granularity step: nothing
    ///   changes (idempotent retry, no charge);
    /// - a live membership that expires earlier: its expiry is extended.
    ///
    /// Whenever something would change, `admit` is called first, inside the write transaction;
    /// if it returns false nothing is persisted and [`StoreError::QuotaDenied`] is returned.
    pub fn put(
        &self,
        claimed_hash: &[u8],
        data: &[u8],
        namespace: &[u8; 32],
        ttl_seconds: u64,
        now_unix: u64,
        admit: &mut dyn FnMut() -> bool,
    ) -> Result<PutOutcome, StoreError> {
        if claimed_hash.len() != HASH_BYTES {
            return Err(StoreError::BadIdentifier);
        }
        if !is_bucket_size(data.len()) {
            return Err(StoreError::NotBucketSized);
        }
        let hash = sha256(data);
        if hash[..] != claimed_hash[..] {
            return Err(StoreError::HashMismatch);
        }
        let wanted_expiry = quantize_expiry(now_unix.saturating_add(ttl_seconds));
        let txn = self.db.begin_write()?;
        let existing = read_membership(&txn, namespace, &hash)?;
        if let Some(m) = &existing {
            if m.expiry > now_unix && m.expiry.saturating_add(EXPIRY_GRANULARITY) >= wanted_expiry {
                drop(txn);
                return Ok(PutOutcome {
                    hash,
                    expiry: m.expiry,
                    changed: false,
                });
            }
        }
        if !admit() {
            drop(txn); // aborts: nothing written
            return Err(StoreError::QuotaDenied);
        }
        match existing {
            Some(m) if m.expiry > now_unix => {
                // Live but too short: extend in place (same seq, same upload minute).
                txn.open_table(EXPIRY_INDEX)?
                    .remove(expiry_key(m.expiry, namespace, &hash).as_slice())?;
                write_membership(
                    &txn,
                    namespace,
                    &hash,
                    &Membership {
                        expiry: wanted_expiry,
                        ..m
                    },
                )?;
            }
            other => {
                if other.is_some() {
                    // Expired but not yet pruned: drop it, then store a fresh membership.
                    remove_membership(&txn, namespace, &hash)?;
                }
                {
                    let mut content = txn.open_table(CONTENT)?;
                    let current: Option<Vec<u8>> =
                        content.get(&hash[..])?.map(|g| g.value().to_vec());
                    let value = match current {
                        Some(mut v) => {
                            let refs = be64(&v).saturating_add(1);
                            v[..8].copy_from_slice(&refs.to_be_bytes());
                            v
                        }
                        None => {
                            let mut v = Vec::with_capacity(8 + data.len());
                            v.extend_from_slice(&1u64.to_be_bytes());
                            v.extend_from_slice(data);
                            v
                        }
                    };
                    content.insert(&hash[..], value.as_slice())?;
                }
                let seq = next_seq(&txn, namespace, now_unix)?;
                write_membership(
                    &txn,
                    namespace,
                    &hash,
                    &Membership {
                        expiry: wanted_expiry,
                        uploaded_minute: time_bucket(now_unix),
                        seq,
                    },
                )?;
                txn.open_table(NAMESPACE_INDEX)?
                    .insert(ns_index_key(namespace, seq).as_slice(), &hash[..])?;
            }
        }
        txn.commit()?;
        Ok(PutOutcome {
            hash,
            expiry: wanted_expiry,
            changed: true,
        })
    }

    /// Returns the blob if `namespace` holds a live membership for it. A blob that exists only in
    /// other namespaces is indistinguishable from an absent one.
    pub fn get(
        &self,
        hash: &[u8],
        namespace: &[u8; 32],
        now_unix: u64,
    ) -> Result<Option<StoredBlob>, StoreError> {
        if hash.len() != HASH_BYTES {
            return Err(StoreError::BadIdentifier);
        }
        let txn = self.db.begin_read()?;
        let members = txn.open_table(MEMBERS)?;
        let Some(m) = members.get(member_key(namespace, hash).as_slice())? else {
            return Ok(None);
        };
        let (expiry, uploaded_minute) = (be64(&m.value()[..8]), be64(&m.value()[8..16]));
        if expiry <= now_unix {
            return Ok(None); // expired but not yet pruned: never served
        }
        let content = txn.open_table(CONTENT)?;
        let Some(c) = content.get(hash)? else {
            return Ok(None);
        };
        Ok(Some(StoredBlob {
            data: c.value()[8..].to_vec(),
            uploaded_minute,
            expiry_unix: expiry,
            namespace: *namespace,
        }))
    }

    /// True if the ciphertext is held under any namespace (relay-to-relay inventory, FR-5.6; the
    /// gossip boundary carries hashes only, TB-3).
    pub fn has_content(&self, hash: &[u8]) -> Result<bool, StoreError> {
        if hash.len() != HASH_BYTES {
            return Err(StoreError::BadIdentifier);
        }
        let txn = self.db.begin_read()?;
        Ok(txn.open_table(CONTENT)?.get(hash)?.is_some())
    }

    /// Returns the subset of `hashes` with a live membership in `namespace`; never reveals blobs
    /// outside the caller's namespace (FR-5.3 "no enumeration outside capability scope").
    pub fn check(
        &self,
        hashes: &[Vec<u8>],
        namespace: &[u8; 32],
        now_unix: u64,
    ) -> Result<Vec<Vec<u8>>, StoreError> {
        if hashes.len() > MAX_BATCH {
            return Err(StoreError::BatchTooLarge);
        }
        let mut out = Vec::new();
        for h in hashes {
            if self.get(h, namespace, now_unix)?.is_some() {
                out.push(h.clone());
            }
        }
        Ok(out)
    }

    /// Lists live blob hashes of a namespace in insertion order after `cursor` (an opaque 8-byte
    /// per-namespace sequence; empty = from the beginning). Returns `(hashes, next_cursor)`.
    /// `next_cursor` is empty when the namespace is exhausted; a non-empty cursor may come with
    /// fewer than `limit` hashes when expired entries awaiting prune were skipped.
    pub fn list(
        &self,
        namespace: &[u8; 32],
        cursor: &[u8],
        limit: usize,
        now_unix: u64,
    ) -> Result<(Vec<[u8; 32]>, Vec<u8>), StoreError> {
        if limit == 0 || limit > MAX_BATCH {
            return Err(StoreError::BatchTooLarge);
        }
        let start_seq = match cursor.len() {
            0 => 0u64,
            8 => be64(cursor).saturating_add(1),
            _ => return Err(StoreError::BadIdentifier),
        };
        let lo = ns_index_key(namespace, start_seq);
        let hi = ns_index_key(namespace, u64::MAX);

        let txn = self.db.begin_read()?;
        let index = txn.open_table(NAMESPACE_INDEX)?;
        let members = txn.open_table(MEMBERS)?;
        let mut hashes = Vec::new();
        let mut last_seq: Option<u64> = None;
        let mut exhausted = true;
        for (scanned, entry) in index
            .range::<&[u8]>(lo.as_slice()..=hi.as_slice())?
            .enumerate()
        {
            if hashes.len() == limit || scanned == MAX_LIST_SCAN {
                exhausted = false;
                break;
            }
            let (k, v) = entry?;
            last_seq = Some(be64(&k.value()[32..40]));
            let live = members
                .get(member_key(namespace, v.value()).as_slice())?
                .map(|m| be64(m.value()) > now_unix)
                .unwrap_or(false);
            if live {
                let mut h = [0u8; 32];
                h.copy_from_slice(v.value());
                hashes.push(h);
            }
        }
        let next = if exhausted {
            Vec::new()
        } else {
            last_seq
                .map(|s| s.to_be_bytes().to_vec())
                .unwrap_or_default()
        };
        Ok((hashes, next))
    }

    /// Removes every membership whose expiry is `<= now`, and the ciphertext once no namespace
    /// holds it. Returns the number of memberships removed (FR-5.5 prune). Malformed index keys
    /// are dropped instead of aborting the sweep.
    pub fn prune_expired(&self, now_unix: u64) -> Result<usize, StoreError> {
        let txn = self.db.begin_write()?;
        let doomed: Vec<Vec<u8>> = {
            let expiry = txn.open_table(EXPIRY_INDEX)?;
            let mut bound = Vec::with_capacity(EXPIRY_KEY);
            bound.extend_from_slice(&now_unix.to_be_bytes());
            bound.extend_from_slice(&[0xff; 64]);
            let keys: Result<Vec<Vec<u8>>, redb::StorageError> = expiry
                .range::<&[u8]>(..=bound.as_slice())?
                .map(|e| e.map(|(k, _)| k.value().to_vec()))
                .collect();
            keys?
        };
        let mut removed = 0usize;
        for key in doomed {
            if key.len() == EXPIRY_KEY && remove_membership(&txn, &key[8..40], &key[40..72])? {
                removed += 1;
            } else {
                // Orphaned or malformed index entry: drop it so prune always converges.
                txn.open_table(EXPIRY_INDEX)?.remove(key.as_slice())?;
            }
        }
        txn.commit()?;
        Ok(removed)
    }

    /// Number of distinct ciphertexts held.
    pub fn count(&self) -> Result<u64, StoreError> {
        let txn = self.db.begin_read()?;
        Ok(txn.open_table(CONTENT)?.len()?)
    }

    /// Number of (namespace, blob) memberships held.
    pub fn membership_count(&self) -> Result<u64, StoreError> {
        let txn = self.db.begin_read()?;
        Ok(txn.open_table(MEMBERS)?.len()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const H: u64 = EXPIRY_GRANULARITY;
    const DAY: u64 = 86_400;
    /// A "now" in the middle of an hour, so rounding is visible.
    const T0: u64 = 1_000 * H + 1_234;

    fn store() -> (BlobStore, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        (
            BlobStore::open(&dir.path().join("relay.redb")).unwrap(),
            dir,
        )
    }

    fn blob(seed: u8, len: usize) -> (Vec<u8>, [u8; 32]) {
        let data = vec![seed; len];
        let h = sha256(&data);
        (data, h)
    }

    fn put(
        s: &BlobStore,
        h: &[u8],
        d: &[u8],
        ns: &[u8; 32],
        ttl: u64,
        now: u64,
    ) -> Result<PutOutcome, StoreError> {
        s.put(h, d, ns, ttl, now, &mut || true)
    }

    fn ns_seq_rows(s: &BlobStore) -> u64 {
        let txn = s.db.begin_read().unwrap();
        txn.open_table(NS_SEQ).unwrap().len().unwrap()
    }

    #[test]
    fn expiry_is_rounded_up_to_the_hour() {
        assert_eq!(quantize_expiry(0), 0);
        assert_eq!(quantize_expiry(1), H);
        assert_eq!(quantize_expiry(H), H);
        assert_eq!(quantize_expiry(H + 1), 2 * H);
        assert_eq!(quantize_expiry(u64::MAX), u64::MAX); // saturates, never panics or wraps
    }

    #[test]
    fn put_get_idempotent_and_hash_checked() {
        let (s, _d) = store();
        let ns = [1u8; 32];
        let (data, h) = blob(7, 1024);
        let o = put(&s, &h, &data, &ns, 7 * DAY, T0).unwrap();
        let expiry = quantize_expiry(T0 + 7 * DAY);
        assert_eq!((o.hash, o.expiry, o.changed), (h, expiry, true));
        assert_eq!(
            expiry % H,
            0,
            "the upload second is not recoverable from the expiry"
        );
        // The same store retried later (lost response) within the granularity: no change, no charge.
        for later in [T0 + 1, T0 + H - 1, T0 + H + 5] {
            let mut called = false;
            let o2 = s
                .put(&h, &data, &ns, 7 * DAY, later, &mut || {
                    called = true;
                    true
                })
                .unwrap();
            assert_eq!((o2.expiry, o2.changed, called), (expiry, false, false));
        }
        let got = s.get(&h, &ns, T0 + 10).unwrap().unwrap();
        assert_eq!(got.data, data);
        assert_eq!(got.uploaded_minute % 60, 0);
        assert_eq!(got.namespace, ns);
        assert!(matches!(
            put(&s, &[0u8; 32], &data, &ns, 1, 1),
            Err(StoreError::HashMismatch)
        ));
        assert!(matches!(
            put(&s, &h, &data[..1000], &ns, 1, 1),
            Err(StoreError::NotBucketSized)
        ));
        assert!(matches!(
            put(&s, &h[..5], &data, &ns, 1, 1),
            Err(StoreError::BadIdentifier)
        ));
    }

    #[test]
    fn a_store_that_is_not_admitted_persists_nothing() {
        let (s, _d) = store();
        let ns = [5u8; 32];
        let (data, h) = blob(1, 4096);
        assert!(matches!(
            s.put(&h, &data, &ns, DAY, T0, &mut || false),
            Err(StoreError::QuotaDenied)
        ));
        assert!(s.get(&h, &ns, T0 + 1).unwrap().is_none());
        assert_eq!(s.count().unwrap(), 0);
        assert_eq!(s.membership_count().unwrap(), 0);
        assert_eq!(ns_seq_rows(&s), 0);
        assert!(s.list(&ns, &[], 10, T0 + 1).unwrap().0.is_empty());
        // A retry is not "idempotent success": it must be admitted again.
        assert!(matches!(
            s.put(&h, &data, &ns, DAY, T0 + 2, &mut || false),
            Err(StoreError::QuotaDenied)
        ));
    }

    #[test]
    fn a_longer_ttl_extends_a_live_membership_and_is_admitted() {
        let (s, _d) = store();
        let ns = [6u8; 32];
        let (data, h) = blob(2, 1024);
        let first = put(&s, &h, &data, &ns, DAY, T0).unwrap();
        let mut admitted = 0;
        let o = s
            .put(&h, &data, &ns, 30 * DAY, T0 + 10, &mut || {
                admitted += 1;
                true
            })
            .unwrap();
        assert!(o.changed);
        assert_eq!(admitted, 1);
        assert_eq!(o.expiry, quantize_expiry(T0 + 10 + 30 * DAY));
        assert_eq!(
            s.get(&h, &ns, T0 + 20).unwrap().unwrap().expiry_unix,
            o.expiry
        );
        // The old expiry entry is gone: pruning at the old expiry removes nothing.
        assert_eq!(s.prune_expired(first.expiry).unwrap(), 0);
        assert_eq!(s.list(&ns, &[], 10, first.expiry).unwrap().0, vec![h]);
    }

    #[test]
    fn same_ciphertext_in_two_namespaces_is_served_from_both() {
        let (s, _d) = store();
        let (a_ns, b_ns) = ([1u8; 32], [2u8; 32]);
        let (data, h) = blob(9, 4096);
        let b = put(&s, &h, &data, &b_ns, DAY, T0).unwrap();
        let a = put(&s, &h, &data, &a_ns, 7 * DAY, T0 + 10).unwrap();
        assert!(a.changed);
        assert_eq!(a.expiry, quantize_expiry(T0 + 10 + 7 * DAY));
        assert_eq!(
            s.get(&h, &a_ns, T0 + 20).unwrap().unwrap().expiry_unix,
            a.expiry
        );
        assert_eq!(
            s.get(&h, &b_ns, T0 + 20).unwrap().unwrap().expiry_unix,
            b.expiry
        );
        assert_eq!(s.count().unwrap(), 1, "ciphertext stored once");
        assert_eq!(s.membership_count().unwrap(), 2);
        assert_eq!(s.prune_expired(b.expiry).unwrap(), 1);
        assert!(s.get(&h, &b_ns, b.expiry + 1).unwrap().is_none());
        assert!(s.get(&h, &a_ns, b.expiry + 1).unwrap().is_some());
        assert_eq!(s.count().unwrap(), 1);
        assert_eq!(s.prune_expired(a.expiry).unwrap(), 1);
        assert_eq!(
            s.count().unwrap(),
            0,
            "content dropped with the last membership"
        );
        assert!(!s.has_content(&h).unwrap());
    }

    #[test]
    fn expired_membership_is_renewed_not_confirmed() {
        let (s, _d) = store();
        let ns = [3u8; 32];
        let (data, h) = blob(4, 1024);
        let first = put(&s, &h, &data, &ns, 100, T0).unwrap(); // expires at the next hour
        let o = put(&s, &h, &data, &ns, DAY, first.expiry).unwrap();
        assert!(o.changed);
        assert_eq!(o.expiry, quantize_expiry(first.expiry + DAY));
        assert!(s.get(&h, &ns, first.expiry + 1).unwrap().is_some());
        assert_eq!(s.membership_count().unwrap(), 1);
        let (listed, _) = s.list(&ns, &[], 10, first.expiry + 1).unwrap();
        assert_eq!(listed, vec![h], "old index entry replaced, not duplicated");
        assert_eq!(s.prune_expired(first.expiry).unwrap(), 0);
    }

    #[test]
    fn expired_blobs_are_never_served_or_listed_and_prune_removes_them() {
        let (s, _d) = store();
        let ns = [2u8; 32];
        let (a, ha) = blob(1, 1024);
        let (b, hb) = blob(2, 1024);
        let ea = put(&s, &ha, &a, &ns, 100, T0).unwrap().expiry;
        put(&s, &hb, &b, &ns, DAY, T0).unwrap();
        assert!(s.get(&ha, &ns, ea).unwrap().is_none());
        assert!(s.get(&hb, &ns, ea).unwrap().is_some());
        assert_eq!(s.list(&ns, &[], 10, ea).unwrap().0, vec![hb]);
        assert_eq!(s.prune_expired(ea).unwrap(), 1);
        assert_eq!(s.count().unwrap(), 1);
        assert_eq!(s.list(&ns, &[], 10, ea).unwrap().0, vec![hb]);
        assert_eq!(s.prune_expired(ea).unwrap(), 0);
    }

    #[test]
    fn nothing_about_a_namespace_outlives_its_blobs() {
        let (s, _d) = store();
        let ns = [7u8; 32];
        let (data, h) = blob(3, 1024);
        let e = put(&s, &h, &data, &ns, DAY, T0).unwrap().expiry;
        let (_, cursor) = s.list(&ns, &[], 1, T0 + 1).unwrap();
        assert!(cursor.is_empty());
        let old_seq = {
            let (d2, h2) = blob(4, 1024);
            put(&s, &h2, &d2, &ns, DAY, T0 + 1).unwrap();
            let (page, c) = s.list(&ns, &[], 1, T0 + 2).unwrap();
            assert_eq!(page, vec![h]);
            c // cursor after the first entry, held by a client
        };
        assert_eq!(ns_seq_rows(&s), 1);
        assert_eq!(s.prune_expired(e + H).unwrap(), 2);
        assert_eq!(
            ns_seq_rows(&s),
            0,
            "the sequence row goes with the last membership"
        );
        assert_eq!(s.membership_count().unwrap(), 0);
        // The namespace comes back later: an old cursor must still see the new entry.
        let (d3, h3) = blob(5, 1024);
        put(&s, &h3, &d3, &ns, DAY, e + 2 * H).unwrap();
        let (page, _) = s.list(&ns, &old_seq, 10, e + 2 * H + 1).unwrap();
        assert_eq!(page, vec![h3]);
    }

    #[test]
    fn list_pages_with_per_namespace_cursor() {
        let (s, _d) = store();
        let ns = [3u8; 32];
        let other = [4u8; 32];
        let mut expected = Vec::new();
        for i in 0..5u8 {
            // Interleave writes to another namespace: they must not show up in ns's cursors.
            let (od, oh) = blob(200 + i, 1024);
            put(&s, &oh, &od, &other, DAY, T0).unwrap();
            let (d, h) = blob(10 + i, 1024);
            put(&s, &h, &d, &ns, DAY, T0).unwrap();
            expected.push(h);
        }
        let (p1, c1) = s.list(&ns, &[], 2, T0).unwrap();
        assert_eq!(p1, expected[..2]);
        assert_eq!(
            c1,
            (seq_seed(T0) + 1).to_be_bytes().to_vec(),
            "cursor counts only this namespace"
        );
        let (p2, c2) = s.list(&ns, &c1, 2, T0).unwrap();
        assert_eq!(p2, expected[2..4]);
        let (p3, c3) = s.list(&ns, &c2, 2, T0).unwrap();
        assert_eq!(p3, expected[4..]);
        assert!(c3.is_empty());
        assert!(matches!(
            s.list(&ns, &[1, 2, 3], 2, T0),
            Err(StoreError::BadIdentifier)
        ));
        assert!(matches!(
            s.list(&ns, &[], MAX_BATCH + 1, T0),
            Err(StoreError::BatchTooLarge)
        ));
        assert!(
            s.list(&ns, &u64::MAX.to_be_bytes(), 2, T0)
                .unwrap()
                .0
                .is_empty(),
            "cursor at u64::MAX must not overflow"
        );
    }

    #[test]
    fn check_never_reveals_other_namespaces() {
        let (s, _d) = store();
        let (d, h) = blob(5, 4096);
        put(&s, &h, &d, &[9u8; 32], DAY, T0).unwrap();
        assert_eq!(
            s.check(&[h.to_vec()], &[9u8; 32], T0).unwrap(),
            vec![h.to_vec()]
        );
        assert!(s.check(&[h.to_vec()], &[8u8; 32], T0).unwrap().is_empty());
        assert!(s.get(&h, &[8u8; 32], T0).unwrap().is_none());
        let too_many = vec![h.to_vec(); MAX_BATCH + 1];
        assert!(matches!(
            s.check(&too_many, &[9u8; 32], T0),
            Err(StoreError::BatchTooLarge)
        ));
    }

    #[test]
    fn a_phase5_database_is_refused_not_reinterpreted() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("old.redb");
        {
            // Minimal schema-1 layout: a `blobs` table and 40-byte expiry keys.
            let db = Database::create(&path).unwrap();
            let txn = db.begin_write().unwrap();
            {
                let old: TableDefinition<&[u8], &[u8]> = TableDefinition::new("blobs");
                txn.open_table(old)
                    .unwrap()
                    .insert(&[1u8; 32][..], &[0u8; 8][..])
                    .unwrap();
                let old_exp: TableDefinition<&[u8], ()> = TableDefinition::new("expiry_index");
                txn.open_table(old_exp)
                    .unwrap()
                    .insert(&[0u8; 40][..], ())
                    .unwrap();
            }
            txn.commit().unwrap();
        }
        assert!(matches!(
            BlobStore::open(&path),
            Err(StoreError::IncompatibleSchema)
        ));
        // A fresh database opens, and reopens, fine.
        let fresh = dir.path().join("new.redb");
        drop(BlobStore::open(&fresh).unwrap());
        BlobStore::open(&fresh).unwrap();
    }
}
