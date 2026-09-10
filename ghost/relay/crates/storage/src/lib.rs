//! Content-addressed blob store (FR-5.1, FR-5.2, FR-5.5) on an embedded, pure-Rust,
//! transactional key-value database (ADR-18: redb instead of RocksDB to keep the relay's
//! dependency graph fully visible to cargo-audit/cargo-deny and reproducible without a C++
//! toolchain).
//!
//! What the store knows about a blob: its SHA-256, its bucket-sized ciphertext, the opaque
//! namespace it was filed under, an upload minute and an expiry. Nothing else exists to leak.

use ghost_relay_api::{is_bucket_size, time_bucket, HASH_BYTES, MAX_BATCH};
use redb::{Database, ReadableDatabase, ReadableTable, ReadableTableMetadata, TableDefinition};
use sha2::{Digest, Sha256};
use std::path::Path;

/// hash(32) -> expiry(8) || uploaded_minute(8) || namespace(32) || data
const BLOBS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("blobs");
/// namespace(32) || seq(8) -> hash(32)
const NAMESPACE_INDEX: TableDefinition<&[u8], &[u8]> = TableDefinition::new("namespace_index");
/// expiry(8) || hash(32) -> ()
const EXPIRY_INDEX: TableDefinition<&[u8], ()> = TableDefinition::new("expiry_index");
/// "seq" -> next sequence number
const META: TableDefinition<&str, u64> = TableDefinition::new("meta");

const HEADER: usize = 8 + 8 + HASH_BYTES;

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

pub struct BlobStore {
    db: Database,
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let d = Sha256::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&d);
    out
}

impl BlobStore {
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        let db = Database::create(path)?;
        let txn = db.begin_write()?;
        {
            txn.open_table(BLOBS)?;
            txn.open_table(NAMESPACE_INDEX)?;
            txn.open_table(EXPIRY_INDEX)?;
            txn.open_table(META)?;
        }
        txn.commit()?;
        Ok(BlobStore { db })
    }

    /// Stores a blob. Recomputes and compares the hash (FR-5.2), requires a bucket-sized body,
    /// and is idempotent: an existing hash is left untouched (its original expiry stands).
    /// Returns `(stored_hash, expiry, newly_inserted)`.
    pub fn put(
        &self,
        claimed_hash: &[u8],
        data: &[u8],
        namespace: &[u8; 32],
        ttl_seconds: u64,
        now_unix: u64,
    ) -> Result<([u8; 32], u64, bool), StoreError> {
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
        let txn = self.db.begin_write()?;
        let (expiry, inserted) = {
            let mut blobs = txn.open_table(BLOBS)?;
            let existing_expiry: Option<u64> = blobs
                .get(&hash[..])?
                .map(|g| u64::from_be_bytes(g.value()[..8].try_into().unwrap()));
            if let Some(expiry) = existing_expiry {
                (expiry, false)
            } else {
                let expiry = now_unix.saturating_add(ttl_seconds);
                let mut value = Vec::with_capacity(HEADER + data.len());
                value.extend_from_slice(&expiry.to_be_bytes());
                value.extend_from_slice(&time_bucket(now_unix).to_be_bytes());
                value.extend_from_slice(namespace);
                value.extend_from_slice(data);
                blobs.insert(&hash[..], value.as_slice())?;

                let mut meta = txn.open_table(META)?;
                let seq = meta.get("seq")?.map(|g| g.value()).unwrap_or(0);
                meta.insert("seq", seq + 1)?;
                let mut ns_key = Vec::with_capacity(40);
                ns_key.extend_from_slice(namespace);
                ns_key.extend_from_slice(&seq.to_be_bytes());
                txn.open_table(NAMESPACE_INDEX)?
                    .insert(ns_key.as_slice(), &hash[..])?;

                let mut exp_key = Vec::with_capacity(40);
                exp_key.extend_from_slice(&expiry.to_be_bytes());
                exp_key.extend_from_slice(&hash);
                txn.open_table(EXPIRY_INDEX)?
                    .insert(exp_key.as_slice(), ())?;
                (expiry, true)
            }
        };
        txn.commit()?;
        Ok((hash, expiry, inserted))
    }

    pub fn get(&self, hash: &[u8], now_unix: u64) -> Result<Option<StoredBlob>, StoreError> {
        if hash.len() != HASH_BYTES {
            return Err(StoreError::BadIdentifier);
        }
        let txn = self.db.begin_read()?;
        let blobs = txn.open_table(BLOBS)?;
        let Some(guard) = blobs.get(hash)? else {
            return Ok(None);
        };
        let v = guard.value();
        let expiry = u64::from_be_bytes(v[..8].try_into().unwrap());
        if expiry <= now_unix {
            return Ok(None); // expired but not yet pruned: never served
        }
        let uploaded_minute = u64::from_be_bytes(v[8..16].try_into().unwrap());
        let mut namespace = [0u8; 32];
        namespace.copy_from_slice(&v[16..HEADER]);
        Ok(Some(StoredBlob {
            data: v[HEADER..].to_vec(),
            uploaded_minute,
            expiry_unix: expiry,
            namespace,
        }))
    }

    /// Returns the subset of `hashes` present (unexpired) in `namespace`; never reveals blobs
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
            if let Some(b) = self.get(h, now_unix)? {
                if b.namespace == *namespace {
                    out.push(h.clone());
                }
            }
        }
        Ok(out)
    }

    /// Lists blob hashes of a namespace in insertion order after `cursor` (opaque 8-byte sequence,
    /// empty = from the beginning). Returns `(hashes, next_cursor)`; `next_cursor` is empty when
    /// there is nothing more.
    pub fn list(
        &self,
        namespace: &[u8; 32],
        cursor: &[u8],
        limit: usize,
    ) -> Result<(Vec<[u8; 32]>, Vec<u8>), StoreError> {
        if limit == 0 || limit > MAX_BATCH {
            return Err(StoreError::BatchTooLarge);
        }
        let start_seq = match cursor.len() {
            0 => 0u64,
            8 => u64::from_be_bytes(cursor.try_into().unwrap()) + 1,
            _ => return Err(StoreError::BadIdentifier),
        };
        let mut lo = Vec::with_capacity(40);
        lo.extend_from_slice(namespace);
        lo.extend_from_slice(&start_seq.to_be_bytes());
        let mut hi = Vec::with_capacity(40);
        hi.extend_from_slice(namespace);
        hi.extend_from_slice(&u64::MAX.to_be_bytes());

        let txn = self.db.begin_read()?;
        let index = txn.open_table(NAMESPACE_INDEX)?;
        let mut hashes = Vec::new();
        let mut last_seq: Option<u64> = None;
        for entry in index.range::<&[u8]>(lo.as_slice()..=hi.as_slice())? {
            let (k, v) = entry?;
            let key = k.value();
            let mut h = [0u8; 32];
            h.copy_from_slice(v.value());
            hashes.push(h);
            last_seq = Some(u64::from_be_bytes(key[32..40].try_into().unwrap()));
            if hashes.len() == limit {
                break;
            }
        }
        let next = if hashes.len() == limit {
            last_seq
                .map(|s| s.to_be_bytes().to_vec())
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        Ok((hashes, next))
    }

    /// Removes every blob whose expiry is `<= now`. Returns the number removed (FR-5.5 prune).
    pub fn prune_expired(&self, now_unix: u64) -> Result<usize, StoreError> {
        let txn = self.db.begin_write()?;
        let mut removed = 0usize;
        {
            let mut expiry = txn.open_table(EXPIRY_INDEX)?;
            let mut blobs = txn.open_table(BLOBS)?;
            let mut ns_index = txn.open_table(NAMESPACE_INDEX)?;
            let mut bound = Vec::with_capacity(40);
            bound.extend_from_slice(&now_unix.to_be_bytes());
            bound.extend_from_slice(&[0xff; 32]);
            let doomed: Vec<Vec<u8>> = expiry
                .range::<&[u8]>(..=bound.as_slice())?
                .map(|e| e.map(|(k, _)| k.value().to_vec()))
                .collect::<Result<_, _>>()?;
            for key in doomed {
                let hash = &key[8..40];
                let namespace: Option<[u8; 32]> = blobs.get(hash)?.map(|g| {
                    let mut ns = [0u8; 32];
                    ns.copy_from_slice(&g.value()[16..HEADER]);
                    ns
                });
                blobs.remove(hash)?;
                expiry.remove(key.as_slice())?;
                if let Some(ns) = namespace {
                    // Find and drop the namespace index entry pointing at this hash.
                    let mut lo = ns.to_vec();
                    lo.extend_from_slice(&0u64.to_be_bytes());
                    let mut hi = ns.to_vec();
                    hi.extend_from_slice(&u64::MAX.to_be_bytes());
                    let victim: Option<Vec<u8>> = ns_index
                        .range::<&[u8]>(lo.as_slice()..=hi.as_slice())?
                        .filter_map(|e| e.ok())
                        .find(|(_, v)| v.value() == hash)
                        .map(|(k, _)| k.value().to_vec());
                    if let Some(k) = victim {
                        ns_index.remove(k.as_slice())?;
                    }
                }
                removed += 1;
            }
        }
        txn.commit()?;
        Ok(removed)
    }

    pub fn count(&self) -> Result<u64, StoreError> {
        let txn = self.db.begin_read()?;
        Ok(txn.open_table(BLOBS)?.len()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn put_get_idempotent_and_hash_checked() {
        let (s, _d) = store();
        let ns = [1u8; 32];
        let (data, h) = blob(7, 1024);
        let (stored, expiry, inserted) = s.put(&h, &data, &ns, 3600, 1_000).unwrap();
        assert_eq!(stored, h);
        assert_eq!(expiry, 4_600);
        assert!(inserted);
        let (_, expiry2, inserted2) = s.put(&h, &data, &ns, 99, 2_000).unwrap();
        assert_eq!(expiry2, 4_600, "idempotent store keeps the original expiry");
        assert!(!inserted2);
        let got = s.get(&h, 1_500).unwrap().unwrap();
        assert_eq!(got.data, data);
        assert_eq!(got.uploaded_minute % 60, 0);
        assert_eq!(got.namespace, ns);
        assert!(matches!(
            s.put(&[0u8; 32], &data, &ns, 1, 1),
            Err(StoreError::HashMismatch)
        ));
        assert!(matches!(
            s.put(&h, &data[..1000], &ns, 1, 1),
            Err(StoreError::NotBucketSized)
        ));
        assert!(matches!(
            s.put(&h[..5], &data, &ns, 1, 1),
            Err(StoreError::BadIdentifier)
        ));
    }

    #[test]
    fn expired_blobs_are_never_served_and_prune_removes_them() {
        let (s, _d) = store();
        let ns = [2u8; 32];
        let (a, ha) = blob(1, 1024);
        let (b, hb) = blob(2, 1024);
        s.put(&ha, &a, &ns, 100, 1_000).unwrap(); // expires 1100
        s.put(&hb, &b, &ns, 1_000, 1_000).unwrap(); // expires 2000
        assert!(s.get(&ha, 1_100).unwrap().is_none());
        assert!(s.get(&hb, 1_100).unwrap().is_some());
        assert_eq!(s.prune_expired(1_100).unwrap(), 1);
        assert_eq!(s.count().unwrap(), 1);
        let (listed, _) = s.list(&ns, &[], 10).unwrap();
        assert_eq!(listed, vec![hb]);
        assert_eq!(s.prune_expired(1_100).unwrap(), 0);
    }

    #[test]
    fn list_pages_in_insertion_order_with_opaque_cursor() {
        let (s, _d) = store();
        let ns = [3u8; 32];
        let other = [4u8; 32];
        let mut expected = Vec::new();
        for i in 0..5u8 {
            let (d, h) = blob(10 + i, 1024);
            s.put(&h, &d, &ns, 1_000, 1).unwrap();
            expected.push(h);
        }
        let (d, h) = blob(99, 1024);
        s.put(&h, &d, &other, 1_000, 1).unwrap();
        let (p1, c1) = s.list(&ns, &[], 2).unwrap();
        assert_eq!(p1, expected[..2]);
        assert_eq!(c1.len(), 8);
        let (p2, c2) = s.list(&ns, &c1, 2).unwrap();
        assert_eq!(p2, expected[2..4]);
        let (p3, c3) = s.list(&ns, &c2, 2).unwrap();
        assert_eq!(p3, expected[4..]);
        assert!(c3.is_empty());
        assert!(matches!(
            s.list(&ns, &[1, 2, 3], 2),
            Err(StoreError::BadIdentifier)
        ));
        assert!(matches!(
            s.list(&ns, &[], MAX_BATCH + 1),
            Err(StoreError::BatchTooLarge)
        ));
    }

    #[test]
    fn check_never_reveals_other_namespaces() {
        let (s, _d) = store();
        let (d, h) = blob(5, 4096);
        s.put(&h, &d, &[9u8; 32], 1_000, 1).unwrap();
        assert_eq!(
            s.check(&[h.to_vec()], &[9u8; 32], 2).unwrap(),
            vec![h.to_vec()]
        );
        assert!(s.check(&[h.to_vec()], &[8u8; 32], 2).unwrap().is_empty());
        let too_many = vec![h.to_vec(); MAX_BATCH + 1];
        assert!(matches!(
            s.check(&too_many, &[9u8; 32], 2),
            Err(StoreError::BatchTooLarge)
        ));
    }
}
