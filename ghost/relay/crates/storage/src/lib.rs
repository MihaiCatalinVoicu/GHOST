//! Relay storage crate: content-addressed blobs with TTL and disk quotas (RocksDB in later phases).
//! Blob keys are the SHA-256 of the exact ciphertext (FR-5.2); no source identity is ever stored.
