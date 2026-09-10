//! Relay API crate: wire types generated from `protocol/relay/v1/relay.proto` (spec v2.0 §9.1)
//! plus the protocol constants every relay and client must agree on.

/// Generated protobuf messages and gRPC service (`ghost.relay.v1`).
pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/ghost.relay.v1.rs"));
}

/// Wire protocol version implemented by this relay.
pub const PROTOCOL_VERSION: u32 = 1;

/// Maximum serialized blob size accepted by a relay (FR-5.1).
pub const MAX_BLOB_BYTES: usize = 65_536;

/// Padding buckets applied to every packet before transport, in bytes (FR-2.5, ADR-09). A relay
/// only accepts blobs whose exact length is one of these, so the sizes it can observe are the
/// bucket sizes and nothing finer.
pub const PADDING_BUCKETS: [usize; 4] = [1_024, 4_096, 16_384, 65_536];

/// Default relay retention, in seconds (FR-5.5: 90 days).
pub const DEFAULT_TTL_SECONDS: u32 = 90 * 24 * 60 * 60;

/// Retention buckets a relay is allowed to observe/record, in days (threat model §6).
pub const TTL_BUCKETS_DAYS: [u32; 4] = [1, 7, 30, 90];

/// Largest batch accepted by CheckBlobs/ListNamespace (§11.2 bounded batches).
pub const MAX_BATCH: usize = 256;

/// Byte length of identifiers that are hashes (SHA-256).
pub const HASH_BYTES: usize = 32;
/// Byte length of client idempotency keys.
pub const REQUEST_ID_BYTES: usize = 16;

/// Returns the padding bucket a payload of `len` bytes must be padded to, or `None` if it
/// exceeds the largest bucket and must be fragmented by the caller.
pub fn padding_bucket(len: usize) -> Option<usize> {
    PADDING_BUCKETS.iter().copied().find(|&b| len <= b)
}

/// True when `len` is exactly a bucket size (the only lengths a relay stores).
pub fn is_bucket_size(len: usize) -> bool {
    PADDING_BUCKETS.contains(&len)
}

/// Rounds a TTL in seconds up to the coarsest allowed bucket, in days; `None` if above the maximum.
pub fn ttl_bucket_days(ttl_seconds: u32) -> Option<u32> {
    let days = ttl_seconds.div_ceil(86_400).max(1);
    TTL_BUCKETS_DAYS.iter().copied().find(|&d| days <= d)
}

/// Unix seconds rounded down to the minute: the only time granularity a relay records.
pub fn time_bucket(unix_seconds: u64) -> u64 {
    unix_seconds - unix_seconds % 60
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buckets_are_ascending_and_end_at_blob_limit() {
        assert!(PADDING_BUCKETS.windows(2).all(|w| w[0] < w[1]));
        assert_eq!(*PADDING_BUCKETS.last().unwrap(), MAX_BLOB_BYTES);
    }

    #[test]
    fn bucket_selection_rounds_up_and_rejects_oversize() {
        assert_eq!(padding_bucket(0), Some(1_024));
        assert_eq!(padding_bucket(1_024), Some(1_024));
        assert_eq!(padding_bucket(1_025), Some(4_096));
        assert_eq!(padding_bucket(65_536), Some(65_536));
        assert_eq!(padding_bucket(65_537), None);
        assert!(is_bucket_size(4_096));
        assert!(!is_bucket_size(4_097));
    }

    #[test]
    fn ttl_and_time_buckets() {
        assert_eq!(ttl_bucket_days(1), Some(1));
        assert_eq!(ttl_bucket_days(86_400 * 2), Some(7));
        assert_eq!(ttl_bucket_days(DEFAULT_TTL_SECONDS), Some(90));
        assert_eq!(ttl_bucket_days(DEFAULT_TTL_SECONDS + 1), None);
        assert_eq!(time_bucket(1_757_491_261), 1_757_491_260);
    }

    #[test]
    fn generated_types_exist() {
        let req = proto::StoreBlobRequest {
            version: PROTOCOL_VERSION,
            ..Default::default()
        };
        assert_eq!(req.version, 1);
    }
}
