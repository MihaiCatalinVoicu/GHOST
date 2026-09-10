//! Relay API crate: bounded store/get/check/list operations with explicit protocol versioning.
//! Wire schema: `protocol/relay/v1/relay.proto` (spec v2.0 §9.1).

/// Wire protocol version implemented by this relay.
pub const PROTOCOL_VERSION: u32 = 1;

/// Maximum serialized blob size accepted by a relay (FR-5.1).
pub const MAX_BLOB_BYTES: usize = 65_536;

/// Padding buckets applied to every packet before transport, in bytes (FR-2.5, ADR-09).
pub const PADDING_BUCKETS: [usize; 4] = [1_024, 4_096, 16_384, 65_536];

/// Default relay retention, in seconds (FR-5.5: 90 days).
pub const DEFAULT_TTL_SECONDS: u32 = 90 * 24 * 60 * 60;

/// Returns the padding bucket a payload of `len` bytes must be padded to, or `None` if it
/// exceeds the largest bucket and must be fragmented by the caller.
pub fn padding_bucket(len: usize) -> Option<usize> {
    PADDING_BUCKETS.iter().copied().find(|&b| len <= b)
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
    }
}
