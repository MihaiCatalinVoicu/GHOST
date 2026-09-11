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

/// Version byte of the v1 capability token layout.
pub const CAPABILITY_VERSION: u8 = 1;
/// Length of the MAC that ends a v1 capability token (HMAC-SHA256, keyed by the minting relay).
pub const CAPABILITY_MAC_BYTES: usize = 32;
/// Length of the authenticated body of a v1 capability token (everything before the MAC).
pub const CAPABILITY_BODY_BYTES: usize = 1 + 1 + 32 + 8 + 8;
/// Total length of a v1 capability token.
pub const CAPABILITY_TOKEN_BYTES: usize = CAPABILITY_BODY_BYTES + CAPABILITY_MAC_BYTES;

/// Right granted by a capability. A write capability also grants read on the same namespace at
/// the relay; read never grants write.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CapabilityKind {
    Read = 1,
    Write = 2,
}

/// Public header of a v1 capability token. The v1 layout, defined only here, is
/// `version(1) || kind(1) || namespace(32) || quota_bytes(8, BE) || expiry_unix(8, BE) || mac(32)`.
/// The header is readable by anyone holding the token; only the minting relay can check the MAC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityHeader {
    pub kind: CapabilityKind,
    pub namespace: [u8; 32],
    pub quota_bytes: u64,
    pub expiry_unix: u64,
}

impl CapabilityHeader {
    /// The authenticated body of the token (the bytes the minting relay MACs).
    pub fn encode_body(&self) -> [u8; CAPABILITY_BODY_BYTES] {
        let mut out = [0u8; CAPABILITY_BODY_BYTES];
        out[0] = CAPABILITY_VERSION;
        out[1] = self.kind as u8;
        out[2..34].copy_from_slice(&self.namespace);
        out[34..42].copy_from_slice(&self.quota_bytes.to_be_bytes());
        out[42..50].copy_from_slice(&self.expiry_unix.to_be_bytes());
        out
    }
}

/// Parses the public header of a capability token. Returns `None` unless the token has the exact
/// v1 length, version 1 and a known kind. The MAC is not checked (only the minting relay can), so
/// a `Some` says what the token claims, not that it is valid. A token of any other format is
/// refused until that format is added here explicitly.
pub fn capability_header(token: &[u8]) -> Option<CapabilityHeader> {
    if token.len() != CAPABILITY_TOKEN_BYTES || token[0] != CAPABILITY_VERSION {
        return None;
    }
    let kind = match token[1] {
        1 => CapabilityKind::Read,
        2 => CapabilityKind::Write,
        _ => return None,
    };
    let namespace: [u8; 32] = token[2..34].try_into().ok()?;
    let quota_bytes = u64::from_be_bytes(token[34..42].try_into().ok()?);
    let expiry_unix = u64::from_be_bytes(token[42..50].try_into().ok()?);
    Some(CapabilityHeader {
        kind,
        namespace,
        quota_bytes,
        expiry_unix,
    })
}

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
    fn capability_header_parses_the_v1_layout_only() {
        let header = CapabilityHeader {
            kind: CapabilityKind::Write,
            namespace: [0x5A; 32],
            quota_bytes: 0x0102_0304_0506_0708,
            expiry_unix: 1_800_000_000,
        };
        let body = header.encode_body();
        assert_eq!(body[0], CAPABILITY_VERSION);
        assert_eq!(body[1], 2);
        assert_eq!(&body[34..42], &[1, 2, 3, 4, 5, 6, 7, 8]);
        let mut token = body.to_vec();
        token.extend_from_slice(&[0xEE; CAPABILITY_MAC_BYTES]);
        assert_eq!(token.len(), 82);
        assert_eq!(capability_header(&token), Some(header.clone()));

        let read = CapabilityHeader {
            kind: CapabilityKind::Read,
            ..header
        };
        let mut read_token = read.encode_body().to_vec();
        read_token.extend_from_slice(&[0; CAPABILITY_MAC_BYTES]);
        assert_eq!(capability_header(&read_token), Some(read));

        // Wrong length, version or kind: not a v1 token.
        assert_eq!(capability_header(&[]), None);
        assert_eq!(capability_header(&token[..81]), None);
        let mut longer = token.clone();
        longer.push(0);
        assert_eq!(capability_header(&longer), None);
        for (index, value) in [(0usize, 0u8), (0, 2), (1, 0), (1, 3), (1, 0xFF)] {
            let mut t = token.clone();
            t[index] = value;
            assert_eq!(capability_header(&t), None, "byte {index} = {value}");
        }
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
