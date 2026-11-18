//! Constant error categories that cross the JNI boundary (ADR-19). A category is the *only*
//! information an error carries into Kotlin: never an address, hash, namespace or relay message,
//! so nothing identifying can reach a log or crash report through an exception.
//! `client-core/README.md` must list every entry of [`ALL`] (enforced by a unit test).

use crate::issuer_client::IssuerError;
use crate::relay_client::RelayError;
use crate::transport::TransportError;

pub const INVALID_ARGUMENT: &str = "invalid_argument";
pub const NOT_ONION: &str = "not_onion";
pub const CLOSED: &str = "closed";
pub const RUNTIME: &str = "runtime";
pub const BRIDGE_CONFIG: &str = "bridge_config";
pub const TOR_SETUP: &str = "tor_setup";
pub const TOR_BOOTSTRAP: &str = "tor_bootstrap";
pub const TOR_BOOTSTRAP_TIMEOUT: &str = "tor_bootstrap_timeout";
pub const NOT_BOOTSTRAPPED: &str = "not_bootstrapped";
pub const TRANSPORT: &str = "transport";
pub const ONION_SERVICE_NOT_FOUND: &str = "onion_service_not_found";
pub const TIMEOUT: &str = "timeout";
pub const UNAUTHORIZED: &str = "unauthorized";
pub const QUOTA: &str = "quota";
pub const NOT_FOUND: &str = "not_found";
pub const REJECTED: &str = "rejected";
pub const RELAY_UNAVAILABLE: &str = "relay_unavailable";
pub const NOT_BUCKET_SIZED: &str = "not_bucket_sized";
pub const NOT_STORED: &str = "not_stored";
pub const MALFORMED_RESPONSE: &str = "malformed_response";
pub const INTERNAL: &str = "internal";
// Phase 12 (design faza12-transports.md §8.3): the PT slice's four categories. `pt_hash_mismatch`
// and `pt_unsupported_abi` are raised by the APK-asset extraction (`:network`'s PtInstaller, the
// PT-1 surface) before any client exists; `bridge_line_invalid` and
// `bridge_line_unsupported_transport` are raised by the bridge-line storage write (PT-3, validated
// by `nativeValidateBridgeLines`). None carries a line's text — the failing index crosses as the
// exception detail, never the line (§6.6, T58).
pub const PT_HASH_MISMATCH: &str = "pt_hash_mismatch";
pub const PT_UNSUPPORTED_ABI: &str = "pt_unsupported_abi";
pub const BRIDGE_LINE_INVALID: &str = "bridge_line_invalid";
pub const BRIDGE_LINE_UNSUPPORTED_TRANSPORT: &str = "bridge_line_unsupported_transport";

pub const ALL: &[&str] = &[
    INVALID_ARGUMENT,
    NOT_ONION,
    CLOSED,
    RUNTIME,
    BRIDGE_CONFIG,
    TOR_SETUP,
    TOR_BOOTSTRAP,
    TOR_BOOTSTRAP_TIMEOUT,
    NOT_BOOTSTRAPPED,
    TRANSPORT,
    ONION_SERVICE_NOT_FOUND,
    TIMEOUT,
    UNAUTHORIZED,
    QUOTA,
    NOT_FOUND,
    REJECTED,
    RELAY_UNAVAILABLE,
    NOT_BUCKET_SIZED,
    NOT_STORED,
    MALFORMED_RESPONSE,
    INTERNAL,
    PT_HASH_MISMATCH,
    PT_UNSUPPORTED_ABI,
    BRIDGE_LINE_INVALID,
    BRIDGE_LINE_UNSUPPORTED_TRANSPORT,
];

pub fn for_transport(e: &TransportError) -> &'static str {
    match e {
        // Config-class: a malformed/unsupported line and a PT line without the extracted binary
        // or the system linker are the same category at the JNI boundary (design §8.3:
        // PtBinaryMissing is config class; rev 3 adds PtLinkerMissing to the same class — a
        // device that cannot launch a PT child answers every PT line with a config error).
        TransportError::Config(_)
        | TransportError::PtBinaryMissing
        | TransportError::PtLinkerMissing => BRIDGE_CONFIG,
        TransportError::Setup(_) => TOR_SETUP,
        TransportError::Bootstrap(_) => TOR_BOOTSTRAP,
        TransportError::BootstrapTimeout => TOR_BOOTSTRAP_TIMEOUT,
        TransportError::BootstrapSpent => TOR_BOOTSTRAP,
        TransportError::NotBootstrapped => NOT_BOOTSTRAPPED,
        TransportError::OnionServiceNotFound => ONION_SERVICE_NOT_FOUND,
        TransportError::Connect(_) => TRANSPORT,
    }
}

pub fn for_relay(e: &RelayError) -> &'static str {
    match e {
        RelayError::Transport(t) => for_transport(t),
        RelayError::Rpc(s) => match s.code() {
            tonic::Code::PermissionDenied | tonic::Code::Unauthenticated => UNAUTHORIZED,
            tonic::Code::ResourceExhausted => QUOTA,
            tonic::Code::NotFound => NOT_FOUND,
            tonic::Code::InvalidArgument => REJECTED,
            // h2 resets / io errors on Tor surface as Unknown/Internal/Unavailable: transient.
            _ => RELAY_UNAVAILABLE,
        },
        RelayError::NotBucketSized => NOT_BUCKET_SIZED,
        RelayError::InvalidArgument => INVALID_ARGUMENT,
        RelayError::NotStored => NOT_STORED,
        RelayError::Malformed => MALFORMED_RESPONSE,
        RelayError::Timeout => TIMEOUT,
    }
}

/// Issuer outcomes onto the existing categories (Phase 8 design §5.7, G-3: no new category, and
/// the sync `ErrorPolicy` never sees issuer calls). Protocol outcomes (`WRONG_PERIOD`, `REPLAYED`,
/// `OTHER_REQUEST_ISSUED`, `CREDITS_SPENT`, `CLAIM_CONFLICT`, `ADDRESS_REJECTED`) are in-band
/// answers, never errors.
pub fn for_issuer(e: &IssuerError) -> &'static str {
    match e {
        IssuerError::Transport(t) => for_transport(t),
        IssuerError::Rpc(code) => for_issuer_code(*code),
        IssuerError::InvalidArgument => INVALID_ARGUMENT,
        IssuerError::Malformed => MALFORMED_RESPONSE,
        IssuerError::Timeout => TIMEOUT,
    }
}

/// The gRPC status of an issuer answer (design §5.7): `INVALID_ARGUMENT` -> `rejected` (a client
/// or issuer bug, never a mutated retry), `PERMISSION_DENIED` -> `unauthorized`,
/// `RESOURCE_EXHAUSTED` -> `quota`; `OUT_OF_RANGE` -> `malformed_response` (the client's 1 MiB
/// answer cap; an issuer answering an honest request never sends it); `UNAVAILABLE` and every
/// other code -> `relay_unavailable` (remote onion service, relay or issuer, transient).
pub fn for_issuer_code(code: tonic::Code) -> &'static str {
    match code {
        tonic::Code::InvalidArgument => REJECTED,
        tonic::Code::PermissionDenied => UNAUTHORIZED,
        tonic::Code::ResourceExhausted => QUOTA,
        tonic::Code::OutOfRange => MALFORMED_RESPONSE,
        _ => RELAY_UNAVAILABLE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn categories_are_unique_and_documented() {
        let mut sorted = ALL.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), ALL.len());
        let readme = include_str!("../../README.md");
        for c in ALL {
            assert!(
                readme.contains(&format!("`{c}`")),
                "README must document `{c}`"
            );
        }
    }

    #[test]
    fn mapping_is_stable() {
        use tonic::{Code, Status};
        let rpc = |c| {
            for_relay(&RelayError::Rpc(Status::new(
                c,
                "relay text never forwarded",
            )))
        };
        assert_eq!(rpc(Code::PermissionDenied), UNAUTHORIZED);
        assert_eq!(rpc(Code::Unauthenticated), UNAUTHORIZED);
        assert_eq!(rpc(Code::Unknown), RELAY_UNAVAILABLE);
        assert_eq!(rpc(Code::ResourceExhausted), QUOTA);
        assert_eq!(rpc(Code::NotFound), NOT_FOUND);
        assert_eq!(rpc(Code::InvalidArgument), REJECTED);
        assert_eq!(rpc(Code::Unavailable), RELAY_UNAVAILABLE);
        assert_eq!(rpc(Code::Internal), RELAY_UNAVAILABLE);
        assert_eq!(for_relay(&RelayError::Timeout), TIMEOUT);
        assert_eq!(for_relay(&RelayError::Malformed), MALFORMED_RESPONSE);
        assert_eq!(for_relay(&RelayError::NotBucketSized), NOT_BUCKET_SIZED);
        assert_eq!(for_relay(&RelayError::NotStored), NOT_STORED);
        assert_eq!(for_relay(&RelayError::InvalidArgument), INVALID_ARGUMENT);
        assert_eq!(
            for_relay(&RelayError::Transport(TransportError::Connect("x".into()))),
            TRANSPORT
        );
        assert_eq!(for_transport(&TransportError::Setup("x".into())), TOR_SETUP);
        assert_eq!(
            for_transport(&TransportError::Bootstrap("x".into())),
            TOR_BOOTSTRAP
        );
        assert_eq!(
            for_transport(&TransportError::BootstrapSpent),
            TOR_BOOTSTRAP
        );
        assert_eq!(
            for_transport(&TransportError::NotBootstrapped),
            NOT_BOOTSTRAPPED
        );
        assert_eq!(
            for_transport(&TransportError::Config("x".into())),
            BRIDGE_CONFIG
        );
        assert_eq!(
            for_transport(&TransportError::PtBinaryMissing),
            BRIDGE_CONFIG
        );
        assert_eq!(
            for_transport(&TransportError::PtLinkerMissing),
            BRIDGE_CONFIG
        );
        assert_eq!(
            for_transport(&TransportError::BootstrapTimeout),
            TOR_BOOTSTRAP_TIMEOUT
        );
        assert_eq!(
            for_transport(&TransportError::Connect("x".into())),
            TRANSPORT
        );
        for c in ALL {
            assert!(c.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'));
        }
    }

    #[test]
    fn issuer_outcomes_use_existing_categories_only() {
        use tonic::Code;
        // The transport-level missing-descriptor category joins the existing 24.
        assert_eq!(ALL.len(), 25);
        let table = [
            (Code::InvalidArgument, REJECTED),
            (Code::PermissionDenied, UNAUTHORIZED),
            (Code::Unavailable, RELAY_UNAVAILABLE),
            (Code::ResourceExhausted, QUOTA),
            // Any other code is transient (the default of for_issuer).
            (Code::Unknown, RELAY_UNAVAILABLE),
            (Code::Internal, RELAY_UNAVAILABLE),
            (Code::Unauthenticated, RELAY_UNAVAILABLE),
            (Code::NotFound, RELAY_UNAVAILABLE),
            (Code::FailedPrecondition, RELAY_UNAVAILABLE),
            (Code::Unimplemented, RELAY_UNAVAILABLE),
            (Code::DeadlineExceeded, RELAY_UNAVAILABLE),
            // The client's own answer cap: never sent by an issuer answering an honest request.
            (Code::OutOfRange, MALFORMED_RESPONSE),
        ];
        for (code, category) in table {
            assert_eq!(for_issuer(&IssuerError::Rpc(code)), category, "{code:?}");
        }
        assert_eq!(for_issuer(&IssuerError::InvalidArgument), INVALID_ARGUMENT);
        assert_eq!(for_issuer(&IssuerError::Malformed), MALFORMED_RESPONSE);
        assert_eq!(for_issuer(&IssuerError::Timeout), TIMEOUT);
        assert_eq!(
            for_issuer(&IssuerError::Transport(TransportError::NotBootstrapped)),
            NOT_BOOTSTRAPPED
        );
        assert_eq!(
            for_issuer(&IssuerError::Transport(TransportError::Connect("x".into()))),
            TRANSPORT
        );
        for code in 0..=16 {
            assert!(ALL.contains(&for_issuer_code(Code::from_i32(code))));
        }
    }
}
