//! Constant error categories that cross the JNI boundary (ADR-19). A category is the *only*
//! information an error carries into Kotlin: never an address, hash, namespace or relay message,
//! so nothing identifying can reach a log or crash report through an exception.
//! `client-core/README.md` must list every entry of [`ALL`] (enforced by a unit test).

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
];

pub fn for_transport(e: &TransportError) -> &'static str {
    match e {
        TransportError::Config(_) => BRIDGE_CONFIG,
        TransportError::Setup(_) => TOR_SETUP,
        TransportError::Bootstrap(_) => TOR_BOOTSTRAP,
        TransportError::BootstrapTimeout => TOR_BOOTSTRAP_TIMEOUT,
        TransportError::BootstrapSpent => TOR_BOOTSTRAP,
        TransportError::NotBootstrapped => NOT_BOOTSTRAPPED,
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
}
