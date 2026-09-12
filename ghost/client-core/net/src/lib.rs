//! GHOST client network core (Phase 6, ADR-01/ADR-09/ADR-19; Phase 8 entitlement calls, ADR-22).
//!
//! Everything the client sends leaves through this crate. Its public API can only target `.onion`
//! destinations over an embedded Tor client (Arti): a relay connection takes an [`OnionAddress`],
//! which rejects IPs, DNS names and URLs and validates the v3 checksum, and the issuer connection
//! ([`IssuerClient::over_tor`]) takes no destination at all: it dials the issuer onion of the
//! Entitlement Schedule built into the library; the underlying Arti client is not exposed. tonic is
//! linked with `codegen` only, so its clearnet `Channel`/`Endpoint` do not exist in the client
//! graph (rust-feature-policy.sh). Inside the crate, clippy `disallowed-methods`/`disallowed-types`
//! (`clippy.toml`) ban a listed set of clearnet and DNS APIs (std/tokio sockets and resolvers,
//! hyper-util's HTTP connector and resolver, the runtime's raw TCP/UDP) and every Arti dial except
//! `transport::connect_isolated`; a negative fixture proves each ban fires
//! (`scripts/gates/clippy-clearnet-fixture.sh`).
//! What this does NOT cover: an API not on the list, or another crate linked into the app, could
//! still open sockets. The Rust package allowlist and the `deny.toml` denylist only keep
//! unreviewed packages out. The complete check is the dynamic T6 test on the emulator (Phase 13).
//!
//! The Arti client stays private to the crate (the `compile_fail` examples name the expected
//! privacy error, E0624; rustdoc checks that code only on a nightly toolchain):
//! ```compile_fail,E0624
//! fn leak(t: &ghost_client_net::TorTransport) {
//!     let _ = t.client(); // error: private method
//! }
//! ```
//! while the public surface compiles:
//! ```
//! fn ok(t: &ghost_client_net::TorTransport) {
//!     t.rotate_circuits();
//!     t.end_issuer_flow(&[9u8; 16]);
//! }
//! ```
//!
//! Each channel/purpose gets its own circuit isolation token so a relay cannot link two namespaces
//! of the same client by the circuit they arrive on, and every issuer flow instance gets its own
//! ([`IsolationScope::IssuerFlow`], dropped when the flow ends). Vanguards-lite is enabled for
//! onion-service circuits. Blobs sent to relays must already be encrypted and bucket-sized;
//! padding is applied inside the AEAD plaintext by the encrypting layer (see
//! `ghost-relay-transport`).
//!
//! Relay calls go through [`NamespaceClient`], bound by type to one namespace: its circuits use
//! that namespace's isolation token and every capability must name the same namespace (T21).
//! The unbound client cannot be built outside the crate, whatever the scope:
//! ```compile_fail,E0624
//! fn unbound(t: &ghost_client_net::TorTransport, a: &ghost_client_net::OnionAddress) {
//!     let scope = ghost_client_net::IsolationScope::IssuerFlow([7u8; 16]);
//!     let _ = ghost_client_net::RelayClient::over_tor(t, a, &scope); // error: private
//! }
//! ```
//! ```
//! fn bound(t: &ghost_client_net::TorTransport, a: &ghost_client_net::OnionAddress) {
//!     let _ = ghost_client_net::NamespaceClient::over_tor(t, a, [7u8; 32]);
//! }
//! ```
//! Issuer calls go through [`issuer_flow`] over an [`IssuerClient`] bound to one flow. Neither
//! [`IssuerClient::over_tor`] nor [`NamespaceClient::redeem`] takes a schedule: the issuer onion
//! they dial and the relay slot a token is bound to come from the Entitlement Schedule built into
//! the library ([`entitlement::embedded_schedule`]), so no caller can redirect an issuer call or
//! bind a token to another relay:
//! ```compile_fail,E0061
//! fn redirect(t: &ghost_client_net::TorTransport, s: &ghost_entitlement::Schedule) {
//!     let _ = ghost_client_net::IssuerClient::over_tor(t, s, [7u8; 16]); // error: no schedule
//! }
//! ```
//! ```compile_fail,E0061
//! async fn rebind(
//!     c: &mut ghost_client_net::NamespaceClient<ghost_client_net::relay_client::OnionConnector>,
//!     s: &ghost_entitlement::Schedule,
//! ) {
//!     let _ = c.redeem(s, &[0u8; 354], [0u8; 16]).await; // error: no schedule
//! }
//! ```
//! ```
//! async fn fixed(
//!     t: &ghost_client_net::TorTransport,
//!     c: &mut ghost_client_net::NamespaceClient<ghost_client_net::relay_client::OnionConnector>,
//!     _s: &ghost_entitlement::Schedule,
//! ) {
//!     let _ = ghost_client_net::IssuerClient::over_tor(t, [7u8; 16]);
//!     let _ = c.redeem(&[0u8; 354], [0u8; 16]).await;
//! }
//! ```
//! The checks [`issuer_flow`] makes before and after each call are generic over the schedule and
//! the [`IssuerRpc`] (I/O-free seams for the tests); the JNI runs them with the embedded ES.

#![deny(clippy::print_stdout, clippy::print_stderr, clippy::dbg_macro)]

pub mod categories;
pub mod entitlement;
pub mod isolation;
pub mod issuer_client;
pub mod issuer_flow;
pub mod namespace_client;
pub mod onion;
pub mod relay_client;
pub mod transport;

#[cfg(feature = "jni-bridge")]
pub mod jni_bridge;

#[cfg(feature = "clippy-fixture")]
mod clippy_fixture;

#[cfg(test)]
mod loopback;

pub use isolation::IsolationScope;
pub use issuer_client::{IssuerClient, IssuerError, IssuerRpc};
pub use namespace_client::{NamespaceClient, RedeemOutcome, RedeemRpc};
pub use onion::{OnionAddress, OnionParseError};
pub use relay_client::{FetchedBlob, RelayClient, RelayError, StoreReceipt, RELAY_RPC_DEADLINE};
pub use transport::{TorTransport, TransportConfig, TransportError, BOOTSTRAP_DEADLINE};
