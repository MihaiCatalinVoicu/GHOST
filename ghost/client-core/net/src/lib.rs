//! GHOST client network core (Phase 6, ADR-01/ADR-09/ADR-19).
//!
//! Everything the client sends leaves through this crate. Its public API can only target `.onion`
//! destinations over an embedded Tor client (Arti): the only public way to open a connection takes
//! an [`OnionAddress`], which rejects IPs, DNS names and URLs and validates the v3 checksum, and the
//! underlying Arti client is not exposed. tonic is linked with `codegen` only, so its clearnet
//! `Channel`/`Endpoint` do not exist in the client graph (rust-feature-policy.sh). Inside the
//! crate, clippy `disallowed-methods`/`disallowed-types` (`clippy.toml`) ban a listed set of
//! clearnet and DNS APIs (std/tokio sockets and resolvers, hyper-util's HTTP connector and
//! resolver, the runtime's raw TCP/UDP) and every Arti dial except `transport::connect_isolated`;
//! a negative fixture proves each ban fires (`scripts/gates/clippy-clearnet-fixture.sh`).
//! What this does NOT cover: an API not on the list, or another crate linked into the app, could
//! still open sockets. The Rust package allowlist and the `deny.toml` denylist only keep
//! unreviewed packages out. The complete check is the dynamic T6 test on the emulator (Phase 13).
//!
//! The Arti client stays private to the crate:
//! ```compile_fail
//! fn leak(t: &ghost_client_net::TorTransport) {
//!     let _ = t.client(); // error: private method
//! }
//! ```
//! while the public surface compiles:
//! ```
//! fn ok(t: &ghost_client_net::TorTransport) {
//!     t.rotate_circuits();
//! }
//! ```
//!
//! Each channel/purpose gets its own circuit isolation token so a relay cannot link two namespaces
//! of the same client by the circuit they arrive on. Vanguards-lite is enabled for onion-service
//! circuits. Blobs sent to relays must already be encrypted and bucket-sized; padding is applied
//! inside the AEAD plaintext by the encrypting layer (see `ghost-relay-transport`).

#![deny(clippy::print_stdout, clippy::print_stderr, clippy::dbg_macro)]

pub mod categories;
pub mod isolation;
pub mod onion;
pub mod relay_client;
pub mod transport;

#[cfg(feature = "jni-bridge")]
pub mod jni_bridge;

#[cfg(feature = "clippy-fixture")]
mod clippy_fixture;

pub use isolation::IsolationScope;
pub use onion::{OnionAddress, OnionParseError};
pub use relay_client::{RelayClient, RelayError, StoreReceipt, RELAY_RPC_DEADLINE};
pub use transport::{TorTransport, TransportConfig, TransportError, BOOTSTRAP_DEADLINE};
