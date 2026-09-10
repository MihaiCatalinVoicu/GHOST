//! GHOST client network core (Phase 6, ADR-01/ADR-09/ADR-19).
//!
//! Everything the client sends leaves through this crate, and this crate can only talk to
//! `.onion` addresses over an embedded Tor client (Arti). There is no clearnet code path: the
//! address type refuses anything that is not a v3 onion address, so a DNS lookup or a direct TCP
//! connection is not a configuration option but a type error. Each channel/purpose gets its own
//! circuit isolation token so a relay cannot link two namespaces of the same client through the
//! circuit they arrive on.

pub mod isolation;
pub mod onion;
pub mod relay_client;
pub mod transport;

#[cfg(feature = "jni-bridge")]
pub mod jni_bridge;

pub use isolation::{IsolationScope, Isolations};
pub use onion::{OnionAddress, OnionParseError};
pub use relay_client::{RelayClient, RelayError};
pub use transport::{TorTransport, TransportConfig, TransportError};
