//! Entitlement formats shared by the client, the relays, the issuer and the operator tools (Phase 8
//! design §2–§4, §7.7): the epoch grid, the client-built TokenChallenge, Privacy Pass type 0x0002
//! tokens and their nullifiers, the offline-signed Entitlement Schedule (ES), seed-derived blinding
//! batches, and Monero address validation with the payment URI.
//!
//! Everything type-0x0002-specific (2048-bit keys, e = 65537, 256-byte blocks) is enforced here;
//! the RSA arithmetic underneath (`ghost-blind-rsa`) is generic in the modulus length.
#![forbid(unsafe_code)]

pub mod batch;
pub mod challenge;
pub mod grid;
pub mod monero;
pub mod onion;
pub mod schedule;
pub mod token;

pub use grid::Kind;
pub use schedule::{Expect, Schedule, ScheduleError, ScheduleMemory, VerifiedToken};
pub use token::Token;

/// Failures of the token, challenge and onion formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FormatError {
    /// A TokenChallenge is malformed (lengths, trailing bytes).
    Challenge,
    /// A relay slot is missing for ACCESS, present for INVITE/CREDIT, or above 31.
    Slot,
    /// A token is not exactly 354 bytes.
    TokenLength,
    /// `token_type` is not 0x0002.
    TokenType,
    /// The key is not a 2048-bit RSA key with e = 65537.
    KeySize,
    /// Blinding refused its input (gcd(em, n) != 1 or r out of range).
    Blind,
    /// The authenticator does not verify, or a blind signature does not finalize.
    Signature,
    /// Not a canonical v3 onion address with port.
    Onion,
}

impl std::fmt::Display for FormatError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            FormatError::Challenge => "malformed token challenge",
            FormatError::Slot => "invalid relay slot for this token kind",
            FormatError::TokenLength => "token must be 354 bytes",
            FormatError::TokenType => "token type must be 0x0002",
            FormatError::KeySize => "token key must be RSA-2048 with e = 65537",
            FormatError::Blind => "blinding input refused",
            FormatError::Signature => "token signature invalid",
            FormatError::Onion => "not a canonical v3 onion address",
        })
    }
}

impl std::error::Error for FormatError {}
