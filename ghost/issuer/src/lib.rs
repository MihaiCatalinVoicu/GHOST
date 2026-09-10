//! Entitlement issuer: blind signatures (RFC 9474 / Privacy Pass) with public period metadata,
//! Monero invoices via a view-only wallet, invite tokens and referral ledger (ADR-02, ADR-05).
//! Wire schema: `protocol/issuer/v1/issuer.proto`.

/// Wire protocol version implemented by this issuer.
pub const PROTOCOL_VERSION: u32 = 1;

/// Referral share credited on every confirmed payment, in basis points (10%, spec v2.0 FR-6.7).
pub const REFERRAL_SHARE_BPS: u32 = 1_000;
