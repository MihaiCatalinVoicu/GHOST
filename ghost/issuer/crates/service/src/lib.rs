//! Entitlement issuer (Phase 8 design §5, §6, §7): blind signatures (RFC 9474 / Privacy Pass type
//! 0x0002) under keys per (kind, epoch) of the Entitlement Schedule, Monero invoices through a
//! view-only wallet behind the [`rail::PaymentRail`] boundary, invite trials and referral credits
//! (ADR-02, ADR-05, ADR-22..ADR-26).
//! Wire schema: `protocol/issuer/v1/issuer.proto`. Design: `docs/design/faza8-issuer.md`.
//!
//! The issuer keeps no logs at all: operators read `status.json` ([`status`]). State lives in
//! `issuer.redb` ([`store`]) and the append-only `issued.journal` ([`journal`]); private keys only
//! in process memory, for the window their obligations need ([`custody`]).
#![forbid(unsafe_code)]

pub mod claim;
pub mod config;
pub mod credit;
pub mod custody;
pub mod invite;
pub mod invoice;
pub mod journal;
pub mod pool;
pub mod quantum;
pub mod rail;
pub mod reconcile;
pub mod scanner;
pub mod server;
pub mod service;
pub mod signer;
pub mod status;
pub mod store;

pub use service::{Issuer, IssuerParams, OpenMode, OsRandom, Ports, Random, StartupError};

/// Wire protocol version implemented by this issuer.
pub const PROTOCOL_VERSION: u32 = 1;

/// Referral share in basis points: every XMR-paid pack yields one blind credit token worth 10 %
/// of the pack price (design D13, §9.2).
pub const REFERRAL_SHARE_BPS: u32 = 1_000;
