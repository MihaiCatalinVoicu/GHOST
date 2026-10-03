//! `ghost-client-mls`: GHOST channels on OpenMLS 0.9.0 with the libcrux provider (Phase 10 design
//! `docs/design/faza10-forum.md` §3, §5, §10.1, §10.2; slice S2a — the Rust API; the closed JNI
//! surface `MlsNative` is slice S2b).
//!
//! - [`kv`]: `GhostKv`, the value-semantics storage adapter (§3.4, S0-6, S0-17).
//! - [`provider`]: the provider composition and the pseudonym signer (§3.3).
//! - [`derive`]: the channel derivations with typed secret inputs (§5.2, gate G-M3).
//! - [`seal`]: the outer seal, size classes, buckets and TTLs (§5.6 … §5.8).
//! - [`ext`]: `GhostChannelContext`, `GhostLeaf`, `GhostBootstrap`, `GhostKpBind`,
//!   `GhostCommitAad`, `ChannelOrder` (§5.3 … §5.5, §19.2).
//! - [`content`]: `ChannelContent` v1 (§5.5).
//! - [`canonical`]: the canonical KeyPackage and leaves (395 B; §6.2.4 (B), S0-4, S0-5, Q42 (a)).
//! - [`invite`], [`join`]: `ChannelInviteV2` with the password layer (§19.28, §19.29) and the join
//!   codecs (§5.6).
//! - [`check`]: a commit's validation summary and CO-2 (§6.4).
//! - [`group`]: the channel operations over `MlsGroup` (§10.2's function list).
//! - [`result`]: the result codes.
//!
//! **No network, async runtime, logger or clock.** The crate reads no clock (a `day` or `minute`
//! is always the caller's, from the trusted clock), prints nothing and installs no logger (gates
//! G-M4, G-M8); `rayon`'s global pool is pinned to one worker at every context open (§3.6).
#![forbid(unsafe_code)]

pub mod canonical;
pub mod check;
pub mod codec;
pub mod content;
pub mod derive;
pub mod ext;
pub mod group;
pub mod invite;
pub mod join;
pub mod kv;
pub mod provider;
pub mod result;
pub mod seal;

#[cfg(test)]
mod props;

pub use group::{pin_rayon_single_worker, ChannelHandle, MlsContext};
pub use result::{Code, CommitReason, MlsError, MlsResult};
