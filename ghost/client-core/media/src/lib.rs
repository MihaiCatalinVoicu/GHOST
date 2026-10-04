//! `ghost-client-media`: the GHOST media object (Phase 11 design `docs/design/faza11-media.md`,
//! revision 4: §3, §4.1, §8.2, §8.3, §13.1; slice S1 of §17.1).
//!
//! - [`consts`], [`class`]: the constants of §3.1 and the eleven size classes of §3.6.
//! - [`labels`], [`keys`]: the labels of §3.2 (with the S0-6 rename) and the derivations
//!   `K_p`, `K_m`, `commit` from a caller-supplied `K_f` and `object_id`, and `op_id` (§6.4).
//! - [`stream`]: the STREAM chunk layer of §3.3 (`aead-stream`'s `StreamBE32` layout).
//! - [`manifest`]: the 65 536-byte manifest blob of §3.5 with the key commitment.
//! - [`descriptor`]: the body of L0 kind 0x05 MEDIA (§4.1).
//! - [`sealer`], [`reader`]: the sealer discipline of §3.7 (CS-M1) and the reader's checks (CS-M2).
//! - [`sniff`]: the magic-byte allowlist of §6.1 and §13.2 M10 (S0-4, S0-21).
//! - [`jpeg`]: the canonical JPEG profile and `jpegCanonicalize` (§8.2).
//! - [`geometry`]: the canonical geometry of D29 and the ladder of Q37 (the target size of a source).
//! - [`fmp4`]: the canonical fMP4 profile, its streaming walker and the `mfra` builder (§8.3).
//! - [`error`]: the typed result codes.
//!
//! **No JNI, no I/O, no clock, no logging, no randomness, no state** (§13.1). Every key and nonce
//! input is the caller's (the S2 native surface draws `K_f` and `object_id` from the OS CSPRNG);
//! the crate reads no file, clock or environment and prints nothing (gates G-M7: `no-logging.sh`,
//! `media-rust-no-logging.sh`, `media-vendored-clock-log.sh`, `media-crate-purity.sh`). The only
//! state is the test feature `nonce-registry` (§3.7 point 5), which no shipped graph may enable.
//! Untrusted bytes reach the walkers, the codecs and the reader; none of them can panic (checked
//! arithmetic and checked indexing are enforced by the lints below outside tests), and each is
//! bounded in time (one pass) and memory (the bounds of [`consts`]).
#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::print_stdout, clippy::print_stderr, clippy::dbg_macro)]
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unreachable,
        clippy::unimplemented,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        clippy::cast_possible_truncation
    )
)]

pub mod class;
pub mod consts;
pub mod descriptor;
pub mod error;
pub mod fmp4;
pub mod geometry;
pub mod jpeg;
pub mod keys;
pub mod labels;
pub mod manifest;
pub mod reader;
pub mod sealer;
pub mod sniff;
pub mod stream;

mod bytes;
mod sps;
mod walk;

#[cfg(any(test, feature = "nonce-registry"))]
pub mod registry;

pub use class::SizeClass;
pub use consts::MediaKind;
pub use descriptor::{Descriptor, KeySlot};
pub use error::{Code, MediaError, MediaResult};
pub use keys::{Commitment, FileKey, ObjectId};
pub use manifest::{Manifest, ManifestFields};
pub use reader::{Expected, Reader, Walked};
pub use sealer::{SealedChunk, SealedObject, Sealer};
pub use sniff::{sniff, SourceType};
