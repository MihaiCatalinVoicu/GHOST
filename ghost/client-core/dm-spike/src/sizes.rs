//! V-3: Olm output overheads over the L0 plaintext, measured on real sessions of each pin.
//!
//! The chain index is the only variable-length header field a sender controls over time, so the
//! probe also sets the sending chain index in the stored pickle (the serde layout both pins
//! share) to reach every protobuf varint length up to ten bytes.

use crate::codes::Code;
use serde_json::Value;

/// `sending_ratchet.symmetric_key_ratchet.index` of an active sending ratchet, replaced.
pub fn set_sending_index(pickle: &[u8], index: u64) -> Result<Vec<u8>, Code> {
    let mut value: Value = serde_json::from_slice(pickle).map_err(|_| Code::StateCorrupt)?;
    let slot = value
        .pointer_mut("/sending_ratchet/symmetric_key_ratchet/index")
        .ok_or(Code::StateCorrupt)?;
    *slot = Value::from(index);
    serde_json::to_vec(&value).map_err(|_| Code::StateCorrupt)
}

/// One measured output: the L1 length minus the plaintext length.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Overhead {
    pub plaintext_len: usize,
    pub chain_index: u64,
    pub prekey: usize,
    pub normal: usize,
}

macro_rules! sizes_version {
    ($module:ident, $olm:path) => {
        pub mod $module {
            use super::{set_sending_index, Overhead};
            use crate::codes::Code;
            use crate::msc3814::DehydratedSecrets;
            use crate::olm::{random_bytes, x25519_public};
            use $olm as olm;

            /// Two fresh sessions: an initiator whose outputs are PreKey messages and a responder
            /// (after one received message) whose outputs are normal messages.
            pub struct Pair {
                pub initiator: Vec<u8>,
                pub responder: Vec<u8>,
            }

            pub fn pair() -> Result<Pair, Code> {
                let a = DehydratedSecrets {
                    curve25519: random_bytes(),
                    ed25519_seed: random_bytes(),
                    fallback: None,
                };
                let b_fallback: [u8; 32] = random_bytes();
                let b = DehydratedSecrets {
                    curve25519: random_bytes(),
                    ed25519_seed: random_bytes(),
                    fallback: Some(b_fallback),
                };
                let a_identity = x25519_public(&a.curve25519);
                let (initiator, _) = olm::session_outbound(
                    &a,
                    &x25519_public(&b.curve25519),
                    &x25519_public(&b_fallback),
                )?;
                let first = olm::encrypt(&initiator, b"first")?;
                let inbound = olm::session_inbound(&b, &a_identity, &first.l1)?;
                Ok(Pair {
                    initiator: first.pickle,
                    responder: inbound.pickle,
                })
            }

            /// Overheads at `plaintext_len` with the sending chain index forced to `chain_index`.
            pub fn overhead(
                pair: &Pair,
                plaintext_len: usize,
                chain_index: u64,
            ) -> Result<Overhead, Code> {
                let plaintext = vec![0u8; plaintext_len];
                let initiator = set_sending_index(&pair.initiator, chain_index)?;
                let pre = olm::encrypt(&initiator, &plaintext)?;
                if !pre.is_prekey {
                    return Err(Code::StateCorrupt);
                }
                // The responder's sending ratchet activates at its first encryption.
                let activated = olm::encrypt(&pair.responder, b"activate")?;
                let responder = set_sending_index(&activated.pickle, chain_index)?;
                let normal = olm::encrypt(&responder, &plaintext)?;
                if normal.is_prekey {
                    return Err(Code::StateCorrupt);
                }
                Ok(Overhead {
                    plaintext_len,
                    chain_index,
                    prekey: pre.l1.len() - plaintext_len,
                    normal: normal.l1.len() - plaintext_len,
                })
            }
        }
    };
}

sizes_version!(v11, crate::olm::v11);
sizes_version!(v10, crate::olm::v10);

/// The fixed parts of the intro and symmetric modes (design §6.2, §6.4, §6.6), independent of Olm.
pub mod fixed {
    /// salt 16 ‖ hint 16 ‖ AEAD tag 16 ‖ mode 1.
    pub const L2_OUTER: usize = 16 + 16 + 16 + 1;
    /// `gen_id` 4 ‖ `xwing_ct` 1 120 ‖ inner tag 16 ‖ kind 1 ‖ card 131 ‖ binding minute 4 ‖
    /// binding 64 ‖ `reply_seed` 32 ‖ `l1_len` 4.
    pub fn intro(xwing_ct_len: usize) -> usize {
        4 + xwing_ct_len + 16 + 1 + 131 + 4 + 64 + 32 + 4
    }
    /// kind 1 ‖ `l1_len` 4 (pair and provisional bodies).
    pub const SYMMETRIC_BODY: usize = 1 + 4;
    /// The fixed L0 fields with the quote reference counted (§21.11).
    pub const L0_FIXED: usize = 52;
    pub const EXT_RESERVE: usize = 160;
    pub const BUCKETS: [usize; 3] = [4096, 16384, 65536];
}
