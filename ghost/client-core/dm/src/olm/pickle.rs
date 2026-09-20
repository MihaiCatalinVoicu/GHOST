//! The two reads of vodozemac's **private serde pickle layout** (design §2.1, §2.6 functions 19
//! and 20, added by S0′ V-7 and V-15).
//!
//! This is the **one recorded deviation** from §2.1/ADR-35 "used unchanged through public API
//! only". `SessionPickle`'s members, `ReceiverChain` (`pub(super)`) and `MessageKeyStore` are all
//! private, so `/receiving_chains/inner`, `ratchet_key`, `/hkdf_ratchet/index` and
//! `/skipped_message_keys/inner` are serde-derived names outside vodozemac's semver surface
//! (`vz:src/olm/session/mod.rs:640-645`, `receiver_chain.rs:53-55,131-150`). It is taken because
//! no upstream API exposes a receiver chain's position or removes a skipped key, and there is no
//! other route to the restart-proof gap hold (§7.7 point 2) or the age bound (§7.7 point 4).
//!
//! Its cost is bounded by three rules, all enforced here:
//!
//! 1. the layout is pinned per vodozemac version by **G-R7** (golden outputs at every bump);
//! 2. **every drift is loud** — [`DmCode::StateCorrupt`], never a silent default. Returning 0 on a
//!    renamed field would report every chain as new, never fire the hold, and bring back the 12 %
//!    offline-burst loss V-7 measured, with no result code to show for it;
//! 3. Q58's upstream contribution (a pruning API and a chain-position accessor) removes the
//!    deviation when vodozemac ships it.
//!
//! Nothing here writes a clock or a time value into the pickle: the day of a skipped key lives in
//! the GHOST sidecar beside it ([`super::state`]), which is what keeps T33 executable ("library
//! state holds no time at all").

use crate::result::{DmCode, DmResult};
use serde_json::Value;

/// Olm's per-chain skipped-key limit (`vz:src/olm/session/receiver_chain.rs:50`).
pub const MAX_MESSAGE_KEYS: usize = 40;
/// Olm's receiver-chain limit (`vz:src/olm/session/mod.rs:55`).
pub const MAX_RECEIVING_CHAINS: usize = 5;

/// A skipped message key, named by its chain's ratchet key and its chain index.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SkippedKey {
    /// The ratchet key of the receiver chain holding the key.
    pub ratchet_key: [u8; 32],
    /// The chain index the key decrypts.
    pub index: u64,
}

/// One receiver chain, as far as GHOST reads it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainView {
    /// The chain's ratchet key.
    pub ratchet_key: [u8; 32],
    /// `hkdf_ratchet.index`: the next chain index this chain's key will produce.
    pub next_index: u64,
    /// The chain indices of the skipped keys it holds, in stored order.
    pub skipped: Vec<u64>,
}

/// The outcome of [`chain_position`] (§2.6 function 19). `NEW_CHAIN` is a **result value**, not an
/// error: the chains were readable and none of them is the one the ratchet key names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChainPosition {
    /// The named chain exists; this is its next chain index.
    Index(u64),
    /// The chains are readable and none matches (including a session with no chain at all).
    NewChain,
}

fn parse(pickle: &[u8]) -> DmResult<Value> {
    serde_json::from_slice(pickle).map_err(|_| DmCode::StateCorrupt)
}

fn bytes32(value: Option<&Value>) -> Option<[u8; 32]> {
    let items = value?.as_array()?;
    if items.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    for (slot, item) in out.iter_mut().zip(items) {
        *slot = u8::try_from(item.as_u64()?).ok()?;
    }
    Some(out)
}

fn chains(value: &Value) -> DmResult<&Vec<Value>> {
    value
        .pointer("/receiving_chains/inner")
        .and_then(Value::as_array)
        .ok_or(DmCode::StateCorrupt)
}

fn chains_mut(value: &mut Value) -> DmResult<&mut Vec<Value>> {
    value
        .pointer_mut("/receiving_chains/inner")
        .and_then(Value::as_array_mut)
        .ok_or(DmCode::StateCorrupt)
}

fn skipped_indices(chain: &Value) -> DmResult<Vec<u64>> {
    let keys = chain
        .pointer("/skipped_message_keys/inner")
        .and_then(Value::as_array)
        .ok_or(DmCode::StateCorrupt)?;
    keys.iter()
        .map(|key| {
            key.get("index")
                .and_then(Value::as_u64)
                .ok_or(DmCode::StateCorrupt)
        })
        .collect()
}

/// Every receiver chain of a stored pickle, in stored order.
///
/// A non-empty `/receiving_chains/inner` in which **no** entry carries a readable 32-byte
/// `ratchet_key` is the drift signal of §2.6 function 19: the field was renamed or retyped, and
/// the answer is [`DmCode::StateCorrupt`]. A single unreadable entry among readable ones is drift
/// too — the layout is one shape for all entries — so both cases fail the same way.
pub fn chain_views(pickle: &[u8]) -> DmResult<Vec<ChainView>> {
    let value = parse(pickle)?;
    chains(&value)?
        .iter()
        .map(|chain| {
            Ok(ChainView {
                ratchet_key: bytes32(chain.get("ratchet_key")).ok_or(DmCode::StateCorrupt)?,
                next_index: chain
                    .pointer("/hkdf_ratchet/index")
                    .and_then(Value::as_u64)
                    .ok_or(DmCode::StateCorrupt)?,
                skipped: skipped_indices(chain)?,
            })
        })
        .collect()
}

/// `chainPosition` (§2.6 function 19): the next chain index of the receiver chain `ratchet_key`
/// names, or [`ChainPosition::NewChain`].
///
/// Called during **peek**, on the envelope of the session the recognition key names. It writes
/// nothing and sends nothing (T28), which is what makes the gap hold of §7.7 point 2 restart-proof
/// without a persisted gap counter (T33).
pub fn chain_position(pickle: &[u8], ratchet_key: &[u8; 32]) -> DmResult<ChainPosition> {
    for chain in chain_views(pickle)? {
        if &chain.ratchet_key == ratchet_key {
            return Ok(ChainPosition::Index(chain.next_index));
        }
    }
    Ok(ChainPosition::NewChain)
}

/// Every skipped key a pickle holds, in stored order.
pub fn skipped_keys(pickle: &[u8]) -> DmResult<Vec<SkippedKey>> {
    Ok(chain_views(pickle)?
        .into_iter()
        .flat_map(|chain| {
            chain.skipped.into_iter().map(move |index| SkippedKey {
                ratchet_key: chain.ratchet_key,
                index,
            })
        })
        .collect())
}

/// Removes from the pickle every skipped key for which `drop_key` holds, keeping the order of the
/// others. Returns the edited pickle and the number of keys removed.
///
/// `sessionPrune` (§2.6 function 20) is this plus the sidecar reconciliation of
/// [`super::state`]; SWEEP calls it on every live session (§7.7 point 4).
pub fn prune(
    pickle: &[u8],
    mut drop_key: impl FnMut(&SkippedKey) -> bool,
) -> DmResult<(Vec<u8>, usize)> {
    let mut value = parse(pickle)?;
    let mut removed = 0usize;
    let mut drift = false;
    for chain in chains_mut(&mut value)?.iter_mut() {
        let ratchet_key = match bytes32(chain.get("ratchet_key")) {
            Some(key) => key,
            None => return Err(DmCode::StateCorrupt),
        };
        let keys = chain
            .pointer_mut("/skipped_message_keys/inner")
            .and_then(Value::as_array_mut)
            .ok_or(DmCode::StateCorrupt)?;
        let before = keys.len();
        keys.retain(|key| match key.get("index").and_then(Value::as_u64) {
            Some(index) => !drop_key(&SkippedKey { ratchet_key, index }),
            None => {
                drift = true;
                true
            }
        });
        if drift {
            return Err(DmCode::StateCorrupt);
        }
        removed += before - keys.len();
    }
    Ok((
        serde_json::to_vec(&value).map_err(|_| DmCode::StateCorrupt)?,
        removed,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A pickle shaped like the pinned layout, without running a session: the layout tests below
    /// are about drift, and the golden-pickle tests exercise real sessions.
    fn shaped(chains: &[(u8, u64, &[u64])]) -> Vec<u8> {
        let entries: Vec<Value> = chains
            .iter()
            .map(|(tag, next_index, skipped)| {
                let keys: Vec<Value> = skipped
                    .iter()
                    .map(|index| serde_json::json!({ "key": vec![1u8; 32], "index": index }))
                    .collect();
                serde_json::json!({
                    "ratchet_key": vec![*tag; 32],
                    "hkdf_ratchet": { "key": vec![2u8; 32], "index": next_index },
                    "skipped_message_keys": { "inner": keys },
                    "ratchet_count": "Unknown",
                })
            })
            .collect();
        serde_json::to_vec(&serde_json::json!({ "receiving_chains": { "inner": entries } }))
            .expect("json")
    }

    #[test]
    fn chain_position_reads_the_named_chain() {
        let pickle = shaped(&[(0xaa, 7, &[3, 5]), (0xbb, 2, &[])]);
        assert_eq!(
            chain_position(&pickle, &[0xaa; 32]).expect("position"),
            ChainPosition::Index(7)
        );
        assert_eq!(
            chain_position(&pickle, &[0xbb; 32]).expect("position"),
            ChainPosition::Index(2)
        );
        assert_eq!(
            chain_position(&pickle, &[0xcc; 32]).expect("position"),
            ChainPosition::NewChain
        );
    }

    /// §7.7 point 2: a session with no chain for the key reports `NEW_CHAIN`, which the hold reads
    /// as position 0.
    #[test]
    fn a_session_without_chains_is_a_new_chain_not_an_error() {
        let pickle = shaped(&[]);
        assert_eq!(
            chain_position(&pickle, &[0xaa; 32]).expect("position"),
            ChainPosition::NewChain
        );
    }

    /// V-7 `chain_position_refuses_a_drifted_layout`: a renamed or retyped field is
    /// `STATE_CORRUPT`, never a silent 0 (§2.1 rule 2).
    #[test]
    fn a_drifted_layout_is_state_corrupt_never_a_silent_zero() {
        let renamed_container = serde_json::to_vec(&serde_json::json!({
            "receiving_chains": { "entries": [] }
        }))
        .expect("json");
        assert_eq!(
            chain_position(&renamed_container, &[0xaa; 32]).err(),
            Some(DmCode::StateCorrupt)
        );

        let renamed_key = serde_json::to_vec(&serde_json::json!({
            "receiving_chains": { "inner": [{
                "chain_key": vec![0xaau8; 32],
                "hkdf_ratchet": { "index": 4 },
                "skipped_message_keys": { "inner": [] },
            }] }
        }))
        .expect("json");
        assert_eq!(
            chain_position(&renamed_key, &[0xaa; 32]).err(),
            Some(DmCode::StateCorrupt)
        );

        let renamed_index = serde_json::to_vec(&serde_json::json!({
            "receiving_chains": { "inner": [{
                "ratchet_key": vec![0xaau8; 32],
                "hkdf_ratchet": { "position": 4 },
                "skipped_message_keys": { "inner": [] },
            }] }
        }))
        .expect("json");
        assert_eq!(
            chain_position(&renamed_index, &[0xaa; 32]).err(),
            Some(DmCode::StateCorrupt)
        );

        assert_eq!(
            chain_position(b"not json", &[0xaa; 32]).err(),
            Some(DmCode::StateCorrupt)
        );
    }

    #[test]
    fn prune_removes_only_the_named_keys_and_keeps_order() {
        let pickle = shaped(&[(0xaa, 9, &[1, 4, 6]), (0xbb, 3, &[2])]);
        let (pruned, removed) = prune(&pickle, |key| key.index == 4).expect("prune");
        assert_eq!(removed, 1);
        assert_eq!(
            skipped_keys(&pruned).expect("keys"),
            vec![
                SkippedKey {
                    ratchet_key: [0xaa; 32],
                    index: 1
                },
                SkippedKey {
                    ratchet_key: [0xaa; 32],
                    index: 6
                },
                SkippedKey {
                    ratchet_key: [0xbb; 32],
                    index: 2
                },
            ]
        );
        let (again, removed) = prune(&pruned, |_| false).expect("prune");
        assert_eq!(removed, 0);
        assert_eq!(skipped_keys(&again).expect("keys").len(), 3);
    }

    #[test]
    fn prune_refuses_an_unreadable_chain_or_entry() {
        let bad_entry = serde_json::to_vec(&serde_json::json!({
            "receiving_chains": { "inner": [{
                "ratchet_key": vec![0xaau8; 32],
                "hkdf_ratchet": { "index": 0 },
                "skipped_message_keys": { "inner": [{ "key": vec![1u8; 32], "position": 3 }] },
            }] }
        }))
        .expect("json");
        assert_eq!(
            prune(&bad_entry, |_| true).err(),
            Some(DmCode::StateCorrupt)
        );
        assert_eq!(prune(b"{}", |_| true).err(), Some(DmCode::StateCorrupt));
    }
}
