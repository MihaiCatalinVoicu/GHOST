//! V-15: the skipped-key age bound (design §7.7 point 4, Q67, RG-6) as a pinned-schema edit of
//! the JSON session pickle.
//!
//! Neither pin exposes an API to drop receiver-chain message keys, so the only public-API route is
//! to edit `receiving_chains.inner[].skipped_message_keys.inner[]` (`{key, index}` entries) in the
//! stored pickle and load the result with `Session::from_pickle`. The first-seen day of a key is
//! GHOST state kept beside the pickle: a key is new when it appears in the pickle after a
//! decryption that did not hold it before ([`added_keys`]).

use crate::codes::Code;
use serde_json::Value;
use std::collections::HashMap;

/// Largest first-seen sidecar of one session, from Olm's own limits: `u8(chains)` and, per chain,
/// `ratchet_key(32) ‖ u8(n) ‖ n × (u64_be index ‖ u32_be day)` with at most
/// `MAX_RECEIVING_CHAINS = 5` chains (`vz:src/olm/session/mod.rs:55`) of at most
/// `MAX_MESSAGE_KEYS = 40` keys (`vz:src/olm/session/receiver_chain.rs:50`). The bound holds only
/// because the sidecar is a projection of the pickle ([`reconcile`]).
pub const SIDECAR_MAX: usize = 1 + 5 * (32 + 1 + 40 * (8 + 4));

/// A skipped message key named by its chain's ratchet key and its chain index.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SkippedKey {
    pub ratchet_key: [u8; 32],
    pub index: u64,
}

fn bytes32(value: &Value) -> Option<[u8; 32]> {
    let items = value.as_array()?;
    if items.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    for (slot, item) in out.iter_mut().zip(items) {
        *slot = u8::try_from(item.as_u64()?).ok()?;
    }
    Some(out)
}

fn chains_mut(value: &mut Value) -> Result<&mut Vec<Value>, Code> {
    value
        .pointer_mut("/receiving_chains/inner")
        .and_then(Value::as_array_mut)
        .ok_or(Code::StateCorrupt)
}

/// Every skipped key held by a pickle, in stored order.
pub fn skipped_keys(pickle: &[u8]) -> Result<Vec<SkippedKey>, Code> {
    let mut value: Value = serde_json::from_slice(pickle).map_err(|_| Code::StateCorrupt)?;
    let mut out = Vec::new();
    for chain in chains_mut(&mut value)?.iter() {
        let ratchet_key = chain
            .get("ratchet_key")
            .and_then(bytes32)
            .ok_or(Code::StateCorrupt)?;
        let keys = chain
            .pointer("/skipped_message_keys/inner")
            .and_then(Value::as_array)
            .ok_or(Code::StateCorrupt)?;
        for key in keys {
            let index = key
                .get("index")
                .and_then(Value::as_u64)
                .ok_or(Code::StateCorrupt)?;
            out.push(SkippedKey { ratchet_key, index });
        }
    }
    Ok(out)
}

/// The number of skipped keys each receiving chain holds, in stored order.
pub fn chain_key_counts(pickle: &[u8]) -> Result<Vec<usize>, Code> {
    let mut value: Value = serde_json::from_slice(pickle).map_err(|_| Code::StateCorrupt)?;
    let mut out = Vec::new();
    for chain in chains_mut(&mut value)?.iter() {
        chain
            .get("ratchet_key")
            .and_then(bytes32)
            .ok_or(Code::StateCorrupt)?;
        out.push(
            chain
                .pointer("/skipped_message_keys/inner")
                .and_then(Value::as_array)
                .ok_or(Code::StateCorrupt)?
                .len(),
        );
    }
    Ok(out)
}

/// Encoded length of the first-seen sidecar of a pickle, in the layout `SIDECAR_MAX` bounds.
pub fn sidecar_len(pickle: &[u8]) -> Result<usize, Code> {
    Ok(1 + chain_key_counts(pickle)?
        .into_iter()
        .map(|n| 32 + 1 + n * (8 + 4))
        .sum::<usize>())
}

/// The first-seen sidecar of a stored pickle: exactly the keys the pickle holds, each keeping the
/// day already recorded for it and a key seen for the first time taking `today`. Rebuilding it at
/// every store is what drops the entries of keys the library evicted itself (its 40-key FIFO and
/// its 5-chain limit), so the sidecar never outgrows [`SIDECAR_MAX`].
pub fn reconcile(
    pickle: &[u8],
    previous: &HashMap<SkippedKey, u32>,
    today: u32,
) -> Result<HashMap<SkippedKey, u32>, Code> {
    Ok(skipped_keys(pickle)?
        .into_iter()
        .map(|key| {
            let day = previous.get(&key).copied().unwrap_or(today);
            (key, day)
        })
        .collect())
}

/// Keys present after a call that were not present before (their first-seen day is today).
pub fn added_keys(before: &[u8], after: &[u8]) -> Result<Vec<SkippedKey>, Code> {
    let old = skipped_keys(before)?;
    Ok(skipped_keys(after)?
        .into_iter()
        .filter(|k| !old.contains(k))
        .collect())
}

/// Removes every skipped key for which `drop_key` holds; the other entries keep their order.
/// Returns the edited pickle and the number of keys removed.
pub fn prune(
    pickle: &[u8],
    mut drop_key: impl FnMut(&SkippedKey) -> bool,
) -> Result<(Vec<u8>, usize), Code> {
    let mut value: Value = serde_json::from_slice(pickle).map_err(|_| Code::StateCorrupt)?;
    let mut removed = 0;
    for chain in chains_mut(&mut value)?.iter_mut() {
        let ratchet_key = chain
            .get("ratchet_key")
            .and_then(bytes32)
            .ok_or(Code::StateCorrupt)?;
        let keys = chain
            .pointer_mut("/skipped_message_keys/inner")
            .and_then(Value::as_array_mut)
            .ok_or(Code::StateCorrupt)?;
        let before = keys.len();
        let mut failed = false;
        keys.retain(|key| match key.get("index").and_then(Value::as_u64) {
            Some(index) => !drop_key(&SkippedKey { ratchet_key, index }),
            None => {
                failed = true;
                true
            }
        });
        if failed {
            return Err(Code::StateCorrupt);
        }
        removed += before - keys.len();
    }
    Ok((
        serde_json::to_vec(&value).map_err(|_| Code::StateCorrupt)?,
        removed,
    ))
}
