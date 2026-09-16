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
