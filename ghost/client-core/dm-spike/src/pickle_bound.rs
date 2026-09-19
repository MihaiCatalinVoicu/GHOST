//! V-4: the largest JSON session pickle a peer can cause (design §7.9 point 4).
//!
//! A real session is driven to the structural maximum (an active sending ratchet with a parent
//! key, 5 receiver chains, 40 skipped message keys in each), then every number is widened to its
//! longest JSON spelling: key bytes to `255` and every `u64` counter to `18446744073709551615`.
//! The widened pickle must still load, so the bound is a reachable encoding of the pinned
//! layout, not an estimate.

use crate::codes::Code;
use serde_json::Value;

/// Counts of the structural maximum reached by the driven session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Shape {
    pub receiver_chains: usize,
    pub skipped_keys_per_chain: [usize; 5],
    pub sending_active: bool,
    pub parent_key_present: bool,
}

pub fn shape(pickle: &[u8]) -> Result<Shape, Code> {
    let value: Value = serde_json::from_slice(pickle).map_err(|_| Code::StateCorrupt)?;
    let chains = value
        .pointer("/receiving_chains/inner")
        .and_then(Value::as_array)
        .ok_or(Code::StateCorrupt)?;
    let mut skipped = [0usize; 5];
    for (i, chain) in chains.iter().enumerate().take(5) {
        skipped[i] = chain
            .pointer("/skipped_message_keys/inner")
            .and_then(Value::as_array)
            .map_or(0, Vec::len);
    }
    let sending = value
        .pointer("/sending_ratchet")
        .ok_or(Code::StateCorrupt)?;
    Ok(Shape {
        receiver_chains: chains.len(),
        skipped_keys_per_chain: skipped,
        sending_active: sending.get("type").and_then(Value::as_str) == Some("active"),
        parent_key_present: sending
            .get("parent_ratchet_key")
            .is_some_and(Value::is_array),
    })
}

fn widen(value: &mut Value, key: Option<&str>) {
    match value {
        Value::Array(items) => {
            let byte_array = items.len() == 32 && items.iter().all(Value::is_u64);
            for item in items.iter_mut() {
                if byte_array {
                    *item = Value::from(255u8);
                } else {
                    widen(item, None);
                }
            }
        }
        Value::Object(map) => {
            for (k, v) in map.iter_mut() {
                widen(v, Some(k.as_str()));
            }
        }
        Value::Number(_) if matches!(key, Some("index") | Some("Known")) => {
            *value = Value::from(u64::MAX);
        }
        _ => {}
    }
}

/// The widened JSON of a driven pickle (every key byte 255, every counter `u64::MAX`).
pub fn widened(pickle: &[u8]) -> Result<Vec<u8>, Code> {
    let mut value: Value = serde_json::from_slice(pickle).map_err(|_| Code::StateCorrupt)?;
    widen(&mut value, None);
    serde_json::to_vec(&value).map_err(|_| Code::StateCorrupt)
}

/// The same bound computed from the layout alone (a cross-check of the widening).
pub fn analytic_bound(label_active_with_parent: bool) -> usize {
    let key = 1 + 32 * 3 + 31 + 1; // "[255,...,255]"
    let u64_max = 20;
    let known = r#"{"Known":}"#.len() + u64_max;
    let skipped = r#"{"key":,"index":}"#.len() + key + u64_max;
    let chain = r#"{"ratchet_key":,"hkdf_ratchet":{"key":,"index":},"skipped_message_keys":{"inner":[]},"ratchet_count":}"#.len()
        + key * 2
        + u64_max
        + 40 * skipped
        + 39
        + known;
    let session_keys = r#"{"identity_key":,"base_key":,"one_time_key":}"#.len() + 3 * key;
    let sending = if label_active_with_parent {
        r#"{"type":"active","parent_ratchet_key":,"ratchet_count":,"active_ratchet":{"root_key":,"ratchet_key":},"symmetric_key_ratchet":{"key":,"index":}}"#.len()
            + 4 * key
            + known
            + u64_max
    } else {
        0
    };
    r#"{"session_keys":,"sending_ratchet":,"receiving_chains":{"inner":[]},"config":{"version":"V1"}}"#.len()
        + session_keys
        + sending
        + 5 * chain
        + 4
}

macro_rules! bound_version {
    ($module:ident, $olm:path) => {
        pub mod $module {
            use crate::codes::Code;
            use crate::msc3814::DehydratedSecrets;
            use crate::olm::{random_bytes, x25519_public};
            use $olm as olm;

            /// Drives a responder session to 5 receiver chains × 40 skipped keys and an active
            /// sending ratchet. Returns the responder's pickle.
            pub fn drive() -> Result<Vec<u8>, Code> {
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
                let (mut a_state, _) = olm::session_outbound(
                    &a,
                    &x25519_public(&b.curve25519),
                    &x25519_public(&b_fallback),
                )?;
                let first = olm::encrypt(&a_state, b"0")?;
                a_state = first.pickle;
                let mut b_state =
                    olm::session_inbound(&b, &x25519_public(&a.curve25519), &first.l1)?.pickle;
                for _round in 0..5 {
                    // A sends 41 messages on its current chain; B receives only the last one,
                    // which stores the 40 keys before it.
                    let mut last = None;
                    for _ in 0..41 {
                        let out = olm::encrypt(&a_state, b"m")?;
                        a_state = out.pickle;
                        last = Some((out.l1, out.is_prekey));
                    }
                    let (l1, is_prekey) = last.ok_or(Code::StateCorrupt)?;
                    b_state = olm::decrypt(&b_state, &l1, is_prekey)?.pickle;
                    // B answers, A receives: A's next message starts a new chain.
                    let reply = olm::encrypt(&b_state, b"r")?;
                    b_state = reply.pickle;
                    a_state = olm::decrypt(&a_state, &reply.l1, reply.is_prekey)?.pickle;
                }
                // Leave B's sending ratchet active with a parent key.
                Ok(olm::encrypt(&b_state, b"final")?.pickle)
            }

            /// The widened pickle still loads, and the library re-serialises it to the same JSON
            /// value and the same length (the widening sorts object keys; the library does not).
            pub fn loads_unchanged(json: &[u8]) -> Result<bool, Code> {
                let stored = olm::store(&olm::load(json)?)?;
                let a: serde_json::Value =
                    serde_json::from_slice(json).map_err(|_| Code::StateCorrupt)?;
                let b: serde_json::Value =
                    serde_json::from_slice(&stored).map_err(|_| Code::StateCorrupt)?;
                Ok(a == b && stored.len() == json.len())
            }
        }
    };
}

bound_version!(v11, crate::olm::v11);
bound_version!(v10, crate::olm::v10);
