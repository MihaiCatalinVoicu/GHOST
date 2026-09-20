//! The stored session state: a vodozemac pickle plus the **first-seen sidecar** of §7.7 point 4,
//! both inside one wrapped envelope (`olm_session.state_env`, §2.5).
//!
//! ```text
//! state   = u32_be(pickle_len) || pickle || sidecar
//! sidecar = u8(chains) || per chain: ratchet_key(32) || u8(n)
//!                                    || n x (u64_be chain_index || u32_be first_seen_day)
//! ```
//!
//! **The sidecar is a projection, not a log.** It is rebuilt at every store as a projection of the
//! stored pickle: it holds exactly the `(ratchet_key, chain_index)` pairs the pickle holds, each
//! keeping the day already recorded for it, a pair not recorded before taking the call's day.
//! Nothing else adds or removes entries, so the keys and chains vodozemac evicts on its own (its
//! 40-key FIFO, its 5-chain limit) leave the sidecar with them, and its size is
//! [`SIDECAR_MAX`] = 2 566 B **by construction** — an insert-only "log of additions" has no bound
//! at all and was measured in S0′ to outgrow the pickle (V-15).
//!
//! **No clock.** `today` is an argument of every state-storing call (`encrypt`, `decrypt`,
//! `sessionInbound`, `sessionPrune`), because this crate reads no clock and because vodozemac's
//! own state holds no time at all (T33). The day index is the caller's; the sidecar is the only
//! place a DM session state records one, and it is erased with the session.

use crate::olm::pickle::{self, SkippedKey};
use crate::result::{DmCode, DmResult};

/// Largest first-seen sidecar of one session, from Olm's own limits (V-15).
pub const SIDECAR_MAX: usize =
    1 + pickle::MAX_RECEIVING_CHAINS * (32 + 1 + pickle::MAX_MESSAGE_KEYS * (8 + 4));

/// `SESSION_STATE_MAX`, frozen by S0′ (V-4): the largest JSON pickle of 0.11.0 and 0.10.0 is
/// 36 685 B and the worst pickle plus sidecar is 39 251 B, so the stored state has 26 285 B to
/// spare. `OVERSIZE` therefore signals a bug or a format change at a bump, never a peer's doing
/// (§7.9 point 4).
///
/// **Deviation, recorded:** §7.9 point 4 states the bound as "bytes of pickle" and its arithmetic
/// adds the sidecar to it (39 251 = 36 685 + 2 566, "with 26 285 B to spare" = 65 536 − 39 251).
/// This module therefore bounds `pickle + sidecar + framing`, which is what
/// `olm_session.state_env`'s CHECK (29 … 65 564 = 65 536 + 28 bytes of wrap overhead) admits; the
/// four framing bytes count toward the budget rather than beside it.
pub const SESSION_STATE_MAX: usize = 65_536;

const LENGTH_PREFIX: usize = 4;

/// One encoded chain of the sidecar: its ratchet key and the `(chain_index, first_seen_day)` pairs
/// of the skipped keys it holds.
type SidecarChain = ([u8; 32], Vec<(u64, u32)>);

/// The first-seen day of every skipped key of a session, in the pickle's own order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Sidecar {
    entries: Vec<(SkippedKey, u32)>,
}

impl Sidecar {
    /// An empty sidecar (a session that has skipped nothing).
    pub fn new() -> Self {
        Self::default()
    }

    /// The recorded first-seen day of a key, if it has one.
    pub fn day_of(&self, key: &SkippedKey) -> Option<u32> {
        self.entries
            .iter()
            .find(|(stored, _)| stored == key)
            .map(|(_, day)| *day)
    }

    /// The keys it records, in stored order.
    pub fn keys(&self) -> Vec<SkippedKey> {
        self.entries.iter().map(|(key, _)| *key).collect()
    }

    /// Number of recorded keys.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether it records nothing.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The projection rule: exactly the pairs `pickle` holds, each keeping the day already
    /// recorded for it, a pair not recorded before taking `today`.
    pub fn reconcile(previous: &Sidecar, pickle_bytes: &[u8], today: u32) -> DmResult<Self> {
        let entries = pickle::skipped_keys(pickle_bytes)?
            .into_iter()
            .map(|key| {
                let day = previous.day_of(&key).unwrap_or(today);
                (key, day)
            })
            .collect();
        Ok(Self { entries })
    }

    /// Keys older than `today - max_age`, in stored order. `today` before a recorded day (a clock
    /// that moved backwards) prunes nothing: the expiry clock never runs backwards (§10.1).
    pub fn expired(&self, today: u32, max_age: u32) -> Vec<SkippedKey> {
        self.entries
            .iter()
            .filter(|(_, day)| today >= day.saturating_add(max_age))
            .map(|(key, _)| *key)
            .collect()
    }

    fn encode(&self) -> DmResult<Vec<u8>> {
        // Grouped by chain, in first-appearance order, which is the pickle's chain order.
        let mut chains: Vec<SidecarChain> = Vec::new();
        for (key, day) in &self.entries {
            match chains.iter_mut().find(|(rk, _)| rk == &key.ratchet_key) {
                Some((_, keys)) => keys.push((key.index, *day)),
                None => chains.push((key.ratchet_key, vec![(key.index, *day)])),
            }
        }
        if chains.len() > pickle::MAX_RECEIVING_CHAINS {
            return Err(DmCode::StateCorrupt);
        }
        let mut out = Vec::with_capacity(SIDECAR_MAX);
        out.push(u8::try_from(chains.len()).map_err(|_| DmCode::StateCorrupt)?);
        for (ratchet_key, keys) in chains {
            if keys.len() > pickle::MAX_MESSAGE_KEYS {
                return Err(DmCode::StateCorrupt);
            }
            out.extend_from_slice(&ratchet_key);
            out.push(u8::try_from(keys.len()).map_err(|_| DmCode::StateCorrupt)?);
            for (index, day) in keys {
                out.extend_from_slice(&index.to_be_bytes());
                out.extend_from_slice(&day.to_be_bytes());
            }
        }
        Ok(out)
    }

    fn decode(bytes: &[u8]) -> DmResult<Self> {
        let mut cursor = 0usize;
        let mut take = |n: usize| -> DmResult<&[u8]> {
            let end = cursor.checked_add(n).ok_or(DmCode::StateCorrupt)?;
            let slice = bytes.get(cursor..end).ok_or(DmCode::StateCorrupt)?;
            cursor = end;
            Ok(slice)
        };
        let chains = usize::from(take(1)?[0]);
        if chains > pickle::MAX_RECEIVING_CHAINS {
            return Err(DmCode::StateCorrupt);
        }
        let mut entries = Vec::new();
        for _ in 0..chains {
            let mut ratchet_key = [0u8; 32];
            ratchet_key.copy_from_slice(take(32)?);
            let count = usize::from(take(1)?[0]);
            if count > pickle::MAX_MESSAGE_KEYS {
                return Err(DmCode::StateCorrupt);
            }
            for _ in 0..count {
                let index =
                    u64::from_be_bytes(take(8)?.try_into().map_err(|_| DmCode::StateCorrupt)?);
                let day =
                    u32::from_be_bytes(take(4)?.try_into().map_err(|_| DmCode::StateCorrupt)?);
                entries.push((SkippedKey { ratchet_key, index }, day));
            }
        }
        if cursor != bytes.len() {
            return Err(DmCode::StateCorrupt);
        }
        Ok(Self { entries })
    }
}

/// A decoded session state: the library's pickle and GHOST's sidecar beside it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionState {
    /// The vodozemac JSON pickle.
    pub pickle: Vec<u8>,
    /// The first-seen days of its skipped keys.
    pub sidecar: Sidecar,
}

impl SessionState {
    /// Builds a state for a pickle, reconciling `previous`'s days into it (the store path of every
    /// state-writing call).
    pub fn build(previous: &Sidecar, pickle: Vec<u8>, today: u32) -> DmResult<Self> {
        let sidecar = Sidecar::reconcile(previous, &pickle, today)?;
        Ok(Self { pickle, sidecar })
    }

    /// The bytes that go inside the wrapped envelope.
    pub fn encode(&self) -> DmResult<Vec<u8>> {
        let sidecar = self.sidecar.encode()?;
        let length = u32::try_from(self.pickle.len()).map_err(|_| DmCode::Oversize)?;
        let total = LENGTH_PREFIX
            .checked_add(self.pickle.len())
            .and_then(|n| n.checked_add(sidecar.len()))
            .ok_or(DmCode::Oversize)?;
        if total > SESSION_STATE_MAX {
            return Err(DmCode::Oversize);
        }
        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(&length.to_be_bytes());
        out.extend_from_slice(&self.pickle);
        out.extend_from_slice(&sidecar);
        Ok(out)
    }

    /// Decodes stored bytes. Anything that does not parse exactly is [`DmCode::StateCorrupt`].
    pub fn decode(bytes: &[u8]) -> DmResult<Self> {
        let prefix = bytes.get(..LENGTH_PREFIX).ok_or(DmCode::StateCorrupt)?;
        let length = usize::try_from(u32::from_be_bytes(
            prefix.try_into().map_err(|_| DmCode::StateCorrupt)?,
        ))
        .map_err(|_| DmCode::StateCorrupt)?;
        let end = LENGTH_PREFIX
            .checked_add(length)
            .ok_or(DmCode::StateCorrupt)?;
        let pickle = bytes
            .get(LENGTH_PREFIX..end)
            .ok_or(DmCode::StateCorrupt)?
            .to_vec();
        let sidecar = Sidecar::decode(bytes.get(end..).ok_or(DmCode::StateCorrupt)?)?;
        Ok(Self { pickle, sidecar })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pickle_with(chains: &[([u8; 32], &[u64])]) -> Vec<u8> {
        let entries: Vec<serde_json::Value> = chains
            .iter()
            .map(|(ratchet_key, skipped)| {
                let keys: Vec<serde_json::Value> = skipped
                    .iter()
                    .map(|index| serde_json::json!({ "key": vec![1u8; 32], "index": index }))
                    .collect();
                serde_json::json!({
                    "ratchet_key": ratchet_key.to_vec(),
                    "hkdf_ratchet": { "key": vec![2u8; 32], "index": 0 },
                    "skipped_message_keys": { "inner": keys },
                })
            })
            .collect();
        serde_json::to_vec(&serde_json::json!({ "receiving_chains": { "inner": entries } }))
            .expect("json")
    }

    #[test]
    fn the_sidecar_bound_is_the_design_number() {
        assert_eq!(SIDECAR_MAX, 2_566);
        assert_eq!(36_685 + SIDECAR_MAX, 39_251);
        assert_eq!(SESSION_STATE_MAX - 39_251, 26_285);
    }

    /// RO6: after every call the sidecar's key set equals the pickle's.
    #[test]
    fn the_sidecar_is_a_projection_of_the_pickle() {
        let first = pickle_with(&[([0xaa; 32], &[1, 2])]);
        let state = SessionState::build(&Sidecar::new(), first, 100).expect("build");
        assert_eq!(
            state.sidecar.keys(),
            pickle::skipped_keys(&state.pickle).expect("keys")
        );
        assert_eq!(state.sidecar.len(), 2);

        // A later call: one key used up, one new key, a whole chain evicted and a new one added.
        let second = pickle_with(&[([0xaa; 32], &[2, 7]), ([0xbb; 32], &[4])]);
        let next = SessionState::build(&state.sidecar, second, 140).expect("build");
        assert_eq!(
            next.sidecar.keys(),
            pickle::skipped_keys(&next.pickle).expect("keys")
        );
        // Kept days for keys that were already there, today for the new ones.
        assert_eq!(
            next.sidecar.day_of(&SkippedKey {
                ratchet_key: [0xaa; 32],
                index: 2
            }),
            Some(100)
        );
        assert_eq!(
            next.sidecar.day_of(&SkippedKey {
                ratchet_key: [0xaa; 32],
                index: 7
            }),
            Some(140)
        );
        assert_eq!(
            next.sidecar.day_of(&SkippedKey {
                ratchet_key: [0xbb; 32],
                index: 4
            }),
            Some(140)
        );
        // The key the library dropped left the sidecar with it: no unbounded log.
        assert_eq!(
            next.sidecar.day_of(&SkippedKey {
                ratchet_key: [0xaa; 32],
                index: 1
            }),
            None
        );
    }

    /// The bound holds for the worst shape Olm admits, and the encoding is exactly `SIDECAR_MAX`.
    #[test]
    fn the_worst_shape_encodes_to_the_bound() {
        let indices: Vec<u64> = (0..pickle::MAX_MESSAGE_KEYS as u64).collect();
        let chains: Vec<([u8; 32], &[u64])> = (0..pickle::MAX_RECEIVING_CHAINS)
            .map(|i| ([i as u8; 32], indices.as_slice()))
            .collect();
        let pickle_bytes = pickle_with(&chains);
        let state = SessionState::build(&Sidecar::new(), pickle_bytes, 7).expect("build");
        assert_eq!(state.sidecar.len(), 200);
        assert_eq!(state.sidecar.encode().expect("encode").len(), SIDECAR_MAX);
    }

    #[test]
    fn a_state_round_trips_and_refuses_anything_else() {
        let pickle_bytes = pickle_with(&[([0xaa; 32], &[5])]);
        let state = SessionState::build(&Sidecar::new(), pickle_bytes, 11).expect("build");
        let encoded = state.encode().expect("encode");
        assert_eq!(SessionState::decode(&encoded).expect("decode"), state);
        for len in 0..encoded.len() {
            assert_eq!(
                SessionState::decode(&encoded[..len]).err(),
                Some(DmCode::StateCorrupt),
                "length {len}"
            );
        }
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(
            SessionState::decode(&trailing).err(),
            Some(DmCode::StateCorrupt)
        );
    }

    #[test]
    fn a_state_larger_than_the_maximum_is_oversize() {
        let state = SessionState {
            pickle: vec![0x7b; SESSION_STATE_MAX],
            sidecar: Sidecar::new(),
        };
        assert_eq!(state.encode().err(), Some(DmCode::Oversize));
    }

    #[test]
    fn expiry_uses_the_recorded_day_and_never_runs_backwards() {
        let pickle_bytes = pickle_with(&[([0xaa; 32], &[1, 2])]);
        let state = SessionState::build(&Sidecar::new(), pickle_bytes, 100).expect("build");
        assert!(state.sidecar.expired(150, 51).is_empty());
        assert_eq!(state.sidecar.expired(151, 51).len(), 2);
        // A day index before the recorded one prunes nothing.
        assert!(state.sidecar.expired(0, 51).is_empty());
    }
}
