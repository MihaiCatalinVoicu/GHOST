//! V-7: reorder loss against Olm's 40-skipped-keys window in seeded worlds (design §7.7).
//!
//! A sender writes a burst of messages on one receiver chain (no replies). Each message is stored
//! on every relay of the set at the sender's (relay, inbox) pair events: immediately in STANDARD,
//! after one `U[0, 10 min]` delay sampled per message and at most 8 stores per pair event in HIGH
//! (Phase 7 design §6.2). The recipient lists every relay at its own pair events (30 s × U[0.5,
//! 1.5], independent phases), fetches at most 8 blobs per pair event in blob-hash order
//! (`InboxStore.dueFetches`), and runs one consumer pass after every read event. Decryption uses a
//! real vodozemac 0.11.0 session with value semantics; a message is lost when the library returns
//! `MissingMessageKey`. [`predict_losses`] replays the same order against a model of the library's
//! rules, as a cross-check of what the declared bound must say.

use crate::codes::Code;
use crate::msc3814::DehydratedSecrets;
use crate::olm::{random_bytes, v11 as vz, x25519_public};
use rand::rngs::StdRng;
use rand::{Rng, RngExt, SeedableRng};
use std::collections::{BTreeSet, HashMap};

pub const MAX_SKIPPED: u64 = 40;
pub const HOLD_MAX_MS: u64 = 12 * 60 * 1000;
const PAIR_INTERVAL_MS: u64 = 30_000;
const FETCHES_PER_EVENT: usize = 8;
const STORES_PER_EVENT: usize = 8;
const MINUTE_MS: u64 = 60_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Standard,
    High,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Withholding {
    None,
    /// One relay of the set never serves the recipient.
    OneNever,
    /// One relay serves each blob up to 30 minutes late.
    OneLate,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Recipient {
    Online,
    /// Offline until an hour after the last store.
    Offline,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Policy {
    /// Phase 7 `Inbox.claim` in fetch order.
    ClaimOrder,
    /// `Inbox.peek` ordered by chain index (§7.7 point 1).
    Peek,
    /// Peek ordering plus the in-memory gap hold (§7.7 point 2).
    PeekHold,
    /// Peek ordering plus a gap hold that reads the expected index from the stored session.
    PeekHoldSession,
}

#[derive(Clone, Copy, Debug)]
pub struct World {
    pub messages: usize,
    pub mode: Mode,
    pub withholding: Withholding,
    pub recipient: Recipient,
    pub policy: Policy,
    /// Every consumer pass runs in a new process (a background job per pass).
    pub fresh_process_per_pass: bool,
    pub seed: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Result_ {
    pub displayed: usize,
    pub lost: usize,
    pub predicted_lost: usize,
    pub held_blobs: usize,
    pub max_display_delay_ms: u64,
    /// Display time minus fetch time: the delay the consumer itself adds.
    pub max_local_delay_ms: u64,
}

fn uniform(rng: &mut StdRng, low: u64, high: u64) -> u64 {
    rng.random_range(low..=high)
}

fn pair_events(rng: &mut StdRng, start: u64, horizon: u64) -> Vec<u64> {
    let mut out = Vec::new();
    let mut t = start + uniform(rng, 0, PAIR_INTERVAL_MS);
    while t <= horizon {
        out.push(t);
        t += uniform(rng, PAIR_INTERVAL_MS / 2, PAIR_INTERVAL_MS * 3 / 2);
    }
    out
}

/// A burst of `count` normal messages on one chain, and the recipient's session before them.
pub struct Burst {
    pub recipient_pickle: Vec<u8>,
    pub l1: Vec<Vec<u8>>,
    pub ratchet_key: [u8; 32],
}

pub fn burst(count: usize) -> Result<Burst, Code> {
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
    let (a_state, _) = vz::session_outbound(
        &a,
        &x25519_public(&b.curve25519),
        &x25519_public(&b_fallback),
    )?;
    let first = vz::encrypt(&a_state, b"hello")?;
    let inbound = vz::session_inbound(&b, &x25519_public(&a.curve25519), &first.l1)?;
    // B answers once so that A's burst is a new chain of normal messages.
    let reply = vz::encrypt(&inbound.pickle, b"reply")?;
    let mut a_state = vz::decrypt(&first.pickle, &reply.l1, false)?.pickle;
    let mut l1 = Vec::with_capacity(count);
    for i in 0..count {
        let out = vz::encrypt(&a_state, format!("m{i}").as_bytes())?;
        if out.is_prekey {
            return Err(Code::StateCorrupt);
        }
        a_state = out.pickle;
        l1.push(out.l1);
    }
    let ratchet_key = vz::parse(l1.first().ok_or(Code::StateCorrupt)?, false)?.ratchet_key();
    Ok(Burst {
        recipient_pickle: reply.pickle,
        l1,
        ratchet_key,
    })
}

/// Olm's receiver-chain rules without Olm: the chain position, a FIFO store of at most 40
/// skipped keys, and keys farther than 40 behind a decrypted index never stored.
pub fn predict_losses(order: &[u64]) -> Vec<bool> {
    let mut next: u64 = 0;
    let mut store: std::collections::VecDeque<u64> = std::collections::VecDeque::new();
    let mut lost = Vec::with_capacity(order.len());
    for &index in order {
        if index < next {
            if let Some(pos) = store.iter().position(|&k| k == index) {
                store.remove(pos);
                lost.push(false);
            } else {
                lost.push(true);
            }
            continue;
        }
        for skipped in next..index {
            if index - skipped <= MAX_SKIPPED {
                if store.len() as u64 == MAX_SKIPPED {
                    store.pop_front();
                }
                store.push_back(skipped);
            }
        }
        next = index + 1;
        lost.push(false);
    }
    lost
}

// Relay rows and message columns are indexed together (visible[relay][message]).
#[allow(clippy::needless_range_loop)]
pub fn run(world: &World, burst: &Burst) -> Result<Result_, Code> {
    let mut rng = StdRng::seed_from_u64(world.seed);
    let n = world.messages.min(burst.l1.len());
    let relays = 3usize;

    // Compose times and per-message store eligibility.
    let mut compose = Vec::with_capacity(n);
    let mut t = 0u64;
    for _ in 0..n {
        t += uniform(&mut rng, 1_000, 10_000);
        compose.push(t);
    }
    let not_before: Vec<u64> = compose
        .iter()
        .map(|&c| match world.mode {
            Mode::Standard => c,
            Mode::High => {
                (c + uniform(&mut rng, 0, 10 * MINUTE_MS)).div_ceil(MINUTE_MS) * MINUTE_MS
            }
        })
        .collect();
    let store_horizon = compose.last().copied().unwrap_or(0) + 30 * MINUTE_MS;

    // Store time per (relay, message).
    let mut stored = vec![vec![u64::MAX; n]; relays];
    for row in stored.iter_mut() {
        match world.mode {
            Mode::Standard => {
                for (slot, composed) in row.iter_mut().zip(&compose) {
                    *slot = composed + uniform(&mut rng, 200, 3_000);
                }
            }
            Mode::High => {
                let events = pair_events(&mut rng, 0, store_horizon);
                let mut pending: Vec<usize> = (0..n).collect();
                pending.sort_by_key(|&i| (not_before[i], i));
                for &event in &events {
                    let due: Vec<usize> = pending
                        .iter()
                        .copied()
                        .filter(|&i| not_before[i] <= event)
                        .take(STORES_PER_EVENT)
                        .collect();
                    for &i in &due {
                        row[i] = event + uniform(&mut rng, 200, 3_000);
                    }
                    pending.retain(|i| !due.contains(i));
                }
            }
        }
    }

    // What each relay shows the recipient, and when.
    let odd_relay = 2usize;
    let visible: Vec<Vec<Option<u64>>> = (0..relays)
        .map(|r| {
            (0..n)
                .map(|i| {
                    let s = stored[r][i];
                    if s == u64::MAX {
                        return None;
                    }
                    match (world.withholding, r == odd_relay) {
                        (Withholding::OneNever, true) => None,
                        (Withholding::OneLate, true) => {
                            Some(s + uniform(&mut rng, 0, 30 * MINUTE_MS))
                        }
                        _ => Some(s),
                    }
                })
                .collect()
        })
        .collect();
    let last_visible = visible
        .iter()
        .flatten()
        .flatten()
        .copied()
        .max()
        .unwrap_or(0);
    let hash: Vec<u64> = (0..n).map(|_| rng.next_u64()).collect();

    let read_start = match world.recipient {
        Recipient::Online => 0,
        Recipient::Offline => last_visible + 60 * MINUTE_MS,
    };
    let read_horizon = read_start.max(last_visible) + 90 * MINUTE_MS;
    let mut events: Vec<(u64, usize)> = Vec::new();
    for r in 0..relays {
        for e in pair_events(&mut rng, read_start, read_horizon) {
            events.push((e, r));
        }
    }
    events.sort();

    // Recipient state.
    let mut listed: Vec<BTreeSet<usize>> = vec![BTreeSet::new(); relays];
    let mut fetched_at: Vec<Option<u64>> = vec![None; n];
    let mut fetch_seq: Vec<usize> = Vec::new();
    let mut consumed = vec![false; n];
    let mut held_once = vec![false; n];
    let mut pickle = burst.recipient_pickle.clone();
    let mut highest: Option<u64> = None;
    let mut order: Vec<u64> = Vec::new();
    let mut outcome = Result_::default();
    let mut first_visible: HashMap<usize, u64> = HashMap::new();
    for i in 0..n {
        if let Some(v) = (0..relays).filter_map(|r| visible[r][i]).min() {
            first_visible.insert(i, v);
        }
    }

    for (now, r) in events {
        for i in 0..n {
            if visible[r][i].is_some_and(|v| v <= now) && fetched_at[i].is_none() {
                listed[r].insert(i);
            }
        }
        let mut candidates: Vec<usize> = listed[r]
            .iter()
            .copied()
            .filter(|&i| fetched_at[i].is_none())
            .collect();
        candidates.sort_by_key(|&i| hash[i]);
        for &i in candidates.iter().take(FETCHES_PER_EVENT) {
            fetched_at[i] = Some(now);
            fetch_seq.push(i);
        }

        // Consumer pass (a fresh process forgets the in-memory decrypted positions).
        if world.fresh_process_per_pass {
            highest = None;
        }
        let ready: Vec<usize> = fetch_seq
            .iter()
            .copied()
            .filter(|&i| !consumed[i])
            .collect();
        let mut ordered = ready.clone();
        if world.policy != Policy::ClaimOrder {
            ordered.sort();
        }
        let peek: BTreeSet<usize> = ready.iter().copied().collect();
        for i in ordered {
            let index = i as u64;
            // The first index the hold waits for: the process memory (PeekHold) or the stored
            // receiver chain of the message's ratchet key (PeekHoldSession; 0 for a new chain).
            let expected = match world.policy {
                Policy::PeekHold => highest.map(|h| h + 1),
                Policy::PeekHoldSession => Some(chain_next_index(&pickle, &burst.ratchet_key)?),
                Policy::ClaimOrder | Policy::Peek => None,
            };
            if let Some(next) = expected {
                let gap_missing =
                    index > next && (next..index).any(|m| !peek.contains(&(m as usize)));
                let first_seen = fetched_at[i].unwrap_or(now);
                if gap_missing && now < first_seen + HOLD_MAX_MS {
                    if !held_once[i] {
                        held_once[i] = true;
                        outcome.held_blobs += 1;
                    }
                    continue;
                }
            }
            consumed[i] = true;
            order.push(index);
            match vz::decrypt(&pickle, &burst.l1[i], false) {
                Ok(done) => {
                    pickle = done.pickle;
                    outcome.displayed += 1;
                    highest = Some(highest.map_or(index, |h| h.max(index)));
                    let delay = now.saturating_sub(first_visible.get(&i).copied().unwrap_or(now));
                    outcome.max_display_delay_ms = outcome.max_display_delay_ms.max(delay);
                    let local = now.saturating_sub(fetched_at[i].unwrap_or(now));
                    outcome.max_local_delay_ms = outcome.max_local_delay_ms.max(local);
                }
                Err(Code::DuplicateOrLost) => outcome.lost += 1,
                Err(other) => return Err(other),
            }
        }
    }
    outcome.predicted_lost = predict_losses(&order).iter().filter(|&&l| l).count();
    Ok(outcome)
}

/// The next chain index of the receiver chain of `ratchet_key` in a stored pickle (0 when the
/// session holds no such chain yet: every new chain starts at index 0).
pub fn chain_next_index(pickle: &[u8], ratchet_key: &[u8; 32]) -> Result<u64, Code> {
    let value: serde_json::Value =
        serde_json::from_slice(pickle).map_err(|_| Code::StateCorrupt)?;
    let chains = value
        .pointer("/receiving_chains/inner")
        .and_then(serde_json::Value::as_array)
        .ok_or(Code::StateCorrupt)?;
    for chain in chains {
        let key: Option<Vec<u8>> = chain
            .get("ratchet_key")
            .and_then(serde_json::Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|b| b.as_u64().and_then(|b| u8::try_from(b).ok()))
                    .collect()
            });
        if key.as_deref() == Some(ratchet_key.as_slice()) {
            return chain
                .pointer("/hkdf_ratchet/index")
                .and_then(serde_json::Value::as_u64)
                .ok_or(Code::StateCorrupt);
        }
    }
    Ok(0)
}
