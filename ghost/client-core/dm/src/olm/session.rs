//! The Olm session calls of design §8.1, with GHOST's value semantics (§7.9).
//!
//! **Value semantics (§7.9 point 1).** Every call receives stored state and returns new state;
//! nothing is cached across calls or transactions. Kotlin writes returned state only inside the
//! calling transaction, and only on `OK`.
//!
//! **vodozemac is not all-or-nothing in memory, and GHOST does not rely on it being so**
//! (§7.9 point 2, RX-1). For a message with an unknown ratchet key, `Session::decrypt` activates
//! an *inactive* sending ratchet with a fresh random ratchet key **before** the decryption can
//! fail (`vz:src/olm/session/double_ratchet.rs:168-191`). Because every function here unpickles a
//! fresh `Session` and drops it on any non-`OK` result, stored state never contains the activation
//! of a failed attempt — V-10, `a_failed_decrypt_leaves_the_stored_state_byte_identical`, whose
//! forgery names a ratchet key the receiver does **not** hold, so the activation really is reached;
//! `a_failed_decrypt_does_change_the_object_it_left_behind` is mutant MC-29 itself and shows the
//! byte comparison is falsifiable. Persisting the activated object would let a forged,
//! relay-injectable blob change stored state (T28).
//!
//! **No clock.** `today` is an argument, because the first-seen sidecar of §7.7 point 4 is rebuilt
//! on every state-storing call and this crate reads no clock.
//!
//! **Trust is the caller's (§8.2).** These functions take the pinned identity as an argument and
//! never decide trust: `sessionOutbound` is called only with the pinned `OI`, `sessionInbound`
//! only with the pinned `OI` or one just pinned under a valid binding in the same transaction, and
//! no session row exists for a `changed`, `blocked` or `revoked` contact. The selection rules
//! R-SS0 … R-SS5 live where the rows live (`:messaging`, slice S7); what belongs here is the
//! two-slot trial of [`decrypt`] and the codes it reports.

use crate::derive::{OlmSecret, ReplySeed, SECRET_BYTES};
use crate::olm::account::{self, AccountSecrets};
use crate::olm::message::{self, L1Header, SESSION_ID_BYTES};
use crate::olm::pickle::{self, ChainPosition, SkippedKey};
use crate::olm::state::{SessionState, Sidecar};
use crate::pq;
use crate::result::{DmCode, DmResult};
use vodozemac::olm::{Session, SessionConfig, SessionPickle};
use vodozemac::Curve25519PublicKey;

/// The skipped-key age bound of §7.7 point 4: `FRESH + 2σ` = 45 d + 6 d.
pub const SKIPPED_KEY_MAX_AGE_DAYS: u32 = 51;

/// Which stored slot a message decrypted on (§8.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Slot {
    /// `current`: the slot every send uses.
    Current,
    /// `previous`: receive only, with a `retire_day`.
    Previous,
}

impl Slot {
    /// The wire byte of the slot, for the JNI reply.
    pub const fn as_u8(self) -> u8 {
        match self {
            Slot::Current => 0,
            Slot::Previous => 1,
        }
    }
}

/// A new outbound session (§2.6 function 7).
pub struct Outbound {
    /// The state to store in `olm_session.state_env`.
    pub state: Vec<u8>,
    /// The raw session id for `olm_session.session_id`.
    pub session_id: [u8; SESSION_ID_BYTES],
    /// The fresh `reply_seed` provisional mode is keyed from (§6.7); the caller wraps it.
    pub reply_seed: ReplySeed,
}

/// The result of [`encrypt`] (§2.6 function 8).
pub struct Encrypted {
    /// The Olm message bytes.
    pub l1: Vec<u8>,
    /// Whether the library produced a PreKey message.
    pub is_pre_key: bool,
    /// The state to store.
    pub state: Vec<u8>,
    /// Whether the peer has answered this session.
    pub acknowledged: bool,
}

/// The result of [`decrypt`] (§2.6 function 13).
pub struct Decrypted {
    /// Which stored slot decrypted the message.
    pub slot: Slot,
    /// The L0 content bytes.
    pub plaintext: Vec<u8>,
    /// The state of that slot, to store.
    pub state: Vec<u8>,
    /// Whether the session is now acknowledged.
    pub acknowledged: bool,
}

/// The result of [`session_inbound`] (§2.6 function 14).
pub struct Inbound {
    /// The state of the created session.
    pub state: Vec<u8>,
    /// Its raw session id.
    pub session_id: [u8; SESSION_ID_BYTES],
    /// The L0 content of the first flight.
    pub plaintext: Vec<u8>,
}

/// One stored slot handed to [`decrypt`].
pub struct StoredSession<'a> {
    /// The slot this state came from.
    pub slot: Slot,
    /// The stored `state_env` plaintext.
    pub state: &'a [u8],
}

/// Decodes a stored state into a live `Session` and the sidecar beside it.
///
/// The decoded JSON pickle is the session's root key, chain keys and skipped message keys in the
/// clear; it is zeroised as soon as vodozemac has parsed it, so the plaintext state lives on the
/// heap for one `serde_json::from_slice` and no longer.
fn load(state: &[u8]) -> DmResult<(Session, Sidecar)> {
    let mut decoded = SessionState::decode(state)?;
    let parsed: Result<SessionPickle, _> = serde_json::from_slice(&decoded.pickle);
    decoded.zeroize_pickle();
    let parsed = parsed.map_err(|_| DmCode::StateCorrupt)?;
    Ok((Session::from_pickle(parsed), decoded.sidecar))
}

/// Serialises a session and its reconciled sidecar into the plaintext of `state_env`, zeroising
/// the intermediate pickle for the same reason.
fn store(session: &Session, previous: &Sidecar, today: u32) -> DmResult<Vec<u8>> {
    let pickle = serde_json::to_vec(&session.pickle()).map_err(|_| DmCode::StateCorrupt)?;
    let mut state = SessionState::build(previous, pickle, today)?;
    let encoded = state.encode();
    state.zeroize_pickle();
    encoded
}

fn session_id_of(session: &Session) -> DmResult<[u8; SESSION_ID_BYTES]> {
    message::session_id_bytes(&session.session_id())
}

/// The store of a function whose §2.6 row does **not** list `OVERSIZE`.
///
/// Only function 8 (`encrypt`) may report it, and the typed facade's `when` arms mirror the table
/// row by row: an `OVERSIZE` from `sessionOutbound`, `decrypt`, `sessionInbound` or `sessionPrune`
/// would reach `DmSessions.unexpected` and throw instead of producing an outcome. The state is one
/// this crate cannot work with either way, so those paths report [`DmCode::StateCorrupt`]; with
/// 26 285 B of spare (§7.9 point 4) the case means a bug or a format change, never a peer's doing.
fn stored_state(state: DmResult<Vec<u8>>) -> DmResult<Vec<u8>> {
    state.map_err(|code| match code {
        DmCode::Oversize => DmCode::StateCorrupt,
        other => other,
    })
}

/// `sessionOutbound` (§2.6 function 7, §8.1): a throwaway account from the own identity runs
/// Olm's 3DH to the peer's identity and fallback key with a fresh base key.
///
/// A malformed or non-contributory peer key is [`DmCode::InvalidKey`] (§22.8.2 rule 1): the
/// contact published a key no session can be built on, which is a refusal, not a crash.
pub fn session_outbound(
    identity: &OlmSecret,
    signing_seed: &OlmSecret,
    peer_identity: &[u8; 32],
    peer_fallback: &[u8; 32],
    today: u32,
) -> DmResult<Outbound> {
    if !pq::contributory(peer_identity) || !pq::contributory(peer_fallback) {
        return Err(DmCode::InvalidKey);
    }
    let secrets = AccountSecrets::identity(identity, signing_seed);
    let session = account::with_account(&secrets, |account| {
        account
            .create_outbound_session(
                SessionConfig::version_1(),
                Curve25519PublicKey::from_bytes(*peer_identity),
                Curve25519PublicKey::from_bytes(*peer_fallback),
            )
            .map_err(|error| message::creation_code(&error))
    })?;

    let mut seed = [0u8; SECRET_BYTES];
    pq::fill_random(&mut seed);
    Ok(Outbound {
        state: stored_state(store(&session, &Sidecar::new(), today))?,
        session_id: session_id_of(&session)?,
        reply_seed: ReplySeed::from_bytes(seed),
    })
}

/// `encrypt` (§2.6 function 8): one ratchet step on the `current` slot.
///
/// The returned state exists only on success, so a failed step never commits (CS-1 rests on the
/// transaction, this rests on the value).
pub fn encrypt(state: &[u8], l0: &[u8], today: u32) -> DmResult<Encrypted> {
    let (mut session, sidecar) = load(state)?;
    let message = session
        .encrypt(l0)
        .map_err(|error| message::encryption_code(&error))?;
    let (kind, l1) = message.to_parts();
    Ok(Encrypted {
        l1,
        is_pre_key: kind == message::MESSAGE_TYPE_PRE_KEY,
        state: store(&session, &sidecar, today)?,
        acknowledged: session.has_received_message(),
    })
}

/// `decrypt` (§2.6 function 13): the two-slot trial of §7.6.
///
/// When one slot reports a missing message key and the other a MAC or key failure, the result is
/// [`DmCode::DuplicateOrLost`]: a replay must not be counted as a forgery. Only the slot that
/// succeeded returns state; the other object is dropped unread, so a failed attempt on `previous`
/// cannot leave an activated sending ratchet behind (§7.9 point 2).
pub fn decrypt(
    slots: &[StoredSession<'_>],
    l1: &[u8],
    is_pre_key: bool,
    today: u32,
) -> DmResult<Decrypted> {
    let parsed = message::decode(l1, is_pre_key)?;
    let mut worst: Option<DmCode> = None;
    for stored in slots {
        let (mut session, sidecar) = load(stored.state)?;
        match session.decrypt(&parsed) {
            Ok(plaintext) => {
                return Ok(Decrypted {
                    slot: stored.slot,
                    plaintext,
                    state: stored_state(store(&session, &sidecar, today))?,
                    acknowledged: session.has_received_message(),
                });
            }
            Err(error) => {
                let code = message::decryption_code(&error);
                worst = Some(match worst {
                    None => code,
                    Some(previous) => combine(previous, code),
                });
            }
        }
    }
    Err(worst.unwrap_or(DmCode::Undecryptable))
}

/// A replay seen on one slot and a forgery-looking failure on the other is a replay (§7.6).
/// `GAP_TOO_BIG` outranks both: it names a real limit the caller reports to the user.
const fn combine(left: DmCode, right: DmCode) -> DmCode {
    match (left, right) {
        (DmCode::GapTooBig, _) | (_, DmCode::GapTooBig) => DmCode::GapTooBig,
        (DmCode::DuplicateOrLost, _) | (_, DmCode::DuplicateOrLost) => DmCode::DuplicateOrLost,
        _ => DmCode::Undecryptable,
    }
}

/// `sessionInbound` (§2.6 function 14, §8.1): a throwaway account holding exactly generation `g`'s
/// fallback secret runs `create_inbound_session`, which refuses another identity, recomputes the
/// 3DH and decrypts the first message before returning.
///
/// The §22.8.2 pre-check runs first: a non-contributory inner ratchet key is [`DmCode::InvalidKey`]
/// rather than a library panic path.
pub fn session_inbound(
    identity: &OlmSecret,
    signing_seed: &OlmSecret,
    generation_fallback: [u8; SECRET_BYTES],
    expected_peer_identity: &[u8; 32],
    l1: &[u8],
    today: u32,
) -> DmResult<Inbound> {
    let header = message::parse(l1, true)?;
    if !header.is_pre_key() {
        return Err(DmCode::NonCanonical);
    }
    if !pq::contributory(&header.ratchet_key()) {
        return Err(DmCode::InvalidKey);
    }
    if !pq::contributory(expected_peer_identity) {
        return Err(DmCode::InvalidKey);
    }
    let pre_key = message::decode_pre_key(l1)?;
    let secrets = AccountSecrets::with_fallback(identity, signing_seed, generation_fallback);
    let created = account::with_account(&secrets, |account| {
        account
            .create_inbound_session(
                SessionConfig::version_1(),
                Curve25519PublicKey::from_bytes(*expected_peer_identity),
                &pre_key,
            )
            .map_err(|error| message::creation_code(&error))
    })?;
    Ok(Inbound {
        state: stored_state(store(&created.session, &Sidecar::new(), today))?,
        session_id: session_id_of(&created.session)?,
        plaintext: created.plaintext,
    })
}

/// `chainPosition` (§2.6 function 19): the gap hold's expected index, read from the stored state.
/// It writes nothing (T28) and is called during peek, outside any transaction.
pub fn chain_position(state: &[u8], ratchet_key: &[u8; 32]) -> DmResult<ChainPosition> {
    let mut decoded = SessionState::decode(state)?;
    let position = pickle::chain_position(&decoded.pickle, ratchet_key);
    decoded.zeroize_pickle();
    position
}

/// `sessionPrune` (§2.6 function 20, §7.7 point 4): SWEEP's age bound on the skipped keys of a
/// live session. Returns the new state, with a **reconciled** sidecar, and the pruned count.
///
/// The keys removed are exactly those whose recorded first-seen day is at least
/// [`SKIPPED_KEY_MAX_AGE_DAYS`] old; the reconciliation afterwards drops their sidecar entries
/// with them, so the projection property of §7.7 point 4 holds after a prune as after any store.
pub fn session_prune(state: &[u8], today: u32) -> DmResult<(Vec<u8>, usize)> {
    let mut decoded = SessionState::decode(state)?;
    let expired: Vec<SkippedKey> = decoded.sidecar.expired(today, SKIPPED_KEY_MAX_AGE_DAYS);
    let pruned = pickle::prune(&decoded.pickle, |key| expired.contains(key));
    decoded.zeroize_pickle();
    let (pickle, removed) = pruned?;
    // A prune is a store: the sidecar is rebuilt as a projection of the pickle it just edited, and
    // a key that survives keeps the day it already had.
    let mut next = SessionState::build(&decoded.sidecar, pickle, today)?;
    let encoded = next.encode();
    next.zeroize_pickle();
    Ok((stored_state(encoded)?, removed))
}

/// The L1 header of a message, for the seal-opening functions that hand it to Kotlin.
pub fn header(l1: &[u8], is_pre_key: bool) -> DmResult<L1Header> {
    message::parse(l1, is_pre_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::derive::MessagingBranch;

    struct Party {
        identity: OlmSecret,
        signing: OlmSecret,
        identity_public: [u8; 32],
    }

    fn party(tag: u8) -> Party {
        let branch = MessagingBranch::from_bytes([tag; 32]);
        let identity = crate::derive::derive_olm_identity(&branch);
        let signing = crate::derive::derive_olm_account_signing(&branch);
        let identity_public = crate::derive::olm_identity_public(&identity);
        Party {
            identity,
            signing,
            identity_public,
        }
    }

    fn fallback(tag: u8) -> ([u8; 32], [u8; 32]) {
        let secret = [tag; 32];
        let public = crate::derive::olm_identity_public(&OlmSecret::from_bytes(secret));
        (secret, public)
    }

    /// A → B first flight, B answers, A reads the answer: the whole round trip on real state.
    fn round_trip() -> (Vec<u8>, Vec<u8>) {
        let a = party(1);
        let b = party(2);
        let (b_fallback_secret, b_fallback_public) = fallback(3);

        let outbound = session_outbound(
            &a.identity,
            &a.signing,
            &b.identity_public,
            &b_fallback_public,
            10,
        )
        .expect("outbound");
        let first = encrypt(&outbound.state, b"hello", 10).expect("encrypt");
        assert!(first.is_pre_key);
        assert!(!first.acknowledged);

        let inbound = session_inbound(
            &b.identity,
            &b.signing,
            b_fallback_secret,
            &a.identity_public,
            &first.l1,
            10,
        )
        .expect("inbound");
        assert_eq!(inbound.plaintext, b"hello");
        assert_eq!(inbound.session_id, outbound.session_id);

        let reply = encrypt(&inbound.state, b"hi back", 11).expect("reply");
        assert!(!reply.is_pre_key);
        let read = decrypt(
            &[StoredSession {
                slot: Slot::Current,
                state: &first.state,
            }],
            &reply.l1,
            reply.is_pre_key,
            11,
        )
        .expect("decrypt");
        assert_eq!(read.plaintext, b"hi back");
        assert_eq!(read.slot, Slot::Current);
        assert!(read.acknowledged);
        (read.state, reply.state)
    }

    #[test]
    fn a_session_round_trips_on_real_state() {
        round_trip();
    }

    /// The scene V-10 and MC-29 need: A's session after its first flight, B's session as
    /// `sessionInbound` left it — with an **inactive** sending ratchet — and a normal message whose
    /// ratchet key B has never seen.
    ///
    /// The unknown key is what matters: a forgery on a key B already holds as a receiver chain
    /// takes `receiving_chains.find_ratchet`'s hit path and never touches the sending ratchet,
    /// while a message with an unknown one reaches `sending_ratchet.advance`
    /// (`vz:src/olm/session/double_ratchet.rs:168-191`), the only place an inactive ratchet is
    /// activated in place, **before** the decryption can fail.
    struct Forgery {
        /// A's state after sending its first flight; it reads B's normal messages.
        initiator: Vec<u8>,
        /// B's state as stored, sending ratchet inactive.
        responder: Vec<u8>,
        /// A normal message of another pair: a well-formed message on an unknown ratchet key.
        unknown_chain: Vec<u8>,
    }

    fn forgery_scene(tag: u8) -> Forgery {
        let a = party(tag);
        let b = party(tag + 1);
        let (b_fallback_secret, b_fallback_public) = fallback(tag + 2);
        let outbound = session_outbound(
            &a.identity,
            &a.signing,
            &b.identity_public,
            &b_fallback_public,
            1,
        )
        .expect("outbound");
        let first = encrypt(&outbound.state, b"one", 1).expect("encrypt");
        let inbound = session_inbound(
            &b.identity,
            &b.signing,
            b_fallback_secret,
            &a.identity_public,
            &first.l1,
            1,
        )
        .expect("inbound");

        // Another pair's settled session: its reply is a normal message with a ratchet key that is
        // not one of B's receiver chains.
        let c = party(tag + 3);
        let d = party(tag + 4);
        let (d_fallback_secret, d_fallback_public) = fallback(tag + 5);
        let other = session_outbound(
            &c.identity,
            &c.signing,
            &d.identity_public,
            &d_fallback_public,
            1,
        )
        .expect("outbound");
        let opening = encrypt(&other.state, b"x", 1).expect("encrypt");
        let answered = session_inbound(
            &d.identity,
            &d.signing,
            d_fallback_secret,
            &c.identity_public,
            &opening.l1,
            1,
        )
        .expect("inbound");
        let foreign = encrypt(&answered.state, b"y", 1).expect("encrypt");
        assert!(!foreign.is_pre_key, "the forgery is a normal message");
        let stored = SessionState::decode(&inbound.state).expect("state");
        let foreign_key = message::parse(&foreign.l1, false)
            .expect("header")
            .ratchet_key();
        assert!(
            !pickle::chain_views(&stored.pickle)
                .expect("views")
                .iter()
                .any(|view| view.ratchet_key == foreign_key),
            "the forgery must name a ratchet key B does not hold"
        );

        Forgery {
            initiator: first.state,
            responder: inbound.state,
            unknown_chain: foreign.l1,
        }
    }

    /// V-10 / MC-29 (§7.9 point 2, RX-1): a failed decrypt that **did** activate the inactive
    /// sending ratchet in memory leaves the stored envelope byte-identical, and the session that
    /// envelope holds still talks to the peer.
    #[test]
    fn a_failed_decrypt_leaves_the_stored_state_byte_identical() {
        let scene = forgery_scene(4);
        // An independently held copy: the comparison below is against bytes no call can reach.
        let held = scene.responder.clone();

        let failed = decrypt(
            &[StoredSession {
                slot: Slot::Current,
                state: &scene.responder,
            }],
            &scene.unknown_chain,
            false,
            1,
        );
        assert_eq!(
            failed.err(),
            Some(DmCode::Undecryptable),
            "a message on an unknown ratchet key must not decrypt"
        );
        assert_eq!(scene.responder, held, "the stored state is byte-identical");

        // The property a persisted activation would break: the stored session still sends, and the
        // peer reads what it sends.
        let reply = encrypt(&scene.responder, b"two", 1).expect("encrypt");
        let read = decrypt(
            &[StoredSession {
                slot: Slot::Current,
                state: &scene.initiator,
            }],
            &reply.l1,
            reply.is_pre_key,
            1,
        )
        .expect("the peer reads the reply of the unchanged session");
        assert_eq!(read.plaintext, b"two");
    }

    /// Mutant MC-29, so the comparison above is known to be falsifiable: the object a failed
    /// decrypt leaves behind is **not** the object that was loaded. vodozemac activated the
    /// inactive sending ratchet in place before the MAC check failed
    /// (`vz:src/olm/session/double_ratchet.rs:168-191`), so a caller that stored the object would
    /// write a state a forged, relay-injectable blob had changed — T28's "every store maps to an
    /// action". GHOST drops the object instead, which is why the bytes above stay equal.
    #[test]
    fn a_failed_decrypt_does_change_the_object_it_left_behind() {
        let scene = forgery_scene(30);
        let (mut session, sidecar) = load(&scene.responder).expect("load");
        let parsed = message::decode(&scene.unknown_chain, false).expect("decode");
        let error = session.decrypt(&parsed).expect_err("the forgery fails");
        assert_eq!(message::decryption_code(&error), DmCode::Undecryptable);

        let mutated = store(&session, &sidecar, 1).expect("store");
        assert_ne!(
            mutated, scene.responder,
            "the failed attempt changed the object: this is the state GHOST does not store"
        );
    }

    /// D2a: the same normal message twice is `DUPLICATE_OR_LOST`, never a forgery.
    #[test]
    fn a_replayed_message_is_duplicate_or_lost() {
        let a = party(7);
        let b = party(8);
        let (b_fallback_secret, b_fallback_public) = fallback(9);
        let outbound = session_outbound(
            &a.identity,
            &a.signing,
            &b.identity_public,
            &b_fallback_public,
            2,
        )
        .expect("outbound");
        let first = encrypt(&outbound.state, b"one", 2).expect("encrypt");
        let inbound = session_inbound(
            &b.identity,
            &b.signing,
            b_fallback_secret,
            &a.identity_public,
            &first.l1,
            2,
        )
        .expect("inbound");
        let reply = encrypt(&inbound.state, b"two", 2).expect("encrypt");
        let read = decrypt(
            &[StoredSession {
                slot: Slot::Current,
                state: &first.state,
            }],
            &reply.l1,
            false,
            2,
        )
        .expect("decrypt");
        assert_eq!(
            decrypt(
                &[StoredSession {
                    slot: Slot::Current,
                    state: &read.state
                }],
                &reply.l1,
                false,
                2
            )
            .err(),
            Some(DmCode::DuplicateOrLost)
        );
    }

    /// §8.2 rule 3 through the library: a PreKey message whose identity is not the pinned one.
    #[test]
    fn an_unexpected_identity_is_identity_mismatch() {
        let a = party(10);
        let b = party(11);
        let other = party(12);
        let (b_fallback_secret, b_fallback_public) = fallback(13);
        let outbound = session_outbound(
            &a.identity,
            &a.signing,
            &b.identity_public,
            &b_fallback_public,
            3,
        )
        .expect("outbound");
        let first = encrypt(&outbound.state, b"one", 3).expect("encrypt");
        assert_eq!(
            session_inbound(
                &b.identity,
                &b.signing,
                b_fallback_secret,
                &other.identity_public,
                &first.l1,
                3
            )
            .err(),
            Some(DmCode::IdentityMismatch)
        );
    }

    /// §2.2: a PreKey message naming a fallback key the loaded generation does not hold.
    #[test]
    fn a_wrong_generation_is_missing_key() {
        let a = party(14);
        let b = party(15);
        let (_, b_fallback_public) = fallback(16);
        let (other_secret, _) = fallback(17);
        let outbound = session_outbound(
            &a.identity,
            &a.signing,
            &b.identity_public,
            &b_fallback_public,
            4,
        )
        .expect("outbound");
        let first = encrypt(&outbound.state, b"one", 4).expect("encrypt");
        assert_eq!(
            session_inbound(
                &b.identity,
                &b.signing,
                other_secret,
                &a.identity_public,
                &first.l1,
                4
            )
            .err(),
            Some(DmCode::MissingKey)
        );
    }

    /// §22.8.2 rule 1: a low-order peer key is refused before any session call.
    #[test]
    fn a_non_contributory_peer_key_is_invalid_key() {
        let a = party(18);
        let b = party(19);
        let (_, b_fallback_public) = fallback(20);
        assert_eq!(
            session_outbound(&a.identity, &a.signing, &[0u8; 32], &b_fallback_public, 5).err(),
            Some(DmCode::InvalidKey)
        );
        assert_eq!(
            session_outbound(&a.identity, &a.signing, &b.identity_public, &[0u8; 32], 5).err(),
            Some(DmCode::InvalidKey)
        );
    }

    /// §7.7 point 2: the hold reads the expected index from the stored state, so it survives a
    /// restart (there is no in-memory index and no persisted gap counter).
    #[test]
    fn chain_position_reports_the_stored_receiver_chain() {
        let (a_state, _) = round_trip();
        // A's state now holds one receiver chain: B's ratchet key, next index 1.
        let views = pickle::chain_views(&SessionState::decode(&a_state).expect("state").pickle)
            .expect("views");
        assert_eq!(views.len(), 1);
        assert_eq!(
            chain_position(&a_state, &views[0].ratchet_key).expect("position"),
            ChainPosition::Index(views[0].next_index)
        );
        assert_eq!(
            chain_position(&a_state, &[0x7e; 32]).expect("position"),
            ChainPosition::NewChain
        );
    }

    /// §7.7 point 4 end to end: a skipped key is pruned once it is 51 days old, the sidecar loses
    /// its entry with it, and the state still loads.
    #[test]
    fn session_prune_applies_the_age_bound_and_reconciles() {
        let a = party(21);
        let b = party(22);
        let (b_fallback_secret, b_fallback_public) = fallback(23);
        let outbound = session_outbound(
            &a.identity,
            &a.signing,
            &b.identity_public,
            &b_fallback_public,
            100,
        )
        .expect("outbound");
        let first = encrypt(&outbound.state, b"one", 100).expect("encrypt");
        let inbound = session_inbound(
            &b.identity,
            &b.signing,
            b_fallback_secret,
            &a.identity_public,
            &first.l1,
            100,
        )
        .expect("inbound");

        // B skips one of A's messages: A sends two, B receives only the second.
        let second = encrypt(&first.state, b"two", 100).expect("encrypt");
        let third = encrypt(&second.state, b"three", 100).expect("encrypt");
        let read = decrypt(
            &[StoredSession {
                slot: Slot::Current,
                state: &inbound.state,
            }],
            &third.l1,
            third.is_pre_key,
            100,
        )
        .expect("decrypt");
        let stored = SessionState::decode(&read.state).expect("state");
        assert_eq!(stored.sidecar.len(), 1, "one skipped key was stored");
        assert_eq!(
            stored.sidecar.keys(),
            pickle::skipped_keys(&stored.pickle).expect("keys")
        );

        // Not yet 51 days old.
        let (kept, removed) = session_prune(&read.state, 150).expect("prune");
        assert_eq!(removed, 0);
        assert_eq!(SessionState::decode(&kept).expect("state").sidecar.len(), 1);
        // The skipped message still decrypts while its key lives.
        decrypt(
            &[StoredSession {
                slot: Slot::Current,
                state: &kept,
            }],
            &second.l1,
            second.is_pre_key,
            150,
        )
        .expect("the skipped message decrypts before the age bound");

        // At 51 days the key is gone, the sidecar with it, and the message no longer decrypts.
        let (pruned, removed) = session_prune(&read.state, 151).expect("prune");
        assert_eq!(removed, 1);
        let after = SessionState::decode(&pruned).expect("state");
        assert!(after.sidecar.is_empty());
        assert!(pickle::skipped_keys(&after.pickle)
            .expect("keys")
            .is_empty());
        assert_eq!(
            decrypt(
                &[StoredSession {
                    slot: Slot::Current,
                    state: &pruned
                }],
                &second.l1,
                second.is_pre_key,
                151
            )
            .err(),
            Some(DmCode::DuplicateOrLost)
        );
    }

    /// The two-slot trial of §7.6: a replay on one slot and a MAC failure on the other reports the
    /// replay, not the forgery.
    #[test]
    fn two_slots_report_a_replay_rather_than_a_forgery() {
        let a = party(24);
        let b = party(25);
        let (b_fallback_secret, b_fallback_public) = fallback(26);
        let outbound = session_outbound(
            &a.identity,
            &a.signing,
            &b.identity_public,
            &b_fallback_public,
            6,
        )
        .expect("outbound");
        let first = encrypt(&outbound.state, b"one", 6).expect("encrypt");
        let inbound = session_inbound(
            &b.identity,
            &b.signing,
            b_fallback_secret,
            &a.identity_public,
            &first.l1,
            6,
        )
        .expect("inbound");
        let reply = encrypt(&inbound.state, b"two", 6).expect("encrypt");
        let read = decrypt(
            &[StoredSession {
                slot: Slot::Current,
                state: &first.state,
            }],
            &reply.l1,
            false,
            6,
        )
        .expect("decrypt");

        // Another session of the same pair: the replayed message is unknown to it.
        let other = session_outbound(
            &a.identity,
            &a.signing,
            &b.identity_public,
            &b_fallback_public,
            6,
        )
        .expect("outbound");
        assert_eq!(
            decrypt(
                &[
                    StoredSession {
                        slot: Slot::Current,
                        state: &other.state
                    },
                    StoredSession {
                        slot: Slot::Previous,
                        state: &read.state
                    },
                ],
                &reply.l1,
                false,
                6
            )
            .err(),
            Some(DmCode::DuplicateOrLost)
        );
    }

    /// §2.6: `OVERSIZE` belongs to function 8 alone. The other state-storing functions report a
    /// state that does not fit as `STATE_CORRUPT`, because the typed facade has an arm for that and
    /// none for `OVERSIZE` — an unnamed code there is an `IllegalStateException`, not an outcome.
    ///
    /// The mapping is tested at the function: `SESSION_STATE_MAX` is 26 285 B above the worst
    /// pickle Olm can produce (§7.9 point 4), so no session reachable through this API encodes
    /// over the bound; `state::tests::a_state_larger_than_the_maximum_is_oversize` covers the
    /// encoder itself.
    #[test]
    fn only_encrypt_reports_an_over_large_state() {
        assert_eq!(
            stored_state(Err(DmCode::Oversize)).err(),
            Some(DmCode::StateCorrupt)
        );
        assert_eq!(
            stored_state(Err(DmCode::StateCorrupt)).err(),
            Some(DmCode::StateCorrupt)
        );
        assert_eq!(stored_state(Ok(vec![7])).expect("passes through"), vec![7]);
    }

    #[test]
    fn a_stored_state_that_does_not_parse_is_state_corrupt() {
        assert_eq!(encrypt(b"", b"x", 0).err(), Some(DmCode::StateCorrupt));
        assert_eq!(
            chain_position(b"\x00\x00\x00\x01{", &[0u8; 32]).err(),
            Some(DmCode::StateCorrupt)
        );
        assert_eq!(session_prune(b"short", 0).err(), Some(DmCode::StateCorrupt));
    }
}
