//! State wrapping (design §2.5, §22.8.3): every secret Kotlin stores crosses JNI wrapped.
//!
//! ```text
//! envelope = nonce(12) || ChaCha20-Poly1305(session_state_key, nonce,
//!                          AD = "ghost/v1/wrap/" || name || binding, plaintext)
//! ```
//!
//! The binding never changes when a value moves between rows — a slot swap is a delete and an
//! insert of the same envelope bytes, and a held row's `prov_env` moves unchanged — so the AD is
//! stable across the flows §22.8.3 lists. An envelope that does not open under its binding is
//! [`DmCode::StateCorrupt`], which the caller handles like `OVERSIZE`: the contact's sessions are
//! deleted and `reset_needed` is set.
//!
//! The wrapping key is `session_state_key`, 32 random bytes created at ACTIVATE and stored in
//! `dm_self.state_key_wrapped` by a non-exportable Keystore key with the database-key
//! authentication policy. **Keystore is Android-only**, so this crate never touches it: it takes
//! the unwrapped [`StateKey`] as an argument, and the Keystore wrapper stays in Kotlin
//! (`:crypto-bridge`, S4b). That seam is what keeps the crate pure Rust and JVM-testable.

use crate::derive::StateKey;
use crate::pq;
use crate::result::{DmCode, DmResult};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use zeroize::Zeroizing;

/// Length of a wrap nonce.
pub const NONCE_BYTES: usize = 12;
/// Length of the Poly1305 tag.
pub const TAG_BYTES: usize = 16;
/// The bytes an envelope adds to its plaintext.
pub const ENVELOPE_OVERHEAD: usize = NONCE_BYTES + TAG_BYTES;
/// Prefix of every wrap associated data.
pub const WRAP_LABEL: &[u8] = b"ghost/v1/wrap/";

/// The kinds of value that are wrapped, and the `name` each one puts in its associated data
/// (§22.8.3 table).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WrapName {
    /// `olm_session.state_env`: an Olm session pickle.
    OlmSession,
    /// `olm_session.prov_env` and `dm_held.prov_env`: a session's `reply_seed`.
    ReplySeed,
    /// `olm_prekey_gen.secrets_env`: a generation's fallback secret and X-Wing seed.
    Generation,
    /// `dm_pair_key.open_env`: a pair week opening key.
    PairKey,
    /// `dm_pair_offer.root_env`: an offered pair root.
    PairRoot,
    /// `dm_pair_offer.offer_env`: the offered TLV bytes, so re-attachment repeats them exactly.
    PairOffer,
    /// A transient `kbEnv` or `kioEnv`: a card-derived seal key on its way into a call.
    CardKey,
    /// A transient provisional opening key `K_prov(dir)` (§6.7), on its way into `sealSym` or
    /// `openOuter`.
    ///
    /// **Added by S7.** §22.8.3's table stops at the seven envelopes that have a **column**; this
    /// one has none, and deliberately: `K_prov` is a pure function of the session's `reply_seed`
    /// and its session keys, so re-deriving it costs one call and storing it would be a second
    /// place for a key to outlive its `prov_erase_minute` (§6.7, mutant PM-36's family). It is
    /// wrapped all the same, because Kotlin holds **recognition** keys in clear and opening keys
    /// never (rule R-S6), and it carries a binding of its own so a key of one direction cannot be
    /// presented as the other's.
    ProvisionalKey,
    /// A media object's `key_env` (Phase 11 design §4.2): the file key `K_f`, the only durable
    /// form of the key, stored in `media_object.key_env` wrapped under `session_state_key`.
    ///
    /// **Added by S2.** The binding `u8(role) || dest_id(16) || object_id(16) || manifest_hash(32)`
    /// follows F9's `olm_session_binding` practice of naming the contact: a `key_env` of one
    /// contact's object does not open for another contact (§4.2, L7-D16).
    MediaFileKey,
}

/// The `role` byte of an `out` `key_env` (the sender's; §4.2).
pub const MEDIA_ROLE_OUT: u8 = 0x01;
/// The `role` byte of an `in` `key_env` (the recipient's; §4.2).
pub const MEDIA_ROLE_IN: u8 = 0x02;

impl WrapName {
    /// The name string inside the associated data.
    pub const fn as_str(self) -> &'static str {
        match self {
            WrapName::OlmSession => "olm-session",
            WrapName::ReplySeed => "reply-seed",
            WrapName::Generation => "generation",
            WrapName::PairKey => "pair-key",
            WrapName::PairRoot => "pair-root",
            WrapName::PairOffer => "pair-offer",
            WrapName::CardKey => "card-key",
            WrapName::ProvisionalKey => "provisional-key",
            WrapName::MediaFileKey => "media-file-key",
        }
    }

    /// Every name, for the exhaustiveness test.
    pub const ALL: [WrapName; 9] = [
        WrapName::OlmSession,
        WrapName::ReplySeed,
        WrapName::Generation,
        WrapName::PairKey,
        WrapName::PairRoot,
        WrapName::PairOffer,
        WrapName::CardKey,
        WrapName::ProvisionalKey,
        WrapName::MediaFileKey,
    ];
}

/// `contact_id(16) || session_id(32)` (`olm_session.state_env`).
pub fn olm_session_binding(contact_id: &[u8; 16], session_id: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(48);
    out.extend_from_slice(contact_id);
    out.extend_from_slice(session_id);
    out
}

/// `session_id(32)` (`prov_env`). It does not name the row, so a held row's envelope moves to the
/// session row unchanged.
pub fn reply_seed_binding(session_id: &[u8; 32]) -> Vec<u8> {
    session_id.to_vec()
}

/// `u32_be(gen_id) || fallback_pub(32)` (`olm_prekey_gen.secrets_env`).
pub fn generation_binding(gen_id: u32, fallback_public: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(36);
    out.extend_from_slice(&gen_id.to_be_bytes());
    out.extend_from_slice(fallback_public);
    out
}

/// `contact_id || direction(1) || u16_be(root_gen) || u64_be(week)` (`dm_pair_key.open_env`).
pub fn pair_key_binding(contact_id: &[u8; 16], direction: u8, root_gen: u16, week: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(27);
    out.extend_from_slice(contact_id);
    out.push(direction);
    out.extend_from_slice(&root_gen.to_be_bytes());
    out.extend_from_slice(&week.to_be_bytes());
    out
}

/// `contact_id || u16_be(root_gen)` (`dm_pair_offer.root_env` and `offer_env`).
pub fn pair_root_binding(contact_id: &[u8; 16], root_gen: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(18);
    out.extend_from_slice(contact_id);
    out.extend_from_slice(&root_gen.to_be_bytes());
    out
}

/// `session_id(32) || dir(1)` of a transient provisional opening key (§6.7).
///
/// The direction is in the binding because the two keys of a session differ only by it: without
/// it, an envelope of the responder's direction would open as the initiator's and a sender could
/// be made to seal under the key its peer recognises as its own.
pub fn provisional_key_binding(session_id: &[u8; 32], direction: u8) -> Vec<u8> {
    let mut out = Vec::with_capacity(33);
    out.extend_from_slice(session_id);
    out.push(direction);
    out
}

/// `identity_pk(32) || kind(1)` of the card the key belongs to (transient `kbEnv`, `kioEnv`).
pub fn card_key_binding(identity_pk: &[u8; 32], kind: u8) -> Vec<u8> {
    let mut out = Vec::with_capacity(33);
    out.extend_from_slice(identity_pk);
    out.push(kind);
    out
}

/// `u8(role) || dest_id(16) || object_id(16) || manifest_hash(32)` of a media file key
/// (`media_object.key_env`, Phase 11 design §4.2). `role` is [`MEDIA_ROLE_OUT`] or
/// [`MEDIA_ROLE_IN`]; `dest_id` is the contact id (the recipient's on the sender, the sender's on
/// the recipient), so a `key_env` of one contact's object does not open for another contact's.
pub fn media_file_key_binding(
    role: u8,
    dest_id: &[u8; 16],
    object_id: &[u8; 16],
    manifest_hash: &[u8; 32],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(65);
    out.push(role);
    out.extend_from_slice(dest_id);
    out.extend_from_slice(object_id);
    out.extend_from_slice(manifest_hash);
    out
}

fn associated_data(name: WrapName, binding: &[u8]) -> Vec<u8> {
    let mut ad = Vec::with_capacity(WRAP_LABEL.len() + name.as_str().len() + binding.len());
    ad.extend_from_slice(WRAP_LABEL);
    ad.extend_from_slice(name.as_str().as_bytes());
    ad.extend_from_slice(binding);
    ad
}

fn cipher(key: &StateKey) -> DmResult<ChaCha20Poly1305> {
    ChaCha20Poly1305::new_from_slice(key.as_bytes()).map_err(|_| DmCode::StateCorrupt)
}

/// Wraps a value with a given nonce (the vector and equivalence-fixture path).
pub fn wrap_with_nonce(
    key: &StateKey,
    name: WrapName,
    binding: &[u8],
    plaintext: &[u8],
    nonce: &[u8; NONCE_BYTES],
) -> DmResult<Vec<u8>> {
    let ad = associated_data(name, binding);
    let ciphertext = cipher(key)?
        .encrypt(
            &Nonce::from(*nonce),
            Payload {
                msg: plaintext,
                aad: &ad,
            },
        )
        .map_err(|_| DmCode::StateCorrupt)?;
    let mut out = Vec::with_capacity(NONCE_BYTES + ciphertext.len());
    out.extend_from_slice(nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Wraps a value with a fresh random nonce.
pub fn wrap(key: &StateKey, name: WrapName, binding: &[u8], plaintext: &[u8]) -> DmResult<Vec<u8>> {
    #[cfg(feature = "test-vectors")]
    if name == WrapName::OlmSession && hooks::unwrapped() {
        return Ok(plaintext.to_vec());
    }
    let mut nonce = [0u8; NONCE_BYTES];
    pq::fill_random(&mut nonce);
    wrap_with_nonce(key, name, binding, plaintext, &nonce)
}

/// Opens an envelope under its name and binding. Anything else is [`DmCode::StateCorrupt`].
///
/// The plaintext is a session state, a root, a seed or a key, so it comes back **erased on drop**
/// (phase review CRY-P9-04): a caller that leaves by an error path — a `?` on the next unwrap, a
/// failed decode — no longer drops a copy of it unerased.
pub fn unwrap(
    key: &StateKey,
    name: WrapName,
    binding: &[u8],
    envelope: &[u8],
) -> DmResult<Zeroizing<Vec<u8>>> {
    #[cfg(feature = "test-vectors")]
    if name == WrapName::OlmSession && hooks::unwrapped() {
        return Ok(Zeroizing::new(envelope.to_vec()));
    }
    if envelope.len() < ENVELOPE_OVERHEAD {
        return Err(DmCode::StateCorrupt);
    }
    let mut nonce = [0u8; NONCE_BYTES];
    nonce.copy_from_slice(&envelope[..NONCE_BYTES]);
    let ad = associated_data(name, binding);
    cipher(key)?
        .decrypt(
            &Nonce::from(nonce),
            Payload {
                msg: &envelope[NONCE_BYTES..],
                aad: &ad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| DmCode::StateCorrupt)
}

/// ME-24 over the JVM crash worlds (design §15.7 ME-24, §22.38): test builds only — `test-vectors`,
/// which only `ghost-dm-host` enables (G-R2 keeps it out of every shipped graph, G-R6 keeps its JNI
/// symbol out of every shipped library).
///
/// One hook per DM context, set by `DmEquivalence.stateWrapHook(handle, unwrapped)`: the mutant
/// "session state stored unwrapped". [`wrap`] hands an Olm session state back as it is, and
/// [`unwrap`] takes the stored bytes as that state — both, so a mutated world still runs its
/// ratchet and only what it stores differs: `olm_session.state_env` holds the pickle and its
/// sidecar in the clear. Every other envelope, and every call outside a context, is untouched.
///
/// Keyed by context handle and active on the calling thread for one context call only ([`scope`],
/// from `with_context` beside `binding::hooks`), so parallel worlds in one JVM never see one
/// another's hook.
#[cfg(feature = "test-vectors")]
pub mod hooks {
    use std::cell::Cell;
    use std::collections::HashSet;
    use std::sync::{Mutex, OnceLock, PoisonError};

    thread_local! {
        /// Whether the context call running on this thread stores its session states unwrapped.
        static ACTIVE: Cell<bool> = const { Cell::new(false) };
    }

    fn registry() -> &'static Mutex<HashSet<i64>> {
        static HOOKS: OnceLock<Mutex<HashSet<i64>>> = OnceLock::new();
        HOOKS.get_or_init(|| Mutex::new(HashSet::new()))
    }

    /// Sets or clears the hook of the context `handle`.
    pub fn set(handle: i64, unwrapped: bool) {
        let mut hooks = registry().lock().unwrap_or_else(PoisonError::into_inner);
        if unwrapped {
            hooks.insert(handle);
        } else {
            hooks.remove(&handle);
        }
    }

    /// Runs `body` with the hook of `handle` active on this thread, and the previous state back
    /// after it, a caught panic included. Its caller is `jni.rs`'s context scope, so a
    /// `test-vectors` build without `jni-bridge` compiles it unused outside the tests.
    #[cfg_attr(not(feature = "jni-bridge"), allow(dead_code))]
    pub(crate) fn scope<T>(handle: i64, body: impl FnOnce() -> T) -> T {
        struct Restore(bool);
        impl Drop for Restore {
            fn drop(&mut self) {
                ACTIVE.with(|active| active.set(self.0));
            }
        }
        let on = registry()
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .contains(&handle);
        let _restore = Restore(ACTIVE.with(|active| active.replace(on)));
        body()
    }

    /// Whether the running context call stores its session states unwrapped.
    pub(crate) fn unwrapped() -> bool {
        ACTIVE.with(Cell::get)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> StateKey {
        StateKey::from_bytes([0x91; 32])
    }

    const CONTACT: [u8; 16] = [1u8; 16];
    const SESSION: [u8; 32] = [2u8; 32];

    #[test]
    fn an_envelope_round_trips_and_costs_twenty_eight_bytes() {
        let binding = olm_session_binding(&CONTACT, &SESSION);
        let plaintext = vec![7u8; 100];
        let envelope = wrap(&key(), WrapName::OlmSession, &binding, &plaintext).expect("wrap");
        assert_eq!(envelope.len(), plaintext.len() + ENVELOPE_OVERHEAD);
        assert_eq!(
            *unwrap(&key(), WrapName::OlmSession, &binding, &envelope).expect("unwrap"),
            plaintext
        );
    }

    /// `WrapBindingTest` (§22.8.3): a value copied to another row does not open.
    #[test]
    fn a_value_moved_to_another_binding_is_state_corrupt() {
        let binding = olm_session_binding(&CONTACT, &SESSION);
        let envelope = wrap(&key(), WrapName::OlmSession, &binding, b"state").expect("wrap");
        let other_contact = olm_session_binding(&[9u8; 16], &SESSION);
        assert_eq!(
            unwrap(&key(), WrapName::OlmSession, &other_contact, &envelope).err(),
            Some(DmCode::StateCorrupt)
        );
        assert_eq!(
            unwrap(&key(), WrapName::ReplySeed, &binding, &envelope).err(),
            Some(DmCode::StateCorrupt)
        );
        let other_key = StateKey::from_bytes([0u8; 32]);
        assert_eq!(
            unwrap(&other_key, WrapName::OlmSession, &binding, &envelope).err(),
            Some(DmCode::StateCorrupt)
        );
    }

    /// A slot swap and a held-to-session move keep the binding, so the same bytes still open.
    #[test]
    fn a_slot_swap_and_a_held_row_move_keep_the_binding() {
        let binding = reply_seed_binding(&SESSION);
        let envelope = wrap(&key(), WrapName::ReplySeed, &binding, b"reply seed").expect("wrap");
        // The row changes from dm_held to olm_session; the binding is the session id either way.
        assert_eq!(
            unwrap(
                &key(),
                WrapName::ReplySeed,
                &reply_seed_binding(&SESSION),
                &envelope
            )
            .expect("unwrap")
            .as_slice(),
            b"reply seed"
        );
    }

    #[test]
    fn generations_pair_keys_and_offers_are_bound_to_their_coordinates() {
        let k = key();
        let generation = generation_binding(7, &[3u8; 32]);
        let envelope = wrap(&k, WrapName::Generation, &generation, b"secrets").expect("wrap");
        assert_eq!(
            unwrap(
                &k,
                WrapName::Generation,
                &generation_binding(8, &[3u8; 32]),
                &envelope
            )
            .err(),
            Some(DmCode::StateCorrupt)
        );

        let week = pair_key_binding(&CONTACT, 1, 2, 2_870);
        let envelope = wrap(&k, WrapName::PairKey, &week, b"week key").expect("wrap");
        assert_eq!(
            unwrap(
                &k,
                WrapName::PairKey,
                &pair_key_binding(&CONTACT, 1, 2, 2_871),
                &envelope
            )
            .err(),
            Some(DmCode::StateCorrupt)
        );
        assert_eq!(
            unwrap(
                &k,
                WrapName::PairKey,
                &pair_key_binding(&CONTACT, 2, 2, 2_870),
                &envelope
            )
            .err(),
            Some(DmCode::StateCorrupt)
        );

        let offer = pair_root_binding(&CONTACT, 4);
        let envelope = wrap(&k, WrapName::PairOffer, &offer, b"tlv").expect("wrap");
        assert_eq!(
            unwrap(&k, WrapName::PairRoot, &offer, &envelope).err(),
            Some(DmCode::StateCorrupt)
        );
    }

    #[test]
    fn a_truncated_or_empty_envelope_is_state_corrupt() {
        let binding = card_key_binding(&[4u8; 32], 1);
        let envelope = wrap(&key(), WrapName::CardKey, &binding, b"kb").expect("wrap");
        for len in 0..envelope.len() {
            assert_eq!(
                unwrap(&key(), WrapName::CardKey, &binding, &envelope[..len]).err(),
                Some(DmCode::StateCorrupt),
                "length {len}"
            );
        }
    }

    #[test]
    fn every_name_is_distinct() {
        let mut names: Vec<&str> = WrapName::ALL.iter().map(|n| n.as_str()).collect();
        names.sort_unstable();
        let count = names.len();
        names.dedup();
        assert_eq!(names.len(), count);
    }

    /// §4.2 (Phase 11): a media file key opens only under its `(role, dest_id, object_id,
    /// manifest_hash)` binding — a value moved to another role, contact, object or manifest is
    /// `STATE_CORRUPT`, like every other envelope.
    #[test]
    fn a_media_file_key_is_bound_to_role_contact_object_and_manifest() {
        let dest = [3u8; 16];
        let object = [4u8; 16];
        let manifest = [5u8; 32];
        let binding = media_file_key_binding(MEDIA_ROLE_OUT, &dest, &object, &manifest);
        let envelope = wrap(&key(), WrapName::MediaFileKey, &binding, b"kf").expect("wrap");
        assert_eq!(
            unwrap(
                &key(),
                WrapName::MediaFileKey,
                &media_file_key_binding(MEDIA_ROLE_IN, &dest, &object, &manifest),
                &envelope
            )
            .expect_err("another role"),
            DmCode::StateCorrupt
        );
        assert_eq!(
            unwrap(
                &key(),
                WrapName::MediaFileKey,
                &media_file_key_binding(MEDIA_ROLE_OUT, &[9u8; 16], &object, &manifest),
                &envelope
            )
            .expect_err("another contact"),
            DmCode::StateCorrupt
        );
        assert_eq!(
            unwrap(
                &key(),
                WrapName::MediaFileKey,
                &media_file_key_binding(MEDIA_ROLE_OUT, &dest, &[9u8; 16], &manifest),
                &envelope
            )
            .expect_err("another object"),
            DmCode::StateCorrupt
        );
        assert_eq!(
            unwrap(
                &key(),
                WrapName::MediaFileKey,
                &media_file_key_binding(MEDIA_ROLE_OUT, &dest, &object, &[9u8; 32]),
                &envelope
            )
            .expect_err("another manifest"),
            DmCode::StateCorrupt
        );
        assert_eq!(
            unwrap(&key(), WrapName::MediaFileKey, &binding, &envelope)
                .expect("its own binding")
                .as_slice(),
            b"kf"
        );
    }

    #[cfg(feature = "test-vectors")]
    #[test]
    fn the_me24_hook_stores_session_states_unwrapped_in_its_own_context_only() {
        let binding = olm_session_binding(&[7u8; 16], &SESSION);
        let state: &[u8] = b"a session state";
        let wrapped = |envelope: &[u8]| envelope.len() == state.len() + ENVELOPE_OVERHEAD;
        hooks::set(41, true);
        let raw =
            hooks::scope(41, || wrap(&key(), WrapName::OlmSession, &binding, state)).expect("wrap");
        assert_eq!(raw, state);
        let opened = hooks::scope(41, || unwrap(&key(), WrapName::OlmSession, &binding, &raw))
            .expect("unwrap");
        assert_eq!(opened.as_slice(), state);
        // Every other envelope of the hooked context is wrapped as ever.
        let seed =
            hooks::scope(41, || wrap(&key(), WrapName::ReplySeed, &binding, state)).expect("wrap");
        assert!(wrapped(&seed));
        // Another context, and a call outside any, see no hook.
        let other =
            hooks::scope(42, || wrap(&key(), WrapName::OlmSession, &binding, state)).expect("wrap");
        assert!(wrapped(&other));
        assert!(wrapped(
            &wrap(&key(), WrapName::OlmSession, &binding, state).expect("wrap")
        ));
        hooks::set(41, false);
        let cleared =
            hooks::scope(41, || wrap(&key(), WrapName::OlmSession, &binding, state)).expect("wrap");
        assert!(wrapped(&cleared));
    }

    #[test]
    fn a_fresh_nonce_gives_fresh_bytes() {
        let binding = reply_seed_binding(&SESSION);
        let first = wrap(&key(), WrapName::ReplySeed, &binding, b"x").expect("wrap");
        let second = wrap(&key(), WrapName::ReplySeed, &binding, b"x").expect("wrap");
        assert_ne!(first, second);
    }
}
