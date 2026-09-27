//! Binding v3 (design §3.4, §21.4 point 1): the Ed25519 signature every intro envelope carries.
//!
//! ```text
//! binding_sig = Ed25519(identity_sk_A,
//!     "ghost/v1/dm-binding/v3" || OI_A(32) || u16_be(card_index_A) || recipient_namespace(32)
//!     || u32_be(binding_minute) || u32_be(gen_id_B) || SHA-256(xwing_ct)(32) || base_key_A(32)
//!     || OI_B(32))
//! ```
//!
//! **What it proves.** A binding cannot be moved to another envelope (the ciphertext is unique,
//! and besides the recipient only its sealer knows the KEM secret), to another Olm session (base
//! key), recipient (namespace, `OI_B`) or time (minute). It blocks key-compromise impersonation at
//! first contact: an attacker holding the recipient's complete state cannot start sessions in a
//! sender's name with fresh base keys, which plain Olm 3DH on a fallback key otherwise allows.
//!
//! **What it does not sign.** No message content and no L1 hash. The recipient can prove that A's
//! identity started a session toward its namespace at that minute, not what A wrote, since the
//! recipient knows the KEM secret and could re-seal any content under the same binding (L7-D20).
//!
//! `binding_minute` is the **sealing** minute, not `author_minute`: a pending send may be sealed
//! days after compose.

use crate::result::DmResult;
use crate::sign;
use sha2::{Digest, Sha256};

/// Label of the binding signature.
pub const BINDING_LABEL: &[u8] = b"ghost/v1/dm-binding/v3";

/// FRESH, in minutes: content older than 45 days is refused (§7.6).
pub const FRESH_MINUTES: u32 = 45 * 24 * 60;
/// `2σ`, in minutes: the Phase 7 per-device clock tolerance is σ = 3 days (§7.6).
pub const TWO_SIGMA_MINUTES: u32 = 6 * 24 * 60;

/// The fields binding v3 covers.
pub struct BindingV3<'a> {
    /// The sender's Olm identity.
    pub oi_a: &'a [u8; 32],
    /// The sender's card index.
    pub card_index_a: u16,
    /// The recipient's inbox namespace this envelope is deposited into.
    pub recipient_namespace: &'a [u8; 32],
    /// `floor_minute(now)` at sealing.
    pub binding_minute: u32,
    /// The recipient's bundle generation this envelope is addressed to.
    pub gen_id_b: u32,
    /// The envelope's X-Wing ciphertext; the signature covers its SHA-256.
    pub xwing_ct: &'a [u8],
    /// The base key of the Olm PreKey message inside the envelope.
    pub base_key_a: &'a [u8; 32],
    /// The recipient's Olm identity, from its bundle.
    pub oi_b: &'a [u8; 32],
}

impl BindingV3<'_> {
    /// The exact bytes the signature covers.
    pub fn transcript(&self) -> Vec<u8> {
        let ct_hash: [u8; 32] = Sha256::digest(self.xwing_ct).into();
        let mut message =
            Vec::with_capacity(BINDING_LABEL.len() + 32 + 2 + 32 + 4 + 4 + 32 + 32 + 32);
        message.extend_from_slice(BINDING_LABEL);
        message.extend_from_slice(self.oi_a);
        message.extend_from_slice(&self.card_index_a.to_be_bytes());
        message.extend_from_slice(self.recipient_namespace);
        message.extend_from_slice(&self.binding_minute.to_be_bytes());
        message.extend_from_slice(&self.gen_id_b.to_be_bytes());
        message.extend_from_slice(&ct_hash);
        message.extend_from_slice(self.base_key_a);
        message.extend_from_slice(self.oi_b);
        #[cfg(feature = "test-vectors")]
        hooks::omit_from(&mut message);
        message
    }
}

/// Signs binding v3 with the sender's `ghost1` Ed25519 seed.
pub fn sign(identity_seed: &[u8; 32], binding: &BindingV3<'_>) -> [u8; sign::SIGNATURE_BYTES] {
    sign::sign(identity_seed, &binding.transcript())
}

/// Verifies binding v3 under the sender's card identity key, strictly (§2.4).
pub fn verify(
    identity_pk: &[u8; 32],
    binding: &BindingV3<'_>,
    signature: &[u8; sign::SIGNATURE_BYTES],
) -> DmResult<()> {
    sign::verify_strict(identity_pk, &binding.transcript(), signature)
}

/// Freshness of a binding minute (§21.4 point 2): `now − FRESH ≤ binding_minute ≤ now + 2σ`.
///
/// It runs in Kotlin at RECV R5, before any state change; the rule lives here so both sides of the
/// vectors compute it the same way.
pub fn is_fresh(binding_minute: u32, now_minute: u32) -> bool {
    let lower = now_minute.saturating_sub(FRESH_MINUTES);
    let upper = now_minute.saturating_add(TWO_SIGMA_MINUTES);
    binding_minute >= lower && binding_minute <= upper
}

/// MC-20 and KC5b over the JVM crash worlds (design §15.5 KC5b, §15.7 MC-20, §22.37): test builds
/// only — `test-vectors`, which only `ghost-dm-host` enables (G-R2 keeps it out of every shipped
/// graph, G-R6 keeps its JNI symbol out of every shipped library).
///
/// Two hooks per DM context, set by `DmEquivalence.bindingHooks(handle, omit, perturb)`:
/// - **omit** is the mutant MC-20, "binding without namespace, minute, ciphertext or base key":
///   [`BindingV3::transcript`] leaves that field out, so a signature neither covers it when it is
///   made nor checks it when it is verified — on every device of a mutated world alike, so the
///   world's own traffic still verifies;
/// - **perturb** is KC5b's input, "a genuine binding replayed with another recipient namespace,
///   another ciphertext or base key, or a stale minute": the intros the context seals carry the
///   sender's genuine signature over another value of that field than the envelope carries —
///   byte for byte what such a replay would present, which no JVM seam can build (§22.27 item 8).
///
/// Keyed by context handle, which `jni.rs` never reuses, and active on the calling thread for one
/// context call only ([`scope`], from `with_context`), so parallel worlds in one JVM never see one
/// another's hooks, and a call outside a context — the equivalence fixture, the crate's own tests —
/// sees none.
#[cfg(feature = "test-vectors")]
pub mod hooks {
    use super::{BindingV3, BINDING_LABEL, FRESH_MINUTES};
    use crate::sign;
    use std::cell::Cell;
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock, PoisonError};

    /// No field: the hook is off.
    pub const NONE: u8 = 0;
    /// `recipient_namespace`.
    pub const NAMESPACE: u8 = 1;
    /// `binding_minute`.
    pub const MINUTE: u8 = 2;
    /// `SHA-256(xwing_ct)`.
    pub const CIPHERTEXT: u8 = 3;
    /// `base_key_a`.
    pub const BASE_KEY: u8 = 4;

    thread_local! {
        /// `(omit, perturb)` of the context call running on this thread.
        static ACTIVE: Cell<(u8, u8)> = const { Cell::new((NONE, NONE)) };
    }

    fn registry() -> &'static Mutex<HashMap<i64, (u8, u8)>> {
        static HOOKS: OnceLock<Mutex<HashMap<i64, (u8, u8)>>> = OnceLock::new();
        HOOKS.get_or_init(|| Mutex::new(HashMap::new()))
    }

    /// Sets the hooks of the context `handle` ([`NONE`] clears one); false for a code out of range.
    pub fn set(handle: i64, omit: u8, perturb: u8) -> bool {
        if omit > BASE_KEY || perturb > BASE_KEY {
            return false;
        }
        let mut hooks = registry().lock().unwrap_or_else(PoisonError::into_inner);
        if omit == NONE && perturb == NONE {
            hooks.remove(&handle);
        } else {
            hooks.insert(handle, (omit, perturb));
        }
        true
    }

    /// Runs `body` with the hooks of `handle` active on this thread, and the previous ones back
    /// after it, a caught panic included. Its caller is `jni.rs`'s context scope, so a
    /// `test-vectors` build without `jni-bridge` compiles it unused.
    #[cfg_attr(not(feature = "jni-bridge"), allow(dead_code))]
    pub(crate) fn scope<T>(handle: i64, body: impl FnOnce() -> T) -> T {
        struct Restore((u8, u8));
        impl Drop for Restore {
            fn drop(&mut self) {
                ACTIVE.with(|active| active.set(self.0));
            }
        }
        let hooks = registry()
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&handle)
            .copied()
            .unwrap_or((NONE, NONE));
        let _restore = Restore(ACTIVE.with(|active| active.replace(hooks)));
        body()
    }

    /// The mutant: the omitted field's bytes out of a finished transcript.
    pub(crate) fn omit_from(transcript: &mut Vec<u8>) {
        // The offsets of `BindingV3::transcript`: label, OI_A(32), card index(2), namespace(32),
        // minute(4), gen_id(4), SHA-256(xwing_ct)(32), base key(32), OI_B(32).
        let namespace = BINDING_LABEL.len() + 32 + 2;
        let minute = namespace + 32;
        let ciphertext = minute + 4 + 4;
        let base_key = ciphertext + 32;
        match ACTIVE.with(|active| active.get().0) {
            NAMESPACE => drop(transcript.drain(namespace..namespace + 32)),
            MINUTE => drop(transcript.drain(minute..minute + 4)),
            CIPHERTEXT => drop(transcript.drain(ciphertext..ciphertext + 32)),
            BASE_KEY => drop(transcript.drain(base_key..base_key + 32)),
            _ => {}
        }
    }

    /// Binding v3's signature for an intro the context seals: over the envelope's own values, or,
    /// under the perturb hook, over another value of the one field it names — another namespace,
    /// ciphertext or base key (one bit flipped), or a **stale** minute (`FRESH` and a minute before
    /// the transmitted one, so the envelope still passes R5 and only the signature can refuse it).
    pub(crate) fn sign_intro(
        identity_seed: &[u8; 32],
        binding: &BindingV3<'_>,
    ) -> [u8; sign::SIGNATURE_BYTES] {
        let mut namespace = *binding.recipient_namespace;
        let mut minute = binding.binding_minute;
        let mut ciphertext = binding.xwing_ct.to_vec();
        let mut base_key = *binding.base_key_a;
        match ACTIVE.with(|active| active.get().1) {
            NAMESPACE => namespace[0] ^= 1,
            MINUTE => minute = minute.saturating_sub(FRESH_MINUTES + 1),
            CIPHERTEXT => {
                if let Some(first) = ciphertext.first_mut() {
                    *first ^= 1;
                }
            }
            BASE_KEY => base_key[0] ^= 1,
            _ => return super::sign(identity_seed, binding),
        }
        super::sign(
            identity_seed,
            &BindingV3 {
                oi_a: binding.oi_a,
                card_index_a: binding.card_index_a,
                recipient_namespace: &namespace,
                binding_minute: minute,
                gen_id_b: binding.gen_id_b,
                xwing_ct: &ciphertext,
                base_key_a: &base_key,
                oi_b: binding.oi_b,
            },
        )
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        const SEED: [u8; 32] = [0x81; 32];

        fn binding<'a>(
            namespace: &'a [u8; 32],
            ct: &'a [u8],
            base_key: &'a [u8; 32],
        ) -> BindingV3<'a> {
            BindingV3 {
                oi_a: &[0x11; 32],
                card_index_a: 0,
                recipient_namespace: namespace,
                binding_minute: 10_000_000,
                gen_id_b: 7,
                xwing_ct: ct,
                base_key_a: base_key,
                oi_b: &[0x13; 32],
            }
        }

        /// Each perturbation is refused by the full transcript and accepted by the one that omits
        /// its field on both sides — the pair MC-20's kill rests on, since a mutated world signs
        /// and verifies with the same transcript — and no other omission accepts it.
        #[test]
        fn each_perturbation_is_refused_unless_its_field_is_omitted() {
            let (namespace, ct, base_key) = ([0x21u8; 32], [0x22u8; 1120], [0x12u8; 32]);
            let fields = binding(&namespace, &ct, &base_key);
            let public = crate::sign::public_key(&SEED);
            let handle = -7_001;
            for perturbed in [NAMESPACE, MINUTE, CIPHERTEXT, BASE_KEY] {
                for omitted in [NONE, NAMESPACE, MINUTE, CIPHERTEXT, BASE_KEY] {
                    assert!(set(handle, omitted, perturbed));
                    let verdict = scope(handle, || {
                        let signature = sign_intro(&SEED, &fields);
                        super::super::verify(&public, &fields, &signature)
                    });
                    assert_eq!(
                        verdict.is_ok(),
                        omitted == perturbed,
                        "perturbed {perturbed}, omitted {omitted}"
                    );
                }
            }
            assert!(set(handle, NONE, NONE));
            assert_eq!(
                sign_intro(&SEED, &fields),
                super::super::sign(&SEED, &fields)
            );
            assert!(!set(handle, BASE_KEY + 1, NONE));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::result::DmCode;

    const SEED: [u8; 32] = [0x81; 32];

    fn fields<'a>(namespace: &'a [u8; 32], ct: &'a [u8], minute: u32) -> BindingV3<'a> {
        BindingV3 {
            oi_a: &[0x11; 32],
            card_index_a: 0,
            recipient_namespace: namespace,
            binding_minute: minute,
            gen_id_b: 7,
            xwing_ct: ct,
            base_key_a: &[0x12; 32],
            oi_b: &[0x13; 32],
        }
    }

    #[test]
    fn the_transcript_covers_every_field() {
        let namespace = [0x21u8; 32];
        let ct = [0x22u8; 1120];
        let base = fields(&namespace, &ct, 100);
        let signature = sign(&SEED, &base);
        let public = crate::sign::public_key(&SEED);
        assert_eq!(verify(&public, &base, &signature), Ok(()));

        let other_namespace = [0x23u8; 32];
        let mut other_ct = ct;
        other_ct[0] ^= 1;
        let variants = [
            BindingV3 {
                oi_a: &[0x14; 32],
                ..fields(&namespace, &ct, 100)
            },
            BindingV3 {
                card_index_a: 1,
                ..fields(&namespace, &ct, 100)
            },
            fields(&other_namespace, &ct, 100),
            fields(&namespace, &ct, 101),
            BindingV3 {
                gen_id_b: 8,
                ..fields(&namespace, &ct, 100)
            },
            fields(&namespace, &other_ct, 100),
            BindingV3 {
                base_key_a: &[0x15; 32],
                ..fields(&namespace, &ct, 100)
            },
            BindingV3 {
                oi_b: &[0x16; 32],
                ..fields(&namespace, &ct, 100)
            },
        ];
        for variant in &variants {
            assert_ne!(variant.transcript(), base.transcript());
            assert_eq!(
                verify(&public, variant, &signature),
                Err(DmCode::BadSignature)
            );
        }
    }

    #[test]
    fn content_is_not_signed() {
        // The transcript has a fixed length whatever the message: no L1 and no body enter it.
        let namespace = [0x21u8; 32];
        let ct = [0x22u8; 1120];
        assert_eq!(
            fields(&namespace, &ct, 1).transcript().len(),
            BINDING_LABEL.len() + 32 + 2 + 32 + 4 + 4 + 32 + 32 + 32
        );
    }

    #[test]
    fn freshness_is_forty_five_days_back_and_six_days_forward() {
        let now = 30_000_000u32;
        assert!(is_fresh(now, now));
        assert!(is_fresh(now - FRESH_MINUTES, now));
        assert!(!is_fresh(now - FRESH_MINUTES - 1, now));
        assert!(is_fresh(now + TWO_SIGMA_MINUTES, now));
        assert!(!is_fresh(now + TWO_SIGMA_MINUTES + 1, now));
        assert_eq!(FRESH_MINUTES, 64_800);
        assert_eq!(TWO_SIGMA_MINUTES, 8_640);
    }
}
