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
