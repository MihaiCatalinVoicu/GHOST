//! The reveal of design §6.9 (`CH-REVEAL`, a user action; slice S9): the `RevealPayload`, its two
//! signatures, and the HPKE seal to a member's per-leaf box key (§5.1, §19.17).
//!
//! ```text
//! RevealPayload = version(1) = 1 ‖ channel_id(32) ‖ P_author(32) ‖ P_M(32) ‖ minute(u32_be)
//!                 ‖ card_v2(131) ‖ sig_id(64) ‖ sig_ps(64)                                   (360 bytes)
//! sig_id = Ed25519(ghost1 identity key, "ghost/v1/ch/reveal-id" ‖ channel_id ‖ P_author ‖ P_M ‖ minute)
//! sig_ps = Ed25519(pseudonym key, "ghost/v1/ch/reveal-ps" ‖ channel_id ‖ SHA-256(card_v2) ‖ P_M ‖ minute)
//! HPKE   = HPKE-Base(KEM 0x0020 DHKEM-X25519-HKDF-SHA256, KDF 0x0001 HKDF-SHA256,
//!                    AEAD 0x0003 ChaCha20-Poly1305)(box_pk(M), info = "ghost/v1/ch/reveal" ‖ channel_id,
//!                    aad = op_id, RevealPayload)
//! ```
//!
//! The HPKE runs through the provider's `hpke_seal`/`hpke_open` — the code MLS already uses
//! (§6.9 point 2). The identity signature and the strict verification of both signatures and the
//! contact card live in `ghost-client-dm` (ADR-35's X-21 rule: exactly one production signer and
//! one verifier per artifact type; `reveal_identity_material` signs with the DM context's identity
//! key, which Kotlin never sees). What crosses to Kotlin of an opened reveal is the author's card
//! and pseudonym only — the payload, its signatures included, is erased when it is dropped, like
//! every other plaintext this crate handles.

use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::types::HpkeCiphertext;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::canonical;
use crate::derive::REVEAL_HPKE_SUITE;
use crate::group::{ChannelHandle, KeyClass, MlsContext};
use crate::result::{Code, MlsError, MlsResult};

/// The payload's one version.
pub const VERSION: u8 = 1;
/// `version ‖ channel_id ‖ P_author ‖ P_M ‖ minute ‖ card ‖ sig_id ‖ sig_ps`.
pub const PAYLOAD_BYTES: usize = 360;
/// `version(1) ‖ channel_id(32)`.
const OFFSET_P_AUTHOR: usize = 33;
/// `‖ P_author(32)`.
const OFFSET_P_RECIPIENT: usize = 65;
/// `‖ P_M(32)`.
const OFFSET_MINUTE: usize = 97;
/// `‖ minute(u32)`.
const OFFSET_CARD: usize = 101;
/// `‖ card_v2(131)`.
const OFFSET_SIG_ID: usize = 232;
/// `‖ sig_id(64)`.
const OFFSET_SIG_PS: usize = 296;
/// `card_v2(131)`: the DM contact card v2 (`ghost-client-dm`'s `card::CARD_BYTES`).
pub const REVEAL_CARD_BYTES: usize = ghost_client_dm::card::CARD_BYTES;
/// An Ed25519 signature (32 + 32).
pub const SIG_BYTES: usize = 64;

/// `sig_id`'s domain separation.
pub const LABEL_ID: &[u8] = b"ghost/v1/ch/reveal-id";
/// `sig_ps`'s domain separation.
pub const LABEL_PS: &[u8] = b"ghost/v1/ch/reveal-ps";
/// The HPKE `info` prefix.
pub const LABEL_INFO: &[u8] = b"ghost/v1/ch/reveal";

// The reveal's HPKE suite (KEM 0x0020/KDF 0x0001/AEAD 0x0003) is [`derive::REVEAL_HPKE_SUITE`]:
// spelled in the typed derivation module, not here, so no `Hkdf…` identifier is named outside
// it (G-M3 rule 2; review of S9, FIX 1).

fn nc() -> MlsError {
    MlsError::new(Code::NonCanonical)
}

/// `info = "ghost/v1/ch/reveal" ‖ channel_id` (§6.9 point 2).
fn info(channel_id: &[u8; 32]) -> Vec<u8> {
    let mut v = Vec::with_capacity(LABEL_INFO.len() + 32);
    v.extend_from_slice(LABEL_INFO);
    v.extend_from_slice(channel_id);
    v
}

/// `sig_id`'s transcript: `"ghost/v1/ch/reveal-id" ‖ channel_id ‖ P_author ‖ P_M ‖ minute`.
fn id_transcript(
    channel_id: &[u8; 32],
    p_author: &[u8; 32],
    p_recipient: &[u8; 32],
    minute: u32,
) -> Vec<u8> {
    let mut v = Vec::with_capacity(LABEL_ID.len() + 32 + 32 + 32 + 4);
    v.extend_from_slice(LABEL_ID);
    v.extend_from_slice(channel_id);
    v.extend_from_slice(p_author);
    v.extend_from_slice(p_recipient);
    v.extend_from_slice(&minute.to_be_bytes());
    v
}

/// `sig_ps`'s transcript: `"ghost/v1/ch/reveal-ps" ‖ channel_id ‖ SHA-256(card_v2) ‖ P_M ‖ minute`.
fn ps_transcript(
    channel_id: &[u8; 32],
    card: &[u8; REVEAL_CARD_BYTES],
    p_recipient: &[u8; 32],
    minute: u32,
) -> Vec<u8> {
    let hash: [u8; 32] = Sha256::digest(card).into();
    let mut v = Vec::with_capacity(LABEL_PS.len() + 32 + 32 + 32 + 4);
    v.extend_from_slice(LABEL_PS);
    v.extend_from_slice(channel_id);
    v.extend_from_slice(&hash);
    v.extend_from_slice(p_recipient);
    v.extend_from_slice(&minute.to_be_bytes());
    v
}

/// A decoded `RevealPayload`. The card is a bearer secret ("may message me"): every copy this
/// crate makes is erased when it is dropped, like a post's plaintext ([`crate::content`]).
#[derive(Clone, Debug, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct RevealPayload {
    /// `channel_id`, bound into the HPKE `info` too.
    pub channel_id: [u8; 32],
    /// `P_author`, the revealing member's pseudonym; verified against the post's MLS sender.
    pub p_author: [u8; 32],
    /// `P_M`, the chosen recipient; verified against the opening member's own pseudonym.
    pub p_recipient: [u8; 32],
    /// The minute the author chose (the caller's trusted clock).
    pub minute: u32,
    /// `card_v2`, the author's DM contact card (131 bytes).
    pub card: Zeroizing<[u8; REVEAL_CARD_BYTES]>,
    /// `sig_id`, the `ghost1` identity key's signature over [`LABEL_ID`]'s transcript.
    pub sig_id: [u8; SIG_BYTES],
    /// `sig_ps`, the pseudonym key's signature over [`LABEL_PS`]'s transcript.
    pub sig_ps: [u8; SIG_BYTES],
}

impl RevealPayload {
    /// The exact 360 bytes of §6.9 point 1; the caller seals and zeroes them.
    pub fn encode(&self) -> Zeroizing<[u8; PAYLOAD_BYTES]> {
        let mut o = Zeroizing::new([0u8; PAYLOAD_BYTES]);
        o[0] = VERSION;
        o[1..OFFSET_P_AUTHOR].copy_from_slice(&self.channel_id);
        o[OFFSET_P_AUTHOR..OFFSET_P_RECIPIENT].copy_from_slice(&self.p_author);
        o[OFFSET_P_RECIPIENT..OFFSET_MINUTE].copy_from_slice(&self.p_recipient);
        o[OFFSET_MINUTE..OFFSET_CARD].copy_from_slice(&self.minute.to_be_bytes());
        o[OFFSET_CARD..OFFSET_SIG_ID].copy_from_slice(self.card.as_slice());
        o[OFFSET_SIG_ID..OFFSET_SIG_PS].copy_from_slice(&self.sig_id);
        o[OFFSET_SIG_PS..].copy_from_slice(&self.sig_ps);
        o
    }

    /// The canonical parse: exactly 360 bytes, version 1, [`CHANNEL_ID`] equal to the channel the
    /// caller named (the HPKE `info` binds it, so a mismatch is a defect, not a transport error).
    /// Anything else is `NON_CANONICAL`.
    pub fn parse(b: &[u8], channel_id: &[u8; 32]) -> MlsResult<Self> {
        let o: &[u8; PAYLOAD_BYTES] = b.try_into().map_err(|_| nc())?;
        if o[0] != VERSION {
            return Err(nc());
        }
        let mut parsed_channel = [0u8; 32];
        parsed_channel.copy_from_slice(&o[1..OFFSET_P_AUTHOR]);
        if &parsed_channel != channel_id {
            return Err(nc());
        }
        let mut p_author = [0u8; 32];
        p_author.copy_from_slice(&o[OFFSET_P_AUTHOR..OFFSET_P_RECIPIENT]);
        let mut p_recipient = [0u8; 32];
        p_recipient.copy_from_slice(&o[OFFSET_P_RECIPIENT..OFFSET_MINUTE]);
        let minute =
            u32::from_be_bytes(o[OFFSET_MINUTE..OFFSET_CARD].try_into().map_err(|_| nc())?);
        let mut card = Zeroizing::new([0u8; REVEAL_CARD_BYTES]);
        card.copy_from_slice(&o[OFFSET_CARD..OFFSET_SIG_ID]);
        let mut sig_id = [0u8; SIG_BYTES];
        sig_id.copy_from_slice(&o[OFFSET_SIG_ID..OFFSET_SIG_PS]);
        let mut sig_ps = [0u8; SIG_BYTES];
        sig_ps.copy_from_slice(&o[OFFSET_SIG_PS..]);
        Ok(Self {
            channel_id: parsed_channel,
            p_author,
            p_recipient,
            minute,
            card,
            sig_id,
            sig_ps,
        })
    }
}

/// What `revealOpen` returns: the verified author and the author's card. The card crosses to
/// Kotlin for the `addContact` offer; the signatures stay native (a received `ch_reveal` row keeps
/// no time but its deadline and no proof columns, §19.21 — the proof is what M learns and can
/// show from the opened payload while the row lives).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevealOpened {
    /// `P_author`, verified to equal the post's MLS sender.
    pub p_author: [u8; 32],
    /// The author's DM contact card v2 (131 bytes), signature-verified.
    pub card: [u8; REVEAL_CARD_BYTES],
}

impl MlsContext {
    /// fn 16 `revealSeal` (§6.9): builds the payload and HPKE-seals it to [recipient_box_pk].
    /// [identity_material] reaches the DM context's identity key — the caller passes a closure over
    /// the `dmHandle` that calls `ghost-client-dm`'s `reveal_identity_material`; `None` (a closed
    /// or foreign DM handle) is `CRYPTO_UNAVAILABLE`, because without the identity key there is
    /// no `sig_id` and no card to send. A non-canonical [recipient_box_pk] is refused before
    /// anything is drawn (the F9 §22.8.2 rule, as for a leaf's key).
    pub fn reveal_seal(
        &self,
        ch: &ChannelHandle,
        identity_material: impl FnOnce(&[u8]) -> Option<([u8; SIG_BYTES], [u8; REVEAL_CARD_BYTES])>,
        recipient: [u8; 32],
        recipient_box_pk: [u8; 32],
        minute: u32,
        op_id: [u8; 16],
    ) -> MlsResult<([u8; 32], Vec<u8>)> {
        let channel_id = *ch.channel_id();
        if !canonical::valid_box_pk(&recipient_box_pk) {
            return Err(nc());
        }
        let p_author = ch.pseudonym();
        let transcript = id_transcript(&channel_id, &p_author, &recipient, minute);
        // The signature is made before the payload exists (the transcript is its input), so the
        // card arrives with it — one crossing, no card copy lives outside the payload.
        let (sig_id, card) =
            identity_material(&transcript).ok_or_else(|| MlsError::new(Code::CryptoUnavailable))?;
        let sig_ps = ch.sign_raw(&ps_transcript(&channel_id, &card, &recipient, minute));
        let payload = RevealPayload {
            channel_id,
            p_author,
            p_recipient: recipient,
            minute,
            card: Zeroizing::new(card),
            sig_id,
            sig_ps,
        };
        let plain = payload.encode();
        let sealed = self
            .crypto()
            .hpke_seal(
                REVEAL_HPKE_SUITE,
                &recipient_box_pk,
                &info(&channel_id),
                &op_id,
                plain.as_slice(),
            )
            .map_err(|_| MlsError::new(Code::Internal))?;
        let mut enc = [0u8; 32];
        if sealed.kem_output.as_slice().len() != 32 {
            return Err(MlsError::new(Code::Internal));
        }
        enc.copy_from_slice(sealed.kem_output.as_slice());
        Ok((enc, sealed.ciphertext.into()))
    }

    /// fn 16 `revealOpen` (§6.9): opens one reveal with the member's box key of the post's epoch
    /// and verifies everything M must verify: the HPKE opens under `b_sk` (`NOT_OPEN` — the
    /// reveal is for another member; one open per reveal post), the payload is canonical, the card
    /// parses and its signature verifies under its own identity key, `sig_id` verifies under the
    /// card's identity key, `sig_ps` verifies under `P_author`, `P_author` equals the post's MLS
    /// sender and `P_M` equals the member's own pseudonym (each `BAD_SIGNATURE` — a forgery,
    /// refused; nothing is returned, so nothing of it is kept).
    pub fn reveal_open(
        &self,
        ch: &ChannelHandle,
        box_env: &[u8],
        enc: [u8; 32],
        ciphertext: &[u8],
        op_id: [u8; 16],
        sender_p: [u8; 32],
    ) -> MlsResult<RevealOpened> {
        let channel_id = *ch.channel_id();
        let b_sk = self.unwrap_key(KeyClass::Box, &channel_id, box_env)?;
        let opened = self
            .crypto()
            .hpke_open(
                REVEAL_HPKE_SUITE,
                &HpkeCiphertext {
                    kem_output: enc.to_vec().into(),
                    ciphertext: ciphertext.to_vec().into(),
                },
                b_sk.as_slice(),
                &info(&channel_id),
                &op_id,
            )
            .map_err(|_| MlsError::new(Code::NotOpen))?;
        let payload = RevealPayload::parse(&opened, &channel_id)?;
        let bad_sig = || MlsError::new(Code::BadSignature);
        let card = ghost_client_dm::card::parse(payload.card.as_slice()).map_err(|_| bad_sig())?;
        ghost_client_dm::sign::verify_strict(
            &card.identity_pk,
            &id_transcript(
                &channel_id,
                &payload.p_author,
                &payload.p_recipient,
                payload.minute,
            ),
            &payload.sig_id,
        )
        .map_err(|_| bad_sig())?;
        ghost_client_dm::sign::verify_strict(
            &payload.p_author,
            &ps_transcript(
                &channel_id,
                &payload.card,
                &payload.p_recipient,
                payload.minute,
            ),
            &payload.sig_ps,
        )
        .map_err(|_| bad_sig())?;
        if payload.p_author != sender_p {
            return Err(bad_sig());
        }
        if payload.p_recipient != ch.pseudonym() {
            return Err(bad_sig());
        }
        Ok(RevealOpened {
            p_author: payload.p_author,
            card: card.encode(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::derive::PseudonymSeed;

    fn ctx_and_channel() -> (MlsContext, ChannelHandle) {
        ctx_and_channel_of([3u8; 32])
    }

    fn ctx_and_channel_of(seed: [u8; 32]) -> (MlsContext, ChannelHandle) {
        let ctx = MlsContext::open(crate::derive::StateKey::from_bytes([7u8; 32])).unwrap();
        let ch = ChannelHandle::open([9u8; 32], &PseudonymSeed::from_bytes(seed));
        (ctx, ch)
    }

    fn card_of(identity_seed: &[u8; 32]) -> [u8; REVEAL_CARD_BYTES] {
        // A card whose signature verifies under its identity key, the dm crate's build.
        let m = ghost_client_dm::derive::MessagingBranch::from_bytes([5u8; 32]);
        let secret = ghost_client_dm::derive::derive_card_secret(&m, 0);
        ghost_client_dm::card::build(identity_seed, 0, &secret).encode()
    }

    #[test]
    fn a_payload_round_trips_exactly() {
        let payload = RevealPayload {
            channel_id: [9u8; 32],
            p_author: [1u8; 32],
            p_recipient: [2u8; 32],
            minute: 41_000_000,
            card: Zeroizing::new([4u8; REVEAL_CARD_BYTES]),
            sig_id: [5u8; SIG_BYTES],
            sig_ps: [6u8; SIG_BYTES],
        };
        let encoded = payload.encode();
        assert_eq!(encoded.len(), PAYLOAD_BYTES);
        assert_eq!(encoded[0], 1);
        assert_eq!(&encoded[1..33], &[9u8; 32]);
        assert_eq!(&encoded[97..101], &41_000_000u32.to_be_bytes());
        assert_eq!(
            RevealPayload::parse(&*encoded, &[9u8; 32]).unwrap(),
            payload
        );
    }

    #[test]
    fn the_parse_is_canonical() {
        let payload = RevealPayload {
            channel_id: [9u8; 32],
            p_author: [1u8; 32],
            p_recipient: [2u8; 32],
            minute: 1,
            card: Zeroizing::new([4u8; REVEAL_CARD_BYTES]),
            sig_id: [5u8; SIG_BYTES],
            sig_ps: [6u8; SIG_BYTES],
        };
        let encoded = payload.encode();
        // Wrong length, version, channel id.
        assert!(RevealPayload::parse(&encoded[..359], &[9u8; 32]).is_err());
        let mut v = encoded.to_vec();
        v[0] = 2;
        assert!(RevealPayload::parse(&v, &[9u8; 32]).is_err());
        assert!(RevealPayload::parse(&*encoded, &[8u8; 32]).is_err());
    }

    #[test]
    fn a_sealed_reveal_opens_for_the_recipient_only() {
        let (author_ctx, author) = ctx_and_channel();
        let (m_ctx, m) = ctx_and_channel();
        let author_box = crate::canonical::box_public(&[11u8; 32]);
        let m_box = crate::canonical::box_public(&[12u8; 32]);
        assert!(crate::canonical::valid_box_pk(&author_box));
        // The author's DM identity: the closure stands in for reveal_identity_material. The
        // fixed sig_id is enough for the AEAD tests here — strict verification is the dm
        // crate's own suite's and the full round trip below.
        let own_card = card_of(&[21u8; 32]);
        let sign = |_msg: &[u8]| Some(([7u8; SIG_BYTES], own_card));
        let op_id = [8u8; 16];
        let (enc, ct) = author_ctx
            .reveal_seal(&author, sign, m.pseudonym(), m_box, 42, op_id)
            .unwrap();
        assert_eq!(enc.len(), 32);
        // The recipient's box secret opens the AEAD: a wrong op id (the aad) is NOT_OPEN; the
        // right one opens onto the payload, whose fixed sig_id is then refused BAD_SIGNATURE.
        let m_env = m_ctx
            .wrap_key(KeyClass::Box, m.channel_id(), &[12u8; 32])
            .unwrap();
        let wrong_op = m_ctx.reveal_open(&m, &m_env, enc, &ct, [0u8; 16], author.pseudonym());
        assert_eq!(wrong_op.unwrap_err().code, Code::NotOpen);
        let refused = m_ctx.reveal_open(&m, &m_env, enc, &ct, op_id, author.pseudonym());
        assert_eq!(refused.unwrap_err().code, Code::BadSignature);
        // A non-canonical recipient key is refused before anything is drawn.
        let bad = author_ctx.reveal_seal(&author, sign, m.pseudonym(), [0u8; 32], 42, op_id);
        assert_eq!(bad.unwrap_err().code, Code::NonCanonical);
        // Another member's box key opens nothing: NOT_OPEN.
        let other_env = m_ctx
            .wrap_key(KeyClass::Box, m.channel_id(), &[13u8; 32])
            .unwrap();
        let not_for_me = m_ctx.reveal_open(&m, &other_env, enc, &ct, op_id, author.pseudonym());
        assert_eq!(not_for_me.unwrap_err().code, Code::NotOpen);
    }

    /// The pinned transcript domains of §6.9 point 1: the exact strings, and a golden vector —
    /// Ed25519 is deterministic, so fixed keys and inputs give fixed signatures. A mutant that
    /// swaps the two domains, renames a label or changes the transcript layout changes the golden
    /// bytes (RV-C1); the derivation gates' text scan pins the strings for the JDK replay.
    #[test]
    fn the_transcripts_are_the_designs_golden_bytes() {
        assert_eq!(LABEL_ID, b"ghost/v1/ch/reveal-id");
        assert_eq!(LABEL_PS, b"ghost/v1/ch/reveal-ps");
        assert_eq!(LABEL_INFO, b"ghost/v1/ch/reveal");
        let channel_id = [0x42u8; 32];
        let p_author = [0x01u8; 32];
        let p_recipient = [0x02u8; 32];
        let card = [0x03u8; REVEAL_CARD_BYTES];
        let id = id_transcript(&channel_id, &p_author, &p_recipient, 1_720_000_000);
        let ps = ps_transcript(&channel_id, &card, &p_recipient, 1_720_000_000);
        let seed = [0x07u8; 32];
        let id_sig = ghost_client_dm::sign::sign(&seed, &id);
        let ps_sig = ghost_client_dm::sign::sign(&seed, &ps);
        assert_eq!(
            id,
            [
                b"ghost/v1/ch/reveal-id".as_slice(),
                channel_id.as_slice(),
                p_author.as_slice(),
                p_recipient.as_slice(),
                &1_720_000_000u32.to_be_bytes(),
            ]
            .concat()
        );
        // Printed once, pinned here: the exact bytes a reviewer compares with §6.9 point 1.
        assert_eq!(
            hex(&id_sig),
            "7c48bb295c55a58ad1a6ddae43288ae8ad4fa2830a281c7791597fe0befe336dd7d46d35cccc0c25b4eff2cb4c8e44f168a13cc9f6df413e26e9e27522058d0b",
            "sig_id's golden bytes changed — a domain, a transcript field or the key input moved",
        );
        assert_eq!(
            hex(&ps_sig),
            "d375cc881d243ba18687cf1bc111e4f2d4ad56973c7640dffdb01e3a0d3f029b8a593f4313da948df10f43dd1d9093434b6082da81471d87b5a2217c47a36c04",
            "sig_ps's golden bytes changed — a domain, a transcript field or the key input moved",
        );
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn a_full_round_trip_verifies_every_binding() {
        let (author_ctx, author) = ctx_and_channel();
        let (m_ctx, m) = ctx_and_channel_of([4u8; 32]);
        let identity_seed = [31u8; 32];
        let m_secret = [44u8; 32];
        let m_box = crate::canonical::box_public(&m_secret);
        let m_env = m_ctx
            .wrap_key(KeyClass::Box, m.channel_id(), &m_secret)
            .unwrap();
        let op_id = [6u8; 16];
        let minute = 77u32;
        let (enc, ct) = author_ctx
            .reveal_seal(
                &author,
                |transcript| {
                    // The same transcript the crate builds: sign it, hand out the real card.
                    assert_eq!(
                        transcript,
                        id_transcript(
                            author.channel_id(),
                            &author.pseudonym(),
                            &m.pseudonym(),
                            minute
                        )
                    );
                    let sig = ghost_client_dm::sign::sign(&identity_seed, transcript);
                    Some((sig, card_of(&identity_seed)))
                },
                m.pseudonym(),
                m_box,
                minute,
                op_id,
            )
            .unwrap();
        let opened = m_ctx
            .reveal_open(&m, &m_env, enc, &ct, op_id, author.pseudonym())
            .unwrap();
        assert_eq!(opened.p_author, author.pseudonym());
        assert_eq!(opened.card, card_of(&identity_seed));
        // A different claimed MLS sender is refused.
        let forged_sender = m_ctx.reveal_open(&m, &m_env, enc, &ct, op_id, m.pseudonym());
        assert_eq!(forged_sender.unwrap_err().code, Code::BadSignature);
        // A different opener (a third party's channel handle: the payload's P_M is not theirs).
        let (_third_ctx, third) = ctx_and_channel_of([9u8; 32]);
        let wrong_recipient =
            m_ctx.reveal_open(&third, &m_env, enc, &ct, op_id, author.pseudonym());
        assert_eq!(wrong_recipient.unwrap_err().code, Code::BadSignature);
    }
}
