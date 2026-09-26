//! The shared fixture of the `dm-fuzz` targets (Phase 9 design §16.2 `dm-fuzz`, §9.5 M-8, §22.35).
//!
//! Every DM layer an attacker writes is sealed: an envelope under a key its sender holds (a card
//! key, a pair week key), the intro inner layer under a key the sender derived from the X-Wing
//! encapsulation it made. A target that handed raw bytes to an `open_*` function would stop at the
//! AEAD tag and never reach a parser. So the fixture holds what an attacker-sender holds and seals
//! attacker-chosen plaintext the way the crate does, from the crate's public labels, associated
//! data, hint and transcript; the targets then call the crate's real openers, which decrypt and
//! parse.
//!
//! [`Fixture::new`] checks that sealing against the crate itself before any input runs: the pair
//! and bundle envelopes byte for byte against `seal_pair_with` and `seal_bundle_with`, and the
//! intro layers by an opener that must get past the AEAD and refuse the plaintext instead. A change
//! in the crate's sealing therefore fails every target at its first input rather than turning it
//! into one that returns early unnoticed.

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use ghost_client_dm::card;
use ghost_client_dm::derive::{CardSecret, KemSecret};
use ghost_client_dm::provenance::{CardSource, KeyProvenance, SealKey};
use ghost_client_dm::seal::{
    self, IntroContext, IntroOuter, SealMode, BUCKETS, HEADER_BYTES, INTRO_AD_LABEL,
    INTRO_INNER_LABEL, INTRO_OUTER_FIXED_BYTES, KIND_OLM_NORMAL, SALT_BYTES, SEAL_LABEL,
    SEAL_VERSION, TAG_BYTES,
};
use ghost_client_dm::{pq, sign, DmCode};
use hkdf::Hkdf;
use sha2::Sha256;
use std::sync::OnceLock;

/// The one salt every sealed input uses: the salt is not what a target explores.
pub const SALT: [u8; SALT_BYTES] = [0x5a; SALT_BYTES];

/// What the recipient holds and what an attacker who writes to it holds, from fixed seeds.
pub struct Fixture {
    /// The sender's Ed25519 identity seed.
    pub sender_seed: [u8; 32],
    /// The recipient's Ed25519 identity key.
    pub recipient_pk: [u8; 32],
    /// The recipient's card, which binding v3 and the bundle checks name.
    pub recipient_card: [u8; card::CARD_BYTES],
    /// The inbox (and bundle) namespace the envelopes are bound to.
    pub namespace: [u8; 32],
    /// The sender's and the recipient's Olm identity keys.
    pub oi_sender: [u8; 32],
    /// See `oi_sender`.
    pub oi_recipient: [u8; 32],
    /// The material of the card-derived key of the intro outer layer and of the bundle.
    pub card_key: [u8; 32],
    /// The material of a pair week key.
    pub pair_key: [u8; 32],
    /// The recipient's bundle generation.
    pub gen_id: u32,
    /// The generation's X-Wing seed and encapsulation key.
    pub gen_seed: KemSecret,
    /// See `gen_seed`.
    pub gen_public: Vec<u8>,
    /// The generation's Olm fallback key `F_gen`.
    pub fallback_key: [u8; 32],
    /// One X-Wing ciphertext to `gen_public`, and the secret the attacker shares with it.
    pub ciphertext: Vec<u8>,
    /// See `ciphertext`.
    pub shared: KemSecret,
}

/// The fixture, built and checked once per process.
pub fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let fixture = Fixture::new();
        fixture.check_against_the_crate();
        fixture
    })
}

/// The bucket a selector byte names.
pub fn bucket(selector: u8) -> usize {
    BUCKETS[usize::from(selector) % BUCKETS.len()]
}

/// The bytes of `data` from `at`, or none.
pub fn tail(data: &[u8], at: usize) -> &[u8] {
    data.get(at..).unwrap_or(&[])
}

/// `N` bytes of `data` from `at`, zero-filled past its end.
pub fn array<const N: usize>(data: &[u8], at: usize) -> [u8; N] {
    let mut out = [0u8; N];
    let src = tail(data, at);
    let n = src.len().min(N);
    out[..n].copy_from_slice(&src[..n]);
    out
}

fn aead(key: &[u8; 32]) -> ChaCha20Poly1305 {
    ChaCha20Poly1305::new_from_slice(key).expect("a 32-byte ChaCha20-Poly1305 key")
}

fn encrypt(key: &[u8; 32], plaintext: &[u8], ad: &[u8]) -> Vec<u8> {
    aead(key)
        .encrypt(
            &Nonce::from([0u8; 12]),
            Payload {
                msg: plaintext,
                aad: ad,
            },
        )
        .expect("ChaCha20-Poly1305 encryption of a bucket-sized plaintext")
}

impl Fixture {
    fn new() -> Self {
        let sender_seed = [0x11u8; 32];
        let recipient_seed = [0x22u8; 32];
        let recipient_pk = sign::public_key(&recipient_seed);
        let recipient_card =
            card::build(&recipient_seed, 0, &CardSecret::from_bytes([0x33; 32])).encode();
        let gen_seed = KemSecret::from_bytes([0x44; 32]);
        let gen_public = pq::public_key(&gen_seed).expect("X-Wing key generation from a seed");
        let (ciphertext, shared) =
            pq::encapsulate_with(&gen_public, &[0x55; pq::ENCAPS_RANDOMNESS_BYTES])
                .expect("X-Wing encapsulation to the fixture's own key");
        Fixture {
            sender_seed,
            recipient_pk,
            recipient_card,
            namespace: [0x66; 32],
            oi_sender: [0x77; 32],
            oi_recipient: [0x88; 32],
            card_key: [0x99; 32],
            pair_key: [0xaa; 32],
            gen_id: 7,
            gen_seed,
            gen_public,
            fallback_key: [0xbb; 32],
            ciphertext,
            shared,
        }
    }

    /// The card-derived seal key of the intro outer layer and of the bundle envelope.
    pub fn card_seal_key(&self) -> SealKey {
        SealKey::new(self.card_key, KeyProvenance::Card(CardSource::InPerson))
    }

    /// A pair week key.
    pub fn pair_seal_key(&self) -> SealKey {
        SealKey::new(self.pair_key, KeyProvenance::Kem)
    }

    /// The recipient's intro context for `bucket`.
    pub fn intro_context(&self, bucket: usize) -> IntroContext<'_> {
        IntroContext {
            namespace: &self.namespace,
            bucket,
            gen_id: self.gen_id,
            gen_public: &self.gen_public,
            recipient_oi: &self.oi_recipient,
            recipient_identity_pk: &self.recipient_pk,
        }
    }

    /// An envelope of `bucket` bytes under `key`, opened as `mode`, whose plaintext is
    /// `first_byte || body || zeros` (the crate's `seal_body` writes the mode byte first; a
    /// target passes another to reach R-S2's check). `None` when the body does not fit.
    pub fn seal_envelope(
        &self,
        key: &SealKey,
        bucket: usize,
        mode: SealMode,
        first_byte: u8,
        pair_ad: &[u8; 32],
        body: &[u8],
    ) -> Option<Vec<u8>> {
        let plaintext_len = bucket - HEADER_BYTES - TAG_BYTES;
        if body.len() + 1 > plaintext_len {
            return None;
        }
        let mut plaintext = vec![0u8; plaintext_len];
        plaintext[0] = first_byte;
        plaintext[1..1 + body.len()].copy_from_slice(body);
        let mut info = Vec::with_capacity(SEAL_LABEL.len() + 32);
        info.extend_from_slice(SEAL_LABEL);
        info.extend_from_slice(&self.namespace);
        let mut derived = [0u8; 32];
        Hkdf::<Sha256>::new(Some(&SALT), key.as_bytes())
            .expand(&info, &mut derived)
            .expect("HKDF-SHA256 with L = 32");
        let ad = seal::associated_data(&self.namespace, bucket, mode, pair_ad);
        let ciphertext = encrypt(&derived, &plaintext, &ad);
        let mut blob = Vec::with_capacity(bucket);
        blob.extend_from_slice(&SALT);
        blob.extend_from_slice(&seal::hint(&seal::recognition_key(key), &SALT));
        blob.extend_from_slice(&ciphertext);
        Some(blob)
    }

    /// The length of the intro inner plaintext in `bucket`.
    pub fn intro_inner_len(bucket: usize) -> usize {
        bucket - INTRO_OUTER_FIXED_BYTES - HEADER_BYTES - TAG_BYTES
    }

    /// The intro inner layer of `bucket` around `plain` (truncated or zero-filled to the layer's
    /// length), under the key the attacker's encapsulation shares with the recipient.
    pub fn seal_intro_inner(&self, bucket: usize, plain: &[u8]) -> Vec<u8> {
        let mut inner = vec![0u8; Self::intro_inner_len(bucket)];
        let n = plain.len().min(inner.len());
        inner[..n].copy_from_slice(&plain[..n]);
        let transcript = seal::intro_transcript(&self.intro_context(bucket), &self.ciphertext);
        let mut key = [0u8; 32];
        Hkdf::<Sha256>::new(Some(&transcript), self.shared.as_bytes())
            .expand(INTRO_INNER_LABEL, &mut key)
            .expect("HKDF-SHA256 with L = 32");
        let mut ad = Vec::with_capacity(INTRO_AD_LABEL.len() + 1 + 32);
        ad.extend_from_slice(INTRO_AD_LABEL);
        ad.push(SEAL_VERSION);
        ad.extend_from_slice(&transcript);
        encrypt(&key, &inner, &ad)
    }

    /// What `open_intro_outer` returns for an envelope carrying `inner` under the fixture's
    /// ciphertext.
    pub fn intro_outer(&self, bucket: usize, inner: Vec<u8>) -> IntroOuter {
        IntroOuter {
            gen_id: self.gen_id,
            ciphertext: self.ciphertext.clone(),
            inner,
            bucket,
        }
    }

    /// The body of a pair or provisional envelope: `kind || u32 len || l1`.
    pub fn symmetric_body(l1: &[u8]) -> Vec<u8> {
        let mut body = Vec::with_capacity(5 + l1.len());
        body.push(KIND_OLM_NORMAL);
        body.extend_from_slice(&(l1.len() as u32).to_be_bytes());
        body.extend_from_slice(l1);
        body
    }

    /// The checks of the module documentation. Panics (a crash at the first input) if the
    /// fixture no longer seals what the crate opens.
    pub fn check_against_the_crate(&self) {
        let l1 = [0x42u8; 64];
        for bucket in BUCKETS {
            let crate_blob = seal::seal_pair_with(
                &self.pair_seal_key(),
                &self.namespace,
                bucket,
                &self.oi_sender,
                &self.oi_recipient,
                &l1,
                &SALT,
            )
            .expect("the crate seals a pair envelope");
            let ours = self.seal_envelope(
                &self.pair_seal_key(),
                bucket,
                SealMode::Pair,
                SealMode::Pair.as_u8(),
                &seal::pair_ad(&self.oi_sender, &self.oi_recipient),
                &Self::symmetric_body(&l1),
            );
            assert_eq!(
                ours.as_deref(),
                Some(&crate_blob[..]),
                "pair envelope, bucket {bucket}"
            );
        }
        let plain = [0x24u8; 1393];
        let crate_blob =
            seal::seal_bundle_with(&self.card_seal_key(), &self.namespace, &plain, &SALT)
                .expect("the crate seals a bundle envelope");
        let ours = self.seal_envelope(
            &self.card_seal_key(),
            BUCKETS[0],
            SealMode::Bundle,
            SealMode::Bundle.as_u8(),
            &[0u8; 32],
            &plain,
        );
        assert_eq!(ours.as_deref(), Some(&crate_blob[..]), "bundle envelope");
        // The inner layer: a wrong kind byte must be refused by the parser (`NonCanonical`), not
        // by the AEAD (`NotOpen`), in every bucket.
        for bucket in BUCKETS {
            let outer = self.intro_outer(bucket, self.seal_intro_inner(bucket, &[0x00]));
            let opened = seal::open_intro_checked(
                &self.gen_seed,
                &self.intro_context(bucket),
                &outer,
                &self.fallback_key,
            );
            assert_eq!(
                opened.err(),
                Some(DmCode::NonCanonical),
                "intro inner layer, bucket {bucket}"
            );
            // The outer layer the same way: a body too short for the ciphertext is refused after
            // the AEAD.
            let blob = self
                .seal_envelope(
                    &self.card_seal_key(),
                    bucket,
                    SealMode::Intro,
                    SealMode::Intro.as_u8(),
                    &[0u8; 32],
                    &[0u8; 8],
                )
                .expect("an 8-byte body fits");
            let blob = &blob[..];
            let outer = seal::open_intro_outer(&self.card_seal_key(), &self.namespace, blob);
            assert!(
                matches!(outer, Ok(ref o) if o.gen_id == 0),
                "intro outer layer, bucket {bucket}: the padded body opens"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_fixture_seals_what_the_crate_opens() {
        super::fixture();
    }
}
