//! PQ1 and PQ5 (design §15.5 "PQ" row; RG-5 and §16.1; §15.7 PM-32; forward notes §22.19), over a
//! scripted DM world with real Olm sessions, the real seal modes and the real X-Wing wrapper.
//!
//! **PQ1**, "every intro open performs exactly one decapsulation and `k_in` depends on `ss`
//! (spy)": the spy of [`crate::pq::spy`] counts the decapsulations of every open of every intro
//! envelope of the world, through both public openers, and perturbs the decapsulated secret of a
//! repeated open, which must then be refused while the ciphertext, the transcript and every other
//! input are unchanged. The same check runs as an **assertion** around every `openIntro` of the
//! host library the JVM worlds load (`pq-spy`; `jni.rs`, `pq::spy::assert_intro_open`), and the
//! tests below also show that assertion refusing opens that break it.
//!
//! **PQ5**, the bump assertion of RG-5: every intro envelope and every `seal_root_pq` of the world
//! carries a 1 120-byte X-Wing ciphertext, `k_in` depends on `ss`, and a `gate`-variant client
//! whose intro inner layer is sealed without the KEM is refused by an honest recipient. "Carries a
//! ciphertext" is measured **independently of this crate**: RustCrypto `x-wing` 0.1.0 (the
//! dev-only oracle of §9.2) decapsulates the 1 120 bytes at their offset under the recipient's
//! seed, and the inner layer is opened, or the root re-derived, from that secret with `hkdf`,
//! `sha2` and `chacha20poly1305` called directly on the labels written out below. A vodozemac or
//! libcrux bump whose KEM stops agreeing with X-Wing draft-06, or whose secret stops keying the
//! layer, fails here even while both sides of GHOST still agree with each other.
//!
//! **Why these two, and not T35 (§22.16 item 18).** `k_in` is derived and used inside the seal and
//! is never a `SealKey`, so no provenance tag describes the X-Wing-keyed layer: PM-32, "the intro
//! inner layer sealed without the X-Wing KEM", is not expressible to T35. PM-32's shapes are the
//! source patches of `client-core/dm/mutants/`; `scripts/gates/pq-mutants.sh` applies each one and
//! requires the tests its header names to fail.
//!
//! Test builds only: the module is `cfg(test)`, and the gate-variant sealer it drives is
//! `seal::gate`, which is `cfg(test)` too.

use crate::card;
use crate::codec::{self, DmContent, Kind, SealRootPq, Tlv};
use crate::derive::{self, CardLabel, KemSecret, MessagingBranch, OlmSecret, ReplySeed};
use crate::olm::message::L1Header;
use crate::olm::session::{self, Slot, StoredSession};
use crate::pq::{self, spy};
use crate::pqroot::{self, PqRootParties};
use crate::provenance::{CardSource, KeyProvenance, SealKey};
use crate::result::{DmCode, DmResult};
use crate::seal::gate::{self, InnerKey};
use crate::seal::{self, IntroContext, IntroOuter, IntroPlain, IntroSender, PreKeyFields, BUCKETS};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::sync::OnceLock;

const TODAY: u32 = 20_354;
const MINUTE: u32 = 29_000_000;
const BASE_WEEK: u64 = 2_907;

// The labels and the length of §6.4 and §9.4, written out rather than imported: the oracle must
// not read the constants a mutant, or a careless edit, could change together with the code.
const INTRO_KEM_LABEL: &[u8] = b"ghost/v1/dm-intro-kem";
const INTRO_INNER_LABEL: &[u8] = b"ghost/v1/dm-intro-inner";
const INTRO_AD_LABEL: &[u8] = b"ghost/v1/dm-intro";
const INTRO_AD_VERSION: u8 = 0x02;
const PQ_ROOT_LABEL: &[u8] = b"ghost/v1/dm/pq-root";
/// X-Wing draft-06: a 1 088-byte ML-KEM-768 ciphertext and a 32-byte X25519 share.
const XWING_CT: usize = 1088 + 32;
/// The intro envelope before the ciphertext (§6.2, §6.4): salt, hint, the outer tag, the mode byte
/// and `gen_id`.
const INTRO_PREFIX: usize = 16 + 16 + 16 + 1 + 4;

// The devices of the world.
const A: usize = 0;
const B: usize = 1;
const C: usize = 2;
/// The `gate`-variant client: a real device with a real Olm session whose sealer drops the KEM.
const G: usize = 3;

// -------------------------------------------------------------------------------------------
// The scripted world
// -------------------------------------------------------------------------------------------

/// A bundle generation: the X-Wing seed, its key, and the Olm fallback key PreKey messages name.
struct Generation {
    gen_id: u32,
    seed: [u8; 32],
    public: Vec<u8>,
    fallback_secret: [u8; 32],
    fallback_public: [u8; 32],
}

impl Generation {
    fn new(gen_id: u32, byte: u8) -> Self {
        let seed = [byte; 32];
        let fallback_secret = [byte ^ 0x80; 32];
        Self {
            gen_id,
            seed,
            public: pq::public_key(&KemSecret::from_bytes(seed)).expect("keygen"),
            fallback_secret,
            fallback_public: derive::olm_identity_public(&OlmSecret::from_bytes(fallback_secret)),
        }
    }

    fn secret(&self) -> KemSecret {
        KemSecret::from_bytes(self.seed)
    }
}

/// A device: the secrets `ctxOpen` derives, its card 0 and its generations.
struct Device {
    identity_seed: [u8; 32],
    olm_identity: OlmSecret,
    olm_signing: OlmSecret,
    oi: [u8; 32],
    card: card::Card,
    card_bytes: [u8; card::CARD_BYTES],
    namespace: [u8; 32],
    intro_key: [u8; 32],
    generations: Vec<Generation>,
}

impl Device {
    fn new(byte: u8, generations: Vec<Generation>) -> Self {
        let branch = MessagingBranch::from_bytes([byte; 32]);
        let identity_seed = [byte ^ 0x40; 32];
        let olm_identity = derive::derive_olm_identity(&branch);
        let card_secret = derive::derive_card_secret(&branch, 0);
        let card = card::build(&identity_seed, 0, &card_secret);
        Self {
            identity_seed,
            oi: derive::olm_identity_public(&olm_identity),
            olm_identity,
            olm_signing: derive::derive_olm_account_signing(&branch),
            card_bytes: card.encode(),
            namespace: derive::derive_inbox_namespace(&card_secret),
            intro_key: derive::derive_card_value(&card_secret, CardLabel::IntroOuter),
            card,
            generations,
        }
    }

    /// The intro key as a **sender** derives it from the card it holds (`card_seal_key` in
    /// `jni.rs` tags every contact card `Link`).
    fn sender_intro_key(&self) -> SealKey {
        let parsed = card::parse(&self.card_bytes).expect("own card");
        SealKey::new(
            derive::derive_card_value(&parsed.card_secret, CardLabel::IntroOuter),
            KeyProvenance::Card(CardSource::Link),
        )
    }

    /// The intro key as the owner of the card opens with it (`openIntro` in `jni.rs`).
    fn own_intro_key(&self) -> SealKey {
        SealKey::new(self.intro_key, KeyProvenance::Card(CardSource::InPerson))
    }

    fn context(&self, generation: usize, bucket: usize) -> IntroContext<'_> {
        let generation = &self.generations[generation];
        IntroContext {
            namespace: &self.namespace,
            bucket,
            gen_id: generation.gen_id,
            gen_public: &generation.public,
            recipient_oi: &self.oi,
            recipient_identity_pk: &self.card.identity_pk,
        }
    }
}

/// One intro envelope of the world, with what its recipient must find inside.
struct Intro {
    label: String,
    recipient: usize,
    generation: usize,
    blob: Vec<u8>,
    sender_card: [u8; card::CARD_BYTES],
    l1: Vec<u8>,
    reply_seed: [u8; 32],
    /// `None`: the production `seal::seal_intro`. `Some`: the gate-variant client.
    sealed_by: Option<InnerKey>,
}

impl Intro {
    /// Sealed by an honest client: the production sealer, or the gate client's KEM control.
    fn honest(&self) -> bool {
        matches!(self.sealed_by, None | Some(InnerKey::Kem))
    }
}

/// One `seal_root_pq` of the world, as the target decoded it from the L0 it arrived in.
struct Root {
    label: String,
    offerer: usize,
    target: usize,
    generation: usize,
    /// The 1 166-byte TLV value the target's `codec::decode` returned.
    value: Vec<u8>,
    /// The root the offerer derived and keeps.
    root: [u8; 32],
}

/// An Olm session between two devices of the world, from the initiator's side and the responder's.
struct Conversation {
    sender: usize,
    recipient: usize,
    generation: usize,
    sender_state: Vec<u8>,
    recipient_state: Option<Vec<u8>>,
    reply_seed: ReplySeed,
    sent: u16,
}

/// Which side of a conversation offers a root.
#[derive(Clone, Copy)]
enum Offerer {
    Initiator,
    Responder,
}

struct World {
    devices: Vec<Device>,
    intros: Vec<Intro>,
    roots: Vec<Root>,
}

/// An L0 text message.
fn text(body: &str, index: u16, ext: Vec<Tlv>) -> Vec<u8> {
    DmContent {
        kind: Kind::Text,
        message_id: [index as u8; 16],
        author_minute: MINUTE,
        minute_index: index,
        timer_code: 0,
        timer_version: 0,
        quote_ref: None,
        body: body.as_bytes().to_vec(),
        ext,
    }
    .encode()
    .expect("an L0 inside its bucket")
}

impl World {
    fn start(&self, sender: usize, recipient: usize, generation: usize) -> Conversation {
        let from = &self.devices[sender];
        let to = &self.devices[recipient];
        let outbound = session::session_outbound(
            &from.olm_identity,
            &from.olm_signing,
            &to.oi,
            &to.generations[generation].fallback_public,
            TODAY,
        )
        .expect("outbound session");
        Conversation {
            sender,
            recipient,
            generation,
            sender_state: outbound.state,
            recipient_state: None,
            reply_seed: outbound.reply_seed,
            sent: 0,
        }
    }

    /// The initiator's next message, a PreKey message while the session is unacknowledged, sealed
    /// in intro mode. Every honest flight is then opened by its recipient and accepted by its Olm
    /// layer, so the world is a working one and not a list of envelopes.
    fn intro(
        &mut self,
        conversation: &mut Conversation,
        label: &str,
        bucket: usize,
        sealed_by: Option<InnerKey>,
    ) {
        let l0 = text(label, conversation.sent, Vec::new());
        conversation.sent += 1;
        let encrypted = session::encrypt(&conversation.sender_state, &l0, TODAY).expect("encrypt");
        assert!(
            encrypted.is_pre_key,
            "{label}: an unacknowledged session sends PreKey messages"
        );
        conversation.sender_state = encrypted.state;
        let blob = self.seal(conversation, &encrypted.l1, bucket, sealed_by);
        if matches!(sealed_by, None | Some(InnerKey::Kem)) {
            let plaintext = self.receive(conversation, &blob);
            assert_eq!(
                plaintext, l0,
                "{label}: the recipient's Olm layer reads the flight"
            );
        }
        self.record(conversation, label, blob, encrypted.l1, sealed_by);
    }

    /// The same PreKey message sealed again in a new envelope, as a re-send of an unacknowledged
    /// message is (§6.4: every envelope has its own encapsulation).
    fn reseal(&mut self, conversation: &Conversation, of: usize, label: &str, bucket: usize) {
        let l1 = self.intros[of].l1.clone();
        let blob = self.seal(conversation, &l1, bucket, None);
        self.record(conversation, label, blob, l1, None);
    }

    fn seal(
        &self,
        conversation: &Conversation,
        l1: &[u8],
        bucket: usize,
        sealed_by: Option<InnerKey>,
    ) -> Vec<u8> {
        let from = &self.devices[conversation.sender];
        let to = &self.devices[conversation.recipient];
        let L1Header::PreKey { base_key, .. } = session::header(l1, true).expect("header") else {
            panic!("a flight of an unacknowledged session is a PreKey message");
        };
        let sender = IntroSender {
            identity_seed: &from.identity_seed,
            card: &from.card_bytes,
            oi: &from.oi,
            base_key: &base_key,
            binding_minute: MINUTE,
            reply_seed: &conversation.reply_seed,
        };
        let context = to.context(conversation.generation, bucket);
        let outer_key = to.sender_intro_key();
        match sealed_by {
            None => seal::seal_intro(&outer_key, &context, &sender, l1),
            Some(variant) => {
                let mut randomness = [0u8; pq::ENCAPS_RANDOMNESS_BYTES];
                pq::fill_random(&mut randomness);
                gate::seal_intro(
                    variant,
                    &outer_key,
                    &context,
                    &sender,
                    l1,
                    &seal::random_salt(),
                    &randomness,
                )
            }
        }
        .expect("seal")
    }

    /// The recipient opens an honest flight and hands its L1 to Olm: a new inbound session for the
    /// first flight, the stored one for the next.
    fn receive(&self, conversation: &mut Conversation, blob: &[u8]) -> Vec<u8> {
        let to = &self.devices[conversation.recipient];
        let from = &self.devices[conversation.sender];
        let generation = &to.generations[conversation.generation];
        let outer =
            seal::open_intro_outer(&to.own_intro_key(), &to.namespace, blob).expect("outer");
        let (opened, _) = seal::open_intro_checked(
            &generation.secret(),
            &to.context(conversation.generation, outer.bucket),
            &outer,
            &generation.fallback_public,
        )
        .expect("an honest flight opens");
        let (state, plaintext) = match &conversation.recipient_state {
            None => {
                let inbound = session::session_inbound(
                    &to.olm_identity,
                    &to.olm_signing,
                    generation.fallback_secret,
                    &from.oi,
                    &opened.l1,
                    TODAY,
                )
                .expect("inbound session");
                (inbound.state, inbound.plaintext)
            }
            Some(state) => {
                let decrypted = session::decrypt(
                    &[StoredSession {
                        slot: Slot::Current,
                        state,
                    }],
                    &opened.l1,
                    true,
                    TODAY,
                )
                .expect("the next flight of the session");
                (decrypted.state, decrypted.plaintext)
            }
        };
        conversation.recipient_state = Some(state);
        plaintext
    }

    fn record(
        &mut self,
        conversation: &Conversation,
        label: &str,
        blob: Vec<u8>,
        l1: Vec<u8>,
        sealed_by: Option<InnerKey>,
    ) {
        self.intros.push(Intro {
            label: label.to_string(),
            recipient: conversation.recipient,
            generation: conversation.generation,
            blob,
            sender_card: self.devices[conversation.sender].card_bytes,
            l1,
            reply_seed: *conversation.reply_seed.as_bytes(),
            sealed_by,
        });
    }

    /// A PQ-C root offered to one of the other side's generations (§9.4), carried in the L0 of a
    /// **normal** message of an acknowledged session (§21.3) and decoded by its target.
    fn root(
        &mut self,
        conversation: &mut Conversation,
        offerer: Offerer,
        generation: usize,
        root_gen: u16,
        label: &str,
    ) {
        let (from, to) = match offerer {
            Offerer::Responder => (conversation.recipient, conversation.sender),
            Offerer::Initiator => (conversation.sender, conversation.recipient),
        };
        let offering = &self.devices[from];
        let target = &self.devices[to];
        let key = &target.generations[generation];
        let offer = pqroot::offer(
            PqRootParties {
                oi_offerer: &offering.oi,
                oi_target: &target.oi,
            },
            key.gen_id,
            &key.public,
            BASE_WEEK,
            root_gen,
        )
        .expect("offer");
        let l0 = text(
            label,
            conversation.sent,
            vec![Tlv {
                tlv_type: codec::TLV_SEAL_ROOT_PQ,
                value: offer.tlv.encode().expect("the TLV"),
            }],
        );
        conversation.sent += 1;
        let responder = conversation
            .recipient_state
            .clone()
            .expect("a root travels in an established session");
        let (own, peer) = match offerer {
            Offerer::Responder => (responder, conversation.sender_state.clone()),
            Offerer::Initiator => (conversation.sender_state.clone(), responder),
        };
        let encrypted = session::encrypt(&own, &l0, TODAY).expect("encrypt");
        assert!(
            !encrypted.is_pre_key,
            "{label}: a root rides only in a normal message (§21.3)"
        );
        let decrypted = session::decrypt(
            &[StoredSession {
                slot: Slot::Current,
                state: &peer,
            }],
            &encrypted.l1,
            false,
            TODAY,
        )
        .expect("decrypt");
        match offerer {
            Offerer::Responder => {
                conversation.recipient_state = Some(encrypted.state);
                conversation.sender_state = decrypted.state;
            }
            Offerer::Initiator => {
                conversation.sender_state = encrypted.state;
                conversation.recipient_state = Some(decrypted.state);
            }
        }
        let received = codec::decode(&decrypted.plaintext).expect("the target decodes the L0");
        let value = received
            .ext
            .iter()
            .find(|tlv| tlv.tlv_type == codec::TLV_SEAL_ROOT_PQ)
            .expect("the seal_root_pq arrived")
            .value
            .clone();
        self.roots.push(Root {
            label: label.to_string(),
            offerer: from,
            target: to,
            generation,
            value,
            root: *offer.root.as_bytes(),
        });
    }

    fn device(&self, index: usize) -> &Device {
        &self.devices[index]
    }

    fn generation_of(&self, intro: &Intro) -> &Generation {
        &self.devices[intro.recipient].generations[intro.generation]
    }

    fn open_outer(&self, intro: &Intro) -> DmResult<IntroOuter> {
        let to = self.device(intro.recipient);
        seal::open_intro_outer(&to.own_intro_key(), &to.namespace, &intro.blob)
    }

    /// §2.6 function 12's opener: the inner layer, binding v3 and the fallback key in one
    /// decapsulation.
    fn open_checked(&self, intro: &Intro, outer: &IntroOuter) -> DmResult<(IntroPlain, L1Header)> {
        let to = self.device(intro.recipient);
        let generation = self.generation_of(intro);
        seal::open_intro_checked(
            &generation.secret(),
            &to.context(intro.generation, outer.bucket),
            outer,
            &generation.fallback_public,
        )
    }

    /// The other public opener, with the PreKey fields taken from the flight itself.
    fn open_inner(&self, intro: &Intro, outer: &IntroOuter) -> DmResult<IntroPlain> {
        let to = self.device(intro.recipient);
        let generation = self.generation_of(intro);
        let L1Header::PreKey {
            identity_key,
            base_key,
            one_time_key,
            ..
        } = session::header(&intro.l1, true).expect("header")
        else {
            panic!("an intro carries a PreKey message");
        };
        seal::open_intro_inner(
            &generation.secret(),
            &to.context(intro.generation, outer.bucket),
            outer,
            &PreKeyFields {
                identity_key: &identity_key,
                base_key: &base_key,
                fallback_key: &one_time_key,
            },
            &generation.fallback_public,
        )
    }

    fn honest(&self) -> impl Iterator<Item = &Intro> {
        self.intros.iter().filter(|intro| intro.honest())
    }

    fn without_kem(&self) -> impl Iterator<Item = &Intro> {
        self.intros.iter().filter(|intro| !intro.honest())
    }
}

/// The world, scripted once per test binary.
///
/// 1. A → B (B's generation 1): the first flight at 4 KiB and a second PreKey message of the same
///    unacknowledged session at 16 KiB; the first flight re-sent in a new envelope at 64 KiB.
/// 2. C → B at 64 KiB. 3. B → A, B's own first flight, at 4 KiB. 4. C → B's generation 2, a new
///    session after B's rotation, at 16 KiB.
/// 5. PQ-C: B answers A with a `seal_root_pq` to A's generation, A (now acknowledged) answers with
///    one to B's generation 2, and B offers C one in C's first session.
/// 6. G, the gate-variant client, introduces itself to B at every bucket and to A at 4 KiB, once
///    with the KEM (the control) and once per way of sealing the inner layer without it.
fn world() -> &'static World {
    static WORLD: OnceLock<World> = OnceLock::new();
    WORLD.get_or_init(|| {
        let mut world = World {
            devices: vec![
                Device::new(0x41, vec![Generation::new(0x4101, 0xa1)]),
                Device::new(
                    0x42,
                    vec![Generation::new(0x4201, 0xb1), Generation::new(0x4202, 0xb2)],
                ),
                Device::new(0x43, vec![Generation::new(0x4301, 0xc1)]),
                Device::new(0x47, vec![Generation::new(0x4701, 0xd1)]),
            ],
            intros: Vec::new(),
            roots: Vec::new(),
        };
        let mut a_to_b = world.start(A, B, 0);
        world.intro(&mut a_to_b, "A to B, first flight", BUCKETS[0], None);
        world.intro(&mut a_to_b, "A to B, second flight", BUCKETS[1], None);
        world.reseal(&a_to_b, 0, "A to B, first flight re-sent", BUCKETS[2]);
        let mut c_to_b = world.start(C, B, 0);
        world.intro(&mut c_to_b, "C to B", BUCKETS[2], None);
        let mut b_to_a = world.start(B, A, 0);
        world.intro(&mut b_to_a, "B to A", BUCKETS[0], None);
        let mut c_to_b2 = world.start(C, B, 1);
        world.intro(&mut c_to_b2, "C to B, generation 2", BUCKETS[1], None);

        world.root(&mut a_to_b, Offerer::Responder, 0, 0, "B offers A");
        world.root(
            &mut a_to_b,
            Offerer::Initiator,
            1,
            0,
            "A offers B at generation 2",
        );
        world.root(&mut c_to_b, Offerer::Responder, 0, 0, "B offers C");

        let mut g_to_b = world.start(G, B, 0);
        let mut g_to_a = world.start(G, A, 0);
        let variants: Vec<InnerKey> = [InnerKey::Kem]
            .into_iter()
            .chain(InnerKey::WITHOUT_KEM)
            .collect();
        for bucket in BUCKETS {
            for variant in &variants {
                let label = format!("G to B, {variant:?}, {bucket} B");
                world.intro(&mut g_to_b, &label, bucket, Some(*variant));
            }
        }
        for variant in &variants {
            let label = format!("G to A, {variant:?}");
            world.intro(&mut g_to_a, &label, BUCKETS[0], Some(*variant));
        }
        world
    })
}

// -------------------------------------------------------------------------------------------
// The oracle: RustCrypto x-wing and the primitives, on the formulas of §6.4 and §9.4
// -------------------------------------------------------------------------------------------

/// Decapsulates `ct` under the seed with RustCrypto `x-wing`, and returns the secret and the
/// encapsulation key that seed has **under the oracle**.
fn oracle_decapsulate(seed: &[u8; 32], ct: &[u8]) -> ([u8; 32], Vec<u8>) {
    use x_wing::{Decapsulate, Decapsulator, KeyExport};
    let key = x_wing::DecapsulationKey::from(*seed);
    let public = key.encapsulation_key().to_bytes().to_vec();
    let ct = x_wing::Ciphertext::try_from(ct).expect("exactly an X-Wing ciphertext");
    let secret: [u8; 32] = key
        .decapsulate(&ct)
        .as_slice()
        .try_into()
        .expect("a 32-byte secret");
    (secret, public)
}

/// `T_in` of §6.4.
fn oracle_transcript(
    to: &Device,
    bucket: usize,
    gen_id: u32,
    public: &[u8],
    ct: &[u8],
) -> [u8; 32] {
    Sha256::new()
        .chain_update(INTRO_KEM_LABEL)
        .chain_update(to.namespace)
        .chain_update((bucket as u32).to_be_bytes())
        .chain_update(gen_id.to_be_bytes())
        .chain_update(public)
        .chain_update(ct)
        .chain_update(to.oi)
        .chain_update(to.card.identity_pk)
        .finalize()
        .into()
}

/// The inner layer opened under `k_in = HKDF-SHA256(ikm = secret, salt = T_in, info)` with
/// `AD_in = label || 0x02 || T_in` (§6.4), or `None`.
fn oracle_open_inner(secret: &[u8; 32], transcript: &[u8; 32], inner: &[u8]) -> Option<Vec<u8>> {
    let mut key = [0u8; 32];
    Hkdf::<Sha256>::new(Some(transcript), secret)
        .expand(INTRO_INNER_LABEL, &mut key)
        .expect("L = 32");
    let mut ad = INTRO_AD_LABEL.to_vec();
    ad.push(INTRO_AD_VERSION);
    ad.extend_from_slice(transcript);
    ChaCha20Poly1305::new_from_slice(&key)
        .expect("a 32-byte key")
        .decrypt(
            &Nonce::from([0u8; 12]),
            Payload {
                msg: inner,
                aad: &ad,
            },
        )
        .ok()
}

/// The PQ-C root of §9.4.
fn oracle_root(
    root_rand: &[u8],
    secret: &[u8; 32],
    oi_offerer: &[u8; 32],
    oi_target: &[u8; 32],
    gen_id: u32,
    public: &[u8],
    ct: &[u8],
) -> [u8; 32] {
    let salt = Sha256::new()
        .chain_update(PQ_ROOT_LABEL)
        .chain_update(oi_offerer)
        .chain_update(oi_target)
        .chain_update(gen_id.to_be_bytes())
        .chain_update(public)
        .chain_update(ct)
        .finalize();
    let mut ikm = root_rand.to_vec();
    ikm.extend_from_slice(secret);
    let mut root = [0u8; 32];
    Hkdf::<Sha256>::new(Some(salt.as_slice()), &ikm)
        .expand(PQ_ROOT_LABEL, &mut root)
        .expect("L = 32");
    root
}

fn flipped(secret: &[u8; 32]) -> [u8; 32] {
    let mut out = *secret;
    out[0] ^= 1;
    out
}

/// Runs `f` and returns its result with the decapsulations it performed on this thread.
fn decapsulations_in<T>(f: impl FnOnce() -> T) -> (T, u64) {
    let before = spy::decapsulations();
    let out = f();
    (out, spy::decapsulations() - before)
}

/// Runs `f` with the next decapsulated secret perturbed, and checks the perturbation was consumed
/// by exactly one decapsulation.
fn with_perturbed_secret<T>(label: &str, f: impl FnOnce() -> T) -> T {
    spy::disarm();
    spy::perturb_next_decapsulation();
    let (out, used) = decapsulations_in(f);
    assert!(
        !spy::disarm(),
        "{label}: the perturbation was never consumed by a decapsulation"
    );
    assert_eq!(
        used, 1,
        "{label}: the perturbed open decapsulated {used} times"
    );
    out
}

// -------------------------------------------------------------------------------------------
// PQ1
// -------------------------------------------------------------------------------------------

/// PQ1, first half: every open of every intro envelope of the world performs **exactly one**
/// decapsulation — through `open_intro_checked` (§2.6 function 12's opener) and through
/// `open_intro_inner`, for the honest envelopes that open and for the gate-variant ones that are
/// refused. The card-keyed outer layer performs none, and an envelope refused before the KEM (the
/// generation it names is not the one loaded) performs none either.
#[test]
fn pq1_every_intro_open_of_the_world_decapsulates_exactly_once() {
    let world = world();
    let mut opens = 0;
    for intro in &world.intros {
        let (outer, used) = decapsulations_in(|| world.open_outer(intro));
        let outer = outer.expect("the outer layer opens under the recipient's card");
        assert_eq!(
            used, 0,
            "{}: the card-keyed layer holds no KEM",
            intro.label
        );

        let (checked, used) = decapsulations_in(|| world.open_checked(intro, &outer));
        assert_eq!(used, 1, "{}: open_intro_checked", intro.label);
        let (inner, used) = decapsulations_in(|| world.open_inner(intro, &outer));
        assert_eq!(used, 1, "{}: open_intro_inner", intro.label);
        if intro.honest() {
            let (plain, header) = checked.expect("an honest envelope opens");
            assert_eq!(plain.l1, intro.l1, "{}", intro.label);
            assert!(header.is_pre_key());
            assert_eq!(inner.expect("and through the other opener").l1, intro.l1);
        } else {
            assert_eq!(checked.err(), Some(DmCode::NotOpen), "{}", intro.label);
            assert_eq!(inner.err(), Some(DmCode::NotOpen), "{}", intro.label);
        }
        opens += 2;

        // Refused before the KEM: another generation of the same recipient, or none of its own.
        let to = world.device(intro.recipient);
        let generation = world.generation_of(intro);
        let mut elsewhere = to.context(intro.generation, outer.bucket);
        elsewhere.gen_id ^= 1;
        let (refused, used) = decapsulations_in(|| {
            seal::open_intro_checked(
                &generation.secret(),
                &elsewhere,
                &outer,
                &generation.fallback_public,
            )
        });
        assert_eq!(refused.err(), Some(DmCode::NotOpen));
        assert_eq!(used, 0, "{}: refused before the KEM", intro.label);
    }
    let honest = world.honest().count();
    let refused = world.without_kem().count();
    assert!(
        honest >= 10 && refused >= 12,
        "{honest} honest and {refused} refused envelopes"
    );
    assert_eq!(opens, 2 * (honest + refused));
}

/// PQ1, second half: **`k_in` depends on `ss`**. Every honest envelope opens twice to the same
/// plaintext (the key is a function of what the open reads), and the same open with nothing
/// changed but the decapsulated secret — one bit of it, flipped by the spy after the KEM — is
/// `NOT_OPEN` through both openers. An opener whose inner key came from the ciphertext, the
/// transcript, the card or a constant would open it anyway.
#[test]
fn pq1_k_in_depends_on_the_decapsulated_secret_in_every_intro_open() {
    let world = world();
    let mut checked = 0;
    for intro in world.honest() {
        let outer = world.open_outer(intro).expect("outer");
        let (first, _) = world.open_checked(intro, &outer).expect("open");
        let (second, _) = world.open_checked(intro, &outer).expect("open again");
        assert_eq!(first.l1, second.l1);
        assert_eq!(first.reply_seed.as_bytes(), second.reply_seed.as_bytes());
        assert_eq!(first.reply_seed.as_bytes(), &intro.reply_seed);
        assert_eq!(first.sender_card, second.sender_card);
        assert_eq!(first.sender_card, intro.sender_card);
        assert_eq!(first.binding_minute, MINUTE);

        let perturbed = with_perturbed_secret(&intro.label, || world.open_checked(intro, &outer));
        assert_eq!(
            perturbed.err(),
            Some(DmCode::NotOpen),
            "{}: opened with its decapsulated secret perturbed",
            intro.label
        );
        let perturbed = with_perturbed_secret(&intro.label, || world.open_inner(intro, &outer));
        assert_eq!(perturbed.err(), Some(DmCode::NotOpen), "{}", intro.label);
        checked += 1;
    }
    assert!(checked >= 10, "{checked} honest envelopes");
}

/// The assertion `ghost-dm-host` runs around every `openIntro` (`pq::spy::assert_intro_open`)
/// accepts every open of the world: the honest ones return their plaintext and the gate-variant
/// ones their refusal, with no panic.
#[test]
fn pq1_the_host_assertion_passes_every_open_of_the_world() {
    let world = world();
    for intro in &world.intros {
        let outer = world.open_outer(intro).expect("outer");
        let opened = spy::assert_intro_open(|| world.open_checked(intro, &outer));
        if intro.honest() {
            assert_eq!(opened.expect("opens").0.l1, intro.l1, "{}", intro.label);
        } else {
            assert_eq!(opened.err(), Some(DmCode::NotOpen), "{}", intro.label);
        }
    }
}

/// A fresh generation and an encapsulation to it, for the assertion's own tests.
fn encapsulated() -> (KemSecret, Vec<u8>) {
    let generation = Generation::new(0x0001_0001, 0x2b);
    let (ct, _) = pq::encapsulate(&generation.public).expect("encapsulate");
    (generation.secret(), ct)
}

/// The assertion is not vacuous: an open that succeeds without a decapsulation panics with PQ1.
#[test]
#[should_panic(expected = "PQ1: an intro open that succeeded performed 0 decapsulations")]
fn pq1_the_host_assertion_refuses_an_open_without_a_decapsulation() {
    let _ = spy::assert_intro_open(|| Ok::<(), DmCode>(()));
}

/// ... an open that decapsulates twice panics ...
#[test]
#[should_panic(expected = "PQ1: an intro open that succeeded performed 2 decapsulations")]
fn pq1_the_host_assertion_refuses_an_open_that_decapsulates_twice() {
    let (seed, ct) = encapsulated();
    let _ = spy::assert_intro_open(|| {
        pq::decapsulate(&seed, &ct)?;
        pq::decapsulate(&seed, &ct).map(|_| ())
    });
}

/// ... an open that decapsulates once but whose result does not depend on the secret panics ...
#[test]
#[should_panic(expected = "k_in does not depend on ss")]
fn pq1_the_host_assertion_refuses_an_open_whose_key_ignores_the_secret() {
    let (seed, ct) = encapsulated();
    let _ = spy::assert_intro_open(|| pq::decapsulate(&seed, &ct).map(|_| ()));
}

/// ... and a refused open that decapsulated twice panics as well.
#[test]
#[should_panic(expected = "PQ1: a refused intro open performed 2 decapsulations")]
fn pq1_the_host_assertion_refuses_a_refusal_after_two_decapsulations() {
    let (seed, ct) = encapsulated();
    let _ = spy::assert_intro_open(|| {
        pq::decapsulate(&seed, &ct)?;
        pq::decapsulate(&seed, &ct)?;
        Err::<(), DmCode>(DmCode::NotOpen)
    });
}

// -------------------------------------------------------------------------------------------
// PQ5
// -------------------------------------------------------------------------------------------

/// PQ5 (RG-5), intro half: every intro envelope an honest client of the world sealed carries,
/// right after `gen_id`, **exactly 1 120 bytes** that RustCrypto `x-wing` decapsulates under the
/// recipient's seed, and the secret it gets keys the inner layer: the oracle opens it with
/// `HKDF(T_in, ss)` to the sender's card, binding minute, `reply_seed` and PreKey message. One bit
/// of that secret and the layer stays shut, and GHOST's opener reads the same plaintext.
#[test]
fn pq5_every_intro_envelope_carries_an_x_wing_ciphertext_whose_secret_keys_its_inner_layer() {
    let world = world();
    let mut buckets = BTreeSet::new();
    let mut recipients = BTreeSet::new();
    let mut checked = 0;
    for intro in world.honest() {
        let to = world.device(intro.recipient);
        let generation = world.generation_of(intro);
        let outer = world.open_outer(intro).expect("outer");
        let bucket = intro.blob.len();
        assert_eq!(outer.bucket, bucket);
        assert_eq!(outer.gen_id, generation.gen_id);
        // §6.4's layout with its lengths written out: the ciphertext is exactly 1 120 bytes and the
        // inner layer is everything after it.
        assert_eq!(outer.ciphertext.len(), XWING_CT, "{}", intro.label);
        assert_eq!(
            outer.inner.len(),
            bucket - INTRO_PREFIX - XWING_CT,
            "{}",
            intro.label
        );

        let (secret, public) = oracle_decapsulate(&generation.seed, &outer.ciphertext);
        assert_eq!(
            public, generation.public,
            "{}: the key the sender encapsulated to is the seed's under the oracle",
            intro.label
        );
        let transcript = oracle_transcript(to, bucket, outer.gen_id, &public, &outer.ciphertext);
        let plain = oracle_open_inner(&secret, &transcript, &outer.inner).unwrap_or_else(|| {
            panic!(
                "{}: the oracle's X-Wing secret does not open the inner layer",
                intro.label
            )
        });
        // kind(1) || card(131) || binding_minute(4) || binding_sig(64) || reply_seed(32)
        // || l1_len(4) || L1 || zeros
        assert_eq!(plain.len(), bucket - 1189);
        assert_eq!(plain[0], 0x02, "an Olm PreKey message");
        assert_eq!(&plain[1..132], &intro.sender_card[..]);
        assert_eq!(&plain[132..136], &MINUTE.to_be_bytes());
        assert_eq!(&plain[200..232], &intro.reply_seed);
        let l1_len = u32::from_be_bytes([plain[232], plain[233], plain[234], plain[235]]) as usize;
        assert_eq!(&plain[236..236 + l1_len], intro.l1.as_slice());
        assert!(plain[236 + l1_len..].iter().all(|byte| *byte == 0));

        assert!(
            oracle_open_inner(&flipped(&secret), &transcript, &outer.inner).is_none(),
            "{}: k_in does not depend on ss",
            intro.label
        );
        let (opened, _) = world.open_checked(intro, &outer).expect("GHOST opens it");
        assert_eq!(opened.l1, intro.l1);
        buckets.insert(bucket);
        recipients.insert((intro.recipient, intro.generation));
        checked += 1;
    }
    assert!(checked >= 10, "{checked} envelopes");
    assert_eq!(buckets.len(), BUCKETS.len(), "every bucket");
    assert!(
        recipients.len() >= 3,
        "both directions and both of B's generations"
    );
}

/// PQ5 (RG-5): the **sender's** `k_in` depends on the secret its ciphertext carries. With the
/// secret the encapsulation returned perturbed after the KEM — the ciphertext untouched — the
/// honest recipient and the oracle both refuse the envelope; without it, both open it. Every seal
/// performs exactly one encapsulation (§6.4: every intro envelope has its own).
#[test]
fn pq5_the_sender_keys_the_inner_layer_with_the_secret_its_ciphertext_carries() {
    let world = world();
    let to = world.device(B);
    let generation = &to.generations[0];
    for bucket in BUCKETS {
        for perturbed in [false, true] {
            let mut conversation = world.start(A, B, 0);
            let l0 = text("a flight", 0, Vec::new());
            let encrypted =
                session::encrypt(&conversation.sender_state, &l0, TODAY).expect("encrypt");
            conversation.sender_state = encrypted.state;
            spy::disarm();
            if perturbed {
                spy::perturb_next_encapsulation();
            }
            let before = spy::encapsulations();
            let blob = world.seal(&conversation, &encrypted.l1, bucket, None);
            assert_eq!(
                spy::encapsulations() - before,
                1,
                "one encapsulation per envelope"
            );
            assert!(!spy::disarm(), "the perturbation was consumed");

            let outer =
                seal::open_intro_outer(&to.own_intro_key(), &to.namespace, &blob).expect("outer");
            let opened = seal::open_intro_checked(
                &generation.secret(),
                &to.context(0, bucket),
                &outer,
                &generation.fallback_public,
            );
            let (secret, public) = oracle_decapsulate(&generation.seed, &outer.ciphertext);
            let transcript =
                oracle_transcript(to, bucket, outer.gen_id, &public, &outer.ciphertext);
            let oracle = oracle_open_inner(&secret, &transcript, &outer.inner);
            if perturbed {
                assert_eq!(opened.err(), Some(DmCode::NotOpen), "{bucket} B");
                assert!(oracle.is_none(), "{bucket} B");
            } else {
                assert_eq!(opened.expect("opens").0.l1, encrypted.l1);
                assert!(oracle.is_some(), "{bucket} B");
            }
        }
    }
}

/// PQ5 (RG-5), PQ-C half: every `seal_root_pq` of the world, as its target decoded it from the L0
/// it arrived in, is 1 166 bytes whose last **1 120** RustCrypto `x-wing` decapsulates under the
/// target generation's seed; the §9.4 formula over that secret is the root the offerer keeps and
/// the one GHOST's opener derives, in exactly one decapsulation. One bit of the secret gives
/// another root, in the oracle and in GHOST's opener alike.
#[test]
fn pq5_every_seal_root_pq_carries_an_x_wing_ciphertext_its_root_depends_on() {
    let world = world();
    for root in &world.roots {
        let offerer = world.device(root.offerer);
        let target = world.device(root.target);
        let generation = &target.generations[root.generation];
        // root_rand(32) || base_week(8) || root_gen(2) || peer_gen_id(4) || xwing_ct(1120), §7.1.
        assert_eq!(
            root.value.len(),
            32 + 8 + 2 + 4 + XWING_CT,
            "{}",
            root.label
        );
        let ct = &root.value[46..];
        let gen_id = u32::from_be_bytes([
            root.value[42],
            root.value[43],
            root.value[44],
            root.value[45],
        ]);
        assert_eq!(gen_id, generation.gen_id, "{}", root.label);

        let (secret, public) = oracle_decapsulate(&generation.seed, ct);
        assert_eq!(public, generation.public);
        let expected = oracle_root(
            &root.value[..32],
            &secret,
            &offerer.oi,
            &target.oi,
            gen_id,
            &public,
            ct,
        );
        assert_eq!(
            expected, root.root,
            "{}: the offerer's root is §9.4 over the oracle's secret",
            root.label
        );
        assert_ne!(
            oracle_root(
                &root.value[..32],
                &flipped(&secret),
                &offerer.oi,
                &target.oi,
                gen_id,
                &public,
                ct
            ),
            expected,
            "{}: the root does not depend on ss",
            root.label
        );

        let tlv = SealRootPq::decode(&root.value).expect("decode");
        let parties = PqRootParties {
            oi_offerer: &offerer.oi,
            oi_target: &target.oi,
        };
        let (opened, used) =
            decapsulations_in(|| pqroot::open(&tlv, gen_id, &generation.secret(), parties));
        assert_eq!(used, 1, "{}: one decapsulation per root open", root.label);
        assert_eq!(
            opened.expect("open").as_bytes(),
            &root.root,
            "{}",
            root.label
        );
        let perturbed = with_perturbed_secret(&root.label, || {
            pqroot::open(&tlv, gen_id, &generation.secret(), parties)
        })
        .expect("no key confirmation: a wrong secret is a wrong root, not a refusal (§9.4)");
        assert_ne!(
            perturbed.as_bytes(),
            &root.root,
            "{}: GHOST's root ignores ss",
            root.label
        );
    }
    assert!(world.roots.len() >= 3, "{} roots", world.roots.len());
}

/// PQ5 (RG-5), PM-32 as a bump gate: the gate-variant client G seals intro envelopes to A and B
/// whose inner layer is keyed **without the KEM** — no encapsulation at all, the secret dropped,
/// the card key, the ciphertext's hash — at every bucket, and the honest recipient refuses each
/// one `NOT_OPEN` after exactly one decapsulation, through both openers. Each refused envelope is
/// what it claims to be: its outer layer opens under the recipient's card, it carries 1 120 bytes
/// where the ciphertext goes, and it **does** open under the non-KEM key it was sealed with, so the
/// refusal is the KEM dependence and nothing else. G's KEM control, sealed by the same code, opens.
#[test]
fn pq5_a_gate_variant_client_sealing_without_the_kem_is_refused_by_an_honest_recipient() {
    let world = world();
    let mut refused = BTreeSet::new();
    let mut controls = BTreeSet::new();
    for intro in world
        .intros
        .iter()
        .filter(|intro| intro.sealed_by.is_some())
    {
        let variant = intro.sealed_by.expect("a gate envelope");
        let to = world.device(intro.recipient);
        let generation = world.generation_of(intro);
        let outer = world
            .open_outer(intro)
            .expect("the gate client's outer layer is honest");
        let bucket = intro.blob.len();
        assert_eq!(outer.ciphertext.len(), XWING_CT);
        assert_eq!(outer.inner.len(), bucket - INTRO_PREFIX - XWING_CT);

        let (checked, used) = decapsulations_in(|| world.open_checked(intro, &outer));
        assert_eq!(used, 1, "{}", intro.label);
        let inner = world.open_inner(intro, &outer);
        if variant == InnerKey::Kem {
            assert_eq!(
                checked.expect("the control opens").0.l1,
                intro.l1,
                "{}",
                intro.label
            );
            assert_eq!(inner.expect("the control opens").l1, intro.l1);
            controls.insert((intro.recipient, bucket));
            continue;
        }
        assert_eq!(
            checked.err(),
            Some(DmCode::NotOpen),
            "{}: accepted",
            intro.label
        );
        assert_eq!(
            inner.err(),
            Some(DmCode::NotOpen),
            "{}: accepted",
            intro.label
        );

        let (_, public) = oracle_decapsulate(&generation.seed, &outer.ciphertext);
        let transcript = oracle_transcript(to, bucket, outer.gen_id, &public, &outer.ciphertext);
        let sealed_under: [u8; 32] = match variant {
            InnerKey::NoEncapsulation | InnerKey::SecretDropped => [0u8; 32],
            InnerKey::CardKey => to.intro_key,
            InnerKey::CiphertextHash => Sha256::digest(&outer.ciphertext).into(),
            InnerKey::Kem => unreachable!("handled above"),
        };
        let plain = oracle_open_inner(&sealed_under, &transcript, &outer.inner)
            .unwrap_or_else(|| panic!("{}: not sealed under the key it claims", intro.label));
        assert_eq!(&plain[1..132], &intro.sender_card[..]);
        refused.insert((variant as u8, intro.recipient, bucket));
    }
    // Four ways without the KEM, at three buckets to B and one to A; the control at the same four.
    assert_eq!(
        refused.len(),
        InnerKey::WITHOUT_KEM.len() * (BUCKETS.len() + 1)
    );
    assert_eq!(controls.len(), BUCKETS.len() + 1);
}
