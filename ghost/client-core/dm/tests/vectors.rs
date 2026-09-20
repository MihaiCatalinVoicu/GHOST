//! The DM conformance vectors (design §15.2): `protocol/test-vectors/dm_derive.txt`,
//! `dm_seal.txt`, `dm_content.txt`, `dm_bundle.txt` and `dm_safety_number.txt`.
//!
//! Each file is **generated** by the test that checks it, from fixed inputs, and compared with the
//! committed copy byte for byte: a change to a derivation, a layout or a label fails here before
//! it can reach a device. Run with `GHOST_DM_VECTORS_WRITE=1` to rewrite the files after a
//! deliberate change, and review the diff.
//!
//! **The JDK cross-check seam.** The files are self-describing `key = value` text with every input
//! and every intermediate value in hex, so an independent implementation replays them without
//! reading this crate: the header of each file states the algorithm of every line. §15.2 assigns
//! that replay to the independent Kotlin/JDK implementation, which covers `dm_seal.txt` (pair,
//! provisional, bundle and the intro **outer** layer, recognition hints), `dm_content.txt` and
//! `dm_safety_number.txt`; X-Wing stays with the Rust differential test, because the JDK 17
//! provider set has no ML-KEM. That Kotlin replayer lands with `:crypto-bridge` in S4b — this
//! slice has no Kotlin module to put it in — so S4a delivers the artifacts it replays, not the
//! replayer.

use ghost_client_dm::binding::BindingV3;
use ghost_client_dm::codec::{self, DmContent, Kind, Tlv};
use ghost_client_dm::derive::{
    self, CardSecret, KemSecret, MessagingBranch, PairRoot, ReplySeed, StateKey,
};
use ghost_client_dm::provenance::{CardSource, KeyProvenance, SealKey};
use ghost_client_dm::seal::{self, IntroContext, IntroSender, SealMode};
use ghost_client_dm::{binding, bundle, card, pq, safety, wrap};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use std::path::PathBuf;

/// The pinned root entropy of `android/identity/src/test/resources/derivation_vectors.txt`.
const ROOT_ENTROPY: [u8; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];
/// The pinned `messaging_seed` of that file: the convention this crate must reproduce.
const MESSAGING_SEED: &str = "82453de069051555acf43dc3b93fa3be1a218d828bc156f7c1f4ad77a66f50cf";
/// The pinned `olm_identity_pub` of S0′ evidence V-1 §1.
const OLM_IDENTITY_PUB: &str = "d80580eca7efdcd429060d7c25bb83d731943aef3cfecd947b048b72d8b00603";
/// `DerivationLabels.MESSAGING` of Phase 3.
const MESSAGING_LABEL: &[u8] = b"ghost/v1/messaging";

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("protocol")
        .join("test-vectors")
}

/// Compares the generated content with the committed file, or rewrites it on request.
fn check(name: &str, content: &str) {
    let path = vectors_dir().join(name);
    if std::env::var("GHOST_DM_VECTORS_WRITE").as_deref() == Ok("1") {
        std::fs::write(&path, content).expect("write vectors");
        return;
    }
    let committed = std::fs::read_to_string(&path)
        .unwrap_or_else(|_| panic!("{} is missing; run with GHOST_DM_VECTORS_WRITE=1", name));
    // Git may check the file out with CRLF; compare the logical lines.
    let committed = committed.replace("\r\n", "\n");
    assert_eq!(
        committed, content,
        "{name} differs from the implementation; review the change, then rerun with \
         GHOST_DM_VECTORS_WRITE=1"
    );
}

struct Out(String);

impl Out {
    fn new(header: &str) -> Self {
        Out(header.to_string())
    }

    fn line(&mut self, text: &str) {
        self.0.push_str(text);
        self.0.push('\n');
    }

    fn blank(&mut self) {
        self.0.push('\n');
    }

    fn section(&mut self, name: &str) {
        self.blank();
        let _ = writeln!(self.0, "[{name}]");
    }

    fn hex(&mut self, key: &str, value: &[u8]) {
        let _ = writeln!(self.0, "{key} = {}", hex::encode(value));
    }

    fn num(&mut self, key: &str, value: u64) {
        let _ = writeln!(self.0, "{key} = {value}");
    }

    fn text(&mut self, key: &str, value: &str) {
        let _ = writeln!(self.0, "{key} = {value}");
    }

    fn sha(&mut self, key: &str, value: &[u8]) {
        let digest: [u8; 32] = Sha256::digest(value).into();
        self.hex(key, &digest);
    }
}

fn messaging_branch() -> MessagingBranch {
    let mut out = [0u8; 32];
    Hkdf::<Sha256>::new(None, &ROOT_ENTROPY)
        .expand(MESSAGING_LABEL, &mut out)
        .expect("expand");
    assert_eq!(
        hex::encode(out),
        MESSAGING_SEED,
        "the MESSAGING branch moved"
    );
    MessagingBranch::from_bytes(out)
}

/// A fixed `ghost1` Ed25519 seed for the card, bundle and binding vectors. It is not derived from
/// the pinned root entropy on purpose: the identity branch belongs to Phase 3, and these vectors
/// must stay stable if that branch's test fixture ever changes.
const IDENTITY_SEED: [u8; 32] = [
    0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf, 0xe0,
    0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef, 0xf0,
];

#[test]
fn dm_derive_vectors() {
    let mut out = Out::new(
        "\
# GHOST DM derivations, contact card v2 and state wrapping (Phase 9 design faza9-dm.md §3.1, §3.2,\n\
# §3.3, §6.3, §6.7, §2.5, §22.8.3). Generated and checked by\n\
# client-core/dm/tests/vectors.rs::dm_derive_vectors; an independent implementation replays it.\n\
#\n\
# Conventions\n\
#   Every value is lower-case hex unless it is a decimal number or a string.\n\
#   hkdf(ikm, salt, info) = HKDF-SHA256(ikm, salt, info, L = 32); an absent salt is the empty one.\n\
#   m  = hkdf(root_entropy, -, \"ghost/v1/messaging\")      (the Phase 3 MESSAGING branch)\n\
#   Seed-level values are hkdf(m, -, label || params); card-level values are\n\
#   hkdf(card_secret_i, -, label || params). Parameters are big-endian.\n\
#\n\
# The card link is \"ghost://contact/\" || z-base-32(card), 226 characters.\n",
    );

    let m = messaging_branch();
    out.section("seed");
    out.hex("root_entropy", &ROOT_ENTROPY);
    out.text("messaging_label", "ghost/v1/messaging");
    out.hex("messaging_seed", m.as_bytes());

    out.section("olm_identity");
    let olm_secret = derive::derive_olm_identity(&m);
    let olm_public = derive::olm_identity_public(&olm_secret);
    out.text("secret_label", "ghost/v1/dm/olm-identity");
    out.hex("olm_identity_secret", olm_secret.as_bytes());
    out.hex("olm_identity_pub", &olm_public);
    assert_eq!(hex::encode(olm_public), OLM_IDENTITY_PUB);
    out.text("account_signing_label", "ghost/v1/dm/olm-account-signing");
    out.hex(
        "olm_account_signing_seed",
        derive::derive_olm_account_signing(&m).as_bytes(),
    );

    out.section("seed_values");
    let card_secret = derive::derive_card_secret(&m, 0);
    out.num("card_index", 0);
    out.hex("card_secret", card_secret.as_bytes());
    out.hex(
        "inbox_read_secret_slot_0",
        &derive::derive_inbox_read_secret(&m, 0, 0),
    );
    out.hex(
        "inbox_read_secret_slot_7",
        &derive::derive_inbox_read_secret(&m, 0, 7),
    );
    out.hex("schedule_key", &derive::derive_schedule_key(&m, 0));
    out.hex(
        "card_secret_index_1",
        derive::derive_card_secret(&m, 1).as_bytes(),
    );

    out.section("card_values");
    let inbox_ns = derive::derive_inbox_namespace(&card_secret);
    let bundle_ns = derive::derive_bundle_namespace(&card_secret);
    out.hex("inbox_namespace", &inbox_ns);
    out.hex("bundle_namespace", &bundle_ns);
    out.hex(
        "deposit_secret_slot_0",
        &derive::derive_card_value(&card_secret, derive::CardLabel::Deposit(0)),
    );
    out.hex(
        "deposit_secret_slot_7",
        &derive::derive_card_value(&card_secret, derive::CardLabel::Deposit(7)),
    );
    out.hex(
        "bundle_read_secret_slot_0",
        &derive::derive_card_value(&card_secret, derive::CardLabel::BundleRead(0)),
    );
    let bundle_seal = derive::derive_card_value(&card_secret, derive::CardLabel::BundleSeal);
    let intro_outer = derive::derive_card_value(&card_secret, derive::CardLabel::IntroOuter);
    out.hex("bundle_seal_key", &bundle_seal);
    out.hex("intro_outer_key", &intro_outer);

    out.section("recognition");
    out.text("recognition_label", "ghost/v1/dm-recognition");
    out.hex(
        "recognition_key_of_bundle_seal",
        &seal::recognition_key(&SealKey::new(
            bundle_seal,
            KeyProvenance::Card(CardSource::InPerson),
        )),
    );
    out.hex(
        "recognition_key_of_intro_outer",
        &seal::recognition_key(&SealKey::new(
            intro_outer,
            KeyProvenance::Card(CardSource::InPerson),
        )),
    );

    out.section("pair");
    let root = PairRoot::from_bytes([0x5a; 32]);
    out.text("epoch_label", "ghost/v1/dm/pair-epoch");
    out.text("next_label", "ghost/v1/dm/pair-next");
    out.hex("pair_root", root.as_bytes());
    out.num("base_week", 2870);
    let base = derive::derive_pair_base_week_key(&root, 2870);
    let next = derive::derive_pair_next_week_key(&base);
    let third = derive::derive_pair_next_week_key(&next);
    out.hex("week_key_2870", base.as_bytes());
    out.hex("week_key_2871", next.as_bytes());
    out.hex("week_key_2872", third.as_bytes());

    out.section("provisional");
    out.text("session_binding_label", "ghost/v1/dm-session-binding");
    out.text("provisional_label", "ghost/v1/dm/prov");
    let oi_initiator = [0x11u8; 32];
    let base_key = [0x12u8; 32];
    let fallback_key = [0x13u8; 32];
    let oi_responder = [0x14u8; 32];
    out.hex("oi_initiator", &oi_initiator);
    out.hex("base_key", &base_key);
    out.hex("fallback_key", &fallback_key);
    out.hex("oi_responder", &oi_responder);
    let sb = derive::session_binding(&oi_initiator, &base_key, &fallback_key, &oi_responder);
    out.hex("session_binding", &sb);
    let reply_seed = ReplySeed::from_bytes([0x6b; 32]);
    out.hex("reply_seed", reply_seed.as_bytes());
    out.hex(
        "provisional_key_dir_01",
        &derive::derive_provisional_key(&reply_seed, &sb, derive::PROVISIONAL_DIR_TO_INITIATOR),
    );
    out.hex(
        "provisional_key_dir_02",
        &derive::derive_provisional_key(&reply_seed, &sb, derive::PROVISIONAL_DIR_TO_RESPONDER),
    );

    out.section("card");
    let card = card::build(&IDENTITY_SEED, 0, &card_secret);
    out.text("card_sign_label", "ghost/v1/contact-card");
    out.hex("identity_seed", &IDENTITY_SEED);
    out.hex("identity_pk", &card.identity_pk);
    out.text("ghost1", &card.ghost1());
    out.hex("card", &card.encode());
    out.text("card_link", &card.link());

    out.section("wrap");
    out.text("wrap_label", "ghost/v1/wrap/");
    let state_key = StateKey::from_bytes([0x7c; 32]);
    let contact_id = [0x21u8; 16];
    let session_id = [0x22u8; 32];
    let nonce = [0x23u8; wrap::NONCE_BYTES];
    out.hex("state_key", state_key.as_bytes());
    out.hex("contact_id", &contact_id);
    out.hex("session_id", &session_id);
    out.hex("nonce", &nonce);
    let binding_bytes = wrap::olm_session_binding(&contact_id, &session_id);
    out.hex("olm_session_binding", &binding_bytes);
    let plaintext = b"ghost/v1 wrapped state".to_vec();
    out.hex("wrap_plaintext", &plaintext);
    let envelope = wrap::wrap_with_nonce(
        &state_key,
        wrap::WrapName::OlmSession,
        &binding_bytes,
        &plaintext,
        &nonce,
    )
    .expect("wrap");
    out.hex("olm_session_envelope", &envelope);
    out.hex(
        "pair_key_binding_week_2870",
        &wrap::pair_key_binding(&contact_id, 1, 2, 2870),
    );
    out.hex(
        "generation_binding",
        &wrap::generation_binding(7, &[0x24; 32]),
    );

    check("dm_derive.txt", &out.0);
}

struct SealCase {
    name: &'static str,
    mode: SealMode,
    bucket: usize,
}

/// `k = HKDF-SHA256(ikm = k_sel, salt = salt, info = "ghost/v1/dm-seal" || namespace, L = 32)`.
/// The crate derives it internally and zeroises it; the vector file records it from the public
/// inputs so a replayer can check the AEAD key and not only the blob (§15.2).
fn seal_key(k_sel: &[u8; 32], namespace: &[u8; 32], salt: &[u8; seal::SALT_BYTES]) -> [u8; 32] {
    let mut info = seal::SEAL_LABEL.to_vec();
    info.extend_from_slice(namespace);
    let mut out = [0u8; 32];
    Hkdf::<Sha256>::new(Some(salt), k_sel)
        .expand(&info, &mut out)
        .expect("expand");
    out
}

/// `k_in = HKDF-SHA256(ikm = ss, salt = t_in, info = "ghost/v1/dm-intro-inner", L = 32)`.
fn intro_inner_key(shared: &KemSecret, transcript: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    Hkdf::<Sha256>::new(Some(transcript), shared.as_bytes())
        .expand(seal::INTRO_INNER_LABEL, &mut out)
        .expect("expand");
    out
}

#[test]
fn dm_seal_vectors() {
    let mut out = Out::new(
        "\
# GHOST DM seal vectors (Phase 9 design faza9-dm.md §6.2 - §6.7, §5.3). Generated and checked by\n\
# client-core/dm/tests/vectors.rs::dm_seal_vectors.\n\
#\n\
# Layout of every blob, in all four modes\n\
#   blob(B)  = salt(16) || hint(16) || ChaCha20-Poly1305(k, nonce = 0^12, ad, p),  |p| = B - 48\n\
#   r_sel    = HKDF-SHA256(ikm = k_sel, salt = -, info = \"ghost/v1/dm-recognition\", L = 32)\n\
#   hint     = HMAC-SHA256(r_sel, \"ghost/v1/dm-hint\" || salt)[0..16]\n\
#   k        = HKDF-SHA256(ikm = k_sel, salt = salt, info = \"ghost/v1/dm-seal\" || namespace, L = 32)\n\
#   ad       = \"ghost/v1/dm-seal\" || 02 || namespace(32) || u32_be(B) || mode(1) || pair_ad(32)\n\
#   pair_ad  = SHA-256(\"ghost/v1/dm-pair-ad\" || oi_sender || oi_recipient)  (pair, provisional)\n\
#              32 zero bytes                                                (intro, bundle)\n\
#   p        = mode(1) || body || zeros;  mode 01 pair, 02 intro, 03 bundle, 04 provisional\n\
#   pair and provisional body = kind(1) = 01 || l1_len(4, BE) || l1\n\
#   bundle body               = bundle_plain(1393)\n\
#   intro body                = gen_id(4) || xwing_ct(1120) || inner\n\
#\n\
# The intro inner layer (the KEM half) is replayed only by the Rust differential test: the JDK 17\n\
# provider set has no ML-KEM. Its shared secret, transcript, key and associated data are recorded\n\
# in full below, so an implementation that does have X-Wing checks every step; the symmetric\n\
# sections record the derived seal key `k` for the same reason.\n\
#   t_in   = SHA-256(\"ghost/v1/dm-intro-kem\" || namespace(32) || u32_be(B) || u32_be(gen_id)\n\
#                    || q_g(1216) || xwing_ct(1120) || oi_recipient(32) || identity_pk_recipient(32))\n\
#   ss     = the X-Wing shared secret of Encaps(q_g, kem_randomness)\n\
#   k_in   = HKDF-SHA256(ikm = ss, salt = t_in, info = \"ghost/v1/dm-intro-inner\", L = 32)\n\
#   ad_in  = \"ghost/v1/dm-intro\" || 02 || t_in\n\
#   q      = kind(1) = 02 || sender_card(131) || binding_minute(4) || binding_sig(64)\n\
#            || reply_seed(32) || l1_len(4, BE) || l1 || zeros,   |q| = B - 1189\n\
#\n\
# The recipient also checks PreKey.one_time_key = gen_fallback_key (the generation's Olm fallback\n\
# key, design S6.5 step 4); it is recorded in [intro_common] and is not inside the envelope.\n\
#\n\
# `blob` is written out in full for the 4 KiB cases; every case carries `blob_sha256`.\n",
    );

    let namespace = [0x31u8; 32];
    let oi_sender = [0x32u8; 32];
    let oi_recipient = [0x33u8; 32];
    let salt = [0x34u8; seal::SALT_BYTES];
    let l1 = (0u16..64).map(|i| (i % 251) as u8).collect::<Vec<u8>>();

    out.section("common");
    out.hex("namespace", &namespace);
    out.hex("oi_sender", &oi_sender);
    out.hex("oi_recipient", &oi_recipient);
    out.hex("salt", &salt);
    out.hex("l1", &l1);
    out.hex("pair_ad", &seal::pair_ad(&oi_sender, &oi_recipient));
    out.num("o_max", seal::O_MAX as u64);
    out.num("capacity_4096", seal::capacity(4096) as u64);
    out.num("capacity_16384", seal::capacity(16384) as u64);
    out.num("capacity_65536", seal::capacity(65536) as u64);
    out.num("max_body_4096", seal::max_body(4096) as u64);
    out.num("max_body_16384", seal::max_body(16384) as u64);
    out.num("max_body_65536", seal::max_body(65536) as u64);

    let symmetric_key_material = [0x35u8; 32];
    let cases = [
        SealCase {
            name: "pair_4096",
            mode: SealMode::Pair,
            bucket: 4096,
        },
        SealCase {
            name: "pair_16384",
            mode: SealMode::Pair,
            bucket: 16384,
        },
        SealCase {
            name: "pair_65536",
            mode: SealMode::Pair,
            bucket: 65536,
        },
        SealCase {
            name: "provisional_4096",
            mode: SealMode::Provisional,
            bucket: 4096,
        },
        SealCase {
            name: "provisional_16384",
            mode: SealMode::Provisional,
            bucket: 16384,
        },
        SealCase {
            name: "provisional_65536",
            mode: SealMode::Provisional,
            bucket: 65536,
        },
    ];
    for case in &cases {
        let key = SealKey::new(
            symmetric_key_material,
            KeyProvenance::Kem.transported_under(),
        );
        let blob = match case.mode {
            SealMode::Pair => seal::seal_pair_with(
                &key,
                &namespace,
                case.bucket,
                &oi_sender,
                &oi_recipient,
                &l1,
                &salt,
            ),
            _ => seal::seal_provisional_with(
                &key,
                &namespace,
                case.bucket,
                &oi_sender,
                &oi_recipient,
                &l1,
                &salt,
            ),
        }
        .expect("seal");
        assert_eq!(
            seal::open_symmetric(
                &key,
                &namespace,
                case.mode,
                &oi_sender,
                &oi_recipient,
                &blob
            )
            .expect("open"),
            l1
        );
        out.section(case.name);
        out.hex("mode", &[case.mode.as_u8()]);
        out.num("bucket", case.bucket as u64);
        out.hex("k_sel", &symmetric_key_material);
        out.hex("recognition_key", &seal::recognition_key(&key));
        out.hex("k", &seal_key(&symmetric_key_material, &namespace, &salt));
        out.hex("hint", &blob[seal::SALT_BYTES..seal::HEADER_BYTES]);
        out.hex(
            "ad",
            &seal::associated_data(
                &namespace,
                case.bucket,
                case.mode,
                &seal::pair_ad(&oi_sender, &oi_recipient),
            ),
        );
        out.sha("blob_sha256", &blob);
        if case.bucket == 4096 {
            out.hex("blob", &blob);
        }
    }

    // Bundle mode: the §5.3 blob, under a card-derived key.
    let bundle_key_material = [0x36u8; 32];
    let bundle_key = SealKey::new(
        bundle_key_material,
        KeyProvenance::Card(CardSource::InPerson),
    );
    let bundle_plain = bundle_fixture();
    let bundle_blob =
        seal::seal_bundle_with(&bundle_key, &namespace, &bundle_plain, &salt).expect("seal");
    out.section("bundle_4096");
    out.hex("mode", &[SealMode::Bundle.as_u8()]);
    out.num("bucket", 4096);
    out.hex("k_sel", &bundle_key_material);
    out.hex("recognition_key", &seal::recognition_key(&bundle_key));
    out.hex("k", &seal_key(&bundle_key_material, &namespace, &salt));
    out.hex("hint", &bundle_blob[seal::SALT_BYTES..seal::HEADER_BYTES]);
    out.hex(
        "ad",
        &seal::associated_data(&namespace, 4096, SealMode::Bundle, &[0u8; 32]),
    );
    out.sha("bundle_plain_sha256", &bundle_plain);
    out.sha("blob_sha256", &bundle_blob);
    out.hex("blob", &bundle_blob);

    // Intro mode at every bucket.
    let intro_key_material = [0x37u8; 32];
    let intro_key = SealKey::new(
        intro_key_material,
        KeyProvenance::Card(CardSource::InPerson),
    );
    let gen_seed = KemSecret::from_bytes([0x38; 32]);
    let gen_public = pq::public_key(&gen_seed).expect("keygen");
    let sender_card = card::build(&IDENTITY_SEED, 0, &CardSecret::from_bytes([0x39; 32]));
    let sender_card_bytes = sender_card.encode();
    let reply_seed = ReplySeed::from_bytes([0x3a; 32]);
    let sender_base_key = [0x3bu8; 32];
    let recipient_identity_pk = [0x3cu8; 32];
    let kem_randomness = [0x3du8; pq::ENCAPS_RANDOMNESS_BYTES];
    let gen_fallback_key = [0x3eu8; 32];
    let gen_id = 0x1234_5678u32;
    let binding_minute = 29_000_000u32;

    out.section("intro_common");
    out.hex("kio", &intro_key_material);
    out.hex("gen_seed", gen_seed.as_bytes());
    out.sha("gen_public_sha256", &gen_public);
    out.num("gen_id", u64::from(gen_id));
    out.hex("gen_fallback_key", &gen_fallback_key);
    out.hex("sender_card", &sender_card_bytes);
    out.hex("sender_oi", &oi_sender);
    out.hex("sender_base_key", &sender_base_key);
    out.num("binding_minute", u64::from(binding_minute));
    out.hex("reply_seed", reply_seed.as_bytes());
    out.hex("recipient_oi", &oi_recipient);
    out.hex("recipient_identity_pk", &recipient_identity_pk);
    out.hex("kem_randomness", &kem_randomness);
    out.text("binding_label", "ghost/v1/dm-binding/v3");
    out.hex("recognition_key", &seal::recognition_key(&intro_key));

    for bucket in seal::BUCKETS {
        let context = IntroContext {
            namespace: &namespace,
            bucket,
            gen_id,
            gen_public: &gen_public,
            recipient_oi: &oi_recipient,
            recipient_identity_pk: &recipient_identity_pk,
        };
        let sender = IntroSender {
            identity_seed: &IDENTITY_SEED,
            card: &sender_card_bytes,
            oi: &oi_sender,
            base_key: &sender_base_key,
            binding_minute,
            reply_seed: &reply_seed,
        };
        let blob =
            seal::seal_intro_with(&intro_key, &context, &sender, &l1, &salt, &kem_randomness)
                .expect("seal");
        let outer = seal::open_intro_outer(&intro_key, &namespace, &blob).expect("outer");
        let prekey = seal::PreKeyFields {
            identity_key: &oi_sender,
            base_key: &sender_base_key,
            fallback_key: &gen_fallback_key,
        };
        let plain = seal::open_intro_inner(&gen_seed, &context, &outer, &prekey, &gen_fallback_key)
            .expect("inner");
        assert_eq!(plain.l1, l1);

        let transcript = seal::intro_transcript(&context, &outer.ciphertext);
        let binding_sig = binding::sign(
            &IDENTITY_SEED,
            &BindingV3 {
                oi_a: &oi_sender,
                card_index_a: 0,
                recipient_namespace: &namespace,
                binding_minute,
                gen_id_b: gen_id,
                xwing_ct: &outer.ciphertext,
                base_key_a: &sender_base_key,
                oi_b: &oi_recipient,
            },
        );
        assert_eq!(plain.binding_sig, binding_sig);

        out.section(&format!("intro_{bucket}"));
        out.hex("mode", &[SealMode::Intro.as_u8()]);
        out.num("bucket", bucket as u64);
        out.num("inner_plaintext_len", (bucket - 1189) as u64);
        out.hex("hint", &blob[seal::SALT_BYTES..seal::HEADER_BYTES]);
        out.hex(
            "ad",
            &seal::associated_data(&namespace, bucket, SealMode::Intro, &[0u8; 32]),
        );
        out.sha("xwing_ct_sha256", &outer.ciphertext);
        out.hex("t_in", &transcript);
        let (_, shared) = pq::encapsulate_with(&gen_public, &kem_randomness).expect("encaps");
        out.hex("ss", shared.as_bytes());
        out.hex("k_in", &intro_inner_key(&shared, &transcript));
        out.hex("ad_in", &{
            let mut ad = seal::INTRO_AD_LABEL.to_vec();
            ad.push(seal::SEAL_VERSION);
            ad.extend_from_slice(&transcript);
            ad
        });
        out.hex("binding_sig", &binding_sig);
        out.sha(
            "binding_transcript_sha256",
            &BindingV3 {
                oi_a: &oi_sender,
                card_index_a: 0,
                recipient_namespace: &namespace,
                binding_minute,
                gen_id_b: gen_id,
                xwing_ct: &outer.ciphertext,
                base_key_a: &sender_base_key,
                oi_b: &oi_recipient,
            }
            .transcript(),
        );
        out.sha("blob_sha256", &blob);
        if bucket == 4096 {
            out.hex("blob", &blob);
        }
    }

    check("dm_seal.txt", &out.0);
}

fn bundle_fixture() -> Vec<u8> {
    let xwing = pq::public_key(&KemSecret::from_bytes([0x41; 32])).expect("keygen");
    bundle::build(
        &IDENTITY_SEED,
        &bundle::BundleFields {
            card_index: 0,
            bundle_week: 2870,
            bundle_rank: 0,
            gen_id: 0x0a0b_0c0d,
            olm_identity: &[0x42; 32],
            fallback_key: &[0x43; 32],
            xwing_public: &xwing,
        },
    )
    .expect("build")
}

#[test]
fn dm_bundle_vectors() {
    let mut out = Out::new(
        "\
# GHOST bundle v2 vectors (Phase 9 design faza9-dm.md §5.3, §5.4). Generated and checked by\n\
# client-core/dm/tests/vectors.rs::dm_bundle_vectors.\n\
#\n\
#   bundle_plain = ver(1) = 02 || card_index(2) || bundle_week(8) || bundle_rank(2) || gen_id(4)\n\
#                || oi(32) || fallback_key(32) || xwing_pk(1216) || identity_pk(32)\n\
#                || sig(64, Ed25519 over \"ghost/v1/dm-bundle/v2\" || all previous bytes)\n\
#                = 1393 bytes\n\
#   blob(4096)   = the seal of dm_seal.txt in bundle mode, under the card's bundle seal key\n\
#\n\
# There is no one-time key, no registration id and no device id. `bundle_rank` is 0 for the weekly\n\
# publication and 1 + max(rank) for an activation or a restore, so no publication hour leaks.\n",
    );

    let xwing_seed = KemSecret::from_bytes([0x41; 32]);
    let xwing = pq::public_key(&xwing_seed).expect("keygen");
    let plain = bundle_fixture();
    let parsed = bundle::parse(&plain).expect("parse");

    out.section("bundle");
    out.text("sign_label", "ghost/v1/dm-bundle/v2");
    out.hex("identity_seed", &IDENTITY_SEED);
    out.hex("identity_pk", &parsed.identity_pk);
    out.num("card_index", u64::from(parsed.card_index));
    out.num("bundle_week", parsed.bundle_week);
    out.num("bundle_rank", u64::from(parsed.bundle_rank));
    out.num("gen_id", u64::from(parsed.gen_id));
    out.hex("olm_identity", &parsed.olm_identity);
    out.hex("fallback_key", &parsed.fallback_key);
    out.hex("xwing_seed", xwing_seed.as_bytes());
    out.sha("xwing_pk_sha256", &xwing);
    out.num("bundle_plain_len", plain.len() as u64);
    out.hex("signature", &parsed.signature);
    out.sha("bundle_plain_sha256", &plain);
    out.hex("bundle_plain", &plain);

    check("dm_bundle.txt", &out.0);
}

#[test]
fn dm_content_vectors() {
    let mut out = Out::new(
        "\
# GHOST L0 content and TLV vectors (Phase 9 design faza9-dm.md §7.1). Generated and checked by\n\
# client-core/dm/tests/vectors.rs::dm_content_vectors; an independent implementation replays it.\n\
#\n\
#   l0 = version(1) = 01 || kind(1) || message_id(16) || author_minute(4) || minute_index(2)\n\
#        || timer_code(1) || timer_version(4) || flags(1) || quote_ref(0 or 16)\n\
#        || body_len(4) || body || ext_len(2) || ext\n\
#   ext = TLVs  type(u16) || len(u16) || value,  strictly ascending type, each at most once\n\
#   kind: 01 TEXT, 02 TIMER_SET, 03 REACTION, 04 CONTROL; 05 MEDIA is refused in Phase 9.\n\
#   flags bit 0 = a quote reference follows; every other bit must be 0.\n\
#   Author time exists only as author_minute, a u32 count of minutes: seconds are zero by type.\n\
#\n\
# [refuse_*] sections carry an `input` that must be refused, with the result code it must give.\n\
# [class_*] sections carry the S21.11 point 3 class boundaries: the bucket is a function of the\n\
# body length alone, so the same body gives the same bucket with and without a quote and with and\n\
# without a pending classical TLV. They record lengths and the L0 digest, not the whole record.\n",
    );

    let cases: Vec<(&str, DmContent)> = vec![
        (
            "text_plain",
            DmContent {
                kind: Kind::Text,
                message_id: [0x51; 16],
                author_minute: 29_000_000,
                minute_index: 0,
                timer_code: 4,
                timer_version: 1,
                quote_ref: None,
                body: "bună ziua".as_bytes().to_vec(),
                ext: Vec::new(),
            },
        ),
        (
            "text_quoted",
            DmContent {
                kind: Kind::Text,
                message_id: [0x52; 16],
                author_minute: 29_000_001,
                minute_index: 7,
                timer_code: 0,
                timer_version: 2,
                quote_ref: Some([0x53; 16]),
                body: "ok".as_bytes().to_vec(),
                ext: Vec::new(),
            },
        ),
        (
            "timer_set",
            DmContent {
                kind: Kind::TimerSet,
                message_id: [0x54; 16],
                author_minute: 29_000_002,
                minute_index: 0,
                timer_code: 5,
                timer_version: 3,
                quote_ref: None,
                body: Vec::new(),
                ext: Vec::new(),
            },
        ),
        (
            "reaction",
            DmContent {
                kind: Kind::Reaction,
                message_id: [0x55; 16],
                author_minute: 29_000_003,
                minute_index: 1,
                timer_code: 3,
                timer_version: 3,
                quote_ref: None,
                body: {
                    let mut body = vec![0x56u8; 16];
                    body.extend_from_slice("👍".as_bytes());
                    body
                },
                ext: Vec::new(),
            },
        ),
        (
            "control_seal_root",
            DmContent {
                kind: Kind::Control,
                message_id: [0x57; 16],
                author_minute: 29_000_004,
                minute_index: 0,
                timer_code: 0,
                timer_version: 4,
                quote_ref: None,
                body: Vec::new(),
                ext: vec![
                    Tlv {
                        tlv_type: codec::TLV_SEAL_ROOT,
                        value: codec::SealRoot {
                            root: [0x58; 32],
                            base_week: 2870,
                            root_gen: 3,
                        }
                        .encode(),
                    },
                    Tlv {
                        tlv_type: codec::TLV_SESSION_RESET,
                        value: Vec::new(),
                    },
                ],
            },
        ),
        (
            "control_seal_root_pq",
            DmContent {
                kind: Kind::Control,
                message_id: [0x5b; 16],
                author_minute: 29_000_006,
                minute_index: 0,
                timer_code: 0,
                timer_version: 6,
                quote_ref: None,
                body: Vec::new(),
                ext: vec![Tlv {
                    tlv_type: codec::TLV_SEAL_ROOT_PQ,
                    value: codec::SealRootPq {
                        root_rand: [0x5c; 32],
                        base_week: 2872,
                        root_gen: 4,
                        peer_gen_id: 0x0506_0708,
                        xwing_ct: pq::encapsulate_with(
                            &pq::public_key(&KemSecret::from_bytes([0x5d; 32])).expect("keygen"),
                            &[0x5e; pq::ENCAPS_RANDOMNESS_BYTES],
                        )
                        .expect("encaps")
                        .0,
                    }
                    .encode()
                    .expect("encode"),
                }],
            },
        ),
        (
            "text_pq_key",
            DmContent {
                kind: Kind::Text,
                message_id: [0x59; 16],
                author_minute: 29_000_005,
                minute_index: 0,
                timer_code: 4,
                timer_version: 5,
                quote_ref: None,
                body: vec![0x41; 16],
                ext: vec![Tlv {
                    tlv_type: codec::TLV_PQ_KEY,
                    value: codec::PqKey {
                        gen_id: 0x0102_0304,
                        bundle_week: 2871,
                        xwing_pk: pq::public_key(&KemSecret::from_bytes([0x5a; 32]))
                            .expect("keygen"),
                    }
                    .encode()
                    .expect("encode"),
                }],
            },
        ),
    ];

    for (name, content) in &cases {
        let bytes = content.encode().expect("encode");
        assert_eq!(&codec::decode(&bytes).expect("decode"), content);
        out.section(name);
        out.hex("kind", &[content.kind.as_u8()]);
        out.hex("message_id", &content.message_id);
        out.num("author_minute", u64::from(content.author_minute));
        out.num("minute_index", u64::from(content.minute_index));
        out.num("timer_code", u64::from(content.timer_code));
        out.num("timer_version", u64::from(content.timer_version));
        match &content.quote_ref {
            Some(quote) => out.hex("quote_ref", quote),
            None => out.text("quote_ref", "-"),
        }
        out.hex("body", &content.body);
        for tlv in &content.ext {
            out.text(
                &format!("tlv_{:04x}_len", tlv.tlv_type),
                &tlv.value.len().to_string(),
            );
        }
        out.num("l0_len", bytes.len() as u64);
        out.num("bucket", content.bucket().expect("bucket") as u64);
        out.sha("l0_sha256", &bytes);
        out.hex("l0", &bytes);
    }

    // The inputs of the `seal_root_pq` case's ciphertext, so a replayer with X-Wing reproduces it.
    let pq_root_seed = KemSecret::from_bytes([0x5d; 32]);
    out.section("seal_root_pq_inputs");
    out.line("# The 0x0005 value of [control_seal_root_pq] carries this encapsulation.");
    out.hex("peer_xwing_seed", pq_root_seed.as_bytes());
    out.sha(
        "peer_xwing_pk_sha256",
        &pq::public_key(&pq_root_seed).expect("keygen"),
    );
    out.hex("kem_randomness", &[0x5e; pq::ENCAPS_RANDOMNESS_BYTES]);

    // Refusals: each input must be refused with the recorded code.
    let base = cases[0].1.encode().expect("encode");
    let refusals: Vec<(&str, Vec<u8>)> = vec![
        ("wrong_version", {
            let mut bytes = base.clone();
            bytes[0] = 0x02;
            bytes
        }),
        ("media_kind_reserved", {
            let mut bytes = base.clone();
            bytes[1] = 0x05;
            bytes
        }),
        ("unknown_kind", {
            let mut bytes = base.clone();
            bytes[1] = 0x09;
            bytes
        }),
        ("timer_code_out_of_range", {
            let mut bytes = base.clone();
            bytes[24] = 6;
            bytes
        }),
        ("reserved_flag_bit", {
            let mut bytes = base.clone();
            bytes[29] = 0x02;
            bytes
        }),
        ("trailing_byte", {
            let mut bytes = base.clone();
            bytes.push(0);
            bytes
        }),
        ("body_over_read", {
            let mut bytes = base.clone();
            bytes[30..34].copy_from_slice(&0x0000_ffffu32.to_be_bytes());
            bytes
        }),
        ("truncated", base[..base.len() - 1].to_vec()),
    ];
    for (name, input) in &refusals {
        let code = codec::decode(input).expect_err("refused");
        out.section(&format!("refuse_{name}"));
        out.hex("input", input);
        out.text("code", code.name());
    }

    out.section("slack_rule");
    out.line("# R-C5: a PQ TLV rides only when it fits in what is left of the bucket the body");
    out.line("# length alone already chose, so the bucket never depends on a PQ TLV.");
    out.num("pq_key_tlv_bytes", codec::PQ_KEY_TLV_BYTES as u64);
    out.num(
        "seal_root_pq_tlv_bytes",
        codec::SEAL_ROOT_PQ_TLV_BYTES as u64,
    );
    for (body_len, tlv, label) in [
        (1148usize, codec::PQ_KEY_TLV_BYTES, "pq_key_body_1148"),
        (1149, codec::PQ_KEY_TLV_BYTES, "pq_key_body_1149"),
        (
            1210,
            codec::SEAL_ROOT_PQ_TLV_BYTES,
            "seal_root_pq_body_1210",
        ),
        (
            1211,
            codec::SEAL_ROOT_PQ_TLV_BYTES,
            "seal_root_pq_body_1211",
        ),
    ] {
        out.num(
            &format!("fits_4096_{label}"),
            u64::from(codec::pq_tlv_fits(4096, body_len, 0, tlv)),
        );
    }

    out.section("ext_reserve");
    out.line(
        "# S21.11 point 3: L_class = 52 + |body| + EXT_RESERVE and the bucket is the smallest",
    );
    out.line(
        "# b with L_class <= b - o_max, computed from the body length alone. A sender refuses",
    );
    out.line("# classical TLVs beyond ext_reserve; receivers accept up to max_ext (2560).");
    out.num("ext_reserve", seal::EXT_RESERVE as u64);
    out.num("max_ext", codec::MAX_EXT_BYTES as u64);
    out.num("l0_fixed_with_quote", seal::L0_FIXED_BYTES as u64);
    out.num("classical_tlv_refused_at", (seal::EXT_RESERVE + 1) as u64);

    // The class boundaries of S21.11 point 3, with and without a quote and a pending classical
    // TLV: the bucket must be the same in all four shapes, because it depends on the body alone.
    for (body_len, label) in [
        (2220usize, "b4096_last"),
        (2221, "b16384_first"),
        (14508, "b16384_last"),
        (14509, "b65536_first"),
    ] {
        for quoted in [false, true] {
            for pending in [0usize, seal::EXT_RESERVE] {
                let mut content = DmContent {
                    kind: Kind::Text,
                    message_id: [0x5f; 16],
                    author_minute: 29_000_007,
                    minute_index: 0,
                    timer_code: 0,
                    timer_version: 7,
                    quote_ref: if quoted { Some([0x60; 16]) } else { None },
                    body: vec![0x41; body_len],
                    ext: Vec::new(),
                };
                if pending > 0 {
                    content.ext = vec![Tlv {
                        tlv_type: codec::TLV_CARD_UPDATE,
                        value: vec![0x61; pending - codec::TLV_HEADER_BYTES],
                    }];
                }
                let bytes = content.encode().expect("encode");
                assert_eq!(&codec::decode(&bytes).expect("decode"), &content);
                let name = format!(
                    "class_{label}_{}_{}",
                    if quoted { "quoted" } else { "plain" },
                    if pending > 0 { "tlv" } else { "no_tlv" }
                );
                out.section(&name);
                out.num("body_len", body_len as u64);
                out.num("has_quote", u64::from(quoted));
                out.num(
                    "classical_ext_len",
                    codec::classical_ext_len(&content.ext) as u64,
                );
                out.num("l0_len", bytes.len() as u64);
                out.num("bucket", content.bucket().expect("bucket") as u64);
                out.sha("l0_sha256", &bytes);
            }
        }
    }

    check("dm_content.txt", &out.0);
}

#[test]
fn dm_safety_number_vectors() {
    let mut out = Out::new(
        "\
# GHOST safety number v1 vectors (Phase 9 design faza9-dm.md §8.4). Generated and checked by\n\
# client-core/dm/tests/vectors.rs::dm_safety_number_vectors; an independent implementation\n\
# replays it on the JDK's own MessageDigest.\n\
#\n\
#   own_id(party) = identity_pk(32, Ed25519) || oi(32, Olm identity)\n\
#   h_0           = SHA-512(\"ghost/v1/safety-number\" || 01 || own_id)\n\
#   h_{k+1}       = SHA-512(h_k || own_id)          for k = 0 .. 5199   (5201 evaluations)\n\
#   digits(party) = for j in 0..5: (u40_be(h_5200[5j .. 5j+5]) mod 100000) as 5 decimal digits\n\
#   display       = digits(a) || digits(b), the smaller 30-digit string first\n\
#   scannable     = 01 || h_5200(own)[0..32] || h_5200(peer)[0..32]           (65 bytes)\n\
#\n\
# The digits of a GHOST safety number are never compared with another messenger's.\n",
    );

    let alice = safety::Party {
        identity_pk: [0x61; 32],
        olm_identity: [0x62; 32],
    };
    let bob = safety::Party {
        identity_pk: [0x63; 32],
        olm_identity: [0x64; 32],
    };
    let a = safety::safety_number(&alice, &bob);
    let b = safety::safety_number(&bob, &alice);
    assert_eq!(a.display, b.display);

    out.section("parties");
    out.num("iterations", safety::ITERATIONS as u64);
    out.hex("a_identity_pk", &alice.identity_pk);
    out.hex("a_olm_identity", &alice.olm_identity);
    out.hex("b_identity_pk", &bob.identity_pk);
    out.hex("b_olm_identity", &bob.olm_identity);

    out.section("outputs");
    out.hex("a_hash", &alice.hash());
    out.hex("b_hash", &bob.hash());
    out.text("a_digits", &alice.digits());
    out.text("b_digits", &bob.digits());
    out.text("display", &a.display);
    out.hex("scannable_from_a", &a.scannable);
    out.hex("scannable_from_b", &b.scannable);

    check("dm_safety_number.txt", &out.0);
}

/// The Ed25519 signing vectors of S0′ V-14 are the Phase 3 artifacts' responsibility; here the
/// crate's own X-21 signers are pinned instead, so a dalek bump that changed signing fails in Rust
/// and not only through the JVM comparison.
///
/// The pin is a **constant**: signing and verifying with the same library in one run proves
/// nothing about a bump, because a changed signer would still verify its own output. Each of the
/// three X-21 artifacts this crate signs — card v2, bundle v2 and binding v3 — therefore carries
/// its expected 64-byte signature here, computed from fixed inputs (Ed25519 is deterministic).
#[test]
fn the_x21_signatures_are_pinned() {
    const CARD_SIGNATURE: &str = "cb7cbc8772ca207ad64093e915dd933f14736e86b6025726e60807ccfb67b4c207710fffba1304bb9ebbc9727a15d2d814ca09ea585d1a7f35dd5f78e57ef809";
    const BUNDLE_SIGNATURE: &str = "154483dc88749812132bbc6b3d41d6eda07012e63cf76d42107e5cca8fea9514a373e70589f05499585da325a679bc3df3aee1dacd12031926e9a067d96aba07";
    const BINDING_SIGNATURE: &str = "abfb2c5a7a934ca7ef789c1570d590bd62ed6daa8aa59a97f4feeb3f23c4a3d277d910316cbfa2b98031ba987068d5c830d6d83fddd3dbacc44fa6a18436700a";

    let card_secret = CardSecret::from_bytes([0x71; 32]);
    let card = card::build(&IDENTITY_SEED, 0, &card_secret);
    assert_eq!(hex::encode(card.signature), CARD_SIGNATURE, "card v2");
    assert!(
        card::parse(&card.encode()).is_ok(),
        "the parser accepts what the signer produced"
    );

    let xwing = pq::public_key(&KemSecret::from_bytes([0x72; 32])).expect("keygen");
    let bundle_plain = bundle::build(
        &IDENTITY_SEED,
        &bundle::BundleFields {
            card_index: 0,
            bundle_week: 2870,
            bundle_rank: 0,
            gen_id: 0x7374_7677,
            olm_identity: &[0x78; 32],
            fallback_key: &[0x79; 32],
            xwing_public: &xwing,
        },
    )
    .expect("build");
    let bundle = bundle::parse(&bundle_plain).expect("parse");
    assert_eq!(hex::encode(bundle.signature), BUNDLE_SIGNATURE, "bundle v2");

    let binding_signature = binding::sign(
        &IDENTITY_SEED,
        &BindingV3 {
            oi_a: &[0x7a; 32],
            card_index_a: 0,
            recipient_namespace: &[0x7b; 32],
            binding_minute: 29_000_000,
            gen_id_b: 0x7c7d_7e7f,
            xwing_ct: &[0x80; pq::CIPHERTEXT_BYTES],
            base_key_a: &[0x81; 32],
            oi_b: &[0x82; 32],
        },
    );
    assert_eq!(
        hex::encode(binding_signature),
        BINDING_SIGNATURE,
        "binding v3"
    );
}
