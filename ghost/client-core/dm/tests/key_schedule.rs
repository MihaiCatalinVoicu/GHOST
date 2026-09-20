//! The Olm key-schedule oracle (design §15.2 item 3, "Substitutes for official vectors").
//!
//! Olm publishes no official test vectors, so GHOST builds one from the **documented** schedule,
//! outside vodozemac:
//!
//! ```text
//! expanded = HKDF-SHA256(salt = 0x00, ikm = M, info = "OLM_KEYS", L = 80)
//!          = aes_key(32) || mac_key(32) || iv(16)
//! plaintext = PKCS#7-unpad(AES-256-CBC-decrypt(aes_key, iv, ciphertext))
//! mac       = HMAC-SHA256(mac_key, encoded_message_without_mac)[0..8]        (V1: truncated)
//! ```
//!
//! The message key `M` comes out of vodozemac through `low-level-api` (dev graph only), and the
//! ciphertext is the one GHOST's own `encrypt` produced. Agreement on both the plaintext and the
//! MAC means the session really ran the schedule the specification describes, with the
//! configuration GHOST asked for.
//!
//! **What it catches that the library's own tests cannot** (§15.2 item 3): a configuration misuse.
//! `SessionConfig::version_1()` must produce an 8-byte MAC; V2 (`experimental-session-config`,
//! forbidden in every shipped graph) produces a 32-byte one, and a wrong or swapped session
//! produces a message key that decrypts nothing. Both fail here.

use aes::cipher::block_padding::Pkcs7;
use aes::cipher::{BlockModeDecrypt, KeyIvInit};
use ghost_client_dm::derive::{self, MessagingBranch, OlmSecret};
use ghost_client_dm::olm::session::{self, Slot, StoredSession};
use ghost_client_dm::olm::state::SessionState;
use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use vodozemac::olm::{Message, Session, SessionPickle};

type Aes256CbcDec = cbc::Decryptor<aes::Aes256>;
type HmacSha256 = Hmac<Sha256>;

/// Olm's V1 MAC length. A V2 message carries 32 bytes here.
const TRUNCATED_MAC_LEN: usize = 8;

/// The oracle's own expansion of a message key, from the specification and nothing else.
fn expand(message_key: &[u8; 32]) -> ([u8; 32], [u8; 32], [u8; 16]) {
    let hkdf: Hkdf<Sha256> = Hkdf::new(Some(&[0]), message_key);
    let mut expanded = [0u8; 80];
    hkdf.expand(b"OLM_KEYS", &mut expanded)
        .expect("80 bytes is inside the HKDF output limit");
    let mut aes_key = [0u8; 32];
    let mut mac_key = [0u8; 32];
    let mut iv = [0u8; 16];
    aes_key.copy_from_slice(&expanded[0..32]);
    mac_key.copy_from_slice(&expanded[32..64]);
    iv.copy_from_slice(&expanded[64..80]);
    (aes_key, mac_key, iv)
}

/// Decrypts an Olm ciphertext with the oracle's own AES-256-CBC.
fn oracle_decrypt(aes_key: &[u8; 32], iv: &[u8; 16], ciphertext: &[u8]) -> Vec<u8> {
    let mut buffer = ciphertext.to_vec();
    let len = Aes256CbcDec::new(aes_key.into(), iv.into())
        .decrypt_padded::<Pkcs7>(&mut buffer)
        .expect("the oracle unpads an Olm ciphertext")
        .len();
    buffer.truncate(len);
    buffer
}

/// The V1 truncated MAC over everything of the wire message before the MAC itself.
fn oracle_mac(mac_key: &[u8; 32], l1: &[u8]) -> [u8; TRUNCATED_MAC_LEN] {
    let split = l1.len() - TRUNCATED_MAC_LEN;
    let mut hmac = HmacSha256::new_from_slice(mac_key).expect("any key length");
    hmac.update(&l1[..split]);
    let full = hmac.finalize().into_bytes();
    let mut out = [0u8; TRUNCATED_MAC_LEN];
    out.copy_from_slice(&full[..TRUNCATED_MAC_LEN]);
    out
}

/// The message key vodozemac would use for the next message of this stored state.
///
/// The state must carry an **active** sending ratchet: on an inactive one, both
/// `next_message_key` and `encrypt` activate it with a fresh random ratchet key, so two copies of
/// the same state would produce two different chains. [`warm`] is what guarantees that.
fn next_message_key(state: &[u8]) -> ([u8; 32], u64) {
    let decoded = SessionState::decode(state).expect("state");
    let pickle: SessionPickle = serde_json::from_slice(&decoded.pickle).expect("pickle");
    // A fresh object: `next_message_key` advances the sending chain, so it is never called on the
    // state GHOST goes on to use.
    let mut session = Session::from_pickle(pickle);
    let key = session
        .next_message_key()
        .expect("an established session has a sending chain");
    (*key.key(), key.index())
}

fn party(tag: u8) -> (OlmSecret, OlmSecret, [u8; 32]) {
    let branch = MessagingBranch::from_bytes([tag; 32]);
    let identity = derive::derive_olm_identity(&branch);
    let signing = derive::derive_olm_account_signing(&branch);
    let public = derive::olm_identity_public(&identity);
    (identity, signing, public)
}

/// A settled session in both directions, so the oracle sees normal messages (a PreKey message
/// wraps the same normal message, which the oracle reaches through `Message::from_bytes`).
fn settled_session() -> (Vec<u8>, Vec<u8>) {
    let (a_identity, a_signing, a_public) = party(0x31);
    let (b_identity, b_signing, b_public) = party(0x32);
    let fallback_secret = [0x33u8; 32];
    let fallback_public = derive::olm_identity_public(&OlmSecret::from_bytes(fallback_secret));

    let outbound =
        session::session_outbound(&a_identity, &a_signing, &b_public, &fallback_public, 1)
            .expect("outbound");
    let first = session::encrypt(&outbound.state, b"settle", 1).expect("encrypt");
    let inbound = session::session_inbound(
        &b_identity,
        &b_signing,
        fallback_secret,
        &a_public,
        &first.l1,
        1,
    )
    .expect("inbound");
    let reply = session::encrypt(&inbound.state, b"settled", 1).expect("encrypt");
    let a_state = session::decrypt(
        &[StoredSession {
            slot: Slot::Current,
            state: &first.state,
        }],
        &reply.l1,
        reply.is_pre_key,
        1,
    )
    .expect("decrypt")
    .state;
    (warm(&a_state), warm(&reply.state))
}

/// One discarded send, so the sending ratchet of the returned state is active and the oracle's
/// exported key is the one the next `encrypt` will use.
fn warm(state: &[u8]) -> Vec<u8> {
    session::encrypt(state, b"warm", 1).expect("encrypt").state
}

#[test]
fn the_oracle_reproduces_the_documented_schedule_for_both_directions() {
    let (a_state, b_state) = settled_session();

    for (label, state, plaintext) in [
        ("initiator", a_state, b"oracle a".as_slice()),
        ("responder", b_state, b"oracle b".as_slice()),
    ] {
        let (message_key, index) = next_message_key(&state);
        let out = session::encrypt(&state, plaintext, 1).expect("encrypt");
        assert!(!out.is_pre_key, "{label}: the session is settled");

        let message = Message::from_bytes(&out.l1).expect("the oracle parses the wire message");
        assert_eq!(
            message.chain_index(),
            index,
            "{label}: the exported key's index"
        );

        let (aes_key, mac_key, iv) = expand(&message_key);
        assert_eq!(
            oracle_decrypt(&aes_key, &iv, message.ciphertext()),
            plaintext,
            "{label}: the oracle decrypts what GHOST encrypted"
        );
        assert_eq!(
            oracle_mac(&mac_key, &out.l1),
            out.l1[out.l1.len() - TRUNCATED_MAC_LEN..],
            "{label}: the oracle reproduces the V1 truncated MAC"
        );
    }
}

/// The configuration assertion: V1 truncates the MAC to 8 bytes. A V2 session would put 32 bytes
/// there, and the `to_mac_bytes` split this oracle uses would land inside the MAC instead.
#[test]
fn the_session_config_is_version_one_with_a_truncated_mac() {
    let (a_state, _) = settled_session();
    let (message_key, _) = next_message_key(&a_state);
    let out = session::encrypt(&a_state, b"mac length", 1).expect("encrypt");
    let message = Message::from_bytes(&out.l1).expect("wire message");

    // The encoded message without its MAC, plus exactly 8 bytes, is the whole wire message.
    let (_, mac_key, _) = expand(&message_key);
    assert_eq!(
        oracle_mac(&mac_key, &out.l1).as_slice(),
        &out.l1[out.l1.len() - TRUNCATED_MAC_LEN..],
        "a V2 message would carry a 32-byte MAC and fail this comparison"
    );
    assert_eq!(message.version(), 3, "Olm's truncated-MAC message version");
}

/// A wrong session's message key decrypts nothing: the oracle is sensitive to which session ran.
#[test]
fn a_message_key_from_another_session_does_not_open_the_ciphertext() {
    let (a_state, b_state) = settled_session();
    let (other_key, _) = next_message_key(&b_state);
    let out = session::encrypt(&a_state, b"wrong session", 1).expect("encrypt");
    let message = Message::from_bytes(&out.l1).expect("wire message");

    let (aes_key, mac_key, iv) = expand(&other_key);
    let mut buffer = message.ciphertext().to_vec();
    let opened = Aes256CbcDec::new((&aes_key).into(), (&iv).into())
        .decrypt_padded::<Pkcs7>(&mut buffer)
        .map(<[u8]>::to_vec);
    assert!(
        opened.as_deref().ok() != Some(b"wrong session".as_slice()),
        "another session's message key must not open this ciphertext"
    );
    assert_ne!(
        oracle_mac(&mac_key, &out.l1),
        out.l1[out.l1.len() - TRUNCATED_MAC_LEN..],
        "another session's MAC key must not authenticate this message"
    );
}
