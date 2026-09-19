//! V-1: the dehydrated-pickle identity (design §2.2, §3.1, D11; §22.8.10 point 14).

use ed25519_dalek::SigningKey;
use ghost_dm_spike::codes::Code;
use ghost_dm_spike::derive;
use ghost_dm_spike::msc3814::{self, DehydratedSecrets};
use ghost_dm_spike::olm::{random_bytes, x25519_public};
use ghost_dm_spike::safety;
use serde_json::Value;

/// Root entropy 00 01 … 1f and its MESSAGING branch (`derivation_vectors.txt`, `messaging_seed`).
const ROOT: [u8; 32] = {
    let mut r = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        r[i] = i as u8;
        i += 1;
    }
    r
};
const MESSAGING_SEED: &str = "82453de069051555acf43dc3b93fa3be1a218d828bc156f7c1f4ad77a66f50cf";

fn bytes32(value: &Value) -> [u8; 32] {
    let items = value.as_array().expect("32-byte array");
    assert_eq!(items.len(), 32);
    let mut out = [0u8; 32];
    for (slot, item) in out.iter_mut().zip(items) {
        *slot = item.as_u64().expect("byte") as u8;
    }
    out
}

fn b64_nonce_and_ciphertext(nonce: &str, ciphertext: &str) -> ([u8; 12], Vec<u8>) {
    let nonce = vz11::base64_decode(nonce).expect("nonce base64");
    (
        <[u8; 12]>::try_from(nonce.as_slice()).expect("12-byte nonce"),
        vz11::base64_decode(ciphertext).expect("ciphertext base64"),
    )
}

macro_rules! v1_checks {
    ($module:ident, $vz:ident, $olm:path) => {
        mod $module {
            use super::*;
            use $olm as olm;
            use $vz::olm::{Account, OlmMessage, SessionConfig, SessionCreationError};

            /// GHOST's encoder equals `to_dehydrated_device` of an account that called
            /// `generate_fallback_key()` (and of one that did not), byte for byte.
            #[test]
            fn encoder_matches_to_dehydrated_device() {
                for with_fallback in [true, false] {
                    for _ in 0..16 {
                        let mut account = Account::new();
                        if with_fallback {
                            account.generate_fallback_key();
                        }
                        let key: [u8; 32] = random_bytes();
                        let exported = account.to_dehydrated_device(&key).expect("export");
                        let (nonce, ciphertext) =
                            b64_nonce_and_ciphertext(&exported.nonce, &exported.ciphertext);
                        let library_plain =
                            msc3814::open(&ciphertext, &key, &nonce).expect("opens");

                        // The secrets come from the account's own JSON pickle, not from the export.
                        let json = serde_json::to_value(account.pickle()).expect("pickle json");
                        let fallback = json.pointer("/fallback_keys/fallback_key/key").map(bytes32);
                        let secrets = DehydratedSecrets {
                            curve25519: bytes32(&json["diffie_hellman_key"]),
                            ed25519_seed: bytes32(&json["signing_key"]["Normal"]),
                            fallback,
                        };
                        assert_eq!(secrets.fallback.is_some(), with_fallback);
                        assert_eq!(
                            msc3814::encode(&secrets),
                            library_plain,
                            "encoder differs ({})",
                            olm::VERSION
                        );
                        let decoded = msc3814::decode(&library_plain).expect("strict decode");
                        assert_eq!(decoded.curve25519, secrets.curve25519);
                    }
                }
            }

            /// The seed-derived identity: `from_dehydrated_device` yields the identity keys
            /// computed outside vodozemac, reproducibly (a restore reproduces OI).
            #[test]
            fn derived_identity_matches_and_restores() {
                let messaging = derive::hkdf32(&ROOT, derive::MESSAGING.as_bytes());
                assert_eq!(
                    hex::encode(messaging),
                    MESSAGING_SEED,
                    "HKDF convention differs from :identity"
                );
                let ids = derive::olm_identity(&messaging);
                let fallback: [u8; 32] = random_bytes();
                let secrets = DehydratedSecrets {
                    curve25519: ids.identity,
                    ed25519_seed: ids.account_signing_seed,
                    fallback: Some(fallback),
                };
                let expected_oi = x25519_public(&ids.identity);
                let expected_ed = SigningKey::from_bytes(&ids.account_signing_seed)
                    .verifying_key()
                    .to_bytes();
                let first = olm::account(&secrets).expect("account");
                let (oi, ed) = olm::identity_keys(&first);
                assert_eq!(oi, expected_oi);
                assert_eq!(ed, expected_ed);
                // The import marks the fallback key published: fallback_key() does not list it.
                assert_eq!(olm::unpublished_fallback_keys(&first), 0);
                // "Restore": re-derive from the same MESSAGING branch, a different sealing key.
                let again = derive::olm_identity(&messaging);
                let restored = olm::account(&DehydratedSecrets {
                    curve25519: again.identity,
                    ed25519_seed: again.account_signing_seed,
                    fallback: None,
                })
                .expect("account");
                assert_eq!(olm::identity_keys(&restored).0, oi);
                // Safety numbers depend only on (identity_pk, OI), so they are reproduced too.
                let peer_id: [u8; 32] = random_bytes();
                let peer_oi: [u8; 32] = random_bytes();
                let own_id: [u8; 32] = random_bytes();
                assert_eq!(
                    safety::display((&own_id, &oi), (&peer_id, &peer_oi)),
                    safety::display(
                        (&own_id, &olm::identity_keys(&restored).0),
                        (&peer_id, &peer_oi)
                    )
                );
            }

            /// The imported fallback secret works behaviourally: a session from a second account
            /// to (OI, F_g) opens; one to another F fails with MissingOneTimeKey.
            #[test]
            fn imported_fallback_secret_opens_sessions() {
                let ids = derive::olm_identity(&random_bytes());
                let f_g: [u8; 32] = random_bytes();
                let generation = DehydratedSecrets {
                    curve25519: ids.identity,
                    ed25519_seed: ids.account_signing_seed,
                    fallback: Some(f_g),
                };
                let oi = x25519_public(&ids.identity);
                let sender = Account::new();
                for (fallback_public, should_open) in [
                    (x25519_public(&f_g), true),
                    (x25519_public(&random_bytes()), false),
                ] {
                    let mut session = sender
                        .create_outbound_session(
                            SessionConfig::version_1(),
                            $vz::Curve25519PublicKey::from_bytes(oi),
                            $vz::Curve25519PublicKey::from_bytes(fallback_public),
                        )
                        .expect("outbound");
                    let OlmMessage::PreKey(prekey) =
                        session.encrypt(b"first flight").expect("encrypt")
                    else {
                        panic!("first output must be a PreKey message");
                    };
                    let mut recipient = olm::account(&generation).expect("account");
                    let result = recipient.create_inbound_session(
                        SessionConfig::version_1(),
                        sender.curve25519_key(),
                        &prekey,
                    );
                    match (result, should_open) {
                        (Ok(created), true) => assert_eq!(created.plaintext, b"first flight"),
                        (Err(SessionCreationError::MissingOneTimeKey(_)), false) => {}
                        (Ok(_), false) => panic!("another fallback key opened a session"),
                        (Err(e), _) => panic!("unexpected error {e:?}"),
                    }
                }
            }

            /// A pickle with a wrong version, and a truncated one, are refused as state errors.
            #[test]
            fn malformed_pickles_are_refused() {
                let secrets = DehydratedSecrets {
                    curve25519: random_bytes(),
                    ed25519_seed: random_bytes(),
                    fallback: None,
                };
                let mut plain = msc3814::encode(&secrets);
                plain[3] = 2;
                let key: [u8; 32] = random_bytes();
                let nonce: [u8; 12] = random_bytes();
                let sealed = msc3814::seal(&plain, &key, &nonce);
                assert!(Account::from_dehydrated_device(
                    &$vz::base64_encode(&sealed),
                    &$vz::base64_encode(nonce),
                    &key
                )
                .is_err());
                let truncated = msc3814::seal(&msc3814::encode(&secrets)[..40], &key, &nonce);
                assert!(Account::from_dehydrated_device(
                    &$vz::base64_encode(&truncated),
                    &$vz::base64_encode(nonce),
                    &key
                )
                .is_err());
                assert_eq!(olm::load(b"{}").err(), Some(Code::StateCorrupt));
            }
        }
    };
}

v1_checks!(vodozemac_0_11_0, vz11, ghost_dm_spike::olm::v11);
v1_checks!(vodozemac_0_10_0, vz10, ghost_dm_spike::olm::v10);

/// A GHOST pickle is read identically by both pins.
#[test]
fn both_pins_import_the_same_identity() {
    let ids = derive::olm_identity(&random_bytes());
    let secrets = DehydratedSecrets {
        curve25519: ids.identity,
        ed25519_seed: ids.account_signing_seed,
        fallback: Some(random_bytes()),
    };
    let a = ghost_dm_spike::olm::v11::account(&secrets).expect("0.11");
    let b = ghost_dm_spike::olm::v10::account(&secrets).expect("0.10");
    assert_eq!(
        ghost_dm_spike::olm::v11::identity_keys(&a),
        ghost_dm_spike::olm::v10::identity_keys(&b)
    );
}
