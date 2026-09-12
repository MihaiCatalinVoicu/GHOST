//! RFC 9578 Appendix A.2 (Issuance Protocol 2, Blind RSA 2048-bit): the 5 vectors replayed
//! through the production type-0x0002 path (Phase 8 design §2.9): canonical SPKI parse, key id,
//! TokenChallenge, token parse, blind, finalize, `ring` verification.

mod common;

use ghost_blind_rsa::{BigUint, PublicKey};
use ghost_entitlement::challenge::TokenChallenge;
use ghost_entitlement::token::{self, Token, AUTHENTICATOR_LEN};
use ghost_entitlement::FormatError;

fn vectors() -> Vec<common::Vector> {
    let v = common::section("rfc9578-a2");
    assert_eq!(
        v.iter().map(|v| v.id.as_str()).collect::<Vec<_>>(),
        ["1", "2", "3", "4", "5"]
    );
    v
}

#[test]
fn appendix_a2_through_the_production_path() {
    for v in vectors() {
        let spki = v.hex("pkI");
        let pk = PublicKey::from_spki(&spki).unwrap();
        token::check_key(&pk).unwrap();
        // The canonical encoder reproduces the RFC's SPKI byte for byte.
        assert_eq!(pk.to_spki(), spki);
        let key_id = token::key_id(&spki);

        let challenge_bytes = v.hex("token_challenge");
        let challenge = TokenChallenge::parse(&challenge_bytes).unwrap();
        assert_eq!(challenge.token_type, 0x0002);
        assert_eq!(challenge.encode().unwrap(), challenge_bytes);
        let challenge_digest = challenge.digest().unwrap();

        let expected = Token::parse(&v.hex("token")).unwrap();
        let nonce: [u8; 32] = v.hex("nonce").try_into().unwrap();
        let input = token::token_input(&nonce, &challenge_digest, &key_id);
        assert_eq!(
            &input,
            expected.token_input(),
            "vector {}: token_input",
            v.id
        );
        assert_eq!(expected.key_id(), key_id);
        assert_eq!(expected.challenge_digest(), challenge_digest);

        // TokenRequest = token_type || truncated_token_key_id || blinded_msg (RFC 9578 §6.1).
        let request = v.hex("token_request");
        assert_eq!(request.len(), 3 + AUTHENTICATOR_LEN);
        assert_eq!(&request[..2], &[0x00, 0x02]);
        assert_eq!(
            request[2], key_id[31],
            "truncated_token_key_id is the last byte of the key id"
        );

        // `blind` is the blinding factor r of RFC 9474 §4.2.
        let r = BigUint::from_bytes_be(&v.hex("blind"));
        let salt: [u8; 48] = v.hex("salt").try_into().unwrap();
        let (blinded, inv) = token::blind_input(&pk, &input, &salt, &r).unwrap();
        assert_eq!(
            blinded.as_slice(),
            &request[3..],
            "vector {}: blinded_msg",
            v.id
        );

        let response = v.hex("token_response");
        let finalized = token::finalize_input(&pk, &input, &response, &inv).unwrap();
        assert_eq!(finalized, expected, "vector {}: token", v.id);
        finalized.verify_signature(&pk).unwrap();
        assert_eq!(finalized.nullifier(), token::nullifier(&input));
    }
}

#[test]
fn appendix_a2_negatives() {
    for v in vectors() {
        let pk = PublicKey::from_spki(&v.hex("pkI")).unwrap();
        let good = v.hex("token");
        // Every byte of every field flipped in turn.
        for i in 0..good.len() {
            let mut bad = good.clone();
            bad[i] ^= 0x01;
            let verdict = Token::parse(&bad).and_then(|t| t.verify_signature(&pk));
            let expected = if i < 2 {
                FormatError::TokenType
            } else {
                FormatError::Signature
            };
            assert_eq!(verdict, Err(expected), "vector {} byte {i}", v.id);
        }
        // A non-canonical SPKI (one byte appended, or the salt length changed) is refused.
        let spki = v.hex("pkI");
        assert!(PublicKey::from_spki(&[spki.as_slice(), &[0]].concat()).is_err());
        let mut salt32 = spki.clone();
        let pos = salt32
            .windows(5)
            .position(|w| w == [0xa2, 0x03, 0x02, 0x01, 0x30])
            .unwrap();
        salt32[pos + 4] = 0x20;
        assert!(PublicKey::from_spki(&salt32).is_err());
        // A blind signature that does not finalize is refused, never turned into a token.
        let nonce: [u8; 32] = v.hex("nonce").try_into().unwrap();
        let digest = TokenChallenge::parse(&v.hex("token_challenge"))
            .unwrap()
            .digest()
            .unwrap();
        let input = token::token_input(&nonce, &digest, &token::key_id(&spki));
        let r = BigUint::from_bytes_be(&v.hex("blind"));
        let salt: [u8; 48] = v.hex("salt").try_into().unwrap();
        let (_, inv) = token::blind_input(&pk, &input, &salt, &r).unwrap();
        let mut response = v.hex("token_response");
        response[10] ^= 0x01;
        assert_eq!(
            token::finalize_input(&pk, &input, &response, &inv),
            Err(FormatError::Signature)
        );
    }
}
