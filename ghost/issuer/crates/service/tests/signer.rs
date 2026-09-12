//! The production signer path: the RFC 9578 A.2 vectors through `ReferenceSigner` inside
//! `CheckedSigner` (the RFC evidence for the production signer, design §19.18), input range
//! checks, determinism, and an injected CRT fault caught by `CheckedSigner` (design §2.9).

mod common;

use ghost_blind_rsa::{BigUint, PublicKey};
use ghost_entitlement::token::AUTHENTICATOR_LEN;
use ghost_entitlement::Kind;
use ghost_issuer::signer::{CheckedSigner, ReferenceSigner, SignError, Signer};

fn block(bytes: &[u8]) -> [u8; AUTHENTICATOR_LEN] {
    bytes.try_into().unwrap()
}

#[test]
fn rfc9578_a2_through_the_production_signer() {
    let vectors = common::section("rfc9578-a2");
    assert_eq!(vectors.len(), 5);
    for v in vectors {
        let pem = String::from_utf8(v.hex("skI")).unwrap();
        let signer = ReferenceSigner::from_pkcs8_pem(Kind::Access, 0, &pem).unwrap();
        let es_key = PublicKey::from_spki(&v.hex("pkI")).unwrap();
        assert_eq!(signer.public_key(), &es_key);
        let checked = CheckedSigner::new(signer, es_key).unwrap();
        let request = v.hex("token_request");
        let blinded = block(&request[3..]);
        let sig = checked.blind_sign(&blinded).unwrap();
        assert_eq!(
            sig.as_slice(),
            v.hex("token_response").as_slice(),
            "vector {}",
            v.id
        );
        // Deterministic in (key, blinded): base blinding does not change the result.
        assert_eq!(checked.blind_sign(&blinded).unwrap(), sig);
        assert_eq!(checked.faults(), 0);
    }
}

fn rfc_signer() -> (ReferenceSigner, PublicKey) {
    let v = common::section("rfc9578-a2").remove(0);
    let pem = String::from_utf8(v.hex("skI")).unwrap();
    (
        ReferenceSigner::from_pkcs8_pem(Kind::Credit, 227, &pem).unwrap(),
        PublicKey::from_spki(&v.hex("pkI")).unwrap(),
    )
}

#[test]
fn zero_n_and_above_n_are_refused() {
    let (signer, pk) = rfc_signer();
    let n = block(pk.n_bytes());
    let mut n_plus_one = n;
    n_plus_one[AUTHENTICATOR_LEN - 1] += 1; // n is odd: no carry
    assert_eq!(
        signer.blind_sign(&[0u8; AUTHENTICATOR_LEN]),
        Err(SignError::InvalidInput)
    );
    assert_eq!(signer.blind_sign(&n), Err(SignError::InvalidInput));
    assert_eq!(signer.blind_sign(&n_plus_one), Err(SignError::InvalidInput));
    assert_eq!(
        signer.blind_sign(&[0xff; AUTHENTICATOR_LEN]),
        Err(SignError::InvalidInput)
    );
    let checked = CheckedSigner::new(signer, pk).unwrap();
    assert_eq!(checked.key(), (Kind::Credit, 227));
    assert_eq!(
        checked.blind_sign(&[0u8; AUTHENTICATOR_LEN]),
        Err(SignError::InvalidInput)
    );
    assert_eq!(checked.blind_sign(&n), Err(SignError::InvalidInput));
    assert!(checked.blind_sign(&[0x01; AUTHENTICATOR_LEN]).is_ok());
}

/// A test-only signer that computes a correct signature and then corrupts it the way a CRT fault
/// would (one half of the CRT result wrong: here, a flipped byte).
struct FaultySigner {
    inner: ReferenceSigner,
    fault_on_call: std::sync::atomic::AtomicU32,
}

impl Signer for FaultySigner {
    fn key(&self) -> (Kind, u64) {
        self.inner.key()
    }

    fn blind_sign(
        &self,
        blinded: &[u8; AUTHENTICATOR_LEN],
    ) -> Result<[u8; AUTHENTICATOR_LEN], SignError> {
        let mut sig = self.inner.blind_sign(blinded)?;
        if self
            .fault_on_call
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed)
            == 1
        {
            sig[AUTHENTICATOR_LEN / 2] ^= 0x40;
        }
        Ok(sig)
    }
}

#[test]
fn an_injected_fault_is_withheld_and_counted() {
    let (signer, pk) = rfc_signer();
    // Call 1 is the construction self-check; call 3 is faulty.
    let faulty = FaultySigner {
        inner: signer,
        fault_on_call: 3.into(),
    };
    let checked = CheckedSigner::new(faulty, pk).unwrap();
    let blinded = [0x02; AUTHENTICATOR_LEN];
    assert!(checked.blind_sign(&blinded).is_ok());
    assert_eq!(checked.blind_sign(&blinded), Err(SignError::Fault));
    assert_eq!(checked.faults(), 1);
    assert!(checked.blind_sign(&blinded).is_ok());
}

#[test]
fn a_signer_that_does_not_match_its_key_is_refused_at_load() {
    let (signer, _) = rfc_signer();
    let other = ReferenceSigner::generate(Kind::Access, 1).unwrap();
    assert_eq!(
        CheckedSigner::new(signer, other.public_key().clone()).err(),
        Some(SignError::Key)
    );
    // A fault on the very first (self-check) signature is also a refusal at load.
    let (signer, pk) = rfc_signer();
    let faulty = FaultySigner {
        inner: signer,
        fault_on_call: 1.into(),
    };
    assert_eq!(CheckedSigner::new(faulty, pk).err(), Some(SignError::Key));
}

#[test]
fn generated_keys_are_type_0x0002_keys() {
    let signer = ReferenceSigner::generate(Kind::Invite, 740).unwrap();
    assert_eq!(signer.public_key().modulus_bits(), 2048);
    assert_eq!(signer.public_key().e(), &BigUint::from(65_537u32));
    let der = signer.to_pkcs8_der().unwrap();
    let again = ReferenceSigner::from_pkcs8_der(Kind::Invite, 740, &der).unwrap();
    assert_eq!(again.public_key(), signer.public_key());
    let blinded = [0x03; AUTHENTICATOR_LEN];
    assert_eq!(
        again.blind_sign(&blinded).unwrap(),
        signer.blind_sign(&blinded).unwrap()
    );
}
