//! Replays the `[ghost]` section of `protocol/test-vectors/blind_rsa_pp2.txt` through
//! ghost-entitlement (Phase 8 design §2.9): redemption contexts, challenges, key ids, the
//! permutation proof, seed-derived positions, layout and request digests, finalized tokens.

mod common;

use common::fixture;
use ghost_blind_rsa::{i2osp, PublicKey};
use ghost_entitlement::batch::{self, Layout};
use ghost_entitlement::challenge::{redemption_context, TokenChallenge};
use ghost_entitlement::grid::Kind;
use ghost_entitlement::token::{self, Token, AUTHENTICATOR_LEN};
use ghost_entitlement::{Expect, Schedule};
use sha2::{Digest, Sha256};

fn vector(id: &str) -> common::Vector {
    common::section("ghost")
        .into_iter()
        .find(|v| v.id == id)
        .unwrap_or_else(|| panic!("no [ghost] vector {id}"))
}

fn u64_field(v: &common::Vector, key: &str) -> u64 {
    u64::from_be_bytes(v.hex(key).try_into().unwrap())
}

fn u32_field(v: &common::Vector, key: &str) -> usize {
    u32::from_be_bytes(v.hex(key).try_into().unwrap()) as usize
}

#[test]
fn schedule_and_challenges() {
    let s = fixture::schedule();
    let v = vector("schedule");
    assert_eq!(v.hex("schedule_key"), fixture::schedule_key());
    assert_eq!(v.hex("schedule_sha256"), s.digest());
    assert_eq!(v.hex("issuer_name"), s.issuer_name().as_bytes());
    for id in ["challenge-01", "challenge-02", "challenge-03"] {
        let v = vector(id);
        let kind = Kind::from_byte(v.hex("kind")[0]).unwrap();
        let epoch = u64_field(&v, "epoch");
        let slot = v.hex("slot").first().copied();
        assert_eq!(v.hex("redemption_context"), redemption_context(kind, epoch));
        let challenge = TokenChallenge::ghost(s.issuer_name(), kind, epoch, slot).unwrap();
        assert_eq!(v.hex("challenge"), challenge.encode().unwrap());
        assert_eq!(
            v.hex("challenge_digest"),
            s.challenge_digest(kind, epoch, slot).unwrap()
        );
        let key = s.key(kind, epoch).unwrap();
        assert_eq!(v.hex("spki"), key.public_key.to_spki());
        assert_eq!(v.hex("key_id"), token::key_id(&v.hex("spki")));
        assert_eq!(v.hex("key_id"), key.key_id);
    }
}

#[test]
fn permutation_proof_valid_and_tampered() {
    let v = vector("perm-proof");
    let pk = PublicKey::from_spki(&v.hex("spki")).unwrap();
    let challenges = ghost_blind_rsa::permutation_proof_challenges(&pk).unwrap();
    assert_eq!(v.hex("challenges"), challenges.concat());
    let blocks = |key: &str| -> [[u8; 256]; 8] {
        let bytes = v.hex(key);
        std::array::from_fn(|i| bytes[i * 256..(i + 1) * 256].try_into().unwrap())
    };
    ghost_blind_rsa::verify_permutation_proof(&pk, &blocks("proof")).unwrap();
    assert!(ghost_blind_rsa::verify_permutation_proof(&pk, &blocks("tampered_proof")).is_err());
}

/// Checks every `pN.*` group of a vector against a fresh derivation.
fn check_positions(s: &Schedule, v: &common::Vector, seed: &[u8; 32], layout: &Layout) -> usize {
    let mut seen = 0;
    for key in v.fields.keys().filter(|k| k.ends_with(".nonce")) {
        let tag = key.trim_end_matches(".nonce");
        let j: usize = tag[1..].parse().unwrap();
        let field = |name: &str| v.hex(&format!("{tag}.{name}"));
        let d = batch::derive(s, seed, layout, j).unwrap();
        assert_eq!(field("kind")[0], d.position.kind.byte(), "{tag}");
        assert_eq!(field("epoch"), d.position.epoch.to_be_bytes());
        assert_eq!(field("slot")[0], d.position.slot.unwrap_or(batch::NO_SLOT));
        assert_eq!(field("nonce"), d.nonce);
        assert_eq!(field("salt"), d.salt);
        assert_eq!(field("r"), i2osp(&d.r, AUTHENTICATOR_LEN).unwrap());
        assert_eq!(field("blinded"), d.blinded);
        let key = s.key(d.position.kind, d.position.epoch).unwrap();
        let blind_sig = field("blind_sig");
        assert!(ghost_blind_rsa::check_blind_signature(
            &key.public_key,
            &d.blinded,
            &blind_sig
        ));
        let token = token::finalize_input(&key.public_key, &d.input, &blind_sig, &d.inv).unwrap();
        assert_eq!(
            token.as_bytes().as_slice(),
            field("token").as_slice(),
            "{tag}"
        );
        assert_eq!(token.nullifier().as_slice(), field("nullifier").as_slice());
        let expect = match d.position.kind {
            Kind::Access => Expect::AccessAtSlot(d.position.slot.unwrap()),
            Kind::Invite => Expect::Invite,
            Kind::Credit => Expect::Credit,
        };
        let verified = s
            .verify_token(&Token::parse(&field("token")).unwrap(), expect)
            .unwrap();
        assert_eq!(
            (verified.kind, verified.epoch, verified.slot),
            (d.position.kind, d.position.epoch, d.position.slot)
        );
        seen += 1;
    }
    seen
}

#[test]
fn pack_paid_in_xmr() {
    let s = fixture::schedule();
    let v = vector("pack-xmr");
    let seed: [u8; 32] = v.hex("seed").try_into().unwrap();
    let base = u64_field(&v, "base_week");
    let layout = Layout::pack(&s, base, true).unwrap();
    assert_eq!(layout.len(), u32_field(&v, "positions"));
    // 5 weeks x 3 slots x 16 + 2 invites + 1 credit.
    assert_eq!(layout.len(), 243);
    assert_eq!(v.hex("layout_digest"), layout.digest());
    layout.check_digest(&v.hex("layout_digest")).unwrap();
    let request = batch::blind(&s, &seed, &layout).unwrap();
    assert_eq!(v.hex("request_sha256"), Sha256::digest(&request).as_slice());
    let invoice_id: [u8; 16] = v.hex("invoice_id").try_into().unwrap();
    assert_eq!(
        v.hex("request_digest"),
        batch::request_digest(&invoice_id, &request)
    );
    // A retry recomputes byte-identical blinded messages.
    assert_eq!(batch::blind(&s, &seed, &layout).unwrap(), request);
    assert_eq!(check_positions(&s, &v, &seed, &layout), 10);
}

#[test]
fn pack_paid_with_credits_trial_and_refresh() {
    let s = fixture::schedule();
    let v = vector("pack-credits");
    let credits = Layout::pack(&s, u64_field(&v, "base_week"), false).unwrap();
    assert_eq!(credits.len(), u32_field(&v, "positions"));
    assert_eq!(v.hex("layout_digest"), credits.digest());

    let v = vector("trial");
    let seed: [u8; 32] = v.hex("seed").try_into().unwrap();
    let base = u64_field(&v, "base_week");
    let trial = Layout::trial(&s, base).unwrap();
    // 2 weeks x 3 slots x 8.
    assert_eq!(trial.len(), 48);
    assert_eq!(trial.len(), u32_field(&v, "positions"));
    assert_eq!(v.hex("layout_digest"), trial.digest());
    let request = batch::blind(&s, &seed, &trial).unwrap();
    assert_eq!(v.hex("request_sha256"), Sha256::digest(&request).as_slice());
    let invite_nullifier: [u8; 32] = v.hex("invite_nullifier").try_into().unwrap();
    assert_eq!(
        v.hex("trial_digest"),
        batch::trial_digest(&invite_nullifier, base, &request)
    );
    assert_eq!(check_positions(&s, &v, &seed, &trial), 1);

    let v = vector("refresh");
    let refresh = Layout::refresh(
        &s,
        ghost_entitlement::grid::credit_epoch(fixture::FIRST_WEEK),
    )
    .unwrap();
    assert_eq!(refresh.len(), u32_field(&v, "positions"));
    assert_eq!(v.hex("layout_digest"), refresh.digest());
}
