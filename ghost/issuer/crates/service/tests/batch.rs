//! The issuer side of the seed-derived batches over the test schedule: the `[ghost]` vectors re-signed
//! by the production signers, and the negative finalization and token cases that need real blind
//! signatures (Phase 8 design §2.6, §2.9, §13.1).

mod common;

use common::fixture::{self, FIRST_WEEK};
use ghost_entitlement::batch::{self, BatchError, Layout, Position};
use ghost_entitlement::grid::{credit_epoch, invite_epoch, Kind};
use ghost_entitlement::schedule::TokenError;
use ghost_entitlement::token::{Token, AUTHENTICATOR_LEN};
use ghost_entitlement::{Expect, Schedule};
use ghost_issuer::signer::Signer;
use sha2::{Digest, Sha256};

fn sign(schedule: &Schedule, layout: &Layout, request: &[u8]) -> Vec<u8> {
    let signers = fixture::signers(schedule);
    let mut out = Vec::new();
    for (p, b) in layout
        .positions()
        .iter()
        .zip(request.as_chunks::<AUTHENTICATOR_LEN>().0)
    {
        out.extend_from_slice(&signers[&(p.kind, p.epoch)].blind_sign(b).unwrap());
    }
    out
}

fn vector(id: &str) -> common::Vector {
    common::section("ghost")
        .into_iter()
        .find(|v| v.id == id)
        .unwrap()
}

#[test]
fn ghost_pack_vector_is_reproduced_by_the_production_signers() {
    let s = fixture::schedule();
    let v = vector("pack-xmr");
    let seed: [u8; 32] = v.hex("seed").try_into().unwrap();
    let base = u64::from_be_bytes(v.hex("base_week").try_into().unwrap());
    let layout = Layout::pack(&s, base, true).unwrap();
    let request = batch::blind(&s, &seed, &layout).unwrap();
    let response = sign(&s, &layout, &request);
    assert_eq!(
        v.hex("response_sha256"),
        Sha256::digest(&response).as_slice()
    );
    let tokens = batch::finalize(&s, &seed, &layout, &response).unwrap();
    let bytes: Vec<u8> = tokens.iter().flat_map(|t| t.as_bytes().to_vec()).collect();
    assert_eq!(v.hex("tokens_sha256"), Sha256::digest(&bytes).as_slice());
    // Signing is deterministic in (key, B): a re-served request is byte-identical (MS-1).
    assert_eq!(sign(&s, &layout, &request), response);

    let v = vector("trial");
    let seed: [u8; 32] = v.hex("seed").try_into().unwrap();
    let trial = Layout::trial(&s, FIRST_WEEK).unwrap();
    let request = batch::blind(&s, &seed, &trial).unwrap();
    assert_eq!(
        v.hex("response_sha256"),
        Sha256::digest(sign(&s, &trial, &request)).as_slice()
    );
}

fn small_layout(s: &Schedule) -> Layout {
    Layout::from_positions(
        s,
        vec![
            Position {
                kind: Kind::Access,
                epoch: FIRST_WEEK,
                slot: Some(1),
            },
            Position {
                kind: Kind::Invite,
                epoch: invite_epoch(FIRST_WEEK),
                slot: None,
            },
            Position {
                kind: Kind::Credit,
                epoch: credit_epoch(FIRST_WEEK),
                slot: None,
            },
        ],
    )
    .unwrap()
}

#[test]
fn finalization_refuses_bad_responses() {
    let s = fixture::schedule();
    let layout = small_layout(&s);
    let seed = [9u8; 32];
    let request = batch::blind(&s, &seed, &layout).unwrap();
    let response = sign(&s, &layout, &request);
    assert_eq!(
        batch::finalize(&s, &seed, &layout, &response)
            .unwrap()
            .len(),
        3
    );

    assert_eq!(
        batch::finalize(&s, &seed, &layout, &response[1..]).err(),
        Some(BatchError::ResponseLength)
    );
    assert_eq!(
        batch::finalize(&s, &seed, &layout, &[]).err(),
        Some(BatchError::ResponseLength)
    );
    for j in 0..3 {
        let mut bad = response.clone();
        bad[j * AUTHENTICATOR_LEN + 7] ^= 0x01;
        assert_eq!(
            batch::finalize(&s, &seed, &layout, &bad).err(),
            Some(BatchError::BlindSignature),
            "position {j}"
        );
    }
    // Signatures for another seed's blinded messages, or in another order, do not finalize.
    assert_eq!(
        batch::finalize(&s, &[8u8; 32], &layout, &response).err(),
        Some(BatchError::BlindSignature)
    );
    let mut swapped = response[AUTHENTICATOR_LEN..2 * AUTHENTICATOR_LEN].to_vec();
    swapped.extend_from_slice(&response[..AUTHENTICATOR_LEN]);
    swapped.extend_from_slice(&response[2 * AUTHENTICATOR_LEN..]);
    assert_eq!(
        batch::finalize(&s, &seed, &layout, &swapped).err(),
        Some(BatchError::BlindSignature)
    );
    // A signature under the right key of B' for another position: s'^e != B.
    let other = batch::blind(&s, &[8u8; 32], &layout).unwrap();
    let other_sig = sign(&s, &layout, &other);
    let mut mixed = response.clone();
    mixed[..AUTHENTICATOR_LEN].copy_from_slice(&other_sig[..AUTHENTICATOR_LEN]);
    assert_eq!(
        batch::finalize(&s, &seed, &layout, &mixed).err(),
        Some(BatchError::BlindSignature)
    );
}

#[test]
fn layouts_refuse_what_the_schedule_does_not_cover() {
    let s = fixture::schedule();
    let last = s.last_access_week();
    // Past the last covered week the slots are still open-ended, but the week's key is missing.
    assert_eq!(
        Layout::pack(&s, last - 3, true).err(),
        Some(BatchError::MissingKey)
    );
    assert_eq!(Layout::trial(&s, last).err(), Some(BatchError::MissingKey));
    // Before the first covered week no slot is valid.
    assert_eq!(
        Layout::pack(&s, FIRST_WEEK - 1, true).err(),
        Some(BatchError::Layout)
    );
    assert!(Layout::pack(&s, last - 4, true).is_ok());
    assert_eq!(
        Layout::pack(&s, u64::MAX - 2, true).err(),
        Some(BatchError::Layout)
    );
    let missing = vec![Position {
        kind: Kind::Credit,
        epoch: 9_999,
        slot: None,
    }];
    assert_eq!(
        Layout::from_positions(&s, missing).err(),
        Some(BatchError::MissingKey)
    );
    let bad_slot = vec![Position {
        kind: Kind::Access,
        epoch: FIRST_WEEK,
        slot: Some(3),
    }];
    assert_eq!(
        Layout::from_positions(&s, bad_slot).err(),
        Some(BatchError::Layout)
    );
    let slotted_invite = vec![Position {
        kind: Kind::Invite,
        epoch: invite_epoch(FIRST_WEEK),
        slot: Some(0),
    }];
    assert_eq!(
        Layout::from_positions(&s, slotted_invite).err(),
        Some(BatchError::Layout)
    );
    assert_eq!(
        Layout::from_positions(&s, Vec::new()).err(),
        Some(BatchError::Layout)
    );
    let layout = small_layout(&s);
    assert_eq!(
        layout.check_digest(&[0; 32]).err(),
        Some(BatchError::LayoutDigest)
    );
    layout.check_digest(&layout.digest()).unwrap();
}

#[test]
fn verify_token_refuses_wrong_kind_slot_key_and_signature() {
    let s = fixture::schedule();
    let layout = small_layout(&s);
    let seed = [5u8; 32];
    let request = batch::blind(&s, &seed, &layout).unwrap();
    let tokens = batch::finalize(&s, &seed, &layout, &sign(&s, &layout, &request)).unwrap();
    let (access, invite, credit) = (&tokens[0], &tokens[1], &tokens[2]);

    let ok = s.verify_token(access, Expect::AccessAtSlot(1)).unwrap();
    assert_eq!(
        (ok.kind, ok.epoch, ok.slot),
        (Kind::Access, FIRST_WEEK, Some(1))
    );
    assert_eq!(ok.nullifier, access.nullifier());
    assert_eq!(
        s.verify_token(access, Expect::AccessAnySlot).unwrap().slot,
        Some(1)
    );
    assert!(s.verify_token(invite, Expect::Invite).is_ok());
    assert!(s.verify_token(credit, Expect::Credit).is_ok());

    // "rejected_token" reasons: another relay's slot, a slot not in the week, another kind.
    assert_eq!(
        s.verify_token(access, Expect::AccessAtSlot(0)).err(),
        Some(TokenError::Challenge)
    );
    assert_eq!(
        s.verify_token(access, Expect::AccessAtSlot(7)).err(),
        Some(TokenError::WrongSlot)
    );
    assert_eq!(
        s.verify_token(access, Expect::Invite).err(),
        Some(TokenError::WrongKind)
    );
    assert_eq!(
        s.verify_token(invite, Expect::Credit).err(),
        Some(TokenError::WrongKind)
    );
    assert_eq!(
        s.verify_token(credit, Expect::AccessAnySlot).err(),
        Some(TokenError::WrongKind)
    );

    // Forged: every byte of every field flipped in turn (bytes 0-1, the type, fail at parse).
    for i in 0..access.as_bytes().len() {
        let mut bytes = *access.as_bytes();
        bytes[i] ^= 0x01;
        let Ok(forged) = Token::parse(&bytes) else {
            assert!(i < 2, "byte {i} must not fail at parse");
            continue;
        };
        let expected = match i {
            66..=97 => TokenError::UnknownKey,
            34..=65 => TokenError::Challenge,
            _ => TokenError::Signature,
        };
        assert_eq!(
            s.verify_token(&forged, Expect::AccessAtSlot(1)).err(),
            Some(expected),
            "byte {i}"
        );
    }

    // A revoked (kind, epoch) is refused even with a valid signature.
    let mut content = s.content().clone();
    content.revoked.push((Kind::Access, FIRST_WEEK));
    let key = fixture::schedule_signing_key();
    use ed25519_dalek::Signer as _;
    let bytes = content
        .to_signed_bytes(&key.sign(&content.signing_message().unwrap()).to_bytes())
        .unwrap();
    let revoked = Schedule::verify_with_key(&bytes, &key.verifying_key().to_bytes()).unwrap();
    assert_eq!(
        revoked.verify_token(access, Expect::AccessAtSlot(1)).err(),
        Some(TokenError::Revoked)
    );
    assert!(revoked.verify_token(invite, Expect::Invite).is_ok());
}
