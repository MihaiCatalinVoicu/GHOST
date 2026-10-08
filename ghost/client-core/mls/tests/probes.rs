//! The test-only native builders the Kotlin suites drive through `MlsVectors.run` (F-S4-6, MM-30
//! and MM-46 / SCN-CM's lifetime cases; §19.37 row 39; MM-31 / §19.14's NEW_SIGNER): a real MLS
//! proposal by a member, a commit carrying a finite-lifetime (expired, non-canonical) KeyPackage,
//! and a commit whose update-path leaf carries a mismatched credential. Compiled only with the
//! `test-vectors` feature (the host library); shipped libraries export neither.
#![cfg(feature = "test-vectors")]

mod support;

use std::time::{SystemTime, UNIX_EPOCH};

use ghost_client_mls::group::ReceiveItem;
use ghost_client_mls::kv::WrappedRows;
use ghost_client_mls::{Code, CommitReason};
use support::*;

fn host_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[test]
fn a_member_builds_a_real_proposal_and_others_drop_it_by_the_header() {
    let mut w = World::create(1, 0);
    w.admit(1);
    let epoch = w.members[1].epoch.as_ref().unwrap().epoch;

    // The proposal is a real MLS handshake message: signed and encrypted by the member.
    let m = &w.members[1];
    let rows = m.wrapped();
    let proposal = m
        .ctx
        .test_proposal(&m.ch, &WrappedRows(&rows), DAY)
        .unwrap();

    // A receiver classifies it by its header and drops it unprocessed (§6.3.2) — F-S4-6's entry.
    let r = &mut w.members[0];
    let rows = r.wrapped();
    let out = r
        .ctx
        .receive(&r.ch, &WrappedRows(&rows), epoch, &[proposal], DAY)
        .unwrap();
    assert!(
        matches!(&out.items[0], ReceiveItem::Proposal),
        "a real proposal, dropped by its header: {:?}",
        out.items[0]
    );
    assert!(out.changes.is_empty(), "a dropped proposal writes nothing");

    // The builder persisted nothing: the author still posts and the receiver still opens it.
    let post = w.post(1, &post_content_probe());
    let r = &mut w.members[0];
    let rows = r.wrapped();
    let out = r
        .ctx
        .receive(&r.ch, &WrappedRows(&rows), epoch, &[post], DAY)
        .unwrap();
    assert!(matches!(&out.items[0], ReceiveItem::App { .. }));
}

#[test]
fn a_member_builds_a_commit_with_an_expired_finite_lifetime_key_package() {
    let mut w = World::create(1, 0);
    w.admit(1);
    let epoch = w.members[0].epoch.as_ref().unwrap().epoch;

    // Valid at the build (OpenMLS validates the Add then), expired by the receive: E-70's case,
    // refused on OpenMLS's refusal branch at every member.
    let now = host_secs();
    let m = &w.members[1];
    let rows = m.wrapped();
    let (kp, commit) = m
        .ctx
        .test_finite_lifetime_commit(&m.ch, &WrappedRows(&rows), DAY, now - 7200, now + 2)
        .unwrap();
    std::thread::sleep(std::time::Duration::from_secs(3));

    // The KeyPackage is non-canonical: GHOST's own parse refuses it (the constant form, §19.29.1).
    assert!(ghost_client_mls::canonical::parse_key_package(
        m.ctx.crypto(),
        &kp,
        Some(&w.channel_id)
    )
    .is_err());

    // Every receiver answers INVALID_COMMIT(lifetime) — MM-46's case — and merges nothing.
    let r = &mut w.members[0];
    let rows = r.wrapped();
    let out = r
        .ctx
        .receive(&r.ch, &WrappedRows(&rows), epoch, &[commit], DAY)
        .unwrap();
    match &out.items[0] {
        ReceiveItem::Failed(e) => {
            assert_eq!(e.code, Code::InvalidCommit);
            assert_eq!(
                e.detail,
                ghost_client_mls::result::Detail::Reason(CommitReason::Lifetime)
            );
        }
        other => panic!("expected INVALID_COMMIT(lifetime), got {other:?}"),
    }
    assert!(out.changes.is_empty());
}

#[test]
fn a_member_builds_a_new_signer_commit_and_every_member_refuses_it() {
    let mut w = World::create(1, 0);
    w.admit(1);
    let epoch = w.members[0].epoch.as_ref().unwrap().epoch;

    // NEW_SIGNER (MM-31, §19.14): the member's own commit, every MLS check passing, but the
    // update-path leaf's credential names another identity than the leaf's signature key.
    let wrong = [0x5Au8; 32];
    let m = &w.members[1];
    let rows = m.wrapped();
    let commit = m
        .ctx
        .test_new_signer(&m.ch, &WrappedRows(&rows), DAY, wrong)
        .unwrap();

    // Every other member answers INVALID_COMMIT(continuity), merging nothing (MM-31). (At the
    // author the blob is its own message and `receive` reports it `OwnPrivateMessage` — §19.13 —
    // which is why the engine's own-candidate path validates the build natively instead.)
    let r = &mut w.members[0];
    let rows = r.wrapped();
    let out = r
        .ctx
        .receive(&r.ch, &WrappedRows(&rows), epoch, &[commit], DAY)
        .unwrap();
    match &out.items[0] {
        ReceiveItem::Commit(s) => {
            assert_eq!(s.verdict, Err(CommitReason::Continuity));
        }
        other => panic!("expected INVALID_COMMIT(continuity), got {other:?}"),
    }
    assert!(out.changes.is_empty());
}

fn post_content_probe() -> Vec<u8> {
    ghost_client_mls::content::ChannelContent {
        kind: ghost_client_mls::content::KIND_POST,
        op_id: [7; 16],
        author_minute: minute(DAY),
        timer_code: 4,
        body: ghost_client_mls::content::Body::Post {
            text: "after the proposal".into(),
            reply_to: None,
        },
    }
    .encode()
    .unwrap()
}
