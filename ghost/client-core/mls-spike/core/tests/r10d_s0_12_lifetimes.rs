//! Round 10d, targeted protocol review of S0-12 (design §19.27, findings TR-1 … TR-3): what a
//! member can and cannot learn when OpenMLS 0.9.0 refuses a received commit for a KeyPackage
//! lifetime, and whether a constant lifetime `[0, 2^64 − 1]` takes OpenMLS's device-clock site out
//! of commit validity.
//!
//! Run: `cargo test --release -p ghost-mls-spike --test r10d_s0_12_lifetimes -- --nocapture --test-threads=1`

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ghost_mls_spike::ext::{self, CommitAad};
use ghost_mls_spike::harness::*;
use openmls::prelude::*;

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// The constant lifetime the review proposes for every canonical KeyPackage (TR-3).
fn constant() -> Lifetime {
    Lifetime::init(0, u64::MAX)
}

/// A KeyPackage object built by `dev` itself (as a modified client or a joiner would), without a
/// committer's `KeyPackageIn::validate`; the commit builder takes it as it is.
fn own_key_package(dev: &mut Device, ch: [u8; 32], lifetime: Lifetime, day: u32) -> KeyPackage {
    let box_pk = [7u8; 32];
    let cred = dev.credential();
    dev.call(&ch, |p, s| {
        KeyPackage::builder()
            .key_package_lifetime(lifetime)
            .leaf_node_capabilities(ghost_capabilities(SUITE, 0))
            .leaf_node_extensions(leaf_extensions(&box_pk, 0))
            .key_package_extensions(
                Extensions::single(Extension::Unknown(
                    ext::EXT_KP_BIND,
                    UnknownExtension(ext::kp_bind(&ch, 1, day)),
                ))
                .map_err(|e| format!("{e:?}"))?,
            )
            .build(SUITE, p, s, cred)
            .map(|b| b.key_package().clone())
            .map_err(|e| format!("{e:?}"))
    })
    .expect("KeyPackage builds")
}

fn add_spec(kps: Vec<KeyPackage>, epoch: u64, day: u32) -> CommitSpec {
    CommitSpec {
        adds: kps,
        aad: CommitAad {
            commit_minute: day * 1440,
            ..Default::default()
        },
        refresh_epoch: Some(epoch),
        force_path: true,
        no_exported_group_info: true,
        ..Default::default()
    }
}

/// TR-1: a commit that a non-committer (GHOST rank 255) makes with an Add. While the KeyPackage is
/// valid on the receiver's clock, OpenMLS stages it and the receiver sees the sender and the Add, so
/// CO-1 ("a rank-255 commit is valid only if it covers no proposal") refuses it. Once the KeyPackage
/// has expired on the receiver's clock, `process_message` returns only a lifetime error: no sender,
/// no proposal list, and only the first failing KeyPackage's bound. The receiver can compute
/// neither the candidate's rank nor CO-1, nor evaluate a predicate over "every KeyPackage".
#[test]
fn r10d_refusal_branch_hides_sender_and_proposals() {
    let day = host_day();
    let mut w = World::build(3, 2, day);
    let ch = w.channel;
    let owner_leaf = w.members[0].leaf_index(ch);
    let attacker_leaf = w.members[2].leaf_index(ch);
    let mut j1 = Device::new(51, day);
    let mut j2 = Device::new(52, day);
    let t = now();
    // Two KeyPackages built by the joiners: the first valid for 3 more seconds, the second for 6.
    let kp1 = own_key_package(&mut j1, ch, Lifetime::init(t - 3600, t + 3), day);
    let kp2 = own_key_package(&mut j2, ch, Lifetime::init(t - 3600, t + 6), day);
    let na1 = kp1.life_time().not_after();
    let na2 = kp2.life_time().not_after();
    let e = w.members[2].epoch(ch);
    let c = w.members[2]
        .commit(ch, &add_spec(vec![kp1, kp2], e, day))
        .expect("the non-committer's client builds the commit");
    w.members[2].clear_own(ch).unwrap();

    // Before expiry: staged; the sender and both Adds are visible.
    let before = w.members[1].validate(ch, &c.commit).map(|x| x.0);
    let r = before.expect("valid on the receiver's clock before expiry");
    println!(
        "R10d TR-1 before expiry: kind {} sender leaf {:?} (owner is leaf {owner_leaf}, attacker leaf {attacker_leaf}), adds {}",
        r.kind, r.sender, r.adds
    );
    assert_eq!(r.kind, "commit");
    assert_eq!(r.sender, Some(attacker_leaf));
    assert_eq!(r.adds, 2);

    // After both expired: only an error, naming one bound.
    std::thread::sleep(Duration::from_secs(8));
    let after = w.members[1].validate(ch, &c.commit).map(|x| x.0.kind);
    let err = after.expect_err("refused on the receiver's clock after expiry");
    println!("R10d TR-1 after expiry: process_message -> Err({err})");
    assert!(
        err.contains("KeyPackageVerifyError(LifetimeError(Expired"),
        "{err}"
    );
    assert!(
        err.contains(&format!("not_after: {na1}")),
        "the error names the first failing KeyPackage: {err}"
    );
    assert!(
        !err.contains(&format!("not_after: {na2}")),
        "and only that one: {err}"
    );
    assert!(
        !err.contains("Member(") && !err.contains("LeafNodeIndex"),
        "no sender in the error: {err}"
    );
    println!(
        "R10d TR-1 the error carries one not_after ({na1}) of two Adds (the second: {na2}), and no sender; \
         MlsGroup::unprotect_message, PublicGroup::parse_message and UnverifiedMessage::verify are pub(crate)"
    );
}

/// TR-3: the constant lifetime is a canonical KeyPackage of the same size (395 B), is accepted by a
/// committer's `KeyPackageIn::validate`, by every receiver of the Add at any later time, and by the
/// default `JoinBuilder` (lifetime verification on) over a tree whose KeyPackage leaves carry it,
/// including the creator's own leaf. A finite lifetime, by contrast, is refused once expired (the
/// V10-11 (b) outcome, re-run here next to it).
#[test]
fn r10d_constant_lifetime_is_never_refused() {
    let day = host_day();
    // The creator's own leaf with the constant lifetime.
    let mut owner = Device::new(0, day);
    let ch: [u8; 32] = [0x42; 32];
    let ctx = ext::ChannelContext::initial(ch, owner.pk, 0);
    let box_pk = [3u8; 32];
    let cred = owner.credential();
    owner
        .call(&ch, |p, s| {
            MlsGroup::builder()
                .with_group_id(GroupId::from_slice(&ch))
                .ciphersuite(SUITE)
                .padding_size(0)
                .use_ratchet_tree_extension(true)
                .sender_ratchet_configuration(SenderRatchetConfiguration::new(16, 1000))
                .max_past_epochs(16)
                .lifetime(constant())
                .with_capabilities(ghost_capabilities(SUITE, 0))
                .with_group_context_extensions(context_extensions(&ctx))
                .with_leaf_node_extensions(leaf_extensions(&box_pk, 0))
                .map_err(|e| format!("{e:?}"))?
                .build(p, s, cred)
                .map(|_| ())
                .map_err(|e| format!("{e:?}"))
        })
        .expect("a group whose creator leaf has the constant lifetime");
    let mut w = World {
        channel: ch,
        members: vec![owner],
        day,
    };

    let mut members_kp_sizes = Vec::new();
    for id in 1..=3usize {
        let mut j = Device::new(id, day);
        let bytes = j
            .key_package_with(ch, 1, constant(), day, 0, 0)
            .expect("constant-lifetime KeyPackage");
        members_kp_sizes.push(bytes.len());
        let kp = w.members[0]
            .parse_key_package(&bytes)
            .expect("the committer's KeyPackageIn::validate accepts it");
        let e = w.members[0].epoch(ch);
        let out = w
            .commit_and_merge(0, &add_spec(vec![kp], e, day))
            .expect("the Add commit is processed by every member");
        // The default JoinBuilder (no skip_lifetime_validation): every KeyPackage leaf of the tree,
        // the creator's included, carries the constant lifetime.
        j.join(ch, out.welcome.as_ref().unwrap(), false)
            .expect("default JoinBuilder joins");
        w.members.push(j);
    }
    assert!(w.authenticators_agree());
    assert!(
        members_kp_sizes.iter().all(|&n| n == 395),
        "{members_kp_sizes:?}"
    );
    println!(
        "R10d TR-3 constant lifetime [0, 2^64-1]: KeyPackage {members_kp_sizes:?} B (the canonical 395); committer parse, receivers and the default JoinBuilder accept; 4 members, equal epoch authenticators"
    );

    // Received later: an Add of a constant-lifetime KeyPackage and, beside it, one whose finite
    // lifetime expires in 3 seconds. After 5 seconds the first still validates, the second does not.
    let mut jc = Device::new(20, day);
    let mut jf = Device::new(21, day);
    let t = now();
    let kpc = own_key_package(&mut jc, ch, constant(), day);
    let kpf = own_key_package(&mut jf, ch, Lifetime::init(t - 3600, t + 3), day);
    let e = w.members[0].epoch(ch);
    let cc = w.members[0]
        .commit(ch, &add_spec(vec![kpc], e, day))
        .unwrap();
    w.members[0].clear_own(ch).unwrap();
    let cf = w.members[0]
        .commit(ch, &add_spec(vec![kpf], e, day))
        .unwrap();
    w.members[0].clear_own(ch).unwrap();
    std::thread::sleep(Duration::from_secs(5));
    let rc = w.members[1].validate(ch, &cc.commit).map(|x| x.0.kind);
    let rf = w.members[1].validate(ch, &cf.commit).map(|x| x.0.kind);
    println!("R10d TR-3 5 s later: constant-lifetime Add -> {rc:?}; finite-lifetime Add (expired) -> {rf:?}");
    assert_eq!(rc, Ok("commit"));
    assert!(rf.unwrap_err().contains("LifetimeError(Expired"));
}
