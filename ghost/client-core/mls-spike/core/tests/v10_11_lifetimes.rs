//! V10-11: OpenMLS's wall-clock lifetime sites against the anchored virtual time of design §12.1:
//! a KeyPackage from each end of a world's day range accepted on the host clock; how a lifetime
//! failure of a received Add surfaces (can GHOST map it to `LIFETIME_PENDING`, CO-2); whether a
//! lifetime failure is reported before or instead of other defects of the same commit; joins with
//! an expired never-updated leaf; and the lifetime span, which OpenMLS never checks.
//!
//! Run: `cargo test --release -p ghost-mls-spike --test v10_11_lifetimes -- --nocapture --test-threads=1`

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ghost_mls_spike::ext::CommitAad;
use ghost_mls_spike::harness::*;
use openmls::prelude::*;

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[test]
fn v10_11_world_range_on_the_host_clock() {
    let host = host_day();
    let w = World::build(2, 1, host);
    let ch = w.channel;
    let committer = w.members.into_iter().next().unwrap();
    // §12.1: a world's first virtual day ≥ host − 79 and last ≤ host + 3.
    for d in [
        host - 81,
        host - 80,
        host - 79,
        host - 1,
        host,
        host + 1,
        host + 3,
        host + 4,
        host + 5,
        host + 6,
    ] {
        let mut j = Device::new(1, d);
        let kp = j.key_package(ch, 1, d, 0).unwrap();
        let r = committer.parse_key_package(&kp);
        let off = d as i64 - host as i64;
        let got = r.map(|_| "accepted".to_string()).unwrap_or_else(|e| e);
        println!(
            "V10-11 KeyPackage made on virtual day host{off:+} (lifetime [d−4, d+80]): committer's KeyPackageIn::validate -> {got}"
        );
        // §12.1's range: accepted from host − 79 to host + 4, whatever the hour of the host day.
        match off {
            -79..=4 => assert_eq!(got, "accepted", "host{off:+}"),
            o if o < -79 => assert!(got.contains("LifetimeError(Expired"), "host{off:+}: {got}"),
            _ => assert!(
                got.contains("LifetimeError(NotValidYet"),
                "host{off:+}: {got}"
            ),
        }
    }
}

/// A KeyPackage whose lifetime ends `secs` seconds from now.
fn short_kp(j: &mut Device, ch: [u8; 32], secs: u64) -> Vec<u8> {
    let t = now();
    j.key_package_with(ch, 1, Lifetime::init(t - 3600, t + secs), host_day(), 0, 0)
        .unwrap()
}

#[test]
fn v10_11_received_add_lifetime_failure_and_ordering() {
    let day = host_day();
    let mut w = World::build(3, 2, day);
    let ch = w.channel;

    // (a) An Add admitted while valid and received after expiry.
    let mut j = Device::new(10, day);
    let kp = short_kp(&mut j, ch, 3);
    let kp = w.members[0]
        .parse_key_package(&kp)
        .expect("valid at admission");
    let e = w.members[0].epoch(ch);
    let spec = CommitSpec {
        adds: vec![kp.clone()],
        aad: CommitAad {
            commit_minute: day * 1440,
            ..Default::default()
        },
        refresh_epoch: Some(e),
        force_path: true,
        ..Default::default()
    };
    let good = w.members[0].commit(ch, &spec).unwrap();
    w.members[0].clear_own(ch).unwrap();
    // (b) The same Add with the commit's framed-content signature corrupted (signature #2 of the
    // build: #1 is the update-path leaf, #2 the FramedContent, #3 the Welcome's GroupInfo).
    let mut bad_sig = Vec::new();
    for n in [1u32, 2] {
        w.members[0].signer.corrupt_nth.set(n);
        let c = w.members[0].commit(ch, &spec).unwrap();
        w.members[0].signer.corrupt_nth.set(0);
        w.members[0].clear_own(ch).unwrap();
        bad_sig.push((n, c.commit));
    }
    // Before expiry: the valid commit validates; the corrupted ones are refused for their defect.
    let r = w.members[1].validate(ch, &good.commit).map(|x| x.0.kind);
    println!("V10-11 before expiry: valid Add commit -> {r:?}");
    assert_eq!(r, Ok("commit"));
    for (n, c) in &bad_sig {
        let got = w.members[1].validate(ch, c).map(|x| x.0.kind);
        println!("V10-11 before expiry: signature #{n} corrupted -> {got:?}");
        let e = got.unwrap_err();
        match n {
            1 => assert!(e.contains("UpdatePathError(SignatureError"), "{e}"),
            _ => assert!(e.contains("InvalidSignature"), "{e}"),
        }
    }
    std::thread::sleep(Duration::from_secs(5));
    let r = w.members[1].validate(ch, &good.commit);
    println!(
        "V10-11 after expiry: valid Add commit -> {:?}",
        r.as_ref().map(|x| x.0.kind)
    );
    let expired = r.map(|x| x.0.kind).unwrap_err();
    assert!(
        expired.contains("KeyPackageVerifyError(LifetimeError(Expired"),
        "{expired}"
    );
    for (n, c) in &bad_sig {
        let got = w.members[1].validate(ch, c).map(|x| x.0.kind);
        println!("V10-11 after expiry: signature #{n} corrupted AND expired KeyPackage -> {got:?}");
        let e = got.unwrap_err();
        match n {
            // The lifetime refusal masks the corrupted update-path signature (S0-12).
            1 => assert!(e.contains("LifetimeError(Expired"), "{e}"),
            // The framed-content signature is checked before the KeyPackages.
            _ => assert!(e.contains("InvalidSignature"), "{e}"),
        }
    }

    // (c) Not yet valid (the receiver's clock behind the committer's): lifetime starting in 1 h.
    let mut j2 = Device::new(11, day);
    let t = now();
    let kp_future = j2
        .key_package_with(ch, 1, Lifetime::init(t + 3600, t + 7200), day, 0, 0)
        .unwrap();
    let future = w.members[0].parse_key_package(&kp_future).map(|_| ());
    println!("V10-11 committer parse of a KeyPackage valid only from now+1 h -> {future:?}");
    assert!(future.unwrap_err().contains("LifetimeError(NotValidYet"));

    // (d) OpenMLS never checks the span: a 100-year lifetime is accepted.
    let mut j3 = Device::new(12, day);
    let kp_long = j3
        .key_package_with(
            ch,
            1,
            Lifetime::init(t - 3600, t + 100 * 365 * 86_400),
            day,
            0,
            0,
        )
        .unwrap();
    let parsed = w.members[0].parse_key_package(&kp_long);
    println!(
        "V10-11 KeyPackage with a 100-year lifetime -> committer parse {:?}",
        parsed.as_ref().map(|_| "accepted")
    );
    let kp = parsed.expect("OpenMLS never checks the lifetime span");
    let e = w.members[0].epoch(ch);
    let s = CommitSpec {
        adds: vec![kp],
        refresh_epoch: Some(e),
        force_path: true,
        ..Default::default()
    };
    let c = w.members[0].commit(ch, &s).unwrap();
    let at_receiver = w.members[1].validate(ch, &c.commit).map(|x| x.0.kind);
    println!("V10-11   its Add commit at a receiver -> {at_receiver:?}");
    assert_eq!(at_receiver, Ok("commit"));
    w.members[0].clear_own(ch).unwrap();
}

#[test]
fn v10_11_join_with_an_expired_leaf() {
    let day = host_day();
    let mut w = World::build(2, 1, day);
    let ch = w.channel;
    // A member admitted with a KeyPackage that expires in 3 s and never updates.
    let mut short = Device::new(20, day);
    let kp = short_kp(&mut short, ch, 3);
    let kp = w.members[0].parse_key_package(&kp).unwrap();
    let e = w.members[0].epoch(ch);
    let out = w
        .commit_and_merge(
            0,
            &CommitSpec {
                adds: vec![kp],
                refresh_epoch: Some(e),
                force_path: true,
                ..Default::default()
            },
        )
        .unwrap();
    short.join(ch, out.welcome.as_ref().unwrap(), true).unwrap();
    w.members.push(short);
    std::thread::sleep(Duration::from_secs(5));
    // A later joiner: its Welcome's tree holds the expired leaf.
    let mut late = Device::new(21, day);
    let kp = late.key_package(ch, 1, day, 0).unwrap();
    let kp = w.members[0].parse_key_package(&kp).unwrap();
    let e = w.members[0].epoch(ch);
    let out = w.members[0]
        .commit(
            ch,
            &CommitSpec {
                adds: vec![kp],
                refresh_epoch: Some(e),
                force_path: true,
                ..Default::default()
            },
        )
        .unwrap();
    let welcome = out.welcome.unwrap();
    let saved = late.rows.clone();
    let strict = late.join(ch, &welcome, false);
    late.rows = saved;
    let skip = late.join(ch, &welcome, true);
    let strict = strict.map(|_| "joined");
    let skip = skip.map(|_| "joined");
    println!(
        "V10-11 join over a tree with an expired never-updated leaf: default JoinBuilder -> {strict:?}"
    );
    println!("V10-11 join over the same Welcome with skip_lifetime_validation() -> {skip:?}");
    assert!(strict
        .unwrap_err()
        .contains("LeafNodeValidation(Lifetime(Expired"));
    assert_eq!(skip, Ok("joined"));
    // And the existing members process that commit (the expired leaf is not re-validated).
    let existing = w.members[1].validate(ch, &out.commit).map(|x| x.0.kind);
    println!(
        "V10-11 existing member processes the commit whose tree holds the expired leaf -> {existing:?}"
    );
    assert_eq!(existing, Ok("commit"));
}
