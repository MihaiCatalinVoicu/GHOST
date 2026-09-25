//! V10-10: host timings of the native calls at 20 and 100 members, under value semantics (every
//! call loads the channel's rows, runs, and returns its change-set; wrapping measured), 2 retained
//! past epochs (the default retention of §8.3 in a quiet channel). Each operation is repeated on
//! the same state (dry calls restore the rows), 15 times; the table prints min / median / max.
//!
//! Run: `cargo test --release -p ghost-mls-spike --test v10_10_timings -- --nocapture --test-threads=1`

use std::time::Instant;

use ghost_mls_spike::ext::{AdmitEvidence, CommitAad};
use ghost_mls_spike::harness::*;
use openmls::prelude::*;

const REPS: usize = 15;

fn stats(mut v: Vec<u128>) -> (u128, u128, u128) {
    v.sort_unstable();
    (v[0], v[v.len() / 2], v[v.len() - 1])
}

fn line(tag: &str, v: Vec<u128>) {
    let (a, m, b) = stats(v);
    println!(
        "V10-10 {tag:<60} min {:>8.2} ms  median {:>8.2} ms  max {:>8.2} ms",
        a as f64 / 1000.0,
        m as f64 / 1000.0,
        b as f64 / 1000.0
    );
}

fn timed<F: FnMut()>(mut f: F) -> Vec<u128> {
    (0..REPS)
        .map(|_| {
            let t = Instant::now();
            f();
            t.elapsed().as_micros()
        })
        .collect()
}

fn run(n: usize, populated: bool) {
    let day = host_day();
    let t = Instant::now();
    let mut w = World::build(n, n - 1, day);
    if populated {
        w.populate();
    }
    let ch = w.channel;
    let shape = if populated { "populated" } else { "blank" };
    println!(
        "V10-10 world n={n} {shape} built in {:.1} s",
        t.elapsed().as_secs_f64()
    );
    // Two retained past epochs at the measured members (0 = committer, 1 = receiver).
    for _ in 0..2 {
        let e = w.members[0].epoch(ch);
        let s = CommitSpec {
            refresh_epoch: Some(e),
            force_path: true,
            no_exported_group_info: true,
            ..Default::default()
        };
        let out = w.members[0].commit(ch, &s).unwrap();
        w.members[1].receive(ch, &out.commit).unwrap();
        w.members[0].merge_own(ch).unwrap();
    }
    // Retention as §8.3 would leave it in a quiet channel: 2 past epochs at both measured members.
    w.members[0].sweep_past(ch, 2).unwrap();
    w.members[1].sweep_past(ch, 2).unwrap();
    w.members[1].wrap_key = Some([0x42; 32]);
    w.members[0].wrap_key = Some([0x42; 32]);
    let tag = |s: &str| format!("n={n} {shape} {s}");

    // KeyPackage creation (a joiner's device).
    let mut j = Device::new(500, day);
    line(
        &tag("keyPackage (new device)"),
        timed(|| {
            let saved = j.rows.clone();
            j.key_package(ch, 1, day, 0).unwrap();
            j.rows = saved;
        }),
    );
    // Committer: an empty PCS commit with path; an Add with evidence; a Remove.
    let e = w.members[0].epoch(ch);
    let pcs = CommitSpec {
        aad: CommitAad {
            commit_minute: day * 1440,
            ..Default::default()
        },
        refresh_epoch: Some(e),
        force_path: true,
        no_exported_group_info: true,
        ..Default::default()
    };
    line(
        &tag("commit: PCS self-update (build, dry)"),
        timed(|| {
            let saved = w.members[0].rows.clone();
            w.members[0].commit(ch, &pcs).unwrap();
            w.members[0].rows = saved;
        }),
    );
    let kp_bytes = j.key_package(ch, 1, day, 0).unwrap();
    let kp = w.members[0].parse_key_package(&kp_bytes).unwrap();
    let r = kp
        .hash_ref(&w.members[0].crypto)
        .unwrap()
        .as_slice()
        .to_vec();
    let add = CommitSpec {
        adds: vec![kp],
        aad: CommitAad {
            commit_minute: day * 1440,
            admits: vec![AdmitEvidence::filler(r)],
            ..Default::default()
        },
        refresh_epoch: Some(e),
        force_path: true,
        no_exported_group_info: true,
        ..Default::default()
    };
    line(
        &tag("commit: Add 1 + Welcome (build, dry)"),
        timed(|| {
            let saved = w.members[0].rows.clone();
            w.members[0].commit(ch, &add).unwrap();
            w.members[0].rows = saved;
        }),
    );
    let far_leaf = w.members[n - 1].leaf_index(ch);
    let rem = CommitSpec {
        removes: vec![LeafNodeIndex::new(far_leaf)],
        ..pcs.clone()
    };
    line(
        &tag("commit: Remove 1 (build, dry)"),
        timed(|| {
            let saved = w.members[0].rows.clone();
            w.members[0].commit(ch, &rem).unwrap();
            w.members[0].rows = saved;
        }),
    );
    // Receiver: the validation run, the settle, a trial settle (both dry).
    let saved0 = w.members[0].rows.clone();
    let out = w.members[0].commit(ch, &add).unwrap();
    w.members[0].rows = saved0;
    line(
        &tag("receive commit: validation run (CO-2, dry)"),
        timed(|| {
            w.members[1].validate(ch, &out.commit).unwrap();
        }),
    );
    line(
        &tag("settle: process + merge (dry)"),
        timed(|| {
            let saved = w.members[1].rows.clone();
            w.members[1].receive(ch, &out.commit).unwrap();
            w.members[1].rows = saved;
        }),
    );
    // The joiner's welcomeJoin (dry).
    line(
        &tag("welcomeJoin (1 joiner, tree in the Welcome)"),
        timed(|| {
            let saved = j.rows.clone();
            let _ = j.join(ch, out.welcome.as_ref().unwrap(), true);
            j.rows = saved;
        }),
    );
    // Posts.
    let post = w.members[0].encrypt(ch, 1, &[0x55; 1000]).unwrap();
    line(
        &tag("encrypt post (1 000 B, dry)"),
        timed(|| {
            let saved = w.members[0].rows.clone();
            w.members[0].encrypt(ch, 2, &[0x55; 1000]).unwrap();
            w.members[0].rows = saved;
        }),
    );
    line(
        &tag("decrypt post (1 000 B, dry)"),
        timed(|| {
            let saved = w.members[1].rows.clone();
            w.members[1].receive(ch, &post).unwrap();
            w.members[1].rows = saved;
        }),
    );
    line(
        &tag("export_secret (load + exporter)"),
        timed(|| {
            w.members[1].export(ch, "ghost/v1/ch/epoch");
        }),
    );
}

#[test]
fn v10_10_timings_20() {
    let _ = ghost_mls_spike::pin_rayon_single_worker();
    run(20, false);
    run(20, true);
}

#[test]
fn v10_10_timings_100() {
    let _ = ghost_mls_spike::pin_rayon_single_worker();
    run(100, false);
}
