//! V10-4: commit and Welcome sizes with GHOST's extensions and `GhostCommitAad` at the class caps
//! (32 members, 4 KiB floor; 100 members, 16 KiB floor), including §5.7's composite worst cases.
//!
//! Every probe commit is built by a real member with GHOST's configuration (forced path with a
//! `GhostLeaf` update leaf, proposals by value, the AAD of §19.2 with evidence of the right size),
//! validated by another member (a dry `process_message`), and then dropped, so the world stays put.
//! Sizes are the `MlsMessageOut` bytes the seal carries as its body; `C(B) = B − 68`.
//!
//! Run: `cargo test --release -p ghost-mls-spike --test v10_04_sizes -- --nocapture --test-threads=1`

use ghost_mls_spike::ext::{AdmitEvidence, ChannelContext, CommitAad, SwapEvidence};
use ghost_mls_spike::harness::*;
use ghost_mls_spike::seal;
use openmls::prelude::*;

struct Probe {
    commit: usize,
    welcome: Option<usize>,
    valid: Result<(), String>,
}

/// Builds `spec` at `by`, validates it at `check`, restores both.
fn probe(w: &mut World, by: usize, check: usize, spec: &CommitSpec) -> Probe {
    let ch = w.channel;
    let saved = w.members[by].rows.clone();
    let out = w.members[by].commit(ch, spec).expect("probe commit builds");
    w.members[by].rows = saved;
    let valid = w.members[check].validate(ch, &out.commit).map(|_| ());
    Probe {
        commit: out.commit.len(),
        welcome: out.welcome.map(|v| v.len()),
        valid,
    }
}

fn aad(admits: Vec<AdmitEvidence>, swaps: Vec<SwapEvidence>) -> CommitAad {
    CommitAad {
        commit_minute: host_day() * 1440 + 1439,
        rotate: true,
        admits,
        swaps,
    }
}

fn rejoin_evidence(kp_ref: Vec<u8>) -> SwapEvidence {
    SwapEvidence::Rejoin {
        kp_ref,
        generation: u32::MAX,
        day: u32::MAX,
        last_epoch: u64::MAX,
        last_hash: [7; 32],
        rejoin_sig: [8; 64],
    }
}

/// A fresh joiner's KeyPackage (MlsMessage bytes ≤ `max_len`, inflated with extra capability
/// extension types to reach it when `inflate`), parsed by the committer.
fn joiner_kp(w: &mut World, by: usize, inflate: Option<usize>) -> (KeyPackage, usize, Vec<u8>) {
    let ch = w.channel;
    let mut j = Device::new(10_000, w.day);
    let bytes = match inflate {
        None => j.key_package(ch, 1, w.day, 0).unwrap(),
        Some(max) => inflated_key_package(&mut j, ch, w.day, max),
    };
    let kp = w.members[by].parse_key_package(&bytes).unwrap();
    let r = kp
        .hash_ref(&w.members[by].crypto)
        .unwrap()
        .as_slice()
        .to_vec();
    (kp, bytes.len(), r)
}

/// The member's own new KeyPackage for a swap (same pseudonym, purpose rejoin or restore).
fn swap_kp(w: &mut World, by: usize, member: usize, purpose: u8) -> (KeyPackage, Vec<u8>) {
    let ch = w.channel;
    let day = w.day;
    let bytes = w.members[member].key_package(ch, purpose, day, 0).unwrap();
    let kp = w.members[by].parse_key_package(&bytes).unwrap();
    let r = kp
        .hash_ref(&w.members[by].crypto)
        .unwrap()
        .as_slice()
        .to_vec();
    (kp, r)
}

fn line(tag: &str, class: u8, p: &Probe) {
    let floor = seal::floor(class);
    let cap = seal::capacity(floor);
    let b = seal::bucket(p.commit, class);
    println!(
        "V10-4 {tag:<58} commit {:>6} B  floor C({floor})={cap:>5}  margin {:>6}  bucket {:>6}  welcome {:>6}  valid {}",
        p.commit,
        cap as i64 - p.commit as i64,
        b.map_or("NO_FIT".into(), |b| b.to_string()),
        p.welcome.map_or("-".into(), |v| format!("{v} ({})", seal::bucket(v, class).map_or("NO_FIT".into(), |b| b.to_string()))),
        p.valid.as_ref().map_or_else(|e| e.clone(), |_| "yes".into())
    );
}

/// Runs the single- and multi-proposal probes on a world of `n` members at class `class`.
/// `committer` is the member who commits (the owner in the blank shape, whose path is set).
fn probes(w: &mut World, shape: &str, class: u8) -> Vec<(String, usize)> {
    let n = w.members.len();
    let by = 0usize;
    let check = 1usize;
    let far = n - 1; // a member far from the committer
    let ch = w.channel;
    let e = w.members[by].epoch(ch);
    let far_leaf = w.members[far].leaf_index(ch);
    let keys: Vec<[u8; 32]> = w.members.iter().map(|m| m.pk).collect();
    let mut out = Vec::new();
    let mut rec = |tag: String, p: &Probe| {
        line(&tag, class, p);
        out.push((tag, p.commit));
    };

    // (a) empty self-update of a rank-255 member (the far one), AAD without evidence.
    let ef = w.members[far].epoch(ch);
    let s = CommitSpec {
        aad: aad(vec![], vec![]),
        refresh_epoch: Some(ef),
        force_path: true,
        ..Default::default()
    };
    let p = probe(w, far, 0, &s);
    rec(
        format!("{shape} n={n} self-update (rank 255, far leaf)"),
        &p,
    );

    // (a') the owner's empty PCS commit.
    let s = CommitSpec {
        aad: aad(vec![], vec![]),
        refresh_epoch: Some(e),
        force_path: true,
        ..Default::default()
    };
    let p = probe(w, by, check, &s);
    rec(
        format!("{shape} n={n} PCS commit (owner, empty with path)"),
        &p,
    );

    // (b) one Remove.
    let s = CommitSpec {
        removes: vec![LeafNodeIndex::new(far_leaf)],
        aad: aad(vec![], vec![]),
        refresh_epoch: Some(e),
        force_path: true,
        ..Default::default()
    };
    let p = probe(w, by, check, &s);
    rec(format!("{shape} n={n} Remove 1"), &p);

    // (c) swap with rejoin evidence: Remove L + Add L's own new KeyPackage.
    let (kp, r) = swap_kp(w, by, far, 2);
    let s = CommitSpec {
        removes: vec![LeafNodeIndex::new(far_leaf)],
        adds: vec![kp],
        aad: aad(vec![], vec![rejoin_evidence(r)]),
        refresh_epoch: Some(e),
        force_path: true,
        ..Default::default()
    };
    let p = probe(w, by, check, &s);
    rec(format!("{shape} n={n} swap (rejoin evidence)"), &p);

    // (d) swap with restore evidence.
    let (kp, r) = swap_kp(w, by, far, 3);
    let s = CommitSpec {
        removes: vec![LeafNodeIndex::new(far_leaf)],
        adds: vec![kp],
        aad: aad(
            vec![],
            vec![SwapEvidence::Restore(AdmitEvidence::filler(r))],
        ),
        refresh_epoch: Some(e),
        force_path: true,
        ..Default::default()
    };
    let p = probe(w, by, check, &s);
    rec(format!("{shape} n={n} swap (restore evidence)"), &p);

    // (e) one Add with AdmitEvidence: a GHOST KeyPackage, and one inflated to the 1 024 B bound.
    for (label, inflate) in [
        ("Add 1 (GHOST KeyPackage)", None),
        ("Add 1 (KeyPackage at the 1 024 B bound)", Some(1024)),
    ] {
        let (kp, kl, r) = joiner_kp(w, by, inflate);
        let s = CommitSpec {
            adds: vec![kp],
            aad: aad(vec![AdmitEvidence::filler(r)], vec![]),
            refresh_epoch: Some(e),
            force_path: true,
            ..Default::default()
        };
        let p = probe(w, by, check, &s);
        rec(format!("{shape} n={n}→{} {label} [kp {kl} B]", n + 1), &p);
    }

    // (f) a context change naming 8 committers and 3 funders with a 48-byte name.
    let ctx = ChannelContext::maximal(ch, &keys);
    let s = CommitSpec {
        context: Some(ctx.clone()),
        aad: aad(vec![], vec![]),
        refresh_epoch: Some(e),
        force_path: true,
        ..Default::default()
    };
    let p = probe(w, by, check, &s);
    rec(
        format!("{shape} n={n} context change (8 committers, 3 funders, name 48)"),
        &p,
    );

    // (g) the reviewer's composite: context change + Remove + swap (restore), one commit.
    let other = n - 2;
    let other_leaf = w.members[other].leaf_index(ch);
    let (kp, r) = swap_kp(w, by, other, 3);
    let s = CommitSpec {
        context: Some(ctx.clone()),
        removes: vec![LeafNodeIndex::new(far_leaf), LeafNodeIndex::new(other_leaf)],
        adds: vec![kp],
        aad: aad(
            vec![],
            vec![SwapEvidence::Restore(AdmitEvidence::filler(r))],
        ),
        refresh_epoch: Some(e),
        force_path: true,
        ..Default::default()
    };
    let p = probe(w, by, check, &s);
    rec(
        format!("{shape} n={n} composite: context + Remove + swap(restore)"),
        &p,
    );

    // (h) composite plus an Add of a 1 024 B KeyPackage.
    let (kp2, _, r2) = joiner_kp(w, by, Some(1024));
    let (kp, r) = swap_kp(w, by, other, 3);
    let s = CommitSpec {
        context: Some(ctx),
        removes: vec![LeafNodeIndex::new(far_leaf), LeafNodeIndex::new(other_leaf)],
        adds: vec![kp, kp2],
        aad: aad(
            vec![AdmitEvidence::filler(r2)],
            vec![SwapEvidence::Restore(AdmitEvidence::filler(r))],
        ),
        refresh_epoch: Some(e),
        force_path: true,
        ..Default::default()
    };
    let p = probe(w, by, check, &s);
    rec(
        format!("{shape} n={n} composite + Add (1 024 B KeyPackage)"),
        &p,
    );
    out
}

#[test]
fn v10_04_small_class_cap_32() {
    let day = host_day();
    // Blank: one batch add of 31 by the owner (only the owner's direct path is set).
    let mut w = World::build(32, 31, day);
    probes(&mut w, "blank", 0);
    // Populated: every member's path set.
    w.populate();
    probes(&mut w, "populated", 0);
}

#[test]
fn v10_04_small_class_threshold() {
    // The largest member count at which each single-proposal kind still fits C(4096) in the
    // blank shape (Q3's re-ask needs it if any kind fails at 32).
    let day = host_day();
    for n in [24usize, 26, 27, 28, 29, 30, 31, 32] {
        let mut w = World::build(n, n - 1, day);
        let ch = w.channel;
        let e = w.members[0].epoch(ch);
        let keys: Vec<[u8; 32]> = w.members.iter().map(|m| m.pk).collect();
        let far_leaf = w.members[n - 1].leaf_index(ch);
        let (kp, _, r) = joiner_kp(&mut w, 0, Some(1024));
        let add = probe(
            &mut w,
            0,
            1,
            &CommitSpec {
                adds: vec![kp],
                aad: aad(vec![AdmitEvidence::filler(r)], vec![]),
                refresh_epoch: Some(e),
                force_path: true,
                ..Default::default()
            },
        );
        let (kpn, _, rn) = joiner_kp(&mut w, 0, None);
        let addn = probe(
            &mut w,
            0,
            1,
            &CommitSpec {
                adds: vec![kpn],
                aad: aad(vec![AdmitEvidence::filler(rn)], vec![]),
                refresh_epoch: Some(e),
                force_path: true,
                ..Default::default()
            },
        );
        let ctx = probe(
            &mut w,
            0,
            1,
            &CommitSpec {
                context: Some(ChannelContext::maximal(ch, &keys)),
                aad: aad(vec![], vec![]),
                refresh_epoch: Some(e),
                force_path: true,
                ..Default::default()
            },
        );
        let (skp, sr) = swap_kp(&mut w, 0, n - 1, 3);
        let swap = probe(
            &mut w,
            0,
            1,
            &CommitSpec {
                removes: vec![LeafNodeIndex::new(far_leaf)],
                adds: vec![skp],
                aad: aad(
                    vec![],
                    vec![SwapEvidence::Restore(AdmitEvidence::filler(sr))],
                ),
                refresh_epoch: Some(e),
                force_path: true,
                ..Default::default()
            },
        );
        let upd = probe(
            &mut w,
            n - 1,
            0,
            &CommitSpec {
                aad: aad(vec![], vec![]),
                refresh_epoch: Some(e),
                force_path: true,
                ..Default::default()
            },
        );
        println!(
            "V10-4 threshold blank n={n:>2}: self-update {:>5}  Add(GHOST kp) {:>5}  Add(1024 kp) {:>5}  context(max) {:>5}  swap(restore) {:>5}   C(4096)=4028",
            upd.commit, addn.commit, add.commit, ctx.commit, swap.commit
        );
    }
}

#[test]
fn v10_04_large_class_cap_100() {
    let day = host_day();
    let mut w = World::build(100, 99, day);
    probes(&mut w, "blank", 1);
    w.populate();
    probes(&mut w, "populated", 1);
}

#[test]
fn v10_04_randomised_histories_32() {
    // Reachable trees under a random history of self-updates, removals and re-adds (blank parents
    // and unmerged leaves arise naturally); records the largest probe commits seen.
    let day = host_day();
    let mut w = World::build(32, 8, day);
    let ch = w.channel;
    let mut state: u64 = 0x9e37_79b9_7f4a_7c15;
    let mut rnd = |m: u64| {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state % m
    };
    let mut worst_upd = 0usize;
    let mut worst_ctx = 0usize;
    for step in 0..60 {
        let n = w.members.len();
        match rnd(3) {
            0 => {
                let i = 1 + rnd(n as u64 - 1) as usize;
                w.self_update(i).unwrap();
            }
            1 if n > 26 => {
                let i = 1 + rnd(n as u64 - 1) as usize;
                let leaf = w.members[i].leaf_index(ch);
                w.remove(0, leaf).unwrap();
            }
            _ if n < 32 => {
                let by = if rnd(2) == 0 { 0 } else { 1 };
                w.add_one(by).unwrap();
            }
            _ => {
                let i = 1 + rnd(n as u64 - 1) as usize;
                w.self_update(i).unwrap();
            }
        }
        if step % 5 == 4 {
            let n = w.members.len();
            let e = w.members[0].epoch(ch);
            let keys: Vec<[u8; 32]> = w.members.iter().map(|m| m.pk).collect();
            for i in [0usize, n - 1] {
                let p = probe(
                    &mut w,
                    i,
                    if i == 0 { 1 } else { 0 },
                    &CommitSpec {
                        aad: aad(vec![], vec![]),
                        refresh_epoch: Some(e),
                        force_path: true,
                        ..Default::default()
                    },
                );
                worst_upd = worst_upd.max(p.commit);
            }
            let p = probe(
                &mut w,
                0,
                1,
                &CommitSpec {
                    context: Some(ChannelContext::maximal(ch, &keys)),
                    aad: aad(vec![], vec![]),
                    refresh_epoch: Some(e),
                    force_path: true,
                    ..Default::default()
                },
            );
            worst_ctx = worst_ctx.max(p.commit);
            println!("V10-4 random history step {step:>2}: {n} members, self-update/PCS worst so far {worst_upd} B, context change worst {worst_ctx} B");
        }
    }
    assert!(w.authenticators_agree());
}

#[test]
fn v10_04_wide_tree_32_in_64_leaves() {
    // 33 members make a 64-leaf tree; removing one low leaf keeps the width (leaf 32 occupied):
    // 32 members at depth 6, the small class after a class change.
    let day = host_day();
    let mut w = World::build(33, 32, day);
    let ch = w.channel;
    let leaf = w.members[5].leaf_index(ch);
    w.remove(0, leaf).unwrap();
    assert_eq!(w.members.len(), 32);
    probes(&mut w, "wide(64)", 0);
}

#[test]
fn v10_04_welcome_worst_case() {
    // Welcome size when every leaf is a KeyPackage leaf inflated to the 1 024 B admission bound
    // (a KeyPackage leaf stays in the tree until its member updates), at 32 and 100 members.
    let day = host_day();
    for (n, class) in [(32usize, 0u8), (100, 1)] {
        let mut owner = Device::new(0, day);
        let ch: [u8; 32] = [n as u8; 32];
        owner
            .create_group(ch, &ChannelContext::initial(ch, owner.pk, class))
            .unwrap();
        let mut w = World {
            channel: ch,
            members: vec![owner],
            day,
        };
        let mut kps = Vec::new();
        for i in 1..n {
            let mut j = Device::new(i, day);
            let b = inflated_key_package(&mut j, ch, day, 1024);
            assert!(b.len() <= 1024);
            kps.push(w.members[0].parse_key_package(&b).unwrap());
            w.members.push(j);
        }
        let e = w.members[0].epoch(ch);
        let out = w.members[0]
            .commit(
                ch,
                &CommitSpec {
                    adds: kps,
                    aad: aad(vec![], vec![]),
                    refresh_epoch: Some(e),
                    force_path: true,
                    ..Default::default()
                },
            )
            .unwrap();
        let wl = out.welcome.as_ref().unwrap().len();
        println!(
            "V10-4 worst Welcome: {n} members, every KeyPackage leaf at the 1 024 B bound: Welcome {wl} B, bucket {} (C(65536) = {})",
            seal::bucket(wl, class).map_or("NO_FIT".into(), |b| b.to_string()),
            seal::capacity(65_536)
        );
    }
}

#[test]
fn v10_04_leaf_inflation_by_self_updates_100() {
    // A rank-255 member's modified client inflates its own leaf with an unknown extension in an
    // empty self-update that still fits the large class's 16 KiB floor (CO-2 as written checks the
    // commit's size, not the leaf's). How many such members does it take until no Welcome fits
    // C(65536)?
    let day = host_day();
    let mut w = World::build(100, 99, day);
    let ch = w.channel;
    let cap = seal::capacity(seal::floor(1));
    for k in 1..=6usize {
        let i = 100 - k; // members far from the owner
        let e = w.members[i].epoch(ch);
        // Largest extra that keeps this self-update within C(16384), found by halving.
        let (mut lo, mut hi) = (0usize, cap);
        while lo + 64 < hi {
            let mid = (lo + hi) / 2;
            let saved = w.members[i].rows.clone();
            let s = CommitSpec {
                refresh_epoch: Some(e),
                force_path: true,
                extra_leaf_bytes: mid,
                no_exported_group_info: true,
                ..Default::default()
            };
            let len = w.members[i]
                .commit(ch, &s)
                .map(|o| o.commit.len())
                .unwrap_or(usize::MAX);
            w.members[i].rows = saved;
            if len <= cap {
                lo = mid;
            } else {
                hi = mid;
            }
        }
        let s = CommitSpec {
            refresh_epoch: Some(e),
            force_path: true,
            extra_leaf_bytes: lo,
            no_exported_group_info: true,
            ..Default::default()
        };
        let out = w
            .commit_and_merge(i, &s)
            .expect("inflated self-update is valid for OpenMLS");
        // The Welcome a committer would now send for one joiner.
        let (kp, _, r) = joiner_kp(&mut w, 0, None);
        let e0 = w.members[0].epoch(ch);
        let add = CommitSpec {
            adds: vec![kp],
            aad: aad(vec![AdmitEvidence::filler(r)], vec![]),
            refresh_epoch: Some(e0),
            force_path: true,
            no_exported_group_info: true,
            ..Default::default()
        };
        let saved = w.members[0].rows.clone();
        let wl = w.members[0]
            .commit(ch, &add)
            .unwrap()
            .welcome
            .unwrap()
            .len();
        w.members[0].rows = saved;
        println!(
            "V10-4 leaf inflation: {k} member(s) inflated (this one +{lo} B, self-update {} B ≤ C(16384)); next Welcome {wl} B -> {}",
            out.commit.len(),
            seal::bucket(wl, 1).map_or("NO_FIT".into(), |b| b.to_string())
        );
        if wl > seal::capacity(65_536) {
            break;
        }
    }
}
