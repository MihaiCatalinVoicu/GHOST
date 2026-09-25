//! V10-5: the cost of the value-semantics storage adapter (design §3.4, R-3, Q18): rows loaded per
//! call, the change-set each call returns (rows and bytes, before and after wrapping), write
//! amplification as retained past epochs grow, and the cost of a trial settle (CO-3), at 32 and
//! 100 members.
//!
//! Run: `cargo test --release -p ghost-mls-spike --test v10_05_adapter -- --nocapture --test-threads=1`

use std::collections::BTreeMap;
use std::time::Instant;

use ghost_mls_spike::ext::CommitAad;
use ghost_mls_spike::harness::*;
use ghost_mls_spike::kv::Scope;

fn report(tag: &str, r: &CallReport) {
    println!(
        "V10-5 {tag:<46} rows in {:>3} (group {:>3}) {:>8} B plain {:>8} B wrapped | change-set puts {:>2} dels {:>2} {:>8} B plain {:>8} B wrapped | raw puts {:>3} {:>8} B, reads {:>3} | {:>7} µs total, {:>7} µs load+op, {:>6} µs wrap",
        r.rows_in,
        r.group_rows_in,
        r.bytes_in,
        r.wrapped_in,
        r.net_puts,
        r.net_deletes,
        r.net_put_bytes,
        r.wrapped_out,
        r.raw.raw_puts,
        r.raw.raw_put_bytes,
        r.raw.reads,
        r.micros,
        r.op_micros,
        r.wrap_micros
    );
}

/// The member's rows by label (the part of the key before the 0 separator), with sizes.
fn rows_by_label(d: &Device) -> BTreeMap<String, (usize, usize)> {
    let mut m: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    for ((scope, k), v) in &d.rows {
        let label = k.split(|b| *b == 0).next().unwrap_or(&[]);
        let key = format!(
            "{}:{}",
            if *scope == Scope::Group { "g" } else { "G" },
            String::from_utf8_lossy(label)
        );
        let e = m.entry(key).or_default();
        e.0 += 1;
        e.1 += v.len();
    }
    m
}

fn measure(n: usize, populated: bool, split: bool) {
    DEFAULT_SPLIT_PAST.store(split, std::sync::atomic::Ordering::Relaxed);
    let day = host_day();
    let t = Instant::now();
    let mut w = World::build(n, n - 1, day);
    if populated {
        w.populate();
    }
    let ch = w.channel;
    let shape = match (populated, split) {
        (false, false) => "blank",
        (true, false) => "populated",
        (false, true) => "blank+split",
        (true, true) => "populated+split",
    };
    println!(
        "V10-5 world n={n} {shape} built in {:.1} s",
        t.elapsed().as_secs_f64()
    );
    // Member M = 1 measures; the owner produces traffic. Only M and the owner advance from here.
    w.members[1].wrap_key = Some([0x42; 32]);
    let mut seq = 0u32;
    for retained in [0usize, 2, 8, 64] {
        // Advance until M holds `retained` past epochs (max_past_epochs(64) is the hard cap).
        let have = past_epochs(&mut w.members[1], ch);
        for _ in have..retained {
            let e = w.members[0].epoch(ch);
            let spec = CommitSpec {
                aad: CommitAad {
                    commit_minute: day * 1440,
                    ..Default::default()
                },
                refresh_epoch: Some(e),
                force_path: true,
                no_exported_group_info: true,
                ..Default::default()
            };
            let out = w.members[0].commit(ch, &spec).unwrap();
            w.members[1].receive(ch, &out.commit).unwrap();
            w.members[0].merge_own(ch).unwrap();
        }
        let have = past_epochs(&mut w.members[1], ch);
        let tag = format!("n={n} {shape} retained={have}");
        let labels = rows_by_label(&w.members[1]);
        let summary: Vec<String> = labels
            .iter()
            .map(|(k, (c, b))| format!("{k}={c}/{b}B"))
            .collect();
        println!("V10-5 {tag} rows of M: {}", summary.join(" "));

        // (1) receive one application message (a post of 200 bytes).
        seq += 1;
        let post = w.members[0].encrypt(ch, seq, &[0x70; 200]).unwrap();
        w.members[1].receive(ch, &post).unwrap();
        let r = w.members[1].last.clone();
        report(&format!("{tag} receive post"), &r);

        // (2) encrypt one post.
        seq += 1;
        w.members[1].encrypt(ch, seq, &[0x71; 200]).unwrap();
        let r = w.members[1].last.clone();
        report(&format!("{tag} encrypt post"), &r);

        // (3) a commit's validation run (CO-2; change-set discarded) and (4) the settle.
        let e = w.members[0].epoch(ch);
        let spec = CommitSpec {
            aad: CommitAad {
                commit_minute: day * 1440,
                ..Default::default()
            },
            refresh_epoch: Some(e),
            force_path: true,
            no_exported_group_info: true,
            ..Default::default()
        };
        let out = w.members[0].commit(ch, &spec).unwrap();
        let (_, r) = w.members[1].validate(ch, &out.commit).unwrap();
        report(&format!("{tag} validate commit (dry)"), &r);
        // (5) a trial settle: process and merge in memory, then open one successor post under the
        // trial state, all discarded (CO-3).
        let succ = {
            let saved0 = w.members[0].rows.clone();
            w.members[0].merge_own(ch).unwrap();
            let p = w.members[0].encrypt(ch, 9999, b"successor").unwrap();
            w.members[0].rows = saved0;
            p
        };
        let t = Instant::now();
        let saved = w.members[1].rows.clone();
        w.members[1].receive(ch, &out.commit).unwrap();
        let settle_rep = w.members[1].last.clone();
        w.members[1].receive(ch, &succ).unwrap();
        let succ_rep = w.members[1].last.clone();
        w.members[1].rows = saved;
        let trial_us = t.elapsed().as_micros();
        report(&format!("{tag} trial settle: merge (dry)"), &settle_rep);
        report(&format!("{tag} trial settle: successor (dry)"), &succ_rep);
        println!(
            "V10-5 {tag} trial settle total (merge + 1 successor, both discarded): {trial_us} µs"
        );
        // The real settle.
        w.members[1].receive(ch, &out.commit).unwrap();
        let r = w.members[1].last.clone();
        report(&format!("{tag} settle commit (merge)"), &r);
        w.members[0].merge_own(ch).unwrap();

        // (6) M's own self-update commit and its merge.
        let e = w.members[1].epoch(ch);
        let spec = CommitSpec {
            aad: CommitAad {
                commit_minute: day * 1440,
                ..Default::default()
            },
            refresh_epoch: Some(e),
            force_path: true,
            no_exported_group_info: true,
            ..Default::default()
        };
        let out = w.members[1].commit(ch, &spec).unwrap();
        let r = w.members[1].last.clone();
        report(&format!("{tag} own commit (self-update)"), &r);
        w.members[1].merge_own(ch).unwrap();
        let r = w.members[1].last.clone();
        report(&format!("{tag} own merge"), &r);
        w.members[0].receive(ch, &out.commit).unwrap();

        // (7) a load-only call: MlsGroup::load over the rows.
        let _ = w.members[1].epoch(ch);
        let r = w.members[1].last.clone();
        report(&format!("{tag} load only"), &r);
    }
    // (8) the sweep to 2 past epochs.
    w.members[1].sweep_past(ch, 2).unwrap();
    let r = w.members[1].last.clone();
    report(&format!("n={n} {shape} sweepPast(keep 2)"), &r);
}

fn past_epochs(d: &mut Device, ch: [u8; 32]) -> usize {
    // The MessageSecretsStore's past_epoch_trees length, read from the stored head row (an
    // array of trees, or of epoch numbers in the split mode).
    let _ = ch;
    let row = d
        .rows
        .iter()
        .find(|((s, k), _)| *s == Scope::Group && k.starts_with(b"MessageSecrets\0"))
        .map(|(_, v)| v.clone())
        .expect("message secrets row");
    let v: serde_json::Value = serde_json::from_slice(&row).unwrap();
    v["past_epoch_trees"].as_array().map_or(0, Vec::len)
}

#[test]
fn v10_05_adapter_cost_32() {
    measure(32, false, false);
    measure(32, true, false);
}

#[test]
fn v10_05_adapter_cost_32_split() {
    measure(32, false, true);
    measure(32, true, true);
}

#[test]
fn v10_05_adapter_cost_100() {
    measure(100, false, false);
}

#[test]
fn v10_05_adapter_cost_100_split() {
    measure(100, false, true);
}

#[test]
fn v10_05_scope_list() {
    let g = ghost_mls_spike::kv::METHOD_SCOPES
        .iter()
        .filter(|(_, s)| *s == Scope::Group)
        .count();
    println!(
        "V10-5 StorageProvider methods in the P0 feature set: {} ({} group-scoped, {} global)",
        ghost_mls_spike::kv::METHOD_SCOPES.len(),
        g,
        ghost_mls_spike::kv::METHOD_SCOPES.len() - g
    );
}
