//! V10-5: the cost of the value-semantics storage adapter (design §3.4, R-3, Q18): rows loaded per
//! call, the change-set each call returns (rows and bytes, before and after wrapping), write
//! amplification as retained past epochs grow, and the cost of a trial settle (CO-3), at 32 and
//! 100 members; and (review pass) that the split of past epochs into rows behaves like the
//! unsplit store on every late-post path.
//!
//! Times: every operation runs `REPS` times on the same state (the member's rows restored after
//! each run) and the lines print min / median / max. The first run printed single measurements,
//! which on a host at 100 % CPU varied by up to five times between identical runs (review finding
//! H4); only the medians are quoted, and they bound nothing (docs/design/faza10-s0-evidence.md §5).
//! Bytes are those of the first repetition (they vary by well under 1 % between runs: serde_json
//! writes random bytes as decimal numbers of varying length).
//!
//! Run: `cargo test --release -p ghost-mls-spike --test v10_05_adapter -- --nocapture --test-threads=1`

use std::collections::BTreeMap;

use ghost_mls_spike::ext::CommitAad;
use ghost_mls_spike::harness::*;
use ghost_mls_spike::kv::Scope;

const REPS: usize = 9;

fn report(tag: &str, r: &CallReport, t: (u128, u128, u128)) {
    println!(
        "V10-5 {tag:<46} rows in {:>3} (group {:>3}) {:>8} B plain {:>8} B wrapped | change-set puts {:>2} dels {:>2} {:>8} B plain {:>8} B wrapped | raw puts {:>3} {:>8} B, reads {:>3} | time min {:>8.2} median {:>8.2} max {:>8.2} ms",
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
        t.0 as f64 / 1000.0,
        t.1 as f64 / 1000.0,
        t.2 as f64 / 1000.0,
    );
}

fn spread(mut v: Vec<u128>) -> (u128, u128, u128) {
    v.sort_unstable();
    (v[0], v[v.len() / 2], v[v.len() - 1])
}

/// Runs `op` on member `i` `REPS` times, restoring its rows after each run. Returns the report of
/// the first run and the spread of the call times `op` returns (µs).
fn repeat(
    w: &mut World,
    i: usize,
    mut op: impl FnMut(&mut Device) -> u128,
) -> (CallReport, (u128, u128, u128)) {
    let saved = w.members[i].rows.clone();
    let mut times = Vec::with_capacity(REPS);
    let mut first = None;
    for _ in 0..REPS {
        let t = op(&mut w.members[i]);
        times.push(t);
        if first.is_none() {
            first = Some(w.members[i].last.clone());
        }
        w.members[i].rows = saved.clone();
    }
    (first.unwrap(), spread(times))
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

fn empty_commit(day: u32, e: u64) -> CommitSpec {
    CommitSpec {
        aad: CommitAad {
            commit_minute: day * 1440,
            ..Default::default()
        },
        refresh_epoch: Some(e),
        force_path: true,
        no_exported_group_info: true,
        ..Default::default()
    }
}

/// Returns, per retention level, the change-set bytes of a received post (for the assertions).
fn measure(n: usize, populated: bool, split: bool) -> Vec<(usize, usize)> {
    DEFAULT_SPLIT_PAST.store(split, std::sync::atomic::Ordering::Relaxed);
    let _ = ghost_mls_spike::pin_rayon_single_worker();
    let day = host_day();
    let t = std::time::Instant::now();
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
    let mut post_bytes = Vec::new();
    for retained in [0usize, 2, 8, 64] {
        // Advance until M holds `retained` past epochs (max_past_epochs(64) is the hard cap).
        let have = past_epochs(&w.members[1]);
        for _ in have..retained {
            let e = w.members[0].epoch(ch);
            let out = w.members[0].commit(ch, &empty_commit(day, e)).unwrap();
            w.members[1].receive(ch, &out.commit).unwrap();
            w.members[0].merge_own(ch).unwrap();
        }
        let have = past_epochs(&w.members[1]);
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
        let (r, tm) = repeat(&mut w, 1, |m| {
            m.receive(ch, &post).unwrap();
            m.last.micros
        });
        report(&format!("{tag} receive post"), &r, tm);
        post_bytes.push((have, r.net_put_bytes));

        // (2) encrypt one post.
        let (r, tm) = repeat(&mut w, 1, |m| {
            m.encrypt(ch, seq + 1, &[0x71; 200]).unwrap();
            m.last.micros
        });
        report(&format!("{tag} encrypt post"), &r, tm);

        // (3) a commit's validation run (CO-2; change-set discarded).
        let e = w.members[0].epoch(ch);
        let out = w.members[0].commit(ch, &empty_commit(day, e)).unwrap();
        let (r, tm) = repeat(&mut w, 1, |m| m.validate(ch, &out.commit).unwrap().1.micros);
        report(&format!("{tag} validate commit (dry)"), &r, tm);
        // (4) a trial settle: process and merge in memory, then open one successor post under the
        // trial state, all discarded (CO-3).
        let succ = {
            let saved0 = w.members[0].rows.clone();
            w.members[0].merge_own(ch).unwrap();
            let p = w.members[0].encrypt(ch, 9999, b"successor").unwrap();
            w.members[0].rows = saved0;
            p
        };
        let (r, tm) = repeat(&mut w, 1, |m| {
            m.receive(ch, &out.commit).unwrap();
            let a = m.last.micros;
            m.receive(ch, &succ).unwrap();
            a + m.last.micros
        });
        report(
            &format!("{tag} trial settle (merge + 1 successor, dry)"),
            &r,
            tm,
        );
        // (5) the settle (process + merge), then for real.
        let (r, tm) = repeat(&mut w, 1, |m| {
            m.receive(ch, &out.commit).unwrap();
            m.last.micros
        });
        report(&format!("{tag} settle commit (merge)"), &r, tm);
        w.members[1].receive(ch, &out.commit).unwrap();
        w.members[0].merge_own(ch).unwrap();

        // (6) M's own self-update commit, its merge (both dry), then for real.
        let e = w.members[1].epoch(ch);
        let (r, tm) = repeat(&mut w, 1, |m| {
            m.commit(ch, &empty_commit(day, e)).unwrap();
            m.last.micros
        });
        report(&format!("{tag} own commit (self-update)"), &r, tm);
        let (r, tm) = repeat(&mut w, 1, |m| {
            m.commit(ch, &empty_commit(day, e)).unwrap();
            m.merge_own(ch).unwrap();
            m.last.micros
        });
        report(&format!("{tag} own merge"), &r, tm);
        let out = w.members[1].commit(ch, &empty_commit(day, e)).unwrap();
        w.members[1].merge_own(ch).unwrap();
        w.members[0].receive(ch, &out.commit).unwrap();

        // (7) a load-only call: MlsGroup::load over the rows.
        let (r, tm) = repeat(&mut w, 1, |m| {
            let _ = m.epoch(ch);
            m.last.micros
        });
        report(&format!("{tag} load only"), &r, tm);
    }
    // (8) the sweep to 2 past epochs.
    let (r, tm) = repeat(&mut w, 1, |m| {
        m.sweep_past(ch, 2).unwrap();
        m.last.micros
    });
    report(&format!("n={n} {shape} sweepPast(keep 2)"), &r, tm);
    post_bytes
}

fn past_epochs(d: &Device) -> usize {
    // The MessageSecretsStore's past_epoch_trees length, read from the stored head row (an
    // array of trees, or of epoch numbers in the split mode).
    let row = d
        .rows
        .iter()
        .find(|((s, k), _)| *s == Scope::Group && k.starts_with(b"MessageSecrets\0"))
        .map(|(_, v)| v.clone())
        .expect("message secrets row");
    let v: serde_json::Value = serde_json::from_slice(&row).unwrap();
    v["past_epoch_trees"].as_array().map_or(0, Vec::len)
}

/// The assertions both modes must meet: a received post's change-set grows with every retained
/// past epoch without the split and stays at the current epoch's secrets with it.
fn check(post_bytes: &[(usize, usize)], split: bool, n: usize) {
    let (at0, at64) = (post_bytes[0].1, post_bytes[post_bytes.len() - 1].1);
    assert_eq!(post_bytes.last().unwrap().0, 64, "64 past epochs retained");
    if split {
        assert!(
            at64 <= at0 + 512,
            "split: {at64} B at 64 epochs vs {at0} B at 0 (n = {n})"
        );
    } else {
        assert!(
            at64 > 30 * at0,
            "unsplit: {at64} B at 64 epochs vs {at0} B at 0 (n = {n})"
        );
    }
}

#[test]
fn v10_05_adapter_cost_32() {
    let b = measure(32, false, false);
    check(&b, false, 32);
    measure(32, true, false);
}

#[test]
fn v10_05_adapter_cost_32_split() {
    let b = measure(32, false, true);
    check(&b, true, 32);
    measure(32, true, true);
}

#[test]
fn v10_05_adapter_cost_100() {
    let b = measure(100, false, false);
    check(&b, false, 100);
}

#[test]
fn v10_05_adapter_cost_100_split() {
    let b = measure(100, false, true);
    check(&b, true, 100);
}

#[test]
fn v10_05_scope_list() {
    let g = ghost_mls_spike::kv::METHOD_SCOPES
        .iter()
        .filter(|(_, s)| *s == Scope::Group)
        .count();
    let all = ghost_mls_spike::kv::METHOD_SCOPES.len();
    println!(
        "V10-5 StorageProvider methods in the P0 feature set: {all} ({g} group-scoped, {} global)",
        all - g
    );
    assert_eq!((all, g), (53, 41));
}

/// Review pass (the impact reviewer's R2, re-run here): every late-post path gives the same result
/// with past epochs split into rows as with OpenMLS's single `MessageSecrets` row — a post decrypted
/// late and out of order inside a retained epoch, its replay refused, a post six epochs late, a post
/// of a swept epoch refused, a post one epoch late after the sweep, and equal epoch authenticators.
#[test]
fn v10_05_split_matches_unsplit_on_late_posts() {
    let _ = ghost_mls_spike::pin_rayon_single_worker();
    // Errors carry no numbers that differ between runs once digits are dropped.
    fn class(r: Result<Received, String>) -> String {
        match r {
            Ok(x) => format!("ok {}", String::from_utf8_lossy(&x.plaintext)),
            Err(e) => e.chars().filter(|c| !c.is_ascii_digit()).collect(),
        }
    }
    let mut runs = Vec::new();
    for split in [false, true] {
        DEFAULT_SPLIT_PAST.store(split, std::sync::atomic::Ordering::Relaxed);
        let day = host_day();
        let mut w = World::build(4, 3, day);
        let ch = w.channel;
        let mut out = Vec::new();
        // Epoch e: the owner sends three posts; M (member 1) receives none of them yet.
        let p: Vec<Vec<u8>> = (1..=3u32)
            .map(|s| {
                w.members[0]
                    .encrypt(ch, s, format!("p{s}").as_bytes())
                    .unwrap()
            })
            .collect();
        // Six commits pass (M processes every one).
        for _ in 0..6 {
            let e = w.members[0].epoch(ch);
            let c = w.members[0].commit(ch, &empty_commit(day, e)).unwrap();
            for j in 1..w.members.len() {
                w.members[j].receive(ch, &c.commit).unwrap();
            }
            w.members[0].merge_own(ch).unwrap();
        }
        out.push(format!("past epochs {}", past_epochs(&w.members[1])));
        // Late and out of order inside the retained epoch, then a replay.
        out.push(class(w.members[1].receive(ch, &p[2])));
        out.push(class(w.members[1].receive(ch, &p[0])));
        out.push(class(w.members[1].receive(ch, &p[0])));
        // A post of the epoch before the last commit, then the sweep to 2 and posts of old epochs.
        let q = w.members[0].encrypt(ch, 10, b"q").unwrap();
        let e = w.members[0].epoch(ch);
        let c = w.members[0].commit(ch, &empty_commit(day, e)).unwrap();
        for j in 1..w.members.len() {
            w.members[j].receive(ch, &c.commit).unwrap();
        }
        w.members[0].merge_own(ch).unwrap();
        w.members[1].sweep_past(ch, 2).unwrap();
        out.push(format!(
            "past epochs after sweepPast(2) {}",
            past_epochs(&w.members[1])
        ));
        out.push(class(w.members[1].receive(ch, &p[1])));
        out.push(class(w.members[1].receive(ch, &q)));
        out.push(format!("authenticators agree {}", w.authenticators_agree()));
        println!("V10-5 late posts, split = {split}: {}", out.join(" | "));
        runs.push(out);
    }
    DEFAULT_SPLIT_PAST.store(false, std::sync::atomic::Ordering::Relaxed);
    assert_eq!(runs[0], runs[1], "split and unsplit give the same results");
    assert!(runs[0][1].starts_with("ok p3") && runs[0][2].starts_with("ok p1"));
    assert!(!runs[0][3].starts_with("ok"), "replay refused");
    assert!(
        !runs[0][5].starts_with("ok"),
        "post of a swept epoch refused"
    );
    assert!(
        runs[0][6].starts_with("ok q"),
        "one epoch late after the sweep decrypts"
    );
}
