//! V10-6 probe: a scripted channel world under the process-global seeded stream (getrandom's
//! custom backend, feature `det`, `--cfg getrandom_backend="custom"`). Prints the SHA-256 of every
//! commit, Welcome and application message, and of every member's final rows, plus which threads
//! drew randomness. Two runs in two processes must print the same lines (design §12.1, §19.10).
//!
//!   det_world <seed-hex-byte> [threads]     threads: rayon workers (default 1; 0 = rayon default)

#[cfg(not(feature = "det"))]
fn main() {
    eprintln!("build with --features det and RUSTFLAGS='--cfg getrandom_backend=\"custom\"'");
    std::process::exit(2);
}

#[cfg(feature = "det")]
fn main() {
    use ghost_mls_spike::ext::CommitAad;
    use ghost_mls_spike::harness::*;
    use openmls::prelude::LeafNodeIndex;
    use sha2::{Digest, Sha256};

    let args: Vec<String> = std::env::args().collect();
    let seed_byte =
        u8::from_str_radix(args.get(1).map(String::as_str).unwrap_or("01"), 16).expect("hex byte");
    let threads: usize = args
        .get(2)
        .map(|s| s.parse().expect("threads"))
        .unwrap_or(1);
    let pool = if threads == 0 {
        rayon::current_num_threads()
    } else {
        let _ = rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build_global();
        rayon::current_num_threads()
    };
    ghost_mls_spike::det::seed([seed_byte; 32]);
    let h = |b: &[u8]| hex(&Sha256::digest(b)[..8]);
    println!("rayon threads: {pool}");

    // A fixed virtual day, so nothing depends on the host clock except OpenMLS's own stamps. Day
    // 20 720 (2026-09-24) reproduces the evidence's hashes; OpenMLS checks KeyPackage lifetimes
    // ([d − 4, d + 80]) against the host clock, so that day works only until 2026-12-12 (review
    // finding H12). GHOST_SPIKE_DAY sets another; outside §12.1's window the probe refuses to run.
    let day: u32 = std::env::var("GHOST_SPIKE_DAY")
        .ok()
        .map(|d| d.parse().expect("GHOST_SPIKE_DAY: a UTC day number"))
        .unwrap_or(20_720);
    let host = host_day();
    if day + 79 < host || day > host + 3 {
        eprintln!(
            "virtual day {day} is outside the host window [{} … {}] of design §12.1; set GHOST_SPIKE_DAY",
            host - 79,
            host + 3
        );
        std::process::exit(2);
    }
    let mut w = World::build(8, 7, day);
    let ch = w.channel;
    println!("channel {}", hex(&ch[..8]));
    let mut outs = Vec::new();
    for i in 0..3 {
        let m = w.members[i]
            .encrypt(ch, i as u32, format!("post {i}").as_bytes())
            .unwrap();
        outs.push(("post", m.clone()));
        for j in 0..w.members.len() {
            if j != i {
                w.members[j].receive(ch, &m).unwrap();
            }
        }
    }
    let u = w.self_update(3).unwrap();
    outs.push(("self-update", u.commit));
    let leaf = w.members[5].leaf_index(ch);
    let r = w.remove(0, leaf).unwrap();
    outs.push(("remove", r.commit));
    let a = w.add_one(0).unwrap();
    outs.push(("add", a.commit.clone()));
    outs.push(("welcome", a.welcome.clone().unwrap()));
    let e = w.members[0].epoch(ch);
    let l1 = w.members[1].leaf_index(ch);
    let big = w.members[0]
        .commit(
            ch,
            &CommitSpec {
                removes: vec![LeafNodeIndex::new(l1)],
                aad: CommitAad {
                    commit_minute: day * 1440,
                    ..Default::default()
                },
                refresh_epoch: Some(e),
                force_path: true,
                ..Default::default()
            },
        )
        .unwrap();
    outs.push(("remove-2 (unmerged)", big.commit));
    for (tag, b) in &outs {
        println!("{tag:<22} {:>6} B  sha256 {}", b.len(), h(b));
    }
    for m in &w.members {
        let mut all = Vec::new();
        for ((s, k), v) in &m.rows {
            all.push(*s as u8);
            all.extend_from_slice(k);
            all.extend_from_slice(v);
        }
        println!(
            "member {} rows {:>2}  sha256 {}",
            m.id,
            m.rows.len(),
            h(&all)
        );
    }
    println!("epoch authenticators equal: {}", w.authenticators_agree());
    let draws = ghost_mls_spike::det::draws();
    let main_id = std::thread::current().id();
    let on_main = draws.iter().filter(|(t, _)| *t == main_id).count();
    let bytes: usize = draws.iter().map(|(_, n)| n).sum();
    let mut threads_seen: Vec<String> = draws.iter().map(|(t, _)| format!("{t:?}")).collect();
    threads_seen.sort();
    threads_seen.dedup();
    println!(
        "draws: {} ({} B) — {} on the main thread, {} on other threads; threads {:?}",
        draws.len(),
        bytes,
        on_main,
        draws.len() - on_main,
        threads_seen
    );
}

#[cfg(feature = "det")]
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
