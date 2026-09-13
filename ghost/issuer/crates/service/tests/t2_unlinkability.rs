//! T2, the unlinkability exit gate (Phase 8 design §1.3, §13.4, §19.16; INVARIANTS T2): the full
//! Rust system (the real issuer handlers on the real redb store and journal, three real relays with
//! the real redeem path and capture, reference clients on the production client-core calls and
//! crypto, scheduled by the reference policy that replays `entitlement_policy.txt`) exported as the
//! complete issuer and relay views and analysed by `ghost-t2-join`.
//!
//! - `t2_pr_variant` (every PR, the `rust` job, release profile): N = 300 packs, 21 days.
//! - `t2_exit_gate` (`t2-exit-gate.yml`): `GHOST_T2_SCALE=gate` (N = 2 000, 84 days), and the
//!   nightly sweep over the ten pinned seed pairs with `GHOST_T2_SEEDS=all`.
//!
//! Both write their report to `GHOST_T2_REPORT` (default `target/t2/<variant>.txt`) and fail on any
//! check. The world tests are ignored in the debug profile (release only, design §19.17 point 2).

mod common;
mod t2;

use std::path::PathBuf;

use t2::config::{Config, Mutant};
use t2::gate;
use t2::population;
use t2::world::World;

fn report_path(name: &str) -> PathBuf {
    std::env::var("GHOST_T2_REPORT").map_or_else(
        |_| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../../target/t2")
                .join(format!("{name}.txt"))
        },
        PathBuf::from,
    )
}

fn write_report(name: &str, text: &str) {
    let path = report_path(name);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, text).unwrap();
    println!("{text}");
    println!("report written to {}", path.display());
}

fn run(name: &str, scale: population::Scale, small: population::Scale, seeds: &[(u64, u64)]) {
    let mut text = String::new();
    let mut failed = Vec::new();
    for (k, &pair) in seeds.iter().enumerate() {
        let r = gate::variant(&format!("{name}-{k}"), scale, small, pair, Mutant::None);
        text.push_str(&r.findings.text());
        text.push('\n');
        failed.extend(
            r.findings
                .failed
                .iter()
                .map(|f| format!("seed pair {k}: {f}")),
        );
    }
    let verdict = if failed.is_empty() {
        "T2 RESULT: PASS".to_string()
    } else {
        format!("T2 RESULT: FAIL ({})", failed.join(", "))
    };
    text.push_str(&verdict);
    text.push('\n');
    write_report(name, &text);
    assert!(failed.is_empty(), "{verdict}");
}

#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "T2 worlds: release profile only (design §19.17 point 2)"
)]
fn t2_pr_variant() {
    run(
        "t2-pr",
        population::PR,
        population::SMALL,
        &gate::SEEDS[..1],
    );
}

#[test]
#[ignore = "the T2 exit gate (t2-exit-gate.yml): GHOST_T2_SCALE=gate, GHOST_T2_SEEDS=all"]
fn t2_exit_gate() {
    let (name, scale, small) = gate::scales();
    // GHOST_T2_SEEDS: "all" (every pinned pair, one after the other), a pair index 0..9 (the
    // nightly matrix), or unset (pair 0).
    let seeds: Vec<(u64, u64)> = match std::env::var("GHOST_T2_SEEDS").as_deref() {
        Ok("all") => gate::SEEDS.to_vec(),
        Ok(k) => vec![gate::SEEDS[k.parse::<usize>().expect("GHOST_T2_SEEDS: all or 0..9")]],
        Err(_) => vec![gate::SEEDS[0]],
    };
    run(&format!("t2-{name}"), scale, small, &seeds);
}

#[test]
#[ignore = "development run: the whole variant at the small scale"]
fn t2_small_variant() {
    run(
        "t2-small",
        population::SMALL,
        population::SMALL,
        &gate::SEEDS[..1],
    );
}

/// Development: the twins with readable per-client lines (GHOST_T2_DEBUG=1), at the small scale or,
/// with GHOST_T2_DEBUG_SCALE=pr, at the PR variant's.
#[test]
#[ignore = "development run: twin worlds with readable differences"]
fn t2_debug_twins() {
    let cache = t2::es::global_cache();
    let scale = match std::env::var("GHOST_T2_DEBUG_SCALE").as_deref() {
        Ok("pr") => population::PR,
        _ => population::SMALL,
    };
    let mut cfg = Config::new("dbg", scale, gate::SEEDS[0].1);
    cfg.per_client = true;
    cfg.analyze = true;
    let a = World::new(cfg.clone(), &cache).run();
    let mut f = gate::Findings::default();
    gate::joins(&mut f, &a);
    let (b1, moved) = gate::ni1_cells_twin(&cfg, &a);
    let b2 = gate::ni2_twin(&cfg, &a);
    let outs = gate::parallel(vec![
        Box::new(|| World::new(b1.clone(), &cache).run()),
        Box::new(|| World::new(b2.clone(), &cache).run()),
    ]);
    gate::ni1_cells(&mut f, &a, &outs[0], &moved);
    gate::ni2(&mut f, &a, &outs[1]);
    println!("{}", f.text());
}

#[test]
#[ignore = "development smoke run"]
fn smoke() {
    let cache = t2::es::SignCache::new();
    let cfg = Config::new("smoke", population::SMALL, 1);
    let out = World::new(cfg, &cache).run();
    println!("seconds {:.1}", out.seconds);
    for (k, v) in &out.log.counts {
        println!("{k}: {v}");
    }
    println!("need-triggered starts {}", out.log.need_starts.len());
    for (k, v) in &out.log.timings {
        println!("time {k}: {v:.1} s");
    }
    println!("issuer calls {}", out.rec.digests.issuer_calls);
    println!("relay calls {:?}", out.rec.digests.relay_calls);
}
