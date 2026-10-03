//! EM-3 runs: every control scenario under the design's rules with its reachability queries, every
//! mutant against its named killer, the finding probes, and the quantitative checks. Lines that
//! start with `EM-3 ` are the report (`channel-state-models.yml` greps them into the job summary and
//! `ch-state-models-check.sh` checks them).
//!
//! Scale: `EM3_SCALE=full` (the workflow) or the PR bound (default, the `rust` job). Budget:
//! `EM3_BUDGET` states per exploration (5 million at the PR bound, 100 million at the full one; a
//! run that reaches it fails: a budget overflow is not a verdict). `EM3_THREADS`: explorations at
//! once (default: every core). Run with `--nocapture --test-threads 1` for the report.

use std::sync::Mutex;
use std::time::Instant;

use ghost_client_mls_models::arith;
use ghost_client_mls_models::props::T_HONEST_ONE_BRANCH;
use ghost_client_mls_models::rules::{Fix, Mutant, Rules};
use ghost_client_mls_models::scenarios::*;
use ghost_client_mls_models::search::*;

fn scale() -> Scale {
    match std::env::var("EM3_SCALE").as_deref() {
        Ok("full") => Scale::Full,
        _ => Scale::Pr,
    }
}

fn budget() -> usize {
    std::env::var("EM3_BUDGET")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(match scale() {
            Scale::Pr => 5_000_000,
            Scale::Full => 100_000_000,
        })
}

fn scale_name() -> &'static str {
    match scale() {
        Scale::Pr => "pr",
        Scale::Full => "full",
    }
}

/// Runs `jobs` on `EM3_THREADS` threads (default: every available core); results come back in
/// input order. Each exploration holds its own fingerprint set, so the thread count bounds memory.
fn parallel<T: Send, R: Send>(jobs: Vec<T>, f: impl Fn(T) -> R + Sync) -> Vec<R> {
    let n = jobs.len();
    let queue: Mutex<Vec<(usize, T)>> = Mutex::new(jobs.into_iter().enumerate().rev().collect());
    let results: Mutex<Vec<Option<R>>> = Mutex::new((0..n).map(|_| None).collect());
    let threads = std::env::var("EM3_THREADS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|&t| t > 0)
        .unwrap_or_else(|| {
            std::thread::available_parallelism()
                .map(|p| p.get())
                .unwrap_or(4)
        })
        .min(n.max(1));
    std::thread::scope(|s| {
        for _ in 0..threads {
            s.spawn(|| loop {
                let job = queue.lock().expect("queue").pop();
                let Some((i, t)) = job else { break };
                let r = f(t);
                results.lock().expect("results")[i] = Some(r);
            });
        }
    });
    results
        .into_inner()
        .expect("results")
        .into_iter()
        .map(|r| r.expect("every job ran"))
        .collect()
}

/// Every control scenario holds every property under the design's rules, and reaches every honest
/// flow it names (without the reachability queries the safety properties could hold vacuously).
#[test]
fn em3_controls_hold_every_property_and_reach_their_flows() {
    // The report's lines start at column 0 (libtest prints "test <name> ... " first).
    println!();
    let scenarios = controls(Rules::DESIGN, scale());
    let budget = budget();
    let results = parallel(scenarios, |s| {
        let t = Instant::now();
        let r = explore(&s.cfg, s.start, budget);
        (s, r, t.elapsed())
    });
    let mut failures = Vec::new();
    let mut totals = Outcome::default();
    for (s, r, took) in &results {
        match r {
            Ok(o) => {
                let missing: Vec<&str> = s
                    .reach
                    .iter()
                    .filter(|(ev, _)| o.events & ev == 0)
                    .map(|(_, what)| *what)
                    .collect();
                println!(
                    "EM-3 {}: {} states, {} transitions, {} decisions, {} terminal, depth {}, \
                     reach {}/{}, {:.1} s",
                    s.cfg.name,
                    o.states,
                    o.transitions,
                    o.decisions,
                    o.terminal,
                    o.max_depth,
                    s.reach.len() - missing.len(),
                    s.reach.len(),
                    took.as_secs_f64()
                );
                for m in &missing {
                    failures.push(format!("{}: unreached: {m}", s.cfg.name));
                }
                totals.states += o.states;
                totals.transitions += o.transitions;
                totals.decisions += o.decisions;
                totals.terminal += o.terminal;
            }
            Err(stop) => {
                println!("EM-3 {}: FAILED\n{}", s.cfg.name, stop.render());
                failures.push(format!("{}: {}", s.cfg.name, stop.render()));
            }
        }
    }
    println!(
        "EM-3 controls ({}): {} scenarios, {} states, {} transitions, {} decisions, {} terminal",
        scale_name(),
        results.len(),
        totals.states,
        totals.transitions,
        totals.decisions,
        totals.terminal
    );
    assert!(
        failures.is_empty(),
        "EM-3 controls:\n{}",
        failures.join("\n")
    );
}

type Build = fn(Rules, Scale) -> Scenario;

/// One mutant per rule (CO-1 … CO-14, §6.5, §6.7), each with the scenario and the property that
/// kill it. The control of every row is that scenario under the design's rules (the test above).
const MUTANTS: &[(Mutant, &str, Build, &str)] = &[
    (
        Mutant::Rank255Proposals,
        "CO-1 (MM-5)",
        adversarial_commits,
        "P-NO-INVALID-MERGE",
    ),
    (
        Mutant::PostCommitRank,
        "CO-1 (rank basis, §19.13)",
        governance,
        "P-GOVERNANCE",
    ),
    (
        Mutant::SwapWithoutEvidence,
        "CO-2 (MM-21)",
        replay_join,
        "P-NO-INVALID-MERGE",
    ),
    (Mutant::LocalHistory, "CO-2 (MM-23)", join, "P-VALID-SAME"),
    (
        Mutant::NoSwapOfLowerRank,
        "CO-2 (MM-33)",
        owner,
        "P-OWNER-BACK",
    ),
    (
        Mutant::NewSigner,
        "CO-2 (MM-31)",
        adversarial_commits,
        "P-NO-INVALID-MERGE",
    ),
    (
        Mutant::LifetimeByClock,
        "CO-2 (S0-12 / round 10d, Q42 (b))",
        clocks,
        "P-VALID-SAME",
    ),
    (
        Mutant::LifetimePending,
        "CO-2, CO-4 (MM-46)",
        junk,
        "P-LIFETIME",
    ),
    (Mutant::HashOnly, "CO-3 (MM-4)", concurrency, "P-RANK"),
    (Mutant::NoSuccessors, "CO-3 (MM-24)", late, "P-FOLLOW"),
    (Mutant::NoWindow, "CO-4 (MM-3)", concurrency, "P-FRESH"),
    (
        Mutant::OwnUnverified,
        "CO-4 (MM-2)",
        indeterminate,
        "P-VERIFIED",
    ),
    (
        Mutant::NoStoreHourAnchor,
        "CO-4 (MM-25)",
        catchup,
        "P-CATCHUP",
    ),
    (
        Mutant::ClearIndeterminate,
        "CO-4 (MM-32)",
        indeterminate,
        "P-CUSTODY",
    ),
    (Mutant::NoListingPass, "CO-4 (ii)", concurrency, "P-FRESH"),
    (
        Mutant::OwnAnchorAtPass,
        "CO-4 (i) (own commit's anchor)",
        late,
        "P-FRESH",
    ),
    (Mutant::WelcomeAtPass, "CO-5 (MM-19)", join, "P-WELCOME"),
    (Mutant::NotSticky, "CO-6 (MM-16)", late, "P-STICKY"),
    (Mutant::Rank255Blocks, "CO-7 (MM-26)", flood, "P-PASS"),
    (Mutant::FreshWork, "CO-8 (MM-34)", join, "P-WORKAGE"),
    (Mutant::NoSkip, "CO-9", concurrency, "P-OWN-VALID"),
    (Mutant::DropLoserWork, "CO-10", remove, "P-LIVENESS"),
    (
        Mutant::CountDraining,
        "CO-11 (MM-37)",
        spam_drain,
        "P-NO-FALSE-RESYNC",
    ),
    (Mutant::NoBranchDeath, "CO-11", fork, "P-DETECT"),
    (Mutant::NoStale, "CO-12 (MM-36)", silent, "P-DETECT"),
    (Mutant::NoPartition, "CO-12", partition, "P-DETECT"),
    (Mutant::NoHold, "CO-13 (PC-14)", remove, "P-HOLD"),
    (Mutant::NoRate, "CO-14 (MM-26)", flood, "P-NO-INVALID-MERGE"),
    (Mutant::NoRotation, "§6.5 (MM-7)", remove, "P-ROTATION"),
    (
        Mutant::PreCommitGeneration,
        "§6.5 (MM-8)",
        remove,
        "P-ROTATION",
    ),
    (
        Mutant::RejoinNoFreshness,
        "§6.7 (MM-20)",
        replay_join,
        "P-REJOIN-SAFE",
    ),
];

/// Every mutant breaks the property its row names, in a real exhaustive run (a budget overflow or
/// another property is not a kill).
#[test]
fn em3_every_mutant_is_killed_by_its_named_property() {
    // The report's lines start at column 0 (libtest prints "test <name> ... " first).
    println!();
    let budget = budget();
    let results = parallel(MUTANTS.to_vec(), |(m, rule, build, killer)| {
        let s = build(Rules::mutant(m), scale());
        let t = Instant::now();
        let r = explore(&s.cfg, s.start, budget);
        (m, rule, killer, s.cfg.name, r, t.elapsed())
    });
    let mut killed = 0;
    let mut failures = Vec::new();
    for (m, rule, killer, name, r, took) in &results {
        match r {
            Err(stop) if stop.property() == Some(killer) => {
                killed += 1;
                let trace_len = match stop {
                    Stop::Property { trace, .. } => trace.len(),
                    Stop::Budget(_) => 0,
                };
                println!(
                    "EM-3 mutant {m:?} [{rule}]: killed by {killer} in {name} ({trace_len} steps, \
                     {:.2} s)",
                    took.as_secs_f64()
                );
            }
            Err(stop) => {
                println!(
                    "EM-3 mutant {m:?} [{rule}]: NOT killed by {killer}\n{}",
                    stop.render()
                );
                failures.push(format!("{m:?}: expected {killer}, got {}", stop.render()));
            }
            Ok(o) => {
                println!(
                    "EM-3 mutant {m:?} [{rule}]: SURVIVED {name} ({} states)",
                    o.states
                );
                failures.push(format!("{m:?}: survived {name}"));
            }
        }
    }
    println!(
        "EM-3 mutants ({}): {} run, {} killed",
        scale_name(),
        results.len(),
        killed
    );
    assert!(
        failures.is_empty(),
        "EM-3 mutants:\n{}",
        failures.join("\n")
    );
}

/// The quantitative halves of the abstractions (ordinal time, store-hour anchors, day clocks).
#[test]
fn em3_arithmetic_of_the_abstractions() {
    // The report's lines start at column 0 (libtest prints "test <name> ... " first).
    println!();
    let all = arith::all();
    for a in &all {
        println!(
            "EM-3 arithmetic {}: {} cases, smallest margin {}",
            a.name, a.cases, a.margin
        );
        assert!(a.margin >= 0, "{}: margin {}", a.name, a.margin);
    }
    println!("EM-3 arithmetic: {} checks hold", all.len());
}

/// A finding probe: the shortest counter-example (breadth-first), which must break `property`.
fn expect_violation(s: &Scenario, property: &str) -> String {
    match explore_shortest(&s.cfg, s.start, budget()) {
        Err(stop) if stop.property() == Some(property) => stop.render(),
        Err(stop) => panic!("{}: expected {property}, got {}", s.cfg.name, stop.render()),
        Ok(o) => panic!(
            "{}: expected {property} under the design, no violation in {} states",
            s.cfg.name, o.states
        ),
    }
}

fn expect_clean(s: &Scenario) -> Outcome {
    match explore(&s.cfg, s.start, budget()) {
        Ok(o) => o,
        Err(stop) => panic!("{}: {}", s.cfg.name, stop.render()),
    }
}

/// Finding F-1 (§19.34): with nothing withheld and no adversary, an honest committer that passes
/// while it holds another member's candidate (CO-7 allows it for any candidate of a higher rank
/// number) creates a candidate that members which already settled see only as a late one. (a) Its
/// copy is verified before its own settle point: its own commit wins there and it forks off. (b) Its
/// copy is not yet verified there: CO-3 demotes it, the held candidate wins, CO-4 (b) clears it, and
/// the copy lands afterwards and wins at members that settle later; the committer is stranded. The
/// correction proposed (`Fix::SettleBeforePass`) removes both in the same scenarios.
#[test]
fn em3_finding_f1_a_pass_over_a_held_candidate_forks_the_channel() {
    // The report's lines start at column 0 (libtest prints "test <name> ... " first).
    println!();
    let mut s = concurrency(Rules::DESIGN, scale());
    s.cfg.terminal |= T_HONEST_ONE_BRANCH;
    let trace = expect_violation(&s, "P-ONE-BRANCH");
    println!("EM-3 finding F-1 (a) reproduced (design rules):\n{trace}");
    let s = remove_over_held(Rules::DESIGN, scale());
    let trace = expect_violation(&s, "P-STRANDED");
    println!("EM-3 finding F-1 (b) reproduced (design rules):\n{trace}");
    let mut fixed = concurrency(Rules::DESIGN.with_fix(Fix::SettleBeforePass), scale());
    fixed.cfg.terminal |= T_HONEST_ONE_BRANCH;
    let o = expect_clean(&fixed);
    let fixed_b = remove_over_held(Rules::DESIGN.with_fix(Fix::SettleBeforePass), scale());
    let ob = expect_clean(&fixed_b);
    println!(
        "EM-3 finding F-1 corrected (SettleBeforePass): (a) {} states, no fork; (b) {} states, no \
         stranded committer",
        o.states, ob.states
    );
}

/// Finding F-2 (§19.34): in a quiet channel no candidate has successor senders, so a member that
/// settles after a late or ground commit arrived decides by (rank, hash) alone. (a) A member that
/// kept an old epoch's state grinds a self-update below the settled winner; a returning member
/// merges it. (b) The owner's session ends between its pass and its store; its better-ranked commit
/// lands after the others settled the moderator's; the owner and a returning member merge it (run
/// under F-1's correction: the two findings are independent). §19.1's "a late copy is harmless" and
/// "makes a late or ground commit lose unless other members continued it" hold only when the
/// winner has a successor (the control SC-GRIND, with one, holds); L8-C21 declares only the
/// two-member collusion.
#[test]
fn em3_finding_f2_a_late_or_ground_commit_diverts_members_in_a_quiet_channel() {
    // The report's lines start at column 0 (libtest prints "test <name> ... " first).
    println!();
    let s = grind(Rules::DESIGN, scale(), true);
    let trace = expect_violation(&s, "P-ONE-BRANCH");
    println!("EM-3 finding F-2 (a) reproduced (design rules):\n{trace}");
    let s = late_quiet(Rules::DESIGN.with_fix(Fix::SettleBeforePass), scale());
    let trace = expect_violation(&s, "P-ONE-BRANCH");
    println!("EM-3 finding F-2 (b) reproduced (design rules with F-1's correction):\n{trace}");
    // The mitigation proposed: settle beacons close (a), not (b) when the winner's author alone
    // settled before the late copy landed (the split the 20-minute window cannot prevent).
    let fixed_a = grind(Rules::DESIGN.with_fix(Fix::SettleBeacon), scale(), true);
    let oa = expect_clean(&fixed_a);
    println!(
        "EM-3 finding F-2 (a) closed by settle beacons (SettleBeacon): {} states, no fork",
        oa.states
    );
    let s = late_quiet(
        Rules::DESIGN
            .with_fix(Fix::SettleBeforePass)
            .with_fix(Fix::SettleBeacon),
        scale(),
    );
    let trace = expect_violation(&s, "P-ONE-BRANCH");
    println!("EM-3 finding F-2 (b) remains with settle beacons (declared residual):\n{trace}");
}

/// Finding F-3 (§19.34): SCN-CL's detection claims fail under CO-11 and CO-12 as written. A subset
/// of two members cut off from the removing commit sees one other member's messages, so it raises
/// neither `partition_suspected` (two other members needed) nor `stale_suspected`; and the majority
/// sees the subset's posts only in the draining namespace, which CO-11 no longer counts (§19.15
/// (c)), so it never raises `split_suspected`. With both corrections proposed the claims hold.
#[test]
fn em3_finding_f3_scn_cl_detection_claims_fail_as_written() {
    // The report's lines start at column 0 (libtest prints "test <name> ... " first).
    println!();
    // (a) the majority's split_suspected, with the subset's half corrected.
    let s = withheld_removal(Rules::DESIGN.with_fix(Fix::PartitionOneOther), scale());
    let trace = expect_violation(&s, "P-SCN-CL-SPLIT");
    println!("EM-3 finding F-3 (a) reproduced (design rules, F-3 (b) corrected):\n{trace}");
    // (b) the subset's partition_suspected, with the majority's half corrected.
    let s = withheld_removal(Rules::DESIGN.with_fix(Fix::SplitCountsDraining), scale());
    let trace = expect_violation(&s, "P-SCN-CL-PARTITION");
    println!("EM-3 finding F-3 (b) reproduced (design rules, F-3 (a) corrected):\n{trace}");
    let fixed = withheld_removal(
        Rules::DESIGN
            .with_fix(Fix::PartitionOneOther)
            .with_fix(Fix::SplitCountsDraining),
        scale(),
    );
    let o = expect_clean(&fixed);
    println!(
        "EM-3 finding F-3 corrected (PartitionOneOther, SplitCountsDraining): {} states",
        o.states
    );
}

/// Finding F-4 (§19.34): CO-4 (i) anchors the window at "the member's first sighting" of a held
/// candidate without saying when a committer first sights its own commit. Read as the pass that
/// built it (the `ch_candidate` row's creation), the committer's window can elapse before its own
/// copy is stored; it then waits (CO-4 (a)) and settles at the op's verification on what its last
/// listing pass left it, missing candidates stored since (P-FRESH), and the 20-minute argument of
/// D8 (T1) fails for the committer itself. EM-3's normative reading is "the listing pass that
/// fetches its stored copy" ("the copy it fetched", CO-4 (i)); the other reading is the mutant
/// `OwnAnchorAtPass`, printed here with its shortest counter-example.
#[test]
fn em3_finding_f4_the_own_commit_anchor_must_be_its_fetched_copy() {
    // The report's lines start at column 0 (libtest prints "test <name> ... " first).
    println!();
    let s = late(Rules::mutant(Mutant::OwnAnchorAtPass), scale());
    let trace = expect_violation(&s, "P-FRESH");
    println!("EM-3 finding F-4 reproduced (the pass-time reading of CO-4 (i)):\n{trace}");
}

/// Finding F-5 (§19.34): CO-3 ranks a committer's own commit without a verified copy below every
/// held foreign candidate, and an op closed INDETERMINATE (the receipt lost) leaves it unverified
/// even when the copy reached the relays. Every other member then holds it and picks it by rank,
/// while its committer picks the foreign candidate and clears it: stranded, with no late copy, no
/// partition and no adversary. The correction (`Fix::FetchedOwnCopy`): a copy the committer
/// fetched (recognised by its hash) is a verified copy. Its run carries F-1's correction too: the
/// probe's P-STRANDED has no premise, and a pass over a held candidate strands as well (F-1 (b)).
#[test]
fn em3_finding_f5_an_indeterminate_copy_others_hold_strands_its_committer() {
    // The report's lines start at column 0 (libtest prints "test <name> ... " first).
    println!();
    let s = indet_competing(Rules::DESIGN, scale());
    let trace = expect_violation(&s, "P-STRANDED");
    println!("EM-3 finding F-5 reproduced (design rules):\n{trace}");
    let fixed = indet_competing(
        Rules::DESIGN
            .with_fix(Fix::FetchedOwnCopy)
            .with_fix(Fix::SettleBeforePass),
        scale(),
    );
    let o = expect_clean(&fixed);
    println!(
        "EM-3 finding F-5 corrected (FetchedOwnCopy, with SettleBeforePass): {} states, no \
         stranded committer",
        o.states
    );
}

/// Reruns every control scenario under `rules` at `scale`; returns the failures (a property, a
/// budget overflow or an unreached flow) and prints one line per scenario with label `label`.
fn rerun_controls(rules: Rules, scale: Scale, label: &str) -> (usize, Vec<String>) {
    let budget = budget();
    let results = parallel(controls(rules, scale), |s| {
        let r = explore(&s.cfg, s.start, budget);
        (s, r)
    });
    let mut failures = Vec::new();
    for (s, r) in &results {
        match r {
            Ok(o) => {
                let missing: Vec<&str> = s
                    .reach
                    .iter()
                    .filter(|(ev, _)| o.events & ev == 0)
                    .map(|(_, w)| *w)
                    .collect();
                println!(
                    "EM-3 {label} {}: {} states, {} transitions, reach {}/{}",
                    s.cfg.name,
                    o.states,
                    o.transitions,
                    s.reach.len() - missing.len(),
                    s.reach.len()
                );
                if !missing.is_empty() {
                    failures.push(format!("{}: unreached {missing:?}", s.cfg.name));
                }
            }
            Err(stop) => failures.push(format!("{}: {}", s.cfg.name, stop.render())),
        }
    }
    (results.len(), failures)
}

/// The corrections proposed for F-1, F-3 and F-5 keep every control scenario's properties and
/// flows, at the run's scale; F-2's settle beacons (an option for the owner, not a correction) at
/// the PR bound, where they already multiply some state spaces by up to 400 (SC-GOV).
#[test]
fn em3_proposed_corrections_keep_every_control() {
    // The report's lines start at column 0 (libtest prints "test <name> ... " first).
    println!();
    let rules = Rules::DESIGN
        .with_fix(Fix::SettleBeforePass)
        .with_fix(Fix::PartitionOneOther)
        .with_fix(Fix::SplitCountsDraining)
        .with_fix(Fix::FetchedOwnCopy);
    let (n, mut failures) = rerun_controls(rules, scale(), "corrected");
    let (nb, fb) = rerun_controls(rules.with_fix(Fix::SettleBeacon), Scale::Pr, "beacons");
    println!(
        "EM-3 corrections: {n} controls rerun with F-1's, F-3's and F-5's corrections ({}), {nb} \
         with F-2's beacons too (pr), {} failures",
        scale_name(),
        failures.len() + fb.len()
    );
    failures.extend(fb);
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
