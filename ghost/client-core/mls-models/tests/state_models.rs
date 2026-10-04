//! EM-3 runs: every control scenario under the design's rules with its reachability queries, every
//! mutant against its named killer, the finding probes, the quantitative checks, and the self-check
//! that every check site is the first violation of some registered run. Lines that start with
//! `EM-3 ` are the report (`channel-state-models.yml` greps them into the job summary and
//! `ch-state-models-check.sh` checks them, at the PR bound in the `rust` job of `ci.yml`).
//!
//! Scale: `EM3_SCALE=full` (the workflow) or the PR bound (default, the `rust` job). Budget:
//! `EM3_BUDGET` states per exploration (5 million at the PR bound, 55 million at the full one; a
//! run that reaches it fails: a budget overflow is not a verdict). `EM3_THREADS`: explorations at
//! once (default: every core). Run with `--nocapture --test-threads 1` for the report.

use std::sync::Mutex;
use std::time::Instant;

use ghost_client_mls_models::arith;
use ghost_client_mls_models::model::*;
use ghost_client_mls_models::props::{self, *};
use ghost_client_mls_models::rules::{Fix, Mutant, Rules};
use ghost_client_mls_models::scenarios::*;
use ghost_client_mls_models::search::*;
use ghost_client_mls_models::step::{successors, Action};

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
            Scale::Full => 55_000_000,
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

/// The terminal properties a control checks, each with the quiescent states where its premise held
/// ("live"): every one must be live somewhere, or the property held vacuously (§19.34.1 item 12) —
/// except P-DETECT's clauses, obligations a correct run discharges by acting on them (the member
/// rejoins, which starts its ghosts over), whose evidence is the scenario's reachability query and
/// the mutants they kill.
fn live_report(s: &Scenario, o: &Outcome) -> (String, Vec<&'static str>) {
    let mut text = Vec::new();
    let mut dead = Vec::new();
    for &(bit, name) in TERMINAL_NAMES {
        if s.cfg.terminal & bit == 0 {
            continue;
        }
        let n = o.live_of(bit);
        text.push(format!("{name} {n}/{}", o.terminal));
        if n == 0 && !name.starts_with("P-DETECT/") {
            dead.push(name);
        }
    }
    if text.is_empty() {
        text.push("none".to_string());
    }
    (text.join(" "), dead)
}

fn list(v: &[u8]) -> String {
    v.iter()
        .map(|x| x.to_string())
        .collect::<Vec<_>>()
        .join(",")
}

/// The bounds a control reached against those it was given (§19.34.1 item 14).
fn bounds_report(s: &Scenario, o: &Outcome) -> String {
    let r = &o.reached;
    format!(
        "epochs {}/{}, commits {} of {}, posts {} of {}, days {}/{}",
        r.epochs,
        s.cfg.depth,
        list(&r.commits),
        list(&s.cfg.commit_budget),
        list(&r.posts),
        list(&s.cfg.post_budget),
        r.days,
        s.cfg.days
    )
}

/// Every control scenario holds every property under the design's rules, reaches every honest flow
/// it names (without the reachability queries the safety properties could hold vacuously), and
/// meets the premise of every terminal property it checks in some quiescent state.
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
    let mut deepest: (usize, Vec<&str>) = (0, Vec::new());
    let mut commits = 0u8;
    let mut posts = 0u8;
    let mut days = 0u8;
    for (s, r, took) in &results {
        match r {
            Ok(o) => {
                let missing: Vec<&str> = s
                    .reach
                    .iter()
                    .filter(|(ev, _)| o.events & ev == 0)
                    .map(|(_, what)| *what)
                    .collect();
                let (live, dead) = live_report(s, o);
                println!(
                    "EM-3 {}: {} states, {} transitions, {} decisions, {} terminal, depth {}, \
                     reach {}/{}, live {live}, bounds {}, {:.1} s",
                    s.cfg.name,
                    o.states,
                    o.transitions,
                    o.decisions,
                    o.terminal,
                    o.max_depth,
                    s.reach.len() - missing.len(),
                    s.reach.len(),
                    bounds_report(s, o),
                    took.as_secs_f64()
                );
                for m in &missing {
                    failures.push(format!("{}: unreached: {m}", s.cfg.name));
                }
                for d in &dead {
                    failures.push(format!("{}: {d} never had its premise", s.cfg.name));
                }
                totals.states += o.states;
                totals.transitions += o.transitions;
                totals.decisions += o.decisions;
                totals.terminal += o.terminal;
                let short = s.cfg.name.split(' ').next().unwrap_or("");
                if o.reached.epochs > deepest.0 {
                    deepest = (o.reached.epochs, vec![short]);
                } else if o.reached.epochs == deepest.0 {
                    deepest.1.push(short);
                }
                commits = commits.max(*o.reached.commits.iter().max().unwrap_or(&0));
                posts = posts.max(*o.reached.posts.iter().max().unwrap_or(&0));
                days = days.max(o.reached.days);
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
    println!(
        "EM-3 bounds ({}): at most {} epoch transitions (reached by {}), {} commits and {} posts \
         per actor, {} days",
        scale_name(),
        deepest.0,
        deepest.1.join(", "),
        commits,
        posts,
        days
    );
    assert!(
        failures.is_empty(),
        "EM-3 controls:\n{}",
        failures.join("\n")
    );
}

type Build = fn(Rules, Scale) -> Scenario;

/// One mutant per rule (CO-1 … CO-14, §6.2.4, §6.5, §6.7), each with the scenario and the check
/// site that kill it. The control of every row is that scenario under the design's rules (the test
/// above).
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
        Mutant::Rank255NeverCandidate,
        "CO-1 (rank-255 candidates)",
        concurrency,
        "P-CONC",
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
        "P-CUSTODY/clear",
    ),
    (Mutant::NoListingPass, "CO-4 (ii)", concurrency, "P-FRESH"),
    (
        Mutant::OwnAnchorAtPass,
        "CO-4 (i) (own commit's anchor)",
        late,
        "P-FRESH",
    ),
    (
        Mutant::UnverifiedOwnNoCandidate,
        "CO-3, CO-4 (a) (round 10b's custody)",
        indeterminate,
        "P-CUSTODY/settle",
    ),
    (Mutant::WelcomeAtPass, "CO-5 (MM-19)", join, "P-WELCOME"),
    (Mutant::NotSticky, "CO-6 (MM-16)", late, "P-STICKY"),
    (Mutant::Rank255Blocks, "CO-7 (MM-26)", flood, "P-PASS"),
    (Mutant::FreshWork, "CO-8 (MM-34)", join, "P-WORKAGE"),
    (Mutant::NoSkip, "CO-9", concurrency, "P-OWN-VALID"),
    (Mutant::DropLoserWork, "CO-10", remove, "P-LIVENESS/remove"),
    (
        Mutant::CountDraining,
        "CO-11 (MM-37)",
        spam_drain,
        "P-NO-FALSE-RESYNC",
    ),
    (Mutant::NoBranchDeath, "CO-11", fork, "P-DETECT/resync"),
    (
        Mutant::RecountProgress,
        "CO-11 (b) (EM-3's first count)",
        missed,
        "P-DETECT/resync",
    ),
    (Mutant::NoStale, "CO-12 (MM-36)", silent, "P-DETECT/stale"),
    (
        Mutant::NoPartition,
        "CO-12",
        partition,
        "P-DETECT/partition",
    ),
    (
        Mutant::RecountStale,
        "CO-12 (EM-3's first stale clock)",
        silent,
        "P-DETECT/stale",
    ),
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
        Mutant::RejoinRotates,
        "§6.5 (rejoin swap)",
        owner,
        "P-REJOIN-SAFE/rotates",
    ),
    (Mutant::NoAdmission, "§6.2.4 (B)", join, "P-JOINED"),
    (
        Mutant::RejoinNoFreshness,
        "§6.7 (MM-20)",
        replay_join,
        "P-REJOIN-SAFE/live-leaf",
    ),
];

/// Every mutant breaks the check site its row names, as the first violation of a real exhaustive
/// run (a budget overflow, another property or another site of the same property is not a kill).
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
            Err(Stop::Property { violation, trace }) if violation.site == *killer => {
                killed += 1;
                println!(
                    "EM-3 mutant {m:?} [{rule}]: killed by {killer} in {name} ({} steps, {:.2} s)",
                    trace.len(),
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

/// A finding probe, whose first violation must be check site `site`. At the PR bound the search is
/// breadth-first, so the counter-example is a shortest one (§19.34 quotes them); at the full bound
/// it is depth-first, which holds one fingerprint per state where a breadth-first frontier of
/// full-bound worlds held gigabytes, so its counter-example need not be the shortest.
fn expect_violation(s: &Scenario, site: &str) -> String {
    let run = match scale() {
        Scale::Pr => explore_shortest(&s.cfg, s.start, budget()),
        Scale::Full => explore(&s.cfg, s.start, budget()),
    };
    match run {
        Err(Stop::Property { violation, trace }) if violation.site == site => {
            Stop::Property { violation, trace }.render()
        }
        Err(stop) => panic!("{}: expected {site}, got {}", s.cfg.name, stop.render()),
        Ok(o) => panic!(
            "{}: expected {site}, no violation in {} states",
            s.cfg.name, o.states
        ),
    }
}

/// A corrected run: no violation, and every flow its scenario names is reached.
fn expect_clean(s: &Scenario) -> Outcome {
    match explore(&s.cfg, s.start, budget()) {
        Ok(o) => {
            let missing: Vec<&str> = s
                .reach
                .iter()
                .filter(|(ev, _)| o.events & ev == 0)
                .map(|(_, w)| *w)
                .collect();
            assert!(
                missing.is_empty(),
                "{}: clean but unreached {missing:?}",
                s.cfg.name
            );
            o
        }
        Err(stop) => panic!("{}: {}", s.cfg.name, stop.render()),
    }
}

/// A finding probe's run: a violation of a named check site expected, or a clean corrected run.
enum Probe {
    Violation(Scenario, &'static str),
    Clean(Scenario),
}

/// What a probe produced: the counter-example of a violation probe, the states of a clean one.
enum Probed {
    Trace(String),
    Clean(usize),
}

impl Probed {
    fn trace(&self) -> &str {
        match self {
            Probed::Trace(t) => t,
            Probed::Clean(_) => unreachable!("a clean run has no trace"),
        }
    }

    fn states(&self) -> usize {
        match self {
            Probed::Clean(states) => *states,
            Probed::Trace(_) => unreachable!("a violation probe has no clean outcome"),
        }
    }
}

/// Runs a finding's probes at once (results in order); each panics as `expect_violation` and
/// `expect_clean` do.
fn probes(v: Vec<Probe>) -> Vec<Probed> {
    parallel(v, |p| match p {
        Probe::Violation(s, site) => Probed::Trace(expect_violation(&s, site)),
        Probe::Clean(s) => Probed::Clean(expect_clean(&s).states),
    })
}

/// F-1's correction, both halves (CO-7's pass, CO-9's self-update).
fn f1() -> Rules {
    Rules::DESIGN
        .with_fix(Fix::SettleBeforePass)
        .with_fix(Fix::SelfUpdateAfterSettle)
}

/// Finding F-1 (§19.34, §19.34.1 item 3): with nothing withheld and no adversary, an honest
/// committer that passes while it holds another member's candidate (CO-7 allows it for any
/// candidate of a higher rank number) creates a candidate that members which already settled see
/// only as a late one. (a) Its copy is verified before its own settle point: its own commit wins
/// there and it forks off. (b) Its copy is not yet verified there: CO-3 demotes it, the held
/// candidate wins, CO-4 (b) clears it, and the copy lands afterwards and wins at members that
/// settle later; the committer is stranded. (c) CO-7's text alone is not the correction: a rank-255
/// member's self-update over a held candidate forks the same way, so CO-9 needs the same clause.
/// The correction (both halves) removes all three in the same scenarios, with their flows.
#[test]
fn em3_finding_f1_a_pass_over_a_held_candidate_forks_the_channel() {
    // The report's lines start at column 0 (libtest prints "test <name> ... " first).
    println!();
    let mut a = concurrency(Rules::DESIGN, scale());
    a.cfg.terminal |= T_HONEST_ONE_BRANCH;
    let mut fixed = concurrency(f1(), scale());
    fixed.cfg.terminal |= T_HONEST_ONE_BRANCH;
    let r = probes(vec![
        Probe::Violation(a, "P-ONE-BRANCH"),
        Probe::Violation(remove_over_held(Rules::DESIGN, scale()), "P-STRANDED"),
        Probe::Violation(
            concurrency_eligible(Rules::DESIGN.with_fix(Fix::SettleBeforePass), scale()),
            "P-ONE-BRANCH",
        ),
        Probe::Clean(fixed),
        Probe::Clean(remove_over_held(f1(), scale())),
        Probe::Clean(concurrency_eligible(f1(), scale())),
    ]);
    println!(
        "EM-3 finding F-1 (a) reproduced (design rules):\n{}",
        r[0].trace()
    );
    println!(
        "EM-3 finding F-1 (b) reproduced (design rules):\n{}",
        r[1].trace()
    );
    println!(
        "EM-3 finding F-1 (c) reproduced (CO-7's half of the correction alone):\n{}",
        r[2].trace()
    );
    println!(
        "EM-3 finding F-1 corrected (SettleBeforePass, SelfUpdateAfterSettle): (a) {} states, no \
         fork; (b) {} states, no stranded committer; (c) {} states, no fork; every flow reached",
        r[3].states(),
        r[4].states(),
        r[5].states()
    );
}

/// Finding F-2 (§19.34, §19.34.1 item 2): a member that settles an epoch after a late or ground
/// commit for it was stored, and holds no successor sender of the winner the earlier settlers
/// merged — a returning or backgrounded member, the late copy's own committer, or the winner's own
/// author — decides by `(rank, hash)` alone. (a) In the scripted quiet probe a member that kept an
/// old epoch's state grinds below the settled winner and a returning member merges it. (b) The
/// owner's session ends between its pass and its store; its better-ranked commit lands after the
/// others settled the moderator's (run under F-1's correction: the findings are independent). (c)
/// SC-GRIND itself, with C0's post allowed: the post comes too late (in epoch e, or after another
/// member settled) and the members that settle after the ground store follow it. Settle beacons
/// close (a) only: with them (b) and (c) remain, because a member that settles after the late store
/// with no beacon of the winner yet sends its own beacon for the late commit. SC-GRIND holds
/// P-LATE-HARMLESS, whose premise is exactly "every such member held a successor of the winner".
#[test]
fn em3_finding_f2_a_late_or_ground_commit_diverts_members_in_a_quiet_channel() {
    // The report's lines start at column 0 (libtest prints "test <name> ... " first).
    println!();
    let beacons = Rules::DESIGN.with_fix(Fix::SettleBeacon);
    let r = probes(vec![
        Probe::Violation(grind(Rules::DESIGN, scale(), true), "P-ONE-BRANCH"),
        Probe::Violation(late_quiet(f1(), scale()), "P-ONE-BRANCH"),
        Probe::Violation(grind_unanchored(Rules::DESIGN, scale()), "P-ONE-BRANCH"),
        Probe::Clean(grind(beacons, scale(), true)),
        Probe::Violation(
            late_quiet(f1().with_fix(Fix::SettleBeacon), scale()),
            "P-ONE-BRANCH",
        ),
        Probe::Violation(grind_unanchored(beacons, scale()), "P-ONE-BRANCH"),
    ]);
    println!(
        "EM-3 finding F-2 (a) reproduced (design rules):\n{}",
        r[0].trace()
    );
    println!(
        "EM-3 finding F-2 (b) reproduced (design rules with F-1's correction):\n{}",
        r[1].trace()
    );
    println!(
        "EM-3 finding F-2 (c) reproduced (SC-GRIND with its post; design rules):\n{}",
        r[2].trace()
    );
    println!(
        "EM-3 finding F-2 (a) closed by settle beacons in the scripted probe (SettleBeacon): {} \
         states, no fork",
        r[3].states()
    );
    println!(
        "EM-3 finding F-2 (b) remains with settle beacons (declared residual):\n{}",
        r[4].trace()
    );
    println!(
        "EM-3 finding F-2 (c) remains with settle beacons:\n{}",
        r[5].trace()
    );
}

/// Finding F-3 (§19.34, §19.34.1 items 1 and 4): SCN-CL's detection claims fail under CO-11 and
/// CO-12 as written. A subset of two members cut off from the removing commit hears one other
/// member, so it raises neither `partition_suspected` (two other members needed) nor, while its
/// members keep posting, `stale_suspected` (each message first opened restarts that clock: one post
/// opened on day 1 is enough within the bound); and the majority sees the subset's posts only in
/// the draining namespace, which CO-11 no longer counts (§19.15 (c)), so it never raises
/// `split_suspected`. The majority makes no progress either, so F-3 (a)'s correction must not
/// require it: as first worded ("while progress continues") it fails the same probe. With both
/// corrections the claims hold and both flags rise.
#[test]
fn em3_finding_f3_scn_cl_detection_claims_fail_as_written() {
    // The report's lines start at column 0 (libtest prints "test <name> ... " first).
    println!();
    let both = Rules::DESIGN
        .with_fix(Fix::PartitionOneOther)
        .with_fix(Fix::SplitCountsDraining);
    let r = probes(vec![
        Probe::Violation(
            withheld_removal(Rules::DESIGN.with_fix(Fix::PartitionOneOther), scale()),
            "P-SCN-CL-SPLIT",
        ),
        Probe::Violation(
            withheld_removal(Rules::DESIGN.with_fix(Fix::SplitCountsDraining), scale()),
            "P-SCN-CL-PARTITION",
        ),
        Probe::Violation(
            withheld_removal(both.with_fix(Fix::SplitNeedsProgress), scale()),
            "P-SCN-CL-SPLIT",
        ),
        Probe::Clean(withheld_removal(both, scale())),
    ]);
    println!(
        "EM-3 finding F-3 (a) reproduced (design rules, F-3 (b) corrected):\n{}",
        r[0].trace()
    );
    println!(
        "EM-3 finding F-3 (b) reproduced (design rules, F-3 (a) corrected):\n{}",
        r[1].trace()
    );
    println!(
        "EM-3 finding F-3 (a) as first worded fails (\"while progress continues\"):\n{}",
        r[2].trace()
    );
    println!(
        "EM-3 finding F-3 corrected (PartitionOneOther, SplitCountsDraining): {} states, both \
         flags raised",
        r[3].states()
    );
}

/// Finding F-4 (§19.34, §19.34.1 item 5): CO-4 (i) anchors the window at "the member's first
/// sighting" of a held candidate without saying when a committer first sights its own commit. Read
/// as the pass that built it (the mutant `OwnAnchorAtPass`), the committer's window can elapse
/// before its own copy is stored; after CO-4 (a)'s wait it settles at the op's verification on
/// what its last listing pass left it, without a candidate stored since (P-FRESH, CO-4 (ii)'s
/// restatement). With P-FRESH switched off and the moderator's process allowed to die between its
/// pass and its store, the consequence shows: the moderator settles its own commit at its store
/// without the owner's, and the others follow the owner's — a fork with no late copy. EM-3's
/// reading ("the listing pass that fetched its stored copy") is clean in the same run.
#[test]
fn em3_finding_f4_the_own_commit_anchor_must_be_its_fetched_copy() {
    // The report's lines start at column 0 (libtest prints "test <name> ... " first).
    println!();
    let at_pass = Rules::mutant(Mutant::OwnAnchorAtPass);
    let r = probes(vec![
        Probe::Violation(late(at_pass, scale()), "P-FRESH"),
        Probe::Violation(late_f4(at_pass, scale()), "P-LATE-HARMLESS"),
        Probe::Clean(late_f4(Rules::DESIGN, scale())),
    ]);
    println!(
        "EM-3 finding F-4 reproduced (the pass-time reading of CO-4 (i)):\n{}",
        r[0].trace()
    );
    println!(
        "EM-3 finding F-4 consequence (P-FRESH off, the moderator's process may die):\n{}",
        r[1].trace()
    );
    println!(
        "EM-3 finding F-4 fetched-copy reading clean in the same run: {} states",
        r[2].states()
    );
}

/// Finding F-5 (§19.34): CO-3 ranks a committer's own commit without a verified copy below every
/// held foreign candidate, and an op closed INDETERMINATE (the receipt lost) leaves it unverified
/// even when the copy reached the relays. Every other member then holds it and picks it by rank,
/// while its committer picks the foreign candidate and clears it: stranded, with no late copy, no
/// partition and no adversary. The correction (`Fix::FetchedOwnCopy`): a copy the committer
/// fetched (recognised by its hash) is a verified copy. Its run carries F-1's correction too: the
/// probe's P-STRANDED has no premise, and a pass over a held candidate strands as well (F-1 (b)).
/// Under F-1's and F-5's corrections MM-2 (`OwnUnverified`) changes no decision: it survives every
/// control and the probes, rerun at the PR bound's scenarios in the full bound's job (§19.34.1
/// item 5, decision D-5).
#[test]
fn em3_finding_f5_an_indeterminate_copy_others_hold_strands_its_committer() {
    // The report's lines start at column 0 (libtest prints "test <name> ... " first).
    println!();
    let r = probes(vec![
        Probe::Violation(indet_competing(Rules::DESIGN, scale()), "P-STRANDED"),
        Probe::Clean(indet_competing(f1().with_fix(Fix::FetchedOwnCopy), scale())),
    ]);
    println!(
        "EM-3 finding F-5 reproduced (design rules):\n{}",
        r[0].trace()
    );
    println!(
        "EM-3 finding F-5 corrected (FetchedOwnCopy, with F-1's correction): {} states, no \
         stranded committer",
        r[1].states()
    );
    if scale() != Scale::Full {
        return;
    }
    // MM-2 under the corrections, at the PR bound's scenarios.
    let corrected = Rules {
        mutant: Some(Mutant::OwnUnverified),
        ..corrections()
    };
    let mut runs = controls(corrected, Scale::Pr);
    runs.push(indet_competing(corrected, Scale::Pr));
    runs.push(remove_over_held(corrected, Scale::Pr));
    runs.push(concurrency_eligible(corrected, Scale::Pr));
    let n = runs.len();
    let budget = budget();
    let results = parallel(runs, |s| (s.cfg.name, explore(&s.cfg, s.start, budget)));
    let killed: Vec<String> = results
        .iter()
        .filter_map(|(name, r)| {
            r.as_ref()
                .err()
                .map(|stop| format!("{name}: {}", stop.render()))
        })
        .collect();
    assert!(
        killed.is_empty(),
        "MM-2 under the corrections is killed after all:\n{}",
        killed.join("\n")
    );
    println!(
        "EM-3 finding F-5 leaves MM-2 equivalent: OwnUnverified with F-1's, F-3's and F-5's \
         corrections survives {n} runs (the pr scenarios; decision D-5)"
    );
}

/// F-1's, F-3's and F-5's corrections together (F-2's beacons are an option, not a correction).
fn corrections() -> Rules {
    f1().with_fix(Fix::PartitionOneOther)
        .with_fix(Fix::SplitCountsDraining)
        .with_fix(Fix::FetchedOwnCopy)
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
/// flows (the flows their scenarios name under the corrected rules: a pass over a held candidate
/// becomes a settle and a pass, an INDETERMINATE own commit whose copy is fetched never waits), at
/// the run's scale. F-2's settle beacons (an option for the owner, not a correction) rerun every
/// control at the PR bound's scenarios in the full bound's job only: they multiply some state
/// spaces by up to 300 (SC-GOV) and SC-JOIN's and SC-CLOCKS' two epochs take some 7 million states
/// each, beyond the PR job's budget.
#[test]
fn em3_proposed_corrections_keep_every_control() {
    // The report's lines start at column 0 (libtest prints "test <name> ... " first).
    println!();
    let rules = corrections();
    let (n, mut failures) = rerun_controls(rules, scale(), "corrected");
    let beacons = if scale() == Scale::Full {
        let (nb, fb) = rerun_controls(rules.with_fix(Fix::SettleBeacon), Scale::Pr, "beacons");
        let len = fb.len();
        failures.extend(fb);
        format!(", {nb} with F-2's beacons too (pr), {len} failures among them")
    } else {
        String::new()
    };
    println!(
        "EM-3 corrections: {n} controls rerun with F-1's, F-3's and F-5's corrections ({}){beacons}, \
         {} failures",
        scale_name(),
        failures.len()
    );
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// The check sites the finding probes produce (each asserted by its probe test above).
const PROBE_SITES: &[&str] = &[
    "P-ONE-BRANCH",
    "P-STRANDED",
    "P-SCN-CL-SPLIT",
    "P-SCN-CL-PARTITION",
    "P-LATE-HARMLESS",
    "P-FRESH",
];

/// A hand-built world that breaks one terminal check site no registered run reaches first (the
/// site is a backstop of a decision-time check).
fn hand_built_owner_pending() -> Result<(), props::Violation> {
    // The owner, online and able to pass, keeps a pending join request at a quiescent state.
    let s = remove(Rules::DESIGN, Scale::Pr);
    let mut w = s.start;
    w.m[C0].work |= W_JOIN;
    check_terminal(&w, &s.cfg, T_LIVENESS).map(|_| ())
}

fn hand_built_third_pass() -> Result<(), props::Violation> {
    // The owner has already passed twice on its user's Remove of M1 and passes again.
    let s = flood(Rules::DESIGN, Scale::Pr);
    let mut w = s.start;
    w.m[C0].work |= W_REMOVE;
    w.h.asked |= abit(C0);
    w.m[C0].tries = 2;
    let mut out = Vec::new();
    match successors(&w, &s.cfg, &mut out) {
        Err((Action::Pass { .. }, v)) => Err(v),
        Err((a, v)) => panic!("expected the owner's pass to break the check, got {a}: {v}"),
        Ok(()) => Ok(()),
    }
}

type HandBuilt = fn() -> Result<(), props::Violation>;

const HAND_BUILT: &[(&str, HandBuilt)] = &[
    ("P-LIVENESS/owner", hand_built_owner_pending),
    ("P-LIVENESS/third-pass", hand_built_third_pass),
];

/// Every check site of `props::SITES` is the expected first violation of a registered run — a
/// mutant's row, a finding probe, or a hand-built world (run here) — so deleting any check fails a
/// test (§19.34.1 item 12; the review found five sites and P-JOINED that no run could fire).
#[test]
fn em3_every_check_site_fires_in_a_registered_run() {
    // The report's lines start at column 0 (libtest prints "test <name> ... " first).
    println!();
    for &(site, build) in HAND_BUILT {
        match build() {
            Err(v) if v.site == site => {}
            Err(v) => panic!("hand-built world for {site} broke {} instead", v.site),
            Ok(()) => panic!("hand-built world for {site} broke nothing"),
        }
    }
    let mut uncovered = Vec::new();
    let mut by = [0usize; 3];
    for &site in SITES {
        if MUTANTS.iter().any(|row| row.3 == site) {
            by[0] += 1;
        } else if PROBE_SITES.contains(&site) {
            by[1] += 1;
        } else if HAND_BUILT.iter().any(|h| h.0 == site) {
            by[2] += 1;
        } else {
            uncovered.push(site);
        }
    }
    for row in MUTANTS {
        assert!(
            SITES.contains(&row.3),
            "{:?} names no site: {}",
            row.0,
            row.3
        );
    }
    for site in PROBE_SITES {
        assert!(SITES.contains(site), "a probe names no site: {site}");
    }
    println!(
        "EM-3 sites: {} check sites, {} first broken by a mutant, {} by a finding probe, {} by a \
         hand-built world, {} by none",
        SITES.len(),
        by[0],
        by[1],
        by[2],
        uncovered.len()
    );
    assert!(uncovered.is_empty(), "uncovered check sites: {uncovered:?}");
}
