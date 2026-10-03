//! The scenarios EM-3 explores exhaustively. Each is a starting world, a rule set, what may happen,
//! the terminal properties checked on its quiescent states, and the reachability queries that prove
//! its honest flows complete (without them a safety property can hold vacuously, Phase 9's lesson).
//!
//! The adversaries of §12.3 are spread over the scenarios (each explored exhaustively with the
//! actions it needs) rather than combined in one world, whose state space no run could exhaust;
//! the crate documentation maps each adversary to its scenario.

use crate::model::*;
use crate::props::*;
use crate::rules::{Fix, Rules};
use crate::search::replay;
use crate::step::*;

/// A scenario: its configuration, its starting world and its reachability queries.
#[derive(Clone)]
pub struct Scenario {
    pub cfg: Cfg,
    pub start: World,
    /// Events the design's run must reach (else its safety properties hold vacuously).
    pub reach: Vec<(u64, &'static str)>,
}

/// The scale of a run: the pull-request bound, or the full bound of the workflow.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scale {
    Pr,
    Full,
}

impl Scale {
    pub fn pick<T>(self, pr: T, full: T) -> T {
        match self {
            Scale::Pr => pr,
            Scale::Full => full,
        }
    }
}

pub const FOUR: u8 = abit(C0) | abit(C1) | abit(M0) | abit(M1);
pub const FIVE: u8 = FOUR | abit(J);

pub fn genesis(roster: u8, refresh: [u8; NA]) -> Genesis {
    Genesis {
        roster,
        committers: [C0 as u8, C1 as u8],
        refresh,
    }
}

/// Committers commit often (refresh 15); M0's leaf is old enough for a self-update at the base
/// epoch (8 + min(8, n) ≤ 16); M1's becomes eligible at epoch 18 (14 + 4).
pub const REFRESH: [u8; NA] = [15, 15, 8, 14, 8];

/// The channel at `BASE_EPOCH`: its members at the root, online, each having listed once.
pub fn base_world(roster: u8) -> World {
    let member = |a: usize| {
        let present = roster & abit(a) != 0;
        Member {
            status: if present {
                Status::Active
            } else {
                Status::Absent
            },
            chain: Chain::ROOT,
            online: present,
            listed: present,
            own: NONE,
            invite_record: true,
            ..Member::default()
        }
    };
    World {
        c: [Commit::default(); NC],
        b: [Blob::default(); NB],
        m: [member(0), member(1), member(2), member(3), member(4)],
        prompt: 0,
        h: History::default(),
        day: 0,
        healed: false,
    }
}

pub fn base_cfg(name: &'static str, rules: Rules, roster: u8) -> Cfg {
    Cfg {
        name,
        genesis: genesis(roster, REFRESH),
        rules,
        depth: 1,
        acts: A_TICK,
        post_budget: [0; NA],
        commit_budget: [0; NA],
        withhold_masks: &[],
        withhold_kinds: 0,
        withhold_slots: 0,
        honest_timing: true,
        remove_target: M1 as u8,
        remover: C0 as u8,
        leaver: M1 as u8,
        malicious: 0,
        days: 0,
        finite_kp: false,
        session_actors: 0,
        session_budget: 0,
        posters: 0,
        resigner: NONE,
        terminal: 0,
    }
}

const COMMIT_KIND: u8 = 1 << B_COMMIT;

/// SC-CONC (CO-3, CO-4, CO-10; D8): the owner's and the moderator's PCS commits and a member's
/// self-update, concurrently, every member online.
pub fn concurrency(rules: Rules, scale: Scale) -> Scenario {
    let mut cfg = base_cfg("SC-CONC concurrent honest commits", rules, FOUR);
    cfg.depth = scale.pick(1, 2);
    cfg.acts |= A_PASS | A_SELFUPDATE;
    cfg.commit_budget = [scale.pick(1, 2), scale.pick(1, 2), 1, 1, 0];
    cfg.terminal = T_CONC | T_STRANDED;
    let mut start = base_world(FOUR);
    start.m[C0].pcs = true;
    start.m[C1].pcs = true;
    start.m[M0].slot = true;
    // M1's slot comes while CO-14 refuses its self-update (14 + 4 > 16, 17): CO-9 skips it.
    start.m[M1].slot = true;
    let cfg_depth = cfg.depth;
    Scenario {
        cfg,
        start,
        reach: vec![
            (EV_SETTLE_CONCURRENT, "a settle with concurrent candidates"),
            (EV_SETTLE_RANK_DECIDED, "a settle decided by (rank, hash)"),
            (
                EV_OWN_CLEARED,
                "a losing own commit cleared at a settle point",
            ),
        ]
        .into_iter()
        .chain(pass_over_reach(
            rules,
            cfg_depth,
            "a committer passes while it holds a rank-255 candidate",
        ))
        .collect(),
    }
}

/// CO-7 lets a committer pass while it holds a rank-255 candidate; F-1's correction settles that
/// candidate first and passes in the same actor step, so its run reaches that step instead (when
/// the epoch bound leaves room for the pass).
fn pass_over_reach(rules: Rules, depth: usize, what: &'static str) -> Option<(u64, &'static str)> {
    if !rules.fixed(Fix::SettleBeforePass) {
        Some((EV_RANK255_PASS, what))
    } else if depth >= 2 {
        Some((
            EV_SETTLE_PASS,
            "a committer settles and passes in one actor step (F-1's correction)",
        ))
    } else {
        None
    }
}

/// SC-LATE (CO-6, CO-3's successors, CO-4's store-hour anchor; §19.1): the moderator's commit is
/// settled and continued; the owner's better-ranked commit is stored late (its session ended between
/// its pass and its store); M1 returns after both are old.
pub fn late(rules: Rules, scale: Scale) -> Scenario {
    let mut cfg = base_cfg("SC-LATE late better commit, returning member", rules, FOUR);
    cfg.depth = scale.pick(1, 2);
    cfg.acts |= A_PASS | A_POST | A_AGE | A_SESSIONS;
    // At PR scale the returning member stays away (SC-GRIND and SC-CATCHUP return members there).
    cfg.session_actors = abit(C0) | scale.pick(0, abit(M1));
    cfg.session_budget = 2;
    cfg.posters = abit(M0);
    cfg.post_budget = [0, 0, 1, 0, 0];
    cfg.commit_budget = [1, scale.pick(1, 2), 0, 0, 0];
    cfg.terminal = T_STRANDED;
    let mut start = base_world(FOUR);
    start.m[C0].pcs = true;
    start.m[C1].pcs = true;
    start.m[M1].online = false;
    start.m[M1].listed = false;
    Scenario {
        cfg,
        start,
        reach: vec![
            (
                EV_LATE_CANDIDATE,
                "a late candidate recorded by a settled member (CO-6)",
            ),
            (
                EV_SUCCESSORS_DECIDED,
                "a settle decided by successor senders",
            ),
            (
                EV_CATCHUP,
                "a returning member settles at its first listing pass",
            ),
            (EV_OWN_CLEARED, "the late committer clears its own commit"),
        ],
    }
}

/// SC-GRIND (§19.1 (b)): a member keeps an old epoch's state and grinds a self-update below the
/// settled rank-255 winner; C1 returns after both are old; C0 may continue the winner. The quiet
/// variant (no post) is finding F-2's probe.
pub fn grind(rules: Rules, scale: Scale, quiet: bool) -> Scenario {
    let name = if quiet {
        "F-2 ground self-update in a quiet channel"
    } else {
        "SC-GRIND ground self-update below a settled winner"
    };
    if quiet {
        return grind_quiet(rules, scale, name);
    }
    let mut cfg = base_cfg(name, rules, FOUR);
    cfg.genesis = genesis(FOUR, [15, 15, 8, 8, 8]);
    cfg.depth = scale.pick(1, 2);
    cfg.acts |= A_SELFUPDATE | A_GRIND | A_AGE | A_SESSIONS;
    if !quiet {
        cfg.acts |= A_POST;
        cfg.posters = abit(C0);
        cfg.post_budget = [1, 0, 0, 0, 0];
    }
    cfg.malicious = abit(M1);
    cfg.session_actors = abit(C1);
    cfg.session_budget = 1;
    cfg.commit_budget = [0, 0, 1, 1, 0];
    cfg.terminal = if quiet { T_HONEST_ONE_BRANCH } else { 0 };
    let mut start = base_world(FOUR);
    start.m[M0].slot = true;
    start.m[C1].online = false;
    start.m[C1].listed = false;
    Scenario {
        cfg,
        start,
        reach: vec![
            (
                EV_GROUND_LATE,
                "a ground commit arrives after the winner was settled",
            ),
            (
                EV_CATCHUP,
                "the returning member settles at its first listing pass",
            ),
        ],
    }
}

/// F-2's ground probe: M0's self-update is settled by every online member (scripted, so that no
/// member idles past its window); nobody posts; M1 grinds a self-update below it after the winner's
/// store-hour anchor passed; C1 returns.
fn grind_quiet(rules: Rules, scale: Scale, name: &'static str) -> Scenario {
    let mut cfg = base_cfg(name, rules, FOUR);
    cfg.genesis = genesis(FOUR, [15, 15, 8, 8, 8]);
    cfg.depth = scale.pick(1, 2);
    cfg.acts |= A_SELFUPDATE | A_GRIND | A_AGE | A_SESSIONS;
    cfg.malicious = abit(M1);
    cfg.session_actors = abit(C1);
    cfg.session_budget = 1;
    cfg.commit_budget = [0, 0, 1, 1, 0];
    cfg.terminal = T_HONEST_ONE_BRANCH;
    let mut start = base_world(FOUR);
    start.m[M0].slot = true;
    start.m[C1].online = false;
    start.m[C1].listed = false;
    let start = replay(
        &cfg,
        start,
        &[
            Action::SelfUpdate {
                actor: M0 as u8,
                hash: 0,
            },
            Action::Store {
                blob: (M0 * PER_ACTOR_COMMITS) as u8,
                withheld: 0,
                indeterminate: false,
            },
            Action::List(C0 as u8),
            Action::List(M0 as u8),
            Action::List(M1 as u8),
            Action::Tick(C0 as u8),
            Action::Tick(M0 as u8),
            Action::Tick(M1 as u8),
        ],
    )
    .unwrap_or_else(|e| panic!("F-2's ground setup replays: {e}"));
    Scenario {
        cfg,
        start,
        reach: vec![(
            EV_GROUND_LATE,
            "a ground commit arrives after the winner was settled",
        )],
    }
}

/// F-2's late-copy probe: SC-LATE in a quiet channel (nobody posts), with the owner's process dying
/// between its pass and its store and the other members listing late (A5); run under F-1's
/// correction to show that the two findings are independent.
pub fn late_quiet(rules: Rules, scale: Scale) -> Scenario {
    let mut s = late(rules, scale);
    s.cfg.name = "F-2 late better commit in a quiet channel";
    s.cfg.acts &= !A_POST;
    s.cfg.posters = 0;
    s.cfg.post_budget = [0; NA];
    // The owner's process dies between its pass and its store; the others list late (A5).
    s.cfg.session_actors = abit(C0);
    s.cfg.terminal = T_HONEST_ONE_BRANCH;
    s.reach = vec![(
        EV_LATE_CANDIDATE,
        "a late candidate recorded by a settled member (CO-6)",
    )];
    s
}

/// F-1's second probe: the owner's user removes M1 (a user action passes at any moment, CO-8) while
/// the moderator's PCS commit is held; P-STRANDED without its premise.
pub fn remove_over_held(rules: Rules, scale: Scale) -> Scenario {
    let mut cfg = base_cfg("F-1 user action over a held candidate", rules, FOUR);
    cfg.depth = 2;
    cfg.acts |= A_PASS | A_POST | A_REMOVE;
    cfg.remover = C0 as u8;
    cfg.posters = abit(M0);
    cfg.post_budget = [0, 0, 1, 0, 0];
    cfg.commit_budget = [scale.pick(1, 2), 1, 0, 0, 0];
    cfg.terminal = T_STRANDED_RAW;
    let mut start = base_world(FOUR);
    start.m[C1].pcs = true;
    Scenario {
        cfg,
        start,
        reach: vec![],
    }
}

/// SC-JOIN (§6.2, §19.2, S0-15; CO-5, CO-8): J's join request, admitted by the owner at once or by
/// the moderator after 48 h, concurrently with a member's self-update; M1 joined after J's
/// INVITE_ISSUED (it never held the record).
pub fn join(rules: Rules, scale: Scale) -> Scenario {
    let mut cfg = base_cfg("SC-JOIN admission, Welcome after the win", rules, FOUR);
    cfg.depth = 1;
    cfg.acts |= A_PASS | A_SELFUPDATE;
    // At full scale J accepts at any point and the moderator's copy of the request ages (the owner
    // and the moderator act on the same aged request, CO-8); at PR scale J's request is stored at
    // the start and only the owner may admit it.
    if scale == Scale::Full {
        cfg.acts |= A_JOIN | A_WORKAGE;
    }
    cfg.commit_budget = [1, 1, 1, 0, 0];
    cfg.terminal = T_STRANDED | T_JOINED;
    let mut start = base_world(FOUR);
    start.m[M1].invite_record = false;
    start.m[M0].slot = true;
    if scale == Scale::Pr {
        let mut setup = cfg.clone();
        setup.acts |= A_JOIN;
        start = replay(&setup, start, &[Action::Accept])
            .unwrap_or_else(|e| panic!("J accepts its invite: {e}"));
    }
    let mut reach = vec![
        (EV_JOINED, "J joins through the Welcome of the won commit"),
        (
            EV_SETTLE_CONCURRENT,
            "an admission settles against a concurrent candidate",
        ),
    ];
    if scale == Scale::Full {
        reach.push((EV_AGED_WORK, "the moderator's request becomes 48 h old"));
        reach.push((
            EV_DOUBLE_ADMIT,
            "the owner and the moderator both commit J's admission for one epoch",
        ));
    }
    Scenario { cfg, start, reach }
}

/// SC-REMOVE (CO-13, CO-10, §6.5; T38): the moderator's user removes M1 (a user action, at once
/// whatever the rank, CO-8) while the owner's PCS commit competes and M0 wants to post; the
/// moderator's removal may lose to the owner's commit and must then be committed at its next pass.
pub fn remove(rules: Rules, scale: Scale) -> Scenario {
    let mut cfg = base_cfg("SC-REMOVE removal hold and rotation", rules, FOUR);
    cfg.depth = 2;
    cfg.acts |= A_PASS | A_POST | A_REMOVE;
    cfg.remover = C1 as u8;
    cfg.posters = abit(M0);
    cfg.post_budget = [0, 0, scale.pick(1, 2), 0, 0];
    cfg.commit_budget = [1, 2, 0, 0, 0];
    cfg.terminal = T_STRANDED | T_LIVENESS;
    let mut start = base_world(FOUR);
    start.m[C0].pcs = true;
    Scenario {
        cfg,
        start,
        reach: vec![
            (EV_REMOVED, "the removed member merges its removal"),
            (EV_ROTATED, "the removal opens a new generation"),
            (
                EV_HOLD,
                "a member holds its post while a removing candidate is held",
            ),
        ],
    }
}

/// SC-GOV (§19.13, §6.6): the owner transfers rank 0, resigns and leaves; the new owner removes it.
pub fn governance(rules: Rules, _scale: Scale) -> Scenario {
    let mut cfg = base_cfg(
        "SC-GOV transfer, resignation and leave of the owner",
        rules,
        FOUR,
    );
    cfg.depth = 3;
    cfg.acts |= A_PASS | A_TRANSFER | A_RESIGN | A_LEAVE;
    cfg.resigner = C0 as u8;
    cfg.leaver = C0 as u8;
    cfg.remove_target = C0 as u8;
    cfg.commit_budget = [2, 1, 0, 0, 0];
    cfg.terminal = T_TRANSFER_LEAVE;
    Scenario {
        cfg,
        start: base_world(FOUR),
        reach: vec![
            (EV_TRANSFER, "a transfer of rank 0 merged"),
            (EV_RESIGN, "a resignation merged"),
            (EV_LEFT, "the former owner leaves"),
            (EV_REMOVAL_MERGED, "the leaver's removal merged"),
        ],
    }
}

/// SC-FLOOD (§19.5; CO-7, CO-14): M1 commits a self-update at every epoch, whatever CO-14 says;
/// the owner removes it.
pub fn flood(rules: Rules, scale: Scale) -> Scenario {
    let mut cfg = base_cfg("SC-FLOOD self-update flood", rules, FOUR);
    cfg.genesis = genesis(FOUR, [15, 15, 8, 0, 8]);
    cfg.depth = scale.pick(2, 3);
    cfg.acts |= A_PASS | A_REMOVE | A_FLOOD;
    cfg.malicious = abit(M1);
    cfg.commit_budget = [2, 0, 0, scale.pick(2, 3), 0];
    cfg.terminal = T_FLOOD | T_LIVENESS;
    let depth = cfg.depth;
    Scenario {
        cfg,
        start: base_world(FOUR),
        reach: [
            (EV_REMOVED, "the flooder is removed"),
            (EV_SELFUPDATE_MERGED, "a self-update within the rate merged"),
        ]
        .into_iter()
        .chain(pass_over_reach(
            rules,
            depth,
            "the owner passes while it holds the flooder's candidate",
        ))
        .collect(),
    }
}

/// SC-INDET (CO-4 revised §19.13): the owner's commit op closes INDETERMINATE with or without a
/// copy at the relays; M0 may continue the owner's commit; (full scale) the moderator's competes.
pub fn indeterminate(rules: Rules, scale: Scale) -> Scenario {
    let mut cfg = base_cfg("SC-INDET own commit closed INDETERMINATE", rules, FOUR);
    cfg.depth = scale.pick(1, 2);
    cfg.acts |= A_PASS | A_POST | A_INDETERMINATE;
    cfg.posters = abit(M0);
    cfg.post_budget = [0, 0, 1, 0, 0];
    cfg.commit_budget = [1, scale.pick(0, 1), 0, 0, 0];
    cfg.terminal = T_STRANDED;
    let mut start = base_world(FOUR);
    start.m[C0].pcs = true;
    start.m[C1].pcs = scale == Scale::Full;
    let mut reach = vec![(
        EV_CLEAR_INDETERMINATE,
        "an own commit with no copy is cleared (CO-4 (c))",
    )];
    if rules.fixed(Fix::FetchedOwnCopy) {
        // F-5's correction: the copy the committer fetched verifies it; it never waits for one.
        reach.push((
            EV_OWN_FETCHED,
            "the committer merges its own commit from a fetched copy",
        ));
    } else {
        reach.push((
            EV_OWN_FROM_SUCCESSORS,
            "the committer merges its own unverified commit from successors",
        ));
        reach.push((
            EV_WAIT,
            "an own commit without a verified copy or a successor waits",
        ));
    }
    Scenario { cfg, start, reach }
}

/// F-5's probe: SC-INDET with the moderator's PCS commit competing (its full-scale configuration
/// at either scale), and P-STRANDED without its premises.
pub fn indet_competing(rules: Rules, _scale: Scale) -> Scenario {
    let mut s = indeterminate(rules, Scale::Full);
    s.cfg.name = "F-5 own copy demoted at its committer";
    s.cfg.depth = 1;
    s.cfg.terminal = T_STRANDED_RAW;
    s.reach = vec![];
    s
}

/// SC-JUNK (§19.29.1, TR-2, E-70): M1 stores an Add carrying an expired finite-lifetime
/// KeyPackage; members' device clocks differ; the owner removes M1.
pub fn junk(rules: Rules, scale: Scale) -> Scenario {
    let mut cfg = base_cfg("SC-JUNK non-canonical lifetime commit", rules, FOUR);
    cfg.depth = scale.pick(1, 2);
    cfg.acts |= A_PASS | A_REMOVE | A_JUNK;
    cfg.malicious = abit(M1);
    cfg.commit_budget = [1, 0, 0, 1, 0];
    cfg.terminal = T_LIVENESS;
    let mut start = base_world(FOUR);
    start.m[M0].clock_late = true;
    start.m[C1].clock_late = true;
    Scenario {
        cfg,
        start,
        reach: vec![(EV_REMOVED, "the insider is removed")],
    }
}

/// SC-CLOCKS (§19.29.1, E-69; CS-C3 "whatever their device and trusted clocks"): the owner admits J
/// while M0 self-updates; M0's and C1's device clocks lie past a finite lifetime's bound. Under the
/// design every KeyPackage carries the constant lifetime; under the withdrawn rule (the
/// `LifetimeByClock` mutant, Q42 (b)) honest KeyPackages carry the finite one.
pub fn clocks(rules: Rules, _scale: Scale) -> Scenario {
    let mut cfg = base_cfg("SC-CLOCKS members with different clocks", rules, FOUR);
    cfg.acts |= A_PASS | A_JOIN | A_SELFUPDATE;
    cfg.commit_budget = [1, 0, 1, 0, 0];
    cfg.finite_kp = rules.is(crate::rules::Mutant::LifetimeByClock);
    cfg.terminal = T_JOINED;
    let mut start = base_world(FOUR);
    start.m[M0].slot = true;
    start.m[M0].clock_late = true;
    start.m[C1].clock_late = true;
    Scenario {
        cfg,
        start,
        reach: vec![(EV_JOINED, "J joins")],
    }
}

/// SC-ADV (CO-1, §19.14): M1 commits a Remove at rank 255 and an update path with a new signature
/// key, beside the owner's PCS commit.
pub fn adversarial_commits(rules: Rules, _scale: Scale) -> Scenario {
    let mut cfg = base_cfg("SC-ADV rank-255 proposals and a new signer", rules, FOUR);
    // M1's leaf is old enough for CO-14, so only CO-1's and §19.14's rules refuse its commits.
    cfg.genesis = genesis(FOUR, [15, 15, 8, 8, 8]);
    cfg.acts |= A_PASS | A_NEWSIGNER | A_PROPOSALS;
    cfg.malicious = abit(M1);
    cfg.commit_budget = [1, 0, 0, 2, 0];
    let mut start = base_world(FOUR);
    start.m[C0].pcs = true;
    Scenario {
        cfg,
        start,
        reach: vec![(EV_DEPTH_MAX, "the owner's PCS commit merged")],
    }
}

/// SC-CATCHUP (CO-4's store-hour anchor, §19.1 rule 3): the owner commits epoch after epoch while
/// M1 is away; M1 returns after the commits are old and must be current after one listing pass.
pub fn catchup(rules: Rules, scale: Scale) -> Scenario {
    let mut cfg = base_cfg("SC-CATCHUP returning member across epochs", rules, FOUR);
    cfg.depth = scale.pick(2, 4);
    cfg.acts |= A_PASS | A_PCS | A_AGE | A_SESSIONS;
    cfg.session_actors = abit(M1);
    cfg.session_budget = 1;
    cfg.commit_budget = [scale.pick(2, 4), 0, 0, 0, 0];
    let mut start = base_world(FOUR);
    start.m[C0].pcs = true;
    start.m[M1].online = false;
    start.m[M1].listed = false;
    // C1 and M0 stay offline (quiet observers); only the owner and the returning member act.
    start.m[C1].online = false;
    start.m[M0].online = false;
    Scenario {
        cfg,
        start,
        reach: vec![
            (
                EV_CATCHUP2,
                "a returning member settles two epochs in one listing pass",
            ),
            (EV_DEPTH_MAX, "the depth bound is reached"),
        ],
    }
}

// ---- day-scale scenarios (CO-11, CO-12, §6.7) ------------------------------------------------------

/// A FORK of the relays: C1's PCS commit k3 reaches everyone but the lone member, whose branch is
/// its own commit (M0: a self-update; C0: a PCS commit), withheld from the others.
pub fn fork_setup(rules: Rules, lone: usize) -> World {
    let masks: &'static [u8] = &[
        1 << M0,
        1 << C0,
        (1 << C1) | (1 << M1) | (1 << C0),
        (1 << C1) | (1 << M1) | (1 << M0),
    ];
    let mut cfg = base_cfg("fork setup", rules, FOUR);
    cfg.acts |= A_PASS | A_SELFUPDATE | A_REJOIN;
    cfg.honest_timing = false;
    cfg.withhold_masks = masks;
    cfg.withhold_kinds = COMMIT_KIND;
    cfg.commit_budget = [1, 1, 1, 0, 0];
    cfg.depth = 2;
    let mut start = base_world(FOUR);
    start.m[C1].pcs = true;
    let others = FOUR & !abit(lone);
    let script: Vec<Action> = if lone == M0 {
        start.m[M0].slot = true;
        vec![
            Action::Pass {
                actor: C1 as u8,
                hash: 0,
            },
            Action::SelfUpdate {
                actor: M0 as u8,
                hash: 1,
            },
            Action::Store {
                blob: 3,
                withheld: abit(M0),
                indeterminate: false,
            },
            Action::Store {
                blob: 6,
                withheld: others,
                indeterminate: false,
            },
            Action::List(C1 as u8),
            Action::Tick(C1 as u8),
            Action::List(M0 as u8),
            Action::Tick(M0 as u8),
            Action::List(C0 as u8),
            Action::List(M1 as u8),
            Action::Tick(C0 as u8),
            Action::Tick(M1 as u8),
        ]
    } else {
        start.m[C0].pcs = true;
        vec![
            Action::Pass {
                actor: C1 as u8,
                hash: 0,
            },
            Action::Pass {
                actor: C0 as u8,
                hash: 1,
            },
            Action::Store {
                blob: 3,
                withheld: abit(C0),
                indeterminate: false,
            },
            Action::Store {
                blob: 0,
                withheld: others & !abit(C0),
                indeterminate: false,
            },
            Action::List(C1 as u8),
            Action::Tick(C1 as u8),
            Action::List(C0 as u8),
            Action::Tick(C0 as u8),
            Action::List(M0 as u8),
            Action::List(M1 as u8),
            Action::Tick(M0 as u8),
            Action::Tick(M1 as u8),
        ]
    };
    let w = replay(&cfg, start, &script).unwrap_or_else(|e| panic!("the fork setup replays: {e}"));
    assert!(
        !w.m[lone].chain.comparable(w.m[C1].chain),
        "the setup forks"
    );
    w
}

/// SC-FORK (CO-11, §6.7; SCN-CG's one-member side): M0 merged its own commit while the relays
/// served everyone else C1's; the others post; M0 must reach `resync_needed` within 72 h and three
/// sessions of their traffic, rejoin, and be readmitted.
pub fn fork(rules: Rules, scale: Scale) -> Scenario {
    let mut cfg = base_cfg("SC-FORK dead branch, resync and rejoin", rules, FOUR);
    cfg.depth = 2;
    cfg.acts |= A_PASS | A_POST | A_DAY | A_SESSIONS | A_REJOIN;
    // At full scale the relays may also end the FORK at any point (both sides' withheld commits
    // served from then on: a partition for an interval, §12.3); at the PR bound it lasts for good.
    if scale == Scale::Full {
        cfg.acts |= A_RELEASE;
    }
    cfg.honest_timing = false;
    cfg.days = scale.pick(3, 4);
    cfg.session_actors = abit(M0);
    cfg.session_budget = 4;
    cfg.posters = abit(C0) | abit(C1) | abit(M1);
    cfg.post_budget = [1, 1, 0, 1, 0];
    cfg.commit_budget = [1, 2, 1, 0, 0];
    cfg.terminal = T_DETECT;
    Scenario {
        cfg,
        start: fork_setup(rules, M0),
        reach: vec![
            (EV_RESYNC, "the lone member reaches resync_needed (CO-11)"),
            (EV_REJOINED, "it is readmitted by a rejoin swap"),
        ],
    }
}

/// SC-OWNER (§19.13, MM-33): the owner merged its own commit while the relays served everyone else
/// C1's; it asks to rejoin; the moderator swaps the owner's leaf and the owner keeps rank 0.
pub fn owner(rules: Rules, _scale: Scale) -> Scenario {
    let mut cfg = base_cfg(
        "SC-OWNER the owner on a dead branch is readmitted",
        rules,
        FOUR,
    );
    cfg.depth = 2;
    // The moderator commits the owner's rejoin only once the request is 48 h old (CO-8's
    // work-age rule; the owner, rank 0, is the one away).
    cfg.acts |= A_PASS | A_REJOIN | A_WORKAGE;
    cfg.honest_timing = false;
    cfg.commit_budget = [1, 2, 0, 0, 0];
    cfg.terminal = T_OWNER_BACK;
    let mut start = fork_setup(rules, C0);
    start.m[C0].status = Status::Resync;
    let start = replay(&cfg, start, &[Action::Rejoin(C0 as u8)])
        .unwrap_or_else(|e| panic!("the owner asks to rejoin: {e}"));
    Scenario {
        cfg,
        start,
        reach: vec![(EV_OWNER_READMITTED, "the owner is readmitted with rank 0")],
    }
}

/// The owner removes M1 (a rotating commit), withheld by the relays from `hidden` for good, and,
/// with `expire`, expired before those members return.
pub fn removal_setup(rules: Rules, roster: u8, hidden: u8, expire: bool) -> World {
    let masks: &'static [u8] = &[1 << M0, (1 << M0) | (1 << J)];
    let mut cfg = base_cfg("removal setup", rules, roster);
    cfg.acts |= A_PASS | A_REMOVE | A_AGE | A_EXPIRE;
    cfg.honest_timing = false;
    cfg.withhold_masks = masks;
    cfg.withhold_kinds = COMMIT_KIND;
    cfg.commit_budget = [1, 0, 0, 0, 0];
    cfg.depth = 2;
    let start = base_world(roster);
    let mut script = vec![
        Action::UserRemove(C0 as u8),
        Action::Pass {
            actor: C0 as u8,
            hash: 0,
        },
        Action::Store {
            blob: 0,
            withheld: hidden,
            indeterminate: false,
        },
        Action::List(C0 as u8),
        Action::Tick(C0 as u8),
    ];
    for a in [C1, M0, M1, J] {
        if roster & abit(a) != 0 && hidden & abit(a) == 0 {
            script.push(Action::List(a as u8));
            script.push(Action::Tick(a as u8));
        }
    }
    if expire {
        script.push(Action::Age(0));
        script.push(Action::Expire(0));
    }
    replay(&cfg, start, &script).unwrap_or_else(|e| panic!("the removal setup replays: {e}"))
}

/// SC-SILENT (CO-12's `stale_suspected`, §19.15; SCN-CL's silent-orphan variant): M0 missed the
/// rotating commit that removed M1 for good (it expired); the others post in the new namespace;
/// M0 must raise `stale_suspected` within 9 days, and its resync inside the drain readmits it.
pub fn silent(rules: Rules, scale: Scale) -> Scenario {
    let mut cfg = base_cfg("SC-SILENT silent orphan", rules, FOUR);
    cfg.depth = 2;
    cfg.acts |= A_PASS | A_POST | A_DAY | A_REJOIN;
    cfg.honest_timing = false;
    cfg.days = scale.pick(9, 10);
    cfg.posters = abit(C0) | abit(C1);
    cfg.post_budget = [1, 1, 0, 0, 0];
    cfg.commit_budget = [2, 0, 0, 0, 0];
    cfg.terminal = T_DETECT;
    Scenario {
        cfg,
        start: removal_setup(rules, FOUR, abit(M0), true),
        reach: vec![
            (EV_STALE, "the orphan raises stale_suspected"),
            (EV_REJOINED, "its resync inside the drain readmits it"),
        ],
    }
}

/// SC-PARTITION (CO-12's `partition_suspected`): the relays withhold the committers' commit from
/// the three other members for good; those keep posting; each must raise `partition_suspected`
/// within 9 days.
pub fn partition(rules: Rules, scale: Scale) -> Scenario {
    let masks: &'static [u8] = &[(1 << M0) | (1 << M1) | (1 << J)];
    let mut setup = base_cfg("partition setup", rules, FIVE);
    setup.acts |= A_PASS;
    setup.honest_timing = false;
    setup.withhold_masks = masks;
    setup.withhold_kinds = COMMIT_KIND;
    setup.commit_budget = [1, 0, 0, 0, 0];
    let mut start = base_world(FIVE);
    start.m[C0].pcs = true;
    let start = replay(
        &setup,
        start,
        &[
            Action::Pass {
                actor: C0 as u8,
                hash: 0,
            },
            Action::Store {
                blob: 0,
                withheld: masks[0],
                indeterminate: false,
            },
            Action::List(C0 as u8),
            Action::Tick(C0 as u8),
            Action::List(C1 as u8),
            Action::Tick(C1 as u8),
        ],
    )
    .unwrap_or_else(|e| panic!("the partition setup replays: {e}"));
    // The committers, cut off, neither read nor commit any more.
    let mut start = start;
    for a in [C0, C1] {
        start.m[a].online = false;
        start.m[a].listed = false;
    }
    let mut cfg = base_cfg("SC-PARTITION committers cut off", rules, FIVE);
    cfg.depth = 1;
    cfg.acts |= A_POST | A_DAY;
    cfg.honest_timing = false;
    cfg.days = scale.pick(9, 10);
    cfg.posters = abit(M0) | abit(M1) | abit(J);
    cfg.post_budget = [0, 0, 1, 1, 1];
    cfg.terminal = T_DETECT;
    Scenario {
        cfg,
        start,
        reach: vec![(EV_PARTITION, "a cut-off member raises partition_suspected")],
    }
}

/// SC-SPAM-DRAIN (§19.15 (c), MM-37): M1, removed at the end of the old generation, deposits
/// unopenable blobs into the draining namespace of a quiet channel; nobody may enter
/// `resync_needed` because of them.
pub fn spam_drain(rules: Rules, scale: Scale) -> Scenario {
    let mut cfg = base_cfg("SC-SPAM-DRAIN spam in the draining namespace", rules, FOUR);
    cfg.depth = 1;
    cfg.acts |= A_SPAM | A_DAY | A_SESSIONS;
    cfg.honest_timing = false;
    cfg.malicious = abit(M1);
    cfg.days = scale.pick(3, 4);
    cfg.session_actors = abit(M0);
    cfg.session_budget = 4;
    cfg.terminal = T_NO_FALSE_RESYNC;
    Scenario {
        cfg,
        start: removal_setup(rules, FOUR, 0, false),
        reach: vec![(
            EV_DRAIN_SPAM,
            "the removed member stores into the draining namespace",
        )],
    }
}

/// SC-SPAM-CURRENT (L8-C11, CO-11's progress rule): M1 deposits unopenable blobs into the current
/// namespace of a quiet channel; M0 may reach `resync_needed` (declared), its rejoin is refused (its
/// claimed epoch is the committers' current one), and the owner's PCS commit returns it to active.
pub fn spam_current(rules: Rules, scale: Scale) -> Scenario {
    let mut cfg = base_cfg("SC-SPAM-CURRENT spam in the current namespace", rules, FOUR);
    cfg.depth = 1;
    cfg.acts |= A_SPAM | A_DAY | A_SESSIONS | A_REJOIN | A_PASS;
    cfg.honest_timing = false;
    cfg.malicious = abit(M1);
    cfg.days = scale.pick(3, 4);
    cfg.session_actors = abit(M0);
    cfg.session_budget = 4;
    cfg.commit_budget = [1, 0, 0, 0, 0];
    let mut start = base_world(FOUR);
    start.m[C0].pcs = true;
    Scenario {
        cfg,
        start,
        reach: vec![
            (
                EV_RESYNC,
                "spam pushes a quiet member into resync_needed (declared, L8-C11)",
            ),
            (EV_REJOIN_REFUSED, "its rejoin is refused"),
            (EV_PROGRESS_RESET, "progress returns it to active"),
        ],
    }
}

/// SC-REPLAY (§19.3, §6.7, REPLAY_JOIN): M0, on a dead branch, rejoins; an insider re-stores a copy
/// of its rejoin request afterwards; a malicious committer re-wraps J's join KeyPackage as a rejoin
/// of M0.
pub fn replay_join(rules: Rules, scale: Scale) -> Scenario {
    let mut cfg = base_cfg("SC-REPLAY replayed and re-wrapped KeyPackages", rules, FOUR);
    // A third epoch: a replayed request could be committed after the rejoin swap.
    cfg.depth = 3;
    cfg.acts |= A_PASS | A_REJOIN | A_REPLAY | A_REPLAY_SWAP;
    cfg.honest_timing = false;
    cfg.malicious = abit(M1);
    cfg.commit_budget = [2, scale.pick(2, 3), 1, 0, 0];
    let mut start = fork_setup(rules, M0);
    start.m[M0].status = Status::Resync;
    let start = replay(&cfg, start, &[Action::Rejoin(M0 as u8)])
        .unwrap_or_else(|e| panic!("M0 asks to rejoin: {e}"));
    Scenario {
        cfg,
        start,
        reach: vec![
            (EV_REJOINED, "M0 rejoins"),
            (EV_REJOIN_REFUSED, "a replayed or stale request is refused"),
        ],
    }
}

/// F-3's probe (SCN-CL, §6.7's table, §12.3 "detection"): the relays withhold the removal of M1 from
/// the two members M0 and J for good; they keep posting in the old epoch; §12.3 claims that the
/// subset raises `partition_suspected` within 9 days and the majority `split_suspected` within the
/// retention plus 72 h.
pub fn withheld_removal(rules: Rules, scale: Scale) -> Scenario {
    let mut cfg = base_cfg("F-3 withheld removal (SCN-CL)", rules, FIVE);
    cfg.depth = 1;
    cfg.acts |= A_POST | A_DAY | A_SESSIONS;
    cfg.honest_timing = false;
    cfg.days = scale.pick(9, 10);
    cfg.session_actors = abit(C0);
    cfg.session_budget = 4;
    // The subset posts; three of its posts make CO-11 (a)'s count at the majority.
    cfg.posters = abit(M0) | abit(J);
    cfg.post_budget = [0, 0, 2, 0, 1];
    cfg.terminal = T_SCN_CL;
    // The removed member and the moderator take no further part (neither reads nor posts).
    let mut start = removal_setup(rules, FIVE, abit(M0) | abit(J), false);
    for a in [C1, M1] {
        start.m[a].online = false;
        start.m[a].listed = false;
    }
    Scenario {
        cfg,
        start,
        reach: vec![],
    }
}

/// Every control scenario at a scale (the design's rules or a mutant's).
pub fn controls(rules: Rules, scale: Scale) -> Vec<Scenario> {
    let mut v = vec![
        concurrency(rules, scale),
        late(rules, scale),
        grind(rules, scale, false),
        join(rules, scale),
        remove(rules, scale),
        governance(rules, scale),
        flood(rules, scale),
        indeterminate(rules, scale),
        junk(rules, scale),
        clocks(rules, scale),
        adversarial_commits(rules, scale),
        catchup(rules, scale),
        fork(rules, scale),
        owner(rules, scale),
        silent(rules, scale),
        partition(rules, scale),
        spam_drain(rules, scale),
        replay_join(rules, scale),
    ];
    if scale == Scale::Full {
        // The declared spam behaviour (L8-C11) is a reachability check only; no mutant needs it.
        v.push(spam_current(rules, scale));
    }
    v
}
