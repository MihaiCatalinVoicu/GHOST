//! The properties EM-3 checks (§12.3), each named by the identifier the counter-examples and the
//! mutant killers print. Decision-time properties run inside the transaction that would break them;
//! terminal properties run on quiescent states (nothing left to do but end a session).
//!
//! Every check is one **site** (`SITES`): a property, or a property and the clause it checks
//! (`P-LIVENESS/remove`). Each site is the first violation of some registered run — a mutant's
//! named killer, a finding probe or a hand-built world (`tests/state_models.rs`,
//! `em3_every_check_site_fires_in_a_registered_run`) — so no check can be deleted without a test
//! noticing (§19.34.1 item 12). A probe may switch sites off (`Cfg::off`) to show what a decision-
//! time check hides; a site switched off never stops the checks after it.

use crate::model::*;
use crate::rules::{Fix, Rules};
use crate::step::Cfg;

/// A property that a reachable state or transition breaks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Violation {
    pub property: &'static str,
    /// The check that failed (`SITES`).
    pub site: &'static str,
    pub detail: String,
}

impl std::fmt::Display for Violation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.property, self.detail)
    }
}

/// Every check site, in no particular order. `tests/state_models.rs` proves that each one is the
/// first violation of a registered run.
pub const SITES: &[&str] = &[
    "P-LIFETIME",
    "P-VALID-SAME",
    "P-NO-INVALID-MERGE",
    "P-FRESH",
    "P-VERIFIED",
    "P-RANK",
    "P-FOLLOW",
    "P-ROTATION",
    "P-REJOIN-SAFE/rotates",
    "P-REJOIN-SAFE/live-leaf",
    "P-CUSTODY/clear",
    "P-CUSTODY/settle",
    "P-WELCOME",
    "P-HOLD",
    "P-OWN-VALID",
    "P-STICKY",
    "P-CATCHUP",
    "P-CONC",
    "P-LATE-HARMLESS",
    "P-ONE-BRANCH",
    "P-STRANDED",
    "P-LIVENESS/remove",
    "P-LIVENESS/owner",
    "P-LIVENESS/third-pass",
    "P-JOINED",
    "P-GOVERNANCE",
    "P-OWNER-BACK",
    "P-DETECT/resync",
    "P-DETECT/partition",
    "P-DETECT/stale",
    "P-NO-FALSE-RESYNC",
    "P-SCN-CL-PARTITION",
    "P-SCN-CL-SPLIT",
    "P-PASS",
    "P-WORKAGE",
];

/// The property a site belongs to (its name up to the first `/`).
pub fn property_of(site: &'static str) -> &'static str {
    match site.find('/') {
        Some(i) => &site[..i],
        None => site,
    }
}

/// One check: `ok` must hold, else `site` fails with `detail` — unless the run switched the site
/// (or its whole property) off. Never returns early on its own: the checks after it still run.
pub fn check(
    cfg: &Cfg,
    site: &'static str,
    ok: bool,
    detail: impl FnOnce() -> String,
) -> Result<(), Violation> {
    let property = property_of(site);
    if ok || cfg.off.iter().any(|&o| o == site || o == property) {
        return Ok(());
    }
    Err(Violation {
        property,
        site,
        detail: detail(),
    })
}

fn name(a: usize) -> &'static str {
    ACTOR_NAMES[a]
}

/// At a settle point (CO-4 (i) and (ii) hold).
///
/// - **P-LIFETIME** (§12.3 "lifetimes", §19.29.1): no lifetime refusal blocks a settle (and with it,
///   since the member is then not current, every pass and post).
/// - **P-VALID-SAME** (T41, CS-C3: validity "depends only on the commit, the group state and the
///   commit's authenticated data", "whatever their device and trusted clocks"): every commit the
///   member holds for its epoch gets the same verdict from every member's judge (its clock, its
///   INVITE_ISSUED records). Under the design's rules it holds by construction — `verdict` reads
///   the judge only under a mutant (§19.34.1 item 7) — so its runs show that the property catches
///   a member-local input (MM-23, round 10d's clock), not that the design has none.
pub fn check_choice(w: &World, cfg: &Cfg, m: usize, choice: &Choice) -> Result<(), Violation> {
    check(cfg, "P-LIFETIME", !choice.blocked, || {
        format!(
            "{} holds only a lifetime-refused commit for {:?} and does not settle",
            name(m),
            w.m[m].chain
        )
    })?;
    let me = &w.m[m];
    let g = group_of(w, &cfg.genesis, me.chain, cfg.rules);
    for s in 0..NC {
        if me.fetched & bit(s) == 0 || w.b[s].kind != B_COMMIT || w.c[s].parent != me.chain {
            continue;
        }
        let mine = verdict(&g, &w.c[s], cfg.rules, me.judge());
        for (n, other) in w.m.iter().enumerate() {
            if n == m {
                continue;
            }
            let theirs = verdict(&g, &w.c[s], cfg.rules, other.judge());
            check(cfg, "P-VALID-SAME", theirs == mine, || {
                format!(
                    "commit k{s} on {:?}: {} judges {mine:?}, {} would judge {theirs:?}",
                    me.chain,
                    name(m),
                    name(n)
                )
            })?;
        }
    }
    Ok(())
}

/// At a merge (CO-5).
///
/// - **P-NO-INVALID-MERGE** (§12.3 "no invalid merge"): the merged commit is valid under the
///   normative CO-1, CO-2 and CO-14 (no rank-255 commit with proposals or above the rate, no
///   removal of a lower rank, no Add without valid evidence, no swap without rejoin or restore
///   evidence, no finite lifetime, no new signature key).
/// - **P-FRESH** (CO-4 (ii) "so it holds every candidate stored before that pass", D8): a member
///   settles only while it holds every valid candidate for its epoch that the relays store and serve
///   to it (it does not settle on what an earlier listing pass left it).
/// - **P-VERIFIED** (CO-4 (a) as written): an own commit is merged only with a verified copy (the
///   op's SENT or DEGRADED outcome; under F-5's correction also a copy the committer fetched) or a
///   successor sender.
/// - **P-RANK** (CO-10 "the lower rank wins"): among candidates with the winner's successor count,
///   none ranks lower (a foreign candidate against an unverified own commit is CO-3's demotion).
/// - **P-FOLLOW** (§19.1 rule 2, SCN-CM "a returning member picks the branch with successors"):
///   when exactly one candidate has successor senders, the member merges it.
/// - **P-ROTATION** (§6.5, P-C4 (b), T38): a commit that removes a pseudonym opens a generation
///   whose secret the removed member's device cannot derive.
/// - **P-REJOIN-SAFE** (§6.7, §19.3, SCN-CM REPLAY_JOIN): a rejoin swap never rotates (`/rotates`)
///   and never evicts a live member, one that is active on this branch and does not hold the
///   KeyPackage (`/live-leaf`).
pub fn check_merge(
    w: &World,
    cfg: &Cfg,
    m: usize,
    s: usize,
    choice: &Choice,
    g: &Group,
) -> Result<(), Violation> {
    let me = &w.m[m];
    let k = &w.c[s];
    let v = normative(g, k);
    check(cfg, "P-NO-INVALID-MERGE", v == Verdict::Valid, || {
        format!(
            "{} merges k{s} on {:?}, which CO-2 refuses: {v:?}",
            name(m),
            me.chain
        )
    })?;
    let vis = visible_mask(w, &cfg.genesis, cfg.rules, m);
    let missed = (0..NC).find(|&x| {
        w.c[x].used
            && w.c[x].parent == me.chain
            && x != me.own as usize
            && me.fetched & bit(x) == 0
            && vis & bit(x) != 0
            && normative(g, &w.c[x]) == Verdict::Valid
    });
    check(cfg, "P-FRESH", missed.is_none(), || {
        format!(
            "{} settles {:?} on k{s} while k{}, stored and served to it, is not fetched",
            name(m),
            me.chain,
            missed.unwrap_or(0)
        )
    })?;
    let own = me.own as usize == s;
    let verified =
        me.op == Op::Verified || (cfg.rules.fixed(Fix::FetchedOwnCopy) && me.fetched & bit(s) != 0);
    check(
        cfg,
        "P-VERIFIED",
        !(own && !verified && choice.successors[s] == 0),
        || {
            format!(
                "{} merges its own commit k{s} with neither a verified copy nor a successor",
                name(m)
            )
        },
    )?;
    let eligible = choice.candidates & !choice.abandoned;
    let rank = |x: usize| g.rank(w.c[x].author as usize);
    for x in 0..NC {
        if eligible & (1 << x) == 0 || x == s {
            continue;
        }
        let demoted = me.own as usize == x && me.op != Op::Verified;
        if demoted || (own && me.op != Op::Verified) {
            continue;
        }
        let lower = choice.successors[x] == choice.successors[s]
            && (rank(x), w.c[x].hash) < (rank(s), w.c[s].hash);
        check(cfg, "P-RANK", !lower, || {
            format!(
                "{} merges k{s} (rank {}) over k{x} (rank {}) with equal successors",
                name(m),
                rank(s),
                rank(x)
            )
        })?;
    }
    let with_succ: Vec<usize> = (0..NC)
        .filter(|&x| eligible & (1 << x) != 0 && successor_senders(w, m, x) != 0)
        .collect();
    let unfollowed = eligible.count_ones() > 1 && with_succ.len() == 1 && with_succ[0] != s && {
        let demoted_own = me.own as usize == with_succ[0] && me.op != Op::Verified;
        !demoted_own || choice.successors[with_succ[0]] > choice.successors[s]
    };
    check(cfg, "P-FOLLOW", !unfollowed, || {
        format!(
            "{} merges k{s} although only k{} has successor senders (others continued it)",
            name(m),
            with_succ[0]
        )
    })?;
    let at = me.chain.push(s);
    let after = group_of(w, &cfg.genesis, at, cfg.rules);
    if k.remove != NONE {
        let x = k.remove as usize;
        let device = &w.m[x];
        let knows = held_ever(device, after.ns) || after.gen == g.gen;
        check(cfg, "P-ROTATION", !knows, || {
            format!(
                "k{s} removes {} but generation {} (from {:?}) is derivable by its device",
                name(x),
                after.gen,
                after.ns
            )
        })?;
    }
    if k.swap != NONE && k.swap_kind == SWAP_REJOIN {
        let x = k.swap as usize;
        check(cfg, "P-REJOIN-SAFE/rotates", after.gen == g.gen, || {
            format!("the rejoin swap k{s} rotates")
        })?;
        let device = &w.m[x];
        // The device lives on the very leaf the swap replaces.
        let live = device.status == Status::Active
            && device.inc == g.inc[x]
            && device.chain.comparable(me.chain);
        let own_kp = kp_owner(k.kp) == x && device.kp & (1 << kp_instance(k.kp)) != 0;
        check(cfg, "P-REJOIN-SAFE/live-leaf", !(live && !own_kp), || {
            format!(
                "k{s} swaps out the live leaf of {} with a KeyPackage it does not hold",
                name(x)
            )
        })?;
    }
    Ok(())
}

/// **P-CUSTODY** (CO-4 revised §19.13, "no stranded committer"): an own commit is never cleared
/// on its own (INDETERMINATE, or the deadline) while the committer holds a successor sender of it
/// (`/clear`).
pub fn check_clear(w: &World, cfg: &Cfg, m: usize, own: usize) -> Result<(), Violation> {
    let senders = successor_senders(w, m, own);
    check(cfg, "P-CUSTODY/clear", senders == 0, || {
        format!(
            "{} clears its own commit k{own} although it holds messages of other members on it",
            name(m)
        )
    })
}

/// **P-CUSTODY** at a settle (`/settle`): clearing where another candidate wins (CO-4 (b)) is
/// CO-3's choice, not custody; this is the decision-time half of "no stranded committer" for an own
/// commit cleared by a settle while it holds successor senders and no candidate has more.
pub fn check_settle_clear(
    w: &World,
    cfg: &Cfg,
    m: usize,
    own: usize,
    winner: usize,
) -> Result<(), Violation> {
    let own_succ = successor_senders(w, m, own).count_ones();
    let win_succ = successor_senders(w, m, winner).count_ones();
    check(
        cfg,
        "P-CUSTODY/settle",
        !(own_succ > 0 && own_succ > win_succ),
        || {
            format!(
                "{} clears its own commit k{own} for k{winner}, which fewer members continued",
                name(m)
            )
        },
    )
}

/// **P-WELCOME** (§19.2, RFC 9750 §5.2.3): a joiner opens only the Welcome of a commit that its
/// committer merged (won).
pub fn check_welcome(w: &World, cfg: &Cfg, s: usize) -> Result<(), Violation> {
    let author = w.c[s].author as usize;
    let merged = {
        let c = w.m[author].chain;
        (0..c.len()).any(|i| c.at(i) == s)
    };
    check(cfg, "P-WELCOME", merged, || {
        format!(
            "a Welcome of k{s} is applied although its committer {} has not merged it",
            name(author)
        )
    })
}

/// **P-HOLD** (CO-13, T38's hold variant): no honest member encrypts a post in epoch e after it
/// first held a valid candidate for e that removes a pseudonym (or its own pending commit does).
pub fn check_post(w: &World, cfg: &Cfg, m: usize) -> Result<(), Violation> {
    let me = &w.m[m];
    let (cands, _) = candidates(w, &cfg.genesis, Rules::DESIGN, m);
    let holds = (0..NC).any(|s| cands & (1 << s) != 0 && w.c[s].removes_someone());
    check(cfg, "P-HOLD", !holds, || {
        format!(
            "{} encrypts a post in {:?} while it holds a candidate that removes a member",
            name(m),
            me.chain
        )
    })
}

/// **P-OWN-VALID** (§19.31 row 14; CO-9 "skips a slot at which CO-14 would refuse it"): an honest
/// member never builds a commit that CO-2 refuses.
pub fn check_own_commit(w: &World, cfg: &Cfg, m: usize, k: &Commit) -> Result<(), Violation> {
    if k.flags & F_ADVERSARY != 0 || (cfg.finite_kp && k.admit) {
        return Ok(());
    }
    let g = group_of(w, &cfg.genesis, k.parent, cfg.rules);
    let v = normative(&g, k);
    check(cfg, "P-OWN-VALID", v == Verdict::Valid, || {
        format!("{} builds a commit CO-2 refuses: {v:?}", name(m))
    })
}

/// **P-STICKY** (CO-6, §19.1 rule 1): a member never leaves a final epoch because of a later
/// commit.
pub fn check_sticky(cfg: &Cfg, old: Chain, new: Chain, m: usize) -> Result<(), Violation> {
    check(cfg, "P-STICKY", old.is_prefix_of(new), || {
        format!(
            "{} leaves its final epochs {old:?} for {new:?} on a late commit",
            name(m)
        )
    })
}

/// **P-CATCHUP** (§12.3 "catch-up latency", §19.1 rule 3): after the first listing pass of a
/// session, a member holds no valid candidate for its current epoch whose store-hour anchor lies in
/// the past without having settled it (no wall-clock wait), unless the only decision is to wait for
/// its own commit's copy (CO-4 (a)).
pub fn check_catchup(w: &World, cfg: &Cfg, m: usize) -> Result<(), Violation> {
    let me = &w.m[m];
    if me.status != Status::Active || me.chain.len() >= cfg.depth.min(MAX_DEPTH) {
        return Ok(());
    }
    let (cands, _) = candidates(w, &cfg.genesis, Rules::DESIGN, m);
    let old = (0..NC).any(|s| {
        cands & (1 << s) != 0 && me.fetched & bit(s) != 0 && w.b[s].old && me.own as usize != s
    });
    if !old {
        return Ok(());
    }
    let choice = decide(w, &cfg.genesis, cfg.rules, m);
    check(
        cfg,
        "P-CATCHUP",
        !matches!(choice.decision, Decision::Merge(_)),
        || {
            format!(
                "{} returns, holds a candidate for {:?} stored long ago, and still waits after its \
                 first listing pass",
                name(m),
                me.chain
            )
        },
    )
}

/// Terminal properties a scenario asks for (bits of [`Cfg::terminal`]); `check_terminal` returns
/// the bits whose premise held at the state (their "live" count is printed per control).
pub const T_CONC: u32 = 1;
pub const T_STRANDED: u32 = 1 << 1;
pub const T_LIVENESS: u32 = 1 << 2;
pub const T_DETECT_RESYNC: u32 = 1 << 3;
pub const T_OWNER_BACK: u32 = 1 << 4;
pub const T_HONEST_ONE_BRANCH: u32 = 1 << 5;
pub const T_JOINED: u32 = 1 << 6;
pub const T_NO_FALSE_RESYNC: u32 = 1 << 7;
pub const T_TRANSFER_LEAVE: u32 = 1 << 8;
pub const T_LATE_HARMLESS: u32 = 1 << 9;
pub const T_SCN_CL: u32 = 1 << 10;
/// P-STRANDED without its premise (F-1's and F-5's probes).
pub const T_STRANDED_RAW: u32 = 1 << 11;
pub const T_DETECT_PARTITION: u32 = 1 << 12;
pub const T_DETECT_STALE: u32 = 1 << 13;
/// Any clause of P-DETECT (the scenarios that keep its ghosts).
pub const T_DETECT: u32 = T_DETECT_RESYNC | T_DETECT_PARTITION | T_DETECT_STALE;

/// The report's name of each terminal bit.
pub const TERMINAL_NAMES: &[(u32, &str)] = &[
    (T_CONC, "P-CONC"),
    (T_LATE_HARMLESS, "P-LATE-HARMLESS"),
    (T_HONEST_ONE_BRANCH, "P-ONE-BRANCH"),
    (T_STRANDED, "P-STRANDED"),
    (T_STRANDED_RAW, "P-STRANDED-RAW"),
    (T_LIVENESS, "P-LIVENESS"),
    (T_JOINED, "P-JOINED"),
    (T_TRANSFER_LEAVE, "P-GOVERNANCE"),
    (T_OWNER_BACK, "P-OWNER-BACK"),
    (T_DETECT_RESYNC, "P-DETECT/resync"),
    (T_DETECT_PARTITION, "P-DETECT/partition"),
    (T_DETECT_STALE, "P-DETECT/stale"),
    (T_NO_FALSE_RESYNC, "P-NO-FALSE-RESYNC"),
    (T_SCN_CL, "P-SCN-CL"),
];

/// Two active members (honest ones only, when `honest_only`) on branches neither of which extends
/// the other.
fn fork(w: &World, cfg: &Cfg, honest_only: bool) -> Option<(usize, usize)> {
    let active: Vec<usize> = (0..NA)
        .filter(|&n| {
            w.m[n].status == Status::Active && !(honest_only && cfg.malicious & abit(n) != 0)
        })
        .collect();
    for (i, &x) in active.iter().enumerate() {
        for &y in &active[i + 1..] {
            if !w.m[x].chain.comparable(w.m[y].chain) {
                return Some((x, y));
            }
        }
    }
    None
}

fn fork_detail(w: &World, f: Option<(usize, usize)>, what: &str) -> String {
    let (x, y) = f.unwrap_or((0, 0));
    format!(
        "{what}: {} on {:?}, {} on {:?}",
        name(x),
        w.m[x].chain,
        name(y),
        w.m[y].chain
    )
}

/// The terminal properties of a quiescent state (nothing left to do but end a session). Returns
/// the bits of `terminal` whose premise held (the property could have failed here).
///
/// - **P-CONC** (D8, CO-10: concurrent candidates are resolved alike; the 20-minute window): with
///   every member online, nothing withheld or delayed and no adversary, honest concurrent commits
///   leave no two active members on different branches. Premise also: no pass over a held foreign
///   candidate (finding F-1 is the run without that clause). It holds **only under its premise**,
///   which few end states meet (the controls print how many).
/// - **P-LATE-HARMLESS** (§19.1 "a late copy is harmless", as F-2 corrects it, §19.34.1 item 2):
///   no two honest active members end on different branches unless a member settled an epoch after
///   a late or ground candidate for it was stored without holding a successor sender of the winner
///   that another member merged before (`History::late_unanchored`), an own copy was lost only by
///   CO-3's demotion (F-5) or a pass was stale (T2). It admits disturbances, process deaths and
///   adversaries, so it covers most end states of the honest-timing controls.
/// - **P-ONE-BRANCH** (F-1's and F-2's probes; D8 "every member picks the same winner", §19.1 "a
///   late copy is harmless"): no two honest active members end on different branches.
/// - **P-STRANDED** (§12.3 "no stranded committer", §19.13): a committer whose own commit another
///   member merged, and that holds a message of another member on it, is not on another branch
///   (OpenMLS cannot open its own commit, so it could never adopt it). Premises: no honest commit
///   was stored after a member had settled its epoch (a late copy: findings F-1 and F-2), and no
///   committer lost its own commit, of which the relays hold a copy, only by CO-3's demotion of an
///   unverified own commit (finding F-5); the findings' probes are the runs without them.
/// - **P-LIVENESS** (§12.3 "liveness"): with the owner online and nothing disturbed, no user's
///   Remove is unmerged (`/remove`) and the owner has no pending work (`/owner`) when nothing else
///   can happen, unless the epoch or commit bound stopped it (a flooding member never blocks the
///   owner's removal of it: SC-FLOOD's `/remove`).
/// - **P-JOINED**, **P-GOVERNANCE**, **P-OWNER-BACK**: the honest flows of SC-JOIN, SC-GOV and
///   SC-OWNER complete (the owner keeps rank 0 after its swap, §19.13). P-JOINED's premise: a
///   committer could still pass.
/// - **P-DETECT** (CS-C4, CO-11, CO-12), on ghost premises (`step::ghost_update`) that no rule
///   reads: a member that for 72 h (three day events) and three sessions since it first held an
///   unopenable foreign blob of its current namespace made no progress at all (merged no other
///   member's commit, first opened no other member's message) and holds three such blobs is in
///   `resync_needed` (`/resync`); a member behind another active member, with no committer commit
///   merged for 9 days, raises `partition_suspected` when it first opened messages of two other
///   members since (`/partition`) and `stale_suspected` when it first opened none for 9 days
///   (`/stale`). The ghosts' "no progress" is stricter than CO-11 (b)'s (fewer than two senders),
///   so the premise implies the rule's.
/// - **P-NO-FALSE-RESYNC** (§19.15 (c), MM-37): a member that shares its branch with another active
///   member is not in `resync_needed` (the scenario's only unopenable blobs are a removed member's,
///   in the draining namespace).
/// - **P-SCN-CL-PARTITION** and **P-SCN-CL-SPLIT** (F-3's probe, §12.3 "detection", SCN-CL, §6.7's
///   table, L8-C17): a subset cut off from a removing commit for good raises
///   `partition_suspected` (or `stale_suspected`) within 9 days; a majority member that has held
///   at least three of the subset's posts unopenable for 72 h of first sightings over three
///   sessions raises `split_suspected`.
pub fn check_terminal(w: &World, cfg: &Cfg, terminal: u32) -> Result<u32, Violation> {
    let mut live = 0u32;
    let clean = !w.h.disturbed && !w.h.adversary && cfg.malicious == 0;
    if terminal & T_CONC != 0 && clean && !w.h.pass_over {
        live |= T_CONC;
        let f = fork(w, cfg, false);
        check(cfg, "P-CONC", f.is_none(), || {
            fork_detail(
                w,
                f,
                "two members end apart after concurrent honest commits",
            )
        })?;
    }
    if terminal & T_LATE_HARMLESS != 0
        && !w.h.late_unanchored
        && !w.h.demoted_copy
        && !w.h.stale_pass
    {
        live |= T_LATE_HARMLESS;
        let f = fork(w, cfg, true);
        check(cfg, "P-LATE-HARMLESS", f.is_none(), || {
            fork_detail(
                w,
                f,
                "honest members fork although every member that settled after a late copy held a \
                 successor of the earlier winner",
            )
        })?;
    }
    if terminal & T_HONEST_ONE_BRANCH != 0 && !w.h.stale_pass {
        live |= T_HONEST_ONE_BRANCH;
        let f = fork(w, cfg, true);
        check(cfg, "P-ONE-BRANCH", f.is_none(), || {
            fork_detail(w, f, "honest members fork")
        })?;
    }
    let stranded_premise = !w.h.late_copy && !w.h.demoted_copy;
    let raw = terminal & T_STRANDED_RAW != 0;
    if raw || (terminal & T_STRANDED != 0 && stranded_premise) {
        live |= if raw { T_STRANDED_RAW } else { T_STRANDED };
        for c in [C0, C1] {
            let me = &w.m[c];
            if me.status != Status::Active {
                continue;
            }
            for s in 0..NC {
                if !w.c[s].used || w.c[s].author != c as u8 || w.c[s].flags & F_ADVERSARY != 0 {
                    continue;
                }
                let merged_by_other = (0..NA).any(|n| {
                    n != c && w.m[n].status.holds_state() && {
                        let ch = w.m[n].chain;
                        (0..ch.len()).any(|i| ch.at(i) == s)
                    }
                });
                if !merged_by_other {
                    continue;
                }
                let at = w.c[s].parent.push(s);
                let holds_successor = (0..NB).any(|i| {
                    me.fetched & bit(i) != 0
                        && w.b[i].author != c as u8
                        && epoch_chain(w, i) == Some(at)
                });
                check(
                    cfg,
                    "P-STRANDED",
                    !(holds_successor && !at.comparable(me.chain)),
                    || {
                        format!(
                            "{} holds messages on its own commit k{s}, which others merged, and \
                             is on {:?}",
                            name(c),
                            me.chain
                        )
                    },
                )?;
            }
        }
    }
    if terminal & T_LIVENESS != 0 && !w.h.disturbed {
        live |= T_LIVENESS;
        // A Remove the user asked for is merged by the asking committer, while it can still pass.
        for c in [C0, C1] {
            let me = &w.m[c];
            if w.h.asked & abit(c) == 0 || me.status != Status::Active || !me.online {
                continue;
            }
            let g = group_of(w, &cfg.genesis, me.chain, cfg.rules);
            let target = cfg.remove_target as usize;
            let unmerged = g.is_member(target)
                && me.chain.len() < cfg.depth
                && (me.seq as usize) < cfg.commit_budget[c] as usize
                && g.rank(c) != 255;
            check(cfg, "P-LIVENESS/remove", !unmerged, || {
                format!(
                    "{}'s user asked to remove {}, who is still a member at {:?} with nothing left \
                     to do",
                    name(c),
                    name(target),
                    me.chain
                )
            })?;
        }
        let me = &w.m[C0];
        let pending = me.work & !(W_RESIGN | W_TRANSFER);
        let stuck = me.online
            && me.status == Status::Active
            && pending != 0
            && me.chain.len() < cfg.depth
            && (me.seq as usize) < cfg.commit_budget[C0] as usize;
        check(cfg, "P-LIVENESS/owner", !stuck, || {
            format!(
                "the owner is online with pending work {pending:#b} at {:?} and nothing can happen",
                me.chain
            )
        })?;
    }
    if terminal & T_JOINED != 0 && w.m[J].status != Status::Absent {
        // The admission is still possible: a committer recorded the request, may commit it now
        // (CO-8: rank 0 at once, rank r ≥ 1 once it is r × 48 h old) and can still pass within
        // the bounds. The property is evaluated where J joined or such a committer exists.
        let could_admit = [C0, C1].iter().any(|&c| {
            let me = &w.m[c];
            let g = group_of(w, &cfg.genesis, me.chain, cfg.rules);
            me.status == Status::Active
                && me.chain.len() < cfg.depth
                && (me.seq as usize) < cfg.commit_budget[c] as usize
                && me.work & W_JOIN != 0
                && (g.rank(c) == 0 || me.aged & W_JOIN != 0)
        });
        let joining = w.m[J].status == Status::Joining;
        if !joining || could_admit {
            live |= T_JOINED;
        }
        check(cfg, "P-JOINED", !(joining && could_admit), || {
            "J's join request is never answered by a Welcome it can apply".to_string()
        })?;
    }
    if terminal & T_TRANSFER_LEAVE != 0 {
        live |= T_TRANSFER_LEAVE;
        let c1 = &w.m[C1];
        let g = group_of(w, &cfg.genesis, c1.chain, cfg.rules);
        let can_pass = c1.status == Status::Active
            && c1.chain.len() < cfg.depth
            && (c1.seq as usize) < cfg.commit_budget[C1] as usize;
        let done = w.m[C0].status == Status::Left && !g.is_member(C0) && g.rank(C1) == 0;
        check(cfg, "P-GOVERNANCE", done || !can_pass, || {
            format!(
                "the owner's transfer, resignation and leave did not complete: C0 {:?}, C1 at {:?} \
                 with rank {}",
                w.m[C0].status,
                c1.chain,
                g.rank(C1)
            )
        })?;
    }
    if terminal & T_OWNER_BACK != 0 {
        live |= T_OWNER_BACK;
        let me = &w.m[C0];
        let on_live = [C1, M0, M1]
            .iter()
            .filter(|&&o| w.m[o].status == Status::Active)
            .all(|&o| w.m[o].chain.comparable(me.chain));
        let rank0 = group_of(w, &cfg.genesis, me.chain, cfg.rules).rank(C0) == 0;
        check(
            cfg,
            "P-OWNER-BACK",
            me.status == Status::Active && on_live && rank0,
            || {
                format!(
                    "the owner ends {:?} on {:?} (rank 0: {rank0}), not readmitted",
                    me.status, me.chain
                )
            },
        )?;
    }
    if terminal & T_DETECT != 0 && w.day >= cfg.days {
        for n in 0..NA {
            let me = &w.m[n];
            if !matches!(me.status, Status::Active | Status::Resync) {
                continue;
            }
            if terminal & T_DETECT_RESYNC != 0 {
                let g = group_of(w, &cfg.genesis, me.chain, cfg.rules);
                let u = crate::step::unopenable_in(w, &cfg.genesis, cfg.rules, n, g.ns);
                if me.g1 >= WINDOW_72H && me.g1s >= 3 && !me.g1p && u >= 3 {
                    live |= T_DETECT_RESYNC;
                    check(cfg, "P-DETECT/resync", me.status == Status::Resync, || {
                        format!(
                            "{} held {u} unopenable blobs of its namespace for 72 h and three \
                             sessions with no progress at all, and is not in resync_needed",
                            name(n)
                        )
                    })?;
                }
            }
            if me.status != Status::Active {
                continue;
            }
            let behind = (0..NA).any(|o| {
                o != n
                    && w.m[o].status == Status::Active
                    && me.chain.is_prefix_of(w.m[o].chain)
                    && w.m[o].chain.len() > me.chain.len()
            });
            if !behind || me.gc < 9 {
                continue;
            }
            if terminal & T_DETECT_PARTITION != 0 && (me.gm & !abit(n)).count_ones() >= 2 {
                live |= T_DETECT_PARTITION;
                check(
                    cfg,
                    "P-DETECT/partition",
                    me.flags & FL_PARTITION != 0,
                    || {
                        format!(
                            "{} is cut off from the committers' commits for 9 days while two other \
                             members' messages arrived, without partition_suspected",
                            name(n)
                        )
                    },
                )?;
            }
            let g = group_of(w, &cfg.genesis, me.chain, cfg.rules);
            let committers_else = g.committer_set() & !abit(n) != 0;
            if terminal & T_DETECT_STALE != 0 && me.gq >= 9 && committers_else {
                live |= T_DETECT_STALE;
                check(cfg, "P-DETECT/stale", me.flags & FL_STALE != 0, || {
                    format!(
                        "{} has merged no committer commit and opened no message for 9 days \
                         (silent orphan) without stale_suspected",
                        name(n)
                    )
                })?;
            }
        }
    }
    if terminal & T_NO_FALSE_RESYNC != 0 {
        live |= T_NO_FALSE_RESYNC;
        for n in 0..NA {
            let me = &w.m[n];
            if me.status != Status::Resync {
                continue;
            }
            let shared = (0..NA)
                .any(|o| o != n && w.m[o].status == Status::Active && w.m[o].chain == me.chain);
            check(cfg, "P-NO-FALSE-RESYNC", !shared, || {
                format!(
                    "{} is in resync_needed on the live branch {:?} (spam of a removed member in \
                     the draining namespace)",
                    name(n),
                    me.chain
                )
            })?;
        }
    }
    if terminal & T_SCN_CL != 0 && w.day >= cfg.days {
        live |= T_SCN_CL;
        for n in [M0, J] {
            let me = &w.m[n];
            check(
                cfg,
                "P-SCN-CL-PARTITION",
                !(me.status == Status::Active && me.flags & (FL_PARTITION | FL_STALE) == 0),
                || {
                    format!(
                        "{} (the subset the removal was withheld from) raises neither \
                         partition_suspected nor stale_suspected by day {}",
                        name(n),
                        w.day
                    )
                },
            )?;
        }
        let me = &w.m[C0];
        let held = crate::step::unopenable_any(w, &cfg.genesis, cfg.rules, C0);
        let due = me.status == Status::Active && me.gw >= WINDOW_72H && me.gs >= 3 && held >= 3;
        check(
            cfg,
            "P-SCN-CL-SPLIT",
            !(due && me.flags & FL_SPLIT == 0),
            || {
                format!(
                    "C0 (majority) has held {held} of the subset's posts unopenable for 72 h over \
                     three sessions by day {} and raises no split_suspected",
                    w.day
                )
            },
        )?;
    }
    Ok(live)
}
