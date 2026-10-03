//! The transition system: every action an actor, the relays, time or the adversary can take, and
//! the decision-time properties checked inside the transaction that would break them.
//!
//! Each action is one transaction (CS-C1): a process death before it leaves the world unchanged,
//! which is the same successor as not taking the action, so death is the [`Action::Offline`]
//! that ends the session and clears what a session holds (the EM-1 argument, extended).

use crate::model::*;
use crate::props::{self, Violation};
use crate::rules::{Fix, Mutant, Rules};

/// Enabled action kinds of a scenario (bits of [`Cfg::acts`]).
pub const A_SESSIONS: u32 = 1;
pub const A_POST: u32 = 1 << 1;
pub const A_PASS: u32 = 1 << 2;
pub const A_SELFUPDATE: u32 = 1 << 3;
pub const A_JOIN: u32 = 1 << 4;
pub const A_REMOVE: u32 = 1 << 5;
pub const A_LEAVE: u32 = 1 << 6;
pub const A_RESIGN: u32 = 1 << 7;
pub const A_TRANSFER: u32 = 1 << 8;
pub const A_REJOIN: u32 = 1 << 9;
pub const A_AGE: u32 = 1 << 10;
pub const A_WORKAGE: u32 = 1 << 11;
pub const A_PCS: u32 = 1 << 12;
pub const A_SLOT: u32 = 1 << 13;
pub const A_DAY: u32 = 1 << 14;
pub const A_EXPIRE: u32 = 1 << 15;
pub const A_RELEASE: u32 = 1 << 16;
pub const A_INDETERMINATE: u32 = 1 << 17;
pub const A_GRIND: u32 = 1 << 18;
pub const A_JUNK: u32 = 1 << 19;
pub const A_SPAM: u32 = 1 << 20;
pub const A_REPLAY: u32 = 1 << 21;
pub const A_NEWSIGNER: u32 = 1 << 22;
pub const A_PROPOSALS: u32 = 1 << 23;
pub const A_REPLAY_SWAP: u32 = 1 << 24;
pub const A_TICK: u32 = 1 << 25;
pub const A_FLOOD: u32 = 1 << 26;

/// A scenario: the rule set and what may happen.
#[derive(Clone, Debug)]
pub struct Cfg {
    pub name: &'static str,
    pub genesis: Genesis,
    pub rules: Rules,
    /// Epoch transitions explored (≤ [`MAX_DEPTH`]).
    pub depth: usize,
    pub acts: u32,
    pub post_budget: [u8; NA],
    pub commit_budget: [u8; NA],
    /// Masks the relays may choose to withhold a stored blob of a kind in `withhold_kinds` with
    /// (FORK, WITHHOLD_COMMIT, a partition). Withholding nothing is always one of the choices.
    pub withhold_masks: &'static [u8],
    pub withhold_kinds: u8,
    /// Commit slots the relays may withhold (all when 0).
    pub withhold_slots: u16,
    /// T1 of the header: an honest commit built at a concurrent pass is stored before any member's
    /// settle window for that epoch elapses, and before any sibling's store-hour anchor, while its
    /// author stays online.
    pub honest_timing: bool,
    /// The pseudonym a user Remove targets, and the committer whose user asks for it.
    pub remove_target: u8,
    pub remover: u8,
    /// The member that leaves, when A_LEAVE is on.
    pub leaver: u8,
    /// Actors the adversary controls.
    pub malicious: u8,
    /// The day horizon of day-scale scenarios (A_DAY).
    pub days: u8,
    /// Q42 (b)'s world (only with the lifetime mutants): honest KeyPackages carry a finite
    /// lifetime, and members' device clocks straddle its bound.
    pub finite_kp: bool,
    /// Actors that may change session (A_SESSIONS); others stay as they start.
    pub session_actors: u8,
    /// Session changes allowed per actor (an end and a start count one each).
    pub session_budget: u8,
    /// Actors that may post (A_POST).
    pub posters: u8,
    /// The committer whose user may resign (A_RESIGN).
    pub resigner: u8,
    /// Terminal properties checked on quiescent states (bits `T_*` of `props`).
    pub terminal: u32,
}

/// An action, for the trace of a counter-example.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Action {
    Online(u8),
    Offline(u8),
    List(u8),
    Tick(u8),
    Store {
        blob: u8,
        withheld: u8,
        indeterminate: bool,
    },
    Indeterminate(u8),
    OwnGone(u8),
    Post(u8),
    Leave(u8),
    Pass {
        actor: u8,
        hash: u8,
    },
    /// The F-1 correction: a settle and, in the same actor step, the committer's pass.
    TickPass {
        actor: u8,
        hash: u8,
    },
    SelfUpdate {
        actor: u8,
        hash: u8,
    },
    UserRemove(u8),
    UserResign(u8),
    UserTransfer(u8),
    Accept,
    Rejoin(u8),
    Age(u8),
    WorkAge(u8),
    PcsDue(u8),
    SlotDue(u8),
    Day,
    Expire(u8),
    Release,
    Grind {
        parent: Chain,
    },
    Junk,
    NewSigner,
    Proposals,
    Flood,
    Spam {
        ns: Chain,
    },
    Replay,
    ReplaySwap {
        restore: bool,
        hash: u8,
    },
    /// Not an action: the state reached by the previous action breaks a state property.
    Observe,
}

impl std::fmt::Display for Action {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let n = |a: &u8| ACTOR_NAMES.get(*a as usize).copied().unwrap_or("?");
        match self {
            Action::Online(a) => write!(f, "{} starts a session", n(a)),
            Action::Offline(a) => write!(f, "{}'s session ends (or its process dies)", n(a)),
            Action::List(a) => write!(f, "{} completes a listing pass", n(a)),
            Action::Tick(a) => write!(
                f,
                "20 min after {}'s anchor (CO-4 (i)) it completes a listing pass",
                n(a)
            ),
            Action::Store {
                blob,
                withheld,
                indeterminate,
            } => {
                write!(f, "blob b{blob} is stored")?;
                if *withheld != 0 {
                    let who: Vec<&str> = (0..NA)
                        .filter(|&x| withheld & abit(x) != 0)
                        .map(|x| ACTOR_NAMES[x])
                        .collect();
                    write!(f, ", withheld from {}", who.join(", "))?;
                }
                if *indeterminate {
                    write!(f, "; its op closes INDETERMINATE")?;
                }
                Ok(())
            }
            Action::Indeterminate(a) => {
                write!(
                    f,
                    "{}'s commit op closes INDETERMINATE, no copy stored",
                    n(a)
                )
            }
            Action::OwnGone(a) => write!(
                f,
                "{}'s own commit is cleared (deadline + handshake TTL, CO-4 (c))",
                n(a)
            ),
            Action::Post(a) => write!(f, "{} posts", n(a)),
            Action::Leave(a) => write!(f, "{} posts LEAVE and leaves", n(a)),
            Action::Pass { actor, hash } => {
                write!(f, "{} passes (commit, hash rank {hash})", n(actor))
            }
            Action::TickPass { actor, hash } => write!(
                f,
                "20 min after {}'s anchor it lists, settles and passes at once (hash rank {hash})",
                n(actor)
            ),
            Action::SelfUpdate { actor, hash } => {
                write!(f, "{} self-updates (hash rank {hash})", n(actor))
            }
            Action::UserRemove(a) => write!(f, "{}'s user removes a member", n(a)),
            Action::UserResign(a) => write!(f, "{}'s user resigns", n(a)),
            Action::UserTransfer(a) => write!(f, "{}'s user transfers rank 0", n(a)),
            Action::Accept => write!(f, "J accepts its invite (join request stored)"),
            Action::Rejoin(a) => write!(f, "{}'s user asks to rejoin (resync)", n(a)),
            Action::Age(b) => write!(f, "blob b{b}'s store-hour anchor passes"),
            Action::WorkAge(a) => write!(f, "{}'s pending work becomes 48 h old", n(a)),
            Action::PcsDue(a) => write!(f, "{}'s PCS commit becomes due", n(a)),
            Action::SlotDue(a) => write!(f, "{}'s self-update slot comes", n(a)),
            Action::Day => write!(f, "a day passes"),
            Action::Expire(b) => write!(f, "blob b{b} expires at the relays"),
            Action::Release => write!(
                f,
                "the relays end the partition (every withheld blob served)"
            ),
            Action::Grind { parent } => write!(
                f,
                "M1 stores a self-update for the settled epoch after {parent:?}, ground below its \
                 siblings"
            ),
            Action::Junk => write!(
                f,
                "M1 commits an Add carrying an expired finite-lifetime KeyPackage"
            ),
            Action::NewSigner => write!(f, "M1 commits an update path with a new signature key"),
            Action::Proposals => write!(f, "M1 commits a Remove of M0 at rank 255"),
            Action::Flood => write!(f, "M1 floods a self-update (whatever CO-14 says)"),
            Action::Spam { ns } => write!(f, "an unopenable blob is stored in namespace {ns:?}"),
            Action::Replay => write!(f, "an insider re-stores a copy of the rejoin request"),
            Action::ReplaySwap { restore, hash } => write!(
                f,
                "C1 commits a {} swap of M0 with J's join KeyPackage re-wrapped (hash rank {hash})",
                if *restore { "restore" } else { "rejoin" }
            ),
            Action::Observe => write!(f, "(the state reached breaks a state property)"),
        }
    }
}

/// Reachability events (the search ORs them over every transition).
pub const EV_SETTLE_CONCURRENT: u64 = 1;
pub const EV_SUCCESSORS_DECIDED: u64 = 1 << 1;
pub const EV_ABANDONED: u64 = 1 << 2;
pub const EV_LATE_CANDIDATE: u64 = 1 << 3;
pub const EV_HOLD: u64 = 1 << 4;
pub const EV_OWN_FROM_SUCCESSORS: u64 = 1 << 5;
pub const EV_SELFUPDATE_MERGED: u64 = 1 << 6;
pub const EV_CATCHUP2: u64 = 1 << 7;
pub const EV_JOINED: u64 = 1 << 8;
pub const EV_REMOVED: u64 = 1 << 9;
pub const EV_REJOINED: u64 = 1 << 10;
pub const EV_RESYNC: u64 = 1 << 11;
pub const EV_SPLIT: u64 = 1 << 12;
pub const EV_PARTITION: u64 = 1 << 13;
pub const EV_STALE: u64 = 1 << 14;
pub const EV_TRANSFER: u64 = 1 << 15;
pub const EV_RESIGN: u64 = 1 << 16;
pub const EV_LEFT: u64 = 1 << 17;
pub const EV_DEPTH_MAX: u64 = 1 << 18;
pub const EV_OWN_CLEARED: u64 = 1 << 19;
pub const EV_LOSER_REPASS: u64 = 1 << 20;
pub const EV_WAIT: u64 = 1 << 21;
pub const EV_ROTATED: u64 = 1 << 22;
pub const EV_REJOIN_REFUSED: u64 = 1 << 23;
pub const EV_INVALID_HELD: u64 = 1 << 24;
pub const EV_GROUND_LATE: u64 = 1 << 25;
pub const EV_RANK255_PASS: u64 = 1 << 26;
pub const EV_PROGRESS_RESET: u64 = 1 << 27;
pub const EV_OWNER_READMITTED: u64 = 1 << 28;
pub const EV_SETTLE_RANK_DECIDED: u64 = 1 << 29;
pub const EV_WELCOME_REFUSED: u64 = 1 << 30;
pub const EV_LATE_POST: u64 = 1 << 31;
pub const EV_AGED_WORK: u64 = 1 << 32;
pub const EV_CATCHUP: u64 = 1 << 33;
pub const EV_DRAIN_SPAM: u64 = 1 << 34;
pub const EV_REPLACED_OWN: u64 = 1 << 35;
pub const EV_CLEAR_INDETERMINATE: u64 = 1 << 36;
pub const EV_REMOVED_READS: u64 = 1 << 37;
pub const EV_SPAM_RESYNC: u64 = 1 << 38;
pub const EV_REMOVAL_MERGED: u64 = 1 << 39;
pub const EV_SETTLE_PASS: u64 = 1 << 40;
pub const EV_OWN_FETCHED: u64 = 1 << 41;
pub const EV_DOUBLE_ADMIT: u64 = 1 << 42;

/// A successor: the action, the world after it and what it did.
pub struct Succ {
    pub action: Action,
    pub world: World,
    pub ev: u64,
    /// Epochs settled by the transition (CO-3 decisions taken).
    pub settles: u32,
}

/// One transaction under construction.
pub struct Step<'a> {
    pub cfg: &'a Cfg,
    pub w: World,
    pub ev: u64,
    pub settles: u32,
}

impl<'a> Step<'a> {
    pub fn new(cfg: &'a Cfg, w: &World) -> Self {
        Step {
            cfg,
            w: *w,
            ev: 0,
            settles: 0,
        }
    }

    fn rules(&self) -> Rules {
        self.cfg.rules
    }

    fn group(&self, chain: Chain) -> Group {
        group_of(&self.w, &self.cfg.genesis, chain, self.cfg.rules)
    }

    fn cands(&self, m: usize) -> (u16, bool) {
        candidates(&self.w, &self.cfg.genesis, self.cfg.rules, m)
    }

    /// The member is current (§6.3.1): a listing pass in this session, every openable blob
    /// processed (the model processes at once), not blocked (only under the withdrawn lifetime
    /// rules), active, and no valid candidate that removes a pseudonym (the removal hold, CO-13).
    pub fn current(&self, m: usize) -> bool {
        let me = &self.w.m[m];
        if me.status != Status::Active || !me.online || !me.listed {
            return false;
        }
        let (cands, pending) = self.cands(m);
        if cands == 0 && pending {
            return false;
        }
        !self.holds_removal(cands)
    }

    /// CO-13: a valid candidate for the member's current epoch removes a pseudonym (Remove, leave,
    /// eviction, swap); its own pending commit counts (§6.3.1, revised §19.13).
    pub fn holds_removal(&self, cands: u16) -> bool {
        if self.rules().is(Mutant::NoHold) {
            return false;
        }
        (0..NC).any(|s| cands & (1 << s) != 0 && self.w.c[s].removes_someone())
    }

    /// The tie-break positions a new commit of `author` may take among its siblings: every
    /// position when a sibling of the same rank exists (CO-3 then reads the hash), otherwise above
    /// them all (the rank decides; the creation order still varies the hash order across runs).
    fn hash_positions(&self, parent: Chain, author: usize) -> Vec<u8> {
        let g = self.group(parent);
        let rank = g.rank(author);
        let sib: Vec<usize> = (0..NC)
            .filter(|&s| self.w.c[s].used && self.w.c[s].parent == parent)
            .collect();
        let n = sib.len() as u8;
        let same = sib
            .iter()
            .any(|&s| g.rank(self.w.c[s].author as usize) == rank);
        if same || self.rules().is(Mutant::HashOnly) {
            (0..=n).collect()
        } else {
            vec![n]
        }
    }

    /// Inserts a new commit at tie-break position `pos` among its siblings; the siblings' hashes are
    /// renumbered 0, 1, … in order (only their order is ever read).
    fn insert_commit(&mut self, slot: usize, mut k: Commit, pos: u8) {
        let parent = k.parent;
        let mut sib: Vec<usize> = (0..NC)
            .filter(|&s| self.w.c[s].used && self.w.c[s].parent == parent)
            .collect();
        sib.sort_by_key(|&s| self.w.c[s].hash);
        for (i, &s) in sib.iter().enumerate() {
            self.w.c[s].hash = 2 * i as u8 + 2;
        }
        k.hash = 2 * pos + 1;
        k.used = true;
        self.w.c[slot] = k;
        sib.push(slot);
        sib.sort_by_key(|&s| self.w.c[s].hash);
        for (i, &s) in sib.iter().enumerate() {
            self.w.c[s].hash = i as u8;
        }
        let g = self.group(parent);
        self.w.b[slot] = Blob {
            kind: B_COMMIT,
            author: k.author,
            chain: parent,
            ns: g.ns,
            ops: 2,
            inc: k.inc,
            ..Blob::default()
        };
    }

    /// A listing pass of member `m`: it fetches every stored blob visible to it, records requests,
    /// joins on a Welcome for it, and settles where CO-4 allows.
    pub fn list(&mut self, m: usize) -> Result<(), Violation> {
        let first = !self.w.m[m].listed;
        let newly =
            visible_mask(&self.w, &self.cfg.genesis, self.rules(), m) & !self.w.m[m].fetched;
        self.w.m[m].fetched |= newly;
        self.w.m[m].listed = true;
        self.late_blobs(m, newly)?;
        self.welcomes(m)?;
        // CO-4 (ii): this pass completes after (i) held when (i) holds now.
        if self.window_holds(m) {
            self.w.m[m].after = true;
        }
        self.pump(m)?;
        if first {
            props::check_catchup(&self.w, self.cfg, m)?;
        }
        self.liveness(m);
        let me = self.w.m[m];
        if me.status == Status::Active && me.posts < self.cfg.post_budget[m] {
            let (cands, _) = self.cands(m);
            if self.holds_removal(cands) {
                self.ev |= EV_HOLD;
            }
        }
        Ok(())
    }

    /// CO-4 (i) for the member's current epoch: 20 minutes after its anchor, the earliest over the
    /// held candidates of min(its own sighting, the store hour + 60 min).
    fn window_holds(&self, m: usize) -> bool {
        if self.rules().is(Mutant::NoWindow) {
            return true;
        }
        let me = &self.w.m[m];
        if me.window {
            return true;
        }
        if self.rules().is(Mutant::NoStoreHourAnchor) {
            return false;
        }
        let (cands, _) = self.cands(m);
        (0..NC).any(|s| {
            cands & (1 << s) != 0
                && me.fetched & bit(s) != 0
                && self.w.b[s].stored
                && self.w.b[s].old
        })
    }

    /// Settles as long as CO-4's settle point holds (catch-up: a returning member's anchors lie in
    /// the past, so it settles epoch after epoch in one listing pass).
    fn pump(&mut self, m: usize) -> Result<(), Violation> {
        let mut settled = 0;
        let via_anchor = !self.w.m[m].window && !self.rules().is(Mutant::NoWindow);
        loop {
            let me = self.w.m[m];
            if !matches!(me.status, Status::Active | Status::Resync) || !me.online {
                break;
            }
            if me.chain.len() >= MAX_DEPTH {
                break;
            }
            let i_holds = self.window_holds(m);
            let ii_holds = self.rules().is(Mutant::NoWindow)
                || self.rules().is(Mutant::NoListingPass)
                || me.after;
            if !(i_holds && ii_holds) {
                break;
            }
            let choice = decide(&self.w, &self.cfg.genesis, self.rules(), m);
            props::check_choice(&self.w, self.cfg, m, &choice)?;
            match choice.decision {
                Decision::Merge(s) => {
                    self.settle(m, s, &choice)?;
                    settled += 1;
                    // The listing pass that fetched the next epoch's candidates came after their
                    // anchors when those lie in the past (store-hour anchor): (ii) holds again.
                    self.w.m[m].after = self.window_holds(m);
                }
                Decision::Wait => {
                    self.ev |= EV_WAIT;
                    break;
                }
                Decision::Nothing => break,
            }
        }
        if settled >= 1 && via_anchor {
            self.ev |= EV_CATCHUP;
        }
        if settled >= 2 {
            self.ev |= EV_CATCHUP2;
        }
        // Inbox.reofferDeferred (§7.5): what the new epoch opens is processed again.
        self.record_requests(m);
        self.mark_opened(m);
        Ok(())
    }

    /// Marks every fetched blob that opens under the member's present keys as processed (its first
    /// sighting, or the re-offer after a settle or a Welcome, §7.5): CO-11 (a) counts only blobs
    /// that stayed unopenable, so a post read under a retained past epoch never counts later.
    fn mark_opened(&mut self, m: usize) {
        let me = self.w.m[m];
        let mut opened = me.opened;
        for i in 0..NB {
            if me.fetched & bit(i) != 0
                && opened & bit(i) == 0
                && opens(&self.w, &self.cfg.genesis, self.rules(), m, i)
            {
                opened |= bit(i);
            }
        }
        self.w.m[m].opened = opened;
    }

    /// CO-5: merges the winner. The epoch is then final at this member.
    fn settle(&mut self, m: usize, s: usize, choice: &Choice) -> Result<(), Violation> {
        let before = self.w.m[m];
        let g = self.group(before.chain);
        let k = self.w.c[s];
        props::check_merge(&self.w, self.cfg, m, s, choice, &g)?;
        self.settles += 1;
        if choice.candidates.count_ones() > 1 {
            self.ev |= EV_SETTLE_CONCURRENT;
            let succ: Vec<u8> = (0..NC)
                .filter(|&x| choice.candidates & (1 << x) != 0)
                .map(|x| choice.successors[x])
                .collect();
            if succ.iter().any(|&c| c != succ[0]) {
                self.ev |= EV_SUCCESSORS_DECIDED;
            } else {
                self.ev |= EV_SETTLE_RANK_DECIDED;
            }
        }
        if choice.abandoned != 0 {
            self.ev |= EV_ABANDONED;
        }
        let own = before.own;
        let chain = before.chain.push(s);
        {
            let day = self.w.day;
            let me = &mut self.w.m[m];
            me.chain = chain;
            me.window = false;
            me.after = false;
            me.settle_day = day;
        }
        if own as usize == s {
            if choice.successors[s] >= 1 && before.op != Op::Verified {
                self.ev |= EV_OWN_FROM_SUCCESSORS;
            }
            if before.op != Op::Verified && before.fetched & bit(s) != 0 {
                self.ev |= EV_OWN_FETCHED;
            }
            self.w.m[m].own = NONE;
            self.w.m[m].op = Op::None;
            if !self.rules().is(Mutant::WelcomeAtPass) {
                self.make_welcomes(s, chain);
            }
        } else if own != NONE && self.w.c[own as usize].parent == before.chain {
            // CO-4 (b): another candidate won at a settle point; the own commit is cleared and its
            // work stays pending for the next pass (CO-10).
            props::check_settle_clear(&self.w, m, own as usize, s)?;
            let o = own as usize;
            let verified = before.op == Op::Verified
                || (self.rules().fixed(Fix::FetchedOwnCopy) && before.fetched & bit(o) != 0);
            if self.w.b[o].stored
                && !verified
                && choice.successors[o] == choice.successors[s]
                && (g.rank(m), self.w.c[o].hash) < (g.rank(k.author as usize), k.hash)
            {
                self.w.h.demoted_copy = true;
            }
            self.w.m[m].own = NONE;
            self.w.m[m].op = Op::None;
            self.ev |= EV_OWN_CLEARED;
            if self.rules().is(Mutant::DropLoserWork) {
                self.w.m[m].work = 0;
                self.w.m[m].aged = 0;
            }
            if !self.w.c[own as usize].has_proposals() && g.rank(m) == 255 {
                // CO-9: a lost self-update is retried at the next session after 24 h.
                self.w.m[m].slot = false;
            }
        }
        if g.rank(k.author as usize) == 255 && !k.has_proposals() {
            self.ev |= EV_SELFUPDATE_MERGED;
        }
        if chain.len() == self.cfg.depth {
            self.ev |= EV_DEPTH_MAX;
        }
        let ng = self.group(chain);
        if ng.gen != g.gen {
            self.ev |= EV_ROTATED;
        }
        if k.ctx == CTX_TRANSFER {
            self.ev |= EV_TRANSFER;
        }
        if k.ctx == CTX_RESIGN {
            self.ev |= EV_RESIGN;
        }
        if k.remove != NONE {
            self.ev |= EV_REMOVAL_MERGED;
        }
        // F-2's correction: a settle beacon in the new epoch for a winner it did not author.
        if self.rules().fixed(Fix::SettleBeacon)
            && k.author != m as u8
            && self.cfg.malicious & abit(m) == 0
            && k.remove != m as u8
            && k.swap != m as u8
        {
            let me = self.w.m[m];
            if ((me.posts + me.beacons) as usize) < POSTS_PER_ACTOR {
                let slot = B_POST0 + m * POSTS_PER_ACTOR + (me.posts + me.beacons) as usize;
                self.w.b[slot] = Blob {
                    kind: B_POST,
                    author: m as u8,
                    chain,
                    ns: ng.ns,
                    stored: true,
                    ops: 2,
                    aux: 2,
                    inc: me.inc,
                    ..Blob::default()
                };
                self.w.m[m].beacons += 1;
            }
        }
        // The member's own fate (§6.6, §6.7).
        if k.remove == m as u8 {
            self.w.m[m].status = Status::Removed;
            self.w.m[m].own = NONE;
            self.ev |= EV_REMOVED;
        } else if k.swap == m as u8 {
            if kp_owner(k.kp) == m && self.w.m[m].kp & (1 << kp_instance(k.kp)) != 0 {
                // Its own KeyPackage (a copied rejoin request): it completes its own rejoin
                // through the Welcome (§6.7 "What a replay can still do").
                self.w.m[m].status = Status::Joining;
                self.ev |= EV_REPLACED_OWN;
            } else {
                self.w.m[m].status = Status::Replaced;
            }
            self.w.m[m].own = NONE;
        }
        // Committer bookkeeping at settle (§6.2.4 (B), §6.7, §6.6, §19.2).
        {
            let me = &mut self.w.m[m];
            let had = me.work;
            if k.admit {
                me.work &= !W_JOIN;
            }
            if k.remove != NONE {
                me.work &= !(W_REMOVE | W_LEAVE);
            }
            if k.swap != NONE {
                me.work &= !W_REJOIN;
            }
            if k.author == m as u8 {
                if k.ctx == CTX_RESIGN {
                    me.work &= !W_RESIGN;
                }
                if k.ctx == CTX_TRANSFER {
                    me.work &= !W_TRANSFER;
                }
                me.pcs = false;
            }
            if ng.rank(m) == 255 {
                me.work &= !(W_RESIGN | W_TRANSFER | W_REMOVE);
            }
            me.aged &= me.work;
            if had & (W_JOIN | W_REMOVE | W_LEAVE | W_REJOIN) != 0
                && me.work & (W_JOIN | W_REMOVE | W_LEAVE | W_REJOIN) == 0
            {
                me.tries = 0;
            }
            // CO-12: a committer commit merged resets the partition and stale clocks.
            if g.rank(k.author as usize) != 255 {
                me.qd = 0;
                me.msgs = 0;
            }
            // CO-11 (b): a commit from another member merged is progress.
            if k.author != m as u8 {
                me.prog = true;
            }
        }
        Ok(())
    }

    /// Welcome blobs of an own winning commit (CO-5; §19.2): one per joiner, in the namespace its
    /// request came from.
    fn make_welcomes(&mut self, s: usize, chain: Chain) {
        let k = self.w.c[s];
        if k.admit {
            self.w.b[B_WELCOME_J] = Blob {
                kind: B_WELCOME,
                author: k.author,
                chain,
                ns: self.w.b[B_JOIN].ns,
                ops: 2,
                aux: s as u8,
                inc: k.inc,
                ..Blob::default()
            };
        }
        if k.swap != NONE && k.flags & F_ADVERSARY == 0 {
            // The namespace of the copy the committer fetched (it shares that generation).
            let me = &self.w.m[k.author as usize];
            let ns = [B_REJOIN, B_REJOIN + 1, B_REPLAY]
                .into_iter()
                .find(|&i| me.fetched & bit(i) != 0 && self.w.b[i].kind == B_REJOINREQ)
                .map(|i| self.w.b[i].ns)
                .unwrap_or(self.group(k.parent).ns);
            self.w.b[B_WELCOME_R] = Blob {
                kind: B_WELCOME,
                author: k.author,
                chain,
                ns,
                ops: 2,
                aux: s as u8,
                inc: k.inc,
                ..Blob::default()
            };
        }
    }

    /// A joiner (J) or a rejoiner applies a Welcome for a KeyPackage it holds, after the committers
    /// anchor (§6.2.5, §19.27 TR-7, §19.29.2).
    fn welcomes(&mut self, m: usize) -> Result<(), Violation> {
        let me = self.w.m[m];
        if !matches!(
            me.status,
            Status::Joining | Status::Resync | Status::Reinvite | Status::Active
        ) {
            return Ok(());
        }
        for wi in [B_WELCOME_J, B_WELCOME_R] {
            let wb = self.w.b[wi];
            if me.fetched & bit(wi) == 0 || wb.kind != B_WELCOME {
                continue;
            }
            let s = wb.aux as usize;
            let k = self.w.c[s];
            let for_me = (k.admit && m == J && me.kp & (1 << KP_JOIN) != 0)
                || (k.swap == m as u8
                    && kp_owner(k.kp) == m
                    && me.kp & (1 << kp_instance(k.kp)) != 0);
            // An active member applies no Welcome (it expects none).
            if !for_me || me.status == Status::Active {
                continue;
            }
            // The committers anchor: for a join, the joined committer set is the invite's and a
            // committer of it signed; for a rejoin, the signer is a committer of the member's last
            // final epoch (no digest comparison, §19.29.2).
            let joined = self.group(wb.chain);
            let anchored = if k.admit && m == J {
                let set = self.cfg.genesis.invite_committers();
                joined.committer_set() == set && set & abit(k.author as usize) != 0
            } else {
                let last = self.group(me.chain);
                last.committer_set() & abit(k.author as usize) != 0
            };
            if !anchored {
                self.ev |= EV_WELCOME_REFUSED;
                continue;
            }
            props::check_welcome(&self.w, s)?;
            let inc = joined.inc[m];
            let day = self.w.day;
            let me = &mut self.w.m[m];
            me.settle_day = day;
            me.status = Status::Active;
            me.chain = wb.chain;
            me.joined = wb.chain.len() as u8;
            me.inc = inc;
            me.window = false;
            me.after = false;
            me.own = NONE;
            me.op = Op::None;
            me.kp &= !(1 << kp_instance(k.kp));
            me.dw = 0;
            me.ds = 0;
            me.prog = false;
            me.flags = 0;
            me.qd = 0;
            me.sd = 0;
            me.msgs = 0;
            if m == J {
                self.ev |= EV_JOINED;
            } else {
                self.ev |= EV_REJOINED;
                if joined.rank(m) == 0 {
                    self.ev |= EV_OWNER_READMITTED;
                }
            }
            return Ok(());
        }
        Ok(())
    }

    /// What a committer records from newly fetched join traffic and requests (§6.2.3, §6.6, §6.7).
    /// The requests a committer holds as pending work, re-evaluated over everything it fetched at
    /// each listing pass and after each settle (`Inbox.reofferDeferred`, §7.5): a join request whose
    /// invite is unconsumed on its branch, a rejoin request its policy admits now (§6.7; a refused
    /// one is ignored until a later re-offer admits it), a LEAVE post it opens whose author is still
    /// a member.
    fn record_requests(&mut self, m: usize) {
        let me = self.w.m[m];
        if me.status != Status::Active {
            return;
        }
        let g = self.group(me.chain);
        if g.rank(m) == 255 {
            // Only committers act on requests (§6.2.3); a member keeps no work.
            self.w.m[m].work &= W_USER;
            self.w.m[m].aged &= W_USER;
            return;
        }
        let mut work = me.work & !(W_JOIN | W_REJOIN | W_LEAVE);
        // Only a committer that holds the INVITE_ISSUED admits (§6.2.4 (B)).
        if me.fetched & bit(B_JOIN) != 0
            && me.invite_record
            && !g.invite_consumed
            && !g.is_member(J)
        {
            work |= W_JOIN;
        }
        let requested = [B_REJOIN, B_REJOIN + 1, B_REPLAY]
            .iter()
            .any(|&i| me.fetched & bit(i) != 0 && self.w.b[i].kind == B_REJOINREQ);
        if requested && g.rank(m) != 255 {
            if rejoin_policy(self, m, &g).is_some() {
                work |= W_REJOIN;
            } else {
                self.ev |= EV_REJOIN_REFUSED;
            }
        }
        let leaver = self.cfg.leaver as usize;
        let leaves = (B_POST0..B_JOIN).any(|i| {
            me.fetched & bit(i) != 0
                && self.w.b[i].aux == 1
                && self.w.b[i].author == leaver as u8
                && opens(&self.w, &self.cfg.genesis, self.rules(), m, i)
        });
        if leaves && g.is_member(leaver) {
            work |= W_LEAVE;
        }
        let me = &mut self.w.m[m];
        // Work first recorded now is not aged; work recorded before keeps its age.
        me.aged &= work;
        me.work = work;
    }

    /// CO-6: a commit that opens under a final epoch with another hash is a late candidate, a fork
    /// signal for diagnostics only (MM-16 re-decides on it). A post of a past epoch is a late post.
    fn late_blobs(&mut self, m: usize, newly: u32) -> Result<(), Violation> {
        let me = self.w.m[m];
        if !me.status.holds_state() {
            return Ok(());
        }
        for i in 0..NB {
            if newly & bit(i) == 0 {
                continue;
            }
            if self.w.b[i].kind == B_POST
                && opens(&self.w, &self.cfg.genesis, self.rules(), m, i)
                && self.w.b[i].chain != me.chain
            {
                self.ev |= EV_LATE_POST;
            }
            if i >= NC || self.w.b[i].kind != B_COMMIT {
                continue;
            }
            let k = self.w.c[i];
            let p = k.parent;
            if p.len() < me.chain.len()
                && p.is_prefix_of(me.chain)
                && p.len() >= me.joined as usize
                && me.chain.at(p.len()) != i
            {
                self.ev |= EV_LATE_CANDIDATE;
                if k.flags & F_ADVERSARY != 0 {
                    self.ev |= EV_GROUND_LATE;
                }
                if self.rules().is(Mutant::NotSticky) {
                    // Round 10a's "fork evidence, better": the member compares the late commit with
                    // the winner it merged and moves when the late one ranks better.
                    let g = self.group(p);
                    let winner = self.w.c[me.chain.at(p.len())];
                    let better = verdict(&g, &k, self.rules(), me.judge()) == Verdict::Valid
                        && (g.rank(k.author as usize), k.hash)
                            < (g.rank(winner.author as usize), winner.hash);
                    if better {
                        props::check_sticky(me.chain, p.push(i), m)?;
                    }
                }
            }
        }
        Ok(())
    }

    /// CO-11 and CO-12 when the member's view changes (fetch, settle, session, day).
    fn liveness(&mut self, m: usize) {
        let me = self.w.m[m];
        if !me.status.holds_state() {
            return;
        }
        let g = self.group(me.chain);
        // Messages of other members that open in its current epoch (CO-11 (b), CO-12).
        let mut senders = 0u8;
        for i in 0..NB {
            if me.fetched & bit(i) != 0
                && matches!(self.w.b[i].kind, B_POST | B_COMMIT)
                && self.w.b[i].author != m as u8
                && epoch_chain(&self.w, i) == Some(me.chain)
            {
                senders |= abit(self.w.b[i].author as usize);
            }
        }
        let (u, u_split) = if self.cfg.acts & A_DAY != 0 {
            let u = unopenable_foreign(&self.w, &self.cfg.genesis, self.rules(), m);
            let us = if self.rules().fixed(Fix::SplitCountsDraining) {
                u + unopenable_draining(&self.w, &self.cfg.genesis, self.rules(), m)
            } else {
                u
            };
            (u, us)
        } else {
            (0, 0)
        };
        // F-3's ghost window: both namespaces, whatever the rule set.
        let u_any = if self.cfg.terminal & props::T_SCN_CL != 0 {
            unopenable_any(&self.w, &self.cfg.genesis, self.rules(), m)
        } else {
            0
        };
        let mut ev = 0;
        {
            let me = &mut self.w.m[m];
            if senders != 0 {
                me.sd = 0;
                me.msgs |= senders;
            }
            // CO-11 (b): messages from at least min(2, members of its branch − 1) other members.
            let need = g.members().saturating_sub(1).min(2);
            let progress_now = need > 0 && senders.count_ones() >= need;
            // CO-11 (a): the liveness window starts at the first unopenable foreign blob of the
            // current generation's namespace.
            if me.dw == 0 && u_split > 0 {
                me.dw = 1;
                me.ds = u8::from(me.online);
                me.prog = progress_now;
            }
            if me.gw == 0 && u_any > 0 {
                me.gw = 1;
                me.gs = u8::from(me.online);
            }
            if progress_now {
                me.prog = true;
            }
            // Progress returns a member in resync_needed to active (CO-11).
            if me.prog && me.status == Status::Resync {
                me.status = Status::Active;
                ev |= EV_PROGRESS_RESET;
            }
            // CO-11: at least 72 h of first sightings covering at least 3 sessions.
            if me.dw >= 3 && me.ds >= 3 {
                if u >= 3 && !me.prog {
                    if me.status == Status::Active && !self.cfg.rules.is(Mutant::NoBranchDeath) {
                        me.status = Status::Resync;
                        ev |= EV_RESYNC;
                    }
                } else if u_split >= 3 && (me.prog || u < 3) {
                    me.flags |= FL_SPLIT;
                    ev |= EV_SPLIT;
                }
                if me.prog {
                    me.dw = 0;
                    me.ds = 0;
                    me.prog = false;
                }
            }
            // CO-12: nine days without a committer commit merged.
            if me.qd >= 9 {
                let others = me.msgs & !abit(m);
                let need = if self.cfg.rules.fixed(Fix::PartitionOneOther) {
                    1
                } else {
                    2
                };
                if others.count_ones() >= need && !self.cfg.rules.is(Mutant::NoPartition) {
                    me.flags |= FL_PARTITION;
                    ev |= EV_PARTITION;
                }
                let someone_else = g.committer_set() & !abit(m) != 0;
                if me.sd >= 9 && someone_else && !self.cfg.rules.is(Mutant::NoStale) {
                    me.flags |= FL_STALE;
                    ev |= EV_STALE;
                }
            }
        }
        self.ev |= ev;
    }

    /// A new own (or adversarial) commit.
    fn new_commit(&mut self, m: usize, k: Commit, pos: u8) -> Result<(), Violation> {
        let seq = self.w.m[m].seq as usize;
        let slot = m * PER_ACTOR_COMMITS + seq;
        props::check_own_commit(&self.w, self.cfg, m, &k)?;
        // T1 covers blind passes only: a commit built while its author held no foreign candidate
        // for that epoch. A pass over a held candidate may be stored after another member's
        // window elapsed (a pass up to 20 minutes after the candidate's store, a send delay of up
        // to 10 minutes), so it is not prompt.
        let (held, _) = self.cands(m);
        let blind = (0..NC).all(|s| held & (1 << s) == 0 || s == self.w.m[m].own as usize);
        let concurrent = self.cfg.honest_timing && blind && self.concurrent(k.parent);
        self.insert_commit(slot, k, pos);
        let me = &mut self.w.m[m];
        me.seq += 1;
        if k.flags & F_ADVERSARY == 0 {
            me.own = slot as u8;
            me.op = Op::Queued;
            if concurrent {
                self.w.prompt |= 1 << slot;
            }
        }
        if self.rules().is(Mutant::WelcomeAtPass) && k.flags & F_ADVERSARY == 0 {
            // MM-19: the Welcome is sealed and enqueued at the pass, before the commit won.
            self.make_welcomes(slot, k.parent.push(slot));
        }
        Ok(())
    }

    /// Whether a commit built now on `chain` is concurrent: no member has started to settle that
    /// epoch (its window elapsed, or it merged a winner for it) and no candidate for it is old.
    fn concurrent(&self, chain: Chain) -> bool {
        let started = (0..NA).any(|n| {
            let o = &self.w.m[n];
            o.status.holds_state()
                && (o.chain == chain && o.window
                    || chain.is_prefix_of(o.chain) && o.chain.len() > chain.len())
        });
        let old =
            (0..NC).any(|s| self.w.c[s].used && self.w.c[s].parent == chain && self.w.b[s].old);
        !started && !old
    }

    /// T2 of the header: a pass (or a self-update) follows the member's listing pass within five
    /// minutes (CO-8), so a member that holds no candidate for its epoch while one is stored, visible
    /// to it and not fetched listed before that store and passes before any member's window for the
    /// epoch can elapse (`arith::blind_pass_is_prompt`). In the T1 scenarios (no withholding) such a
    /// stale blind pass after the epoch stopped being concurrent is not a real ordering.
    pub fn stale_blind_late(&self, m: usize) -> bool {
        if !self.cfg.honest_timing {
            return false;
        }
        let me = &self.w.m[m];
        let own = me.own as usize;
        let (held, _) = self.cands(m);
        let blind = (0..NC).all(|s| held & (1 << s) == 0 || s == own);
        if !blind {
            return false;
        }
        let vis = visible_mask(&self.w, &self.cfg.genesis, self.rules(), m);
        let stale = (0..NC).any(|s| {
            self.w.c[s].used
                && self.w.c[s].parent == me.chain
                && s != own
                && me.fetched & bit(s) == 0
                && vis & bit(s) != 0
        });
        stale && !self.concurrent(me.chain)
    }
}

/// CO-11 (a)'s count: fetched blobs that are not the member's own, stored in its current
/// generation's namespace (MM-37: or the draining one), that do not open under any key it holds.
pub fn unopenable_foreign(w: &World, gen: &Genesis, rules: Rules, m: usize) -> u32 {
    let g = group_of(w, gen, w.m[m].chain, rules);
    let mut n = unopenable_in(w, gen, rules, m, g.ns);
    if rules.is(Mutant::CountDraining) && g.gen > 0 {
        n += unopenable_in(w, gen, rules, m, g.prev_ns);
    }
    n
}

/// The same count in the draining namespace (F-3's correction counts it for `split_suspected`).
pub fn unopenable_draining(w: &World, gen: &Genesis, rules: Rules, m: usize) -> u32 {
    let g = group_of(w, gen, w.m[m].chain, rules);
    if g.gen == 0 || rules.is(Mutant::CountDraining) {
        return 0;
    }
    unopenable_in(w, gen, rules, m, g.prev_ns)
}

/// The unopenable foreign blobs of both listened namespaces, whatever the rule set (F-3's probe).
pub fn unopenable_any(w: &World, gen: &Genesis, rules: Rules, m: usize) -> u32 {
    let g = group_of(w, gen, w.m[m].chain, rules);
    let mut n = unopenable_in(w, gen, rules, m, g.ns);
    if g.gen > 0 && g.prev_ns != g.ns {
        n += unopenable_in(w, gen, rules, m, g.prev_ns);
    }
    n
}

fn unopenable_in(w: &World, gen: &Genesis, rules: Rules, m: usize, ns: Chain) -> u32 {
    let me = &w.m[m];
    (0..NB)
        .filter(|&i| {
            let b = &w.b[i];
            me.fetched & bit(i) != 0
                && me.opened & bit(i) == 0
                && matches!(b.kind, B_POST | B_COMMIT | B_SPAMBLOB)
                && b.author != m as u8
                && b.ops >= 2
                && b.ns == ns
                && !opens(w, gen, rules, m, i)
        })
        .map(|i| {
            if w.b[i].kind == B_SPAMBLOB {
                w.b[i].aux.max(1) as u32
            } else {
                1
            }
        })
        .sum()
}

/// Every successor of `w` under `cfg`, or the first property a transition (or the state itself)
/// breaks.
pub fn successors(w: &World, cfg: &Cfg, out: &mut Vec<Succ>) -> Result<(), (Action, Violation)> {
    out.clear();
    let acts = cfg.acts;
    let gen = &cfg.genesis;
    let rules = cfg.rules;
    let st0 = Step::new(cfg, w);
    check_pass_gate(&st0).map_err(|v| (Action::Observe, v))?;
    macro_rules! emit {
        ($action:expr, $st:expr) => {{
            let st: Step = $st;
            out.push(Succ {
                action: $action,
                world: st.w,
                ev: st.ev,
                settles: st.settles,
            });
        }};
    }
    macro_rules! attempt {
        ($action:expr, $body:block) => {{
            let action = $action;
            let body = || -> Result<Option<Step>, Violation> { $body };
            match body() {
                Ok(Some(st)) => emit!(action, st),
                Ok(None) => {}
                Err(v) => return Err((action, v)),
            }
        }};
    }

    // ---- sessions (process death at every step) and listing passes ----------------------------
    for m in 0..NA {
        let me = w.m[m];
        if acts & A_SESSIONS != 0
            && cfg.session_actors & abit(m) != 0
            && me.status != Status::Absent
            && me.toggles < cfg.session_budget
        {
            if me.online {
                attempt!(Action::Offline(m as u8), {
                    let mut st = Step::new(cfg, w);
                    st.w.m[m].online = false;
                    st.w.m[m].listed = false;
                    st.w.m[m].toggles += 1;
                    st.w.h.disturbed = true;
                    // An author offline cannot store its queued commit promptly (T1 lifts).
                    if me.own != NONE {
                        st.w.prompt &= !(1 << me.own);
                    }
                    Ok(Some(st))
                });
            } else {
                attempt!(Action::Online(m as u8), {
                    let mut st = Step::new(cfg, w);
                    st.w.m[m].online = true;
                    st.w.m[m].listed = false;
                    st.w.m[m].toggles += 1;
                    st.w.m[m].sess = (st.w.m[m].sess + 1).min(3);
                    if st.w.m[m].dw > 0 && st.w.m[m].ds < 3 {
                        st.w.m[m].ds += 1;
                    }
                    if st.w.m[m].gw > 0 && st.w.m[m].gs < 3 {
                        st.w.m[m].gs += 1;
                    }
                    st.liveness(m);
                    Ok(Some(st))
                });
            }
        }
        if !me.online {
            continue;
        }
        let any_new = visible_mask(w, gen, rules, m) & !me.fetched != 0;
        let would_after = st0.window_holds(m) && !me.after;
        if !me.listed || any_new || would_after {
            attempt!(Action::List(m as u8), {
                let mut st = Step::new(cfg, w);
                st.list(m)?;
                Ok(Some(st))
            });
        }
    }

    // ---- time: a member's settle window elapses and it lists (CO-4 (i), (ii)) -------------------
    if acts & A_TICK != 0 {
        for m in 0..NA {
            let me = w.m[m];
            if !matches!(me.status, Status::Active | Status::Resync) || me.window || !me.online {
                continue;
            }
            // CO-4 (i): the window runs from the member's first sighting of a candidate, the
            // listing pass that fetched its copy (for its own commit too: "the copy it fetched");
            // under the withdrawn lifetime rules a lifetime-pending commit starts it as well (the
            // settle then finds it blocking).
            let (cands, pending) = st0.cands(m);
            let sighted = if cfg.rules.is(Mutant::OwnAnchorAtPass) {
                cands != 0
            } else {
                (0..NC).any(|s| cands & (1 << s) != 0 && me.fetched & bit(s) != 0)
            };
            if !sighted && !pending {
                continue;
            }
            // T1: an honest commit of a concurrent pass is stored before any window elapses.
            if cfg.honest_timing
                && (0..NC).any(|s| w.prompt & (1 << s) != 0 && w.c[s].parent == me.chain)
            {
                continue;
            }
            let tick = || -> Result<Step, Violation> {
                let mut st = Step::new(cfg, w);
                st.w.m[m].window = true;
                if st.rules().is(Mutant::NoListingPass) {
                    // CO-4 (ii) dropped: it settles on what it fetched before the window elapsed.
                    st.w.m[m].after = true;
                    st.pump(m)?;
                } else {
                    st.list(m)?;
                }
                Ok(st)
            };
            let st = match tick() {
                Ok(st) => st,
                Err(v) => return Err((Action::Tick(m as u8), v)),
            };
            // The F-1 correction: a committer that settled passes in the same actor step.
            if cfg.rules.fixed(Fix::SettleBeforePass) && acts & A_PASS != 0 {
                let me1 = st.w.m[m];
                let g1 = st.group(me1.chain);
                if g1.rank(m) != 255
                    && st.current(m)
                    && me1.chain.len() < cfg.depth
                    && (me1.seq as usize) < cfg.commit_budget[m] as usize
                {
                    if let Some(k) = build_pass(&st, m) {
                        for pos in st.hash_positions(me1.chain, m) {
                            let action = Action::TickPass {
                                actor: m as u8,
                                hash: pos,
                            };
                            let mut st2 = Step {
                                cfg,
                                w: st.w,
                                ev: st.ev,
                                settles: st.settles,
                            };
                            let r =
                                note_pass(&mut st2, m, &k).and_then(|_| st2.new_commit(m, k, pos));
                            if let Err(v) = r {
                                return Err((action, v));
                            }
                            st2.ev |= EV_SETTLE_PASS;
                            emit!(action, st2);
                        }
                    }
                }
            }
            emit!(Action::Tick(m as u8), st);
        }
    }

    // ---- stores --------------------------------------------------------------------------------
    for i in 0..NB {
        let b = w.b[i];
        if b.kind == B_NONE || b.stored || b.expired {
            continue;
        }
        let author = b.author as usize;
        if author >= NA || !w.m[author].online {
            continue;
        }
        let own_commit = i < NC && w.m[author].own == i as u8;
        if own_commit && w.m[author].op != Op::Queued {
            continue;
        }
        let mut masks: Vec<u8> = vec![0];
        let slot_ok = i >= NC || cfg.withhold_slots == 0 || cfg.withhold_slots & (1 << i) != 0;
        if cfg.withhold_kinds & (1u8 << b.kind) != 0 && slot_ok {
            masks.extend(cfg.withhold_masks.iter().copied().filter(|&x| x != 0));
        }
        let indet_choices: &[bool] = if own_commit && acts & A_INDETERMINATE != 0 {
            &[false, true]
        } else {
            &[false]
        };
        for &mask in &masks {
            for &indeterminate in indet_choices {
                attempt!(
                    Action::Store {
                        blob: i as u8,
                        withheld: mask & !abit(author),
                        indeterminate
                    },
                    {
                        let mut st = Step::new(cfg, w);
                        st.w.b[i].stored = true;
                        st.w.b[i].withheld = mask & !abit(author);
                        if i < NC && w.c[i].flags & F_ADVERSARY == 0 {
                            let p = w.c[i].parent;
                            let settled = (0..NA).any(|n| {
                                w.m[n].status != Status::Absent
                                    && p.is_prefix_of(w.m[n].chain)
                                    && w.m[n].chain.len() > p.len()
                            });
                            if settled {
                                st.w.h.late_copy = true;
                            }
                        }
                        if mask != 0 {
                            st.w.h.disturbed = true;
                        }
                        if i < NC {
                            st.w.prompt &= !(1 << i);
                        }
                        if own_commit {
                            if indeterminate {
                                // The copy reached a relay but no receipt did: the op closes
                                // INDETERMINATE, which makes nothing CO-4 (a) reads true.
                                st.w.h.disturbed = true;
                                st.w.m[author].op = Op::Indeterminate;
                            } else {
                                st.w.m[author].op = Op::Verified;
                                st.pump(author)?;
                            }
                        }
                        Ok(Some(st))
                    }
                );
            }
        }
    }

    // ---- own-commit custody (CO-4 (c), §19.13) ----------------------------------------------------
    if acts & A_INDETERMINATE != 0 {
        for m in 0..NA {
            let me = w.m[m];
            if me.own == NONE || !me.status.holds_state() {
                continue;
            }
            let s = me.own as usize;
            if me.op == Op::Queued && !w.b[s].stored && me.online {
                // The op closes INDETERMINATE after its resends and no copy reached a relay.
                attempt!(Action::Indeterminate(m as u8), {
                    let mut st = Step::new(cfg, w);
                    st.w.m[m].op = Op::Indeterminate;
                    st.w.prompt &= !(1 << s);
                    st.w.b[s].expired = true;
                    st.w.h.disturbed = true;
                    Ok(Some(st))
                });
            }
            let gone = w.b[s].expired || !w.b[s].stored;
            let clear = if cfg.rules.is(Mutant::ClearIndeterminate) {
                // Round 10b: the commit is cleared as soon as its op closed without a verified copy.
                me.op == Op::Indeterminate
            } else {
                // (c): the op's deadline plus the handshake TTL passed with neither (a) nor (b): no
                // copy can remain on any relay.
                me.op == Op::Indeterminate && gone
            };
            if clear {
                attempt!(Action::OwnGone(m as u8), {
                    let mut st = Step::new(cfg, w);
                    props::check_clear(&st.w, cfg, m, s)?;
                    st.w.m[m].own = NONE;
                    st.w.m[m].op = Op::None;
                    st.ev |= EV_CLEAR_INDETERMINATE;
                    Ok(Some(st))
                });
            }
        }
    }

    // ---- members: posts, passes, self-updates, user actions ---------------------------------------
    for m in 0..NA {
        let me = w.m[m];
        if !me.online {
            continue;
        }
        let current = st0.current(m);
        // Posts (CH-POST, §6.3.1): only when the channel is current.
        if acts & A_POST != 0
            && cfg.posters & abit(m) != 0
            && me.posts < cfg.post_budget[m]
            && ((me.posts + me.beacons) as usize) < POSTS_PER_ACTOR
            && me.status == Status::Active
        {
            let own_removes = me.own != NONE
                && w.c[me.own as usize].removes_someone()
                && !cfg.rules.is(Mutant::NoHold);
            if current && !own_removes {
                attempt!(Action::Post(m as u8), {
                    let mut st = Step::new(cfg, w);
                    let slot = B_POST0 + m * POSTS_PER_ACTOR + (me.posts + me.beacons) as usize;
                    props::check_post(&st.w, cfg, m)?;
                    let g = st.group(me.chain);
                    st.w.b[slot] = Blob {
                        kind: B_POST,
                        author: m as u8,
                        chain: me.chain,
                        ns: g.ns,
                        stored: true,
                        ops: 2,
                        inc: me.inc,
                        ..Blob::default()
                    };
                    st.w.m[m].posts += 1;
                    // A post of the removed member's epochs: it can read it (L8-C18's residue).
                    Ok(Some(st))
                });
            }
        }
        if acts & A_LEAVE != 0 && m == cfg.leaver as usize && me.status == Status::Active && current
        {
            let g = st0.group(me.chain);
            if g.rank(m) == 255 && ((me.posts + me.beacons) as usize) < POSTS_PER_ACTOR {
                attempt!(Action::Leave(m as u8), {
                    let mut st = Step::new(cfg, w);
                    let slot = B_POST0 + m * POSTS_PER_ACTOR + (me.posts + me.beacons) as usize;
                    st.w.b[slot] = Blob {
                        kind: B_POST,
                        author: m as u8,
                        chain: me.chain,
                        ns: g.ns,
                        stored: true,
                        ops: 2,
                        aux: 1,
                        inc: me.inc,
                        ..Blob::default()
                    };
                    st.w.m[m].posts += 1;
                    st.w.m[m].status = Status::Left;
                    st.ev |= EV_LEFT;
                    Ok(Some(st))
                });
            }
        }
        if me.status != Status::Active || me.chain.len() >= cfg.depth {
            continue;
        }
        let g = st0.group(me.chain);
        let rank = g.rank(m);
        // User actions of a committer: pending work that passes at once (CO-8).
        if rank != 255 && me.listed {
            if acts & A_REMOVE != 0
                && m == cfg.remover as usize
                && me.work & W_REMOVE == 0
                && w.h.asked & abit(m) == 0
            {
                let x = cfg.remove_target as usize;
                let rx = g.rank(x);
                if g.is_member(x) && x != m && (rx == 255 || rx > rank) {
                    attempt!(Action::UserRemove(m as u8), {
                        let mut st = Step::new(cfg, w);
                        st.w.m[m].work |= W_REMOVE;
                        st.w.h.asked |= abit(m);
                        Ok(Some(st))
                    });
                }
            }
            if acts & A_RESIGN != 0
                && m == cfg.resigner as usize
                && rank != 0
                && me.work & W_RESIGN == 0
            {
                attempt!(Action::UserResign(m as u8), {
                    let mut st = Step::new(cfg, w);
                    st.w.m[m].work |= W_RESIGN;
                    Ok(Some(st))
                });
            }
            if acts & A_TRANSFER != 0
                && m == cfg.resigner as usize
                && rank == 0
                && g.committers[1] != NONE
                && me.work & W_TRANSFER == 0
            {
                attempt!(Action::UserTransfer(m as u8), {
                    let mut st = Step::new(cfg, w);
                    st.w.m[m].work |= W_TRANSFER;
                    Ok(Some(st))
                });
            }
        }
        if me.seq as usize >= cfg.commit_budget[m] as usize || me.own != NONE {
            continue;
        }
        // T2 of the header: a stale blind pass precedes every window of its epoch.
        let late_blind = st0.stale_blind_late(m);
        // CO-7 / CO-8: a committer's pass.
        if acts & A_PASS != 0 && rank != 255 && current && !late_blind {
            if let Some(k) = build_pass(&st0, m) {
                for pos in st0.hash_positions(me.chain, m) {
                    attempt!(
                        Action::Pass {
                            actor: m as u8,
                            hash: pos
                        },
                        {
                            let mut st = Step::new(cfg, w);
                            note_pass(&mut st, m, &k)?;
                            st.new_commit(m, k, pos)?;
                            Ok(Some(st))
                        }
                    );
                }
            }
        }
        // CO-9: a self-update of a rank-255 member at its slot, skipped where CO-14 refuses it.
        if acts & A_SELFUPDATE != 0 && rank == 255 && current && me.slot {
            let k = Commit {
                used: true,
                parent: me.chain,
                author: m as u8,
                inc: me.inc,
                remove: NONE,
                swap: NONE,
                ..Commit::default()
            };
            let ok = normative(&g, &k) == Verdict::Valid;
            let (held, _) = st0.cands(m);
            // The F-1 correction holds a self-update too while a candidate is held.
            let blocked = cfg.rules.fixed(Fix::SettleBeforePass) && held != 0;
            if (ok || cfg.rules.is(Mutant::NoSkip)) && !blocked && !late_blind {
                for pos in st0.hash_positions(me.chain, m) {
                    attempt!(
                        Action::SelfUpdate {
                            actor: m as u8,
                            hash: pos
                        },
                        {
                            let mut st = Step::new(cfg, w);
                            st.w.m[m].slot = false;
                            if held != 0 {
                                // A self-update over a held candidate (the F-1 premise).
                                st.w.h.pass_over = true;
                            }
                            st.new_commit(m, k, pos)?;
                            Ok(Some(st))
                        }
                    );
                }
            }
        }
    }

    // ---- the invitee and the rejoiner -----------------------------------------------------------
    if acts & A_JOIN != 0 && w.m[J].status == Status::Absent {
        attempt!(Action::Accept, {
            let mut st = Step::new(cfg, w);
            let me = &mut st.w.m[J];
            me.status = Status::Joining;
            me.online = true;
            me.listed = false;
            me.kp |= 1 << KP_JOIN;
            st.w.b[B_JOIN] = Blob {
                kind: B_JOINREQ,
                author: J as u8,
                chain: Chain::ROOT,
                ns: Chain::ROOT,
                stored: true,
                ops: 2,
                aux: kp_id(J, KP_JOIN),
                ..Blob::default()
            };
            Ok(Some(st))
        });
    }
    if acts & A_REJOIN != 0 && w.b[B_REJOIN].kind == B_NONE {
        for m in 0..NA {
            let me = w.m[m];
            // The user's resync action: in resync_needed, or from a flag (CO-12).
            let asked = me.status == Status::Resync || me.status == Status::Active && me.flags != 0;
            if !asked || !me.online {
                continue;
            }
            attempt!(Action::Rejoin(m as u8), {
                let mut st = Step::new(cfg, w);
                let g = st.group(me.chain);
                let mut copies = vec![g.ns];
                if g.gen > 0 {
                    copies.push(g.prev_ns);
                }
                for (j, ns) in copies.into_iter().enumerate() {
                    st.w.b[B_REJOIN + j] = Blob {
                        kind: B_REJOINREQ,
                        author: m as u8,
                        chain: me.chain,
                        ns,
                        stored: true,
                        ops: 2,
                        aux: kp_id(m, KP_REJOIN),
                        inc: me.inc,
                        ..Blob::default()
                    };
                }
                st.w.m[m].kp |= 1 << KP_REJOIN;
                st.w.m[m].status = Status::Resync;
                Ok(Some(st))
            });
        }
    }

    // ---- time events -----------------------------------------------------------------------------
    if acts & A_AGE != 0 {
        for s in 0..NC {
            let b = w.b[s];
            // T1: a prompt honest store precedes the store-hour anchor of any sibling (that anchor
            // is at least 80 minutes after the sibling's store; a prompt store at most 30 minutes
            // after a concurrent pass, itself less than 20 minutes after the sibling's store).
            let blocked = cfg.honest_timing
                && (0..NC).any(|t| w.prompt & (1 << t) != 0 && w.c[t].parent == w.c[s].parent);
            if b.kind == B_COMMIT && b.stored && !b.old && !blocked {
                attempt!(Action::Age(s as u8), {
                    let mut st = Step::new(cfg, w);
                    st.w.b[s].old = true;
                    Ok(Some(st))
                });
            }
        }
    }
    for m in 0..NA {
        let me = w.m[m];
        if !me.status.holds_state() {
            continue;
        }
        let committer = group_of(w, gen, me.chain, rules).rank(m) != 255;
        if acts & A_WORKAGE != 0 && committer && me.work & !me.aged & !W_USER != 0 {
            attempt!(Action::WorkAge(m as u8), {
                let mut st = Step::new(cfg, w);
                st.w.m[m].aged = st.w.m[m].work;
                st.ev |= EV_AGED_WORK;
                Ok(Some(st))
            });
        }
        let g = group_of(w, gen, me.chain, rules);
        if acts & A_PCS != 0 && !me.pcs && g.rank(m) != 255 {
            attempt!(Action::PcsDue(m as u8), {
                let mut st = Step::new(cfg, w);
                st.w.m[m].pcs = true;
                Ok(Some(st))
            });
        }
        if acts & A_SLOT != 0 && !me.slot && me.own == NONE && g.rank(m) == 255 {
            attempt!(Action::SlotDue(m as u8), {
                let mut st = Step::new(cfg, w);
                st.w.m[m].slot = true;
                Ok(Some(st))
            });
        }
    }
    if acts & A_DAY != 0 && w.day < cfg.days {
        attempt!(Action::Day, {
            let mut st = Step::new(cfg, w);
            st.w.day += 1;
            for m in 0..NA {
                if !st.w.m[m].status.holds_state() {
                    continue;
                }
                let me = &mut st.w.m[m];
                if me.dw > 0 && me.dw < 3 {
                    me.dw += 1;
                }
                if me.gw > 0 && me.gw < 3 {
                    me.gw += 1;
                }
                me.qd = (me.qd + 1).min(9);
                me.sd = (me.sd + 1).min(9);
                st.liveness(m);
            }
            Ok(Some(st))
        });
    }

    // ---- the relays ------------------------------------------------------------------------------
    if acts & A_EXPIRE != 0 {
        for s in 0..NC {
            if w.b[s].kind == B_COMMIT && w.b[s].stored && !w.b[s].expired && w.b[s].old {
                attempt!(Action::Expire(s as u8), {
                    let mut st = Step::new(cfg, w);
                    st.w.b[s].expired = true;
                    st.w.h.disturbed = true;
                    Ok(Some(st))
                });
            }
        }
    }
    // A partition for an interval (§12.3): the relays end it once, serving every withheld blob.
    if acts & A_RELEASE != 0 && !w.healed && (0..NB).any(|i| w.b[i].withheld != 0) {
        attempt!(Action::Release, {
            let mut st = Step::new(cfg, w);
            st.w.healed = true;
            for i in 0..NB {
                st.w.b[i].withheld = 0;
            }
            Ok(Some(st))
        });
    }

    adversary(w, cfg, out)?;
    Ok(())
}

/// §12.3 "a flooding member never blocks a committer's pass" (CO-7, §19.5), checked on every state:
/// a committer that is current, holds no pending commit, has work it may commit and holds no
/// valid candidate of a rank at or below its own can pass.
fn check_pass_gate(st: &Step) -> Result<(), Violation> {
    if st.cfg.acts & A_PASS == 0 {
        return Ok(());
    }
    for m in [C0, C1] {
        let me = &st.w.m[m];
        if !st.current(m) || me.own != NONE || me.seq as usize >= st.cfg.commit_budget[m] as usize {
            continue;
        }
        if me.chain.len() >= st.cfg.depth {
            continue;
        }
        let g = st.group(me.chain);
        let rank = g.rank(m);
        if rank == 255 {
            continue;
        }
        let (cands, _) = st.cands(m);
        let lower = (0..NC).any(|s| {
            cands & (1 << s) != 0
                && s != me.own as usize
                && (g.rank(st.w.c[s].author as usize) <= rank
                    || st.rules().fixed(Fix::SettleBeforePass))
        });
        if lower {
            continue;
        }
        let ignoring = Step {
            cfg: st.cfg,
            w: st.w,
            ev: 0,
            settles: 0,
        };
        let want = build_pass_items(&ignoring, m, true).is_some();
        let got = build_pass(st, m).is_some();
        if want && !got {
            return Err(Violation {
                property: "P-PASS",
                detail: format!(
                    "{} is current with work to commit and holds only rank-255 candidates, but its \
                     pass is blocked",
                    ACTOR_NAMES[m]
                ),
            });
        }
    }
    Ok(())
}

/// Ghost bookkeeping of a pass, and the decision-time check of CO-8 (**P-WORKAGE**, MM-34: a
/// moderator's scheduled pass never includes work younger than `r × 48 h`).
fn note_pass(st: &mut Step, m: usize, k: &Commit) -> Result<(), Violation> {
    let me = st.w.m[m];
    let gen = st.cfg.genesis;
    let rules = st.rules();
    let vis = visible_mask(&st.w, &gen, rules, m);
    let stale = (0..NC).any(|s| {
        st.w.c[s].used
            && st.w.c[s].parent == me.chain
            && me.fetched & bit(s) == 0
            && s != me.own as usize
            && vis & bit(s) != 0
    });
    if stale {
        st.w.h.stale_pass = true;
    }
    let g = st.group(me.chain);
    let (cands, _) = st.cands(m);
    let over = (0..NC).any(|s| cands & (1 << s) != 0 && st.w.c[s].author != m as u8);
    if over {
        st.w.h.pass_over = true;
    }
    if (0..NC).any(|s| cands & (1 << s) != 0 && g.rank(st.w.c[s].author as usize) == 255) {
        st.ev |= EV_RANK255_PASS;
    }
    let rank = g.rank(m);
    if rank >= 1 {
        let fresh = me.work & !me.aged & !W_USER;
        let carries_fresh = (k.admit && fresh & W_JOIN != 0)
            || (k.swap != NONE && fresh & W_REJOIN != 0)
            || (k.remove != NONE && me.work & W_REMOVE == 0 && fresh & W_LEAVE != 0);
        if carries_fresh {
            return Err(Violation {
                property: "P-WORKAGE",
                detail: format!(
                    "{} (rank {rank}) commits a request it recorded less than {} h ago",
                    ACTOR_NAMES[m],
                    48 * rank as u32
                ),
            });
        }
    }
    // §12.3's "a moderator and the owner acting on the same aged request": two committers' Adds of
    // the same request for one epoch.
    if k.admit
        && (0..NC).any(|s| {
            st.w.c[s].used
                && st.w.c[s].admit
                && st.w.c[s].author != m as u8
                && st.w.c[s].parent == k.parent
                && st.w.c[s].flags & F_ADVERSARY == 0
        })
    {
        st.ev |= EV_DOUBLE_ADMIT;
    }
    if m == C0 && (k.admit || k.remove != NONE || k.swap != NONE) {
        st.w.m[m].tries = st.w.m[m].tries.saturating_add(1);
        if st.w.m[m].tries > 2 && !st.w.h.disturbed {
            return Err(Violation {
                property: "P-LIVENESS",
                detail: "the owner passes a third time on the same pending request".to_string(),
            });
        }
    }
    Ok(())
}

/// CO-7 and CO-8: the commit of a pass of committer `m`, if it may pass and has something to
/// commit. Admission and rejoin policy (§6.2.4 (B), §6.7) decide the items.
pub fn build_pass(st: &Step, m: usize) -> Option<Commit> {
    build_pass_items(st, m, false)
}

/// `ignore_rank255`: the pass gate as CO-7 states it (a rank-255 candidate never blocks), used by
/// the P-PASS check whatever the rule set.
fn build_pass_items(st: &Step, m: usize, ignore_rank255: bool) -> Option<Commit> {
    let me = &st.w.m[m];
    let rules = st.rules();
    let g = st.group(me.chain);
    let rank = g.rank(m);
    if me.own != NONE {
        return None;
    }
    // CO-7: no held candidate of a rank at or below its own (a rank-255 candidate never blocks,
    // §19.5). MM-26 lets a rank-255 candidate block; F-1's correction blocks on any held candidate
    // (the committer settles first).
    let (cands, _) = st.cands(m);
    let any_blocks =
        (rules.is(Mutant::Rank255Blocks) && !ignore_rank255) || rules.fixed(Fix::SettleBeforePass);
    for s in 0..NC {
        if cands & (1 << s) == 0 {
            continue;
        }
        if any_blocks || g.rank(st.w.c[s].author as usize) <= rank {
            return None;
        }
    }
    // CO-8: rank 0 commits any pending work; rank r ≥ 1 work first recorded r × 48 h ago, and user
    // actions at once.
    let eligible = if rank == 0 || rules.is(Mutant::FreshWork) {
        me.work
    } else {
        (me.work & me.aged) | (me.work & W_USER)
    };
    let mut k = Commit {
        used: true,
        parent: me.chain,
        author: m as u8,
        inc: me.inc,
        remove: NONE,
        swap: NONE,
        ..Commit::default()
    };
    let mut any = false;
    if eligible & (W_REMOVE | W_LEAVE) != 0 {
        let x = if eligible & W_LEAVE != 0 && g.is_member(st.cfg.leaver as usize) {
            st.cfg.leaver as usize
        } else {
            st.cfg.remove_target as usize
        };
        let rx = g.rank(x);
        if g.is_member(x) && x != m && (rx == 255 || rx > rank) {
            k.remove = x as u8;
            any = true;
        }
    }
    if eligible & W_RESIGN != 0 && rank != 255 {
        k.ctx = CTX_RESIGN;
        any = true;
    } else if eligible & W_TRANSFER != 0 && rank == 0 && g.committers[1] != NONE {
        k.ctx = CTX_TRANSFER;
        any = true;
    }
    if eligible & W_REJOIN != 0 {
        if let Some((x, req)) = rejoin_policy(st, m, &g) {
            if k.remove != x as u8 {
                k.swap = x as u8;
                k.swap_kind = SWAP_REJOIN;
                k.kp = st.w.b[req].aux;
                any = true;
            }
        }
    }
    if eligible & W_JOIN != 0 && join_policy(st, &g) {
        // S0-15: an Add only in a commit that leaves `committers` unchanged; otherwise deferred.
        let changes = k.ctx != 0 || k.remove != NONE && g.rank(k.remove as usize) != 255;
        if !changes {
            k.admit = true;
            k.kp = kp_id(J, KP_JOIN);
            if st.cfg.finite_kp {
                k.flags |= F_FINITE;
            }
            any = true;
        }
    }
    if !any && !me.pcs {
        return None;
    }
    // The committer's own CO-2 check (§19.31 row 14): a commit it would refuse is not built.
    if verdict(&g, &k, rules, me.judge()) != Verdict::Valid {
        return None;
    }
    Some(k)
}

/// §6.2.4 (B): the admitting committer holds J's INVITE_ISSUED (recorded as work), the invite is
/// unconsumed on its branch and not void (the committer set of its issue), the sponsor is still a
/// member.
fn join_policy(st: &Step, g: &Group) -> bool {
    let set = st.cfg.genesis.invite_committers();
    !g.invite_consumed && !g.is_member(J) && g.is_member(C0) && g.committer_set() == set
}

/// §6.7: a committer admits a rejoin only if the pseudonym is a current member of its branch, the
/// KeyPackage was never seen, the claimed last final epoch is before its current epoch and cannot
/// be caught up from (a fork on its branch, or the commit after it is past its TTL), and no message
/// from the pseudonym's current leaf opened on its branch after the claimed epoch (a live leaf is
/// never replaced). A request whose KeyPackage is not the pseudonym's own rejoin KeyPackage carries
/// no valid `rejoin_sig` (`joinVerify` refuses it). MM-20 drops the freshness clauses.
fn rejoin_policy(st: &Step, m: usize, g: &Group) -> Option<(usize, usize)> {
    let me = &st.w.m[m];
    for req in [B_REJOIN, B_REJOIN + 1, B_REPLAY] {
        let b = st.w.b[req];
        if me.fetched & bit(req) == 0 || b.kind != B_REJOINREQ {
            continue;
        }
        let x = b.author as usize;
        if !g.is_member(x) || x == m || b.aux != kp_id(x, KP_REJOIN) {
            continue;
        }
        if st.rules().is(Mutant::RejoinNoFreshness) {
            return Some((x, req));
        }
        let c = me.chain;
        let seen = (0..c.len()).any(|i| {
            let k = &st.w.c[c.at(i)];
            k.swap == x as u8 && k.kp == b.aux
        });
        if seen {
            continue;
        }
        let claim = b.chain;
        let behind = claim.len() <= c.len();
        let fork = !claim.is_prefix_of(c);
        let stuck =
            claim.is_prefix_of(c) && claim.len() < c.len() && st.w.b[c.at(claim.len())].expired;
        if !(behind && (fork || stuck)) {
            continue;
        }
        let live = (0..NB).any(|i| {
            me.fetched & bit(i) != 0
                && st.w.b[i].author == x as u8
                && st.w.b[i].inc == g.inc[x]
                && epoch_chain(&st.w, i)
                    .is_some_and(|e| e.is_prefix_of(c) && e.len() >= claim.len())
        });
        if live {
            continue;
        }
        return Some((x, req));
    }
    None
}

/// The insider's actions (§12.3's adversaries).
fn adversary(w: &World, cfg: &Cfg, out: &mut Vec<Succ>) -> Result<(), (Action, Violation)> {
    let acts = cfg.acts;
    let gen = &cfg.genesis;
    let rules = cfg.rules;
    let a = M1;
    let me = w.m[a];
    let can_commit = me.online && (me.seq as usize) < cfg.commit_budget[a] as usize;
    let mut push = |action: Action, st: Step| {
        out.push(Succ {
            action,
            world: st.w,
            ev: st.ev,
            settles: st.settles,
        });
    };
    // GRIND: M1 kept an old epoch's state and grinds a self-update below every sibling for an epoch
    // other members settled; valid under CO-14 on that epoch's group.
    if acts & A_GRIND != 0 && can_commit && cfg.malicious & abit(a) != 0 {
        let mut parents: Vec<Chain> = Vec::new();
        for n in 0..NA {
            let o = &w.m[n];
            if !o.status.holds_state() || n == a {
                continue;
            }
            for d in 0..o.chain.len() {
                let p = o.chain.prefix(d);
                if !parents.contains(&p) {
                    parents.push(p);
                }
            }
        }
        for p in parents {
            let already =
                (0..NC).any(|s| w.c[s].used && w.c[s].author == a as u8 && w.c[s].parent == p);
            if already {
                continue;
            }
            let g = group_of(w, gen, p, rules);
            if !g.is_member(a) {
                continue;
            }
            let k = Commit {
                used: true,
                parent: p,
                author: a as u8,
                inc: g.inc[a],
                remove: NONE,
                swap: NONE,
                flags: F_ADVERSARY,
                ..Commit::default()
            };
            if normative(&g, &k) != Verdict::Valid {
                continue;
            }
            let mut st = Step::new(cfg, w);
            st.w.h.adversary = true;
            if let Err(v) = st.new_commit(a, k, 0) {
                return Err((Action::Grind { parent: p }, v));
            }
            push(Action::Grind { parent: p }, st);
        }
    }
    let here = me.chain;
    let g = group_of(w, gen, here, rules);
    let mk = |flags: u8| Commit {
        used: true,
        parent: here,
        author: a as u8,
        inc: me.inc,
        remove: NONE,
        swap: NONE,
        flags: flags | F_ADVERSARY,
        ..Commit::default()
    };
    let busy = (0..NC).any(|s| w.c[s].used && w.c[s].author == a as u8 && w.c[s].parent == here);
    if me.status == Status::Active
        && can_commit
        && here.len() < cfg.depth
        && cfg.malicious & abit(a) != 0
        && !busy
    {
        let mut tries: Vec<(Action, Commit)> = Vec::new();
        if acts & A_JUNK != 0 {
            // An Add carrying an expired finite-lifetime KeyPackage (E-70's insider commit).
            let mut k = mk(F_FINITE | F_EXPIRED);
            k.admit = true;
            k.kp = kp_id(J, KP_JOIN);
            tries.push((Action::Junk, k));
        }
        if acts & A_NEWSIGNER != 0 {
            tries.push((Action::NewSigner, mk(F_NEW_SIGNER)));
        }
        if acts & A_FLOOD != 0 {
            // FLOOD_SELFUPDATE: a self-update every epoch, whatever CO-14 says.
            tries.push((Action::Flood, mk(0)));
        }
        if acts & A_PROPOSALS != 0 && g.is_member(M0) {
            // A Remove of a non-committer: only CO-1's "no proposal at rank 255" refuses it.
            let mut k = mk(0);
            k.remove = M0 as u8;
            tries.push((Action::Proposals, k));
        }
        for (action, k) in tries {
            let mut st = Step::new(cfg, w);
            st.w.h.adversary = true;
            if let Err(v) = st.new_commit(a, k, 0) {
                return Err((action, v));
            }
            push(action, st);
        }
    }
    // SPAM_UNOPENABLE: an unopenable blob into a namespace the spammer can deposit to.
    // Three unopenable blobs at once (CO-11 (a)'s threshold), from both operators.
    let spam = w.b[B_SPAM];
    if acts & A_SPAM != 0 && spam.kind == B_NONE {
        for sp in (0..NA).filter(|&n| cfg.malicious & abit(n) != 0) {
            let o = w.m[sp];
            if !o.online {
                continue;
            }
            let Some((ns, prev)) = listened(w, gen, rules, sp) else {
                continue;
            };
            let mut nss = vec![ns];
            if let Some(p) = prev {
                if p != ns {
                    nss.push(p);
                }
            }
            for ns in nss {
                let mut st = Step::new(cfg, w);
                st.w.h.adversary = true;
                st.w.b[B_SPAM] = Blob {
                    kind: B_SPAMBLOB,
                    author: sp as u8,
                    chain: Chain::ROOT,
                    ns,
                    stored: true,
                    ops: 2,
                    aux: 3,
                    ..Blob::default()
                };
                if matches!(o.status, Status::Removed | Status::Left) {
                    st.ev |= EV_DRAIN_SPAM;
                }
                push(Action::Spam { ns }, st);
            }
        }
    }
    // REPLAY_JOIN: an insider re-stores a copy of the rejoin request.
    if acts & A_REPLAY != 0 && w.b[B_REPLAY].kind == B_NONE && w.b[B_REJOIN].kind == B_REJOINREQ {
        let mut st = Step::new(cfg, w);
        st.w.h.adversary = true;
        st.w.b[B_REPLAY] = Blob {
            stored: true,
            withheld: 0,
            expired: false,
            ..w.b[B_REJOIN]
        };
        push(Action::Replay, st);
    }
    // A malicious committer re-wraps J's join KeyPackage as a rejoin or a restore of M0 (no
    // pseudonym or invite signature, the wrong purpose): CO-2 refuses it at every member.
    if acts & A_REPLAY_SWAP != 0 {
        let c = C1;
        let o = w.m[c];
        let gc = group_of(w, gen, o.chain, rules);
        let busy =
            (0..NC).any(|s| w.c[s].used && w.c[s].author == c as u8 && w.c[s].parent == o.chain);
        if o.online
            && o.status == Status::Active
            && o.own == NONE
            && !busy
            && (o.seq as usize) < cfg.commit_budget[c] as usize
            && gc.rank(c) != 255
            && gc.is_member(M0)
            && o.chain.len() < cfg.depth
        {
            for restore in [false, true] {
                let k = Commit {
                    used: true,
                    parent: o.chain,
                    author: c as u8,
                    inc: o.inc,
                    remove: NONE,
                    swap: M0 as u8,
                    swap_kind: if restore { SWAP_RESTORE } else { SWAP_REJOIN },
                    kp: kp_id(J, KP_JOIN),
                    flags: F_BAD_EVIDENCE | F_WRONG_PURPOSE | F_ADVERSARY,
                    ..Commit::default()
                };
                let st0 = Step::new(cfg, w);
                for pos in st0.hash_positions(o.chain, c) {
                    let action = Action::ReplaySwap { restore, hash: pos };
                    let mut st = Step::new(cfg, w);
                    st.w.h.adversary = true;
                    if let Err(v) = st.new_commit(c, k, pos) {
                        return Err((action, v));
                    }
                    push(action, st);
                }
            }
        }
    }
    Ok(())
}
