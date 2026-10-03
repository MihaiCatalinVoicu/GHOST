//! The model's state and its pure rule functions: the group state a branch implies, CO-1 / CO-2 /
//! CO-14 validity, what a member lists and opens, and the CO-3 / CO-4 choice at a settle point.
//!
//! Every rule cites the design section it encodes (`docs/design/faza10-forum.md`; §19.26 … §19.31
//! win over §0 … §19.25 where they differ). A rule that a mutant changes reads [`Rules::is`]; the
//! normative branch is the one taken when no mutant is set.

use crate::rules::{Fix, Mutant, Rules};

/// Actors: the owner (rank 0), the moderator (rank 1), two members (rank 255) and one invitee.
pub const NA: usize = 5;
pub const C0: usize = 0;
pub const C1: usize = 1;
pub const M0: usize = 2;
pub const M1: usize = 3;
pub const J: usize = 4;
pub const NONE: u8 = 0xff;
pub const ACTOR_NAMES: [&str; NA] = ["C0", "C1", "M0", "M1", "J"];

/// Epoch numbers are absolute: the model starts in a channel already in use (CO-14 compares a
/// leaf's `refresh_epoch` with the epoch, so the start must lie past `min(8, n)`), and explores at
/// most [`MAX_DEPTH`] epoch transitions from it (§12.3: "epochs ≤ 4").
pub const BASE_EPOCH: u8 = 16;
pub const MAX_DEPTH: usize = 4;

/// Commit slots: three per actor, assigned by (author, sequence number), so that the same commits
/// created in another interleaving are the same state.
pub const PER_ACTOR_COMMITS: usize = 3;
pub const NC: usize = NA * PER_ACTOR_COMMITS;

/// Blob slots (a `u32` mask per member records what it fetched). A commit's blob shares its slot.
pub const NB: usize = 32;
pub const POSTS_PER_ACTOR: usize = 2;
/// 15 … 24: two posts per actor.
pub const B_POST0: usize = NC;
/// 25: J's join request.
pub const B_JOIN: usize = B_POST0 + NA * POSTS_PER_ACTOR;
/// 26, 27: the rejoin request, one copy per listened namespace (current, draining; §6.7).
pub const B_REJOIN: usize = B_JOIN + 1;
/// 28: a request an insider re-wraps or copies (REPLAY_JOIN, §12.1).
pub const B_REPLAY: usize = B_REJOIN + 2;
/// 29: the Welcome of J's admission; 30: the Welcome of the rejoin swap.
pub const B_WELCOME_J: usize = B_REPLAY + 1;
pub const B_WELCOME_R: usize = B_WELCOME_J + 1;
/// 31: an unopenable blob (SPAM_UNOPENABLE, §12.1).
pub const B_SPAM: usize = B_WELCOME_R + 1;

pub const fn bit(i: usize) -> u32 {
    1u32 << i
}

pub const fn abit(a: usize) -> u8 {
    1u8 << a
}

/// A branch: the commit slots of its final epochs, in order (§1.3 "branch"): four four-bit slots and
/// a length, so it fits a `u32`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct Chain(u32);

impl Chain {
    pub const ROOT: Chain = Chain(0);

    pub fn len(self) -> usize {
        (self.0 >> 16) as usize
    }

    pub fn is_empty(self) -> bool {
        self.len() == 0
    }

    pub fn at(self, i: usize) -> usize {
        ((self.0 >> (4 * i)) & 0xf) as usize
    }

    pub fn push(self, slot: usize) -> Chain {
        let n = self.len();
        assert!(n < MAX_DEPTH && slot < 16, "a branch longer than MAX_DEPTH");
        Chain((self.0 & 0xffff) | ((slot as u32) << (4 * n)) | (((n + 1) as u32) << 16))
    }

    pub fn prefix(self, n: usize) -> Chain {
        let n = n.min(self.len());
        let mask = if n == 0 { 0 } else { (1u32 << (4 * n)) - 1 };
        Chain((self.0 & mask) | ((n as u32) << 16))
    }

    pub fn is_prefix_of(self, other: Chain) -> bool {
        self.len() <= other.len() && other.prefix(self.len()) == self
    }

    pub fn last(self) -> Option<usize> {
        (!self.is_empty()).then(|| self.at(self.len() - 1))
    }

    pub fn parent(self) -> Chain {
        self.prefix(self.len().saturating_sub(1))
    }

    /// Two branches are comparable when one extends the other (no fork between them).
    pub fn comparable(self, other: Chain) -> bool {
        self.is_prefix_of(other) || other.is_prefix_of(self)
    }
}

impl std::fmt::Debug for Chain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[")?;
        for i in 0..self.len() {
            if i > 0 {
                write!(f, " ")?;
            }
            write!(f, "k{}", self.at(i))?;
        }
        write!(f, "]")
    }
}

/// Swap kinds of `SwapEvidence` (§19.2): a rejoin (fork repair; no rotation) or a restore (an
/// invite-authorised swap onto a new device, which rotates; §6.5, §19.16).
pub const SWAP_REJOIN: u8 = 1;
pub const SWAP_RESTORE: u8 = 2;
/// Context changes (§5.3, CO-2, §19.13): a resignation (the author drops its own key) and a
/// transfer of rank 0 (rank 0 reorders `committers`).
pub const CTX_RESIGN: u8 = 1;
pub const CTX_TRANSFER: u8 = 2;

/// The evidence of an Add or a swap does not verify (a forged, re-wrapped or replayed request).
pub const F_BAD_EVIDENCE: u8 = 1;
/// The commit carries a KeyPackage whose lifetime is not the constant `[0, 2⁶⁴ − 1]` (§19.29.1).
pub const F_FINITE: u8 = 2;
/// … and that lifetime has expired for every correct clock (the insider's commit of E-70).
pub const F_EXPIRED: u8 = 4;
/// The update-path leaf carries a new signature key (NEW_SIGNER, §19.14).
pub const F_NEW_SIGNER: u8 = 8;
/// The KeyPackage's `GhostKpBind.purpose` does not match the evidence kind (§19.3).
pub const F_WRONG_PURPOSE: u8 = 16;
/// The rotation flag of `GhostCommitAad` (§6.5; committers only, CO-2).
pub const F_ROTATE: u8 = 32;
/// Built by the adversary (a property premise; no rule reads it).
pub const F_ADVERSARY: u8 = 64;

/// KeyPackage instances (a KeyPackage is named by its owner and the instance).
pub const KP_JOIN: u8 = 0;
pub const KP_REJOIN: u8 = 1;
pub const KP_RESTORE: u8 = 2;

pub const fn kp_id(owner: usize, instance: u8) -> u8 {
    (owner as u8) * 4 + instance
}

pub const fn kp_owner(kp: u8) -> usize {
    (kp / 4) as usize
}

pub const fn kp_instance(kp: u8) -> u8 {
    kp % 4
}

/// An abstract MLS commit: what CO-1 … CO-14 read of it. Its bytes are abstracted to `hash`, a
/// tie-break key whose order among the siblings of one parent is all that CO-3 reads.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
pub struct Commit {
    pub used: bool,
    /// The branch it is built on: a commit for epoch `BASE_EPOCH + parent.len()`.
    pub parent: Chain,
    pub author: u8,
    /// The author's leaf incarnation the commit was built from (its device).
    pub inc: u8,
    /// An Add of J with its `AdmitEvidence` (§6.2.4 (A), §19.2).
    pub admit: bool,
    pub remove: u8,
    pub swap: u8,
    pub swap_kind: u8,
    pub ctx: u8,
    pub flags: u8,
    pub hash: u8,
    /// The KeyPackage an Add or a swap carries.
    pub kp: u8,
}

impl Commit {
    pub fn has_proposals(&self) -> bool {
        self.admit || self.remove != NONE || self.swap != NONE || self.ctx != 0
    }

    /// The commit removes a pseudonym or swaps a leaf: the removal hold applies (CO-13: "Remove,
    /// leave, eviction, swap").
    pub fn removes_someone(&self) -> bool {
        self.remove != NONE || self.swap != NONE
    }
}

pub const B_NONE: u8 = 0;
pub const B_COMMIT: u8 = 1;
pub const B_POST: u8 = 2;
pub const B_JOINREQ: u8 = 3;
pub const B_REJOINREQ: u8 = 4;
pub const B_WELCOME: u8 = 5;
pub const B_SPAMBLOB: u8 = 6;

/// A relay-stored blob (§5.6): its kind and the key class that opens it.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
pub struct Blob {
    pub kind: u8,
    pub author: u8,
    /// Post: the epoch it is encrypted in. Commit: its parent. Welcome: the branch it joins.
    /// Rejoin request: the requester's last final epoch (its claim, §6.7).
    pub chain: Chain,
    /// The generation namespace it is stored in (§6.5).
    pub ns: Chain,
    pub stored: bool,
    /// CO-4's store-hour anchor lies in the past: `relayExpiryHour − TTL + 60 min + 20 min ≤ now`.
    pub old: bool,
    /// Past its relay TTL, or dropped by an EXPIRE_LOG relay.
    pub expired: bool,
    /// Actors the relays withhold it from (WITHHOLD_COMMIT, FORK, a partition).
    pub withheld: u8,
    /// Operators that serve it (CO-11 counts blobs from at least two).
    pub ops: u8,
    /// Welcome: the commit slot. Rejoin request: the KeyPackage. Post: 1 for a LEAVE request.
    pub aux: u8,
    /// The author's leaf incarnation when it sealed the blob.
    pub inc: u8,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
pub enum Status {
    /// Not in the channel (the invitee before it accepts its invite).
    #[default]
    Absent,
    /// Waiting for a Welcome (§6.2.2), or for the Welcome of its own copied rejoin (§6.7).
    Joining,
    Active,
    /// Left the channel (§6.6).
    Left,
    /// Removed by a merged commit (§6.6).
    Removed,
    /// Its leaf was swapped by a KeyPackage it did not make (§6.7, §19.3).
    Replaced,
    /// CO-11's dead branch: `resync_needed`, waiting for the user's rejoin (§6.7).
    Resync,
    /// `reinvite_needed` (§6.7).
    Reinvite,
}

impl Status {
    /// It holds an MLS group state of the channel (epoch keys to open blobs with).
    pub fn holds_state(self) -> bool {
        matches!(self, Status::Active | Status::Resync | Status::Reinvite)
    }
}

/// The Phase 7 outcome of the op that stores an own commit (CO-4).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
pub enum Op {
    #[default]
    None,
    /// Built at a pass, not yet stored.
    Queued,
    /// SENT or DEGRADED: a verified copy exists.
    Verified,
    /// Closed INDETERMINATE: a copy may or may not exist (§19.13).
    Indeterminate,
}

/// CO-12's flags.
pub const FL_SPLIT: u8 = 1;
pub const FL_PARTITION: u8 = 2;
pub const FL_STALE: u8 = 4;

/// A committer's pending work (§6.2.3, §6.6, §6.7; CO-8): requests it recorded, user actions.
pub const W_JOIN: u8 = 1;
pub const W_REMOVE: u8 = 2;
pub const W_REJOIN: u8 = 4;
pub const W_LEAVE: u8 = 8;
pub const W_RESIGN: u8 = 16;
pub const W_TRANSFER: u8 = 32;
/// User actions: passes at once whatever the rank (CO-8), never under the work-age rule.
pub const W_USER: u8 = W_REMOVE | W_RESIGN | W_TRANSFER;

/// One device: its view of the channel and its local state. Every field is persisted (CS-C1)
/// except `online` and `listed`, which a process death clears.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
pub struct Member {
    pub status: Status,
    /// Its final epochs. For a removed or replaced member: up to and including the commit that
    /// removed it. For the invitee: the root until it joins.
    pub chain: Chain,
    /// The depth from which it holds epoch keys (its join or rejoin epoch; history "none", §8.4).
    pub joined: u8,
    /// Its leaf incarnation (a swap installs a new one, §6.7, §6.12).
    pub inc: u8,
    pub online: bool,
    /// It completed a listing pass in the present session (§6.3.1 "current"; CO-4 (ii)).
    pub listed: bool,
    pub fetched: u32,
    /// CO-4 (i) holds for its current epoch through its own sighting: `anchor + 20 min ≤ now`.
    pub window: bool,
    /// CO-4 (ii): a listing pass completed after (i) held.
    pub after: bool,
    /// Its own pending commit (a slot), and the op that stores it.
    pub own: u8,
    pub op: Op,
    pub seq: u8,
    pub posts: u8,
    /// Settle beacons sent (F-2's correction); they share the post slots.
    pub beacons: u8,
    pub work: u8,
    /// Work first recorded at least `r × 48 h` ago (CO-8; rank 1: 48 h).
    pub aged: u8,
    /// A PCS commit is due (CO-8: its last commit is at least 7 days old).
    pub pcs: bool,
    /// A self-update slot is due (CO-9), or the retry after a lost self-update.
    pub slot: bool,
    pub flags: u8,
    /// KeyPackages whose private keys it holds (bit per instance).
    pub kp: u8,
    /// J's INVITE_ISSUED is in its records (it was a member when it was posted, §6.2.4 (B)).
    pub invite_record: bool,
    /// Its device clock is past a finite KeyPackage bound (only Q42 (b)'s world reads it).
    pub clock_late: bool,
    /// CO-11: days of the liveness window (saturating at 3 = 72 h), sessions in it (at 3), and
    /// whether progress was seen in it.
    pub dw: u8,
    pub ds: u8,
    pub prog: bool,
    /// CO-12: days without a committer commit merged and without another member's message (at 9).
    pub qd: u8,
    pub sd: u8,
    /// CO-12: other members whose messages arrived in those days.
    pub msgs: u8,
    /// Ghost (no rule reads it): the owner's passes that carried a pending request, for §12.3's
    /// "every pending request is committed within two passes".
    pub tries: u8,
    /// The day its current epoch became current (§8.3: past epochs are kept until their final day
    /// plus R = 2 days; the model keeps every past epoch of the branch until this day + 2, which is
    /// generous for the older ones).
    pub settle_day: u8,
    /// Ghost: sessions started (saturating at 3).
    pub sess: u8,
    /// Fetched blobs that opened at their first sighting or at a later re-offer (§7.5): processed,
    /// so CO-11 (a) never counts them ("stayed unopenable").
    pub opened: u32,
    /// Ghost (F-3's probe): the CO-11 window over the current and the draining namespace together,
    /// whatever the rule set: days (at 3) and sessions (at 3) since the member first held such a
    /// blob unopenable.
    pub gw: u8,
    pub gs: u8,
    /// Session changes so far (a scenario bounds them per actor; one death and one return already
    /// place a process death after every step of the run).
    pub toggles: u8,
}

impl Member {
    pub fn judge(&self) -> Judge {
        Judge {
            invite_record: self.invite_record,
            clock_late: self.clock_late,
        }
    }
}

/// Ghost variables: premises of conditional properties. No rule reads them.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
pub struct History {
    /// A committer passed while a candidate for that epoch was stored and visible to it but not
    /// yet fetched (it had not listed since): a stale pass.
    pub stale_pass: bool,
    /// An honest committer passed while it held a foreign valid candidate for that epoch.
    pub pass_over: bool,
    /// A session ended, the relays withheld, dropped or expired a blob, or an op closed
    /// INDETERMINATE.
    pub disturbed: bool,
    /// An adversary acted (P-CONC's premise; an insider's action never excuses a liveness failure).
    pub adversary: bool,
    /// An honest commit was stored after some member had already settled its epoch: a late copy
    /// (findings F-1 and F-2).
    pub late_copy: bool,
    /// A committer cleared an own commit whose copy the relays hold only because CO-3 demoted it as
    /// unverified (it would have won otherwise): finding F-5.
    pub demoted_copy: bool,
    /// Ghost: committers whose user asked for a Remove (P-LIVENESS reads it).
    pub asked: u8,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct World {
    pub c: [Commit; NC],
    pub b: [Blob; NB],
    pub m: [Member; NA],
    /// Commits an honest committer built at a concurrent pass and has not stored yet (the
    /// prompt-store assumption T1 of the header).
    pub prompt: u16,
    pub h: History,
    /// Days elapsed (day-scale scenarios only).
    pub day: u8,
    /// The relays ended their partition (A_RELEASE: every withheld blob served from then on).
    pub healed: bool,
}

/// The group state a branch implies: what every member that merged the same commits holds.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Group {
    pub depth: u8,
    pub roster: u8,
    pub inc: [u8; NA],
    /// `GhostLeaf.refresh_epoch` of every leaf (§5.4, CO-14).
    pub refresh: [u8; NA],
    /// `committers` (rank = index); `NONE` when absent.
    pub committers: [u8; 2],
    pub gen: u8,
    /// The epoch the current generation's secret is exported from (§5.2 rule (2)), which names
    /// its namespace; and the one before it (draining, §6.5).
    pub ns: Chain,
    pub prev_ns: Chain,
    /// J's invite was consumed on this branch (§6.2.4 (B), recorded at settle).
    pub invite_consumed: bool,
}

impl Group {
    pub fn rank(&self, a: usize) -> u8 {
        if self.committers[0] == a as u8 {
            0
        } else if self.committers[1] == a as u8 {
            1
        } else {
            255
        }
    }

    pub fn is_member(&self, a: usize) -> bool {
        self.roster & abit(a) != 0
    }

    pub fn members(&self) -> u32 {
        self.roster.count_ones()
    }

    pub fn committer_set(&self) -> u8 {
        self.committers
            .iter()
            .filter(|&&c| c != NONE)
            .fold(0, |s, &c| s | abit(c as usize))
    }

    pub fn epoch(&self) -> u8 {
        BASE_EPOCH + self.depth
    }
}

/// The channel at `BASE_EPOCH`: the scenario's starting group.
#[derive(Clone, Copy, Debug)]
pub struct Genesis {
    pub roster: u8,
    pub committers: [u8; 2],
    pub refresh: [u8; NA],
}

impl Genesis {
    pub fn group(&self) -> Group {
        Group {
            depth: 0,
            roster: self.roster,
            inc: [0; NA],
            refresh: self.refresh,
            committers: self.committers,
            gen: 0,
            ns: Chain::ROOT,
            prev_ns: Chain::ROOT,
            invite_consumed: false,
        }
    }

    /// The committer set when J's invite was issued (at genesis): its `committers_digest`.
    pub fn invite_committers(&self) -> u8 {
        self.group().committer_set()
    }
}

/// Why CO-1, CO-2 or CO-14 refuses a commit (the reasons of the native verdict, §19.30 item 10).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Reason {
    NotAMember,
    Permission,
    Rate,
    Evidence,
    Lifetime,
    Continuity,
    CommittersChanged,
    Context,
}

/// A member's verdict on a commit for its current epoch.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Verdict {
    Valid,
    Invalid(Reason),
    /// Only under the withdrawn lifetime rules (MM-46, S0-12 / round 10d): OpenMLS refused the
    /// KeyPackage's lifetime and the member holds the commit as lifetime-pending.
    Pending,
}

/// The member-local inputs a mutant may let into CO-2 (the design forbids it: no clock, no local
/// history, §19.2, §19.29.1).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Judge {
    pub invite_record: bool,
    pub clock_late: bool,
}

/// Applies a merged commit to the group state (CO-5, §6.5, §6.6, §6.7, §19.13). `at` is the branch
/// that ends with this commit (the new epoch).
pub fn apply(g: &mut Group, k: &Commit, at: Chain, rules: Rules) {
    let epoch = g.epoch();
    let a = k.author as usize;
    // Every GHOST commit carries an update path (§6.8, `force_self_update`) whose leaf has
    // `refresh_epoch` = the commit's epoch (§19.5).
    g.refresh[a] = epoch;
    let mut removed = false;
    if k.admit {
        g.roster |= abit(J);
        g.inc[J] = 0;
        g.refresh[J] = 0;
        g.invite_consumed = true;
    }
    if k.remove != NONE {
        let x = k.remove as usize;
        g.roster &= !abit(x);
        // A Remove of P and the drop of P's key are one unit (§5.7, S0-16).
        for c in g.committers.iter_mut() {
            if *c == k.remove {
                *c = NONE;
            }
        }
        removed = true;
    }
    let mut restore = false;
    if k.swap != NONE {
        let x = k.swap as usize;
        // A new leaf; the pseudonym keeps its place in `committers` and `funders` (§19.13).
        g.inc[x] = (g.inc[x] + 1) & 3;
        g.refresh[x] = 0;
        restore = k.swap_kind == SWAP_RESTORE;
    }
    match k.ctx {
        CTX_RESIGN => {
            for c in g.committers.iter_mut() {
                if *c == k.author {
                    *c = NONE;
                }
            }
        }
        CTX_TRANSFER => g.committers.swap(0, 1),
        _ => {}
    }
    if g.committers[0] == NONE {
        g.committers.swap(0, 1);
    }
    // §6.5's rotation rule; MM-7 drops the removal clause, MM-8 exports from the pre-commit epoch.
    let rotates = if rules.is(Mutant::NoRotation) {
        restore || k.flags & F_ROTATE != 0
    } else {
        removed || restore || k.flags & F_ROTATE != 0
    };
    g.depth += 1;
    if rotates {
        g.gen += 1;
        g.prev_ns = g.ns;
        g.ns = if rules.is(Mutant::PreCommitGeneration) {
            at.parent()
        } else {
            at
        };
    }
}

/// The group state of a branch.
pub fn group_of(w: &World, gen: &Genesis, chain: Chain, rules: Rules) -> Group {
    let mut g = gen.group();
    for i in 0..chain.len() {
        apply(&mut g, &w.c[chain.at(i)], chain.prefix(i + 1), rules);
    }
    g
}

/// CO-1, CO-2 and CO-14 on commit `k` against its pre-commit group state `g` (§6.4; revised
/// §19.13, §19.14, §19.29.1): a function of the commit, the pre-commit state and the commit's
/// authenticated data only. `judge` reaches it only through a mutant.
pub fn verdict(g: &Group, k: &Commit, rules: Rules, judge: Judge) -> Verdict {
    use Verdict::{Invalid, Pending, Valid};
    let a = k.author as usize;
    // CO-1: a candidate only if its sender is a member (its current leaf).
    if !g.is_member(a) || g.inc[a] != k.inc {
        return Invalid(Reason::NotAMember);
    }
    // §19.29.1 (Q42 (a)): a KeyPackage with any lifetime but the constant one is invalid for every
    // member on both of OpenMLS's branches, whatever the clocks. The withdrawn rules: S0-12 /
    // round 10d judge a finite lifetime by the device clock (a clock past the bound reaches the
    // refusal branch, where the commit is lifetime-pending; a clock within it the accept branch,
    // where the trusted-day predicate accepts an honest KeyPackage and refuses an expired one);
    // MM-46 holds a lifetime refusal as pending.
    if k.flags & F_FINITE != 0 {
        if rules.is(Mutant::LifetimeByClock) {
            if judge.clock_late || k.flags & F_EXPIRED != 0 {
                return Pending;
            }
        } else if rules.is(Mutant::LifetimePending) {
            return Pending;
        } else {
            return Invalid(Reason::Lifetime);
        }
    }
    // CO-1: the rank is read from the context before the commit (§19.13).
    let rank = if rules.is(Mutant::PostCommitRank) {
        let mut post = *g;
        apply(&mut post, k, Chain::ROOT, Rules::DESIGN);
        post.rank(a)
    } else {
        g.rank(a)
    };
    // §19.14: every leaf the commit installs keeps its member's signature key and credential.
    if k.flags & F_NEW_SIGNER != 0 && !rules.is(Mutant::NewSigner) {
        return Invalid(Reason::Continuity);
    }
    if rank == 255 {
        // CO-1: a rank-255 commit covers no proposal and sets no rotation flag …
        if (k.has_proposals() || k.flags & F_ROTATE != 0) && !rules.is(Mutant::Rank255Proposals) {
            return Invalid(Reason::Permission);
        }
        // … and satisfies CO-14: `refresh_epoch ≤ e − min(8, n)`, n the member count before it.
        if !rules.is(Mutant::NoRate) {
            let kk = g.members().min(8) as u16;
            if g.refresh[a] as u16 + kk > g.epoch() as u16 {
                return Invalid(Reason::Rate);
            }
        }
    }
    // A Remove by rank r targets only non-committers or committers of rank > r, except a swap
    // (§19.13); a commit cannot remove its own committer (RFC 9420 §12.2, `CannotRemoveSelf`).
    if k.remove != NONE {
        let x = k.remove as usize;
        if !g.is_member(x) || x == a {
            return Invalid(Reason::Permission);
        }
        let rx = g.rank(x);
        if rx != 255 && rx <= rank {
            return Invalid(Reason::Permission);
        }
    }
    if k.swap != NONE {
        let x = k.swap as usize;
        if !g.is_member(x) || k.remove == k.swap {
            return Invalid(Reason::Evidence);
        }
        // Any committer may swap a member of any rank (§19.13). MM-33 is round 10b's rule.
        if rules.is(Mutant::NoSwapOfLowerRank) {
            let rx = g.rank(x);
            if rx != 255 && rx <= rank {
                return Invalid(Reason::Permission);
            }
        }
        // Rejoin evidence is the pseudonym's signature over the KeyPackage; restore evidence an
        // invite's; the KeyPackage's purpose matches the kind and its leaf keeps the pseudonym
        // (§19.2, §19.3, §19.14). MM-21 accepts a swap without them.
        let evidence = k.flags & (F_BAD_EVIDENCE | F_WRONG_PURPOSE) == 0 && kp_owner(k.kp) == x;
        if !evidence && !rules.is(Mutant::SwapWithoutEvidence) {
            return Invalid(Reason::Evidence);
        }
    }
    if k.admit {
        if g.is_member(J) {
            return Invalid(Reason::Evidence);
        }
        // §6.2.4 (A): the sponsor (C0, who issued J's invite) is a current member not removed by
        // this commit, and the sponsor's and the invite's signatures verify. MM-23 checks the Add
        // against the member's own INVITE_ISSUED records.
        let local = !rules.is(Mutant::LocalHistory) || judge.invite_record;
        if k.flags & F_BAD_EVIDENCE != 0 || !g.is_member(C0) || k.remove == C0 as u8 || !local {
            return Invalid(Reason::Evidence);
        }
        // S0-15: a commit that carries an Add leaves `committers` unchanged.
        let drops = k.remove != NONE && g.rank(k.remove as usize) != 255;
        if drops || k.ctx == CTX_RESIGN {
            return Invalid(Reason::CommittersChanged);
        }
    }
    match k.ctx {
        // Any committer may drop its own key (a resignation), `committers` staying non-empty.
        CTX_RESIGN => {
            if rank == 255 {
                return Invalid(Reason::Permission);
            }
            let others = g
                .committers
                .iter()
                .filter(|&&c| c != NONE && c != k.author && c != k.remove)
                .count();
            if others == 0 {
                return Invalid(Reason::Context);
            }
        }
        // Only rank 0 reorders `committers` (a transfer of rank 0), into a list of two.
        CTX_TRANSFER => {
            if rank != 0 {
                return Invalid(Reason::Permission);
            }
            if g.committers[1] == NONE || k.remove == g.committers[1] {
                return Invalid(Reason::Context);
            }
        }
        _ => {}
    }
    Valid
}

/// The normative verdict (no mutant, no judge): what every member must conclude.
pub fn normative(g: &Group, k: &Commit) -> Verdict {
    verdict(g, k, Rules::DESIGN, Judge::default())
}

/// Whether member `m` lists namespace `ns` (§6.5, §7.1): its current generation and the draining
/// one; a removed, replaced or departed member keeps listing the namespaces it was in until the
/// drain ends (§6.5, §6.6, §19.8); the invitee lists its invite's namespace.
pub fn listens(w: &World, gen: &Genesis, rules: Rules, m: usize, ns: Chain) -> bool {
    let me = &w.m[m];
    let g = match me.status {
        Status::Absent => return false,
        Status::Removed | Status::Replaced | Status::Left => {
            group_of(w, gen, me.chain.parent(), rules)
        }
        _ => group_of(w, gen, me.chain, rules),
    };
    ns == g.ns || (g.gen > 0 && ns == g.prev_ns)
}

/// The namespaces member `m` lists (its current generation's and, if any, the draining one's).
pub fn listened(
    w: &World,
    gen: &Genesis,
    rules: Rules,
    m: usize,
) -> Option<(Chain, Option<Chain>)> {
    let me = &w.m[m];
    let g = match me.status {
        Status::Absent => return None,
        Status::Removed | Status::Replaced | Status::Left => {
            group_of(w, gen, me.chain.parent(), rules)
        }
        _ => group_of(w, gen, me.chain, rules),
    };
    Some((g.ns, (g.gen > 0).then_some(g.prev_ns)))
}

/// Every stored blob visible to `m` at a listing pass, as a mask.
pub fn visible_mask(w: &World, gen: &Genesis, rules: Rules, m: usize) -> u32 {
    let Some((ns, prev)) = listened(w, gen, rules, m) else {
        return 0;
    };
    let mut mask = 0;
    for i in 0..NB {
        let b = &w.b[i];
        if b.kind != B_NONE
            && b.stored
            && !b.expired
            && b.withheld & abit(m) == 0
            && (b.ns == ns || Some(b.ns) == prev)
        {
            mask |= bit(i);
        }
    }
    mask
}

/// Whether a stored blob is visible to `m` at a listing pass.
pub fn visible(w: &World, gen: &Genesis, rules: Rules, m: usize, i: usize) -> bool {
    let b = &w.b[i];
    b.kind != B_NONE
        && b.stored
        && !b.expired
        && b.withheld & abit(m) == 0
        && listens(w, gen, rules, m, b.ns)
}

/// The epoch a blob is sealed under (mode 0x11), when it is an epoch blob: a post's epoch, a
/// commit's parent.
pub fn epoch_chain(w: &World, i: usize) -> Option<Chain> {
    let b = &w.b[i];
    match b.kind {
        B_POST => Some(b.chain),
        B_COMMIT => Some(w.c[i].parent),
        _ => None,
    }
}

/// Whether the member holds the epoch key of `chain` (§5.6 CS-S5: its current epoch and the
/// retained past ones, from its join epoch on, history "none", §8.4; a past epoch for two days
/// after it became past, §8.3).
pub fn holds_epoch(me: &Member, chain: Chain, day: u8) -> bool {
    me.status.holds_state()
        && chain.is_prefix_of(me.chain)
        && chain.len() >= me.joined as usize
        && (chain == me.chain || day <= me.settle_day.saturating_add(2))
}

/// Whether the device ever held the epoch key of `chain` (it may have exported from it): for a
/// removed or replaced device, the epochs before the commit that removed it.
pub fn held_ever(me: &Member, chain: Chain) -> bool {
    let last = match me.status {
        Status::Removed | Status::Replaced => me.chain.parent(),
        Status::Absent | Status::Joining => return false,
        _ => me.chain,
    };
    chain.len() >= me.joined as usize && chain.is_prefix_of(last)
}

/// Whether the member opens a blob with the keys it holds now.
pub fn opens(w: &World, gen: &Genesis, rules: Rules, m: usize, i: usize) -> bool {
    let b = &w.b[i];
    match b.kind {
        B_POST | B_COMMIT => epoch_chain(w, i).is_some_and(|c| holds_epoch(&w.m[m], c, w.day)),
        // Join traffic opens under `JK_g` (modes 0x12, 0x13), which every member of g holds.
        B_JOINREQ | B_REJOINREQ | B_WELCOME => {
            w.m[m].status.holds_state() && listens(w, gen, rules, m, b.ns)
        }
        _ => false,
    }
}

/// What a settle decided, and from what (for the decision-time properties and the trace).
#[derive(Clone, Copy, Debug, Default)]
pub struct Choice {
    pub decision: Decision,
    /// Valid candidates held (the own commit included), at most one per sender (§6.3.5).
    pub candidates: u16,
    /// Candidates excluded as abandoned.
    pub abandoned: u16,
    pub successors: [u8; NC],
    pub trial: bool,
    /// Only under the withdrawn lifetime rules: a lifetime-pending commit held alone blocks.
    pub blocked: bool,
}

/// The CO-3 / CO-4 decision at a settle point.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Decision {
    /// Merge this commit slot (own or foreign).
    Merge(usize),
    /// Keep waiting: an own commit without a verified copy and without successors (CO-4 (a)).
    Wait,
    /// Nothing to settle.
    #[default]
    Nothing,
}

/// The successor senders of candidate `x` (CO-3): the distinct authenticated senders, other than
/// `x`'s committer and the member itself, of the held blobs sealed under `x`'s trial epoch
/// (`R_ep(e + 1)` of a trial settle of `x`; §19.31 M1: only messages of that epoch count).
pub fn successor_senders(w: &World, m: usize, x: usize) -> u8 {
    let me = &w.m[m];
    let trial = me.chain.push(x);
    let committer = w.c[x].author;
    let mut senders = 0u8;
    for i in 0..NB {
        if me.fetched & bit(i) == 0 {
            continue;
        }
        let b = &w.b[i];
        if b.author == m as u8 || b.author == committer || b.author == NONE {
            continue;
        }
        if epoch_chain(w, i) == Some(trial) {
            senders |= abit(b.author as usize);
        }
    }
    senders
}

/// Whether some held blob (not its own) does not open under the member's current keys: CO-3 runs
/// the trial settles only then.
pub fn something_unopened(w: &World, gen: &Genesis, rules: Rules, m: usize) -> bool {
    (0..NB).any(|i| {
        w.m[m].fetched & bit(i) != 0
            && w.b[i].kind != B_NONE
            && w.b[i].author != m as u8
            && !opens(w, gen, rules, m, i)
    })
}

/// The valid candidates a member holds for its current epoch, at most one per sender (the lowest
/// hash, §6.3.5), its own pending commit included; and whether it holds a lifetime-pending one.
pub fn candidates(w: &World, gen: &Genesis, rules: Rules, m: usize) -> (u16, bool) {
    let me = &w.m[m];
    if !me.status.holds_state() {
        return (0, false);
    }
    let g = group_of(w, gen, me.chain, rules);
    let mut cands: u16 = 0;
    let mut pending = false;
    for s in 0..NC {
        if me.fetched & bit(s) == 0 || w.b[s].kind != B_COMMIT || s == me.own as usize {
            continue;
        }
        let k = &w.c[s];
        if k.parent != me.chain {
            continue;
        }
        match verdict(&g, k, rules, me.judge()) {
            Verdict::Valid => {
                // One per sender: the lowest hash.
                let mut keep = true;
                for t in 0..NC {
                    if cands & (1 << t) != 0 && w.c[t].author == k.author {
                        if w.c[t].hash <= k.hash {
                            keep = false;
                        } else {
                            cands &= !(1 << t);
                        }
                    }
                }
                if keep {
                    cands |= 1 << s;
                }
            }
            Verdict::Pending => pending = true,
            Verdict::Invalid(_) => {}
        }
    }
    if me.own != NONE && w.c[me.own as usize].parent == me.chain {
        cands |= 1 << me.own;
    }
    (cands, pending)
}

/// CO-3 and CO-4 (a) … (c) at the member's settle point (§6.4, revised §19.13, §19.29.1).
pub fn decide(w: &World, gen: &Genesis, rules: Rules, m: usize) -> Choice {
    let me = &w.m[m];
    let g = group_of(w, gen, me.chain, rules);
    let own =
        (me.own != NONE && w.c[me.own as usize].parent == me.chain).then_some(me.own as usize);
    // CO-4: a verified copy is the op's SENT or DEGRADED outcome (F-5's correction: or a copy of it
    // the member fetched).
    let own_verified = me.op == Op::Verified
        || (rules.fixed(Fix::FetchedOwnCopy) && own.is_some_and(|s| me.fetched & bit(s) != 0));
    let (cands, pending) = candidates(w, gen, rules, m);
    let mut choice = Choice {
        candidates: cands,
        ..Choice::default()
    };
    if cands == 0 {
        // S0-12 / round 10d / MM-46: a lifetime-pending commit held alone blocks the settle.
        choice.blocked = pending;
        return choice;
    }
    let own_unverified = own.is_some() && !own_verified;
    let hash_only = rules.is(Mutant::HashOnly);
    let no_successors = hash_only || rules.is(Mutant::NoSuccessors);
    // The trial settles run only when more than one valid candidate is held and some held blob
    // does not open under the current keys; for an unverified own commit whenever a held blob does
    // not open (CO-3, CO-4 (a)).
    choice.trial = !no_successors
        && something_unopened(w, gen, rules, m)
        && (cands.count_ones() > 1 || own_unverified);
    if choice.trial {
        for s in 0..NC {
            if cands & (1 << s) != 0 {
                choice.successors[s] = successor_senders(w, m, s).count_ones() as u8;
            }
        }
        // Abandoned: the candidate's committer has an authenticated message that opens under
        // another candidate's trial state (it moved on).
        {
            for x in 0..NC {
                if cands & (1 << x) == 0 || Some(x) == own {
                    continue;
                }
                let cx = w.c[x].author;
                for y in 0..NC {
                    if y == x || cands & (1 << y) == 0 {
                        continue;
                    }
                    let trial = me.chain.push(y);
                    let moved = (0..NB).any(|i| {
                        me.fetched & bit(i) != 0
                            && w.b[i].author == cx
                            && epoch_chain(w, i) == Some(trial)
                    });
                    if moved {
                        choice.abandoned |= 1 << x;
                    }
                }
            }
        }
    }
    let eligible = cands & !choice.abandoned;
    // Most successor senders, then (rank, hash); an own commit without a verified copy ranks below
    // every held foreign candidate unless it has more successor senders.
    let better = |a: usize, b: usize| -> bool {
        if hash_only {
            return w.c[a].hash < w.c[b].hash;
        }
        let (sa, sb) = (choice.successors[a], choice.successors[b]);
        if sa != sb {
            return sa > sb;
        }
        let (la, lb) = (
            Some(a) == own && own_unverified,
            Some(b) == own && own_unverified,
        );
        if la != lb {
            return lb;
        }
        let (ra, rb) = (
            g.rank(w.c[a].author as usize),
            g.rank(w.c[b].author as usize),
        );
        if ra != rb {
            return ra < rb;
        }
        w.c[a].hash < w.c[b].hash
    };
    let mut best: Option<usize> = None;
    for s in 0..NC {
        if eligible & (1 << s) != 0 && best.is_none_or(|b| better(s, b)) {
            best = Some(s);
        }
    }
    let Some(winner) = best else {
        return choice;
    };
    choice.decision = if Some(winner) == own {
        // CO-4 (a): an own commit merges with a verified copy or at least one successor sender.
        if own_verified || choice.successors[winner] >= 1 || rules.is(Mutant::OwnUnverified) {
            Decision::Merge(winner)
        } else {
            Decision::Wait
        }
    } else {
        Decision::Merge(winner)
    };
    choice
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chains_push_and_compare() {
        let a = Chain::ROOT.push(3).push(7);
        assert_eq!(a.len(), 2);
        assert_eq!(a.at(0), 3);
        assert_eq!(a.at(1), 7);
        assert_eq!(a.parent(), Chain::ROOT.push(3));
        assert!(Chain::ROOT.push(3).is_prefix_of(a));
        assert!(!Chain::ROOT.push(4).is_prefix_of(a));
        assert!(a.comparable(Chain::ROOT));
        assert!(!a.comparable(Chain::ROOT.push(4)));
        assert_eq!(a.prefix(1).last(), Some(3));
        assert_eq!(format!("{a:?}"), "[k3 k7]");
    }

    fn genesis() -> Genesis {
        Genesis {
            roster: abit(C0) | abit(C1) | abit(M0) | abit(M1),
            committers: [C0 as u8, C1 as u8],
            refresh: [15, 15, 8, 14, 0],
        }
    }

    fn commit(author: usize) -> Commit {
        Commit {
            used: true,
            author: author as u8,
            remove: NONE,
            swap: NONE,
            ..Commit::default()
        }
    }

    #[test]
    fn co1_co2_co14_on_the_genesis_group() {
        let g = genesis().group();
        let ok = |k: &Commit| normative(&g, k);
        // A self-update of an eligible member (refresh 8 + min(8, 4) <= 16), not of M1 (14 + 4).
        assert_eq!(ok(&commit(M0)), Verdict::Valid);
        assert_eq!(ok(&commit(M1)), Verdict::Invalid(Reason::Rate));
        // A rank-255 commit with a proposal.
        let mut k = commit(M0);
        k.remove = C1 as u8;
        assert_eq!(ok(&k), Verdict::Invalid(Reason::Permission));
        // Rank 1 removes a member, not rank 0; rank 0 removes rank 1.
        let mut k = commit(C1);
        k.remove = M1 as u8;
        assert_eq!(ok(&k), Verdict::Valid);
        k.remove = C0 as u8;
        assert_eq!(ok(&k), Verdict::Invalid(Reason::Permission));
        let mut k = commit(C0);
        k.remove = C1 as u8;
        assert_eq!(ok(&k), Verdict::Valid);
        // A swap needs evidence; any committer may swap any rank.
        let mut k = commit(C1);
        k.swap = C0 as u8;
        k.swap_kind = SWAP_REJOIN;
        k.kp = kp_id(C0, KP_REJOIN);
        assert_eq!(ok(&k), Verdict::Valid);
        k.flags = F_BAD_EVIDENCE;
        assert_eq!(ok(&k), Verdict::Invalid(Reason::Evidence));
        // A finite lifetime is invalid whatever the clock.
        let mut k = commit(C0);
        k.admit = true;
        k.flags = F_FINITE;
        assert_eq!(ok(&k), Verdict::Invalid(Reason::Lifetime));
        assert_eq!(
            verdict(
                &g,
                &k,
                Rules::DESIGN,
                Judge {
                    invite_record: false,
                    clock_late: true
                }
            ),
            Verdict::Invalid(Reason::Lifetime)
        );
        // An admission leaves `committers` unchanged.
        let mut k = commit(C0);
        k.admit = true;
        k.remove = C1 as u8;
        assert_eq!(ok(&k), Verdict::Invalid(Reason::CommittersChanged));
        // Only rank 0 transfers; any committer resigns, not the last one.
        let mut k = commit(C1);
        k.ctx = CTX_TRANSFER;
        assert_eq!(ok(&k), Verdict::Invalid(Reason::Permission));
        k.ctx = CTX_RESIGN;
        assert_eq!(ok(&k), Verdict::Valid);
        // A new signature key.
        let mut k = commit(C0);
        k.flags = F_NEW_SIGNER;
        assert_eq!(ok(&k), Verdict::Invalid(Reason::Continuity));
    }

    #[test]
    fn rotation_follows_section_6_5() {
        let gen = genesis();
        let mut g = gen.group();
        let mut k = commit(C0);
        k.remove = M1 as u8;
        let at = Chain::ROOT.push(0);
        apply(&mut g, &k, at, Rules::DESIGN);
        assert_eq!(g.gen, 1);
        assert_eq!(g.ns, at);
        assert!(!g.is_member(M1));
        // A rejoin swap does not rotate; a restore swap does.
        let mut k = commit(C0);
        k.swap = M0 as u8;
        k.swap_kind = SWAP_REJOIN;
        let mut g2 = g;
        apply(&mut g2, &k, at.push(1), Rules::DESIGN);
        assert_eq!(g2.gen, 1);
        k.swap_kind = SWAP_RESTORE;
        apply(&mut g2, &k, at.push(1).push(2), Rules::DESIGN);
        assert_eq!(g2.gen, 2);
        // The transfer of rank 0 reorders; a resignation drops the key and compacts.
        let mut g3 = gen.group();
        let mut k = commit(C0);
        k.ctx = CTX_TRANSFER;
        apply(&mut g3, &k, Chain::ROOT.push(0), Rules::DESIGN);
        assert_eq!(g3.rank(C1), 0);
        assert_eq!(g3.rank(C0), 1);
        let mut k = commit(C1);
        k.ctx = CTX_RESIGN;
        apply(&mut g3, &k, Chain::ROOT.push(0).push(1), Rules::DESIGN);
        assert_eq!(g3.rank(C0), 0);
        assert_eq!(g3.rank(C1), 255);
    }
}
