//! The rule set a run uses. Since slice S5a (owner decision D-1 … D-6 of 2026-10-05) the default
//! [`Rules::DESIGN`] **is** the design with the adopted corrections; [`Rules::LEGACY`] is the
//! pre-S5 design, kept for the findings' reproduction lines (§19.34 records the EM-3 build against
//! it). A mutant is the adopted design with exactly one rule changed; the killers are named in
//! `MUTANTS` and proven by `tests/state_models.rs`, and `Mutant::OwnUnverified` (MM-2) is the
//! registry's equivalent-mutant record (withdrawn as equivalent by D-5, not deleted: the check
//! counts it).

/// One deliberate defect per rule, each the rule's mutation of §12.9 or the round that withdrew it.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Mutant {
    // ---- CO-1 -----------------------------------------------------------------------------------
    /// MM-5: a rank-255 commit with proposals is accepted.
    Rank255Proposals,
    /// CO-1 / §19.13: the rank is read from the context after the commit.
    PostCommitRank,
    /// CO-1: a rank-255 self-update is never a candidate (only committers' commits are), so its
    /// author merges it alone (§19.34.1 item 12: P-CONC's registered killer).
    Rank255NeverCandidate,
    // ---- CO-2 -----------------------------------------------------------------------------------
    /// MM-21: a swap without rejoin or restore evidence is accepted.
    SwapWithoutEvidence,
    /// MM-23: an Add is checked against the member's own INVITE_ISSUED records (local history).
    LocalHistory,
    /// MM-33: a swap of a committer by a higher rank is refused (round 10b).
    NoSwapOfLowerRank,
    /// MM-31: a leaf whose signature key changed is accepted.
    NewSigner,
    /// S0-12 / round 10d (withdrawn by §19.29.1): finite lifetimes judged on the device clock; a
    /// `LifetimeError` candidate is lifetime-pending, ranked lowest and blocking as the sole one.
    LifetimeByClock,
    /// MM-46: a `LifetimeError`-refused commit is held as a lifetime-pending candidate (it blocks
    /// the settle, and with it every pass, as the sole candidate) instead of being invalid.
    LifetimePending,
    // ---- CO-3 -----------------------------------------------------------------------------------
    /// MM-4 (round 10a): the lowest hash wins, with neither successors nor rank.
    HashOnly,
    /// MM-24: no successor preference (plain `(rank, hash)`).
    NoSuccessors,
    // ---- CO-4 -----------------------------------------------------------------------------------
    /// MM-3: no settle window (a member settles at its first sighting).
    NoWindow,
    /// MM-2: an own commit is merged without a verified copy or a successor. **Withdrawn as
    /// equivalent by the owner's D-5 (2026-10-05, §19.34):** over the corrected CO-4 (D-1, D-4,
    /// D-5) it changes no decision — a window runs from a fetched copy, which is a verified one —
    /// and it survives every control and probe. It stays in the registry (the report check counts
    /// 37 mutants) as the equivalent-mutant record, run and expected to survive.
    OwnUnverified,
    /// MM-25: the anchor is the local first sighting only (no store-hour anchor).
    NoStoreHourAnchor,
    /// MM-32 (round 10b): an own commit is cleared when its op closes INDETERMINATE.
    ClearIndeterminate,
    /// CO-4 (ii) dropped: the settle does not wait for a listing pass after the window.
    NoListingPass,
    /// CO-4 (i) read with the committer's first sighting of its own commit at its pass (the
    /// `ch_candidate` row's creation) instead of the listing pass that fetches its stored copy.
    OwnAnchorAtPass,
    /// CO-3 / CO-4 (a) (round 10b's custody): an own commit without a verified copy is no candidate
    /// at its committer's settle, so a foreign candidate wins even when the own commit has more
    /// successor senders. **Equivalent under the adopted corrections (the S5a run):** with D-5's
    /// fetched-copy verification and D-1's settle-first rule the mutant explores exactly the
    /// control's state graph (SC-INDET), so it is registered as equivalent like MM-2.
    UnverifiedOwnNoCandidate,
    // ---- CO-5 -----------------------------------------------------------------------------------
    /// MM-19: Welcomes are enqueued at the pass, not at the settle of a won commit.
    WelcomeAtPass,
    // ---- CO-6 -----------------------------------------------------------------------------------
    /// MM-16: finality is not sticky; a settled member re-decides on a later (late or ground)
    /// commit (round 10a's "fork evidence, better").
    NotSticky,
    // ---- CO-7 -----------------------------------------------------------------------------------
    /// MM-26 (second half): a committer's pass is blocked by a rank-255 candidate. **Equivalent
    /// under the adopted corrections (the S5a run):** D-1's CO-7 settles the held candidate first
    /// and then passes, so blocking is indistinguishable from the design's delay — the mutant
    /// explores exactly the control's state graph (SC-FLOOD).
    Rank255Blocks,
    // ---- CO-8 -----------------------------------------------------------------------------------
    /// MM-34: a moderator's scheduled pass includes work younger than `r × 48 h`.
    FreshWork,
    // ---- CO-9 -----------------------------------------------------------------------------------
    /// CO-9: a member self-updates at a slot where CO-14 refuses it (no skip).
    NoSkip,
    // ---- CO-10 ----------------------------------------------------------------------------------
    /// CO-10: the losing committer drops its work instead of keeping it pending.
    DropLoserWork,
    // ---- CO-11 ----------------------------------------------------------------------------------
    /// MM-37: unopenable blobs in a draining namespace count for branch death.
    CountDraining,
    /// CO-11 dropped: a dead branch never reaches `resync_needed`.
    NoBranchDeath,
    /// CO-11 (b) as EM-3 first implemented it (§19.34.1 item 1): every message of the current
    /// epoch the member ever fetched counts as progress at every evaluation, so one old message
    /// restarts every window.
    RecountProgress,
    // ---- CO-12 ----------------------------------------------------------------------------------
    /// MM-36: no `stale_suspected`.
    NoStale,
    /// CO-12: no `partition_suspected`.
    NoPartition,
    /// CO-12's stale clock as EM-3 first implemented it (§19.34.1 item 1): every evaluation that
    /// finds an old message of the current epoch restarts it.
    RecountStale,
    // ---- CO-13 ----------------------------------------------------------------------------------
    /// PC-14: no removal hold.
    NoHold,
    // ---- CO-14 ----------------------------------------------------------------------------------
    /// MM-26 (first half): no rank-255 rate.
    NoRate,
    // ---- §6.5 -----------------------------------------------------------------------------------
    /// MM-7: no rotation on removal.
    NoRotation,
    /// MM-8: the next generation is derived from the pre-commit epoch.
    PreCommitGeneration,
    /// §6.5: a rejoin swap rotates like a restore swap.
    RejoinRotates,
    // ---- §6.2.4 (B) -----------------------------------------------------------------------------
    /// The admission policy refuses every join request (no committer ever commits the Add).
    NoAdmission,
    // ---- §6.7 -----------------------------------------------------------------------------------
    /// MM-20: a rejoin is admitted without freshness (a live leaf, a point the requester can catch
    /// up from).
    RejoinNoFreshness,
}

/// Corrections EM-3 proposed for its findings (§19.34, §19.34.1). Bits of [`Rules::fixes`].
/// **The owner's D-1 … D-6 (2026-10-05) adopted `SettleBeforePass`, `SelfUpdateAfterSettle`,
/// `PartitionOneOther`, `SplitCountsDraining` and `FetchedOwnCopy`: they are `Rules::DESIGN` since
/// slice S5a** (`Rules::LEGACY` keeps the uncorrected design for the findings' reproduction lines).
/// `SettleBeacon` (F-2's measured option: the owner declared the residual instead, D-2) and
/// `SplitNeedsProgress` (F-3 (a)'s first wording, kept as the evidence that it fails) were not
/// adopted and stay evidence-only.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Fix {
    /// F-1, CO-7's half: a committer that holds a valid candidate for its current epoch does not
    /// pass on that epoch: it settles first and may pass in the same actor step, before it lists
    /// again (so a self-update stored after the settle cannot delay it).
    SettleBeforePass = 1,
    /// F-3 (b): `partition_suspected` needs messages from one other member, not two.
    PartitionOneOther = 2,
    /// F-3 (a): `split_suspected` is CO-11 (a) over the current **and** the draining namespace
    /// while the member does not enter `resync_needed` (which keeps counting the current namespace
    /// only, §19.15 (c)).
    SplitCountsDraining = 4,
    /// F-2: a member that settles an epoch on a winner it did not author sends one empty
    /// authenticated message in the new epoch (a settle beacon): the winner gains a successor
    /// sender everywhere, and any own candidate of a committer that settled another winner is
    /// abandoned. **Not adopted (D-2: the residual is declared; beacons close the scripted ground
    /// probe only).**
    SettleBeacon = 8,
    /// F-5: the committer's own copy fetched by one of its listing passes (recognised by its hash)
    /// is a verified copy for CO-3 and CO-4, whatever the op's outcome.
    FetchedOwnCopy = 16,
    /// F-1, CO-9's half (§19.34.1 item 3): a member that holds a valid candidate for its current
    /// epoch self-updates only after it settles that epoch. With CO-7's half alone a rank-255
    /// self-update over a held candidate forks honest members as a committer's pass did.
    SelfUpdateAfterSettle = 32,
    /// Evidence only (§19.34.1 item 4): F-3 (a)'s correction as §19.34 first worded it,
    /// "`split_suspected`: CO-11 (a) holds over both namespaces **while progress continues**";
    /// with it the majority still raises nothing (it has no progress). **Not adopted (D-3).**
    SplitNeedsProgress = 64,
}

/// The adopted corrections (D-1, D-3, D-5): the design's rule set since slice S5a.
pub const ADOPTED: u8 = Fix::SettleBeforePass as u8
    | Fix::SelfUpdateAfterSettle as u8
    | Fix::PartitionOneOther as u8
    | Fix::SplitCountsDraining as u8
    | Fix::FetchedOwnCopy as u8;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
pub struct Rules {
    pub mutant: Option<Mutant>,
    pub fixes: u8,
}

impl Rules {
    /// The design's rule set: CO-1 … CO-14 and §6.5 … §6.7 **as corrected by D-1 … D-6** (owner
    /// 2026-10-05; the `Fix` bits above). Slice S5a switched EM-3's default to it.
    pub const DESIGN: Rules = Rules {
        mutant: None,
        fixes: ADOPTED,
    };

    /// The pre-S5 design (no correction): the uncorrected rule set the findings F-1 … F-5
    /// reproduce against, kept for the reproduction lines (§19.34's record of the EM-3 build).
    pub const LEGACY: Rules = Rules {
        mutant: None,
        fixes: 0,
    };

    /// One deliberate defect over the **adopted** design (the current [`Rules::DESIGN`] with one
    /// rule mutated), §12.9's method applied to the corrected rules.
    pub fn mutant(m: Mutant) -> Rules {
        Rules {
            mutant: Some(m),
            fixes: ADOPTED,
        }
    }

    pub fn with_fix(self, f: Fix) -> Rules {
        Rules {
            fixes: self.fixes | f as u8,
            ..self
        }
    }

    pub fn is(&self, m: Mutant) -> bool {
        self.mutant == Some(m)
    }

    pub fn fixed(&self, f: Fix) -> bool {
        self.fixes & f as u8 != 0
    }
}
