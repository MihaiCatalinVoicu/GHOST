//! EM-3: the exhaustive commit-arbitration model of the channel design (Phase 10 design
//! `docs/design/faza10-forum.md` §12.3; what it found is in §19.34). Test-only: no dependency,
//! outside every shipped and host graph; `tests/state_models.rs` runs it.
//!
//! # What it is
//!
//! The method of EM-1 and EM-2 (Phase 9 design §15.2): an explicit-state model of CO-1 … CO-14 and
//! §6.5 … §6.7, explored exhaustively — every interleaving of every enabled action within stated
//! bounds — with the properties of §12.3 checked as assertions at every transition and at every
//! quiescent state, and reachability queries proving that each scenario's honest flows complete (a
//! safety property that holds because nothing happens proves nothing, Phase 9's lesson). The rules
//! are the normative text: §19.26 … §19.31 win over §0 … §19.25 where they differ — in particular
//! §19.29.1 (a KeyPackage whose lifetime is not the constant one makes the commit invalid for every
//! member, on both of OpenMLS's branches, whatever its clocks), §19.29.2 (a rejoin's Welcome is
//! anchored to a committer of the rejoiner's last final epoch), §19.31 row 3 (successor senders,
//! abandonment and progress count only messages of the epoch whose key opened them) and §19.31 row
//! 14 (a committer never builds a commit its own CO-2 check refuses).
//!
//! # The world (`model`)
//!
//! - **Actors** (§12.3: "2 committers (ranks 0 and 1), 2 members"): C0 (rank 0, the owner and the
//!   sponsor of J's invite), C1 (rank 1), M0 and M1 (rank 255), and the invitee J (one join, §6.2).
//!   `committers`, the ranks, the roster, the generation and its namespace are a function of the
//!   branch (`group_of`), never stored apart from it.
//! - **Commits**: what CO-1, CO-2 and CO-14 read of an MLS commit — the sender and its leaf
//!   incarnation, an Add with its `AdmitEvidence` (§6.2.4 (A)), a Remove, a swap with its kind and
//!   KeyPackage (§19.2, §19.3), a context change (resignation, transfer of rank 0, §19.13), the
//!   rotation flag (§6.5) and the defects an adversary can put in (§19.14's new signature key,
//!   §19.29.1's finite or expired lifetime, a forged or re-wrapped evidence) — and a tie-break key.
//!   MLS cryptography is not modelled: `verdict` is the oracle for OpenMLS plus GHOST's checks, in
//!   the design's order (the lifetime first, V10-11). The hash is only an order among the siblings
//!   of one parent, which is all CO-3 reads; its positions are explored where CO-3 reads them (a
//!   sibling of the same rank exists) and a new commit takes the last one otherwise.
//! - **Blobs** (§5.6): commits, posts (a LEAVE request is a post, §6.6), join and rejoin requests
//!   (§6.2.3, §6.7), Welcomes (§19.2) and unopenable spam (§12.1), each stored in the namespace of
//!   its generation (§6.5) and served by two operators (CO-11 (a)). A member opens an epoch blob
//!   (mode 0x11) with the key of an epoch of its branch from its join epoch on (history "none",
//!   §8.4), a past epoch for two days after it became past (R = 2, §8.3), and join traffic under
//!   `JK_g` of a generation it lists (§5.6); a blob it opened once is processed (CO-11 (a) counts
//!   only blobs that "stayed unopenable").
//! - **Members**: every field the design persists (CS-C1); a process death clears only the session
//!   (`online`, `listed`).
//!
//! # Abstractions, and why each is sound
//!
//! - **A1 Ordinal time.** There is no clock: time passes through events whose order is all that
//!   CO-4 and CO-8 … CO-12 read. `Tick(m)` is m's settle window elapsing (CO-4 (i): 20 minutes
//!   after its anchor) together with the listing pass of CO-4 (ii) (a member that lists later is
//!   the same member listing again; listing is idempotent). `Age(k)` is k's store-hour anchor
//!   passing (store hour + 60 + 20 minutes, CO-4). `Day` is 24 hours: CO-11's 72 hours and CO-12's
//!   9 days are counted in days with saturating counters, and a past epoch's key is kept for R = 2
//!   days (§8.3). `WorkAge`, `PcsDue` and `SlotDue` are CO-8's 48 hours of rank 1, CO-8's 7-day PCS
//!   commit and CO-9's slot. The quantitative facts the orderings rest on are proven exhaustively,
//!   in minutes and days, by `arith`.
//! - **A2 The window's argument (T1).** A blind pass — its committer held no candidate for the
//!   epoch — runs at most 5 minutes after the committer's listing pass (CO-8), which came before
//!   the first candidate's store s, and is stored within the send delay (10 minutes, Phase 7 HIGH
//!   mode): before s + 20, when the earliest window of the epoch can end, since a window runs from a
//!   sighting of a stored copy (A4). So the search lets no window of the epoch elapse, and no
//!   sibling's store-hour anchor pass, while a commit built at such a pass (no member had started to
//!   settle the epoch) is unstored and its author online (`arith::blind_pass_is_prompt`,
//!   `arith::prompt_store_precedes_anchors`). Every other honest commit — a pass over a held
//!   candidate, a store after a process death or an op's resends — may be stored at any later
//!   point.
//! - **A3 Stale blind passes (T2).** For the same reason, a committer that holds no candidate while
//!   one is stored and served to it (it listed before that store) passes only while no member has
//!   started to settle the epoch, in the scenarios without withholding (`Step::stale_blind_late`).
//! - **A4 CO-4 (i)'s own-commit anchor.** A committer's first sighting of its own commit is the
//!   listing pass that fetches its stored copy ("the copy it fetched"), the reading under which T1
//!   holds for the committer as well; the other reading, the pass that built it, is the mutant
//!   `OwnAnchorAtPass` (finding F-4).
//! - **A5 Sessions and process death (CS-C1; EM-1's argument).** Each action is one transaction: a
//!   process death before it is the same successor as not taking it, so death is `Offline`, which
//!   ends the session and clears what a session holds. `online` means that the process is alive, in
//!   the foreground or not: a member may list late (a backgrounded app lists only at its jobs,
//!   CO-8), so no listing cadence is assumed. Session changes are bounded per scenario.
//! - **A6 Relays.** A store reaches every relay of the set at once. The relays may withhold a
//!   stored commit from chosen members (FORK, WITHHOLD_COMMIT, a partition, §12.1) for good or, in
//!   SC-FORK at full scale, until they end the partition; they drop a copy (its TTL, EXPIRE_LOG); an
//!   op may close INDETERMINATE with or without a copy (Phase 7, §19.13). Reordering is the
//!   interleaving itself; loss is withholding for good, expiry or a lost store; duplication is
//!   REPLAY_JOIN's re-stored copy (the copies of one blob at two operators are one blob: processing
//!   is idempotent).
//! - **A7 Posts** are stored at once (their send delay is not modelled): here a post is a successor
//!   sender (CO-3), progress (CO-11, CO-12) or the object of the removal hold (CO-13).
//! - **A8 Bounds.** At most 4 epoch transitions from epoch 16 (§12.3: "epochs ≤ 4"; epoch 16 so that
//!   CO-14's `min(8, n)` lies in the past), 3 commits and 2 posts per actor, per-scenario commit, post
//!   and session budgets, and a horizon of 9 or 10 days. A finding is a counter-example within the
//!   bounds; "holds" means "holds within the bounds".
//! - **A9 The search** (`search`). Depth-first, every reached state stored as a 128-bit fingerprint
//!   (hash compaction: a collision could hide states, never invent a violation, and its probability
//!   at the largest run is far below 10⁻¹⁸). No symmetry reduction: the actors differ in rank,
//!   budget and role, and commit and blob slots are already canonical (by author and sequence). The
//!   finding probes run breadth-first and print a shortest counter-example. A run that reaches its
//!   state budget fails (EM-1's rule: an overflow is not a verdict).
//! - **A10 Terminal properties** run at quiescent states (nothing is left but ending a session), so
//!   "eventually" claims — liveness, detection — are checked within the bounds.
//! - **A11 Ghost variables** (`History`, `Member::tries`, `Member::gw`, `Member::gs`) are premises of
//!   conditional properties and probes; no rule reads them.
//!
//! # The adversaries of §12.3 and where each runs (`scenarios`)
//!
//! | Adversary (§12.3, the section it comes from) | Scenario |
//! |---|---|
//! | a late but better commit, stored after every honest member settled (§19.1) | SC-LATE; F-2 (b) |
//! | a member that keeps an old epoch's state and grinds a self-update below a settled winner (§19.1) | SC-GRIND; F-2 (a) |
//! | a returning member catching up across epochs, with and without successors (§19.1) | SC-CATCHUP (without), SC-LATE and SC-GRIND (with) |
//! | a member flooding self-updates (§19.5) | SC-FLOOD |
//! | a member or invite holder storing unopenable blobs (§19.15, L8-C11) | SC-SPAM-DRAIN; SC-SPAM-CURRENT (full scale) |
//! | a relay withholding a removing commit from a subset of two members for good (§19.1, PRV-H4) | F-3's probe (SCN-CL); SC-PARTITION (three members) |
//! | a replayed KeyPackage re-wrapped as a rejoin or a restore (§19.3, §6.7) | SC-REPLAY |
//! | a member whose system clock rejects a lifetime (§19.4, §19.29.1) | SC-CLOCKS |
//! | a committer whose own commit ends INDETERMINATE while others merge it (§19.13) | SC-INDET; F-5 |
//! | the owner on a dead branch, which must be readmitted (§19.13) | SC-OWNER |
//! | a resignation and a transfer of rank 0, then the former owner's leave (§19.13, §6.6) | SC-GOV |
//! | a moderator and the owner acting on the same aged request (§19.13, CO-8) | SC-JOIN (full scale) |
//! | a commit installing a leaf with a new signature key (§19.14) | SC-ADV |
//! | a member that misses a rotating commit for good: the silent orphan (§19.15) | SC-SILENT |
//! | members with different device and trusted clocks (S0-12, revised §19.29.1) | SC-CLOCKS |
//! | a member storing a commit that carries a non-canonical, expired KeyPackage (§19.29.1, E-70) | SC-JUNK |
//!
//! And §12.3's setting: message loss, duplication and reordering (A6), a partition of either side
//! for an interval or for good (SC-FORK, SC-PARTITION, F-3's probe), settle timers with store-hour
//! anchors (every scenario; A1, A2), process death at every step (A5), one removal (SC-REMOVE), one
//! join (SC-JOIN, SC-CLOCKS) and one rejoin (SC-FORK, SC-OWNER, SC-REPLAY).
//!
//! # Properties (`props`, `step`)
//!
//! §12.3's properties, by the identifiers the reports print: **convergence** — P-VALID-SAME (T41,
//! CS-C3), P-RANK, P-FOLLOW, P-FRESH, P-CONC (D8), P-STICKY (CO-6); **detection** — P-DETECT,
//! P-NO-FALSE-RESYNC (CO-11, CO-12, §19.15); **no stranded committer** — P-STRANDED, P-CUSTODY
//! (§19.13); **no invalid merge** — P-NO-INVALID-MERGE, P-OWN-VALID; **liveness** — P-LIVENESS (two
//! passes per request, the asked Remove merged), P-PASS (a flooding member never blocks a pass),
//! P-JOINED, P-GOVERNANCE, P-OWNER-BACK; **catch-up latency** — P-CATCHUP; **Welcomes** — P-WELCOME;
//! **removal hold** — P-HOLD; **rotation** — P-ROTATION; **lifetimes** — P-VALID-SAME, P-LIFETIME,
//! P-NO-INVALID-MERGE; and the rules' own decision-time checks P-VERIFIED (CO-4 (a)), P-WORKAGE
//! (CO-8), P-REJOIN-SAFE (§6.7). The finding probes add P-ONE-BRANCH (no two honest members on
//! different branches) and P-SCN-CL-PARTITION / P-SCN-CL-SPLIT (SCN-CL's detection claims).
//!
//! # Mutants and findings (`rules`)
//!
//! `rules::Mutant` holds one deliberate defect per rule — MM-2, MM-3, MM-4, MM-5, MM-7, MM-8,
//! MM-16, MM-19 … MM-21, MM-23 … MM-26, MM-31 … MM-34, MM-36, MM-37, MM-46 and the rules §12.9 has
//! no number for — and `tests/state_models.rs` names, for each, the scenario and the property that
//! kill it in a real run whose control (the same scenario under the design's rules) passes.
//! `rules::Fix` holds the corrections EM-3 proposes for its findings (§19.34): F-1 a committer
//! passing over a held candidate forks or strands; F-2 a late or ground commit diverts members
//! settling later in a quiet channel; F-3 SCN-CL's detection claims fail; F-4 CO-4 (i)'s own-commit
//! anchor must be the fetched copy; F-5 an INDETERMINATE own copy that others hold strands its
//! committer.
//!
//! # Scale
//!
//! The pull-request bound (the default; the `rust` job of `ci.yml`): 18 control scenarios, about
//! one million states, the 9 tests in under a minute in the debug profile (the crate is built at
//! opt-level 3). The full bound (`EM3_SCALE=full`; `channel-state-models.yml`, weekly, on
//! dispatch and on pushes to `main`): 19 scenarios, about 35 million states, the 9 tests in about
//! six minutes in the release profile with 8 explorations at once (`EM3_THREADS`; each holds its
//! own fingerprint set). Every exploration has a state budget (`EM3_BUDGET`: 5 million at the PR
//! bound, 100 million at the full one); reaching it fails the run.

pub mod arith;
pub mod model;
pub mod props;
pub mod rules;
pub mod scenarios;
pub mod search;
pub mod step;
