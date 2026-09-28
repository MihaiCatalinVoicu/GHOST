//! Round 10e, the adversarial review of round 10d (design §19.29, the protocol findings):
//!
//! - the lifetime-refusal rule TR-1 wrote (a `LifetimeError` candidate ranked lowest, blocking the
//!   settle only as the sole candidate) forks honest members and lets any member freeze a channel,
//!   while the rule of Q42's constant lifetime (a `LifetimeError` can only come from a non-canonical
//!   KeyPackage, so the commit is invalid on both branches) gives every member one verdict;
//! - a removed committer that keeps its last state captures an invitee in a fork that passes the
//!   anchor and §5.3's validity and stays live, while E-63's fresh-group form fails §5.3;
//! - the rejoin anchor must stay "the GroupInfo signature verifies under one of the last
//!   committers": TR-7's set-digest equality refuses a legitimate rejoin Welcome.
//!
//! Device clocks are emulated as V10-11 and round 10d did: a KeyPackage whose bound is a few seconds
//! away is processed before the bound (a device clock inside the lifetime) and after it (a device
//! clock past it). That stands in for the day-scale case the design is about: an honest KeyPackage
//! of the finite canonical lifetime `[d − 4, d + 80]`, which the trusted-day predicate of S0-12
//! accepts on the accept branch, and a member whose device clock is more than four days slow.
//!
//! Run: `cargo test --release -p ghost-mls-spike --test r10e_protocol -- --nocapture --test-threads=1`

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ghost_mls_spike::ext::{self, ChannelContext, CommitAad};
use ghost_mls_spike::harness::*;
use ghost_mls_spike::kv::Scope;
use openmls::prelude::tls_codec::Deserialize as _;
use openmls::prelude::*;
use sha2::{Digest, Sha256};

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// The constant canonical lifetime of Q42 (a).
const CONSTANT: (u64, u64) = (0, u64::MAX);

/// A KeyPackage object built by `dev` itself (a joiner's or a modified client's), without a
/// committer's `KeyPackageIn::validate`: the commit builder takes it as it is.
fn own_key_package(
    dev: &mut Device,
    ch: [u8; 32],
    lifetime: Lifetime,
    purpose: u8,
    day: u32,
) -> KeyPackage {
    let box_pk = [7u8; 32];
    let cred = dev.credential();
    dev.call(&ch, |p, s| {
        KeyPackage::builder()
            .key_package_lifetime(lifetime)
            .leaf_node_capabilities(ghost_capabilities(SUITE, 0))
            .leaf_node_extensions(leaf_extensions(&box_pk, 0))
            .key_package_extensions(
                Extensions::single(Extension::Unknown(
                    ext::EXT_KP_BIND,
                    UnknownExtension(ext::kp_bind(&ch, purpose, day)),
                ))
                .map_err(|e| format!("{e:?}"))?,
            )
            .build(SUITE, p, s, cred)
            .map(|b| b.key_package().clone())
            .map_err(|e| format!("{e:?}"))
    })
    .expect("KeyPackage builds")
}

fn aad(day: u32) -> CommitAad {
    CommitAad {
        commit_minute: day * 1440,
        ..Default::default()
    }
}

fn spec(
    adds: Vec<KeyPackage>,
    removes: Vec<LeafNodeIndex>,
    ctx: Option<ChannelContext>,
    e: u64,
    day: u32,
) -> CommitSpec {
    CommitSpec {
        adds,
        removes,
        context: ctx,
        aad: aad(day),
        refresh_epoch: Some(e),
        force_path: true,
        no_exported_group_info: true,
        ..Default::default()
    }
}

fn sha(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}

// ---- the two lifetime rules -------------------------------------------------------------------

/// What a member's validation run (CO-2's first step) yields for a received commit.
#[derive(Clone, Debug, PartialEq)]
enum Seen {
    /// OpenMLS staged it: the sender leaf and every Add's `(not_before, not_after)`.
    Staged {
        sender: u32,
        lifetimes: Vec<(u64, u64)>,
    },
    /// `ValidationError(KeyPackageVerifyError(LifetimeError(..)))`: no sender, no proposal list.
    LifetimeError,
    /// Any other refusal.
    Other(String),
}

fn validate(dev: &mut Device, ch: [u8; 32], bytes: &[u8]) -> Seen {
    let r = dev
        .dry_call(&ch, |p, _| {
            let mut g = Device::load(p, &ch)?;
            let m = MlsMessageIn::tls_deserialize_exact(bytes).map_err(|e| format!("{e:?}"))?;
            let pm = m
                .try_into_protocol_message()
                .map_err(|e| format!("{e:?}"))?;
            let processed = g.process_message(p, pm).map_err(|e| format!("{e:?}"))?;
            let sender = match processed.sender() {
                Sender::Member(i) => i.u32(),
                _ => return Err("not a member sender".to_string()),
            };
            match processed.into_content() {
                ProcessedMessageContent::StagedCommitMessage(sc) => Ok((
                    sender,
                    sc.add_proposals()
                        .map(|a| {
                            let lt = a.add_proposal().key_package().life_time();
                            (lt.not_before(), lt.not_after())
                        })
                        .collect::<Vec<_>>(),
                )),
                _ => Err("not a commit".to_string()),
            }
        })
        .map(|(v, _)| v);
    match r {
        Ok((sender, lifetimes)) => Seen::Staged { sender, lifetimes },
        Err(e) if e.contains("KeyPackageVerifyError(LifetimeError(") => Seen::LifetimeError,
        Err(e) => Seen::Other(e),
    }
}

#[derive(Debug, PartialEq)]
enum Settle {
    Winner(&'static str),
    /// TR-1's `clock_blocked`: only lifetime-pending candidates are held.
    Blocked,
    /// No valid candidate: nothing merges and nothing is blocked.
    Nothing,
}

type Cand = (&'static str, Seen, [u8; 32]);

/// CO-3 in its normal case (no successors): the valid candidate with the lowest `(rank, hash)`.
fn lowest(valid: impl Iterator<Item = (&'static str, u8, [u8; 32])>) -> Option<&'static str> {
    valid.min_by_key(|&(_, r, h)| (r, h)).map(|(n, _, _)| n)
}

/// TR-1 as round 10d wrote it (withdrawn by §19.29): a staged commit is judged (the trusted-day
/// predicate accepts the honest KeyPackage this emulation stands in for); a `LifetimeError`
/// candidate is lifetime-pending at rank 255, never wins, and blocks the settle only when no
/// decidable valid candidate is held.
fn tr1_settle(c: &[Cand], rank_of: impl Fn(u32) -> u8) -> Settle {
    let valid = c.iter().filter_map(|(n, s, h)| match s {
        Seen::Staged { sender, .. } => Some((*n, rank_of(*sender), *h)),
        _ => None,
    });
    match lowest(valid) {
        Some(n) => Settle::Winner(n),
        None if c.iter().any(|(_, s, _)| *s == Seen::LifetimeError) => Settle::Blocked,
        None => Settle::Nothing,
    }
}

/// Round 10e's rule under Q42 (a): every Add must carry the constant lifetime (CO-2 (A)'s canonical
/// form, read on the accept branch), and a `LifetimeError` can only come from a non-canonical
/// KeyPackage, so the commit is invalid on the refusal branch too. No clock is read.
fn q42_settle(c: &[Cand], rank_of: impl Fn(u32) -> u8) -> Settle {
    let valid = c.iter().filter_map(|(n, s, h)| match s {
        Seen::Staged { sender, lifetimes } if lifetimes.iter().all(|&l| l == CONSTANT) => {
            Some((*n, rank_of(*sender), *h))
        }
        _ => None,
    });
    match lowest(valid) {
        Some(n) => Settle::Winner(n),
        None => Settle::Nothing,
    }
}

/// Finding 1, the fork (§19.29 R10D-P1): an honest rank-0 commit C1 adding a KeyPackage of finite
/// lifetime and an honest rank-255 self-update C2 for the same epoch. Under TR-1 a member whose
/// device clock is inside the KeyPackage's range picks C1 and one whose clock is past it picks C2:
/// same epoch, different epoch authenticators. Under Q42 (a) both judge C1 invalid (a finite
/// lifetime is not canonical) and merge C2; and an honest C1' whose KeyPackage carries the constant
/// lifetime is staged by both, whenever they process it, and merged by both.
#[test]
fn r10e_tr1_rule_forks_honest_members_q42_rule_converges() {
    let day = host_day();
    let mut w = World::build(4, 3, day);
    let ch = w.channel;
    // CO-14 (a KeyPackage leaf may self-update once e >= min(8, n) = 4): four owner commits first.
    for _ in 0..4 {
        w.self_update(0).unwrap();
    }
    let e = w.members[0].epoch(ch);
    let owner_leaf = w.members[0].leaf_index(ch);
    let rank_of = move |leaf: u32| if leaf == owner_leaf { 0u8 } else { 255u8 };
    let owner_base = w.members[0].rows.clone();
    let m1_base = w.members[1].rows.clone();
    let m3_base = w.members[3].rows.clone();

    let mut j = Device::new(60, day);
    let mut jc = Device::new(61, day);
    let t = now();
    let kp_finite = own_key_package(&mut j, ch, Lifetime::init(t - 3600, t + 4), 1, day);
    let kp_const = own_key_package(&mut jc, ch, Lifetime::init(0, u64::MAX), 1, day);
    // C1 (finite) and C1' (constant), each the owner's pending commit on its own copy of epoch e.
    let c1 = w.members[0]
        .commit(ch, &spec(vec![kp_finite], vec![], None, e, day))
        .unwrap();
    let owner_c1 = w.members[0].rows.clone();
    w.members[0].rows = owner_base.clone();
    let c1c = w.members[0]
        .commit(ch, &spec(vec![kp_const], vec![], None, e, day))
        .unwrap();
    let owner_c1c = w.members[0].rows.clone();
    let c2 = w.members[2]
        .commit(ch, &spec(vec![], vec![], None, e, day))
        .unwrap(); // a rank-255 self-update
    w.members[2].clear_own(ch).unwrap();

    let judge = |m: &mut Device| -> Vec<Cand> {
        vec![
            ("C1", validate(m, ch, &c1.commit), sha(&c1.commit)),
            ("C2", validate(m, ch, &c2.commit), sha(&c2.commit)),
            ("C1'", validate(m, ch, &c1c.commit), sha(&c1c.commit)),
        ]
    };
    let s1 = judge(&mut w.members[1]); // member 1: device clock inside the finite range
    std::thread::sleep(Duration::from_secs(6));
    let s3 = judge(&mut w.members[3]); // member 3: device clock past its bound
    println!(
        "R10e F1 member 1 (clock inside): {:?}",
        s1.iter().map(|x| (x.0, &x.1)).collect::<Vec<_>>()
    );
    println!(
        "R10e F1 member 3 (clock past):   {:?}",
        s3.iter().map(|x| (x.0, &x.1)).collect::<Vec<_>>()
    );
    assert!(matches!(s1[0].1, Seen::Staged { .. }));
    assert_eq!(s3[0].1, Seen::LifetimeError);
    assert!(
        matches!(s3[2].1, Seen::Staged { ref lifetimes, .. } if lifetimes.iter().all(|&l| l == CONSTANT))
    );

    // The candidates {C1, C2} of the finite world, and {C1', C2} of Q42 (a).
    let pair = |s: &[Cand], a: usize| vec![s[a].clone(), s[1].clone()];
    let (t1, t3) = (
        tr1_settle(&pair(&s1, 0), rank_of),
        tr1_settle(&pair(&s3, 0), rank_of),
    );
    let (q1, q3) = (
        q42_settle(&pair(&s1, 0), rank_of),
        q42_settle(&pair(&s3, 0), rank_of),
    );
    let (h1, h3) = (
        q42_settle(&pair(&s1, 2), rank_of),
        q42_settle(&pair(&s3, 2), rank_of),
    );
    println!("R10e F1 {{C1, C2}}: TR-1 rule member 1 -> {t1:?}, member 3 -> {t3:?}; Q42 rule member 1 -> {q1:?}, member 3 -> {q3:?}");
    println!("R10e F1 {{C1', C2}} under Q42 (a): member 1 -> {h1:?}, member 3 -> {h3:?}");
    assert_eq!((&t1, &t3), (&Settle::Winner("C1"), &Settle::Winner("C2")));
    assert_eq!((&q1, &q3), (&Settle::Winner("C2"), &Settle::Winner("C2")));
    assert_eq!((&h1, &h3), (&Settle::Winner("C1'"), &Settle::Winner("C1'")));

    // The merges. Member 3 merges C2 under either rule.
    w.members[3].receive(ch, &c2.commit).unwrap();
    let a3 = w.members[3].authenticator(ch);
    // TR-1: the owner's clock accepted C1 (like member 1's), so it merges its own C1: a fork.
    w.members[0].rows = owner_c1.clone();
    w.members[0].merge_own(ch).unwrap();
    let a0_tr1 = w.members[0].authenticator(ch);
    println!(
        "R10e F1 TR-1 merges: owner C1 {}.. vs member 3 C2 {}.. -> {}",
        hex::encode(&a0_tr1[..8]),
        hex::encode(&a3[..8]),
        if a0_tr1 == a3 { "CONVERGED" } else { "FORKED" }
    );
    assert_ne!(a0_tr1, a3, "TR-1's rule forks honest members");
    // Q42 rule: the owner clears its own C1 (it lost) and merges C2, like members 1 and 3.
    w.members[0].rows = owner_c1;
    w.members[0].clear_own(ch).unwrap();
    w.members[0].receive(ch, &c2.commit).unwrap();
    w.members[1].receive(ch, &c2.commit).unwrap();
    let q = [
        w.members[0].authenticator(ch),
        w.members[1].authenticator(ch),
        a3.clone(),
    ];
    println!(
        "R10e F1 Q42 rule: owner, members 1 and 3 all merge C2 -> equal authenticators {}",
        q.windows(2).all(|x| x[0] == x[1])
    );
    assert!(q.windows(2).all(|x| x[0] == x[1]));
    // Q42 (a), the honest C1': merged by the owner, by member 1 (clock inside) and by member 3
    // (processed 6 s later), from their epoch-e states.
    w.members[0].rows = owner_c1c;
    w.members[0].merge_own(ch).unwrap();
    w.members[1].rows = m1_base;
    w.members[1].receive(ch, &c1c.commit).unwrap();
    w.members[3].rows = m3_base;
    w.members[3].receive(ch, &c1c.commit).unwrap();
    let h = [
        w.members[0].authenticator(ch),
        w.members[1].authenticator(ch),
        w.members[3].authenticator(ch),
    ];
    println!(
        "R10e F1 Q42 (a) honest C1' merged by the owner and members 1 and 3 -> equal authenticators {}",
        h.windows(2).all(|x| x[0] == x[1])
    );
    assert!(h.windows(2).all(|x| x[0] == x[1]));
}

/// Finding 1, the freeze (§19.29 R10D-P1): a member of rank 255 deposits a commit adding a
/// KeyPackage whose finite lifetime has expired. Every member with a correct clock, the owner
/// included, gets `LifetimeError`; under TR-1 it is the sole candidate, so every member is
/// `clock_blocked`: the channel is not current (§6.3.1) and CO-7 forbids every pass, the owner's
/// Remove of the insider included. Under Q42 (a) the commit is invalid everywhere, nothing is
/// blocked, and the owner's Remove of the insider is merged by every member.
#[test]
fn r10e_tr2_insider_freezes_under_tr1_not_under_q42() {
    let day = host_day();
    let mut w = World::build(4, 3, day);
    let ch = w.channel;
    let owner_leaf = w.members[0].leaf_index(ch);
    let rank_of = move |leaf: u32| if leaf == owner_leaf { 0u8 } else { 255u8 };
    let insider_leaf = w.members[2].leaf_index(ch);
    let e = w.members[2].epoch(ch);
    let mut j = Device::new(62, day);
    let t = now();
    let kp = own_key_package(&mut j, ch, Lifetime::init(t - 3600, t + 3), 1, day);
    let junk = w.members[2]
        .commit(ch, &spec(vec![kp], vec![], None, e, day))
        .unwrap();
    w.members[2].clear_own(ch).unwrap();
    std::thread::sleep(Duration::from_secs(5)); // the KeyPackage has expired for every clock
    let mut tr1 = Vec::new();
    let mut q42 = Vec::new();
    for i in [0usize, 1, 3] {
        let s = validate(&mut w.members[i], ch, &junk.commit);
        assert_eq!(s, Seen::LifetimeError, "member {i} (correct clock)");
        let c = vec![("junk", s, sha(&junk.commit))];
        tr1.push(tr1_settle(&c, rank_of));
        q42.push(q42_settle(&c, rank_of));
    }
    println!("R10e F1 freeze: owner, members 1 and 3 all get LifetimeError; TR-1 settle -> {tr1:?} (every member clock_blocked: not current, CO-7 forbids every pass); Q42 rule -> {q42:?}");
    assert!(tr1.iter().all(|s| *s == Settle::Blocked));
    assert!(q42.iter().all(|s| *s == Settle::Nothing));
    // Under Q42 (a) nothing blocks the owner's pass: it removes the insider and every member merges.
    w.remove(0, insider_leaf)
        .expect("the owner's Remove of the insider");
    assert!(w.authenticators_agree());
    println!(
        "R10e F1 Q42 rule: the owner's pass removes the insider; {} members agree",
        w.members.len()
    );
}

// ---- capture by a removed committer -----------------------------------------------------------

/// S0-15's digest with TR-6's correction: over the committers sorted bytewise.
fn set_digest(ch: &[u8; 32], committers: &[[u8; 32]]) -> [u8; 32] {
    let mut s = committers.to_vec();
    s.sort();
    let mut h = Sha256::new();
    h.update(b"ghost/v1/ch/committers");
    h.update(ch);
    h.update([u8::try_from(s.len()).unwrap()]);
    for c in &s {
        h.update(c);
    }
    h.finalize().into()
}

fn ctx_with(ch: [u8; 32], committers: Vec<[u8; 32]>) -> ChannelContext {
    let mut c = ChannelContext::initial(ch, committers[0], 0);
    c.funders = vec![committers[0]];
    c.committers = committers;
    c
}

/// A joined state as the anchor sees it: the context, the GroupInfo signer's key, every leaf's key.
type JoinedView = (ChannelContext, [u8; 32], Vec<[u8; 32]>);

/// The joined state's context, the GroupInfo signer and every leaf's signature key, from a Welcome
/// (a dry call: nothing is written).
fn joined_view(j: &mut Device, ch: [u8; 32], welcome: &[u8]) -> Result<JoinedView, String> {
    j.dry_call(&ch, |p, _| {
        let m = MlsMessageIn::tls_deserialize_exact(welcome).map_err(|e| format!("{e:?}"))?;
        let w = match m.extract() {
            MlsMessageBodyIn::Welcome(w) => w,
            _ => return Err("not a welcome".to_string()),
        };
        let pw = ProcessedWelcome::new_from_welcome(p, &join_config(), w)
            .map_err(|e| format!("{e:?}"))?;
        let staged = JoinBuilder::new(p, pw)
            .skip_lifetime_validation()
            .build()
            .map_err(|e| format!("{e:?}"))?;
        let ctx = staged
            .group_context()
            .extensions()
            .unknown(ext::EXT_CHANNEL_CONTEXT)
            .and_then(|u| ChannelContext::decode(&u.0))
            .ok_or("no GhostChannelContext")?;
        let signer: [u8; 32] = staged
            .welcome_sender()
            .map_err(|e| format!("{e:?}"))?
            .signature_key()
            .as_slice()
            .try_into()
            .map_err(|_| "signature key length")?;
        let leaves: Vec<[u8; 32]> = staged
            .members()
            .map(|m| m.signature_key.as_slice().try_into().unwrap())
            .collect();
        Ok::<_, String>((ctx, signer, leaves))
    })
    .map(|(v, _)| v)
}

/// The join anchor of S0-15 with TR-6's set digest: the joined committers hash to the invite's
/// digest and the GroupInfo signer is one of them.
fn anchored(ch: &[u8; 32], invite: &[u8; 32], ctx: &ChannelContext, signer: &[u8; 32]) -> bool {
    &set_digest(ch, &ctx.committers) == invite && ctx.committers.contains(signer)
}

/// §5.3's validity of the joined context, the part a forger cannot fake in a fresh group: every
/// committer and every funder key is the signature key of a current leaf.
fn every_committer_a_leaf(ctx: &ChannelContext, leaves: &[[u8; 32]]) -> bool {
    ctx.committers
        .iter()
        .chain(ctx.funders.iter())
        .all(|k| leaves.contains(k))
}

/// Findings 2 (protocol) and 2 (privacy), §19.29 R10D-P2: E-63's forgery (a fresh group naming the
/// real committers) fails §5.3's leaf rule, so E-63 showed only the anchor comparison; a removed
/// moderator that keeps its last state forks the REAL group instead: the anchor and §5.3 both hold,
/// the joiner applies it, and the forger keeps it live with a committer commit and a post, so
/// neither `stale_suspected` nor `reinvite_needed` ever fires. Only an out-of-band comparison of the
/// fingerprint reveals it.
#[test]
fn r10e_tr4_capture_by_fork_passes_every_check_and_stays_live() {
    let day = host_day();
    let mut w = World::build(3, 2, day);
    let ch = w.channel;
    let owner = w.members[0].pk;
    let moderator = w.members[1].pk;
    let e0 = w.members[0].epoch(ch);
    w.commit_and_merge(
        0,
        &spec(
            vec![],
            vec![],
            Some(ctx_with(ch, vec![owner, moderator])),
            e0,
            day,
        ),
    )
    .unwrap();
    let invite_digest = set_digest(&ch, &[owner, moderator]);
    let mut j = Device::new(90, day);
    let kp_bytes = j.key_package(ch, 1, day, 0).unwrap();
    // The owner removes the moderator (the Remove and the drop of its key, one unit); the moderator
    // never processes it and keeps its epoch-e state.
    let e = w.members[0].epoch(ch);
    let mod_leaf = w.members[1].leaf_index(ch);
    let rm = w.members[0]
        .commit(
            ch,
            &spec(
                vec![],
                vec![LeafNodeIndex::new(mod_leaf)],
                Some(ctx_with(ch, vec![owner])),
                e,
                day,
            ),
        )
        .unwrap();
    w.members[2].receive(ch, &rm.commit).unwrap();
    w.members[0].merge_own(ch).unwrap();
    assert_ne!(set_digest(&ch, &[owner]), invite_digest); // CO-5 voids the invite

    // (1) E-63's form: a fresh group of the moderator's own naming [owner, moderator].
    let real_rows = w.members[1].rows.clone();
    w.members[1].rows.retain(|(s, _), _| *s == Scope::Global);
    w.members[1]
        .create_group(ch, &ctx_with(ch, vec![owner, moderator]))
        .unwrap();
    let kpf = w.members[1].parse_key_package(&kp_bytes).unwrap();
    let ef = w.members[1].epoch(ch);
    let fresh = w.members[1]
        .commit(ch, &spec(vec![kpf], vec![], None, ef, day))
        .unwrap()
        .welcome
        .unwrap();
    let (fctx, fsigner, fleaves) = joined_view(&mut j, ch, &fresh).expect("OpenMLS accepts it");
    let f_anchor = anchored(&ch, &invite_digest, &fctx, &fsigner);
    let f_valid = every_committer_a_leaf(&fctx, &fleaves);
    println!("R10e F2 E-63's fresh-group forgery: anchor {f_anchor}; §5.3 every committer a leaf {f_valid} -> refused by welcomeJoin's context check");
    assert!(f_anchor && !f_valid);
    w.members[1].rows = real_rows;

    // (2) The fork: the removed moderator commits the joiner's Add on its last real state.
    let kp = w.members[1].parse_key_package(&kp_bytes).unwrap();
    let fork = w.members[1]
        .commit(ch, &spec(vec![kp], vec![], None, e, day))
        .unwrap();
    w.members[1].merge_own(ch).unwrap();
    let welcome = fork.welcome.unwrap();
    let (ctx, signer, leaves) = joined_view(&mut j, ch, &welcome).expect("OpenMLS accepts it");
    let k_anchor = anchored(&ch, &invite_digest, &ctx, &signer);
    let k_valid = every_committer_a_leaf(&ctx, &leaves);
    println!(
        "R10e F2 fork capture: anchor {k_anchor}; §5.3 every committer a leaf {k_valid}; roster of {} leaves (the real members' included)",
        leaves.len()
    );
    assert!(k_anchor && k_valid);
    j.join(ch, &welcome, true).expect("captured");

    // The forger keeps it live: a committer commit (its PCS commit) and a post.
    let ej = w.members[1].epoch(ch);
    let pcs = w.members[1]
        .commit(ch, &spec(vec![], vec![], None, ej, day))
        .unwrap();
    w.members[1].merge_own(ch).unwrap();
    let r = j
        .receive(ch, &pcs.commit)
        .expect("the joiner merges the forger's commit");
    let post = w.members[1].encrypt(ch, 0, b"weekly notice").unwrap();
    let rp = j.receive(ch, &post).expect("and reads its post");
    assert_eq!(r.kind, "commit");
    assert_eq!(rp.plaintext, b"weekly notice");
    let (a_real, a_j) = (w.members[0].authenticator(ch), j.authenticator(ch));
    assert_ne!(a_real, a_j);
    println!(
        "R10e F2 the captured joiner merged a commit and read a post from leaf {:?} (a committer of its context): no stale_suspected, no reinvite_needed; real epoch {} vs captured epoch {}, authenticators differ (only an out-of-band comparison shows it)",
        r.sender,
        w.members[0].epoch(ch),
        j.epoch(ch)
    );
}

/// TR-5 in its fork form (§19.29 R10D-P2): a member offline across a moderator's removal sends a
/// rejoin request; the removed moderator, from its last real state (in which the rejoiner is still
/// a member), swaps the rejoiner's leaf. The Welcome passes the rejoin pre-check (the moderator is
/// among the rejoiner's last committers) and §5.3 (every committer is a leaf of the fork).
#[test]
fn r10e_tr5_rejoin_capture_by_fork() {
    let day = host_day();
    let mut w = World::build(3, 2, day);
    let ch = w.channel;
    let owner = w.members[0].pk;
    let moderator = w.members[1].pk;
    let e0 = w.members[0].epoch(ch);
    w.commit_and_merge(
        0,
        &spec(
            vec![],
            vec![],
            Some(ctx_with(ch, vec![owner, moderator])),
            e0,
            day,
        ),
    )
    .unwrap();
    let last = vec![owner, moderator]; // member 2's last final epoch
    let e = w.members[0].epoch(ch);
    let mod_leaf = w.members[1].leaf_index(ch);
    w.members[0]
        .commit(
            ch,
            &spec(
                vec![],
                vec![LeafNodeIndex::new(mod_leaf)],
                Some(ctx_with(ch, vec![owner])),
                e,
                day,
            ),
        )
        .unwrap();
    w.members[0].merge_own(ch).unwrap(); // members 1 (removed) and 2 (offline) never process it
    let kp_bytes = w.members[2].key_package(ch, 2, day, 0).unwrap();
    let kp = w.members[1].parse_key_package(&kp_bytes).unwrap();
    let leaf2 = w.members[2].leaf_index(ch);
    let welcome = w.members[1]
        .commit(
            ch,
            &spec(vec![kp], vec![LeafNodeIndex::new(leaf2)], None, e, day),
        )
        .unwrap()
        .welcome
        .unwrap();
    let mut view = Device::new(94, day);
    view.rows = w.members[2]
        .rows
        .iter()
        .filter(|((s, _), _)| *s == Scope::Global)
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    let pre = rejoin_precheck(&mut view, ch, &welcome, &last);
    let (ctx, signer, leaves) = joined_view(&mut view, ch, &welcome).expect("OpenMLS accepts it");
    let valid = every_committer_a_leaf(&ctx, &leaves);
    println!(
        "R10e F2 rejoin capture by fork: pre-check {pre:?}; signer is the removed moderator {}; §5.3 every committer a leaf {valid}",
        signer == moderator
    );
    assert_eq!(pre, Ok(()));
    assert!(signer == moderator && valid);
}

// ---- the rejoin anchor --------------------------------------------------------------------------

/// The rejoin pre-check §19.29 keeps (S0-15's rule, run on the unverified GroupInfo before
/// `JoinBuilder::build()`): the GroupInfo signature verifies under one of the committers of the
/// rejoiner's last final epoch. No digest is compared.
fn rejoin_precheck(
    j: &mut Device,
    ch: [u8; 32],
    welcome: &[u8],
    last: &[[u8; 32]],
) -> Result<(), String> {
    j.dry_call(&ch, |p, _| {
        let m = MlsMessageIn::tls_deserialize_exact(welcome).map_err(|e| format!("{e:?}"))?;
        let w = match m.extract() {
            MlsMessageBodyIn::Welcome(w) => w,
            _ => return Err("not a welcome".to_string()),
        };
        let pw = ProcessedWelcome::new_from_welcome(p, &join_config(), w)
            .map_err(|e| format!("{e:?}"))?;
        let gi = pw.unverified_group_info();
        for c in last {
            let pk = OpenMlsSignaturePublicKey::new(c.to_vec().into(), SignatureScheme::ED25519)
                .map_err(|e| format!("{e:?}"))?;
            if gi.verify_no_out(p.crypto(), &pk).is_ok() {
                return Ok(());
            }
        }
        Err("GroupInfo not signed by a last-known committer".to_string())
    })
    .map(|(v, _)| v)
}

/// Finding 8 (protocol) and 10 (privacy), §19.29 R10D-P8: after the live branch adds a moderator,
/// the owner's legitimate rejoin Welcome passes S0-15's rule (signer among the rejoiner's last
/// committers) and the kept pre-check, and fails TR-7's set-digest equality; a Welcome forged by a
/// non-committer holder of the join key is refused by the pre-check before any tree validation.
#[test]
fn r10e_tr7_rejoin_anchor_is_the_signature_only() {
    let day = host_day();
    let mut w = World::build(3, 2, day);
    let ch = w.channel;
    let owner = w.members[0].pk;
    let m1 = w.members[1].pk;
    let last = vec![owner]; // member 2's last final epoch
    let e = w.members[0].epoch(ch);
    let c = w.members[0]
        .commit(
            ch,
            &spec(vec![], vec![], Some(ctx_with(ch, vec![owner, m1])), e, day),
        )
        .unwrap();
    w.members[1].receive(ch, &c.commit).unwrap();
    w.members[0].merge_own(ch).unwrap(); // member 2 is offline
    let kp_bytes = w.members[2].key_package(ch, 2, day, 0).unwrap();
    let kp = w.members[0].parse_key_package(&kp_bytes).unwrap();
    let leaf2 = w.members[2].leaf_index(ch);
    let e = w.members[0].epoch(ch);
    let welcome = w.members[0]
        .commit(
            ch,
            &spec(vec![kp], vec![LeafNodeIndex::new(leaf2)], None, e, day),
        )
        .unwrap()
        .welcome
        .unwrap();
    // welcomeJoin for a rejoin gets only the KeyPackage's global rows (§6.2.5).
    let mut view = Device::new(92, day);
    view.rows = w.members[2]
        .rows
        .iter()
        .filter(|((s, _), _)| *s == Scope::Global)
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    let (ctx, signer, _) = joined_view(&mut view, ch, &welcome).expect("real rejoin Welcome");
    let s015 = last.contains(&signer);
    let tr7 = set_digest(&ch, &ctx.committers) == set_digest(&ch, &last);
    let kept = rejoin_precheck(&mut view, ch, &welcome, &last);
    println!("R10e F8 legitimate rejoin Welcome: S0-15 rule {s015}; TR-7 set-digest equality {tr7}; the kept pre-check (signature only) {kept:?}");
    assert!(s015 && !tr7);
    assert_eq!(kept, Ok(()));

    // A holder of the join key that is not a committer: its own group under the channel's id with
    // the real committers copied, adding member 2's rejoin KeyPackage.
    let mut forger = Device::new(93, day);
    forger.create_group(ch, &ctx_with(ch, vec![owner])).unwrap();
    let kpf = forger.parse_key_package(&kp_bytes).unwrap();
    let ef = forger.epoch(ch);
    let forged = forger
        .commit(ch, &spec(vec![kpf], vec![], None, ef, day))
        .unwrap()
        .welcome
        .unwrap();
    let r = rejoin_precheck(&mut view, ch, &forged, &last);
    println!("R10e F8 a non-committer's forged rejoin Welcome: pre-check -> {r:?}");
    assert!(r
        .unwrap_err()
        .contains("not signed by a last-known committer"));
}
