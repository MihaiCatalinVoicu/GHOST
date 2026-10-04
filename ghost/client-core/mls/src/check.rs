//! A commit's validation summary and CO-2 (design §6.4, revised §19.29.1) as far as it is a
//! function of the commit, the pre-commit group state and the commit's `GhostCommitAad` — no clock,
//! no local history (§19.2 rule 2). The verdict also applies CO-14 (a rank-255 commit's rate, which
//! reads only the tree) and requires every HPKE key of the resulting tree to be a valid X25519 key
//! (review of S2a, H1; §19.31). The summary is `receive`'s COMMIT output (§10.2 fn 6); the
//! arbitration that uses it (CO-1 … CO-14, slice S5) is Kotlin's. The same function validates a
//! committer's own pending commit before it leaves the device, and `settle` re-runs it on the
//! winner before merging.

use openmls::prelude::tls_codec::Serialize as _;
use openmls::prelude::*;
use openmls::treesync::RatchetTree;
use sha2::{Digest, Sha256};

use crate::canonical::{self, CanonicalKeyPackage, LeafFacts};
use crate::ext::{
    AdmitEvidence, ChannelContext, CommitAad, KpBind, Purpose, SwapEvidence,
    FLAG_MEMBERS_MAY_INVITE, FLAG_PASSWORD,
};
use crate::invite::{sponsor_message, verify_ed25519};
use crate::join::{invite_sig_message, rejoin_sig_message};
use crate::kv::KvError;
use crate::result::{Code, CommitReason, MlsError, MlsResult};
use crate::seal;

/// The pre-commit state a validation reads: the epoch, the context (ranks are always read from
/// it, §19.13), every member's leaf, signature key and `GhostLeaf.refresh_epoch` (CO-14), and — for
/// a commit's validation — the ratchet tree (the base of the tree check of H1).
#[derive(Clone, Debug)]
pub struct PreState {
    pub epoch: u64,
    pub context: ChannelContext,
    pub members: Vec<(u32, [u8; 32])>,
    /// `(leaf, GhostLeaf.refresh_epoch)` of every member whose leaf carries a readable `GhostLeaf`.
    pub refresh: Vec<(u32, u64)>,
    pub own_leaf: u32,
    /// The pre-commit ratchet tree ([`PreState::with_tree`]); `summarize` requires it.
    pub tree: Option<RatchetTree>,
}

impl PreState {
    pub fn of(g: &MlsGroup) -> MlsResult<Self> {
        let context = g
            .extensions()
            .unknown(crate::ext::EXT_CHANNEL_CONTEXT)
            .and_then(|u| ChannelContext::decode(&u.0))
            .ok_or(MlsError::new(Code::StateCorrupt))?;
        let mut members = Vec::new();
        let mut refresh = Vec::new();
        for m in g.members() {
            let k: [u8; 32] = m
                .signature_key
                .as_slice()
                .try_into()
                .map_err(|_| MlsError::new(Code::StateCorrupt))?;
            members.push((m.index.u32(), k));
            let leaf = g.public_group().leaf(m.index);
            if let Some(gl) = leaf.and_then(|l| {
                l.extensions()
                    .unknown(crate::ext::EXT_LEAF)
                    .and_then(|u| crate::ext::GhostLeaf::decode(&u.0))
            }) {
                refresh.push((m.index.u32(), gl.refresh_epoch));
            }
        }
        Ok(Self {
            epoch: g.epoch().as_u64(),
            context,
            members,
            refresh,
            own_leaf: g.own_leaf_index().u32(),
            tree: None,
        })
    }

    /// The pre-state of a commit's validation: with the ratchet tree.
    pub fn of_commit(g: &MlsGroup) -> MlsResult<Self> {
        let mut pre = Self::of(g)?;
        pre.tree = Some(g.export_ratchet_tree());
        Ok(pre)
    }

    /// The `GhostLeaf.refresh_epoch` of a member's leaf before the commit.
    pub fn refresh_of(&self, leaf: u32) -> Option<u64> {
        self.refresh
            .iter()
            .find(|(l, _)| *l == leaf)
            .map(|(_, e)| *e)
    }

    pub fn key_of(&self, leaf: u32) -> Option<[u8; 32]> {
        self.members
            .iter()
            .find(|(l, _)| *l == leaf)
            .map(|(_, k)| *k)
    }

    pub fn leaf_of(&self, key: &[u8; 32]) -> Option<LeafNodeIndex> {
        self.members
            .iter()
            .find(|(_, k)| k == key)
            .map(|(l, _)| LeafNodeIndex::new(*l))
    }

    pub fn is_member(&self, key: &[u8; 32]) -> bool {
        self.members.iter().any(|(_, k)| k == key)
    }
}

/// An Add of a new pseudonym (a join), or the Add half of a swap.
#[derive(Clone, Debug)]
pub struct AddSummary {
    pub kp_ref: Vec<u8>,
    pub pseudonym: [u8; 32],
    pub bind: Option<KpBind>,
    pub box_pk: Option<[u8; 32]>,
    /// The KeyPackage's lifetime is the constant `[0, 2⁶⁴ − 1]` (§19.29.1).
    pub constant_lifetime: bool,
    pub canonical: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemoveSummary {
    pub leaf: u32,
    pub pseudonym: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SwapKind {
    Rejoin,
    Restore,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SwapSummary {
    pub leaf: u32,
    pub pseudonym: [u8; 32],
    pub kind: Option<SwapKind>,
}

/// `receive`'s COMMIT output (fn 6): everything CO-1 … CO-5 read, and the native verdict of CO-2.
#[derive(Clone, Debug)]
pub struct CommitSummary {
    /// SHA-256 of the MLS commit bytes (CO-3's tie-break).
    pub hash: [u8; 32],
    pub size: usize,
    /// The epoch the commit leaves.
    pub epoch: u64,
    pub sender_leaf: u32,
    pub sender: [u8; 32],
    /// The sender's rank in the pre-commit `committers` (255 for a non-committer, CO-1).
    pub rank: u8,
    pub aad: Option<CommitAad>,
    pub joins: Vec<AddSummary>,
    pub removes: Vec<RemoveSummary>,
    pub swaps: Vec<SwapSummary>,
    /// The new context when the commit changes it.
    pub context: Option<ChannelContext>,
    pub rotates: bool,
    /// The update-path leaf's GHOST facts (`refresh_epoch`, `box_pk`), when the commit has a path.
    pub update_leaf: Option<LeafFacts>,
    /// The sender's leaf `GhostLeaf.refresh_epoch` **before** the commit, and the member count `n`
    /// before it: the inputs of CO-14 (a rank-255 commit's rate), which the verdict applies.
    pub sender_refresh_epoch: Option<u64>,
    pub members: usize,
    pub epoch_authenticator: Option<Vec<u8>>,
    /// `Ok` when CO-2 holds, or the first rule it breaks.
    pub verdict: Result<(), CommitReason>,
}

/// Maps a `process_message` refusal of a commit (§6.4 CO-2; §19.29.1: a `LifetimeError` can come
/// only from a non-canonical KeyPackage, so the commit is invalid for every member).
pub fn map_process_error(e: &ProcessMessageError<KvError>) -> MlsError {
    match e {
        ProcessMessageError::ValidationError(ValidationError::KeyPackageVerifyError(
            KeyPackageVerifyError::LifetimeError(_),
        )) => MlsError::commit(CommitReason::Lifetime),
        ProcessMessageError::ValidationError(ValidationError::WrongEpoch) => {
            MlsError::new(Code::WrongEpoch)
        }
        ProcessMessageError::UnauthorizedExternalCommitMessage => {
            MlsError::commit(CommitReason::NotAMember)
        }
        ProcessMessageError::StorageError(_) => MlsError::new(Code::StateCorrupt),
        _ => MlsError::commit(CommitReason::Refused),
    }
}

/// CO-2 (A)'s window: a KeyPackage's day within `[commit_day − 7, commit_day + 3]` (§6.2.4).
pub fn in_window(kp_day: u32, commit_day: u32) -> bool {
    kp_day.saturating_add(7) >= commit_day && kp_day <= commit_day.saturating_add(3)
}

/// Evidence that does not verify (§6.2.4 (A)); `INVALID_EVIDENCE` or `INVALID_COMMIT(evidence)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EvidenceFault;

/// Join or restore evidence (§6.2.4 (A)): the reference, a sponsor who is a current member not
/// removed by this commit and may invite, `sponsor_sig` under the sponsor, `invite_sig` under the
/// invite key over the KeyPackage.
pub fn verify_admit(
    channel_id: &[u8; 32],
    pre: &PreState,
    removed: &[[u8; 32]],
    ev: &AdmitEvidence,
    kp: &CanonicalKeyPackage,
) -> Result<(), EvidenceFault> {
    if ev.kp_ref != kp.kp_ref || !pre.is_member(&ev.sponsor) || removed.contains(&ev.sponsor) {
        return Err(EvidenceFault);
    }
    let ctx = &pre.context;
    let committer = ctx.rank_of(&ev.sponsor) != 255;
    let password = ctx.flags & FLAG_PASSWORD != 0;
    // Q46 (b): in a password channel only committers invite.
    if !(committer || (!password && ctx.flags & FLAG_MEMBERS_MAY_INVITE != 0)) {
        return Err(EvidenceFault);
    }
    let sponsor_msg = sponsor_message(channel_id, &ev.invite_id, &ev.invite_pk, ev.expiry_day);
    if !verify_ed25519(&ev.sponsor, &sponsor_msg, &ev.sponsor_sig) {
        return Err(EvidenceFault);
    }
    let invite_msg = invite_sig_message(channel_id, &ev.invite_id, &kp.bytes);
    if !verify_ed25519(&ev.invite_pk, &invite_msg, &ev.invite_sig) {
        return Err(EvidenceFault);
    }
    Ok(())
}

/// Swap evidence (§19.2, §19.3): a restore carries join evidence and a restore-purpose
/// KeyPackage; a rejoin carries `rejoin_sig` under the replaced leaf's key over the KeyPackage.
pub fn verify_swap(
    channel_id: &[u8; 32],
    pre: &PreState,
    key: &[u8; 32],
    removed: &[[u8; 32]],
    ev: &SwapEvidence,
    kp: &CanonicalKeyPackage,
) -> Result<(), EvidenceFault> {
    if kp.pseudonym != *key || !pre.is_member(key) || ev.kp_ref() != kp.kp_ref.as_slice() {
        return Err(EvidenceFault);
    }
    match ev {
        SwapEvidence::Restore(a) => {
            if kp.bind.purpose != Purpose::Restore {
                return Err(EvidenceFault);
            }
            verify_admit(channel_id, pre, removed, a, kp)
        }
        SwapEvidence::Rejoin {
            generation,
            day,
            last_epoch,
            last_hash,
            rejoin_sig,
            ..
        } => {
            if kp.bind.purpose != Purpose::Rejoin {
                return Err(EvidenceFault);
            }
            let m = rejoin_sig_message(
                channel_id,
                *generation,
                *day,
                *last_epoch,
                last_hash,
                &kp.bytes,
            );
            verify_ed25519(key, &m, rejoin_sig)
                .then_some(())
                .ok_or(EvidenceFault)
        }
    }
}

/// The roster change and the rotation rule of §6.5 from a staged commit: the pseudonyms added
/// (not re-added), those removed (not re-added), and whether it opens a new generation (a removal
/// not re-added, a restore swap, a size-class change or the rotation flag).
pub fn membership_change(
    pre: &PreState,
    sc: &StagedCommit,
    aad: &CommitAad,
) -> (Vec<[u8; 32]>, Vec<[u8; 32]>, bool) {
    let removed_all: Vec<[u8; 32]> = sc
        .remove_proposals()
        .filter_map(|r| pre.key_of(r.remove_proposal().removed().u32()))
        .collect();
    let added_all: Vec<[u8; 32]> = sc
        .add_proposals()
        .filter_map(|a| {
            a.add_proposal()
                .key_package()
                .leaf_node()
                .signature_key()
                .as_slice()
                .try_into()
                .ok()
        })
        .collect();
    let added: Vec<[u8; 32]> = added_all
        .iter()
        .filter(|k| !removed_all.contains(k))
        .copied()
        .collect();
    let removed: Vec<[u8; 32]> = removed_all
        .iter()
        .filter(|k| !added_all.contains(k))
        .copied()
        .collect();
    let class_change = sc
        .group_context()
        .extensions()
        .unknown(crate::ext::EXT_CHANNEL_CONTEXT)
        .and_then(|u| ChannelContext::decode(&u.0))
        .is_some_and(|c| c.size_class != pre.context.size_class);
    let restore = aad
        .swaps
        .iter()
        .any(|s| matches!(s, SwapEvidence::Restore(_)));
    let rotates = !removed.is_empty() || restore || class_change || aad.rotate;
    (added, removed, rotates)
}

fn kp_bytes(kp: &KeyPackage) -> Option<Vec<u8>> {
    MlsMessageOut::from(kp.clone())
        .tls_serialize_detached()
        .ok()
}

/// Builds the summary of a staged commit and evaluates CO-2 on it. `bytes` is the MLS commit as
/// received (its size and hash); `floor` the class floor of the pre-commit context.
#[allow(clippy::too_many_arguments)]
pub fn summarize(
    crypto: &impl OpenMlsCrypto,
    channel_id: &[u8; 32],
    pre: &PreState,
    sender: &Sender,
    aad_bytes: &[u8],
    sc: &StagedCommit,
    bytes: &[u8],
    floor: usize,
) -> MlsResult<CommitSummary> {
    let Sender::Member(idx) = sender else {
        return Err(MlsError::commit(CommitReason::NotAMember));
    };
    let sender_key = pre
        .key_of(idx.u32())
        .ok_or(MlsError::commit(CommitReason::NotAMember))?;
    let rank = pre.context.rank_of(&sender_key);
    let aad = CommitAad::decode(aad_bytes);
    let mut faults: Vec<CommitReason> = Vec::new();
    let mut fault = |r: CommitReason| faults.push(r);
    if aad.is_none() {
        fault(CommitReason::Aad);
    }
    let aad_v = aad.clone().unwrap_or_default();
    let commit_day = aad_v.commit_minute / 1440;

    // Proposals: Add, Remove and GroupContextExtensions only; a rank-255 commit covers none.
    let mut proposals = 0usize;
    for q in sc.queued_proposals() {
        proposals += 1;
        match q.proposal().proposal_type() {
            ProposalType::Add | ProposalType::Remove | ProposalType::GroupContextExtensions => {}
            _ => fault(CommitReason::Proposal),
        }
    }
    if rank == 255 && proposals > 0 {
        fault(CommitReason::Permission);
    }
    if rank == 255 && aad_v.rotate {
        fault(CommitReason::Permission);
    }

    // Removes (with the pre-commit keys) and Adds (canonical KeyPackages).
    let removes: Vec<RemoveSummary> = sc
        .remove_proposals()
        .map(|r| {
            let leaf = r.remove_proposal().removed().u32();
            RemoveSummary {
                leaf,
                pseudonym: pre.key_of(leaf).unwrap_or([0u8; 32]),
            }
        })
        .collect();
    let removed_keys: Vec<[u8; 32]> = removes.iter().map(|r| r.pseudonym).collect();
    let mut canonical_kps: Vec<Option<CanonicalKeyPackage>> = Vec::new();
    let mut adds: Vec<AddSummary> = Vec::new();
    for a in sc.add_proposals() {
        let kp = a.add_proposal().key_package();
        let constant_lifetime = canonical::is_constant_lifetime(kp.life_time());
        let kp_ref = kp
            .hash_ref(crypto)
            .map(|r| r.as_slice().to_vec())
            .unwrap_or_default();
        let pseudonym: [u8; 32] = kp
            .leaf_node()
            .signature_key()
            .as_slice()
            .try_into()
            .unwrap_or([0u8; 32]);
        let checked = canonical::check_key_package(kp);
        let bytes_ok = kp_bytes(kp).filter(|b| b.len() == crate::join::KEY_PACKAGE_LEN);
        let canonical_kp = match (&checked, bytes_ok) {
            (Ok((facts, bind)), Some(b)) => Some(CanonicalKeyPackage {
                key_package: kp.clone(),
                bytes: b,
                kp_ref: kp_ref.clone(),
                pseudonym: facts.signature_key,
                box_pk: facts.leaf.box_pk,
                bind: *bind,
            }),
            _ => None,
        };
        if !constant_lifetime {
            fault(CommitReason::NonCanonicalLeaf);
        }
        if canonical_kp.is_none() {
            fault(CommitReason::NonCanonicalLeaf);
        }
        adds.push(AddSummary {
            kp_ref,
            pseudonym,
            bind: checked.as_ref().ok().map(|(_, b)| *b),
            box_pk: checked.as_ref().ok().map(|(f, _)| f.leaf.box_pk),
            constant_lifetime,
            canonical: canonical_kp.is_some(),
        });
        canonical_kps.push(canonical_kp);
    }

    // Joins and swaps, with their evidence (by KeyPackage reference, each entry used once).
    let mut joins = Vec::new();
    let mut swaps = Vec::new();
    let mut admits_used = vec![false; aad_v.admits.len()];
    let mut swaps_used = vec![false; aad_v.swaps.len()];
    let mut invite_ids: Vec<[u8; 16]> = Vec::new();
    for (a, kp) in adds.iter().zip(&canonical_kps) {
        if let Some(r) = removes.iter().find(|r| r.pseudonym == a.pseudonym) {
            // A swap: a Remove of leaf L and an Add of L's own pseudonym.
            let found = aad_v
                .swaps
                .iter()
                .enumerate()
                .find(|(i, s)| !swaps_used[*i] && s.kp_ref() == a.kp_ref.as_slice());
            let mut kind = None;
            match (found, kp) {
                (Some((i, ev)), Some(kp)) => {
                    swaps_used[i] = true;
                    kind = Some(match ev {
                        SwapEvidence::Rejoin { .. } => SwapKind::Rejoin,
                        SwapEvidence::Restore(_) => SwapKind::Restore,
                    });
                    let ok = verify_swap(channel_id, pre, &r.pseudonym, &removed_keys, ev, kp)
                        .is_ok()
                        && kp.bind.channel_id == *channel_id
                        && in_window(kp.bind.day, commit_day);
                    if !ok {
                        fault(CommitReason::Evidence);
                    }
                    if let SwapEvidence::Restore(e) = ev {
                        if invite_ids.contains(&e.invite_id) {
                            fault(CommitReason::Evidence);
                        }
                        invite_ids.push(e.invite_id);
                    }
                }
                _ => fault(CommitReason::Evidence),
            }
            swaps.push(SwapSummary {
                leaf: r.leaf,
                pseudonym: r.pseudonym,
                kind,
            });
        } else {
            // A join: a new pseudonym, admitted by an invite.
            if pre.is_member(&a.pseudonym) {
                fault(CommitReason::Evidence);
            }
            let found = aad_v
                .admits
                .iter()
                .enumerate()
                .find(|(i, e)| !admits_used[*i] && e.kp_ref == a.kp_ref);
            match (found, kp) {
                (Some((i, ev)), Some(kp)) => {
                    admits_used[i] = true;
                    let ok = kp.bind.purpose == Purpose::Join
                        && kp.bind.channel_id == *channel_id
                        && in_window(kp.bind.day, commit_day)
                        && verify_admit(channel_id, pre, &removed_keys, ev, kp).is_ok();
                    if !ok || invite_ids.contains(&ev.invite_id) {
                        fault(CommitReason::Evidence);
                    }
                    invite_ids.push(ev.invite_id);
                }
                _ => fault(CommitReason::Evidence),
            }
            joins.push(a.clone());
        }
    }
    // No evidence without its Add.
    if admits_used.iter().any(|u| !u) || swaps_used.iter().any(|u| !u) {
        fault(CommitReason::Evidence);
    }

    // The update path's leaf: canonical, keeps its member's identity, refresh_epoch = epoch.
    let update_leaf = match sc.update_path_leaf_node() {
        Some(leaf) => match canonical::check_leaf(leaf) {
            Ok(f) => {
                if f.signature_key != sender_key {
                    fault(CommitReason::Continuity);
                }
                if f.leaf.refresh_epoch != pre.epoch {
                    fault(CommitReason::RefreshEpoch);
                }
                Some(f)
            }
            Err(canonical::Fault::Credential) => {
                fault(CommitReason::Continuity);
                None
            }
            Err(_) => {
                fault(CommitReason::NonCanonicalLeaf);
                None
            }
        },
        None => {
            // A rank-255 commit is an empty commit *with* a path (CO-1).
            if rank == 255 {
                fault(CommitReason::Permission);
            }
            None
        }
    };

    // Removes by rank: a committer of rank r removes non-committers or committers of rank > r;
    // a swap may target any rank (§19.13).
    for r in &removes {
        if swaps.iter().any(|s| s.leaf == r.leaf) {
            continue;
        }
        let target = pre.context.rank_of(&r.pseudonym);
        if rank == 255 || (target != 255 && target <= rank) {
            fault(CommitReason::Permission);
        }
    }

    // The context after the commit.
    let new_ctx = sc
        .group_context()
        .extensions()
        .unknown(crate::ext::EXT_CHANNEL_CONTEXT)
        .and_then(|u| ChannelContext::decode(&u.0));
    let context = match &new_ctx {
        None => {
            fault(CommitReason::Context);
            None
        }
        Some(c) if *c == pre.context => None,
        Some(c) => {
            if rank != 0 && !is_allowed_drop(&pre.context, c, &sender_key, &removed_keys) {
                fault(CommitReason::Permission);
            }
            if c.check_password_change(&pre.context, rank).is_err() {
                fault(CommitReason::Context);
            }
            Some(c.clone())
        }
    };
    if let Some(c) = &new_ctx {
        let admits = !joins.is_empty() || swaps.iter().any(|s| s.kind == Some(SwapKind::Restore));
        let mut a = c.committers.clone();
        let mut b = pre.context.committers.clone();
        a.sort_unstable();
        b.sort_unstable();
        if admits && a != b {
            fault(CommitReason::CommittersChanged);
        }
        let mut leaves: Vec<[u8; 32]> = pre
            .members
            .iter()
            .map(|(_, k)| *k)
            .filter(|k| !removed_keys.contains(k))
            .collect();
        for a in &adds {
            leaves.push(a.pseudonym);
        }
        if c.check(channel_id, &leaves).is_err() {
            fault(CommitReason::Context);
        }
    }
    if bytes.len() > seal::capacity(floor) {
        fault(CommitReason::Size);
    }
    // Every HPKE key of the tree the commit produces — the update path's leaf and parent nodes,
    // the Adds' leaves — is a valid X25519 key (H1, §19.31): a low-order key would make every later
    // commit that encrypts to that node fail for everyone. Read from the staged tree, so every
    // member checks every node alike (a member can derive only the path keys above its own
    // subtree). A member the commit removes gets a public staged state whose tree OpenMLS 0.9.0
    // keeps crate-private: it checks the leaves (the Adds' KeyPackages and the path's leaf, above)
    // and not the parent nodes, which concerns only its own departure (§19.31).
    let pre_tree = pre.tree.clone().ok_or(MlsError::new(Code::Internal))?;
    if !sc.self_removed() {
        match sc.export_ratchet_tree(crypto, pre_tree) {
            Ok(Some(t)) if canonical::tree_keys_valid(&t) => {}
            _ => fault(CommitReason::NonCanonicalLeaf),
        }
    }
    // CO-14 (§6.4, §19.5): a rank-255 commit for epoch e only from a leaf whose `refresh_epoch`
    // before the commit is at most e − min(8, n), n the member count before the commit.
    let sender_refresh_epoch = pre.refresh_of(idx.u32());
    if rank == 255 {
        let k = pre.members.len().min(8) as u64;
        let within = sender_refresh_epoch
            .and_then(|r| r.checked_add(k))
            .is_some_and(|x| x <= pre.epoch);
        if !within {
            fault(CommitReason::Rate);
        }
    }

    let (_, _, rotates) = membership_change(pre, sc, &aad_v);
    // The first broken rule in a fixed order (the reason reported).
    let order = [
        CommitReason::Aad,
        CommitReason::Proposal,
        CommitReason::NonCanonicalLeaf,
        CommitReason::Continuity,
        CommitReason::RefreshEpoch,
        CommitReason::Evidence,
        CommitReason::CommittersChanged,
        CommitReason::Permission,
        CommitReason::Rate,
        CommitReason::Context,
        CommitReason::Size,
    ];
    let verdict = match order.iter().find(|r| faults.contains(r)) {
        Some(r) => Err(*r),
        None => Ok(()),
    };
    Ok(CommitSummary {
        hash: Sha256::digest(bytes).into(),
        size: bytes.len(),
        epoch: pre.epoch,
        sender_leaf: idx.u32(),
        sender: sender_key,
        rank,
        aad,
        joins,
        removes,
        swaps,
        context,
        rotates,
        update_leaf,
        sender_refresh_epoch,
        members: pre.members.len(),
        epoch_authenticator: sc.epoch_authenticator().map(|a| a.as_slice().to_vec()),
        verdict,
    })
}

/// A context change a committer of rank ≥ 1 may make (CO-2, §19.13): only drops from `committers`
/// and `funders` of keys its commit removes, or of its own key (a resignation), every other field
/// unchanged and `committers` non-empty.
fn is_allowed_drop(
    prev: &ChannelContext,
    next: &ChannelContext,
    sender: &[u8; 32],
    removed: &[[u8; 32]],
) -> bool {
    let droppable = |k: &[u8; 32]| removed.contains(k) || k == sender;
    let mut expect = prev.clone();
    let dropped_c: Vec<[u8; 32]> = prev
        .committers
        .iter()
        .filter(|k| !next.committers.contains(k))
        .copied()
        .collect();
    let dropped_f: Vec<[u8; 32]> = prev
        .funders
        .iter()
        .filter(|k| !next.funders.contains(k))
        .copied()
        .collect();
    if !dropped_c.iter().chain(&dropped_f).all(droppable) {
        return false;
    }
    expect.committers.retain(|k| !dropped_c.contains(k));
    expect.funders.retain(|k| !dropped_f.contains(k));
    !expect.committers.is_empty() && expect == *next
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_admission_window() {
        assert!(in_window(100, 100));
        assert!(in_window(93, 100));
        assert!(!in_window(92, 100));
        assert!(in_window(103, 100));
        assert!(!in_window(104, 100));
        assert!(in_window(0, 3));
    }

    fn ctx(committers: Vec<[u8; 32]>, funders: Vec<[u8; 32]>) -> ChannelContext {
        ChannelContext {
            channel_id: [1; 32],
            size_class: 0,
            timer_code: 4,
            timer_version: 0,
            history_policy: 0,
            flags: 1,
            idle_evict_days: 63,
            pw_version: 0,
            name: vec![],
            committers,
            funders,
        }
    }

    #[test]
    fn drops_a_moderator_may_make() {
        let (o, m, x) = ([1u8; 32], [2u8; 32], [3u8; 32]);
        let prev = ctx(vec![o, m, x], vec![o, x]);
        // Resignation: its own key.
        assert!(is_allowed_drop(
            &prev,
            &ctx(vec![o, x], vec![o, x]),
            &m,
            &[]
        ));
        // The key of a pseudonym the commit removes, from both lists.
        assert!(is_allowed_drop(&prev, &ctx(vec![o, m], vec![o]), &m, &[x]));
        // Not another committer's key, not a reorder, not another field.
        assert!(!is_allowed_drop(
            &prev,
            &ctx(vec![m, x], vec![o, x]),
            &m,
            &[]
        ));
        assert!(!is_allowed_drop(
            &prev,
            &ctx(vec![m, o, x], vec![o, x]),
            &m,
            &[]
        ));
        let mut renamed = prev.clone();
        renamed.name = b"n".to_vec();
        assert!(!is_allowed_drop(&prev, &renamed, &m, &[]));
        // Never an empty committers list.
        let solo = ctx(vec![m], vec![]);
        assert!(!is_allowed_drop(&solo, &ctx(vec![], vec![]), &m, &[]));
    }
}
