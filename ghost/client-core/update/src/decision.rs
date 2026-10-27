//! The trust-epoch rule (§7.4 step 0) and the bundle acceptance (steps 1–7).

use std::collections::HashSet;

use ghost_client_release::bundle::GHRB;
use ghost_client_release::manifest::GHRM;
use ghost_client_release::proof::{GHRP, leaf_hash};
use ghost_client_release::root::{GHRT, Network};
use ghost_client_release::{check_inclusion, key_id, sha256_of};
use sha2::{Digest, Sha256};

use crate::state::{ChannelStatus, Floor, Pair, PersistedChange, StoredState, Time, TrustEpoch};
use crate::UpdateError;

const SIGMA_PLUS_DAY_SECS: u64 = 4 * 86_400;

fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// The result of one acceptance run: the facts to persist (already reflecting a verified newer
/// root, even when the manifest was refused), the channel status and the directory changes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptOutcome {
    pub state: StoredState,
    pub status: ChannelStatus,
    pub changes: Vec<PersistedChange>,
    /// `Some` when the manifest was not accepted this run: `ROLLBACK`, `UNCHANGED`, `CONFLICT`,
    /// `NOT_YET_VALID`, or a refusal after a verified newer root (which is still persisted).
    pub refused: Option<UpdateError>,
}

/// §7.4 step 0: establish or continue the trust epoch for the installed `versionCode`.
/// `embedded` is the whole committed embedded chain of this APK's lineage (never truncated,
/// G-D4); `stored` is the state of the previous installed version, if any.
pub fn start_epoch(
    installed_vc: u32,
    embedded: Vec<GHRT>,
    stored: Option<StoredState>,
) -> StoredState {
    match stored {
        None => fresh_epoch(installed_vc, embedded),
        Some(s) if s.epoch.version_code == installed_vc => s,
        Some(mut s) => {
            let (e_version, e_bytes) = {
                let e = embedded.last().expect("embedded chain is never empty");
                (e.body.root_version, e.to_bytes())
            };
            let t_bytes = s.trusted_root().to_bytes();
            let same_lineage = s.chain.iter().any(|r| r.to_bytes() == e_bytes)
                || embedded.iter().any(|r| r.to_bytes() == t_bytes);
            if same_lineage {
                // One lineage: the trusted root becomes the newer of E and S; the stored chain
                // extends to E if E is newer.
                s.epoch.version_code = installed_vc;
                if e_version > s.trusted_root().body.root_version {
                    s.chain = embedded;
                }
                s
            } else {
                // A recovery APK: a new trust epoch from the embedded chain.
                fresh_epoch(installed_vc, embedded)
            }
        }
    }
}

fn fresh_epoch(installed_vc: u32, embedded: Vec<GHRT>) -> StoredState {
    let (e_version, e_id) = {
        let e = embedded.last().expect("embedded chain is never empty");
        (e.body.root_version, sha256(&e.to_bytes()))
    };
    StoredState {
        epoch: TrustEpoch { id: e_id, version_code: installed_vc },
        chain: embedded,
        pair: Pair { root_version: e_version, manifest_seq: 0 },
        manifest: None,
        manifest_proof: None,
        manifest_sha256: None,
        floor: Floor { version_code: 0, root_version: e_version },
        conflict: false,
        root_conflict: false,
    }
}

/// §7.4 steps 1–7. `network` is the app's network byte; `time` must be trusted (with an
/// untrusted clock nothing changes and `CLOCK_UNTRUSTED` comes back before any parse).
pub fn accept_bundle(
    bundle_bytes: &[u8],
    state: &StoredState,
    network: u8,
    time: Time,
) -> Result<AcceptOutcome, UpdateError> {
    let (today, now) = match time {
        Time::Trusted { day, now_secs } => (day, now_secs),
        Time::Untrusted => return Err(UpdateError::ClockUntrusted),
    };
    Network::from_u8(network).map_err(|_| UpdateError::WrongNetwork)?;

    // Step 1: parse within bounds; the network must be the app's.
    let bundle = GHRB::parse(bundle_bytes).map_err(UpdateError::from)?;
    if bundle.network != network {
        return Err(UpdateError::WrongNetwork);
    }
    let manifest_bytes = bundle.manifest.body_bytes_with_block();

    // Step 2: the root chain. R is the newest root reached; a verified newer root is adopted
    // even if a later step refuses the manifest.
    let t_version = state.trusted_root().body.root_version;
    let chain = &bundle.chain;
    let mut root_conflict = state.root_conflict;
    // Entries at or below T.version are compared with the stored chain.
    for root in &chain.roots {
        if root.body.root_version > t_version {
            break;
        }
        let Some(stored_root) = state
            .chain
            .iter()
            .find(|r| r.body.root_version == root.body.root_version)
        else {
            continue;
        };
        if stored_root.to_bytes() != root.to_bytes() {
            // A differing root at the same version: equivocation evidence only if it verifies
            // by the chain rule from its stored predecessor; otherwise it is ignored.
            if let Some(pred) = state
                .chain
                .iter()
                .find(|r| r.body.root_version + 1 == root.body.root_version)
            {
                if root.verify_block(&pred.body.root.keys, pred.body.root.threshold).is_ok() {
                    root_conflict = true;
                }
            }
        }
    }
    // Walk the new roots from T.version + 1, applying the chain rule with its logging clause.
    // `root_proofs[j-1]` is the proof of `chain.roots[j]` (one proof per entry after the first).
    // A failure stops the walk and is reported; the last good root is kept (§7.4 step 2).
    let mut adopted: Vec<GHRT> = state.chain.clone();
    let mut step2_report: Option<UpdateError> = if chain.first_version > t_version + 1 {
        Some(UpdateError::RootChainBroken)
    } else {
        None
    };
    if step2_report.is_none() {
        for j in 0..chain.roots.len() {
        let root = &chain.roots[j];
        if root.body.root_version <= t_version {
            continue;
        }
        let prev = adopted.last().expect("adopted is never empty");
        if root.verify_block(&prev.body.root.keys, prev.body.root.threshold).is_err() {
            step2_report = Some(UpdateError::RootChainBroken);
            break;
        }
        let Some(proof) = bundle.root_proofs.get(j.wrapping_sub(1)) else {
            step2_report = Some(UpdateError::RootUnlogged);
            break;
        };
        // The logging clause: the proof sits under the previous root's policy, and the leaf was
        // signed by a root or release key of the previous root.
        if verify_proof(proof, &root.to_bytes(), prev, now, true).is_err() {
            step2_report = Some(UpdateError::RootUnlogged);
            break;
        }
        adopted.push(root.clone());
        }
    }
    let newest = adopted.last().expect("adopted is never empty").clone();

    let mut base = state.clone();
    base.chain = adopted;
    base.root_conflict = root_conflict;
    let (state, status, changes, mut refused) = accept_manifest(
        &bundle.manifest,
        &manifest_bytes,
        &bundle.manifest_proof,
        &newest,
        &base,
        today,
        now,
    );
    if refused.is_none() {
        refused = step2_report;
    }
    Ok(AcceptOutcome { state, status, changes, refused })
}

fn accept_manifest(
    m: &GHRM,
    manifest_bytes: &[u8],
    proof: &GHRP,
    r: &GHRT,
    base: &StoredState,
    today: u32,
    now: u64,
) -> (StoredState, ChannelStatus, Vec<PersistedChange>, Option<UpdateError>) {
    let mut new_state = base.clone();

    // Step 3: the manifest names R and verifies under R's release keyset.
    if m.body.root_version != r.body.root_version
        || m.body.root_sha256 != sha256_of(&r.to_bytes())
    {
        return refuse(new_state, base, UpdateError::RootMismatch);
    }
    if m.verify_block(&r.body.release.keys, r.body.release.threshold).is_err() {
        return refuse(new_state, base, UpdateError::BadSignature);
    }
    // No extra mirror may equal an anchor mirror (the rest of MALFORMED is parse-level).
    for (onion, _) in &m.body.extra_mirrors {
        if r.body.anchor_mirrors.iter().any(|a| a.onion == *onion) {
            return refuse(new_state, base, UpdateError::Malformed);
        }
    }
    // The floor bound: no higher than the highest flavor-1 release whose attestation meets
    // (R.attest.keys, R.attest.t) — with threshold 0 every flavor-1 release counts.
    let attested_max = m
        .body
        .releases
        .iter()
        .enumerate()
        .filter(|(i, _)| {
            m.attestations.get(*i).is_some_and(|at| {
                at.meets(
                    &r.body.attest.keys,
                    r.body.attest.threshold,
                    &ghost_client_release::statement_bytes(
                        ghost_client_release::StatementType::BuildAttestation,
                        m.body.network,
                        &m.body.releases[*i].attestation(m.body.network).to_bytes(),
                    ),
                )
                .is_ok()
            })
        })
        .map(|(_, rel)| rel.version_code)
        .max()
        .unwrap_or(0);
    if m.body.floor_version_code > attested_max {
        return refuse(new_state, base, UpdateError::FloorInvalid);
    }

    // Step 4: the log proof under R's policy.
    if let Err(e) = verify_proof(proof, manifest_bytes, r, now, false) {
        return refuse(new_state, base, e);
    }

    // Step 5: time.
    if m.body.issued_day > today + 4 {
        return refuse(new_state, base, UpdateError::NotYetValid);
    }
    // MC-D8 (the `mutants` feature, host libraries only): the not-after day is ignored and an
    // expired manifest is treated as fresh. The selector's default keeps the shipped test.
    #[cfg(feature = "mutants")]
    let expiry_enforced = !crate::mutants::active(crate::mutants::EXPIRY_IGNORED);
    #[cfg(not(feature = "mutants"))]
    let expiry_enforced = true;
    let fresh = expiry_enforced && today <= m.body.not_after_day;

    // Step 6: the pair.
    let pair = Pair { root_version: m.body.root_version, manifest_seq: m.body.manifest_seq };
    let stored_pair = base.pair;
    // MC-D6 (the `mutants` feature, host libraries only): a lower pair is accepted — the
    // Rollback refusal is skipped. The selector's default keeps the shipped check.
    #[cfg(feature = "mutants")]
    let lower_pair_refused = !crate::mutants::active(crate::mutants::LOWER_PAIR_ACCEPTED);
    #[cfg(not(feature = "mutants"))]
    let lower_pair_refused = true;
    if pair < stored_pair && lower_pair_refused {
        return refuse(new_state, base, UpdateError::Rollback);
    }
    let hash = sha256(manifest_bytes);
    // Same pair, different hash: equivocation evidence, kept for this root version. MC-D7 (the
    // `mutants` feature, host libraries only): the equal-pair block is skipped and the
    // equivocating manifest is accepted over the stored one.
    #[cfg(feature = "mutants")]
    let equal_pair_checked = !crate::mutants::active(crate::mutants::EQUAL_PAIR_ACCEPTED);
    #[cfg(not(feature = "mutants"))]
    let equal_pair_checked = true;
    if pair == stored_pair && equal_pair_checked {
        if base.manifest_sha256 == Some(hash) {
            return refuse(new_state, base, UpdateError::Unchanged);
        }
        let (mut st, status, ch, rf) = refuse(new_state, base, UpdateError::Conflict);
        st.conflict = true;
        return (st, status, ch, rf);
    }

    // Step 7: accept. Persist the manifest, the pair and hash, the floor and the conflict flag's
    // root-version scope.
    new_state.pair = pair;
    new_state.manifest = Some(m.clone());
    new_state.manifest_proof = Some(proof.clone());
    new_state.manifest_sha256 = Some(hash);
    // MC-D17 (the `mutants` feature, host libraries only): a manifest lowers the floor within
    // its root version — `min` replaces `max`. The selector's default keeps the shipped rule.
    #[cfg(feature = "mutants")]
    let floor_merge = if crate::mutants::active(crate::mutants::FLOOR_LOWERED) {
        base.floor.version_code.min(m.body.floor_version_code)
    } else {
        base.floor.version_code.max(m.body.floor_version_code)
    };
    #[cfg(not(feature = "mutants"))]
    let floor_merge = base.floor.version_code.max(m.body.floor_version_code);
    new_state.floor = if m.body.root_version == base.floor.root_version {
        Floor {
            version_code: floor_merge,
            root_version: base.floor.root_version,
        }
    } else {
        Floor { version_code: m.body.floor_version_code, root_version: m.body.root_version }
    };
    if m.body.root_version != base.pair.root_version {
        new_state.conflict = false;
    }
    let (status, changes) = if fresh {
        let mut changes: Vec<PersistedChange> = m
            .body
            .relays
            .iter()
            .map(|(o, op)| PersistedChange::RelayUpsert(o.clone(), *op))
            .collect();
        changes.push(PersistedChange::MirrorsFromManifest(m.body.extra_mirrors.clone()));
        (ChannelStatus::Current, changes)
    } else {
        // An expired manifest is accepted as a fact but contributes no directory and no mirror.
        (ChannelStatus::Stale, vec![])
    };
    (new_state, status, changes, None)
}

fn refuse(
    mut new_state: StoredState,
    base: &StoredState,
    code: UpdateError,
) -> (StoredState, ChannelStatus, Vec<PersistedChange>, Option<UpdateError>) {
    // The manifest and pair stay as they were; the chain/root adoption stays (its key removals
    // take effect at once). The old manifest is current only while it names the trusted root.
    new_state.pair = base.pair;
    new_state.manifest = base.manifest.clone();
    new_state.manifest_proof = base.manifest_proof.clone();
    new_state.manifest_sha256 = base.manifest_sha256;
    new_state.floor = base.floor;
    new_state.conflict = base.conflict;
    let status = if base
        .manifest
        .as_ref()
        .is_some_and(|m| m.body.root_version == new_state.trusted_root().body.root_version)
    {
        ChannelStatus::Current
    } else {
        ChannelStatus::NoManifest
    };
    (new_state, status, vec![], Some(code))
}

/// The §4.7 proof check under a policy root. `root_leaf` widens the leaf-signer set to the
/// policy root's own keyset (the chain rule's logging clause); the manifest proof uses the
/// release keyset only. Returns `LOG_PROOF_INVALID` or `QUORUM_NOT_MET`.
fn verify_proof(
    p: &GHRP,
    file: &[u8],
    policy: &GHRT,
    now: u64,
    root_leaf: bool,
) -> Result<(), UpdateError> {
    if p.message != sha256(file) {
        return Err(UpdateError::LogProofInvalid);
    }
    let signer = if root_leaf {
        policy
            .body
            .release
            .keys
            .iter()
            .chain(policy.body.root.keys.iter())
            .find(|k| key_id(k) == p.leaf_key_id)
    } else {
        policy.body.release.keys.iter().find(|k| key_id(k) == p.leaf_key_id)
    };
    let signer = signer.ok_or(UpdateError::LogProofInvalid)?;
    if p.verify_leaf(file, signer).is_err() {
        return Err(UpdateError::LogProofInvalid);
    }
    let log = policy
        .body
        .logs
        .get(p.log as usize)
        .ok_or(UpdateError::LogProofInvalid)?;
    if p.verify_log_signature(&log.pk).is_err() {
        return Err(UpdateError::LogProofInvalid);
    }
    if check_inclusion(leaf_hash(&p.leaf(file)), p.leaf_index, &p.path, &p.root_hash).is_err() {
        return Err(UpdateError::LogProofInvalid);
    }
    let mut good = 0usize;
    let mut seen: HashSet<[u8; 32]> = HashSet::new();
    for c in &p.cosignatures {
        if c.time > now + SIGMA_PLUS_DAY_SECS {
            return Err(UpdateError::LogProofInvalid);
        }
        if seen.contains(&c.witness_key_id) {
            continue;
        }
        if let Some(w) = policy
            .body
            .witnesses
            .iter()
            .find(|w| key_id(w) == c.witness_key_id)
        {
            if p.verify_cosignature(c, w, &log.pk).is_ok() {
                seen.insert(c.witness_key_id);
                good += 1;
            }
        }
    }
    if good < policy.body.quorum {
        return Err(UpdateError::QuorumNotMet);
    }
    Ok(())
}
