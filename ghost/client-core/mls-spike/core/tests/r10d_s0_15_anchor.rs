//! Round 10d, targeted protocol review of S0-15, the committers anchor (design §19.27, findings
//! TR-4 … TR-7): a committer that leaves the set is the only party that can still answer the
//! invites its departure voided; a rejoiner's anchor can be a committer removed since; the
//! transfer of rank 0 voids invites under an ordered digest; and the anchor can be checked on the
//! unverified GroupInfo before `JoinBuilder::build()` validates the whole ratchet tree.
//!
//! Run: `cargo test --release -p ghost-mls-spike --test r10d_s0_15_anchor -- --nocapture --test-threads=1`

use std::time::Instant;

use ghost_mls_spike::ext::{self, ChannelContext, CommitAad};
use ghost_mls_spike::harness::*;
use ghost_mls_spike::kv::Scope;
use openmls::prelude::tls_codec::Deserialize as _;
use openmls::prelude::*;
use sha2::{Digest, Sha256};

/// S0-15's digest: over the committers **in order**.
fn digest_ordered(channel: &[u8; 32], committers: &[[u8; 32]]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"ghost/v1/ch/committers");
    h.update(channel);
    h.update([u8::try_from(committers.len()).unwrap()]);
    for c in committers {
        h.update(c);
    }
    h.finalize().into()
}

/// The review's correction (TR-6): the same digest over the committers **sorted bytewise**.
fn digest_set(channel: &[u8; 32], committers: &[[u8; 32]]) -> [u8; 32] {
    let mut s = committers.to_vec();
    s.sort();
    digest_ordered(channel, &s)
}

fn aad(day: u32) -> CommitAad {
    CommitAad {
        commit_minute: day * 1440,
        ..Default::default()
    }
}

/// The context of the group and the GroupInfo signer's key, after `JoinBuilder::build()`, in a dry
/// call over `rows` (so nothing is written); `rows` is the joiner's (for a rejoin: only its global
/// rows, design §6.2.5).
fn inspect_welcome(
    j: &mut Device,
    ch: [u8; 32],
    welcome: &[u8],
) -> Result<(ChannelContext, [u8; 32]), String> {
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
        Ok::<_, String>((ctx, signer))
    })
    .map(|(v, _)| v)
}

/// The joiner's anchor for a join or restore (S0-15): the joined context's committers hash to the
/// invite's digest and the GroupInfo signer is one of them.
fn join_anchor(
    ch: &[u8; 32],
    invite_digest: &[u8; 32],
    ctx: &ChannelContext,
    signer: &[u8; 32],
) -> Result<(), &'static str> {
    if &ctx.channel_id != ch {
        return Err("channel_id");
    }
    if &digest_ordered(ch, &ctx.committers) != invite_digest {
        return Err("committers digest differs from the invite's");
    }
    if !ctx.committers.contains(signer) {
        return Err("GroupInfo signer is not a committer");
    }
    Ok(())
}

/// A context with the given committers (and the first of them as the only funder).
fn ctx_with(ch: [u8; 32], committers: Vec<[u8; 32]>) -> ChannelContext {
    let mut c = ChannelContext::initial(ch, committers[0], 0);
    c.funders = vec![committers[0]];
    c.committers = committers;
    c
}

/// A group of the forger's own under the real channel id, with `committers` in its context and the
/// forger as its only member; the joiner's KeyPackage is added and the forged Welcome returned.
fn forged_welcome(
    forger: &mut Device,
    ch: [u8; 32],
    committers: Vec<[u8; 32]>,
    kp_bytes: &[u8],
    day: u32,
) -> Vec<u8> {
    forger.rows.clear(); // a removed member deletes its MLS state; the forger starts from nothing
    forger
        .create_group(ch, &ctx_with(ch, committers))
        .expect("the forger's group");
    let kp = forger
        .parse_key_package(kp_bytes)
        .expect("the joiner's KeyPackage");
    let e = forger.epoch(ch);
    let out = forger
        .commit(
            ch,
            &CommitSpec {
                adds: vec![kp],
                aad: aad(day),
                refresh_epoch: Some(e),
                force_path: true,
                no_exported_group_info: true,
                ..Default::default()
            },
        )
        .expect("forged Add");
    out.welcome.expect("forged Welcome")
}

/// World of three: owner (rank 0), member 1 made a moderator (rank 1), member 2.
fn world_with_moderator(day: u32) -> (World, [u8; 32], [u8; 32]) {
    let mut w = World::build(3, 2, day);
    let ch = w.channel;
    let owner = w.members[0].pk;
    let moderator = w.members[1].pk;
    let e = w.members[0].epoch(ch);
    w.commit_and_merge(
        0,
        &CommitSpec {
            context: Some(ctx_with(ch, vec![owner, moderator])),
            aad: aad(day),
            refresh_epoch: Some(e),
            force_path: true,
            no_exported_group_info: true,
            ..Default::default()
        },
    )
    .expect("the owner names a moderator");
    (w, owner, moderator)
}

/// The owner removes the moderator: the Remove and the drop of its key in one commit (§5.7's
/// unit). `skip` members do not process it (offline); the removed moderator is left out too.
fn remove_moderator(w: &mut World, owner: [u8; 32], skip: &[usize]) {
    let ch = w.channel;
    let day = w.day;
    let leaf = w.members[1].leaf_index(ch);
    let e = w.members[0].epoch(ch);
    let out = w.members[0]
        .commit(
            ch,
            &CommitSpec {
                removes: vec![LeafNodeIndex::new(leaf)],
                context: Some(ctx_with(ch, vec![owner])),
                aad: aad(day),
                refresh_epoch: Some(e),
                force_path: true,
                no_exported_group_info: true,
                ..Default::default()
            },
        )
        .expect("remove the moderator");
    for i in 2..w.members.len() {
        if !skip.contains(&i) {
            w.members[i]
                .receive(ch, &out.commit)
                .expect("members merge the removal");
        }
    }
    w.members[0].merge_own(ch).unwrap();
}

/// TR-4: after the moderator's removal the real committers void the invite (the digest of the new
/// committers differs), so they never admit its join request; the removed moderator, whose key the
/// invite still names, builds a group of its own and the invitee's anchor accepts that Welcome.
#[test]
fn r10d_removed_committer_answers_the_invites_it_voided() {
    let day = host_day();
    let (mut w, owner, moderator) = world_with_moderator(day);
    let ch = w.channel;
    // The invite is issued now: its digest names [owner, moderator].
    let invite_digest = digest_ordered(&ch, &[owner, moderator]);
    let mut j = Device::new(90, day);
    let kp = j.key_package(ch, 1, day, 0).unwrap();
    // The owner removes the moderator (every other member merges it).
    remove_moderator(&mut w, owner, &[]);
    let now_digest = digest_ordered(&ch, &[owner]);
    println!(
        "R10d TR-4 after the removal the real committers' digest {} the invite's -> CO-5 voids it and (B) never admits it",
        if now_digest == invite_digest { "EQUALS" } else { "differs from" }
    );
    assert_ne!(now_digest, invite_digest);
    // The removed moderator (it held JK_g of the generation the invite names) forges the Welcome.
    let forged = forged_welcome(&mut w.members[1], ch, vec![owner, moderator], &kp, day);
    let (ctx, signer) = inspect_welcome(&mut j, ch, &forged).expect("OpenMLS accepts the forgery");
    let verdict = join_anchor(&ch, &invite_digest, &ctx, &signer);
    println!(
        "R10d TR-4 the removed moderator's own group: signer is the moderator {}, anchor -> {verdict:?} (the invitee is captured)",
        signer == moderator
    );
    assert_eq!(verdict, Ok(()));
    // The joiner applies it (nothing distinguishes it) and its KeyPackage is consumed.
    j.join(ch, &forged, true).expect("captured");
    // A fresh invite from the sponsor names the new committers: its digest differs from the digest
    // of the group the joiner now holds, which is what the correction's ANCHOR_CONFLICT detects.
    let held = digest_ordered(&ch, &ctx.committers);
    println!(
        "R10d TR-4 re-invite: new invite digest == digest of the joined group's committers? {} (ANCHOR_CONFLICT when not)",
        held == now_digest
    );
    assert_ne!(held, now_digest);
}

/// TR-5: a member offline across the moderator's removal rejoins later; its anchor is the
/// committers of its last final epoch, which still name the removed moderator.
#[test]
fn r10d_stale_rejoin_anchor() {
    let day = host_day();
    let (mut w, owner, moderator) = world_with_moderator(day);
    let ch = w.channel;
    // Member 2 is offline across the removal.
    remove_moderator(&mut w, owner, &[2]);
    let last_committers = [owner, moderator]; // member 2's last final epoch
                                              // Member 2's rejoin KeyPackage (purpose 2), sealed into the generation it still listens to,
                                              // whose join key the removed moderator holds.
    let kp = w.members[2].key_package(ch, 2, day, 0).unwrap();
    let forged = forged_welcome(&mut w.members[1], ch, vec![owner, moderator], &kp, day);
    // welcomeJoin for a rejoin gets only the KeyPackage's global rows (§6.2.5).
    let mut view = Device::new(91, day);
    view.rows = w.members[2]
        .rows
        .iter()
        .filter(|((s, _), _)| *s == Scope::Global)
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    let (_ctx, signer) =
        inspect_welcome(&mut view, ch, &forged).expect("OpenMLS accepts the forgery");
    let passes = last_committers.contains(&signer);
    println!(
        "R10d TR-5 rejoin Welcome forged by the removed moderator: signer among the rejoiner's last committers -> {passes} (captured)"
    );
    assert!(passes);
}

/// TR-6: the transfer of rank 0 reorders `committers`; an ordered digest changes (every outstanding
/// invite is voided) although the set of keys that may sign a Welcome is the same; a set digest
/// does not change. The anchor needs only the set.
#[test]
fn r10d_transfer_of_rank_0_and_the_digest() {
    let ch = [5u8; 32];
    let a = [1u8; 32];
    let b = [2u8; 32];
    let ordered_changes = digest_ordered(&ch, &[a, b]) != digest_ordered(&ch, &[b, a]);
    let set_changes = digest_set(&ch, &[a, b]) != digest_set(&ch, &[b, a]);
    println!("R10d TR-6 transfer of rank 0: ordered digest changes {ordered_changes}; set digest changes {set_changes}");
    assert!(ordered_changes && !set_changes);
    assert_ne!(digest_set(&ch, &[a, b]), digest_set(&ch, &[a]));
}

/// The pre-check of TR-7: after `ProcessedWelcome::new_from_welcome` (HPKE open of the group
/// secrets, AEAD open of the GroupInfo; no tree validation), read the unverified context, compare
/// the committers digest, and verify the GroupInfo signature under each anchored committer key
/// (`Verifiable::verify_no_out`, public). Returns which step refused.
fn precheck(j: &mut Device, ch: [u8; 32], welcome: &[u8], anchor: &[u8; 32]) -> Result<(), String> {
    j.dry_call(&ch, |p, _| {
        let m = MlsMessageIn::tls_deserialize_exact(welcome).map_err(|e| format!("{e:?}"))?;
        let w = match m.extract() {
            MlsMessageBodyIn::Welcome(w) => w,
            _ => return Err("not a welcome".to_string()),
        };
        let pw = ProcessedWelcome::new_from_welcome(p, &join_config(), w)
            .map_err(|e| format!("{e:?}"))?;
        let gi = pw.unverified_group_info();
        let ctx = gi
            .group_context()
            .extensions()
            .unknown(ext::EXT_CHANNEL_CONTEXT)
            .and_then(|u| ChannelContext::decode(&u.0))
            .ok_or("no GhostChannelContext")?;
        if &digest_ordered(&ch, &ctx.committers) != anchor {
            return Err("digest".to_string());
        }
        for c in &ctx.committers {
            let pk = OpenMlsSignaturePublicKey::new(c.to_vec().into(), SignatureScheme::ED25519)
                .map_err(|e| format!("{e:?}"))?;
            if gi.verify_no_out(p.crypto(), &pk).is_ok() {
                return Ok(());
            }
        }
        Err("GroupInfo not signed by an anchored committer".to_string())
    })
    .map(|(v, _)| v)
}

/// The anchor after the full `JoinBuilder::build()` (S0-15 as written).
fn full_check(
    j: &mut Device,
    ch: [u8; 32],
    welcome: &[u8],
    anchor: &[u8; 32],
) -> Result<(), String> {
    let (ctx, signer) = inspect_welcome(j, ch, welcome)?;
    join_anchor(&ch, anchor, &ctx, &signer).map_err(str::to_string)
}

fn median_ms(mut v: Vec<f64>) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[v.len() / 2]
}

/// A forger's group of `n` members (itself and puppets) under the real channel id with the real
/// committers list copied, then the joiner's Add: a forged Welcome of the real one's size.
fn forged_welcome_n(
    ch: [u8; 32],
    committers: Vec<[u8; 32]>,
    n: usize,
    kp_bytes: &[u8],
    day: u32,
) -> Vec<u8> {
    let mut f = Device::new(500, day);
    f.create_group(ch, &ctx_with(ch, committers)).unwrap();
    let mut puppets: Vec<KeyPackage> = Vec::new();
    for i in 1..n {
        let mut d = Device::new(500 + i, day);
        let b = d.key_package(ch, 1, day, 0).unwrap();
        puppets.push(f.parse_key_package(&b).unwrap());
    }
    let e = f.epoch(ch);
    f.commit(
        ch,
        &CommitSpec {
            adds: puppets,
            aad: aad(day),
            refresh_epoch: Some(e),
            force_path: true,
            no_exported_group_info: true,
            ..Default::default()
        },
    )
    .unwrap();
    f.merge_own(ch).unwrap();
    let kp = f.parse_key_package(kp_bytes).unwrap();
    let e = f.epoch(ch);
    f.commit(
        ch,
        &CommitSpec {
            adds: vec![kp],
            aad: aad(day),
            refresh_epoch: Some(e),
            force_path: true,
            no_exported_group_info: true,
            ..Default::default()
        },
    )
    .unwrap()
    .welcome
    .unwrap()
}

/// TR-7: the cost of refusing a non-committer's forged Welcome with the pre-check versus after the
/// full tree validation, at the class caps (blank trees), and the pre-check on the real Welcome.
#[test]
fn r10d_anchor_precheck_cost() {
    let day = host_day();
    for n in [32usize, 100] {
        let mut w = World::build(n, n - 1, day);
        let ch = w.channel;
        let owner = w.members[0].pk;
        let anchor = digest_ordered(&ch, &[owner]);
        let mut j = Device::new(900, day);
        let kp = j.key_package(ch, 1, day, 0).unwrap();
        let forged = forged_welcome_n(ch, vec![owner], n, &kp, day);
        let kpp = w.members[0].parse_key_package(&kp).unwrap();
        let e = w.members[0].epoch(ch);
        let real = w.members[0]
            .commit(
                ch,
                &CommitSpec {
                    adds: vec![kpp],
                    aad: aad(day),
                    refresh_epoch: Some(e),
                    force_path: true,
                    no_exported_group_info: true,
                    ..Default::default()
                },
            )
            .unwrap()
            .welcome
            .unwrap();
        w.members[0].clear_own(ch).unwrap();
        let (mut pre_f, mut full_f, mut pre_r, mut full_r) = (vec![], vec![], vec![], vec![]);
        for _ in 0..9 {
            let t = Instant::now();
            let r = precheck(&mut j, ch, &forged, &anchor);
            pre_f.push(t.elapsed().as_secs_f64() * 1e3);
            // (the harness renders the closure's error with `{:?}`)
            assert!(
                r.as_ref()
                    .unwrap_err()
                    .contains("GroupInfo not signed by an anchored committer"),
                "{r:?}"
            );
            let t = Instant::now();
            let r = full_check(&mut j, ch, &forged, &anchor);
            full_f.push(t.elapsed().as_secs_f64() * 1e3);
            assert!(r.is_err());
            let t = Instant::now();
            assert_eq!(precheck(&mut j, ch, &real, &anchor), Ok(()));
            pre_r.push(t.elapsed().as_secs_f64() * 1e3);
            let t = Instant::now();
            assert_eq!(full_check(&mut j, ch, &real, &anchor), Ok(()));
            full_r.push(t.elapsed().as_secs_f64() * 1e3);
        }
        println!(
            "R10d TR-7 n={n}: forged Welcome {} B, real {} B; refusing the forgery: pre-check {:.2} ms vs full build {:.2} ms (medians of 9); real Welcome: pre-check {:.2} ms, full build {:.2} ms",
            forged.len(),
            real.len(),
            median_ms(pre_f),
            median_ms(full_f),
            median_ms(pre_r),
            median_ms(full_r)
        );
        // Nothing was written by any of the dry calls: the joiner still holds its KeyPackage.
        let kp_rows = j
            .rows
            .keys()
            .filter(|(s, k)| *s == Scope::Global && k.starts_with(b"KeyPackage\0"))
            .count();
        assert_eq!(kp_rows, 1);
    }
}
