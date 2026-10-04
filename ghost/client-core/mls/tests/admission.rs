//! Admission and CO-2 (design §6.2.4, §6.4, §19.2, §19.3, §19.13, §19.28): §5.7's deferral order,
//! restore and rejoin swaps with their evidence, the channel password (§19.28.3, §19.29.3), and
//! commits CO-2 refuses — the rank rules, a non-canonical update-path leaf (S0-5, the closure of
//! SRLabs S0-1 for channels) and an Add without its evidence.

mod support;

use ghost_client_mls::canonical;
use ghost_client_mls::derive::InvitePassword;
use ghost_client_mls::ext::{
    self, AdmitEvidence, ChannelContext, CommitAad, Purpose, SwapEvidence, FLAG_PASSWORD,
};
use ghost_client_mls::group::{Anchor, ContextKept, KeyClass, ReceiveItem};
use ghost_client_mls::invite;
use ghost_client_mls::join::{JoinAuth, WelcomeBlob};
use ghost_client_mls::kv::WrappedRows;
use ghost_client_mls::provider::GhostProvider;
use ghost_client_mls::seal::{self, Order};
use ghost_client_mls::{Code, CommitReason, MlsError};
use openmls::prelude::tls_codec::Serialize as _;
use openmls::prelude::{
    Extension, Extensions, GroupId, LeafNodeParameters, MlsGroup, UnknownExtension,
};
use openmls_libcrux_crypto::CryptoProvider;
use support::Member;
use support::*;

fn join_from(
    w: &World,
    j: &mut Member,
    out_welcome: &[u8],
    kp_ref: &[u8],
    digest: [u8; 32],
    expected: (u32, [u8; 32]),
) {
    let blob = WelcomeBlob {
        kp_ref: kp_ref.to_vec(),
        welcome: out_welcome.to_vec(),
    }
    .encode()
    .unwrap();
    let rows = j.wrapped();
    let joined = j
        .ctx
        .welcome_join(
            &j.ch,
            &WrappedRows(&rows),
            &blob,
            w.day,
            expected,
            &Anchor::Invite {
                committers_digest: digest,
            },
        )
        .expect("join");
    j.apply(joined.changes);
    j.epoch = Some(joined.epoch);
    j.generation = Some(joined.generation);
}

/// §5.7 (S0-16): a pass with more Adds than fit the small floor keeps the first ones and defers
/// the rest from the end; the commit fits `C(4096)`.
#[test]
fn adds_that_do_not_fit_the_floor_are_deferred_from_the_end() {
    let mut w = World::create(30, 0);
    let mut req = w.request(0);
    let mut pending = Vec::new();
    for _ in 0..10 {
        let (j, kp, ev, digest, expected) = w.invite_and_key_package(0);
        req.adds.push((kp, ev.clone()));
        pending.push((j, ev.kp_ref, digest, expected));
    }
    let out = w.commit_and_settle(0, &req);
    assert!(out.commit.len() <= 4028, "{} bytes", out.commit.len());
    let kept = out.kept_adds.clone();
    assert!(!kept.is_empty() && kept.len() < 10, "kept {kept:?}");
    assert_eq!(
        kept,
        (0..kept.len()).collect::<Vec<_>>(),
        "deferred from the end"
    );
    let welcome = out.welcome.unwrap();
    for (i, (mut j, kp_ref, digest, expected)) in pending.into_iter().enumerate() {
        if kept.contains(&i) {
            join_from(&w, &mut j, &welcome, &kp_ref, digest, expected);
            w.members.push(j);
        }
    }
    let a = w.authenticators();
    assert!(a.windows(2).all(|p| p[0] == p[1]));
}

/// The review of S2b: a pass with the most requests a channel holds (64, §6.3.5) keeps the same
/// prefix a pass of 10 keeps — §5.7's order — and every member validates the commit; the deferral
/// bisects, so this costs about ten builds where S2b's first version built the commit sixty times.
/// One request more than the bound is refused before anything is parsed, and so is a member
/// removed twice.
#[test]
fn a_pass_of_sixty_four_requests_keeps_the_prefix_that_fits() {
    let mut w = World::create(36, 0);
    let mut req = w.request(0);
    let mut pending = Vec::new();
    for _ in 0..ghost_client_mls::group::COMMIT_JOINERS_MAX {
        let (j, kp, ev, digest, expected) = w.invite_and_key_package(0);
        req.adds.push((kp, ev.clone()));
        pending.push((j, ev.kp_ref, digest, expected));
    }
    let mut over = req.clone();
    over.adds.push(req.adds[0].clone());
    let rows = w.owner().wrapped();
    let owner = w.owner();
    assert_eq!(
        owner
            .ctx
            .commit(&owner.ch, &WrappedRows(&rows), &over, w.day)
            .err(),
        Some(MlsError::new(Code::InvalidPolicy)),
        "65 Adds"
    );
    // The first ten alone: the reference prefix.
    let mut ten = req.clone();
    ten.adds.truncate(10);
    let reference = owner
        .ctx
        .commit(&owner.ch, &WrappedRows(&rows), &ten, w.day)
        .expect("ten Adds")
        .kept_adds;
    let out = w.commit_and_settle(0, &req);
    assert!(out.commit.len() <= 4028, "{} bytes", out.commit.len());
    assert_eq!(out.kept_adds, reference, "the same prefix as a pass of ten");
    assert!(
        !reference.is_empty() && reference.len() < 10,
        "kept {reference:?}"
    );
    let welcome = out.welcome.unwrap();
    for (i, (mut j, kp_ref, digest, expected)) in pending.into_iter().enumerate() {
        if out.kept_adds.contains(&i) {
            join_from(&w, &mut j, &welcome, &kp_ref, digest, expected);
            w.members.push(j);
        }
    }
    let a = w.authenticators();
    assert_eq!(a.len(), 1 + reference.len());
    assert!(a.windows(2).all(|p| p[0] == p[1]));
    // A member removed twice in one request is refused; once, it is removed.
    let gone = w.members[1].p();
    let mut twice = w.request(0);
    twice.removes = vec![gone, gone];
    let rows = w.owner().wrapped();
    let owner = w.owner();
    assert_eq!(
        owner
            .ctx
            .commit(&owner.ch, &WrappedRows(&rows), &twice, w.day)
            .err(),
        Some(MlsError::new(Code::InvalidPolicy)),
        "a member removed twice"
    );
    twice.removes.pop();
    let out = w.commit_and_settle(0, &twice);
    assert_eq!(out.kept_removes, vec![0]);
}

/// The invite's join key in a class of its own (review of S2b, §19.36): `invite_parse` wraps `JK_g`
/// as class 6, which never opens as the channel's own class 3. It seals the invitee's join request
/// (mode 0x12), which the sponsor opens with its own key, and opens the Welcome blob the sponsor
/// seals (mode 0x13) — and nothing else, so an invite anyone can write for any channel id cannot
/// open the join requests a member reads. A slot named twice is refused, before any Argon2id.
#[test]
fn an_invites_join_key_seals_the_request_and_opens_the_welcome_only() {
    let w = World::create(37, 0);
    let owner = w.owner();
    let g = owner.generation.clone().unwrap();
    let rows = owner.wrapped();
    let inv = owner
        .ctx
        .invite_build(
            &owner.ch,
            &WrappedRows(&rows),
            &g.g_env,
            g.generation,
            w.day + 7,
            0,
            None,
            false,
            w.day,
        )
        .unwrap();
    let joiner = Member::new(w.channel_id, 37_500);
    let nc = Some(MlsError::new(Code::NonCanonical));
    assert_eq!(
        joiner.ctx.invite_parse(&inv.invite, None, &[1, 2, 1]).err(),
        nc
    );
    let p = joiner.ctx.invite_parse(&inv.invite, None, &[1, 2]).unwrap();
    assert_eq!(p.slots.len(), 2);
    assert_eq!(
        joiner
            .ctx
            .unwrap_key(KeyClass::Join, &w.channel_id, &p.jk_env)
            .err(),
        Some(MlsError::new(Code::StateCorrupt)),
        "an invite's key is not the channel's own"
    );
    let none = Order::default();
    let policy = Some(MlsError::new(Code::InvalidPolicy));
    let request = joiner
        .ctx
        .seal_blob(
            &w.channel_id,
            &p.jk_env,
            KeyClass::InviteJoin,
            &p.ns,
            4096,
            seal::MODE_JOIN,
            &none,
            b"request",
        )
        .unwrap();
    let opened = owner
        .ctx
        .open_blob(
            &w.channel_id,
            &g.jk_env,
            KeyClass::Join,
            &g.ns,
            seal::MODE_JOIN,
            &request,
        )
        .unwrap();
    assert_eq!(opened.body, b"request");
    assert_eq!(
        joiner
            .ctx
            .open_blob(
                &w.channel_id,
                &p.jk_env,
                KeyClass::InviteJoin,
                &p.ns,
                seal::MODE_JOIN,
                &request,
            )
            .err(),
        policy,
        "an invite's key opens no join request"
    );
    let welcome = owner
        .ctx
        .seal_blob(
            &w.channel_id,
            &g.jk_env,
            KeyClass::Join,
            &g.ns,
            16384,
            seal::MODE_WELCOME,
            &none,
            b"welcome",
        )
        .unwrap();
    let opened = joiner
        .ctx
        .open_blob(
            &w.channel_id,
            &p.jk_env,
            KeyClass::InviteJoin,
            &p.ns,
            seal::MODE_WELCOME,
            &welcome,
        )
        .unwrap();
    assert_eq!(opened.body, b"welcome");
    assert_eq!(
        joiner
            .ctx
            .seal_blob(
                &w.channel_id,
                &p.jk_env,
                KeyClass::InviteJoin,
                &p.ns,
                16384,
                seal::MODE_WELCOME,
                &none,
                b"x",
            )
            .err(),
        policy,
        "an invite's key seals no Welcome"
    );
    assert_eq!(
        owner
            .ctx
            .generation(&w.channel_id, &g.g_env, g.generation, g.open_epoch, &[0, 0])
            .err(),
        nc,
        "a slot named twice"
    );
}

/// A restore swap (§6.12, §19.3): a lost device's pseudonym comes back through an invite with a
/// restore-purpose KeyPackage; the commit rotates the generation (§6.5).
#[test]
fn a_restore_swap_rotates_and_the_restored_device_joins() {
    let mut w = World::create(31, 0);
    w.admit(2);
    let lost = w.members.remove(2);
    let (i, p) = (lost.index, lost.p());
    drop(lost);
    // The restored device: the same pseudonym seed, no state.
    let mut restored = Member::new(w.channel_id, i);
    assert_eq!(restored.p(), p);
    let owner = &w.members[0];
    let g = owner.generation.clone().unwrap();
    let rows = owner.wrapped();
    let inv = owner
        .ctx
        .invite_build(
            &owner.ch,
            &WrappedRows(&rows),
            &g.g_env,
            g.generation,
            w.day + 7,
            0,
            None,
            false,
            w.day,
        )
        .unwrap();
    let (_, fields) = invite::parse_v2(&inv.invite, None).unwrap();
    let kp = restored
        .ctx
        .key_package(&restored.ch, Purpose::Restore, w.day)
        .unwrap();
    restored.apply(kp.changes);
    let body = restored.ctx.join_request(&fields, &kp.key_package).unwrap();
    let v = owner
        .ctx
        .join_verify(
            &w.channel_id,
            &body,
            Some(&inv.issued.invite_pk),
            None,
            g.generation,
        )
        .unwrap();
    let JoinAuth::Invite { invite_sig, .. } = v.auth else {
        unreachable!()
    };
    let ev = AdmitEvidence {
        kp_ref: kp.kp_ref.clone(),
        invite_id: inv.issued.invite_id,
        invite_pk: inv.issued.invite_pk,
        expiry_day: inv.issued.expiry_day,
        sponsor: owner.p(),
        sponsor_sig: inv.issued.sponsor_sig,
        invite_sig,
    };
    let mut req = w.request(0);
    req.swaps
        .push((p, kp.key_package.clone(), SwapEvidence::Restore(ev)));
    let out = w.commit_and_settle(0, &req);
    assert!(out.rotates, "a restore swap rotates the generation");
    assert_eq!(out.summary.swaps.len(), 1);
    // The Welcome of a rotating commit carries the new generation, exported by the joiner.
    join_from(
        &w,
        &mut restored,
        &out.welcome.unwrap(),
        &kp.kp_ref,
        inv.issued.committers_digest,
        (fields.generation, fields.ns),
    );
    assert_eq!(
        restored.generation.as_ref().unwrap().ns,
        w.members[0].generation.as_ref().unwrap().ns
    );
    assert_eq!(
        restored.generation.as_ref().unwrap().generation,
        fields.generation + 1
    );
    w.members.push(restored);
    let a = w.authenticators();
    assert!(a.windows(2).all(|p| p[0] == p[1]));
}

/// A rejoin swap (§6.7, §19.3): signed with the member's pseudonym key; it does not rotate; the
/// rejoiner's anchor is the committers of its last final epoch (signature only, §19.29.2).
#[test]
fn a_rejoin_swap_keeps_the_generation() {
    let mut w = World::create(32, 0);
    w.admit(2);
    let m = w.members.remove(1);
    let last_epoch = m.epoch.as_ref().unwrap().epoch;
    let last_hash = [0x5a; 32];
    let g = w.members[0].generation.clone().unwrap();
    let mut rejoiner = Member::new(w.channel_id, m.index);
    let kp = rejoiner
        .ctx
        .key_package(&rejoiner.ch, Purpose::Rejoin, w.day)
        .unwrap();
    rejoiner.apply(kp.changes);
    let body = rejoiner
        .ctx
        .rejoin_request(
            &rejoiner.ch,
            g.generation,
            w.day,
            last_epoch,
            &last_hash,
            &kp.key_package,
        )
        .unwrap();
    let owner = &w.members[0];
    let v = owner
        .ctx
        .join_verify(&w.channel_id, &body, None, Some(&m.p()), g.generation)
        .unwrap();
    // The signature binds the generation of the namespace the request was sealed into.
    assert_eq!(
        owner
            .ctx
            .join_verify(&w.channel_id, &body, None, Some(&m.p()), g.generation + 1)
            .err(),
        Some(MlsError::new(Code::BadSignature))
    );
    let JoinAuth::Rejoin {
        rejoin_sig, day, ..
    } = v.auth
    else {
        unreachable!()
    };
    let mut req = w.request(0);
    req.swaps.push((
        m.p(),
        kp.key_package.clone(),
        SwapEvidence::Rejoin {
            kp_ref: kp.kp_ref.clone(),
            generation: g.generation,
            day,
            last_epoch,
            last_hash,
            rejoin_sig,
        },
    ));
    let out = w.commit_and_settle(0, &req);
    assert!(!out.rotates, "a rejoin swap does not rotate");
    let blob = WelcomeBlob {
        kp_ref: kp.kp_ref.clone(),
        welcome: out.welcome.unwrap(),
    }
    .encode()
    .unwrap();
    let rows = rejoiner.global_rows();
    let joined = rejoiner
        .ctx
        .welcome_join(
            &rejoiner.ch,
            &WrappedRows(&rows),
            &blob,
            w.day,
            (g.generation, g.ns),
            &Anchor::Rejoin {
                last_committers: vec![w.members[0].p()],
            },
        )
        .unwrap();
    assert_eq!(joined.generation.ns, g.ns);
    assert_eq!(
        joined.epoch.epoch_authenticator,
        w.members[0].epoch.as_ref().unwrap().epoch_authenticator
    );
}

#[test]
fn the_channel_password() {
    let mut w = World::create(33, 0);
    w.admit(1);
    let pw = InvitePassword::from_bytes(b"cabin frost ladder margin orbit".to_vec());
    // Rank 0 sets a password: flag bit 2, pw_version 1, and (Q46 (b)) members no longer invite.
    let mut ctx: ChannelContext = w.members[0]
        .ctx
        .roster(
            &w.members[0].ch,
            &WrappedRows(&w.members[0].wrapped()),
            w.day,
        )
        .unwrap()
        .context;
    ctx.flags = FLAG_PASSWORD;
    ctx.pw_version = 1;
    // A member of rank 255 may not change it: its own CO-2 refuses the commit.
    let mut bad = w.request(1);
    bad.context = Some(ctx.clone());
    let m1 = &w.members[1];
    assert_eq!(
        m1.ctx
            .commit(&m1.ch, &WrappedRows(&m1.wrapped()), &bad, w.day)
            .err(),
        Some(MlsError::new(Code::InvalidPolicy))
    );
    let mut req = w.request(0);
    req.context = Some(ctx.clone());
    w.commit_and_settle(0, &req);
    let owner = &w.members[0];
    let g = owner.generation.clone().unwrap();
    let rows = owner.wrapped();
    // kdf_code must match flag bit 2.
    assert_eq!(
        owner
            .ctx
            .invite_build(
                &owner.ch,
                &WrappedRows(&rows),
                &g.g_env,
                g.generation,
                w.day + 7,
                0,
                None,
                false,
                w.day
            )
            .err(),
        Some(MlsError::new(Code::InvalidPolicy))
    );
    let inv = owner
        .ctx
        .invite_build(
            &owner.ch,
            &WrappedRows(&rows),
            &g.g_env,
            g.generation,
            w.day + 7,
            1,
            Some(&pw),
            false,
            w.day,
        )
        .unwrap();
    assert_eq!(inv.invite.len(), 335);
    assert_eq!(inv.issued.pw_version, Some(1));
    assert_eq!(
        invite::parse_v2(&inv.invite, None).err(),
        Some(MlsError::new(Code::PasswordRequired))
    );
    let wrong = InvitePassword::from_bytes(b"cabin frost ladder margin orbit.".to_vec());
    assert_eq!(
        invite::parse_v2(&inv.invite, Some(&wrong)).err(),
        Some(MlsError::new(Code::WrongPassword))
    );
    let (code, fields) = invite::parse_v2(&inv.invite, Some(&pw)).unwrap();
    assert_eq!(code, 1);
    assert_eq!(fields.ns, g.ns);
    // A non-committer may not invite in a password channel (Q46 (b)).
    let m1 = &w.members[1];
    let g1 = m1.generation.clone().unwrap();
    assert_eq!(
        m1.ctx
            .invite_build(
                &m1.ch,
                &WrappedRows(&m1.wrapped()),
                &g1.g_env,
                g1.generation,
                w.day + 7,
                1,
                Some(&pw),
                false,
                w.day
            )
            .err(),
        Some(MlsError::new(Code::InvalidPolicy))
    );
    // Removing the password clears the flag without a bump (§19.29.3); invites are open again.
    let mut open = ctx.clone();
    open.flags = 0;
    let mut req = w.request(0);
    req.context = Some(open);
    w.commit_and_settle(0, &req);
    let owner = &w.members[0];
    let g = owner.generation.clone().unwrap();
    let inv = owner
        .ctx
        .invite_build(
            &owner.ch,
            &WrappedRows(&owner.wrapped()),
            &g.g_env,
            g.generation,
            w.day + 7,
            0,
            None,
            false,
            w.day,
        )
        .unwrap();
    assert_eq!(inv.issued.pw_version, None);
}

#[test]
fn co2_rank_rules_on_the_committers_own_check() {
    let mut w = World::create(34, 0);
    w.admit(2);
    // A member of rank 255 may not remove anyone.
    let mut req = w.request(1);
    req.removes.push(w.members[2].p());
    let m1 = &w.members[1];
    assert_eq!(
        m1.ctx
            .commit(&m1.ch, &WrappedRows(&m1.wrapped()), &req, w.day)
            .err(),
        Some(MlsError::commit(CommitReason::Permission))
    );
    // Nor set the rotation flag.
    let mut req = w.request(1);
    req.rotate = true;
    assert_eq!(
        m1.ctx
            .commit(&m1.ch, &WrappedRows(&m1.wrapped()), &req, w.day)
            .err(),
        Some(MlsError::new(Code::InvalidPolicy))
    );
    // The owner removes a committer (a moderator) and its key leaves the lists in the same commit
    // (§5.7's unit), even when no context change was requested.
    let moderator = w.members[1].p();
    let mut ctx = w.members[0]
        .ctx
        .roster(
            &w.members[0].ch,
            &WrappedRows(&w.members[0].wrapped()),
            w.day,
        )
        .unwrap()
        .context;
    ctx.committers.push(moderator);
    let mut req = w.request(0);
    req.context = Some(ctx);
    w.commit_and_settle(0, &req);
    let mut req = w.request(0);
    req.removes.push(moderator);
    let out = w.commit_and_settle(0, &req);
    assert_eq!(out.context, ContextKept::NotRequested);
    let after = out
        .summary
        .context
        .expect("the drop of the removed committer's key");
    assert!(!after.committers.contains(&moderator));
}

/// Hand-built commits (OpenMLS directly, with the member's own rows) that CO-2 refuses at every
/// receiver: a self-update whose leaf carries an extra extension (SRLabs S0-1's leaf inflation,
/// closed by canonical leaves, S0-5), and an Add without its evidence (§19.2).
#[test]
fn co2_refuses_an_inflated_leaf_and_an_add_without_evidence() {
    let mut w = World::create(35, 0);
    w.admit(2);
    // CO-14 (k = min(8, n) = 3 with three members): a rank-255 self-update of a KeyPackage leaf
    // (refresh_epoch 0) is valid from epoch 3; two passes of the owner get there.
    for _ in 0..2 {
        let req = w.request(0);
        w.commit_and_settle(0, &req);
    }
    let epoch = w.members[1].epoch.as_ref().unwrap().epoch;
    let crypto = CryptoProvider::new().unwrap();
    let build = |m: &Member, adds: Vec<openmls::prelude::KeyPackage>, extra: bool| -> Vec<u8> {
        let p = GhostProvider {
            crypto: &crypto,
            storage: raw_storage(m, DAY),
        };
        let signer = raw_signer(m);
        let mut g = MlsGroup::load(&p.storage, &GroupId::from_slice(&m.channel_id()))
            .unwrap()
            .unwrap();
        g.set_aad(
            CommitAad {
                commit_minute: minute(DAY),
                ..Default::default()
            }
            .encode(),
        );
        let leaf = ext::GhostLeaf {
            box_pk: canonical::box_public(&[3; 32]),
            refresh_epoch: epoch,
        };
        let mut exts = vec![Extension::Unknown(
            ext::EXT_LEAF,
            UnknownExtension(leaf.encode()),
        )];
        let mut caps = canonical::canonical_capabilities();
        if extra {
            exts.push(Extension::Unknown(
                0xF100,
                UnknownExtension(vec![0x5a; 2000]),
            ));
            caps = openmls::prelude::Capabilities::new(
                None,
                Some(&[canonical::SUITE]),
                Some(&[
                    openmls::prelude::ExtensionType::Unknown(ext::EXT_CHANNEL_CONTEXT),
                    openmls::prelude::ExtensionType::Unknown(ext::EXT_LEAF),
                    openmls::prelude::ExtensionType::Unknown(ext::EXT_KP_BIND),
                    openmls::prelude::ExtensionType::Unknown(0xF100),
                ]),
                None,
                Some(&[openmls::prelude::CredentialType::Basic]),
            );
        }
        let params = LeafNodeParameters::builder()
            .with_capabilities(caps)
            .with_extensions(Extensions::from_vec(exts).unwrap())
            .build();
        let bundle = g
            .commit_builder()
            .propose_adds(adds)
            .force_self_update(true)
            .leaf_node_parameters(params)
            .load_psks(&p.storage)
            .unwrap()
            .create_group_info(false)
            .build(
                openmls::prelude::OpenMlsProvider::rand(&p),
                openmls::prelude::OpenMlsProvider::crypto(&p),
                &signer,
                |_| true,
            )
            .unwrap()
            .stage_commit(&p)
            .unwrap();
        bundle.into_messages().0.tls_serialize_detached().unwrap()
    };
    let verdict = |m: &Member, c: &[u8]| -> Result<(), CommitReason> {
        let r = m
            .ctx
            .receive(&m.ch, &WrappedRows(&m.wrapped()), epoch, &[c.to_vec()], DAY)
            .unwrap();
        match &r.items[0] {
            ReceiveItem::Commit(s) => s.verdict,
            other => panic!("{other:?}"),
        }
    };
    // (a) Member 1 (rank 255) inflates its own leaf in an empty self-update.
    let inflated = build(&w.members[1], vec![], true);
    assert_eq!(
        verdict(&w.members[2], &inflated),
        Err(CommitReason::NonCanonicalLeaf)
    );
    // A canonical self-update by the same member is valid.
    let fine = build(&w.members[1], vec![], false);
    assert_eq!(verdict(&w.members[2], &fine), Ok(()));
    // (b) The owner adds a canonical KeyPackage without its AdmitEvidence.
    let joiner = Member::new(w.channel_id, 9999);
    let kp = joiner
        .ctx
        .key_package(&joiner.ch, Purpose::Join, DAY)
        .unwrap();
    let kp = canonical::parse_key_package(&crypto, &kp.key_package, Some(&w.channel_id)).unwrap();
    let naked = build(&w.members[0], vec![kp.key_package], false);
    assert_eq!(verdict(&w.members[2], &naked), Err(CommitReason::Evidence));
}
