//! V10-8: `GhostBootstrap` (0xF0A3) passed through `CommitBuilder::create_group_info_with_extensions`
//! reaches the GroupInfo inside the Welcome, the joiner reads it, and the committer's GroupInfo
//! signature authenticates it (design §5.4, §19.16).

use ghost_mls_spike::ext::{self, CommitAad};
use ghost_mls_spike::harness::*;
use openmls::prelude::*;

/// The joiner, its join result (the bootstrap it read), the bootstrap sent, the commit.
type Probe = (Device, Result<Option<Vec<u8>>, String>, Vec<u8>, CommitOut);

fn add_with_bootstrap(w: &mut World, corrupt_nth: u32) -> Probe {
    let ch = w.channel;
    let day = w.day;
    let mut j = Device::new(99, day);
    let kp = j.key_package(ch, 1, day, 0).unwrap();
    let kp = w.members[0].parse_key_package(&kp).unwrap();
    let e = w.members[0].epoch(ch);
    let boot = ext::bootstrap(3, e + 1, &[0xab; 32]);
    let spec = CommitSpec {
        adds: vec![kp],
        aad: CommitAad {
            commit_minute: day * 1440,
            ..Default::default()
        },
        refresh_epoch: Some(e),
        force_path: true,
        group_info_extensions: vec![Extension::Unknown(
            ext::EXT_BOOTSTRAP,
            UnknownExtension(boot.clone()),
        )],
        ..Default::default()
    };
    w.members[0].signer.corrupt_nth.set(corrupt_nth);
    let out = w.members[0]
        .commit(ch, &spec)
        .expect("commit with bootstrap");
    w.members[0].signer.corrupt_nth.set(0);
    let r = j.join(ch, out.welcome.as_ref().unwrap(), true);
    (j, r, boot, out)
}

#[test]
fn v10_08_bootstrap_in_welcome_group_info() {
    let day = host_day();
    let mut w = World::build(4, 3, day);
    let ch = w.channel;

    let (mut j, r, boot, out) = add_with_bootstrap(&mut w, 0);
    let got = r
        .expect("join succeeds")
        .expect("GhostBootstrap present in the Welcome's GroupInfo");
    assert_eq!(got, boot);
    println!(
        "V10-8 bootstrap: {} B extension in the Welcome's GroupInfo; Welcome {} B; commit {} B; exported GroupInfo also built: {} ({} B)",
        got.len(),
        out.welcome.as_ref().unwrap().len(),
        out.commit.len(),
        out.group_info_exported.is_some(),
        out.group_info_exported.as_ref().map_or(0, Vec::len)
    );
    for m in w.members.iter_mut().skip(1) {
        m.receive(ch, &out.commit).unwrap();
    }
    w.members[0].merge_own(ch).unwrap();
    assert_eq!(
        j.authenticator(ch),
        w.members[0].authenticator(ch),
        "the joiner is in the group"
    );

    // Authentication: a Welcome whose GroupInfo signature is wrong is refused by the joiner. The
    // committer's signer is made to corrupt one of the signatures of the next commit; the probe
    // finds which one is the Welcome's GroupInfo by the joiner's result.
    for n in 1..=4u32 {
        let before = w.members[0].rows.clone();
        let (_, r, _, out) = add_with_bootstrap(&mut w, n);
        println!(
            "V10-8 corrupt signature #{n} of the commit: joiner -> {:?}",
            r.as_ref().map(|b| b.as_ref().map(Vec::len))
        );
        if n == 1 {
            // The update-path leaf signature: receivers refuse the commit as well.
            let v = w.members[1].validate(ch, &out.commit);
            println!(
                "V10-8   (#1) member validation of that commit -> {:?}",
                v.as_ref().map(|x| x.0.kind).map_err(|e| e.clone())
            );
        }
        w.members[0].rows = before; // drop the pending commit
    }

    // Reading the extension before `build()` gives an *unverified* value (OpenMLS's own label).
    println!("V10-8 read path: ProcessedWelcome::unverified_group_info().extensions() before JoinBuilder::build(); build() verifies the GroupInfo signature");
    let _ = &mut j;
}

/// The committers digest an invite would carry (the review-pass anchor, S0-15 in the design's §5.9):
/// `SHA-256("ghost/v1/ch/committers" ‖ channel_id ‖ u8(k) ‖ committers)` over the context's list.
fn committers_digest(channel: &[u8; 32], committers: &[[u8; 32]]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let k = u8::try_from(committers.len()).expect("at most 8 committers");
    let mut h = Sha256::new();
    h.update(b"ghost/v1/ch/committers");
    h.update(channel);
    h.update([k]);
    for c in committers {
        h.update(c);
    }
    h.finalize().into()
}

/// What `welcomeJoin` can learn about a Welcome after `JoinBuilder::build()` verified its GroupInfo
/// signature: the `GhostChannelContext` of the group it describes and the signature key of the
/// leaf that signed its GroupInfo. Runs as a dry call, so nothing is written.
fn inspect_welcome(
    j: &mut Device,
    ch: [u8; 32],
    welcome: &[u8],
) -> Result<(ext::ChannelContext, [u8; 32]), String> {
    use openmls::prelude::tls_codec::Deserialize as _;
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
            .and_then(|u| ext::ChannelContext::decode(&u.0))
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

/// Review finding I1: the GroupInfo signature authenticates the Welcome only to a signer the
/// Welcome's own ratchet tree supplies. Any holder of the generation's join key can open a join
/// request (mode 0x12), create its own group with `group_id = channel_id` and a well-formed
/// `GhostChannelContext`, add the joiner's KeyPackage and deposit the Welcome (mode 0x13): OpenMLS
/// accepts it, and a join that is applied consumes the KeyPackage, so the real Welcome then fails.
/// The anchor of the corrected S0-9 (the invite's digest of the committers at issue, and the
/// GroupInfo signer among them) refuses it before anything is written.
#[test]
fn v10_08_forged_welcome_and_the_committer_anchor() {
    let day = host_day();
    let mut w = World::build(4, 3, day);
    let ch = w.channel;
    let owner_pk = w.members[0].pk;
    // The invite carries the digest of the committers when it was issued (here: the owner).
    let anchor = committers_digest(&ch, &[owner_pk]);
    let anchor_check = |ctx: &ext::ChannelContext, signer: &[u8; 32]| -> Result<(), &'static str> {
        if ctx.channel_id != ch {
            return Err("channel_id");
        }
        if committers_digest(&ch, &ctx.committers) != anchor {
            return Err("committers digest differs from the invite's");
        }
        if !ctx.committers.contains(signer) {
            return Err("GroupInfo signer is not a committer");
        }
        Ok(())
    };
    // The joiner's KeyPackage, as its join request carries it under JK_g.
    let mut j = Device::new(99, day);
    let kp_bytes = j.key_package(ch, 1, day, 0).unwrap();

    // Two forgeries by a holder of JK_g who is not a committer: (a) a context naming itself as
    // committer; (b) a context copying the real committers list (so the digest matches) while the
    // forger signs the GroupInfo with its own leaf.
    let mut forged = Vec::new();
    for (tag, copy_committers) in [
        ("own committers list", false),
        ("copied committers list", true),
    ] {
        let mut atk = Device::new(66, day);
        let mut ctx = ext::ChannelContext::initial(ch, atk.pk, 0);
        if copy_committers {
            ctx.committers = vec![owner_pk];
            ctx.funders = vec![owner_pk];
        }
        atk.create_group(ch, &ctx).unwrap();
        let kp = atk.parse_key_package(&kp_bytes).unwrap();
        let e = atk.epoch(ch);
        // A bootstrap naming a newer generation (only the GroupInfo signature "authenticates" it).
        let boot = ext::bootstrap(9, e + 1, &[0xee; 32]);
        let out = atk
            .commit(
                ch,
                &CommitSpec {
                    adds: vec![kp],
                    aad: CommitAad {
                        commit_minute: day * 1440,
                        ..Default::default()
                    },
                    refresh_epoch: Some(e),
                    force_path: true,
                    group_info_extensions: vec![Extension::Unknown(
                        ext::EXT_BOOTSTRAP,
                        UnknownExtension(boot),
                    )],
                    no_exported_group_info: true,
                    ..Default::default()
                },
            )
            .unwrap();
        let welcome = out.welcome.unwrap();
        let seen = inspect_welcome(&mut j, ch, &welcome);
        let (ctx_seen, signer) = seen.clone().expect("OpenMLS accepts the forged Welcome");
        let verdict = anchor_check(&ctx_seen, &signer);
        println!(
            "V10-8 forged Welcome ({tag}): OpenMLS JoinBuilder::build -> accepted (GroupInfo verified under the forger's own leaf); channel_id matches {}; anchor -> {:?}",
            ctx_seen.channel_id == ch,
            verdict
        );
        assert!(verdict.is_err(), "the anchor refuses a forged Welcome");
        forged.push(welcome);
    }

    // Without the anchor the join is applied: the KeyPackage is consumed by the forgery.
    let kp_rows = |d: &Device| {
        d.rows
            .keys()
            .filter(|(s, k)| {
                *s == ghost_mls_spike::kv::Scope::Global && k.starts_with(b"KeyPackage\0")
            })
            .count()
    };
    let mut j2 = Device::new(98, day);
    j2.rows = j.rows.clone();
    let before = kp_rows(&j2);
    let applied = j2.join(ch, &forged[0], true);
    println!(
        "V10-8 forged Welcome applied without the anchor -> {:?} (the joiner now posts into the forger's group); KeyPackage rows {before} -> {}",
        applied.as_ref().map(|_| "joined"),
        kp_rows(&j2)
    );
    assert!(applied.is_ok());
    assert_eq!(
        (before, kp_rows(&j2)),
        (1, 0),
        "the forgery consumed the KeyPackage"
    );
    // The anchor refused both forgeries in dry calls: the joiner's KeyPackage is intact.
    assert_eq!(kp_rows(&j), 1);

    // The real committer admits the same KeyPackage.
    let kp = w.members[0].parse_key_package(&kp_bytes).unwrap();
    let e = w.members[0].epoch(ch);
    let out = w
        .commit_and_merge(
            0,
            &CommitSpec {
                adds: vec![kp],
                aad: CommitAad {
                    commit_minute: day * 1440,
                    ..Default::default()
                },
                refresh_epoch: Some(e),
                force_path: true,
                no_exported_group_info: true,
                ..Default::default()
            },
        )
        .unwrap();
    let real = out.welcome.unwrap();
    // The joiner that applied the forgery can no longer join the real channel.
    let after_forgery = j2.join(ch, &real, true);
    println!(
        "V10-8 the real Welcome after an applied forgery -> {:?}",
        after_forgery
            .as_ref()
            .map(|_| "joined")
            .map_err(|e| e.chars().take(120).collect::<String>())
    );
    assert!(
        after_forgery.is_err(),
        "the forgery consumed the KeyPackage"
    );
    // With the anchor the forgeries were refused in dry calls: the real Welcome passes the anchor
    // and joins.
    let (ctx_real, signer_real) = inspect_welcome(&mut j, ch, &real).unwrap();
    assert_eq!(anchor_check(&ctx_real, &signer_real), Ok(()));
    j.join(ch, &real, true).expect("the real Welcome joins");
    assert_eq!(j.authenticator(ch), w.members[0].authenticator(ch));
    println!("V10-8 the real Welcome with the anchor: signer = the owner (a committer), digest equal -> joined, epoch authenticator equal to the owner's");
}

#[test]
fn v10_08_default_commit_builds_an_exported_group_info() {
    let day = host_day();
    let mut w = World::build(3, 2, day);
    let e = w.members[0].epoch(w.channel);
    let spec = CommitSpec {
        refresh_epoch: Some(e),
        force_path: true,
        ..Default::default()
    };
    let a = w.members[0].commit(w.channel, &spec).unwrap();
    w.members[0].clear_own(w.channel).unwrap();
    let spec2 = CommitSpec {
        no_exported_group_info: true,
        ..spec
    };
    let b = w.members[0].commit(w.channel, &spec2).unwrap();
    println!(
        "V10-8 self-update at 3 members: exported GroupInfo with the ratchet tree built by default: {} ({} B); with create_group_info(false): {}",
        a.group_info_exported.is_some(),
        a.group_info_exported.as_ref().map_or(0, Vec::len),
        b.group_info_exported.is_some()
    );
}

#[test]
fn v10_08_bootstrap_without_an_exported_group_info() {
    // create_group_info_with_extensions() turns the exported GroupInfo on (with ExternalPub);
    // create_group_info(false) afterwards must keep the bootstrap in the Welcome's GroupInfo.
    let day = host_day();
    let mut w = World::build(3, 2, day);
    let ch = w.channel;
    let mut j = Device::new(77, day);
    let kp = j.key_package(ch, 1, day, 0).unwrap();
    let kp = w.members[0].parse_key_package(&kp).unwrap();
    let e = w.members[0].epoch(ch);
    let boot = ext::bootstrap(1, e + 1, &[0xcd; 32]);
    let spec = CommitSpec {
        adds: vec![kp],
        refresh_epoch: Some(e),
        force_path: true,
        group_info_extensions: vec![Extension::Unknown(
            ext::EXT_BOOTSTRAP,
            UnknownExtension(boot.clone()),
        )],
        no_exported_group_info: true,
        ..Default::default()
    };
    let out = w.members[0].commit(ch, &spec).unwrap();
    let got = j.join(ch, out.welcome.as_ref().unwrap(), true).unwrap();
    println!(
        "V10-8 bootstrap with create_group_info(false): exported GroupInfo {}; bootstrap in the Welcome {}",
        out.group_info_exported.is_some(),
        got.as_deref() == Some(&boot[..])
    );
    assert!(out.group_info_exported.is_none());
    assert_eq!(got.as_deref(), Some(&boot[..]));
}
