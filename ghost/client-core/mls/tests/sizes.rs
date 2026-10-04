//! Golden sizes of design §5.5 and §5.7 (S0-4, V10-4) measured with the real crate: the canonical
//! KeyPackage (395 B), the longest posts, and the single-proposal commits and the Welcome of a
//! small channel at its cap in the blank shape (only the committer's direct path set, so its update
//! path carries all n − 1 path-secret ciphertexts). `GHOST_WRITE_VECTORS=1` writes
//! `protocol/test-vectors/ch_sizes.txt`; otherwise the file is compared. The spike's V10-4 values
//! predate `pw_version` (§19.29.5): every row that carries a context — a context change, a Welcome's
//! GroupInfo — is 2 bytes larger here, and the others are equal (asserted below).

mod support;

use std::fmt::Write as _;

use ghost_client_mls::content::{Body, ChannelContent, KIND_POST};
use ghost_client_mls::ext::{AdmitEvidence, ChannelContext, Purpose, SwapEvidence};
use ghost_client_mls::group::CommitRequest;
use ghost_client_mls::invite;
use ghost_client_mls::join::JoinAuth;
use ghost_client_mls::kv::WrappedRows;
use ghost_client_mls::seal;
use support::Member;
use support::*;

fn commit_size(w: &World, req: &CommitRequest) -> usize {
    let o = &w.members[0];
    let rows = o.wrapped();
    let out = o
        .ctx
        .commit(&o.ch, &WrappedRows(&rows), req, w.day)
        .expect("a single-proposal commit fits the floor");
    assert_eq!(out.summary.verdict, Ok(()));
    out.commit.len()
}

fn restore_request(w: &mut World, target: usize) -> CommitRequest {
    let (i, p) = (w.members[target].index, w.members[target].p());
    let mut dev = Member::new(w.channel_id, i);
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
    let (_, f) = invite::parse_v2(&inv.invite, None).unwrap();
    let kp = dev
        .ctx
        .key_package(&dev.ch, Purpose::Restore, w.day)
        .unwrap();
    dev.apply(kp.changes);
    let body = dev.ctx.join_request(&f, &kp.key_package).unwrap();
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
    let mut req = w.request(0);
    req.swaps.push((
        p,
        kp.key_package,
        SwapEvidence::Restore(AdmitEvidence {
            kp_ref: kp.kp_ref,
            invite_id: inv.issued.invite_id,
            invite_pk: inv.issued.invite_pk,
            expiry_day: inv.issued.expiry_day,
            sponsor: owner.p(),
            sponsor_sig: inv.issued.sponsor_sig,
            invite_sig,
        }),
    ));
    req
}

fn rejoin_request(w: &mut World, target: usize) -> CommitRequest {
    let (i, p) = (w.members[target].index, w.members[target].p());
    let last_epoch = w.members[target].epoch.as_ref().unwrap().epoch;
    let mut dev = Member::new(w.channel_id, i);
    let g = w.members[0].generation.clone().unwrap();
    let kp = dev
        .ctx
        .key_package(&dev.ch, Purpose::Rejoin, w.day)
        .unwrap();
    dev.apply(kp.changes);
    let body = dev
        .ctx
        .rejoin_request(
            &dev.ch,
            g.generation,
            w.day,
            last_epoch,
            &[7; 32],
            &kp.key_package,
        )
        .unwrap();
    let v = w.members[0]
        .ctx
        .join_verify(&w.channel_id, &body, None, Some(&p), g.generation)
        .unwrap();
    let JoinAuth::Rejoin { rejoin_sig, .. } = v.auth else {
        unreachable!()
    };
    let mut req = w.request(0);
    req.swaps.push((
        p,
        kp.key_package,
        SwapEvidence::Rejoin {
            kp_ref: kp.kp_ref,
            generation: g.generation,
            day: w.day,
            last_epoch,
            last_hash: [7; 32],
            rejoin_sig,
        },
    ));
    req
}

/// The largest context §5.3 allows: 8 committers, 3 funders, a 48-byte name (448 bytes).
fn maximal_context(w: &World) -> ChannelContext {
    let keys: Vec<[u8; 32]> = w.members.iter().map(|m| m.p()).take(8).collect();
    ChannelContext {
        name: vec![b'a'; 48],
        committers: keys.clone(),
        funders: keys[..3].to_vec(),
        timer_version: 0xffff,
        ..initial_context(w.channel_id, keys[0], 0)
    }
}

#[test]
fn golden_sizes_small_class_at_the_cap() {
    let mut w = World::create(40, 0);
    let mut lines = String::new();
    // The canonical KeyPackage.
    let m = Member::new(w.channel_id, 40_999);
    let kp = m.ctx.key_package(&m.ch, Purpose::Join, w.day).unwrap();
    assert_eq!(kp.key_package.len(), 395);
    let _ = writeln!(lines, "key_package = {}", kp.key_package.len());

    // The longest text posts (16 000 bytes of text; with reply_to), in a 2-member channel.
    w.admit(1);
    for (name, reply) in [
        ("post_16000", None),
        ("post_16000_reply_to", Some([1u8; 16])),
    ] {
        let c = ChannelContent {
            kind: KIND_POST,
            op_id: [2; 16],
            author_minute: minute(DAY),
            timer_code: 4,
            body: Body::Post {
                text: "a".repeat(16_000),
                reply_to: reply,
            },
        }
        .encode()
        .unwrap();
        let mls = w.post(0, &c);
        let _ = writeln!(
            lines,
            "{name} = {} (margin {} to C(16384))",
            mls.len(),
            seal::capacity(16_384) - mls.len()
        );
    }

    // Grow to 31 members with the owner's passes only (the blank shape), then measure an Add
    // 31 -> 32 and the Welcome for one joiner.
    while w.members.len() < 31 {
        let n = (31 - w.members.len()).min(4);
        w.admit(n);
    }
    let (_j, kpb, ev, _digest, _expected) = w.invite_and_key_package(0);
    let mut add = w.request(0);
    add.adds.push((kpb, ev));
    let o = &w.members[0];
    let out = o
        .ctx
        .commit(&o.ch, &WrappedRows(&o.wrapped()), &add, w.day)
        .unwrap();
    let add_size = out.commit.len();
    let welcome = out.welcome.unwrap().len();
    let _ = writeln!(
        lines,
        "add_31_to_32 = {add_size} (margin {})",
        seal::capacity(4096) - add_size
    );
    let _ = writeln!(lines, "welcome_one_joiner_32 = {welcome}");
    w.admit(1);
    assert_eq!(w.members.len(), 32);

    // Rank-255 empty self-update, the owner's PCS commit, Remove 1, the swaps, the context change
    // and the Remove + context-change unit (§5.7), at 32 members in 32 leaves.
    // The far member (leaf 31), as V10-4 measured it: the update-path size depends on the leaf.
    let far = w.members.len() - 1;
    let r255 = {
        let m = &w.members[far];
        let rows = m.wrapped();
        m.ctx
            .commit(&m.ch, &WrappedRows(&rows), &w.request(far), w.day)
            .unwrap()
            .commit
            .len()
    };
    let pcs = commit_size(&w, &w.request(0));
    let mut rm = w.request(0);
    rm.removes.push(w.members[20].p());
    let remove1 = commit_size(&w, &rm);
    let rejoin = {
        let req = rejoin_request(&mut w, 21);
        commit_size(&w, &req)
    };
    let restore = {
        let req = restore_request(&mut w, 22);
        commit_size(&w, &req)
    };
    let mut ctx_req = w.request(0);
    ctx_req.context = Some(maximal_context(&w));
    let ctx_change = commit_size(&w, &ctx_req);
    let mut unit = w.request(0);
    let mut c = maximal_context(&w);
    let gone = c.committers[7];
    c.committers.retain(|k| *k != gone);
    unit.context = Some(c);
    unit.removes.push(gone);
    let unit_size = commit_size(&w, &unit);
    // V10-4's row: a Remove of a non-committer with the maximal context change.
    let mut v104 = w.request(0);
    v104.context = Some(maximal_context(&w));
    v104.removes.push(w.members[25].p());
    let v104_size = commit_size(&w, &v104);
    for (name, v) in [
        ("self_update_rank_255", r255),
        ("pcs_commit", pcs),
        ("remove_1", remove1),
        ("swap_rejoin", rejoin),
        ("swap_restore", restore),
        ("context_change_max", ctx_change),
        ("remove_1_with_context_change", v104_size),
        ("remove_committer_with_drop_of_its_key", unit_size),
    ] {
        let _ = writeln!(
            lines,
            "{name} = {v} (margin {})",
            seal::capacity(4096) as i64 - v as i64
        );
    }
    // V10-4's measurements (blank, 32 leaves), unchanged where no context travels and +2 bytes
    // where one does (pw_version, §19.29.5).
    assert_eq!(add_size, 3745);
    assert_eq!(pcs, 3185);
    assert_eq!(remove1, 3110);
    assert_eq!(rejoin, 3653);
    assert_eq!(restore, 3786);
    assert_eq!(ctx_change, 3653 + 2);
    assert_eq!(v104_size, 3578 + 2);
    // The unit of §5.7 proper (the removed pseudonym is a committer and its key leaves the list):
    // one 32-byte key fewer in the context than V10-4's row.
    assert_eq!(unit_size, 3578 + 2 - 32);
    // The Welcome also carries GhostBootstrap in its GroupInfo (S0-9: extension type 2 bytes, a
    // 1-byte length and 45 bytes), which V10-4's size probe did not: 8 818 + 2 + 48.
    assert_eq!(welcome, 8818 + 2 + 48);
    assert_eq!(r255, 1955);

    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../protocol/test-vectors/ch_sizes.txt");
    let text = format!(
        "# GHOST channel golden sizes (design §5.5, §5.7; S0-4, V10-4) in bytes of the MlsMessage the seal\n\
         # carries, measured with ghost-client-mls on OpenMLS 0.9.0, suite 0x0003: a small channel at its cap\n\
         # (32 members, 32 leaves, the blank shape: only the owner's direct path set), GHOST's extensions\n\
         # and evidence, every commit with a forced path. Generated and checked by\n\
         # client-core/mls/tests/sizes.rs; the independent replay checks the KeyPackage's 395 bytes from its\n\
         # structure (mls-kat/tests/spec_replay.rs). C(4096) = 4028, C(16384) = 16316.\n\n[sizes]\n{lines}"
    );
    if std::env::var("GHOST_WRITE_VECTORS").is_ok_and(|v| v == "1") {
        std::fs::write(&path, text).unwrap();
    } else {
        assert_eq!(std::fs::read_to_string(&path).expect("ch_sizes.txt"), text);
    }
}
