//! The regressions of the S2a review (design faza10-forum.md §19.31): each test fails on the tree
//! the review read (`16e66dc`) and passes with its fix. H1 low-order HPKE keys, H2 the author of a
//! late post, M1 a re-sealed message of an older epoch, M2 the committer's size rule, ML1 a pending
//! swap and the post it would leak, and the settle, invite, `Debug` and CO-14 findings.

mod support;

use ghost_client_mls::canonical::{self, Fault};
use ghost_client_mls::content::{Body, ChannelContent, KIND_POST};
use ghost_client_mls::derive::{self, InvitePassword};
use ghost_client_mls::ext::{self, AdmitEvidence, Bootstrap, CommitAad, Purpose, SwapEvidence};
use ghost_client_mls::group::{Anchor, CommitRequest, KeyClass, ReceiveItem, Standing, Winner};
use ghost_client_mls::invite;
use ghost_client_mls::join::{self, JoinAuth, WelcomeBlob};
use ghost_client_mls::kv::WrappedRows;
use ghost_client_mls::provider::{GhostProvider, PseudonymSigner};
use ghost_client_mls::seal::{self, Order};
use ghost_client_mls::{Code, CommitReason, MlsError};
use openmls::prelude::tls_codec::{Deserialize as _, Serialize as _};
use openmls::prelude::{
    Extension, Extensions, GroupId, KeyPackage, LeafNodeParameters, MlsGroup, MlsMessageBodyIn,
    MlsMessageIn, ProtocolVersion, UnknownExtension,
};
use openmls_libcrux_crypto::CryptoProvider;
use support::*;

fn post(text: &str, op: u8) -> Vec<u8> {
    ChannelContent {
        kind: KIND_POST,
        op_id: [op; 16],
        author_minute: minute(DAY),
        timer_code: 4,
        body: Body::Post {
            text: text.into(),
            reply_to: None,
        },
    }
    .encode()
    .unwrap()
}

/// u = 1: a point of order 4 on Curve25519, the key the review admitted.
fn low_order() -> [u8; 32] {
    let mut u = [0u8; 32];
    u[0] = 1;
    u
}

fn vbytes(v: &[u8]) -> Vec<u8> {
    let mut o = Vec::new();
    if v.len() < 64 {
        o.push(v.len() as u8);
    } else {
        o.extend_from_slice(&((v.len() as u16) | 0x4000).to_be_bytes());
    }
    o.extend_from_slice(v);
    o
}

fn vlen(b: &[u8], i: &mut usize) -> usize {
    let f = b[*i];
    match f >> 6 {
        0 => {
            *i += 1;
            usize::from(f & 0x3f)
        }
        1 => {
            let v = usize::from(u16::from_be_bytes([f & 0x3f, b[*i + 1]]));
            *i += 2;
            v
        }
        _ => panic!("a vector longer than a canonical KeyPackage holds"),
    }
}

/// A canonical KeyPackage with its `init_key` and/or its leaf's `encryption_key` replaced, both
/// signatures redone with the member's own pseudonym key (what any invite holder can make).
fn resign_kp(
    bytes: &[u8],
    signer: &PseudonymSigner,
    init: Option<[u8; 32]>,
    enc: Option<[u8; 32]>,
) -> Vec<u8> {
    let mut b = bytes.to_vec();
    let kp_start = 4; // after the MlsMessage's version and wire format
    let mut i = kp_start + 4; // after the KeyPackage's version and suite
    assert_eq!(vlen(&b, &mut i), 32);
    if let Some(k) = init {
        b[i..i + 32].copy_from_slice(&k);
    }
    i += 32;
    let leaf_start = i;
    assert_eq!(vlen(&b, &mut i), 32);
    if let Some(k) = enc {
        b[i..i + 32].copy_from_slice(&k);
    }
    i += 32;
    let n = vlen(&b, &mut i); // signature key
    i += n;
    i += 2; // credential type
    let n = vlen(&b, &mut i); // identity
    i += n;
    for _ in 0..5 {
        let n = vlen(&b, &mut i); // the capabilities' five lists
        i += n;
    }
    assert_eq!(b[i], 1, "key_package source");
    i += 17; // source and the lifetime
    let n = vlen(&b, &mut i); // leaf extensions
    i += n;
    let leaf_tbs_end = i;
    assert_eq!(vlen(&b, &mut i), 64);
    let leaf_sig_at = i;
    i += 64;
    let n = vlen(&b, &mut i); // KeyPackage extensions
    i += n;
    let kp_tbs_end = i;
    assert_eq!(vlen(&b, &mut i), 64);
    let kp_sig_at = i;
    assert_eq!(i + 64, b.len());
    let sign = |label: &str, content: &[u8]| {
        let mut sc = vbytes(format!("MLS 1.0 {label}").as_bytes());
        sc.extend(vbytes(content));
        signer.sign_raw(&sc)
    };
    let ls = sign("LeafNodeTBS", &b[leaf_start..leaf_tbs_end]);
    b[leaf_sig_at..leaf_sig_at + 64].copy_from_slice(&ls);
    let ks = sign("KeyPackageTBS", &b[kp_start..kp_tbs_end]);
    b[kp_sig_at..kp_sig_at + 64].copy_from_slice(&ks);
    b
}

/// OpenMLS's own parse and validation of a KeyPackage (signatures, and only `init ≠ enc` of its
/// keys): what a committer that skips GHOST's canonical check would add.
fn openmls_kp(crypto: &CryptoProvider, bytes: &[u8]) -> KeyPackage {
    let m = MlsMessageIn::tls_deserialize_exact(bytes).unwrap();
    let MlsMessageBodyIn::KeyPackage(k) = m.extract() else {
        panic!("not a KeyPackage")
    };
    k.validate(crypto, ProtocolVersion::Mls10)
        .expect("OpenMLS accepts it")
}

/// An invite of the owner and a crafted KeyPackage of a new member with the evidence the owner's
/// commit carries for it, computed by hand (`join_verify` now refuses the KeyPackage itself).
fn crafted_admission(
    w: &mut World,
    init: Option<[u8; 32]>,
    enc: Option<[u8; 32]>,
) -> (Vec<u8>, AdmitEvidence) {
    let crypto = CryptoProvider::new().unwrap();
    let id = w.next_id;
    w.next_id += 1;
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
    let (_, fields) = invite::parse_v2(&inv.invite, None).unwrap();
    let a = Member::new(w.channel_id, id);
    let kp = a.ctx.key_package(&a.ch, Purpose::Join, w.day).unwrap();
    let crafted = resign_kp(&kp.key_package, &raw_signer(&a), init, enc);
    let kp_ref = openmls_kp(&crypto, &crafted)
        .hash_ref(&crypto)
        .unwrap()
        .as_slice()
        .to_vec();
    let key = derive::derive_invite_signing_key(&fields.invite_seed);
    let invite_sig = invite::sign_sponsor(
        &key,
        &join::invite_sig_message(&w.channel_id, &fields.invite_id, &crafted),
    );
    let ev = AdmitEvidence {
        kp_ref,
        invite_id: inv.issued.invite_id,
        invite_pk: inv.issued.invite_pk,
        expiry_day: inv.issued.expiry_day,
        sponsor: owner.p(),
        sponsor_sig: inv.issued.sponsor_sig,
        invite_sig,
    };
    (crafted, ev)
}

/// A commit of member `m` built with OpenMLS directly over its stored rows (a committer that skips
/// the crate's own checks): the Adds, a forced path with a canonical leaf, the AAD, and the
/// bootstrap of the current generation in the Welcome. Nothing is written back.
fn raw_commit(
    w: &World,
    m: &Member,
    adds: Vec<KeyPackage>,
    aad: &CommitAad,
) -> (Vec<u8>, Option<Vec<u8>>) {
    let crypto = CryptoProvider::new().unwrap();
    let p = GhostProvider {
        crypto: &crypto,
        storage: raw_storage(m, DAY),
    };
    let mut g = MlsGroup::load(&p.storage, &GroupId::from_slice(&m.channel_id()))
        .unwrap()
        .unwrap();
    let epoch = g.epoch().as_u64();
    g.set_aad(aad.encode());
    let leaf = ext::GhostLeaf {
        box_pk: canonical::box_public(&[9; 32]),
        refresh_epoch: epoch,
    };
    let params = LeafNodeParameters::builder()
        .with_capabilities(canonical::canonical_capabilities())
        .with_extensions(
            Extensions::from_vec(vec![Extension::Unknown(
                ext::EXT_LEAF,
                UnknownExtension(leaf.encode()),
            )])
            .unwrap(),
        )
        .build();
    let gen = m.generation.clone().unwrap();
    let gsec = m
        .ctx
        .unwrap_key(KeyClass::Generation, &w.channel_id, &gen.g_env)
        .unwrap();
    let boot = Bootstrap {
        generation: gen.generation,
        open_epoch: gen.open_epoch,
        g: *gsec,
    };
    let joiners = !adds.is_empty();
    let mut b = g
        .commit_builder()
        .propose_adds(adds)
        .force_self_update(true)
        .leaf_node_parameters(params)
        .load_psks(&p.storage)
        .unwrap();
    if joiners {
        b = b
            .create_group_info_with_extensions(vec![Extension::Unknown(
                ext::EXT_BOOTSTRAP,
                UnknownExtension(boot.encode()),
            )])
            .unwrap();
    }
    let bundle = b
        .create_group_info(false)
        .build(
            openmls::prelude::OpenMlsProvider::rand(&p),
            openmls::prelude::OpenMlsProvider::crypto(&p),
            &raw_signer(m),
            |_| true,
        )
        .unwrap()
        .stage_commit(&p)
        .unwrap();
    let (c, welcome, _) = bundle.into_messages();
    (
        c.tls_serialize_detached().unwrap(),
        welcome.map(|x| x.tls_serialize_detached().unwrap()),
    )
}

fn verdict(m: &Member, epoch: u64, commit: &[u8]) -> Box<ghost_client_mls::check::CommitSummary> {
    let r = m
        .ctx
        .receive(
            &m.ch,
            &WrappedRows(&m.wrapped()),
            epoch,
            &[commit.to_vec()],
            DAY,
        )
        .unwrap();
    match r.items.into_iter().next() {
        Some(ReceiveItem::Commit(s)) => s,
        other => panic!("{other:?}"),
    }
}

/// H1: a KeyPackage with a low-order `init_key` or leaf `encryption_key` is refused wherever one
/// enters — the canonical parse, the join request and its verification, and the committer's
/// commit, which names it by index (so the committer can defer it; the review's variant failed the
/// whole commit with `INVALID_POLICY`).
#[test]
fn low_order_hpke_keys_are_refused_wherever_a_key_package_enters() {
    let mut w = World::create(60, 0);
    w.admit(1);
    for (init, enc) in [(Some(low_order()), None), (None, Some(low_order()))] {
        let (crafted, ev) = crafted_admission(&mut w, init, enc);
        let o = &w.members[0];
        assert_eq!(
            canonical::parse_key_package(o.ctx.crypto(), &crafted, Some(&w.channel_id)).err(),
            Some(Fault::HpkeKey)
        );
        let mut req = w.request(0);
        req.adds.push((crafted.clone(), ev));
        assert_eq!(
            o.ctx
                .commit(&o.ch, &WrappedRows(&o.wrapped()), &req, w.day)
                .err(),
            Some(MlsError::at(Code::InvalidKeyPackage, 0))
        );
        // The rejoin path parses the same way.
        let rejoin = o.ctx.rejoin_request(&o.ch, 0, w.day, 1, &[0; 32], &crafted);
        assert_eq!(rejoin.err(), Some(MlsError::new(Code::InvalidKeyPackage)));
    }
    // The keys of an honest KeyPackage pass.
    let m = Member::new(w.channel_id, 60_999);
    let kp = m.ctx.key_package(&m.ch, Purpose::Join, w.day).unwrap();
    assert!(canonical::parse_key_package(m.ctx.crypto(), &kp.key_package, None).is_ok());
}

/// H1 on the receiving side: a committer that skips its own check adds a KeyPackage whose leaf key
/// is of low order (OpenMLS accepts it). Every member's CO-2 refuses the commit, the settle refuses
/// it too (it re-runs CO-2), and a joiner refuses the Welcome whose tree holds that leaf — while
/// the same commit without it is valid and joinable.
#[test]
fn co2_the_settle_and_the_joiner_refuse_a_tree_with_a_low_order_key() {
    let mut w = World::create(61, 0);
    w.admit(2);
    let epoch = w.members[1].epoch.as_ref().unwrap().epoch;
    let crypto = CryptoProvider::new().unwrap();
    let (crafted, ev_bad) = crafted_admission(&mut w, None, Some(low_order()));
    let (j, kp_j, ev_j, digest, expected) = w.invite_and_key_package(0);
    let with_bad = CommitAad {
        commit_minute: minute(w.day),
        admits: vec![ev_bad, ev_j.clone()],
        ..Default::default()
    };
    let (bad, bad_welcome) = raw_commit(
        &w,
        &w.members[0],
        vec![openmls_kp(&crypto, &crafted), openmls_kp(&crypto, &kp_j)],
        &with_bad,
    );
    let s = verdict(&w.members[1], epoch, &bad);
    assert_eq!(s.verdict, Err(CommitReason::NonCanonicalLeaf));
    let b = &w.members[1];
    let settled = b.ctx.settle(
        &b.ch,
        &WrappedRows(&b.wrapped()),
        Winner::Foreign(&bad),
        w.generation,
        w.day,
    );
    assert_eq!(
        settled.err(),
        Some(MlsError::commit(CommitReason::NonCanonicalLeaf))
    );
    let kp_ref_j = ev_j.kp_ref.clone();
    let join = |welcome: &[u8]| {
        let blob = WelcomeBlob {
            kp_ref: kp_ref_j.clone(),
            welcome: welcome.to_vec(),
        }
        .encode()
        .unwrap();
        j.ctx.welcome_join(
            &j.ch,
            &WrappedRows(&j.wrapped()),
            &blob,
            w.day,
            expected,
            &Anchor::Invite {
                committers_digest: digest,
            },
        )
    };
    assert_eq!(
        join(&bad_welcome.unwrap()).err(),
        Some(MlsError::new(Code::InvalidWelcome))
    );
    // The control: the same commit without the crafted KeyPackage.
    let good_aad = CommitAad {
        commit_minute: minute(w.day),
        admits: vec![ev_j],
        ..Default::default()
    };
    let (good, good_welcome) = raw_commit(
        &w,
        &w.members[0],
        vec![openmls_kp(&crypto, &kp_j)],
        &good_aad,
    );
    assert_eq!(verdict(&w.members[1], epoch, &good).verdict, Ok(()));
    assert!(join(&good_welcome.unwrap()).is_ok());
}

/// H1's check reads every node of a real tree (not vacuous): after a commit with a path in a
/// channel of five, the tree has parent nodes, and each of their keys and each leaf's is read.
#[test]
fn every_node_key_of_a_real_tree_is_read() {
    let mut w = World::create(62, 0);
    w.admit(4);
    let req = w.request(0);
    w.commit_and_settle(0, &req);
    let o = &w.members[0];
    let p = GhostProvider {
        crypto: o.ctx.crypto(),
        storage: raw_storage(o, DAY),
    };
    let g = MlsGroup::load(&p.storage, &GroupId::from_slice(&o.channel_id()))
        .unwrap()
        .unwrap();
    let tree = g.export_ratchet_tree();
    let parents: Vec<_> = tree.parents().collect();
    assert!(!parents.is_empty());
    assert!(parents
        .iter()
        .all(|n| canonical::parent_encryption_key(n).is_some()));
    assert_eq!(tree.leaves().count(), 5);
    assert!(tree
        .leaves()
        .all(|l| canonical::leaf_encryption_key(l).is_some()));
    assert!(canonical::tree_keys_valid(&tree));
    assert!(!canonical::valid_hpke_key(&low_order()));
    assert!(!canonical::valid_hpke_key(&[7; 31]));
}

/// H2: a post of a retained past epoch is attributed to the leaf that signed it in that epoch, not
/// to whoever holds the leaf index now (X removed, Y admitted at X's index in one commit).
#[test]
fn a_late_post_is_attributed_to_its_author_not_to_the_next_holder_of_its_leaf() {
    let mut w = World::create(63, 0);
    w.admit(2); // O leaf 0, B leaf 1, X leaf 2
    let x = w.members[2].p();
    let e1 = w.members[1].epoch.as_ref().unwrap().epoch;
    let m = w.post(2, &post("signed by X", 1));
    let (y, kp, ev, _digest, _expected) = w.invite_and_key_package(0);
    let mut req = w.request(0);
    req.removes.push(x);
    req.adds.push((kp, ev));
    w.commit_and_settle(0, &req);
    let b = &w.members[1];
    let r = b
        .ctx
        .receive(
            &b.ch,
            &WrappedRows(&b.wrapped()),
            e1,
            std::slice::from_ref(&m),
            DAY,
        )
        .unwrap();
    match &r.items[0] {
        ReceiveItem::App { sender, order, .. } => {
            assert_eq!(order.sender_leaf, 2, "Y now holds leaf 2");
            assert_eq!(*sender, x);
            assert_ne!(*sender, y.p());
        }
        other => panic!("{other:?}"),
    }
}

/// M1: a member re-seals another member's still-unread post of epoch e under `K_ep(e + 1)` of a
/// candidate. `trialCount` does not count its author as a successor sender, `open_blob` refuses
/// it, and `seal_blob` refuses to seal an order of another epoch than the key's.
#[test]
fn a_resealed_message_of_an_older_epoch_is_not_of_the_newer_epoch() {
    let mut w = World::create(64, 0);
    w.admit(3); // O 0, B 1, C 2, Z 3
    let z = w.members[3].p();
    let e1 = w.members[1].epoch.as_ref().unwrap().epoch;
    let mz = w.post(3, &post("Z at epoch 1", 7));
    let o = &w.members[0];
    let cand = o
        .ctx
        .commit(&o.ch, &WrappedRows(&o.wrapped()), &w.request(0), DAY)
        .unwrap();
    let c = &w.members[2];
    let s = c
        .ctx
        .settle(
            &c.ch,
            &WrappedRows(&c.wrapped()),
            Winner::Foreign(&cand.commit),
            0,
            DAY,
        )
        .unwrap();
    let k_env = s.epoch.unwrap().k_env;
    assert_eq!(k_env.len(), 68, "an epoch key's envelope names its epoch");
    let ns = c.generation.as_ref().unwrap().ns;
    let old = Order {
        epoch: e1,
        sender_leaf: 3,
        seq: 1,
    };
    let bucket = seal::bucket(mz.len(), 0).unwrap();
    // The API refuses to seal an order of another epoch than the key's.
    assert_eq!(
        c.ctx
            .seal_blob(
                &w.channel_id,
                &k_env,
                KeyClass::Epoch,
                &ns,
                bucket,
                seal::MODE_EPOCH,
                &old,
                &mz
            )
            .err(),
        Some(MlsError::new(Code::InvalidPolicy))
    );
    // A malicious member seals it with the primitive.
    let (k, e2) = c.ctx.unwrap_epoch_key(&w.channel_id, &k_env).unwrap();
    assert_eq!(e2, e1 + 1);
    let k = derive::EpochExport::from_bytes(*k);
    let lying = seal::seal(
        &seal::SealKeyInput::Epoch { key: &k, epoch: e1 },
        &ns,
        bucket,
        seal::MODE_EPOCH,
        &old,
        &mz,
        [7; 16],
    )
    .unwrap();
    assert_eq!(
        c.ctx
            .open_blob(
                &w.channel_id,
                &k_env,
                KeyClass::Epoch,
                &ns,
                seal::MODE_EPOCH,
                &lying
            )
            .err(),
        Some(MlsError::new(Code::NonCanonical))
    );
    let b = &w.members[1];
    let t = b
        .ctx
        .trial_count(
            &b.ch,
            &WrappedRows(&b.wrapped()),
            Winner::Foreign(&cand.commit),
            &[(ns, lying)],
            DAY,
        )
        .unwrap();
    assert!(
        !t.senders.contains(&z),
        "Z never saw the candidate, yet counted as its successor"
    );
    assert!(t.senders.is_empty());
}

/// M2 and the panic: the committer's size rule is the class floor every member applies; another
/// floor, a 16 KiB one in a small channel or 0, is refused before it is used.
#[test]
fn the_committer_applies_the_members_floor() {
    let mut w = World::create(65, 0);
    w.admit(1);
    for floor in [16_384, 0, 65_536, 4095] {
        let mut req = w.request(0);
        req.floor = floor;
        let o = &w.members[0];
        assert_eq!(
            o.ctx
                .commit(&o.ch, &WrappedRows(&o.wrapped()), &req, w.day)
                .err(),
            Some(MlsError::new(Code::InvalidPolicy)),
            "floor {floor}"
        );
    }
    assert_eq!(seal::capacity(0), 0);
}

/// A restore swap of B: the owner's commit request.
fn restore_request(w: &mut World, target: usize) -> (CommitRequest, Member) {
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
    (req, dev)
}

/// ML1: while the owner's restore swap of B is pending, `encrypt` refuses (CO-13 counts a swap as
/// a removal); B's replaced leaf — a seized device, for a restore — would read the post.
#[test]
fn a_pending_swap_holds_the_committers_posts() {
    let mut w = World::create(66, 0);
    w.admit(2);
    let (req, _dev) = restore_request(&mut w, 1);
    let o = &mut w.members[0];
    let out = o
        .ctx
        .commit(&o.ch, &WrappedRows(&o.wrapped()), &req, w.day)
        .unwrap();
    assert_eq!(out.kept_swaps, vec![0]);
    o.apply(out.changes);
    let e = o.ctx.encrypt(
        &o.ch,
        &WrappedRows(&o.wrapped()),
        &post("while the swap is pending", 3),
        1,
        w.day,
    );
    assert_eq!(e.err(), Some(MlsError::new(Code::PendingCommit)));
}

/// §6.6: a member removed by a commit settles it and learns it is removed; the leaf of a member
/// whose pseudonym a restore swap re-adds with another device's KeyPackage learns it is replaced.
/// Neither gets epoch keys (the group is inactive); both learn the rotation (the drain's end).
#[test]
fn a_removed_or_replaced_member_settles_its_own_removal() {
    let mut w = World::create(67, 0);
    w.admit(3);
    let victim = w.members[3].p();
    let mut req = w.request(0);
    req.removes.push(victim);
    let o = &w.members[0];
    let out = o
        .ctx
        .commit(&o.ch, &WrappedRows(&o.wrapped()), &req, w.day)
        .unwrap();
    let x = &w.members[3];
    let s = x
        .ctx
        .settle(
            &x.ch,
            &WrappedRows(&x.wrapped()),
            Winner::Foreign(&out.commit),
            0,
            w.day,
        )
        .unwrap();
    assert_eq!(s.standing, Standing::Removed);
    assert!(s.epoch.is_none() && s.rotated.is_none());
    assert!(s.rotates, "a removal rotates");
    assert_eq!(s.removed, vec![victim]);
    // Replaced: the owner restores B on a new device; B's old state settles the swap.
    let (req, _dev) = restore_request(&mut w, 1);
    let o = &w.members[0];
    let out = o
        .ctx
        .commit(&o.ch, &WrappedRows(&o.wrapped()), &req, w.day)
        .unwrap();
    let b = &w.members[1];
    let s = b
        .ctx
        .settle(
            &b.ch,
            &WrappedRows(&b.wrapped()),
            Winner::Foreign(&out.commit),
            0,
            w.day,
        )
        .unwrap();
    assert_eq!(s.standing, Standing::Replaced);
    assert!(s.epoch.is_none());
    // Another member stays.
    let c = &w.members[2];
    let s = c
        .ctx
        .settle(
            &c.ch,
            &WrappedRows(&c.wrapped()),
            Winner::Foreign(&out.commit),
            0,
            w.day,
        )
        .unwrap();
    assert_eq!(s.standing, Standing::Member);
    assert!(s.epoch.is_some() && s.rotated.is_some());
}

/// §5.9 and §19.28: an invite expires at most seven days after its issue day and not before it,
/// and a password invite needs a non-empty password, on both sides.
#[test]
fn invites_have_a_bounded_expiry_and_a_non_empty_password() {
    let w = World::create(68, 0);
    let o = &w.members[0];
    let g = o.generation.clone().unwrap();
    let build = |expiry: u32| {
        o.ctx.invite_build(
            &o.ch,
            &WrappedRows(&o.wrapped()),
            &g.g_env,
            g.generation,
            expiry,
            0,
            None,
            false,
            w.day,
        )
    };
    assert!(build(w.day).is_ok());
    let inv = build(w.day + 7).unwrap();
    for bad in [w.day + 8, w.day + 10_000, w.day - 1] {
        assert_eq!(build(bad).err(), Some(MlsError::new(Code::InvalidPolicy)));
    }
    let (_, fields) = invite::parse_v2(&inv.invite, None).unwrap();
    let empty = InvitePassword::from_bytes(Vec::new());
    assert_eq!(
        invite::build_v2(&fields, 1, Some(&empty), [3; 16]).err(),
        Some(MlsError::new(Code::PasswordRequired))
    );
    let pw = InvitePassword::from_bytes(b"cabin frost ladder margin orbit".to_vec());
    let link = invite::build_v2(&fields, 1, Some(&pw), [3; 16]).unwrap();
    assert_eq!(
        invite::parse_v2(&link, Some(&empty)).err(),
        Some(MlsError::new(Code::PasswordRequired))
    );
    assert_eq!(invite::parse_v2(&link, Some(&pw)).unwrap().1, fields);
}

/// The crate's own rule, "secrets never render": the recognition keys, the bearer credentials and
/// an open invite link stay out of every `Debug` of an output.
#[test]
fn outputs_render_without_their_secrets() {
    let w = World::create(69, 0);
    let o = &w.members[0];
    let e = o.epoch.clone().unwrap();
    let g = o.generation.clone().unwrap();
    let shown = format!("{e:?} {g:?}");
    for secret in [format!("{:?}", e.r_ep), format!("{:?}", g.r_join)] {
        assert!(!shown.contains(&secret), "{shown}");
    }
    let (_, creds) = o
        .ctx
        .generation(&w.channel_id, &g.g_env, g.generation, g.open_epoch, &[0, 1])
        .unwrap();
    for c in &creds {
        let shown = format!("{c:?}");
        assert!(
            !shown.contains(&format!("{:?}", c.read_credential)),
            "{shown}"
        );
        assert!(
            !shown.contains(&format!("{:?}", c.deposit_credential)),
            "{shown}"
        );
    }
    let inv = o
        .ctx
        .invite_build(
            &o.ch,
            &WrappedRows(&o.wrapped()),
            &g.g_env,
            g.generation,
            w.day + 7,
            0,
            None,
            false,
            w.day,
        )
        .unwrap();
    let shown = format!("{inv:?}");
    assert!(!shown.contains(&format!("{:?}", inv.invite)), "{shown}");
    assert!(shown.contains("invite_len: 335"));
}

/// CO-14 (§6.4, §19.5): a rank-255 commit for epoch e only from a leaf refreshed at most at
/// e − min(8, n). With three members (k = 3), member 1's KeyPackage leaf (refresh 0) may
/// self-update from epoch 3 on; before, its own check refuses it, and a member refuses one built
/// without that check. The summary carries CO-14's inputs.
#[test]
fn co14_bounds_rank_255_self_updates() {
    let mut w = World::create(70, 0);
    w.admit(2);
    let e1 = w.members[1].epoch.as_ref().unwrap().epoch;
    assert_eq!(e1, 1);
    let m1 = &w.members[1];
    assert_eq!(
        m1.ctx
            .commit(&m1.ch, &WrappedRows(&m1.wrapped()), &w.request(1), w.day)
            .err(),
        Some(MlsError::commit(CommitReason::Rate))
    );
    let (raw, _) = raw_commit(
        &w,
        m1,
        Vec::new(),
        &CommitAad {
            commit_minute: minute(w.day),
            ..Default::default()
        },
    );
    let s = verdict(&w.members[2], e1, &raw);
    assert_eq!(s.verdict, Err(CommitReason::Rate));
    assert_eq!(
        (s.sender_refresh_epoch, s.members, s.rank),
        (Some(0), 3, 255)
    );
    for _ in 0..2 {
        let req = w.request(0);
        w.commit_and_settle(0, &req);
    }
    // Epoch 3 = 0 + k: valid, and it refreshes the leaf to 3.
    let req = w.request(1);
    let out = w.commit_and_settle(1, &req);
    assert_eq!(out.summary.verdict, Ok(()));
    assert_eq!(out.summary.sender_refresh_epoch, Some(0));
    // Right after (epoch 4, refresh 3): refused again until epoch 6.
    let m1 = &w.members[1];
    assert_eq!(
        m1.ctx
            .commit(&m1.ch, &WrappedRows(&m1.wrapped()), &w.request(1), w.day)
            .err(),
        Some(MlsError::commit(CommitReason::Rate))
    );
}
