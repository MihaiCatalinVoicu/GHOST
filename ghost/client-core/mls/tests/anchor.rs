//! `welcome_join`'s committers anchor (S0-15, §19.27 TR-7, §19.29.2) and the constant KeyPackage
//! lifetime (Q42 (a), §19.29.1): the V10-8 forged-Welcome probes and the E-62/E-69/E-70 lifetime
//! probes of the S0 spike, moved into the crate (design §12.2).

mod support;

use ghost_client_mls::canonical::{self, SUITE};
use ghost_client_mls::derive::PseudonymSeed;
use ghost_client_mls::ext::{self, Bootstrap, CommitAad, KpBind, Purpose};
use ghost_client_mls::group::{Anchor, ReceiveItem};
use ghost_client_mls::join::WelcomeBlob;
use ghost_client_mls::kv::{GhostKv, WrappedRows};
use ghost_client_mls::provider::{GhostProvider, PseudonymSigner};
use ghost_client_mls::{Code, CommitReason, MlsError};
use openmls::prelude::tls_codec::{Deserialize as _, Serialize as _};
use openmls::prelude::*;
use openmls_libcrux_crypto::CryptoProvider;
use support::*;

fn credential(p: [u8; 32]) -> CredentialWithKey {
    CredentialWithKey {
        credential: BasicCredential::new(p.to_vec()).into(),
        signature_key: p.to_vec().into(),
    }
}

/// A group of the forger's own under the real channel id, with `committers` in its context and the
/// forger as its only member; the joiner's KeyPackage is added and the forged Welcome returned.
/// Built with OpenMLS directly: nothing in the crate's API makes a context whose committers are not
/// its own leaves.
fn forged_welcome(
    channel_id: [u8; 32],
    committers: Vec<[u8; 32]>,
    forger_seed: u8,
    kp: &[u8],
) -> Vec<u8> {
    let crypto = CryptoProvider::new().unwrap();
    let p = GhostProvider {
        crypto: &crypto,
        storage: GhostKv::new(channel_id, DAY),
    };
    let signer = PseudonymSigner::from_seed(&PseudonymSeed::from_bytes([forger_seed; 32]));
    let mut ctx = initial_context(channel_id, committers[0], 0);
    ctx.committers = committers;
    let exts = Extensions::from_vec(vec![
        Extension::Unknown(ext::EXT_CHANNEL_CONTEXT, UnknownExtension(ctx.encode())),
        canonical::required_capabilities(),
    ])
    .unwrap();
    let mut g = MlsGroup::builder()
        .with_group_id(GroupId::from_slice(&channel_id))
        .ciphersuite(SUITE)
        .use_ratchet_tree_extension(true)
        .lifetime(canonical::constant_lifetime())
        .with_capabilities(canonical::canonical_capabilities())
        .with_group_context_extensions(exts)
        .with_leaf_node_extensions(
            canonical::leaf_extensions(&ext::GhostLeaf {
                box_pk: canonical::box_public(&[forger_seed; 32]),
                refresh_epoch: 0,
            })
            .unwrap(),
        )
        .unwrap()
        .build(&p, &signer, credential(signer.public()))
        .unwrap();
    let kp = canonical::parse_key_package(&crypto, kp, Some(&channel_id)).unwrap();
    g.set_aad(CommitAad::default().encode());
    let boot = Bootstrap {
        generation: 0,
        open_epoch: 0,
        g: [0x42; 32],
    };
    let bundle = g
        .commit_builder()
        .propose_adds([kp.key_package])
        .force_self_update(true)
        .load_psks(p.storage())
        .unwrap()
        .create_group_info_with_extensions(vec![Extension::Unknown(
            ext::EXT_BOOTSTRAP,
            UnknownExtension(boot.encode()),
        )])
        .unwrap()
        .create_group_info(false)
        .build(p.rand(), p.crypto(), &signer, |_| true)
        .unwrap()
        .stage_commit(&p)
        .unwrap();
    let (_, w, _) = bundle.into_messages();
    w.unwrap().tls_serialize_detached().unwrap()
}

#[test]
fn forged_welcomes_are_refused_before_the_tree_and_the_key_package_stays() {
    let mut w = World::create(10, 0);
    w.admit(1); // a moderator candidate and a second member
    let (mut j, kp, ev, digest, expected) = w.invite_and_key_package(0);
    let rows_before = j.rows.clone();
    let kp_ref = ev.kp_ref.clone();
    let owner = w.members[0].p();
    // (a) the forger's own committers list: the digest differs from the invite's.
    // (b) the real list copied: the digest matches, but no anchored committer signed the GroupInfo.
    for committers in [vec![bytes32("forger", 1)], vec![owner]] {
        let welcome = forged_welcome(w.channel_id, committers, 0x33, &kp);
        let blob = WelcomeBlob {
            kp_ref: kp_ref.clone(),
            welcome,
        }
        .encode()
        .unwrap();
        let rows = j.wrapped();
        let r = j.ctx.welcome_join(
            &j.ch,
            &WrappedRows(&rows),
            &blob,
            DAY,
            expected,
            &Anchor::Invite {
                committers_digest: digest,
            },
        );
        assert_eq!(r.err(), Some(MlsError::new(Code::InvalidWelcome)));
        // Nothing is returned, so nothing is written: the KeyPackage and its keys stay.
        assert_eq!(j.rows, rows_before);
    }
    // The real Welcome still joins.
    let mut req = w.request(0);
    req.adds.push((kp, ev));
    let out = w.commit_and_settle(0, &req);
    let blob = WelcomeBlob {
        kp_ref,
        welcome: out.welcome.unwrap(),
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
            DAY,
            expected,
            &Anchor::Invite {
                committers_digest: digest,
            },
        )
        .unwrap();
    assert_eq!(
        joined.epoch.epoch_authenticator,
        w.members[0].epoch.as_ref().unwrap().epoch_authenticator
    );
    // The bootstrap names the invite's generation and its namespace.
    assert_eq!(joined.generation.ns, expected.1);
    // A second use of the same Welcome finds no KeyPackage: it was consumed by the join.
    j.apply(joined.changes);
    let rows = j.wrapped();
    let again = j.ctx.welcome_join(
        &j.ch,
        &WrappedRows(&rows),
        &blob,
        DAY,
        expected,
        &Anchor::Invite {
            committers_digest: digest,
        },
    );
    assert!(again.is_err());
}

#[test]
fn a_rejoin_anchor_checks_the_signature_only() {
    let mut w = World::create(11, 0);
    let (j, kp, ev, _digest, expected) = w.invite_and_key_package(0);
    let owner = w.members[0].p();
    let mut req = w.request(0);
    req.adds.push((kp.clone(), ev.clone()));
    let out = w.commit_and_settle(0, &req);
    let blob = WelcomeBlob {
        kp_ref: ev.kp_ref.clone(),
        welcome: out.welcome.unwrap(),
    }
    .encode()
    .unwrap();
    let rows = j.wrapped();
    // Signed by one of the last committers: accepted without any digest comparison.
    let ok = j.ctx.welcome_join(
        &j.ch,
        &WrappedRows(&rows),
        &blob,
        DAY,
        expected,
        &Anchor::Rejoin {
            last_committers: vec![bytes32("someone", 0), owner],
        },
    );
    assert!(ok.is_ok(), "{:?}", ok.err());
    // Not signed by any of them: refused before the tree.
    let refused = j.ctx.welcome_join(
        &j.ch,
        &WrappedRows(&rows),
        &blob,
        DAY,
        expected,
        &Anchor::Rejoin {
            last_committers: vec![bytes32("someone", 0)],
        },
    );
    assert_eq!(refused.err(), Some(MlsError::new(Code::InvalidWelcome)));
    // A wrong invite digest is refused too (the join anchor).
    let wrong = j.ctx.welcome_join(
        &j.ch,
        &WrappedRows(&rows),
        &blob,
        DAY,
        expected,
        &Anchor::Invite {
            committers_digest: [0; 32],
        },
    );
    assert_eq!(wrong.err(), Some(MlsError::new(Code::InvalidWelcome)));
    // A Welcome arriving in the invite's generation must match its namespace (§5.4).
    let bad_ns = j.ctx.welcome_join(
        &j.ch,
        &WrappedRows(&rows),
        &blob,
        DAY,
        (expected.0, [9; 32]),
        &Anchor::Rejoin {
            last_committers: vec![owner],
        },
    );
    assert_eq!(bad_ns.err(), Some(MlsError::new(Code::InvalidBootstrap)));
}

/// A KeyPackage of a member, with a given lifetime, built with OpenMLS directly (the crate's
/// `key_package` only makes the canonical one).
fn key_package_with_lifetime(channel_id: [u8; 32], seed: u8, lifetime: Lifetime) -> Vec<u8> {
    let crypto = CryptoProvider::new().unwrap();
    let p = GhostProvider {
        crypto: &crypto,
        storage: GhostKv::new(channel_id, DAY),
    };
    let signer = PseudonymSigner::from_seed(&PseudonymSeed::from_bytes([seed; 32]));
    let bind = KpBind {
        channel_id,
        purpose: Purpose::Join,
        day: DAY,
    };
    let b = KeyPackage::builder()
        .key_package_lifetime(lifetime)
        .leaf_node_capabilities(canonical::canonical_capabilities())
        .leaf_node_extensions(
            canonical::leaf_extensions(&ext::GhostLeaf {
                box_pk: canonical::box_public(&[seed; 32]),
                refresh_epoch: 0,
            })
            .unwrap(),
        )
        .key_package_extensions(
            Extensions::single(Extension::Unknown(
                ext::EXT_KP_BIND,
                UnknownExtension(bind.encode()),
            ))
            .unwrap(),
        )
        .build(SUITE, &p, &signer, credential(signer.public()))
        .unwrap();
    MlsMessageOut::from(b.key_package().clone())
        .tls_serialize_detached()
        .unwrap()
}

#[test]
fn the_constant_lifetime_is_accepted_and_a_finite_one_is_invalid_on_both_branches() {
    let w = World::create(12, 0);
    let ch = w.channel_id;
    let crypto = CryptoProvider::new().unwrap();
    // The constant lifetime: canonical, 395 bytes, accepted by `KeyPackageIn::validate`.
    let constant = key_package_with_lifetime(ch, 5, canonical::constant_lifetime());
    assert_eq!(constant.len(), 395);
    assert!(canonical::parse_key_package(&crypto, &constant, Some(&ch)).is_ok());
    // A finite lifetime that is valid now: OpenMLS accepts it (the accept branch), GHOST refuses
    // it as non-canonical — at admission and in CO-2 (§19.29.1).
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let finite = key_package_with_lifetime(ch, 6, Lifetime::init(now - 86_400, now + 86_400));
    assert_eq!(
        finite.len(),
        395,
        "a lifetime is two fixed u64s: the size does not change"
    );
    assert_eq!(
        canonical::parse_key_package(&crypto, &finite, Some(&ch)).err(),
        Some(canonical::Fault::Lifetime)
    );
    // An expired lifetime: OpenMLS itself refuses (the refusal branch).
    let expired = key_package_with_lifetime(ch, 7, Lifetime::init(0, now - 60));
    assert_eq!(
        canonical::parse_key_package(&crypto, &expired, Some(&ch)).err(),
        Some(canonical::Fault::Signature),
        "KeyPackageIn::validate refuses an expired lifetime"
    );
}

/// A received Add of an expired finite-lifetime KeyPackage: every member's `process_message`
/// refuses it with `LifetimeError`, which is `INVALID_COMMIT(Lifetime)` — invalid for every member,
/// never a pending candidate (E-70; the insider's junk commit blocks nothing).
#[test]
fn an_expired_add_is_invalid_commit_lifetime() {
    let mut w = World::create(13, 0);
    w.admit(1);
    let ch = w.channel_id;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    // Valid for 3 more seconds when committed (OpenMLS's committer-side check passes), expired by
    // the time the receiver processes it.
    let short = key_package_with_lifetime(ch, 8, Lifetime::init(0, now + 3));
    let owner = &w.members[0];
    let crypto = CryptoProvider::new().unwrap();
    let rows = owner.wrapped();
    let src = WrappedRows(&rows);
    let storage = GhostKv::new(ch, DAY);
    storage
        .load(
            ghost_client_mls::kv::RowSource::load(
                &src,
                &ch,
                &ghost_client_mls::derive::StateKey::from_bytes(bytes32("state", 13 * 1000)),
            )
            .unwrap(),
        )
        .unwrap();
    let p = GhostProvider {
        crypto: &crypto,
        storage,
    };
    let signer = PseudonymSigner::from_seed(&PseudonymSeed::from_bytes(bytes32("ps", 13 * 1000)));
    let mut g = MlsGroup::load(p.storage(), &GroupId::from_slice(&ch))
        .unwrap()
        .unwrap();
    let kp = match MlsMessageIn::tls_deserialize_exact(&short)
        .unwrap()
        .extract()
    {
        MlsMessageBodyIn::KeyPackage(k) => k.validate(&crypto, ProtocolVersion::Mls10).unwrap(),
        _ => unreachable!(),
    };
    g.set_aad(
        CommitAad {
            commit_minute: minute(DAY),
            ..Default::default()
        }
        .encode(),
    );
    let epoch = g.epoch().as_u64();
    let bundle = g
        .commit_builder()
        .propose_adds([kp])
        .force_self_update(true)
        .leaf_node_parameters(
            LeafNodeParameters::builder()
                .with_capabilities(canonical::canonical_capabilities())
                .with_extensions(
                    canonical::leaf_extensions(&ext::GhostLeaf {
                        box_pk: canonical::box_public(&[9; 32]),
                        refresh_epoch: epoch,
                    })
                    .unwrap(),
                )
                .build(),
        )
        .load_psks(p.storage())
        .unwrap()
        .create_group_info(false)
        .build(p.rand(), p.crypto(), &signer, |_| true)
        .unwrap()
        .stage_commit(&p)
        .unwrap();
    let commit = bundle.into_messages().0.tls_serialize_detached().unwrap();
    std::thread::sleep(std::time::Duration::from_secs(4));
    let m = &w.members[1];
    let rows = m.wrapped();
    let r = m
        .ctx
        .receive(&m.ch, &WrappedRows(&rows), epoch, &[commit], DAY)
        .unwrap();
    match &r.items[0] {
        ReceiveItem::Failed(e) => assert_eq!(*e, MlsError::commit(CommitReason::Lifetime)),
        other => panic!("{other:?}"),
    }
}
