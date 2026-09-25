//! V10-13: `GhostLeaf.refresh_epoch` through `leaf_node_parameters` reaches the update-path leaf
//! and is readable from the staged commit; `GhostKpBind` (0xF0A4) is accepted as a KeyPackage
//! extension; `set_aad` on commits round-trips through `ProcessedMessage::aad`; on application
//! messages `ChannelOrder` is readable before decryption through `PrivateMessageIn::aad` and reset
//! after each message (design §14 S0, §19.2, §19.5, §19.18).

use ghost_mls_spike::ext::{self, CommitAad};
use ghost_mls_spike::harness::*;
use openmls::prelude::tls_codec::Deserialize as _;
use openmls::prelude::*;

#[test]
fn v10_13_extensions_and_aad() {
    let day = host_day();
    let mut w = World::build(3, 2, day);
    let ch = w.channel;
    println!("V10-13 world: 3 members, epoch {}", w.members[0].epoch(ch));

    // (1) GhostKpBind as a KeyPackage extension: accepted when the leaf lists 0xF0A4 ...
    let mut j = Device::new(10, day);
    let kp = j.key_package(ch, 1, day, 0).expect("kp");
    let parsed = w.members[0]
        .parse_key_package(&kp)
        .expect("KeyPackage with GhostKpBind parses and validates");
    let bind = parsed
        .extensions()
        .unknown(ext::EXT_KP_BIND)
        .expect("0xF0A4 present")
        .0
        .clone();
    assert_eq!(bind, ext::kp_bind(&ch, 1, day));
    println!(
        "V10-13 GhostKpBind accepted: KeyPackage {} B, extension {} B",
        kp.len(),
        bind.len()
    );

    // ... and refused by OpenMLS itself when the leaf capabilities omit it.
    let err = {
        let box_pk = [9u8; 32];
        let cred = j.credential();
        j.call(&ch, |p, s| {
            let kpb = KeyPackage::builder()
                .key_package_lifetime(ghost_lifetime(day))
                .leaf_node_capabilities(Capabilities::new(
                    None,
                    Some(&[SUITE]),
                    Some(&[
                        ExtensionType::Unknown(ext::EXT_CHANNEL_CONTEXT),
                        ExtensionType::Unknown(ext::EXT_LEAF),
                    ]),
                    None,
                    Some(&[CredentialType::Basic]),
                ))
                .leaf_node_extensions(leaf_extensions(&box_pk, 0))
                .key_package_extensions(
                    Extensions::single(Extension::Unknown(
                        ext::EXT_KP_BIND,
                        UnknownExtension(ext::kp_bind(&ch, 1, day)),
                    ))
                    .unwrap(),
                )
                .build(SUITE, p, s, cred);
            match kpb {
                Ok(b) => Ok::<_, String>(ser(&MlsMessageOut::from(b.key_package().clone()))),
                Err(e) => Err(format!("build: {e:?}")),
            }
        })
    };
    match err {
        Ok(bytes) => {
            let r = w.members[0].parse_key_package(&bytes);
            println!(
                "V10-13 KeyPackage without 0xF0A4 in capabilities: built; committer parse -> {r:?}"
            );
            assert!(r.is_err());
        }
        Err(e) => {
            println!("V10-13 KeyPackage without 0xF0A4 in capabilities: refused at build -> {e}")
        }
    }

    // (2) refresh_epoch through leaf_node_parameters, read from the staged commit, and (3) the
    // commit AAD round trip.
    let e = w.members[1].epoch(ch);
    let aad = CommitAad {
        commit_minute: day * 1440 + 777,
        rotate: true,
        ..Default::default()
    };
    let spec = CommitSpec {
        aad: aad.clone(),
        refresh_epoch: Some(e),
        force_path: true,
        ..Default::default()
    };
    let out = w.members[1].commit(ch, &spec).expect("self-update");
    let r = w.members[2].receive(ch, &out.commit).expect("process");
    assert_eq!(r.kind, "commit");
    assert_eq!(
        r.aad,
        aad.encode(),
        "GhostCommitAad round-trips through ProcessedMessage::aad"
    );
    let leaf = r
        .update_leaf_ext
        .expect("update-path leaf carries GhostLeaf");
    assert_eq!(
        ext::leaf_decode(&leaf).expect("GhostLeaf decodes").1,
        e,
        "refresh_epoch = the commit's epoch"
    );
    println!(
        "V10-13 commit AAD {} B round-trips; update-path GhostLeaf refresh_epoch = {e}",
        aad.encode().len()
    );
    w.members[0]
        .receive(ch, &out.commit)
        .expect("owner processes");
    w.members[1].merge_own(ch).expect("merge own");

    // (4) The committer's next message carries no stale AAD: set_aad is reset by stage_commit.
    let m = w.members[1].call(&ch, |p, s| {
        let mut g = Device::load(p, &ch)?;
        assert!(
            g.aad().is_empty(),
            "AAD reset after the commit (and not persisted)"
        );
        let m = g
            .create_message(p, s, b"no aad")
            .map_err(|e| format!("{e:?}"))?;
        Ok::<_, String>(ser(&m))
    });
    let r = w.members[2].receive(ch, &m.unwrap()).expect("app");
    assert!(r.aad.is_empty());

    // (5) ChannelOrder on application messages: readable before decryption, reset after each.
    let sender_leaf = w.members[1].leaf_index(ch);
    let bytes = w.members[1]
        .encrypt(ch, 41, b"post with order")
        .expect("encrypt");
    let pre = match MlsMessageIn::tls_deserialize_exact(&bytes)
        .unwrap()
        .extract()
    {
        MlsMessageBodyIn::PrivateMessage(pm) => {
            (pm.aad().to_vec(), pm.epoch().as_u64(), pm.content_type())
        }
        _ => panic!("expected a PrivateMessage"),
    };
    assert_eq!(
        pre.0,
        ext::channel_order(sender_leaf, 41),
        "ChannelOrder readable before decryption"
    );
    assert_eq!(pre.2, ContentType::Application);
    println!(
        "V10-13 ChannelOrder read before decryption: {} B, epoch {}, content type {:?}",
        pre.0.len(),
        pre.1,
        pre.2
    );
    let r = w.members[2].receive(ch, &bytes).expect("decrypt");
    assert_eq!(r.aad, pre.0);
    assert_eq!(r.sender, Some(sender_leaf));
    let second = w.members[1].call(&ch, |p, s| {
        let mut g = Device::load(p, &ch)?;
        g.set_aad(ext::channel_order(sender_leaf, 42));
        let a = g
            .create_message(p, s, b"one")
            .map_err(|e| format!("{e:?}"))?;
        let b = g
            .create_message(p, s, b"two, no set_aad")
            .map_err(|e| format!("{e:?}"))?;
        Ok::<_, String>((ser(&a), ser(&b)))
    });
    let (a, b) = second.unwrap();
    let ra = w.members[2].receive(ch, &a).unwrap();
    let rb = w.members[2].receive(ch, &b).unwrap();
    assert_eq!(ra.aad, ext::channel_order(sender_leaf, 42));
    assert!(
        rb.aad.is_empty(),
        "set_aad applies to exactly the next message"
    );
    println!(
        "V10-13 set_aad applies to the next message only; the one after carries {} AAD bytes",
        rb.aad.len()
    );
    assert!(w.authenticators_agree());
    println!("V10-13 OK");
}
