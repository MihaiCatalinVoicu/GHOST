//! End-to-end channel operations over the public API with value semantics: creation, invites,
//! admissions with evidence (CO-2 on every member), Welcomes with the committers anchor, posts in
//! batches, settles, removals that rotate the generation, and the canonical KeyPackage.

mod support;

use ghost_client_mls::content::{Body, ChannelContent, KIND_POST};
use ghost_client_mls::ext::ChannelOrder;
use ghost_client_mls::group::{KeyClass, ReceiveItem};
use ghost_client_mls::kv::WrappedRows;
use ghost_client_mls::seal::{self, EpochContent, Order};
use ghost_client_mls::{Code, MlsError};
use support::*;

fn post_content(text: &str, op: u8) -> Vec<u8> {
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

#[test]
fn create_admit_post_receive_remove() {
    let mut w = World::create(1, 0);
    let out = w.admit(3);
    assert_eq!(out.joiners.len(), 3);
    assert_eq!(w.members.len(), 4);
    let a = w.authenticators();
    assert!(
        a.windows(2).all(|p| p[0] == p[1]),
        "every member in the same epoch"
    );

    // Member 1 posts three messages; member 2 receives them in one batch (peek order).
    let posts: Vec<Vec<u8>> = (0..3)
        .map(|i| w.post(1, &post_content(&format!("hello {i}"), i)))
        .collect();
    let epoch = w.members[2].epoch.as_ref().unwrap().epoch;
    let author = w.members[1].p();
    let m = &mut w.members[2];
    let rows = m.wrapped();
    let r = m
        .ctx
        .receive(&m.ch, &WrappedRows(&rows), epoch, &posts, DAY)
        .unwrap();
    assert_eq!(r.items.len(), 3);
    for (i, item) in r.items.iter().enumerate() {
        match item {
            ReceiveItem::App {
                content,
                order,
                sender,
            } => {
                assert_eq!(
                    content.body,
                    Body::Post {
                        text: format!("hello {i}"),
                        reply_to: None
                    }
                );
                assert_eq!(order.seq, i as u32 + 1);
                assert_eq!(*sender, author);
            }
            other => panic!("{other:?}"),
        }
    }
    m.apply(r.changes);
    // A replay of a consumed message is refused and rolled back; the rest of the batch is kept.
    let rows = m.wrapped();
    let r2 = m
        .ctx
        .receive(&m.ch, &WrappedRows(&rows), epoch, &posts[..1], DAY)
        .unwrap();
    assert!(matches!(r2.items[0], ReceiveItem::Failed(e) if e.code == Code::Undecryptable));
    assert!(r2.changes.is_empty());

    // The author sees its own message as OWN (evidence of nothing).
    let a1 = &w.members[1];
    let rows = a1.wrapped();
    let r3 = a1
        .ctx
        .receive(&a1.ch, &WrappedRows(&rows), epoch, &posts[..1], DAY)
        .unwrap();
    assert!(matches!(r3.items[0], ReceiveItem::Own));

    // The owner removes member 3: the commit rotates the generation (§6.5).
    let victim = w.members[3].p();
    let mut req = w.request(0);
    req.removes.push(victim);
    let g_before = w.members[0].generation.clone().unwrap();
    let out = w.commit_and_settle(0, &req);
    assert!(out.rotates);
    assert_eq!(w.members.len(), 3);
    let g_after = w.members[0].generation.clone().unwrap();
    assert_eq!(g_after.generation, g_before.generation + 1);
    assert_ne!(g_after.ns, g_before.ns);
    for m in &w.members {
        assert_eq!(m.generation.as_ref().unwrap().ns, g_after.ns);
    }
    let a = w.authenticators();
    assert!(a.windows(2).all(|p| p[0] == p[1]));
}

#[test]
fn seal_and_open_an_epoch_message() {
    let mut w = World::create(2, 0);
    w.admit(1);
    let content = post_content("sealed", 9);
    let mls = w.post(0, &content);
    let epoch = w.members[0].epoch.as_ref().unwrap().epoch;
    let order = Order {
        epoch,
        sender_leaf: 0,
        seq: 1,
    };
    let blob = w.seal_epoch(0, &mls, order);
    assert_eq!(blob.len(), 4096);
    let m = &w.members[1];
    let e = m.epoch.as_ref().unwrap();
    let g = m.generation.as_ref().unwrap();
    let opened = m
        .ctx
        .open_blob(
            &w.channel_id,
            &e.k_env,
            KeyClass::Epoch,
            &g.ns,
            seal::MODE_EPOCH,
            &blob,
        )
        .unwrap();
    assert_eq!(opened.body, mls);
    let h = opened.header.unwrap();
    assert_eq!(h.content, EpochContent::Application);
    assert_eq!(
        h.channel_order,
        Some(ChannelOrder {
            sender_leaf: 0,
            seq: 1
        })
    );
    // CS-S7: a re-seal under a false order is refused before any decryption.
    let lie = w.seal_epoch(
        0,
        &mls,
        Order {
            epoch,
            sender_leaf: 1,
            seq: 1,
        },
    );
    assert_eq!(
        m.ctx.open_blob(
            &w.channel_id,
            &e.k_env,
            KeyClass::Epoch,
            &g.ns,
            seal::MODE_EPOCH,
            &lie
        ),
        Err(MlsError::new(Code::NonCanonical))
    );
}

#[test]
fn the_canonical_key_package_is_395_bytes() {
    let w = World::create(3, 0);
    let m = Member::new(w.channel_id, 77);
    for purpose in [
        ghost_client_mls::ext::Purpose::Join,
        ghost_client_mls::ext::Purpose::Rejoin,
        ghost_client_mls::ext::Purpose::Restore,
    ] {
        let kp = m.ctx.key_package(&m.ch, purpose, DAY).unwrap();
        assert_eq!(kp.key_package.len(), 395);
        let parsed = ghost_client_mls::canonical::parse_key_package(
            m.ctx.crypto(),
            &kp.key_package,
            Some(&w.channel_id),
        )
        .unwrap();
        assert_eq!(parsed.pseudonym, m.p());
        assert_eq!(parsed.bind.purpose, purpose);
        assert!(ghost_client_mls::canonical::is_constant_lifetime(
            parsed.key_package.life_time()
        ));
        // Only global rows: the KeyPackage bundle and its private keys (§3.4 point 1).
        assert!(kp
            .changes
            .iter()
            .all(|c| c.scope == ghost_client_mls::kv::Scope::Global));
    }
}
