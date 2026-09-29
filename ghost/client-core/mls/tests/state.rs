//! The adapter under value semantics (design §3.4, S0-6, S0-17): the reload oracle's two halves on
//! scripted groups (point 6), batched receive with per-item rollback (point 9), late and
//! out-of-order posts across retained epochs and the sweep (§8.3), the trial count (CO-3), the
//! own pending commit (fn 8, fn 10), the day rewrite (point 5) and the one-worker pool (§3.6).

mod support;

use ghost_client_mls::content::{Body, ChannelContent, KIND_POST};
use ghost_client_mls::group::{KeyClass, ReceiveItem, Winner};
use ghost_client_mls::kv::{label_of, Scope, WrappedRows};
use ghost_client_mls::seal::Order;
use ghost_client_mls::{Code, MlsError};
use openmls::prelude::{GroupId, MlsGroup};
use openmls_libcrux_crypto::CryptoProvider;
use support::Member;
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

/// The fingerprint half of the reload oracle (§3.4 point 6): what the call returned — epoch,
/// `epoch_authenticator`, `K_ep` (an exporter output) — against the group reloaded from the rows
/// its change-set produced, read with OpenMLS directly; plus the tree hash and own leaf of the
/// reloaded group against `roster()`.
fn reload_oracle(m: &Member) {
    let crypto = CryptoProvider::new().unwrap();
    let kv = raw_storage(m, DAY);
    let g = MlsGroup::load(&kv, &GroupId::from_slice(&m.channel_id()))
        .unwrap()
        .expect("the stored rows hold the group");
    let e = m.epoch.as_ref().unwrap();
    assert_eq!(g.epoch().as_u64(), e.epoch);
    assert_eq!(
        g.epoch_authenticator().as_slice(),
        e.epoch_authenticator.as_slice()
    );
    let k = g
        .export_secret(&crypto, "ghost/v1/ch/epoch", &m.channel_id(), 32)
        .unwrap();
    let k_env = m
        .ctx
        .unwrap_key(KeyClass::Epoch, &m.channel_id(), &e.k_env)
        .unwrap();
    assert_eq!(
        k.as_slice(),
        k_env.as_slice(),
        "K_ep of the call equals the reloaded exporter"
    );
    let rows = m.wrapped();
    let roster = m.ctx.roster(&m.ch, &WrappedRows(&rows), DAY).unwrap();
    assert_eq!(
        roster.tree_hash,
        g.public_group().group_context().tree_hash()
    );
    assert_eq!(roster.own_leaf, g.own_leaf_index().u32());
    assert_eq!(roster.epoch, e.epoch);
}

#[test]
fn reload_oracle_fingerprint_half_after_every_call() {
    let mut w = World::create(20, 0);
    reload_oracle(&w.members[0]);
    for _ in 0..3 {
        w.admit(1);
        for m in &w.members {
            reload_oracle(m);
        }
    }
    let victim = w.members[2].p();
    let mut req = w.request(0);
    req.removes.push(victim);
    w.commit_and_settle(0, &req);
    for m in &w.members {
        reload_oracle(m);
    }
    // A member's rank-255 self-update (an empty commit with a path).
    let req = w.request(1);
    w.commit_and_settle(1, &req);
    for m in &w.members {
        reload_oracle(m);
    }
}

/// The behavioural half (§3.4 point 6): under value semantics every call is a reload, so a member
/// that received a post decrypts the next one of the same sender from the stored rows and refuses
/// a replay of the one it consumed (the property GHSA-qr9h-x63w-vqfm broke: a secret tree not
/// persisted after processing). Late and out-of-order posts across retained epochs, and the sweep.
#[test]
fn reload_oracle_behavioural_half_late_posts_and_the_sweep() {
    let mut w = World::create(21, 0);
    w.admit(2);
    let e0 = w.members[0].epoch.as_ref().unwrap().epoch;
    let p: Vec<Vec<u8>> = (1..=3u8)
        .map(|i| w.post(0, &post(&format!("p{i}"), i)))
        .collect();
    // Six epochs pass; member 1 processes every commit but none of the posts yet.
    for _ in 0..6 {
        let req = w.request(0);
        w.commit_and_settle(0, &req);
    }
    let recv = |m: &mut Member, epoch: u64, msg: &Vec<u8>| -> Result<String, MlsError> {
        let rows = m.wrapped();
        let r = m
            .ctx
            .receive(
                &m.ch,
                &WrappedRows(&rows),
                epoch,
                std::slice::from_ref(msg),
                DAY,
            )
            .unwrap();
        m.apply(r.changes);
        match &r.items[0] {
            ReceiveItem::App { content, .. } => match &content.body {
                Body::Post { text, .. } => Ok(text.clone()),
                _ => unreachable!(),
            },
            ReceiveItem::Failed(e) => Err(*e),
            other => panic!("{other:?}"),
        }
    };
    let m1 = &mut w.members[1];
    // Late and out of order inside the retained epoch e0, then a replay.
    assert_eq!(recv(m1, e0, &p[2]), Ok("p3".into()));
    assert_eq!(recv(m1, e0, &p[0]), Ok("p1".into()));
    assert_eq!(recv(m1, e0, &p[0]), Err(MlsError::new(Code::Undecryptable)));
    assert_eq!(recv(m1, e0, &p[1]), Ok("p2".into()));
    // The sweep keeps 2 past epochs: a post of e0 (now 6 behind) no longer decrypts.
    let q = w.post(0, &post("q", 9));
    let rows = w.members[2].wrapped();
    let m2 = &mut w.members[2];
    let swept = m2
        .ctx
        .sweep_past(&m2.ch, &WrappedRows(&rows), 2, DAY)
        .unwrap();
    assert!(
        swept.iter().any(|c| c.env.is_none()),
        "the sweep deletes past-epoch rows"
    );
    m2.apply(swept);
    assert_eq!(recv(m2, e0, &p[0]), Err(MlsError::new(Code::Undecryptable)));
    let now = m2.epoch.as_ref().unwrap().epoch;
    assert_eq!(recv(m2, now, &q), Ok("q".into()));
}

#[test]
fn a_failed_item_rolls_back_alone_inside_a_batch() {
    let mut w = World::create(22, 0);
    w.admit(1);
    let a = w.post(0, &post("a", 1));
    let b = w.post(0, &post("b", 2));
    let epoch = w.members[1].epoch.as_ref().unwrap().epoch;
    let mut garbage = a.clone();
    let last = garbage.len() - 1;
    garbage[last] ^= 1;
    let m = &mut w.members[1];
    let rows = m.wrapped();
    let r = m
        .ctx
        .receive(
            &m.ch,
            &WrappedRows(&rows),
            epoch,
            &[a.clone(), garbage, b.clone()],
            DAY,
        )
        .unwrap();
    assert!(matches!(r.items[0], ReceiveItem::App { .. }));
    assert!(matches!(r.items[1], ReceiveItem::Failed(_)));
    assert!(matches!(r.items[2], ReceiveItem::App { .. }));
    m.apply(r.changes);
    // The change-set is the net of the successful items: both are consumed.
    let rows = m.wrapped();
    let again = m
        .ctx
        .receive(&m.ch, &WrappedRows(&rows), epoch, &[a, b], DAY)
        .unwrap();
    assert!(again
        .items
        .iter()
        .all(|i| matches!(i, ReceiveItem::Failed(e) if e.code == Code::Undecryptable)));
    assert!(again.changes.is_empty());
    // A commit is refused inside a batch; a batch above 32 is refused.
    let too_many = vec![vec![0u8; 3]; 33];
    assert_eq!(
        m.ctx
            .receive(&m.ch, &WrappedRows(&rows), epoch, &too_many, DAY)
            .err(),
        Some(MlsError::new(Code::InvalidPolicy))
    );
    // Rows that do not open under the state key: STATE_CORRUPT, nothing returned.
    let mut bad = m.wrapped();
    bad[0].env[20] ^= 1;
    assert_eq!(
        m.ctx
            .receive(&m.ch, &WrappedRows(&bad), epoch, &[vec![0u8; 3]], DAY)
            .err(),
        Some(MlsError::new(Code::StateCorrupt))
    );
}

#[test]
fn trial_count_counts_successor_senders_and_writes_nothing() {
    let mut w = World::create(23, 0);
    w.admit(2);
    // CO-14 (k = min(8, n) = 3 with three members): a rank-255 self-update of a KeyPackage leaf
    // (refresh_epoch 0) is valid from epoch 3; two passes of the owner get there.
    for _ in 0..2 {
        let req = w.request(0);
        w.commit_and_settle(0, &req);
    }
    let epoch = w.members[0].epoch.as_ref().unwrap().epoch;
    // The owner's commit X; member 1 settles it and posts in the next epoch.
    let rows = w.members[0].wrapped();
    let x = w.members[0]
        .ctx
        .commit(&w.members[0].ch, &WrappedRows(&rows), &w.request(0), DAY)
        .unwrap();
    {
        let m1 = &mut w.members[1];
        let rows = m1.wrapped();
        let s = m1
            .ctx
            .settle(
                &m1.ch,
                &WrappedRows(&rows),
                Winner::Foreign(&x.commit),
                0,
                DAY,
            )
            .unwrap();
        m1.apply(s.changes);
        m1.epoch = s.epoch;
    }
    let successor = w.post(1, &post("after X", 7));
    let order = Order {
        epoch: epoch + 1,
        sender_leaf: 1,
        seq: w.members[1].seq,
    };
    let blob = w.seal_epoch(1, &successor, order);
    let ns = w.members[1].generation.as_ref().unwrap().ns;
    // Member 2 has not settled: the blob does not open under its keys, so it trials X.
    let m2 = &w.members[2];
    let rows = m2.wrapped();
    let t = m2
        .ctx
        .trial_count(
            &m2.ch,
            &WrappedRows(&rows),
            Winner::Foreign(&x.commit),
            &[(ns, blob.clone())],
            DAY,
        )
        .unwrap();
    assert_eq!(t.committer, w.members[0].p());
    assert_eq!(t.senders, vec![w.members[1].p()]);
    // Another candidate (member 2's own self-update, kept pending) has no successor.
    let own = m2
        .ctx
        .commit(&m2.ch, &WrappedRows(&rows), &w.request(2), DAY)
        .unwrap();
    let mut own_rows = m2.rows.clone();
    for c in &own.changes {
        match &c.env {
            Some(v) => {
                own_rows.insert((c.scope, c.key.clone()), v.clone());
            }
            None => {
                own_rows.remove(&(c.scope, c.key.clone()));
            }
        }
    }
    let own_wrapped: Vec<_> = own_rows
        .iter()
        .map(|((s, k), v)| ghost_client_mls::kv::WrappedRow {
            scope: *s,
            key: k.clone(),
            env: v.clone(),
        })
        .collect();
    let t2 = m2
        .ctx
        .trial_count(
            &m2.ch,
            &WrappedRows(&own_wrapped),
            Winner::Own(&own.commit),
            &[(ns, blob)],
            DAY,
        )
        .unwrap();
    assert_eq!(t2.committer, m2.p());
    assert!(t2.senders.is_empty());
    // While its pending commit only self-updates, the member may still post (§6.3.1).
    let e = m2.ctx.encrypt(
        &m2.ch,
        &WrappedRows(&own_wrapped),
        &post("still", 3),
        1,
        DAY,
    );
    assert!(e.is_ok());
    // clear_own drops the pending commit.
    let cleared = m2
        .ctx
        .clear_own(&m2.ch, &WrappedRows(&own_wrapped), DAY)
        .unwrap();
    assert!(!cleared.is_empty());
}

#[test]
fn a_pending_removal_holds_the_committers_posts() {
    let mut w = World::create(24, 0);
    w.admit(2);
    let victim = w.members[2].p();
    let mut req = w.request(0);
    req.removes.push(victim);
    let second = w.request(0);
    let owner = &mut w.members[0];
    let rows = owner.wrapped();
    let out = owner
        .ctx
        .commit(&owner.ch, &WrappedRows(&rows), &req, DAY)
        .unwrap();
    owner.apply(out.changes);
    let rows = owner.wrapped();
    assert_eq!(
        owner
            .ctx
            .encrypt(&owner.ch, &WrappedRows(&rows), &post("x", 1), 1, DAY)
            .err(),
        Some(MlsError::new(Code::PendingCommit))
    );
    // A second pass while a commit is pending is refused (CO-7).
    assert_eq!(
        owner
            .ctx
            .commit(&owner.ch, &WrappedRows(&rows), &second, DAY)
            .err(),
        Some(MlsError::new(Code::PendingCommit))
    );
}

/// §3.4 point 5 (T33 and V10-6's precondition (b)): every stored `added_at` stamp is the start of
/// a UTC day — the call's day — never the device's clock; and past epochs are one row each
/// (point 8).
#[test]
fn stored_message_secrets_carry_the_call_day_and_past_epochs_are_rows() {
    let mut w = World::create(25, 0);
    w.admit(1);
    for _ in 0..3 {
        let req = w.request(0);
        w.commit_and_settle(0, &req);
    }
    let m = &w.members[1];
    let kv = raw_storage(m, DAY);
    let rows = kv.rows();
    let head = rows
        .iter()
        .find(|((s, k), _)| *s == Scope::Group && label_of(k) == b"MessageSecrets")
        .expect("the head row");
    let v: serde_json::Value = serde_json::from_slice(head.1).unwrap();
    let past = v["past_epoch_trees"].as_array().unwrap();
    assert_eq!(
        past.len(),
        3,
        "the head lists the retained epochs by number"
    );
    assert!(past.iter().all(|e| e.is_u64()));
    let past_rows = rows
        .keys()
        .filter(|(_, k)| label_of(k) == b"MessageSecretsPast")
        .count();
    assert_eq!(past_rows, 3, "one row per retained past epoch");
    let mut stamps = Vec::new();
    fn walk(v: &serde_json::Value, out: &mut Vec<(u64, u64)>) {
        match v {
            serde_json::Value::Object(m) => {
                if let Some(a) = m.get("added_at") {
                    if let (Some(s), Some(n)) = (
                        a["secs_since_epoch"].as_u64(),
                        a["nanos_since_epoch"].as_u64(),
                    ) {
                        out.push((s, n));
                    }
                }
                m.values().for_each(|c| walk(c, out));
            }
            serde_json::Value::Array(a) => a.iter().for_each(|c| walk(c, out)),
            _ => {}
        }
    }
    for ((_, k), val) in &rows {
        if label_of(k).starts_with(b"MessageSecrets") {
            walk(&serde_json::from_slice(val).unwrap(), &mut stamps);
        }
    }
    assert!(!stamps.is_empty());
    for (s, n) in stamps {
        assert_eq!(
            (s, n),
            (u64::from(DAY) * 86_400, 0),
            "a day stamp, not the device clock"
        );
    }
}

#[test]
fn the_rayon_pool_has_one_worker_inside_a_call() {
    let w = World::create(26, 0);
    assert_eq!(ghost_client_mls::pin_rayon_single_worker(), 1);
    // Inside OpenMLS's parallel section (the update path's encryption) the pool is the same one.
    let inside = rayon::scope(|_| rayon::current_num_threads());
    assert_eq!(inside, 1);
    drop(w);
}
