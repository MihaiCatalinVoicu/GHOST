//! V10-6 (design §12.1, §19.10; S0-7): a scripted channel world run twice, in two processes, must
//! print byte-identical outputs — every commit, Welcome, KeyPackage, post, sealed blob, change-set
//! and epoch authenticator, and every member's stored rows at the end.
//!
//! Built by `scripts/ci/mls-determinism.sh` with `--cfg getrandom_backend="custom"`, which makes
//! `ghost-host-rng` serve every getrandom draw of the process from one ChaCha20 stream keyed by the
//! seed (argument 1, hex; default all-zero). Every call runs under `ghost_host_rng::serialized`, the
//! one lock of §12.1. The three preconditions of S0-7 are in force: `rayon` at one worker (checked),
//! the `added_at` day rewrite (GhostKv), and one getrandom major in the graph (checked by the script).
//! Without the cfg the example still runs, but its output is not reproducible, and it says so.

use std::collections::BTreeMap;

use ghost_client_mls::content::{Body, ChannelContent, KIND_POST};
use ghost_client_mls::derive::{PseudonymSeed, StateKey};
use ghost_client_mls::ext::{AdmitEvidence, ChannelContext, Purpose, FLAG_MEMBERS_MAY_INVITE};
use ghost_client_mls::group::{
    Anchor, ChannelHandle, CommitRequest, GenerationValues, KeyClass, MlsContext, Winner,
};
use ghost_client_mls::invite;
use ghost_client_mls::join::{JoinAuth, WelcomeBlob};
use ghost_client_mls::kv::{ChangeSet, Scope, WrappedRow, WrappedRows};
use ghost_client_mls::seal::{self, Order};
use ghost_host_rng::serialized;
use sha2::{Digest, Sha256};

const DAY: u32 = 20_725;

struct M {
    ctx: MlsContext,
    ch: ChannelHandle,
    rows: BTreeMap<(Scope, Vec<u8>), Vec<u8>>,
    epoch: u64,
    k_env: Vec<u8>,
    g: Option<GenerationValues>,
    seq: u32,
}

impl M {
    fn new(channel: [u8; 32], i: u8) -> Self {
        let ctx =
            serialized(|| MlsContext::open(StateKey::from_bytes([i ^ 0x5a; 32]))).expect("ctx");
        Self {
            ctx,
            ch: ChannelHandle::open(channel, &PseudonymSeed::from_bytes([i; 32])),
            rows: BTreeMap::new(),
            epoch: 0,
            k_env: Vec::new(),
            g: None,
            seq: 0,
        }
    }
    fn wrapped(&self) -> Vec<WrappedRow> {
        self.rows
            .iter()
            .map(|((s, k), v)| WrappedRow {
                scope: *s,
                key: k.clone(),
                env: v.clone(),
            })
            .collect()
    }
    fn apply(&mut self, c: ChangeSet) {
        for x in c {
            match x.env {
                Some(v) => {
                    self.rows.insert((x.scope, x.key), v);
                }
                None => {
                    self.rows.remove(&(x.scope, x.key));
                }
            }
        }
    }
}

fn h(b: &[u8]) -> String {
    hex::encode(&Sha256::digest(b)[..8])
}

fn changes_hash(c: &ChangeSet) -> String {
    let mut all = Vec::new();
    for x in c {
        all.push(x.scope as u8);
        all.extend_from_slice(&x.key);
        all.extend_from_slice(x.env.as_deref().unwrap_or(b"-"));
    }
    h(&all)
}

fn out(line: String) {
    // An example binary is the one place that prints: it is the probe's output (never a library).
    use std::io::Write as _;
    let _ = writeln!(std::io::stdout(), "{line}");
}

fn post(i: u8) -> Vec<u8> {
    ChannelContent {
        kind: KIND_POST,
        op_id: [i; 16],
        author_minute: DAY * 1440,
        timer_code: 4,
        body: Body::Post {
            text: format!("post {i}"),
            reply_to: None,
        },
    }
    .encode()
    .unwrap()
}

fn main() {
    let seed_hex = std::env::args().nth(1).unwrap_or_else(|| "00".repeat(32));
    let seed: [u8; 32] = hex::decode(&seed_hex)
        .ok()
        .and_then(|v| v.try_into().ok())
        .expect("seed: 64 hex characters");
    ghost_host_rng::seed(seed);
    out(format!("backend_active = {}", ghost_host_rng::ACTIVE));
    assert_eq!(
        ghost_client_mls::pin_rayon_single_worker(),
        1,
        "rayon at one worker (S0-7 (a))"
    );

    let channel = [0xc4; 32];
    let mut ms = vec![M::new(channel, 1)];
    let ctx = ChannelContext {
        channel_id: channel,
        size_class: 0,
        timer_code: 4,
        timer_version: 0,
        history_policy: 0,
        flags: FLAG_MEMBERS_MAY_INVITE,
        idle_evict_days: 63,
        pw_version: 0,
        name: Vec::new(),
        committers: vec![ms[0].ch.pseudonym()],
        funders: vec![ms[0].ch.pseudonym()],
    };
    let c = serialized(|| ms[0].ctx.group_create(&ms[0].ch, &ctx, DAY)).unwrap();
    out(format!("create changes {}", changes_hash(&c.changes)));
    ms[0].apply(c.changes);
    ms[0].epoch = c.epoch.epoch;
    ms[0].k_env = c.epoch.k_env;
    ms[0].g = Some(c.generation);

    let mut generation = 0u32;
    let mut next = 2u8;
    // Two admissions of three and four members; a post by each of three members; a self-update;
    // a removal (rotating); an admission after it; a removal against unmerged leaves.
    for (step, action) in [
        "admit3",
        "admit4",
        "posts",
        "self_update",
        "remove",
        "admit1",
        "remove2",
    ]
    .iter()
    .enumerate()
    {
        let mut req = {
            let g = ms[0].g.clone().unwrap();
            CommitRequest {
                commit_minute: DAY * 1440,
                floor: 4096,
                generation: g.generation,
                generation_open_epoch: g.open_epoch,
                g_env: g.g_env,
                ..Default::default()
            }
        };
        let mut joiners = Vec::new();
        match *action {
            "admit3" | "admit4" | "admit1" => {
                let n = match *action {
                    "admit3" => 3,
                    "admit4" => 4,
                    _ => 1,
                };
                for _ in 0..n {
                    let mut j = M::new(channel, next);
                    next += 1;
                    let owner = &ms[0];
                    let g = owner.g.clone().unwrap();
                    let rows = owner.wrapped();
                    let inv = serialized(|| {
                        owner.ctx.invite_build(
                            &owner.ch,
                            &WrappedRows(&rows),
                            &g.g_env,
                            g.generation,
                            DAY + 7,
                            0,
                            None,
                            false,
                            DAY,
                        )
                    })
                    .unwrap();
                    let (_, f) = invite::parse_v2(&inv.invite, None).unwrap();
                    let kp = serialized(|| j.ctx.key_package(&j.ch, Purpose::Join, DAY)).unwrap();
                    out(format!("step {step} key_package {}", h(&kp.key_package)));
                    j.apply(kp.changes);
                    let body = serialized(|| j.ctx.join_request(&f, &kp.key_package)).unwrap();
                    let v = serialized(|| {
                        owner.ctx.join_verify(
                            &channel,
                            &body,
                            Some(&inv.issued.invite_pk),
                            None,
                            g.generation,
                        )
                    })
                    .unwrap();
                    let JoinAuth::Invite { invite_sig, .. } = v.auth else {
                        unreachable!()
                    };
                    req.adds.push((
                        kp.key_package,
                        AdmitEvidence {
                            kp_ref: kp.kp_ref.clone(),
                            invite_id: inv.issued.invite_id,
                            invite_pk: inv.issued.invite_pk,
                            expiry_day: inv.issued.expiry_day,
                            sponsor: owner.ch.pseudonym(),
                            sponsor_sig: inv.issued.sponsor_sig,
                            invite_sig,
                        },
                    ));
                    joiners.push((
                        j,
                        kp.kp_ref,
                        inv.issued.committers_digest,
                        (f.generation, f.ns),
                    ));
                }
            }
            "posts" => {
                for i in [0usize, 2, 4] {
                    let m = &mut ms[i];
                    m.seq += 1;
                    let rows = m.wrapped();
                    let e = serialized(|| {
                        m.ctx
                            .encrypt(&m.ch, &WrappedRows(&rows), &post(i as u8), m.seq, DAY)
                    })
                    .unwrap();
                    m.apply(e.changes);
                    let g = m.g.clone().unwrap();
                    let order = Order {
                        epoch: e.epoch,
                        sender_leaf: e.sender_leaf,
                        seq: m.seq,
                    };
                    let blob = serialized(|| {
                        m.ctx.seal_blob(
                            &channel,
                            &m.k_env,
                            KeyClass::Epoch,
                            &g.ns,
                            4096,
                            seal::MODE_EPOCH,
                            &order,
                            &e.mls,
                        )
                    })
                    .unwrap();
                    out(format!(
                        "step {step} post {i} mls {} blob {}",
                        h(&e.mls),
                        h(&blob)
                    ));
                    for (j, r) in ms.iter_mut().enumerate() {
                        if j == i {
                            continue;
                        }
                        let rows = r.wrapped();
                        let x = serialized(|| {
                            r.ctx.receive(
                                &r.ch,
                                &WrappedRows(&rows),
                                e.epoch,
                                std::slice::from_ref(&e.mls),
                                DAY,
                            )
                        })
                        .unwrap();
                        r.apply(x.changes);
                    }
                }
                continue;
            }
            "self_update" => {}
            "remove" => req.removes.push(ms[3].ch.pseudonym()),
            "remove2" => req.removes.push(ms[ms.len() - 1].ch.pseudonym()),
            _ => unreachable!(),
        }
        let by = if *action == "self_update" { 2 } else { 0 };
        if by != 0 {
            let g = ms[by].g.clone().unwrap();
            req.generation = g.generation;
            req.generation_open_epoch = g.open_epoch;
            req.g_env = g.g_env;
        }
        let rows = ms[by].wrapped();
        let o = serialized(|| {
            ms[by]
                .ctx
                .commit(&ms[by].ch, &WrappedRows(&rows), &req, DAY)
        })
        .unwrap();
        out(format!(
            "step {step} {action} commit {} welcome {} changes {}",
            h(&o.commit),
            o.welcome.as_deref().map_or("-".into(), h),
            changes_hash(&o.changes)
        ));
        ms[by].apply(o.changes.clone());
        let removed: Vec<[u8; 32]> = req.removes.clone();
        for (j, m) in ms.iter_mut().enumerate() {
            let rows = m.wrapped();
            let winner = if j == by {
                Winner::Own(&o.commit)
            } else {
                Winner::Foreign(&o.commit)
            };
            if removed.contains(&m.ch.pseudonym()) {
                continue;
            }
            let s = serialized(|| {
                m.ctx
                    .settle(&m.ch, &WrappedRows(&rows), winner, generation, DAY)
            })
            .unwrap();
            out(format!(
                "step {step} settle {j} changes {} authenticator {}",
                changes_hash(&s.changes),
                h(&s.epoch.epoch_authenticator)
            ));
            m.apply(s.changes);
            m.epoch = s.epoch.epoch;
            m.k_env = s.epoch.k_env;
            if let Some(g) = s.rotated {
                m.g = Some(g);
            }
        }
        if o.rotates {
            generation += 1;
        }
        ms.retain(|m| !removed.contains(&m.ch.pseudonym()));
        if let Some(w) = &o.welcome {
            for (mut j, kp_ref, digest, expected) in joiners {
                let blob = WelcomeBlob {
                    kp_ref,
                    welcome: w.clone(),
                }
                .encode()
                .unwrap();
                let rows = j.wrapped();
                let r = serialized(|| {
                    j.ctx.welcome_join(
                        &j.ch,
                        &WrappedRows(&rows),
                        &blob,
                        DAY,
                        expected,
                        &Anchor::Invite {
                            committers_digest: digest,
                        },
                    )
                })
                .unwrap();
                out(format!(
                    "step {step} join changes {} authenticator {}",
                    changes_hash(&r.changes),
                    h(&r.epoch.epoch_authenticator)
                ));
                j.apply(r.changes);
                j.epoch = r.epoch.epoch;
                j.k_env = r.epoch.k_env;
                j.g = Some(r.generation);
                ms.push(j);
            }
        }
    }
    for (i, m) in ms.iter().enumerate() {
        let mut all = Vec::new();
        for ((s, k), v) in &m.rows {
            all.push(*s as u8);
            all.extend_from_slice(k);
            all.extend_from_slice(v);
        }
        out(format!(
            "final member {i} rows {} count {}",
            h(&all),
            m.rows.len()
        ));
    }
    let (draws, bytes) = ghost_host_rng::draws();
    out(format!("draws {draws} bytes {bytes}"));
}
