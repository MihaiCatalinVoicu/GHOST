//! A small channel world over the crate's public API, as Kotlin will drive it (value semantics):
//! each member keeps its wrapped rows (`mls_kv` and its global rows), passes them to every call,
//! and applies a change-set only when the call succeeded.
#![allow(dead_code)]

use std::collections::BTreeMap;

use ghost_client_mls::derive::{PseudonymSeed, StateKey};
use ghost_client_mls::ext::{ChannelContext, CommitAad, Purpose, FLAG_MEMBERS_MAY_INVITE};
use ghost_client_mls::group::{
    Anchor, ChannelHandle, CommitOut, CommitRequest, EpochKeys, GenerationValues, KeyClass,
    MlsContext, ReceiveItem, Winner,
};
use ghost_client_mls::invite;
use ghost_client_mls::join::WelcomeBlob;
use ghost_client_mls::kv::{ChangeSet, Scope, WrappedRow, WrappedRows};
use ghost_client_mls::seal::{self, Order};

pub const DAY: u32 = 20_725;

pub fn minute(day: u32) -> u32 {
    day * 1440
}

/// A deterministic 32-byte value from a label (test inputs only).
pub fn bytes32(label: &str, i: usize) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(label.as_bytes());
    h.update((i as u64).to_be_bytes());
    h.finalize().into()
}

pub struct Member {
    pub ctx: MlsContext,
    pub ch: ChannelHandle,
    pub rows: BTreeMap<(Scope, Vec<u8>), Vec<u8>>,
    pub epoch: Option<EpochKeys>,
    pub generation: Option<GenerationValues>,
    pub seq: u32,
    pub index: usize,
}

impl Member {
    pub fn new(channel_id: [u8; 32], i: usize) -> Self {
        let ctx = MlsContext::open(StateKey::from_bytes(bytes32("state", i))).expect("ctx");
        let ch = ChannelHandle::open(channel_id, &PseudonymSeed::from_bytes(bytes32("ps", i)));
        Self {
            ctx,
            ch,
            rows: BTreeMap::new(),
            epoch: None,
            generation: None,
            seq: 0,
            index: i,
        }
    }

    pub fn p(&self) -> [u8; 32] {
        self.ch.pseudonym()
    }

    pub fn wrapped(&self) -> Vec<WrappedRow> {
        self.rows
            .iter()
            .map(|((s, k), v)| WrappedRow {
                scope: *s,
                key: k.clone(),
                env: v.clone(),
            })
            .collect()
    }

    /// Only the global rows (a rejoin's or restore's `welcomeJoin`, §6.2.5).
    pub fn global_rows(&self) -> Vec<WrappedRow> {
        self.wrapped()
            .into_iter()
            .filter(|r| r.scope == Scope::Global)
            .collect()
    }

    pub fn apply(&mut self, changes: ChangeSet) {
        for c in changes {
            match c.env {
                Some(v) => {
                    self.rows.insert((c.scope, c.key), v);
                }
                None => {
                    self.rows.remove(&(c.scope, c.key));
                }
            }
        }
    }

    pub fn channel_id(&self) -> [u8; 32] {
        *self.ch.channel_id()
    }
}

pub fn initial_context(channel_id: [u8; 32], owner: [u8; 32], size_class: u8) -> ChannelContext {
    ChannelContext {
        channel_id,
        size_class,
        timer_code: 4,
        timer_version: 0,
        history_policy: 0,
        flags: FLAG_MEMBERS_MAY_INVITE,
        idle_evict_days: 63,
        pw_version: 0,
        name: Vec::new(),
        committers: vec![owner],
        funders: vec![owner],
    }
}

/// A new member, its KeyPackage, the evidence for the AAD, the invite's digest and the
/// (generation, namespace) the Welcome will arrive in.
pub type Invited = (
    Member,
    Vec<u8>,
    ghost_client_mls::ext::AdmitEvidence,
    [u8; 32],
    (u32, [u8; 32]),
);

pub struct World {
    pub channel_id: [u8; 32],
    pub members: Vec<Member>,
    pub next_id: usize,
    pub day: u32,
    pub generation: u32,
}

impl World {
    /// The owner creates a small channel.
    pub fn create(tag: usize, size_class: u8) -> Self {
        let channel_id = bytes32("channel", tag);
        let mut owner = Member::new(channel_id, tag * 1000);
        let ctx = initial_context(channel_id, owner.p(), size_class);
        let out = owner
            .ctx
            .group_create(&owner.ch, &ctx, DAY)
            .expect("create");
        owner.apply(out.changes);
        owner.epoch = Some(out.epoch);
        owner.generation = Some(out.generation);
        Self {
            channel_id,
            members: vec![owner],
            next_id: tag * 1000 + 1,
            day: DAY,
            generation: 0,
        }
    }

    pub fn owner(&self) -> &Member {
        &self.members[0]
    }

    /// An invite by member `by` and the join material of a new member: its KeyPackage, the
    /// evidence the committer puts in the AAD, and the invite's anchor.
    pub fn invite_and_key_package(&mut self, by: usize) -> Invited {
        let id = self.next_id;
        self.next_id += 1;
        let sponsor = &self.members[by];
        let g = sponsor.generation.clone().expect("generation");
        let rows = sponsor.wrapped();
        let out = sponsor
            .ctx
            .invite_build(
                &sponsor.ch,
                &WrappedRows(&rows),
                &g.g_env,
                g.generation,
                self.day + 7,
                0,
                None,
                false,
                self.day,
            )
            .expect("invite");
        let (_, fields) = invite::parse_v2(&out.invite, None).expect("parse invite");
        let mut joiner = Member::new(self.channel_id, id);
        let kp = joiner
            .ctx
            .key_package(&joiner.ch, Purpose::Join, self.day)
            .expect("kp");
        joiner.apply(kp.changes);
        let body = joiner
            .ctx
            .join_request(&fields, &kp.key_package)
            .expect("join request");
        let verified = self.members[0]
            .ctx
            .join_verify(
                &self.channel_id,
                &body,
                Some(&out.issued.invite_pk),
                None,
                g.generation,
            )
            .expect("join verify");
        let invite_sig = match verified.auth {
            ghost_client_mls::join::JoinAuth::Invite { invite_sig, .. } => invite_sig,
            _ => unreachable!(),
        };
        let evidence = ghost_client_mls::ext::AdmitEvidence {
            kp_ref: kp.kp_ref.clone(),
            invite_id: out.issued.invite_id,
            invite_pk: out.issued.invite_pk,
            expiry_day: out.issued.expiry_day,
            sponsor: sponsor.p(),
            sponsor_sig: out.issued.sponsor_sig,
            invite_sig,
        };
        (
            joiner,
            kp.key_package,
            evidence,
            out.issued.committers_digest,
            (fields.generation, fields.ns),
        )
    }

    pub fn request(&self, by: usize) -> CommitRequest {
        let g = self.members[by].generation.clone().expect("generation");
        CommitRequest {
            commit_minute: minute(self.day),
            floor: 4096,
            generation: g.generation,
            generation_open_epoch: g.open_epoch,
            g_env: g.g_env,
            ..Default::default()
        }
    }

    /// Member `by` commits `req`; every other member validates it (CO-2 must hold) and settles it;
    /// the committer settles its own. Returns the commit.
    pub fn commit_and_settle(&mut self, by: usize, req: &CommitRequest) -> CommitOut {
        let rows = self.members[by].wrapped();
        let out = self.members[by]
            .ctx
            .commit(&self.members[by].ch, &WrappedRows(&rows), req, self.day)
            .expect("commit");
        let committer = &mut self.members[by];
        committer.apply(out.changes.clone());
        let epoch = committer.epoch.as_ref().unwrap().epoch;
        let removed_keys: Vec<[u8; 32]> =
            out.kept_removes.iter().map(|&i| req.removes[i]).collect();
        for j in 0..self.members.len() {
            if j == by || removed_keys.contains(&self.members[j].p()) {
                continue;
            }
            let m = &mut self.members[j];
            let rows = m.wrapped();
            let r = m
                .ctx
                .receive(
                    &m.ch,
                    &WrappedRows(&rows),
                    epoch,
                    std::slice::from_ref(&out.commit),
                    self.day,
                )
                .expect("receive commit");
            assert!(
                r.changes.is_empty(),
                "a validation run returns no change-set"
            );
            match &r.items[0] {
                ReceiveItem::Commit(s) => assert_eq!(s.verdict, Ok(()), "CO-2 at member {j}"),
                other => panic!("member {j}: {other:?}"),
            }
            let s = m
                .ctx
                .settle(
                    &m.ch,
                    &WrappedRows(&rows),
                    Winner::Foreign(&out.commit),
                    self.generation,
                    self.day,
                )
                .expect("settle");
            m.apply(s.changes);
            m.epoch = Some(s.epoch);
            if let Some(g) = s.rotated {
                m.generation = Some(g);
            }
        }
        let c = &mut self.members[by];
        let rows = c.wrapped();
        let s = c
            .ctx
            .settle(
                &c.ch,
                &WrappedRows(&rows),
                Winner::Own(&out.commit),
                self.generation,
                self.day,
            )
            .expect("settle own");
        c.apply(s.changes);
        c.epoch = Some(s.epoch);
        if let Some(g) = s.rotated {
            c.generation = Some(g);
            self.generation += 1;
        }
        self.members.retain(|m| !removed_keys.contains(&m.p()));
        out
    }

    /// Admits `n` new members in one commit by the owner; they join from the Welcome.
    pub fn admit(&mut self, n: usize) -> CommitOut {
        self.admit_floor(n, 4096)
    }

    /// `admit` with another floor bucket (a large batch in one commit builds the blank tree of
    /// §5.7's size table: only the owner's direct path set).
    pub fn admit_floor(&mut self, n: usize, floor: usize) -> CommitOut {
        let mut joiners = Vec::new();
        let mut req = self.request(0);
        req.floor = floor;
        let mut anchors = Vec::new();
        for _ in 0..n {
            let (j, kp, ev, digest, expected) = self.invite_and_key_package(0);
            req.adds.push((kp, ev));
            joiners.push(j);
            anchors.push((digest, expected));
        }
        let out = self.commit_and_settle(0, &req);
        let welcome = out.welcome.clone().expect("welcome");
        for ((mut j, (digest, expected)), kp_ref) in
            joiners.into_iter().zip(anchors).zip(&out.joiners)
        {
            let blob = WelcomeBlob {
                kp_ref: kp_ref.clone(),
                welcome: welcome.clone(),
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
                    self.day,
                    expected,
                    &Anchor::Invite {
                        committers_digest: digest,
                    },
                )
                .expect("welcome join");
            j.apply(joined.changes);
            j.epoch = Some(joined.epoch);
            j.generation = Some(joined.generation);
            self.members.push(j);
        }
        out
    }

    /// Member `i` posts `content` (encoded); returns the MLS message.
    pub fn post(&mut self, i: usize, content: &[u8]) -> Vec<u8> {
        let m = &mut self.members[i];
        m.seq += 1;
        let rows = m.wrapped();
        let out = m
            .ctx
            .encrypt(&m.ch, &WrappedRows(&rows), content, m.seq, self.day)
            .expect("encrypt");
        m.apply(out.changes);
        out.mls
    }

    pub fn authenticators(&self) -> Vec<Vec<u8>> {
        self.members
            .iter()
            .map(|m| m.epoch.as_ref().unwrap().epoch_authenticator.clone())
            .collect()
    }

    /// Seals an epoch message of member `i` (mode 0x11) the way the relay will carry it.
    pub fn seal_epoch(&self, i: usize, body: &[u8], order: Order) -> Vec<u8> {
        let m = &self.members[i];
        let e = m.epoch.as_ref().unwrap();
        let g = m.generation.as_ref().unwrap();
        let b = seal::bucket(body.len(), 0).unwrap();
        m.ctx
            .seal_blob(
                &self.channel_id,
                &e.k_env,
                KeyClass::Epoch,
                &g.ns,
                b,
                seal::MODE_EPOCH,
                &order,
                body,
            )
            .expect("seal")
    }
}

pub fn empty_aad() -> CommitAad {
    CommitAad::default()
}

/// The index a member was created with (its seeds are `bytes32("state", i)`, `bytes32("ps", i)`).
pub fn state_key_of(i: usize) -> ghost_client_mls::derive::StateKey {
    ghost_client_mls::derive::StateKey::from_bytes(bytes32("state", i))
}

/// A member's rows loaded into a fresh adapter with OpenMLS directly (the reload oracle and the
/// hand-built commits of the negative tests).
pub fn raw_storage(m: &Member, day: u32) -> ghost_client_mls::kv::GhostKv {
    use ghost_client_mls::kv::RowSource;
    let rows = m.wrapped();
    let kv = ghost_client_mls::kv::GhostKv::new(m.channel_id(), day);
    kv.load(
        WrappedRows(&rows)
            .load(&m.channel_id(), &state_key_of(m.index))
            .expect("rows open"),
    )
    .expect("rows load");
    kv
}

/// The pseudonym signer of a member (hand-built commits in the negative tests).
pub fn raw_signer(m: &Member) -> ghost_client_mls::provider::PseudonymSigner {
    ghost_client_mls::provider::PseudonymSigner::from_seed(&PseudonymSeed::from_bytes(bytes32(
        "ps", m.index,
    )))
}
