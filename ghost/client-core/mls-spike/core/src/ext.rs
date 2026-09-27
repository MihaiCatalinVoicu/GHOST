//! GHOST's MLS formats exactly as design §5.3, §5.4 and §19.2 define them, so that V10-4 measures
//! commits and Welcomes with the bytes Phase 10 would really put on the wire.

use crate::codec::{put_vec, Reader};

/// GroupContext extension `GhostChannelContext` (§5.3), private-use range.
pub const EXT_CHANNEL_CONTEXT: u16 = 0xF0A1;
/// LeafNode extension `GhostLeaf` (§5.4).
pub const EXT_LEAF: u16 = 0xF0A2;
/// GroupInfo extension `GhostBootstrap` (§5.4).
pub const EXT_BOOTSTRAP: u16 = 0xF0A3;
/// KeyPackage extension `GhostKpBind` (§5.4, §19.3).
pub const EXT_KP_BIND: u16 = 0xF0A4;

/// §5.3 `GhostChannelContext`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChannelContext {
    pub channel_id: [u8; 32],
    pub size_class: u8,
    pub timer_code: u8,
    pub timer_version: u16,
    pub history_policy: u8,
    pub flags: u8,
    pub idle_evict_days: u16,
    pub name: Vec<u8>,
    pub committers: Vec<[u8; 32]>,
    pub funders: Vec<[u8; 32]>,
}

impl ChannelContext {
    pub fn encode(&self) -> Vec<u8> {
        let mut o = Vec::with_capacity(446);
        o.push(1);
        o.extend_from_slice(&self.channel_id);
        o.push(self.size_class);
        o.push(self.timer_code);
        o.extend_from_slice(&self.timer_version.to_be_bytes());
        o.push(self.history_policy);
        o.push(self.flags);
        o.extend_from_slice(&self.idle_evict_days.to_be_bytes());
        put_vec(&mut o, &self.name);
        put_vec(&mut o, &self.committers.concat());
        put_vec(&mut o, &self.funders.concat());
        o
    }

    pub fn decode(b: &[u8]) -> Option<Self> {
        let mut r = Reader::new(b);
        if r.u8()? != 1 {
            return None;
        }
        let channel_id = r.fixed::<32>()?;
        let size_class = r.u8()?;
        let timer_code = r.u8()?;
        let timer_version = r.u16()?;
        let history_policy = r.u8()?;
        let flags = r.u8()?;
        let idle_evict_days = r.u16()?;
        let name = r.vec()?.to_vec();
        let keys = |v: &[u8]| -> Option<Vec<[u8; 32]>> {
            if !v.len().is_multiple_of(32) {
                return None;
            }
            Some(v.chunks(32).map(|c| c.try_into().unwrap()).collect())
        };
        let committers = keys(r.vec()?)?;
        let funders = keys(r.vec()?)?;
        if !r.done() {
            return None;
        }
        Some(Self {
            channel_id,
            size_class,
            timer_code,
            timer_version,
            history_policy,
            flags,
            idle_evict_days,
            name,
            committers,
            funders,
        })
    }

    /// The largest context §5.3 allows: a 48-byte name, 8 committers, 3 funders (446 bytes).
    pub fn maximal(channel_id: [u8; 32], keys: &[[u8; 32]]) -> Self {
        Self {
            channel_id,
            size_class: 0,
            timer_code: 4,
            timer_version: 0xffff,
            history_policy: 0,
            flags: 1,
            idle_evict_days: 70,
            name: vec![0x61; 48],
            committers: keys.iter().take(8).copied().collect(),
            funders: keys.iter().take(3).copied().collect(),
        }
    }

    /// The default at creation (§6.1): the owner as the only committer and funder, no name.
    pub fn initial(channel_id: [u8; 32], owner: [u8; 32], size_class: u8) -> Self {
        Self {
            channel_id,
            size_class,
            timer_code: 4,
            timer_version: 0,
            history_policy: 0,
            flags: 1,
            idle_evict_days: 63,
            name: Vec::new(),
            committers: vec![owner],
            funders: vec![owner],
        }
    }
}

/// §5.4 `GhostLeaf`: 41 bytes.
pub fn leaf(box_pk: &[u8; 32], refresh_epoch: u64) -> Vec<u8> {
    let mut o = Vec::with_capacity(41);
    o.push(1);
    o.extend_from_slice(box_pk);
    o.extend_from_slice(&refresh_epoch.to_be_bytes());
    o
}

/// Parses `GhostLeaf`, returning `(box_pk, refresh_epoch)`.
pub fn leaf_decode(b: &[u8]) -> Option<([u8; 32], u64)> {
    let mut r = Reader::new(b);
    if r.u8()? != 1 {
        return None;
    }
    let pk = r.fixed::<32>()?;
    let e = r.u64()?;
    r.done().then_some((pk, e))
}

/// §5.4 `GhostKpBind`: 38 bytes.
pub fn kp_bind(channel_id: &[u8; 32], purpose: u8, day: u32) -> Vec<u8> {
    let mut o = Vec::with_capacity(38);
    o.push(1);
    o.extend_from_slice(channel_id);
    o.push(purpose);
    o.extend_from_slice(&day.to_be_bytes());
    o
}

/// §5.4 `GhostBootstrap`: 45 bytes.
pub fn bootstrap(generation: u32, open_epoch: u64, g: &[u8; 32]) -> Vec<u8> {
    let mut o = Vec::with_capacity(45);
    o.push(1);
    o.extend_from_slice(&generation.to_be_bytes());
    o.extend_from_slice(&open_epoch.to_be_bytes());
    o.extend_from_slice(g);
    o
}

/// §19.2 `AdmitEvidence` (about 245 bytes with a 32-byte KeyPackageRef).
#[derive(Clone, Debug)]
pub struct AdmitEvidence {
    pub kp_ref: Vec<u8>,
    pub invite_id: [u8; 16],
    pub invite_pk: [u8; 32],
    pub expiry_day: u32,
    pub sponsor: [u8; 32],
    pub sponsor_sig: [u8; 64],
    pub invite_sig: [u8; 64],
}

impl AdmitEvidence {
    fn encode_into(&self, o: &mut Vec<u8>) {
        put_vec(o, &self.kp_ref);
        o.extend_from_slice(&self.invite_id);
        o.extend_from_slice(&self.invite_pk);
        o.extend_from_slice(&self.expiry_day.to_be_bytes());
        o.extend_from_slice(&self.sponsor);
        o.extend_from_slice(&self.sponsor_sig);
        o.extend_from_slice(&self.invite_sig);
    }

    /// Evidence with random-looking signature bytes of the right length (V10-4 measures sizes;
    /// §6.2.4's verification is S4's).
    pub fn filler(kp_ref: Vec<u8>) -> Self {
        Self {
            kp_ref,
            invite_id: [0x11; 16],
            invite_pk: [0x22; 32],
            expiry_day: 20_725,
            sponsor: [0x33; 32],
            sponsor_sig: [0x44; 64],
            invite_sig: [0x55; 64],
        }
    }
}

/// §19.2 `SwapEvidence`.
#[derive(Clone, Debug)]
pub enum SwapEvidence {
    Rejoin {
        kp_ref: Vec<u8>,
        generation: u32,
        day: u32,
        last_epoch: u64,
        last_hash: [u8; 32],
        rejoin_sig: [u8; 64],
    },
    Restore(AdmitEvidence),
}

impl SwapEvidence {
    fn encode_into(&self, o: &mut Vec<u8>) {
        match self {
            SwapEvidence::Rejoin {
                kp_ref,
                generation,
                day,
                last_epoch,
                last_hash,
                rejoin_sig,
            } => {
                put_vec(o, kp_ref);
                o.push(1);
                o.extend_from_slice(&generation.to_be_bytes());
                o.extend_from_slice(&day.to_be_bytes());
                o.extend_from_slice(&last_epoch.to_be_bytes());
                o.extend_from_slice(last_hash);
                o.extend_from_slice(rejoin_sig);
            }
            SwapEvidence::Restore(a) => {
                put_vec(o, &a.kp_ref);
                o.push(2);
                a.encode_into(o);
            }
        }
    }
}

/// §19.2 `GhostCommitAad`, carried in every commit's MLS `authenticated_data`.
#[derive(Clone, Debug, Default)]
pub struct CommitAad {
    pub commit_minute: u32,
    pub rotate: bool,
    pub admits: Vec<AdmitEvidence>,
    pub swaps: Vec<SwapEvidence>,
}

impl CommitAad {
    pub fn encode(&self) -> Vec<u8> {
        let mut o = vec![1];
        o.extend_from_slice(&self.commit_minute.to_be_bytes());
        o.push(u8::from(self.rotate));
        let mut a = Vec::new();
        for e in &self.admits {
            e.encode_into(&mut a);
        }
        put_vec(&mut o, &a);
        let mut s = Vec::new();
        for e in &self.swaps {
            e.encode_into(&mut s);
        }
        put_vec(&mut o, &s);
        o
    }
}

/// §5.5 `ChannelOrder` (9 bytes): the author's ordering claim in an application message's AAD.
pub fn channel_order(sender_leaf: u32, seq: u32) -> Vec<u8> {
    let mut o = Vec::with_capacity(9);
    o.push(1);
    o.extend_from_slice(&sender_leaf.to_be_bytes());
    o.extend_from_slice(&seq.to_be_bytes());
    o
}
