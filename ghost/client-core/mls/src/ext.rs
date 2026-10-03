//! GHOST's MLS formats (TLS presentation language, RFC 9420 §2.1): the GroupContext extension
//! `GhostChannelContext` 0xF0A1 (§5.3, with `pw_version` of §19.28.3), the leaf extension
//! `GhostLeaf` 0xF0A2, the GroupInfo extension `GhostBootstrap` 0xF0A3, the KeyPackage extension
//! `GhostKpBind` 0xF0A4 (§5.4), the commit AAD `GhostCommitAad` with its evidence (§19.2) and the
//! application AAD `ChannelOrder` (§5.5). Every decoder is strict: one encoding per value, no
//! trailing bytes, reserved bits zero.

use crate::codec::{put_u16, put_u32, put_u64, put_vec, Reader};

/// GroupContext extension `GhostChannelContext` (§5.3), private-use range.
pub const EXT_CHANNEL_CONTEXT: u16 = 0xF0A1;
/// LeafNode extension `GhostLeaf` (§5.4).
pub const EXT_LEAF: u16 = 0xF0A2;
/// GroupInfo extension `GhostBootstrap` (§5.4).
pub const EXT_BOOTSTRAP: u16 = 0xF0A3;
/// KeyPackage extension `GhostKpBind` (§5.4, §19.3).
pub const EXT_KP_BIND: u16 = 0xF0A4;

/// The largest encoded context: 448 bytes (§5.3, §19.29.5).
pub const CONTEXT_MAX_BYTES: usize = 448;
pub const NAME_MAX_BYTES: usize = 48;
pub const MAX_COMMITTERS: usize = 8;
pub const MAX_FUNDERS: usize = 3;
/// Member caps of the size classes (§5.3): small ≤ 32, large ≤ 100.
pub const CLASS_CAP: [usize; 2] = [32, 100];

/// `flags` bit 0: members may invite.
pub const FLAG_MEMBERS_MAY_INVITE: u8 = 1 << 0;
/// `flags` bit 2: joining requires a password (§19.28).
pub const FLAG_PASSWORD: u8 = 1 << 2;
/// Bits 1 and 3–7 are reserved and zero in P0.
pub const FLAGS_RESERVED: u8 = !(FLAG_MEMBERS_MAY_INVITE | FLAG_PASSWORD);

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
    pub pw_version: u16,
    pub name: Vec<u8>,
    pub committers: Vec<[u8; 32]>,
    pub funders: Vec<[u8; 32]>,
}

/// Why a context is invalid (§5.3); every variant is `INVALID_POLICY` or `INVALID_COMMIT(context)`
/// at the API.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContextFault {
    Encoding,
    ChannelId,
    HistoryPolicy,
    Timer,
    SizeClass,
    MemberCount,
    IdleEvict,
    ReservedFlags,
    PasswordAndMembersInvite,
    Committers,
    Funders,
    NotALeaf,
    Name,
    PasswordPolicy,
}

impl ChannelContext {
    pub fn encode(&self) -> Vec<u8> {
        let mut o = Vec::with_capacity(CONTEXT_MAX_BYTES);
        o.push(1);
        o.extend_from_slice(&self.channel_id);
        o.push(self.size_class);
        o.push(self.timer_code);
        put_u16(&mut o, self.timer_version);
        o.push(self.history_policy);
        o.push(self.flags);
        put_u16(&mut o, self.idle_evict_days);
        put_u16(&mut o, self.pw_version);
        put_vec(&mut o, &self.name);
        put_vec(&mut o, &self.committers.concat());
        put_vec(&mut o, &self.funders.concat());
        o
    }

    /// Strict decoding: version 1, minimal varints, key lists of whole 32-byte keys, no trailing
    /// bytes. Field bounds are [`ChannelContext::check`]'s.
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
        let pw_version = r.u16()?;
        let name = r.vec()?.to_vec();
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
            pw_version,
            name,
            committers,
            funders,
        })
    }

    /// The validity of §5.3 that needs no previous context: bounds, reserved bits, the lists, and
    /// that every committer and funder is the signature key of a current leaf (`leaves`, after
    /// the commit), and the member count within the class cap.
    pub fn check(&self, group_id: &[u8], leaves: &[[u8; 32]]) -> Result<(), ContextFault> {
        if self.encode().len() > CONTEXT_MAX_BYTES {
            return Err(ContextFault::Encoding);
        }
        if group_id != self.channel_id {
            return Err(ContextFault::ChannelId);
        }
        if self.history_policy != 0 {
            return Err(ContextFault::HistoryPolicy);
        }
        if self.timer_code > 5 {
            return Err(ContextFault::Timer);
        }
        let cap = *CLASS_CAP
            .get(usize::from(self.size_class))
            .ok_or(ContextFault::SizeClass)?;
        if leaves.len() > cap {
            return Err(ContextFault::MemberCount);
        }
        if !(35..=70).contains(&self.idle_evict_days) {
            return Err(ContextFault::IdleEvict);
        }
        if self.flags & FLAGS_RESERVED != 0 {
            return Err(ContextFault::ReservedFlags);
        }
        // Q46 (b) (§19.29.3): in a password channel only committers invite.
        if self.flags & FLAG_PASSWORD != 0 && self.flags & FLAG_MEMBERS_MAY_INVITE != 0 {
            return Err(ContextFault::PasswordAndMembersInvite);
        }
        // A password channel has had its password set at least once (`pw_version ≥ 1`).
        if self.flags & FLAG_PASSWORD != 0 && self.pw_version == 0 {
            return Err(ContextFault::PasswordPolicy);
        }
        if self.name.len() > NAME_MAX_BYTES || core::str::from_utf8(&self.name).is_err() {
            return Err(ContextFault::Name);
        }
        if self.committers.is_empty()
            || self.committers.len() > MAX_COMMITTERS
            || !distinct(&self.committers)
        {
            return Err(ContextFault::Committers);
        }
        if self.funders.len() > MAX_FUNDERS || !distinct(&self.funders) {
            return Err(ContextFault::Funders);
        }
        for k in self.committers.iter().chain(&self.funders) {
            if !leaves.contains(k) {
                return Err(ContextFault::NotALeaf);
            }
        }
        Ok(())
    }

    /// The password policy of a change from `prev` (§5.3, §19.28.3 corrected by §19.29.3):
    /// `pw_version` never decreases and grows by at most one; setting flag bit 2 raises it by
    /// exactly one; clearing bit 2 leaves it unchanged; a raise while bit 2 stays set is a change;
    /// only rank 0 changes bit 2 or `pw_version`.
    pub fn check_password_change(
        &self,
        prev: &ChannelContext,
        rank: u8,
    ) -> Result<(), ContextFault> {
        let (was, is) = (
            prev.flags & FLAG_PASSWORD != 0,
            self.flags & FLAG_PASSWORD != 0,
        );
        let bump = self.pw_version.checked_sub(prev.pw_version);
        let ok = match (was, is) {
            (false, true) => bump == Some(1),
            (true, false) => bump == Some(0),
            (true, true) => matches!(bump, Some(0) | Some(1)),
            (false, false) => bump == Some(0),
        };
        if !ok {
            return Err(ContextFault::PasswordPolicy);
        }
        if (was != is || bump != Some(0)) && rank != 0 {
            return Err(ContextFault::PasswordPolicy);
        }
        Ok(())
    }

    /// The rank of a signature key: its index in `committers` (0 … 7) or 255 (CO-1).
    pub fn rank_of(&self, key: &[u8; 32]) -> u8 {
        self.committers
            .iter()
            .position(|c| c == key)
            .map_or(255, |i| i as u8)
    }
}

fn keys(v: &[u8]) -> Option<Vec<[u8; 32]>> {
    if !v.len().is_multiple_of(32) {
        return None;
    }
    Some(v.as_chunks::<32>().0.to_vec())
}

fn distinct(v: &[[u8; 32]]) -> bool {
    let mut s = v.to_vec();
    s.sort_unstable();
    s.dedup();
    s.len() == v.len()
}

/// §5.4 `GhostLeaf`: `version(1) = 1 ‖ box_pk(32) ‖ refresh_epoch(u64)`, 41 bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GhostLeaf {
    pub box_pk: [u8; 32],
    pub refresh_epoch: u64,
}

impl GhostLeaf {
    pub const LEN: usize = 41;

    pub fn encode(&self) -> Vec<u8> {
        let mut o = Vec::with_capacity(Self::LEN);
        o.push(1);
        o.extend_from_slice(&self.box_pk);
        put_u64(&mut o, self.refresh_epoch);
        o
    }

    pub fn decode(b: &[u8]) -> Option<Self> {
        let mut r = Reader::new(b);
        if r.u8()? != 1 {
            return None;
        }
        let box_pk = r.fixed::<32>()?;
        let refresh_epoch = r.u64()?;
        r.done().then_some(Self {
            box_pk,
            refresh_epoch,
        })
    }
}

/// KeyPackage purposes of `GhostKpBind` (§19.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Purpose {
    Join = 1,
    Rejoin = 2,
    Restore = 3,
}

impl Purpose {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Purpose::Join),
            2 => Some(Purpose::Rejoin),
            3 => Some(Purpose::Restore),
            _ => None,
        }
    }
}

/// §5.4 `GhostKpBind`: `version(1) = 1 ‖ channel_id(32) ‖ purpose(1) ‖ day(u32)`, 38 bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KpBind {
    pub channel_id: [u8; 32],
    pub purpose: Purpose,
    pub day: u32,
}

impl KpBind {
    pub const LEN: usize = 38;

    pub fn encode(&self) -> Vec<u8> {
        let mut o = Vec::with_capacity(Self::LEN);
        o.push(1);
        o.extend_from_slice(&self.channel_id);
        o.push(self.purpose as u8);
        put_u32(&mut o, self.day);
        o
    }

    pub fn decode(b: &[u8]) -> Option<Self> {
        let mut r = Reader::new(b);
        if r.u8()? != 1 {
            return None;
        }
        let channel_id = r.fixed::<32>()?;
        let purpose = Purpose::from_u8(r.u8()?)?;
        let day = r.u32()?;
        r.done().then_some(Self {
            channel_id,
            purpose,
            day,
        })
    }
}

/// §5.4 `GhostBootstrap`: `version(1) = 1 ‖ generation(u32) ‖ open_epoch(u64) ‖ G(32)`, 45 bytes.
/// It travels only in the Welcome's encrypted GroupInfo (S0-9). When the commit that carries the
/// Welcome itself opens the generation (a rotating commit, `open_epoch` = the joined epoch), the
/// committer cannot know `G` before its commit exists and `G` is 32 zero bytes: the joiner exports
/// it from the joined epoch (a gap of the design found in S2a, §19.30).
#[derive(Clone, PartialEq, Eq)]
pub struct Bootstrap {
    pub generation: u32,
    pub open_epoch: u64,
    pub g: [u8; 32],
}

impl core::fmt::Debug for Bootstrap {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "Bootstrap {{ generation: {}, open_epoch: {}, g: .. }}",
            self.generation, self.open_epoch
        )
    }
}

impl Bootstrap {
    pub const LEN: usize = 45;

    pub fn encode(&self) -> Vec<u8> {
        let mut o = Vec::with_capacity(Self::LEN);
        o.push(1);
        put_u32(&mut o, self.generation);
        put_u64(&mut o, self.open_epoch);
        o.extend_from_slice(&self.g);
        o
    }

    pub fn decode(b: &[u8]) -> Option<Self> {
        let mut r = Reader::new(b);
        if r.u8()? != 1 {
            return None;
        }
        let generation = r.u32()?;
        let open_epoch = r.u64()?;
        let g = r.fixed::<32>()?;
        r.done().then_some(Self {
            generation,
            open_epoch,
            g,
        })
    }
}

/// §19.2 `AdmitEvidence`.
#[derive(Clone, Debug, PartialEq, Eq)]
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
        put_u32(o, self.expiry_day);
        o.extend_from_slice(&self.sponsor);
        o.extend_from_slice(&self.sponsor_sig);
        o.extend_from_slice(&self.invite_sig);
    }

    fn decode_from(r: &mut Reader<'_>) -> Option<Self> {
        let kp_ref = r.vec()?.to_vec();
        if kp_ref.is_empty() || kp_ref.len() > 64 {
            return None;
        }
        Some(Self {
            kp_ref,
            invite_id: r.fixed()?,
            invite_pk: r.fixed()?,
            expiry_day: r.u32()?,
            sponsor: r.fixed()?,
            sponsor_sig: r.fixed()?,
            invite_sig: r.fixed()?,
        })
    }
}

/// §19.2 `SwapEvidence`.
#[derive(Clone, Debug, PartialEq, Eq)]
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
    pub fn kp_ref(&self) -> &[u8] {
        match self {
            SwapEvidence::Rejoin { kp_ref, .. } => kp_ref,
            SwapEvidence::Restore(a) => &a.kp_ref,
        }
    }

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
                put_u32(o, *generation);
                put_u32(o, *day);
                put_u64(o, *last_epoch);
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

    fn decode_from(r: &mut Reader<'_>) -> Option<Self> {
        let kp_ref = r.vec()?.to_vec();
        if kp_ref.is_empty() || kp_ref.len() > 64 {
            return None;
        }
        match r.u8()? {
            1 => Some(SwapEvidence::Rejoin {
                kp_ref,
                generation: r.u32()?,
                day: r.u32()?,
                last_epoch: r.u64()?,
                last_hash: r.fixed()?,
                rejoin_sig: r.fixed()?,
            }),
            2 => {
                let a = AdmitEvidence::decode_from(r)?;
                // The swap's reference and its restore evidence's reference name one KeyPackage.
                (a.kp_ref == kp_ref).then_some(SwapEvidence::Restore(a))
            }
            _ => None,
        }
    }
}

/// §19.2 `GhostCommitAad`, carried in every commit's MLS `authenticated_data`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CommitAad {
    pub commit_minute: u32,
    /// `flags` bit 0: rotate (committers only, CO-2); bits 1–7 zero.
    pub rotate: bool,
    pub admits: Vec<AdmitEvidence>,
    pub swaps: Vec<SwapEvidence>,
}

impl CommitAad {
    pub fn encode(&self) -> Vec<u8> {
        let mut o = vec![1];
        put_u32(&mut o, self.commit_minute);
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

    pub fn decode(b: &[u8]) -> Option<Self> {
        let mut r = Reader::new(b);
        if r.u8()? != 1 {
            return None;
        }
        let commit_minute = r.u32()?;
        let flags = r.u8()?;
        if flags & !1 != 0 {
            return None;
        }
        let mut admits_r = Reader::new(r.vec()?);
        let mut admits = Vec::new();
        while !admits_r.done() {
            admits.push(AdmitEvidence::decode_from(&mut admits_r)?);
        }
        let mut swaps_r = Reader::new(r.vec()?);
        let mut swaps = Vec::new();
        while !swaps_r.done() {
            swaps.push(SwapEvidence::decode_from(&mut swaps_r)?);
        }
        if !r.done() {
            return None;
        }
        let aad = Self {
            commit_minute,
            rotate: flags & 1 == 1,
            admits,
            swaps,
        };
        // One encoding per value (the re-encoding is the input).
        (aad.encode() == b).then_some(aad)
    }
}

/// §5.5 `ChannelOrder`: `version(1) = 1 ‖ sender_leaf(u32) ‖ seq(u32)`, 9 bytes, the author's
/// ordering claim in an application message's MLS AAD.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChannelOrder {
    pub sender_leaf: u32,
    pub seq: u32,
}

impl ChannelOrder {
    pub const LEN: usize = 9;

    pub fn encode(&self) -> Vec<u8> {
        let mut o = Vec::with_capacity(Self::LEN);
        o.push(1);
        put_u32(&mut o, self.sender_leaf);
        put_u32(&mut o, self.seq);
        o
    }

    pub fn decode(b: &[u8]) -> Option<Self> {
        let mut r = Reader::new(b);
        if r.u8()? != 1 {
            return None;
        }
        let sender_leaf = r.u32()?;
        let seq = r.u32()?;
        r.done().then_some(Self { sender_leaf, seq })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> ChannelContext {
        ChannelContext {
            channel_id: [9; 32],
            size_class: 0,
            timer_code: 4,
            timer_version: 0,
            history_policy: 0,
            flags: FLAG_MEMBERS_MAY_INVITE,
            idle_evict_days: 63,
            pw_version: 0,
            name: Vec::new(),
            committers: vec![[1; 32]],
            funders: vec![[1; 32]],
        }
    }

    #[test]
    fn the_largest_context_is_448_bytes() {
        let keys: Vec<[u8; 32]> = (1..=8u8).map(|i| [i; 32]).collect();
        let c = ChannelContext {
            name: vec![b'a'; 48],
            committers: keys.clone(),
            funders: keys[..3].to_vec(),
            pw_version: 0xffff,
            ..ctx()
        };
        assert_eq!(c.encode().len(), CONTEXT_MAX_BYTES);
        assert_eq!(ChannelContext::decode(&c.encode()), Some(c.clone()));
        assert!(c.check(&[9; 32], &keys).is_ok());
    }

    #[test]
    fn context_decoding_is_strict() {
        let e = ctx().encode();
        let mut long = e.clone();
        long.push(0);
        assert_eq!(ChannelContext::decode(&long), None);
        let mut v2 = e.clone();
        v2[0] = 2;
        assert_eq!(ChannelContext::decode(&v2), None);
        assert_eq!(ChannelContext::decode(&e[..e.len() - 1]), None);
    }

    #[test]
    fn context_validity_rules() {
        let leaves = [[1u8; 32], [2; 32]];
        let base = ctx();
        assert_eq!(base.check(&[9; 32], &leaves), Ok(()));
        let bad = |f: &dyn Fn(&mut ChannelContext)| {
            let mut c = base.clone();
            f(&mut c);
            c.check(&[9; 32], &leaves)
        };
        assert_eq!(
            bad(&|c| c.history_policy = 1),
            Err(ContextFault::HistoryPolicy)
        );
        assert_eq!(bad(&|c| c.timer_code = 6), Err(ContextFault::Timer));
        assert_eq!(bad(&|c| c.size_class = 2), Err(ContextFault::SizeClass));
        assert_eq!(
            bad(&|c| c.idle_evict_days = 34),
            Err(ContextFault::IdleEvict)
        );
        assert_eq!(
            bad(&|c| c.idle_evict_days = 71),
            Err(ContextFault::IdleEvict)
        );
        assert_eq!(bad(&|c| c.flags = 0b10), Err(ContextFault::ReservedFlags));
        assert_eq!(bad(&|c| c.flags = 0b1000), Err(ContextFault::ReservedFlags));
        assert_eq!(
            bad(&|c| {
                c.flags = FLAG_PASSWORD | FLAG_MEMBERS_MAY_INVITE;
                c.pw_version = 1
            }),
            Err(ContextFault::PasswordAndMembersInvite)
        );
        assert_eq!(
            bad(&|c| c.flags = FLAG_PASSWORD),
            Err(ContextFault::PasswordPolicy)
        );
        assert_eq!(
            bad(&|c| {
                c.flags = FLAG_PASSWORD;
                c.pw_version = 1
            }),
            Ok(())
        );
        assert_eq!(
            bad(&|c| c.committers = vec![]),
            Err(ContextFault::Committers)
        );
        assert_eq!(
            bad(&|c| c.committers = vec![[1; 32], [1; 32]]),
            Err(ContextFault::Committers)
        );
        assert_eq!(
            bad(&|c| c.committers = vec![[3; 32]]),
            Err(ContextFault::NotALeaf)
        );
        assert_eq!(
            bad(&|c| c.funders = vec![[3; 32]]),
            Err(ContextFault::NotALeaf)
        );
        assert_eq!(bad(&|c| c.name = vec![0xff]), Err(ContextFault::Name));
        assert_eq!(
            bad(&|c| c.channel_id = [8; 32]),
            Err(ContextFault::ChannelId)
        );
        let many: Vec<[u8; 32]> = (0..33u8).map(|i| [i; 32]).collect();
        let mut c = base.clone();
        c.committers = vec![[0; 32]];
        c.funders = vec![];
        assert_eq!(c.check(&[9; 32], &many), Err(ContextFault::MemberCount));
    }

    #[test]
    fn password_policy_transitions() {
        let open = ctx();
        let mut set = ctx();
        set.flags = FLAG_PASSWORD;
        set.pw_version = 1;
        // Set: +1 by rank 0 only.
        assert_eq!(set.check_password_change(&open, 0), Ok(()));
        assert_eq!(
            set.check_password_change(&open, 1),
            Err(ContextFault::PasswordPolicy)
        );
        // Change: +1 while set; +2 refused; a decrease refused.
        let mut changed = set.clone();
        changed.pw_version = 2;
        assert_eq!(changed.check_password_change(&set, 0), Ok(()));
        let mut jump = set.clone();
        jump.pw_version = 3;
        assert_eq!(
            jump.check_password_change(&set, 0),
            Err(ContextFault::PasswordPolicy)
        );
        assert_eq!(
            set.check_password_change(&changed, 0),
            Err(ContextFault::PasswordPolicy)
        );
        // Remove: clear the flag without a bump (§19.29.3).
        let mut removed = changed.clone();
        removed.flags = 0;
        assert_eq!(removed.check_password_change(&changed, 0), Ok(()));
        let mut removed_bumped = removed.clone();
        removed_bumped.pw_version = 3;
        assert_eq!(
            removed_bumped.check_password_change(&changed, 0),
            Err(ContextFault::PasswordPolicy)
        );
        // Unchanged: any rank.
        assert_eq!(changed.check_password_change(&changed, 255), Ok(()));
    }

    #[test]
    fn fixed_formats_round_trip() {
        let l = GhostLeaf {
            box_pk: [5; 32],
            refresh_epoch: 7,
        };
        assert_eq!(l.encode().len(), GhostLeaf::LEN);
        assert_eq!(GhostLeaf::decode(&l.encode()), Some(l));
        let b = KpBind {
            channel_id: [3; 32],
            purpose: Purpose::Restore,
            day: 20_725,
        };
        assert_eq!(b.encode().len(), KpBind::LEN);
        assert_eq!(KpBind::decode(&b.encode()), Some(b));
        let mut bad = b.encode();
        bad[33] = 4;
        assert_eq!(KpBind::decode(&bad), None);
        let s = Bootstrap {
            generation: 2,
            open_epoch: 9,
            g: [1; 32],
        };
        assert_eq!(s.encode().len(), Bootstrap::LEN);
        assert_eq!(Bootstrap::decode(&s.encode()), Some(s));
        let o = ChannelOrder {
            sender_leaf: 3,
            seq: 11,
        };
        assert_eq!(ChannelOrder::decode(&o.encode()), Some(o));
    }

    #[test]
    fn commit_aad_round_trips_and_is_strict() {
        let admit = AdmitEvidence {
            kp_ref: vec![1; 32],
            invite_id: [2; 16],
            invite_pk: [3; 32],
            expiry_day: 20_000,
            sponsor: [4; 32],
            sponsor_sig: [5; 64],
            invite_sig: [6; 64],
        };
        let aad = CommitAad {
            commit_minute: 29_000_000,
            rotate: true,
            admits: vec![admit.clone()],
            swaps: vec![
                SwapEvidence::Rejoin {
                    kp_ref: vec![7; 32],
                    generation: 1,
                    day: 20_001,
                    last_epoch: 5,
                    last_hash: [8; 32],
                    rejoin_sig: [9; 64],
                },
                SwapEvidence::Restore(admit.clone()),
            ],
        };
        let e = aad.encode();
        assert_eq!(CommitAad::decode(&e), Some(aad));
        // The measured sizes of §5.7's evidence: 245 B admit, 146 B rejoin, 279 B restore (with
        // their share of the vector headers, the V10-4 accounting).
        let empty = CommitAad::default().encode();
        assert_eq!(empty.len(), 8);
        let mut flags = e.clone();
        flags[5] = 2;
        assert_eq!(CommitAad::decode(&flags), None);
        let mut trailing = e.clone();
        trailing.push(0);
        assert_eq!(CommitAad::decode(&trailing), None);
    }
}
