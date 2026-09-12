//! The Entitlement Schedule (ES, Phase 8 design §3.1, §19.2): one canonical, offline-signed,
//! append-only binary document holding every key, permutation proof, price, constant and the
//! relay slot table. There is no network path for keys: the client embeds the ES in its native
//! library, relays and the issuer load it from their configuration.
//!
//! ```text
//! ES v1 := "GHES" || version u8 = 1 || seq u64 || network u8 {1 mainnet, 2 stagenet, 3 regtest}
//!   || issuer_name <u16 ASCII 1..64> || issuer_onion <u16 "<56>.onion:<port>">
//!   || confirmations u8 || invoice_blocks u16 || grace_blocks u16 || access_per_slot u8
//!   || trial_per_slot u8 || invites_per_pack u8 || credits_per_free_pack u8
//!   || min_claim_credits u8 || max_claim_credits u8 || early_window_hours u8
//!   || capability_quota_bytes u64
//!   || slot count u8 (1..64) || count x (slot u8 (0..31) || onion <u16> || valid_from_week u64
//!                                        || valid_until_week u64 (0 = open))
//!   || price count u16 || count x (price_epoch u64 || pack_price_atomic u64 (divisible by 10))
//!   || key count u16 || count x (kind u8 || epoch u64 || spki <u16 DER> || proof 8 x 256)
//!   || revoked count u16 || count x (kind u8 || epoch u64)
//!   || Ed25519 signature over "ghost/v1/entitlement-schedule" || all preceding bytes (64)
//! ```
//! Big-endian fixed fields; `<u16>` is a u16-length-prefixed byte string.
//!
//! Validity rules (each has a negative test): (1) magic, version, exact lengths, no trailing
//! bytes, signature under the pinned key; (2) (kind, epoch) unique, every key id and modulus
//! distinct, every SPKI canonical, 2048-bit, e = 65537, no prime factor <= 65 537, permutation
//! proof valid; (3) access keys cover >= 26 consecutive weeks, invite and credit keys and prices
//! cover the epochs those weeks touch; (4) per slot number non-overlapping week ranges, onions
//! valid, every covered week has a slot; (5) append-only against local memory
//! ([`ScheduleMemory`]: keys, slot sets, prices and revocations); (6) the production client
//! refuses regtest ([`Schedule::refuse_regtest`]).

use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::{Signature, VerifyingKey};
use ghost_blind_rsa::{PublicKey, PROOF_BLOCK_LEN, PROOF_ROUNDS};
use sha2::{Digest, Sha256};

use crate::challenge::{challenge_digest, MAX_SLOT};
use crate::grid::{credit_epoch, invite_epoch, price_epoch, Kind};
use crate::monero::MoneroNetwork;
use crate::onion::Onion;
use crate::token::{self, Token};
use crate::FormatError;

pub const MAGIC: &[u8; 4] = b"GHES";
pub const VERSION: u8 = 1;
/// Domain separation of the schedule signature.
pub const SIGNATURE_DOMAIN: &[u8] = b"ghost/v1/entitlement-schedule";
/// A schedule covers at least this many consecutive access weeks.
pub const MIN_ACCESS_WEEKS: u64 = 26;
/// At most this many slots are valid in one week (slot numbers 0..31).
pub const MAX_SLOTS_PER_WEEK: usize = 32;
const MAX_SLOT_ENTRIES: usize = 64;
const MAX_ISSUER_NAME_LEN: usize = 64;
const SIGNATURE_LEN: usize = 64;
/// A pack price is divisible by 10 so a credit's value (price / 10) is exact (design §4.6).
const CREDITS_PER_PRICE: u64 = 10;

/// Schedule public keys pinned per network (design §3.1 rule 1, §19.20 point 3), at most one per
/// network and pairwise distinct. [`Schedule::verify`] picks the key by the schedule's network
/// byte, which the signature covers, so a key pinned for one network never verifies a schedule of
/// another.
///
/// - Stagenet: the stagenet-only schedule key of slice S2b (§15.1, §19.17 point 1, Q20 as revised
///   2026-09-12), generated with `ghost-issuer-ops keygen --new-schedule-key` on the owner's
///   machine outside the repository. It signs the alpha's stagenet schedules only.
/// - Mainnet: none until the K1 ceremony with the real offline key (Phase 16/17); until then every
///   mainnet schedule is refused (fail closed).
/// - Regtest: never pinned; regtest schedules are test schedules (rule 6).
const PINNED_SCHEDULE_KEYS: &[(MoneroNetwork, [u8; 32])] = &[(
    MoneroNetwork::Stagenet,
    [
        0x8b, 0x95, 0xa7, 0x51, 0x97, 0x43, 0x52, 0x37, 0x27, 0x33, 0x71, 0x8e, 0x49, 0x35, 0x8b,
        0xe2, 0xf2, 0x8b, 0xbc, 0x5c, 0x45, 0xd1, 0xbf, 0x4a, 0x4d, 0xd7, 0xb6, 0xc1, 0x66, 0x4b,
        0x7d, 0xad,
    ],
)];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScheduleError {
    /// Truncated, trailing bytes, bad magic or version, or a malformed length prefix (rule 1).
    Encoding,
    /// Unknown network byte.
    Network,
    /// No schedule key is pinned for the schedule's network.
    NoPinnedKey,
    /// The Ed25519 signature does not verify (rule 1).
    Signature,
    /// issuer_name is not 1..64 printable ASCII characters.
    IssuerName,
    /// An onion address is not a canonical v3 address (rules 1 and 4).
    Onion,
    /// A protocol constant is out of range.
    Constants,
    /// A slot entry is malformed or overlaps another entry of the same slot (rule 4).
    SlotTable,
    /// A price entry is duplicated, zero or not divisible by 10.
    PriceTable,
    /// A key entry duplicates a (kind, epoch), a key id or a modulus (rule 2).
    DuplicateKey,
    /// A key entry has an unknown kind, or its SPKI is not canonical, not 2048-bit or e != 65537
    /// (rule 2).
    KeyFormat,
    /// A key has a small prime factor or its permutation proof fails (rule 2).
    KeyProof,
    /// Access keys do not cover 26 consecutive weeks, or an invite/credit key, a price or a
    /// slot is missing for a covered week (rules 3 and 4).
    Coverage,
    /// A revocation names an unknown or duplicated (kind, epoch).
    Revocation,
    /// `seq` went backwards against local memory (rule 5).
    Rollback,
    /// A remembered (kind, epoch) has another key id or is missing (rule 5).
    KeyChanged,
    /// The slot numbers of a remembered week changed (rule 5, §19.2).
    SlotSetChanged,
    /// The price of a remembered price epoch changed (rule 5, §19.2).
    PriceChanged,
    /// A remembered revocation is missing: revocations are append-only too (rule 5, runbook I1).
    RevocationDropped,
    /// A regtest schedule offered to the production client (rule 6).
    RegtestRefused,
}

impl std::fmt::Display for ScheduleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

impl std::error::Error for ScheduleError {}

/// Why a token was refused by [`Schedule::verify_token`]. Relays report all of them as one
/// `rejected_token` (no oracle between forged, wrong-kind and wrong-slot tokens, design §10.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TokenError {
    /// `token_key_id` is not an ES key.
    UnknownKey,
    /// The key belongs to another kind than expected.
    WrongKind,
    /// The (kind, epoch) of the key is revoked.
    Revoked,
    /// The verifier's slot is not valid in the token's week.
    WrongSlot,
    /// `challenge_digest` does not match the expected challenge.
    Challenge,
    /// The authenticator does not verify.
    Signature,
}

/// Protocol constants of the schedule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Constants {
    pub confirmations: u8,
    pub invoice_blocks: u16,
    pub grace_blocks: u16,
    pub access_per_slot: u8,
    pub trial_per_slot: u8,
    pub invites_per_pack: u8,
    pub credits_per_free_pack: u8,
    pub min_claim_credits: u8,
    pub max_claim_credits: u8,
    pub early_window_hours: u8,
    pub capability_quota_bytes: u64,
}

impl Constants {
    fn check(&self) -> Result<(), ScheduleError> {
        let ok = self.confirmations >= 1
            && self.invoice_blocks >= 1
            && self.grace_blocks >= 1
            && self.access_per_slot >= 1
            && self.trial_per_slot >= 1
            && self.credits_per_free_pack >= 1
            && self.min_claim_credits >= 1
            && self.min_claim_credits <= self.max_claim_credits
            && self.capability_quota_bytes >= 1;
        ok.then_some(()).ok_or(ScheduleError::Constants)
    }
}

/// One row of the slot table: `slot` is served by `onion` in weeks `[valid_from, valid_until)`
/// (`valid_until_week == 0`: open-ended).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotEntry {
    pub slot: u8,
    pub onion: String,
    pub valid_from_week: u64,
    pub valid_until_week: u64,
}

impl SlotEntry {
    pub fn valid_in(&self, week: u64) -> bool {
        self.valid_from_week <= week && (self.valid_until_week == 0 || week < self.valid_until_week)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PriceEntry {
    pub price_epoch: u64,
    pub pack_price_atomic: u64,
}

/// A key entry as written in the schedule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyContent {
    pub kind: Kind,
    pub epoch: u64,
    pub spki: Vec<u8>,
    pub proof: [[u8; PROOF_BLOCK_LEN]; PROOF_ROUNDS],
}

/// The unsigned content of a schedule: the encoder's input (operator tools, tests) and the
/// parser's output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduleContent {
    pub seq: u64,
    pub network: MoneroNetwork,
    pub issuer_name: String,
    pub issuer_onion: String,
    pub constants: Constants,
    pub slots: Vec<SlotEntry>,
    pub prices: Vec<PriceEntry>,
    pub keys: Vec<KeyContent>,
    pub revoked: Vec<(Kind, u64)>,
}

impl ScheduleContent {
    /// The encoding of every field before the signature. Refuses what the format cannot carry.
    pub fn body(&self) -> Result<Vec<u8>, ScheduleError> {
        let mut w = Vec::new();
        w.extend_from_slice(MAGIC);
        w.push(VERSION);
        w.extend_from_slice(&self.seq.to_be_bytes());
        w.push(network_byte(self.network));
        put_u16_bytes(&mut w, self.issuer_name.as_bytes())?;
        put_u16_bytes(&mut w, self.issuer_onion.as_bytes())?;
        let c = &self.constants;
        w.push(c.confirmations);
        w.extend_from_slice(&c.invoice_blocks.to_be_bytes());
        w.extend_from_slice(&c.grace_blocks.to_be_bytes());
        w.extend_from_slice(&[
            c.access_per_slot,
            c.trial_per_slot,
            c.invites_per_pack,
            c.credits_per_free_pack,
            c.min_claim_credits,
            c.max_claim_credits,
            c.early_window_hours,
        ]);
        w.extend_from_slice(&c.capability_quota_bytes.to_be_bytes());
        w.push(u8::try_from(self.slots.len()).map_err(|_| ScheduleError::SlotTable)?);
        for s in &self.slots {
            w.push(s.slot);
            put_u16_bytes(&mut w, s.onion.as_bytes())?;
            w.extend_from_slice(&s.valid_from_week.to_be_bytes());
            w.extend_from_slice(&s.valid_until_week.to_be_bytes());
        }
        put_count(&mut w, self.prices.len())?;
        for p in &self.prices {
            w.extend_from_slice(&p.price_epoch.to_be_bytes());
            w.extend_from_slice(&p.pack_price_atomic.to_be_bytes());
        }
        put_count(&mut w, self.keys.len())?;
        for k in &self.keys {
            w.push(k.kind.byte());
            w.extend_from_slice(&k.epoch.to_be_bytes());
            put_u16_bytes(&mut w, &k.spki)?;
            for block in &k.proof {
                w.extend_from_slice(block);
            }
        }
        put_count(&mut w, self.revoked.len())?;
        for (kind, epoch) in &self.revoked {
            w.push(kind.byte());
            w.extend_from_slice(&epoch.to_be_bytes());
        }
        Ok(w)
    }

    /// The message the offline schedule key signs: `"ghost/v1/entitlement-schedule" || body`.
    pub fn signing_message(&self) -> Result<Vec<u8>, ScheduleError> {
        Ok([SIGNATURE_DOMAIN, &self.body()?].concat())
    }

    /// The complete schedule file: `body || signature`.
    pub fn to_signed_bytes(
        &self,
        signature: &[u8; SIGNATURE_LEN],
    ) -> Result<Vec<u8>, ScheduleError> {
        let mut out = self.body()?;
        out.extend_from_slice(signature);
        Ok(out)
    }
}

/// A key of a verified schedule.
#[derive(Debug, Clone)]
pub struct KeyEntry {
    pub kind: Kind,
    pub epoch: u64,
    pub key_id: [u8; 32],
    pub public_key: PublicKey,
}

/// What a verifier expects of a token (design §3.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expect {
    /// An ACCESS token for this relay slot (the relay of that slot, design §10.2).
    AccessAtSlot(u8),
    /// An ACCESS token for any slot the schedule lists in the token's week (a client checking a
    /// token it holds).
    AccessAnySlot,
    Invite,
    Credit,
}

/// A token that passed [`Schedule::verify_token`]. The acceptance window of `epoch` is the
/// caller's check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedToken {
    pub kind: Kind,
    pub epoch: u64,
    pub slot: Option<u8>,
    pub nullifier: [u8; 32],
}

/// Facts remembered from previously accepted schedules (client `ent_key`/`ent_schedule_fact`,
/// relay `es_keys`, issuer `es_memory`): rule 5 compares a new schedule against them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScheduleMemory {
    pub max_seq: Option<u64>,
    pub keys: BTreeMap<(Kind, u64), [u8; 32]>,
    pub week_slots: BTreeMap<u64, BTreeSet<u8>>,
    pub prices: BTreeMap<u64, u64>,
    /// Every (kind, epoch) a previously accepted schedule revoked: a later schedule may add
    /// revocations but never drop one, or a leaked key's tokens would become valid again.
    pub revoked: BTreeSet<(Kind, u64)>,
}

/// A parsed schedule whose signature and rules 1–4 hold.
#[derive(Debug, Clone)]
pub struct Schedule {
    content: ScheduleContent,
    keys: BTreeMap<(Kind, u64), KeyEntry>,
    key_ids: BTreeMap<[u8; 32], (Kind, u64)>,
    revoked: BTreeSet<(Kind, u64)>,
    first_access_week: u64,
    last_access_week: u64,
    digest: [u8; 32],
}

impl Schedule {
    /// The production entry point: verifies under the schedule key pinned for the schedule's
    /// network, then rules 1–4.
    pub fn verify(bytes: &[u8]) -> Result<Self, ScheduleError> {
        Self::verify_pinned(bytes, PINNED_SCHEDULE_KEYS)
    }

    /// [`Schedule::verify`] over a given pin table. The key is chosen by the network byte, which
    /// the signature covers: a schedule signed for one network cannot be read as another, and a
    /// key pinned for one network never verifies a schedule of another.
    fn verify_pinned(
        bytes: &[u8],
        pinned: &[(MoneroNetwork, [u8; 32])],
    ) -> Result<Self, ScheduleError> {
        let network = bytes
            .get(MAGIC.len() + 1 + 8)
            .copied()
            .ok_or(ScheduleError::Encoding)?;
        let network = MoneroNetwork::from_schedule_byte(network).ok_or(ScheduleError::Network)?;
        let key = pinned
            .iter()
            .find(|(n, _)| *n == network)
            .map(|(_, k)| k)
            .ok_or(ScheduleError::NoPinnedKey)?;
        Self::verify_with_key(bytes, key)
    }

    /// Verification under an explicit schedule key: test schedules and the operator tools.
    pub fn verify_with_key(bytes: &[u8], schedule_key: &[u8; 32]) -> Result<Self, ScheduleError> {
        if bytes.len() < SIGNATURE_LEN {
            return Err(ScheduleError::Encoding);
        }
        let (body, sig) = bytes.split_at(bytes.len() - SIGNATURE_LEN);
        // The signature is checked first: nothing unauthenticated reaches the parser's rules.
        let key = VerifyingKey::from_bytes(schedule_key).map_err(|_| ScheduleError::Signature)?;
        let sig = Signature::from_slice(sig).map_err(|_| ScheduleError::Signature)?;
        key.verify_strict(&[SIGNATURE_DOMAIN, body].concat(), &sig)
            .map_err(|_| ScheduleError::Signature)?;
        let content = parse_body(body)?;
        let mut schedule = Self::check(content)?;
        schedule.digest = Sha256::digest(bytes).into();
        Ok(schedule)
    }

    /// Rules 2–4 on parsed content.
    fn check(content: ScheduleContent) -> Result<Self, ScheduleError> {
        if content.issuer_name.is_empty()
            || content.issuer_name.len() > MAX_ISSUER_NAME_LEN
            || !content.issuer_name.bytes().all(|b| b.is_ascii_graphic())
        {
            return Err(ScheduleError::IssuerName);
        }
        canonical_onion(&content.issuer_onion)?;
        content.constants.check()?;
        check_slots(&content.slots)?;
        let mut price_epochs = BTreeSet::new();
        for p in &content.prices {
            if !price_epochs.insert(p.price_epoch)
                || p.pack_price_atomic == 0
                || p.pack_price_atomic % CREDITS_PER_PRICE != 0
            {
                return Err(ScheduleError::PriceTable);
            }
        }

        let mut keys = BTreeMap::new();
        let mut key_ids = BTreeMap::new();
        let mut moduli = BTreeSet::new();
        for k in &content.keys {
            let public_key = PublicKey::from_spki(&k.spki).map_err(|_| ScheduleError::KeyFormat)?;
            token::check_key(&public_key).map_err(|_| ScheduleError::KeyFormat)?;
            let key_id = token::key_id(&k.spki);
            if keys.contains_key(&(k.kind, k.epoch))
                || key_ids.contains_key(&key_id)
                || !moduli.insert(public_key.n_bytes().to_vec())
            {
                return Err(ScheduleError::DuplicateKey);
            }
            ghost_blind_rsa::verify_permutation_proof(&public_key, &k.proof)
                .map_err(|_| ScheduleError::KeyProof)?;
            key_ids.insert(key_id, (k.kind, k.epoch));
            keys.insert(
                (k.kind, k.epoch),
                KeyEntry {
                    kind: k.kind,
                    epoch: k.epoch,
                    key_id,
                    public_key,
                },
            );
        }

        // Rule 3: consecutive access weeks, and the invite/credit epochs and prices they touch.
        let access: Vec<u64> = keys
            .keys()
            .filter(|(k, _)| *k == Kind::Access)
            .map(|&(_, e)| e)
            .collect();
        let (&first, &last) = access
            .first()
            .zip(access.last())
            .ok_or(ScheduleError::Coverage)?;
        // first <= last (BTreeMap order); the + 1 overflows for epochs 0 and u64::MAX.
        let span = (last - first)
            .checked_add(1)
            .ok_or(ScheduleError::Coverage)?;
        if span != access.len() as u64 || span < MIN_ACCESS_WEEKS {
            return Err(ScheduleError::Coverage);
        }
        let prices: BTreeSet<u64> = content.prices.iter().map(|p| p.price_epoch).collect();
        for w in first..=last {
            let covered = keys.contains_key(&(Kind::Invite, invite_epoch(w)))
                && keys.contains_key(&(Kind::Credit, credit_epoch(w)))
                && prices.contains(&price_epoch(w))
                && content.slots.iter().any(|s| s.valid_in(w));
            if !covered {
                return Err(ScheduleError::Coverage);
            }
        }

        let mut revoked = BTreeSet::new();
        for r in &content.revoked {
            if !keys.contains_key(r) || !revoked.insert(*r) {
                return Err(ScheduleError::Revocation);
            }
        }
        Ok(Self {
            content,
            keys,
            key_ids,
            revoked,
            first_access_week: first,
            last_access_week: last,
            digest: [0; 32],
        })
    }

    /// Rule 5: the schedule is append-only against what was accepted before (keys, the slot sets
    /// of covered weeks and the prices of covered price epochs never change; revocations are never
    /// dropped; seq never goes backwards).
    pub fn check_memory(&self, memory: &ScheduleMemory) -> Result<(), ScheduleError> {
        if memory.max_seq.is_some_and(|s| self.content.seq < s) {
            return Err(ScheduleError::Rollback);
        }
        for (kind_epoch, key_id) in &memory.keys {
            if self.keys.get(kind_epoch).map(|k| &k.key_id) != Some(key_id) {
                return Err(ScheduleError::KeyChanged);
            }
        }
        for (week, slots) in &memory.week_slots {
            if &self
                .slots_in_week(*week)
                .into_iter()
                .collect::<BTreeSet<u8>>()
                != slots
            {
                return Err(ScheduleError::SlotSetChanged);
            }
        }
        for (epoch, price) in &memory.prices {
            if self.pack_price(*epoch) != Some(*price) {
                return Err(ScheduleError::PriceChanged);
            }
        }
        if !memory.revoked.is_subset(&self.revoked) {
            return Err(ScheduleError::RevocationDropped);
        }
        Ok(())
    }

    /// Records this schedule's facts after it was accepted.
    pub fn remember(&self, memory: &mut ScheduleMemory) {
        memory.max_seq = Some(
            memory
                .max_seq
                .map_or(self.content.seq, |s| s.max(self.content.seq)),
        );
        for (kind_epoch, entry) in &self.keys {
            memory.keys.insert(*kind_epoch, entry.key_id);
        }
        for w in self.first_access_week..=self.last_access_week {
            memory
                .week_slots
                .insert(w, self.slots_in_week(w).into_iter().collect());
        }
        for p in &self.content.prices {
            memory.prices.insert(p.price_epoch, p.pack_price_atomic);
        }
        memory.revoked.extend(self.revoked.iter().copied());
    }

    /// Rule 6: the production client refuses regtest schedules.
    pub fn refuse_regtest(&self) -> Result<(), ScheduleError> {
        match self.content.network {
            MoneroNetwork::Regtest => Err(ScheduleError::RegtestRefused),
            _ => Ok(()),
        }
    }

    pub fn content(&self) -> &ScheduleContent {
        &self.content
    }

    pub fn seq(&self) -> u64 {
        self.content.seq
    }

    pub fn network(&self) -> MoneroNetwork {
        self.content.network
    }

    pub fn issuer_name(&self) -> &str {
        &self.content.issuer_name
    }

    pub fn constants(&self) -> &Constants {
        &self.content.constants
    }

    /// SHA-256 of the whole schedule file.
    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    pub fn first_access_week(&self) -> u64 {
        self.first_access_week
    }

    pub fn last_access_week(&self) -> u64 {
        self.last_access_week
    }

    pub fn key(&self, kind: Kind, epoch: u64) -> Option<&KeyEntry> {
        self.keys.get(&(kind, epoch))
    }

    pub fn key_by_id(&self, key_id: &[u8]) -> Option<&KeyEntry> {
        let id: [u8; 32] = key_id.try_into().ok()?;
        self.key_ids.get(&id).and_then(|ke| self.keys.get(ke))
    }

    pub fn keys(&self) -> impl Iterator<Item = &KeyEntry> {
        self.keys.values()
    }

    pub fn is_revoked(&self, kind: Kind, epoch: u64) -> bool {
        self.revoked.contains(&(kind, epoch))
    }

    /// The slot numbers valid in `week`, ascending (the layout order of design §4.2).
    pub fn slots_in_week(&self, week: u64) -> Vec<u8> {
        let set: BTreeSet<u8> = self
            .content
            .slots
            .iter()
            .filter(|s| s.valid_in(week))
            .map(|s| s.slot)
            .collect();
        set.into_iter().collect()
    }

    /// The onion serving `slot` in `week`.
    pub fn slot_onion(&self, slot: u8, week: u64) -> Option<&str> {
        self.content
            .slots
            .iter()
            .find(|s| s.slot == slot && s.valid_in(week))
            .map(|s| s.onion.as_str())
    }

    pub fn pack_price(&self, price_epoch: u64) -> Option<u64> {
        self.content
            .prices
            .iter()
            .find(|p| p.price_epoch == price_epoch)
            .map(|p| p.pack_price_atomic)
    }

    /// A credit's value: the pack price of the credit epoch of its key, divided by 10 (exact).
    pub fn credit_value(&self, credit_epoch: u64) -> Option<u64> {
        self.pack_price(credit_epoch).map(|p| p / CREDITS_PER_PRICE)
    }

    /// `challenge_digest` under this schedule's issuer name.
    pub fn challenge_digest(
        &self,
        kind: Kind,
        epoch: u64,
        slot: Option<u8>,
    ) -> Result<[u8; 32], FormatError> {
        challenge_digest(&self.content.issuer_name, kind, epoch, slot)
    }

    /// Verifies a token against the schedule in the relay's order (design §10.2 steps 4, 6, 7):
    /// the key id names an ES key of the expected kind, not revoked; the challenge digest matches
    /// the expected (kind, epoch, slot); `ring` verifies the authenticator. The nullifier is
    /// computed here, never read from the wire.
    pub fn verify_token(&self, token: &Token, expect: Expect) -> Result<VerifiedToken, TokenError> {
        let entry = self
            .key_by_id(token.key_id())
            .ok_or(TokenError::UnknownKey)?;
        let expected_kind = match expect {
            Expect::AccessAtSlot(_) | Expect::AccessAnySlot => Kind::Access,
            Expect::Invite => Kind::Invite,
            Expect::Credit => Kind::Credit,
        };
        if entry.kind != expected_kind {
            return Err(TokenError::WrongKind);
        }
        if self.is_revoked(entry.kind, entry.epoch) {
            return Err(TokenError::Revoked);
        }
        let digest_of =
            |slot: Option<u8>| self.challenge_digest(entry.kind, entry.epoch, slot).ok();
        let slot = match expect {
            Expect::AccessAtSlot(s) => {
                if !self.slots_in_week(entry.epoch).contains(&s) {
                    return Err(TokenError::WrongSlot);
                }
                if digest_of(Some(s)).as_ref().map(|d| d.as_slice())
                    != Some(token.challenge_digest())
                {
                    return Err(TokenError::Challenge);
                }
                Some(s)
            }
            Expect::AccessAnySlot => Some(
                self.slots_in_week(entry.epoch)
                    .into_iter()
                    .find(|&s| {
                        digest_of(Some(s)).as_ref().map(|d| d.as_slice())
                            == Some(token.challenge_digest())
                    })
                    .ok_or(TokenError::Challenge)?,
            ),
            Expect::Invite | Expect::Credit => {
                if digest_of(None).as_ref().map(|d| d.as_slice()) != Some(token.challenge_digest())
                {
                    return Err(TokenError::Challenge);
                }
                None
            }
        };
        token
            .verify_signature(&entry.public_key)
            .map_err(|_| TokenError::Signature)?;
        Ok(VerifiedToken {
            kind: entry.kind,
            epoch: entry.epoch,
            slot,
            nullifier: token.nullifier(),
        })
    }
}

fn check_slots(slots: &[SlotEntry]) -> Result<(), ScheduleError> {
    if slots.is_empty() || slots.len() > MAX_SLOT_ENTRIES {
        return Err(ScheduleError::SlotTable);
    }
    for (i, s) in slots.iter().enumerate() {
        if s.slot > MAX_SLOT || (s.valid_until_week != 0 && s.valid_until_week <= s.valid_from_week)
        {
            return Err(ScheduleError::SlotTable);
        }
        canonical_onion(&s.onion)?;
        // Same slot number: the week ranges must not overlap (a relay changes at a week boundary).
        for t in &slots[..i] {
            if t.slot == s.slot && ranges_overlap(s, t) {
                return Err(ScheduleError::SlotTable);
            }
        }
    }
    // Slot numbers are 0..31 and one entry per slot and week: at most 32 slots in any week.
    debug_assert!(usize::from(MAX_SLOT) < MAX_SLOTS_PER_WEEK);
    Ok(())
}

fn ranges_overlap(a: &SlotEntry, b: &SlotEntry) -> bool {
    let end = |s: &SlotEntry| {
        if s.valid_until_week == 0 {
            u64::MAX
        } else {
            s.valid_until_week
        }
    };
    a.valid_from_week < end(b) && b.valid_from_week < end(a)
}

fn canonical_onion(text: &str) -> Result<(), ScheduleError> {
    let onion = Onion::parse(text).map_err(|_| ScheduleError::Onion)?;
    (onion.format() == text)
        .then_some(())
        .ok_or(ScheduleError::Onion)
}

fn network_byte(n: MoneroNetwork) -> u8 {
    n.schedule_byte()
}

fn put_u16_bytes(w: &mut Vec<u8>, bytes: &[u8]) -> Result<(), ScheduleError> {
    let len = u16::try_from(bytes.len()).map_err(|_| ScheduleError::Encoding)?;
    w.extend_from_slice(&len.to_be_bytes());
    w.extend_from_slice(bytes);
    Ok(())
}

fn put_count(w: &mut Vec<u8>, count: usize) -> Result<(), ScheduleError> {
    let count = u16::try_from(count).map_err(|_| ScheduleError::Encoding)?;
    w.extend_from_slice(&count.to_be_bytes());
    Ok(())
}

fn parse_body(body: &[u8]) -> Result<ScheduleContent, ScheduleError> {
    let mut r = Reader(body);
    if r.take(4)? != MAGIC || r.u8()? != VERSION {
        return Err(ScheduleError::Encoding);
    }
    let seq = r.u64()?;
    let network = MoneroNetwork::from_schedule_byte(r.u8()?).ok_or(ScheduleError::Network)?;
    let issuer_name = r.ascii()?;
    let issuer_onion = r.ascii()?;
    let constants = Constants {
        confirmations: r.u8()?,
        invoice_blocks: r.u16()?,
        grace_blocks: r.u16()?,
        access_per_slot: r.u8()?,
        trial_per_slot: r.u8()?,
        invites_per_pack: r.u8()?,
        credits_per_free_pack: r.u8()?,
        min_claim_credits: r.u8()?,
        max_claim_credits: r.u8()?,
        early_window_hours: r.u8()?,
        capability_quota_bytes: r.u64()?,
    };
    let slot_count = r.u8()?;
    let mut slots = Vec::with_capacity(usize::from(slot_count));
    for _ in 0..slot_count {
        slots.push(SlotEntry {
            slot: r.u8()?,
            onion: r.ascii()?,
            valid_from_week: r.u64()?,
            valid_until_week: r.u64()?,
        });
    }
    let price_count = r.u16()?;
    let mut prices = Vec::with_capacity(usize::from(price_count));
    for _ in 0..price_count {
        prices.push(PriceEntry {
            price_epoch: r.u64()?,
            pack_price_atomic: r.u64()?,
        });
    }
    let key_count = r.u16()?;
    let mut keys = Vec::with_capacity(usize::from(key_count));
    for _ in 0..key_count {
        let kind = Kind::from_byte(r.u8()?).ok_or(ScheduleError::KeyFormat)?;
        let epoch = r.u64()?;
        let spki_len = usize::from(r.u16()?);
        let spki = r.take(spki_len)?.to_vec();
        let mut proof = [[0u8; PROOF_BLOCK_LEN]; PROOF_ROUNDS];
        for block in proof.iter_mut() {
            block.copy_from_slice(r.take(PROOF_BLOCK_LEN)?);
        }
        keys.push(KeyContent {
            kind,
            epoch,
            spki,
            proof,
        });
    }
    let revoked_count = r.u16()?;
    let mut revoked = Vec::with_capacity(usize::from(revoked_count));
    for _ in 0..revoked_count {
        let kind = Kind::from_byte(r.u8()?).ok_or(ScheduleError::Revocation)?;
        revoked.push((kind, r.u64()?));
    }
    if !r.0.is_empty() {
        return Err(ScheduleError::Encoding);
    }
    Ok(ScheduleContent {
        seq,
        network,
        issuer_name,
        issuer_onion,
        constants,
        slots,
        prices,
        keys,
        revoked,
    })
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], ScheduleError> {
        if self.0.len() < n {
            return Err(ScheduleError::Encoding);
        }
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        Ok(head)
    }

    fn u8(&mut self) -> Result<u8, ScheduleError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, ScheduleError> {
        Ok(u16::from_be_bytes(
            self.take(2)?
                .try_into()
                .map_err(|_| ScheduleError::Encoding)?,
        ))
    }

    fn u64(&mut self) -> Result<u64, ScheduleError> {
        Ok(u64::from_be_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| ScheduleError::Encoding)?,
        ))
    }

    /// A `<u16>` string of ASCII bytes.
    fn ascii(&mut self) -> Result<String, ScheduleError> {
        let len = usize::from(self.u16()?);
        let bytes = self.take(len)?;
        if !bytes.is_ascii() {
            return Err(ScheduleError::Encoding);
        }
        String::from_utf8(bytes.to_vec()).map_err(|_| ScheduleError::Encoding)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer as _, SigningKey};

    /// A schedule of `network` signed by `key`. Its content fails rule 4 (no issuer onion), so a
    /// verification that reports `Onion` got past the signature.
    fn signed(network: MoneroNetwork, key: &SigningKey) -> Vec<u8> {
        let content = ScheduleContent {
            seq: 1,
            network,
            issuer_name: "ghost-issuer".into(),
            issuer_onion: String::new(),
            constants: Constants {
                confirmations: 10,
                invoice_blocks: 720,
                grace_blocks: 2160,
                access_per_slot: 16,
                trial_per_slot: 8,
                invites_per_pack: 2,
                credits_per_free_pack: 10,
                min_claim_credits: 10,
                max_claim_credits: 50,
                early_window_hours: 24,
                capability_quota_bytes: 268_435_456,
            },
            slots: Vec::new(),
            prices: Vec::new(),
            keys: Vec::new(),
            revoked: Vec::new(),
        };
        let signature = key.sign(&content.signing_message().unwrap()).to_bytes();
        content.to_signed_bytes(&signature).unwrap()
    }

    #[test]
    fn pinned_keys_are_one_per_network_and_distinct() {
        let networks: BTreeSet<u8> = PINNED_SCHEDULE_KEYS
            .iter()
            .map(|(n, _)| network_byte(*n))
            .collect();
        let keys: BTreeSet<[u8; 32]> = PINNED_SCHEDULE_KEYS.iter().map(|(_, k)| *k).collect();
        assert_eq!(networks.len(), PINNED_SCHEDULE_KEYS.len());
        assert_eq!(keys.len(), PINNED_SCHEDULE_KEYS.len());
        let pinned = |n: MoneroNetwork| PINNED_SCHEDULE_KEYS.iter().any(|(m, _)| *m == n);
        // S2b pins the stagenet key; the mainnet key comes from the K1 ceremony (Phase 16/17);
        // regtest schedules are test schedules, verified under an explicit key only (rule 6).
        assert!(pinned(MoneroNetwork::Stagenet));
        assert!(!pinned(MoneroNetwork::Mainnet));
        assert!(!pinned(MoneroNetwork::Regtest));
        for (_, key) in PINNED_SCHEDULE_KEYS {
            assert!(VerifyingKey::from_bytes(key).is_ok());
        }
    }

    #[test]
    fn a_key_pinned_for_one_network_never_verifies_another() {
        let key = SigningKey::from_bytes(&[0x5a; 32]);
        let other = SigningKey::from_bytes(&[0xa5; 32]);
        let public = key.verifying_key().to_bytes();
        let stagenet_only = [(MoneroNetwork::Stagenet, public)];
        let both = [
            (MoneroNetwork::Stagenet, public),
            (MoneroNetwork::Mainnet, other.verifying_key().to_bytes()),
        ];
        let verdict = |bytes: &[u8], table: &[(MoneroNetwork, [u8; 32])]| {
            Schedule::verify_pinned(bytes, table).err()
        };
        // Past the signature under its own network's pin.
        let stagenet = signed(MoneroNetwork::Stagenet, &key);
        assert_eq!(
            verdict(&stagenet, &stagenet_only),
            Some(ScheduleError::Onion)
        );
        // A mainnet or regtest schedule signed by the stagenet key: no pin for its network, or the
        // mainnet pin, which is another key.
        for network in [MoneroNetwork::Mainnet, MoneroNetwork::Regtest] {
            let bytes = signed(network, &key);
            assert_eq!(
                verdict(&bytes, &stagenet_only),
                Some(ScheduleError::NoPinnedKey)
            );
        }
        assert_eq!(
            verdict(&signed(MoneroNetwork::Mainnet, &key), &both),
            Some(ScheduleError::Signature)
        );
        // The network byte is signed: a stagenet schedule relabelled as mainnet verifies under
        // no key, not even the one that signed it.
        let offset = MAGIC.len() + 1 + 8;
        for network in [MoneroNetwork::Mainnet, MoneroNetwork::Regtest] {
            let mut relabelled = stagenet.clone();
            relabelled[offset] = network_byte(network);
            assert_eq!(
                Schedule::verify_with_key(&relabelled, &public).err(),
                Some(ScheduleError::Signature)
            );
            assert!(verdict(&relabelled, &both).is_some());
        }
        // The production table: whatever key signed a mainnet or regtest schedule, the stagenet
        // pin never verifies it.
        for signer in [&key, &other] {
            for network in [MoneroNetwork::Mainnet, MoneroNetwork::Regtest] {
                assert!(matches!(
                    Schedule::verify(&signed(network, signer)),
                    Err(ScheduleError::NoPinnedKey | ScheduleError::Signature)
                ));
            }
        }
    }
}
