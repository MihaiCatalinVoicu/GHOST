//! Seed-derived blinding batches (Phase 8 design §2.6, §4.2, §4.3). A flow (pack purchase, trial,
//! credit refresh) persists one 32-byte CSPRNG seed; every nonce, PSS salt and blinding factor r
//! is an HKDF-SHA256 output over the position, so a retry after any crash sends byte-identical
//! blinded messages. The layout is a pure function of (base week, product) under every schedule
//! version that covers the base week (§19.2).
//!
//! ```text
//! prk     = HKDF-Extract(salt = "ghost/v1/blind-batch", ikm = seed)
//! info_j  = kind(1) || epoch(8, BE) || slot(1, 0xFF if none) || j(2, BE)
//! okm     = HKDF-Expand(prk, info_j || "n", 80)      nonce_j = okm[0..32], salt_j = okm[32..80]
//! r_j     = first c in 0..=255 with R = OS2IP(HKDF-Expand(prk, info_j || "r" || c, 256)),
//!           1 < R < n and gcd(R, n) = 1
//! input_j = 0x0002 || nonce_j || challenge_digest(kind, epoch, slot) || key_id(kind, epoch)
//! B_j     = I2OSP(EMSA-PSS-ENCODE(input_j, 2047, salt_j) * r_j^e mod n, 256)
//! ```
//! r, its inverse, nonces, salts, blinded messages and blind signatures exist only inside one call
//! (the JNI boundary, design §11.7); Kotlin holds only the seed and the layout parameters.

use ghost_blind_rsa::{BigUint, SALT_LEN};
use ring::hkdf;
use sha2::{Digest, Sha256};

use crate::grid::{credit_epoch, invite_epoch, Kind};
use crate::schedule::Schedule;
use crate::token::{self, Token, AUTHENTICATOR_LEN, NONCE_LEN, TOKEN_INPUT_LEN};
use crate::FormatError;

pub const SEED_LEN: usize = 32;
/// A pack covers the base week and the next four.
pub const PACK_WEEKS: u64 = 5;
/// A trial covers the base week and the next one.
pub const TRIAL_WEEKS: u64 = 2;
/// Positions are numbered with a u16.
pub const MAX_POSITIONS: usize = 1 << 16;
/// Rejection-sampling budget for r (failure probability about 2^-256).
pub const R_TRIES: u16 = 256;
/// The slot byte of positions that have no relay slot (INVITE, CREDIT).
pub const NO_SLOT: u8 = 0xFF;

const PRK_SALT: &[u8] = b"ghost/v1/blind-batch";
const LAYOUT_DOMAIN: &[u8] = b"ghost/v1/layout";
const BLINDSIGN_DOMAIN: &[u8] = b"ghost/v1/blindsign";
const TRIAL_DOMAIN: &[u8] = b"ghost/v1/trial";
const CLAIM_DOMAIN: &[u8] = b"ghost/v1/issuer-claim";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BatchError {
    /// The schedule has no key for a position's (kind, epoch).
    MissingKey,
    /// A covered week has no slot, or the layout is empty or too long.
    Layout,
    /// The stored layout digest differs from the recomputed layout.
    LayoutDigest,
    /// HKDF failed or no admissible r within 256 tries.
    Derivation,
    /// The response is not N x 256 bytes.
    ResponseLength,
    /// A blind signature fails s'^e == B (mod n).
    BlindSignature,
    /// Blinding or finalization refused (includes a signature that does not verify).
    Format(FormatError),
}

impl std::fmt::Display for BatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

impl std::error::Error for BatchError {}

impl From<FormatError> for BatchError {
    fn from(e: FormatError) -> Self {
        BatchError::Format(e)
    }
}

/// One position of a layout: which key signs it and which challenge it carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Position {
    pub kind: Kind,
    pub epoch: u64,
    pub slot: Option<u8>,
}

impl Position {
    /// `kind(1) || epoch(8, BE) || slot(1)`, the unit of the layout digest and of `info_j`.
    fn encode(&self) -> [u8; 10] {
        let mut out = [0u8; 10];
        out[0] = self.kind.byte();
        out[1..9].copy_from_slice(&self.epoch.to_be_bytes());
        out[9] = self.slot.unwrap_or(NO_SLOT);
        out
    }
}

/// A frozen, ordered list of positions whose keys all exist in the schedule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layout {
    positions: Vec<Position>,
}

impl Layout {
    /// The pack layout (design §4.2): for each week base..base+4 and each slot of that week in
    /// ascending order, `access_per_slot` ACCESS positions; then `invites_per_pack` INVITE
    /// positions of `invite_epoch(base)`; then, when paid in XMR, one CREDIT position of
    /// `credit_epoch(base)`.
    pub fn pack(
        schedule: &Schedule,
        base_week: u64,
        paid_in_xmr: bool,
    ) -> Result<Self, BatchError> {
        let c = *schedule.constants();
        let mut positions = access_positions(schedule, base_week, PACK_WEEKS, c.access_per_slot)?;
        let invite = Position {
            kind: Kind::Invite,
            epoch: invite_epoch(base_week),
            slot: None,
        };
        positions.extend(std::iter::repeat_n(invite, usize::from(c.invites_per_pack)));
        if paid_in_xmr {
            positions.push(Position {
                kind: Kind::Credit,
                epoch: credit_epoch(base_week),
                slot: None,
            });
        }
        Self::from_positions(schedule, positions)
    }

    /// The trial layout (design §4.3): weeks base and base+1, `trial_per_slot` ACCESS positions per
    /// slot; no invite and no credit position.
    pub fn trial(schedule: &Schedule, base_week: u64) -> Result<Self, BatchError> {
        let per_slot = schedule.constants().trial_per_slot;
        Self::from_positions(
            schedule,
            access_positions(schedule, base_week, TRIAL_WEEKS, per_slot)?,
        )
    }

    /// One CREDIT position of `credit_epoch` (`RefreshCredit`, design §19.8).
    pub fn refresh(schedule: &Schedule, credit_epoch: u64) -> Result<Self, BatchError> {
        Self::from_positions(
            schedule,
            vec![Position {
                kind: Kind::Credit,
                epoch: credit_epoch,
                slot: None,
            }],
        )
    }

    /// Any non-empty list of positions whose keys the schedule holds and whose slots are valid.
    pub fn from_positions(
        schedule: &Schedule,
        positions: Vec<Position>,
    ) -> Result<Self, BatchError> {
        if positions.is_empty() || positions.len() > MAX_POSITIONS {
            return Err(BatchError::Layout);
        }
        for p in &positions {
            if schedule.key(p.kind, p.epoch).is_none() {
                return Err(BatchError::MissingKey);
            }
            let slot_ok = match (p.kind, p.slot) {
                (Kind::Access, Some(s)) => schedule.slots_in_week(p.epoch).contains(&s),
                (Kind::Invite | Kind::Credit, None) => true,
                _ => false,
            };
            if !slot_ok {
                return Err(BatchError::Layout);
            }
        }
        Ok(Self { positions })
    }

    pub fn positions(&self) -> &[Position] {
        &self.positions
    }

    pub fn len(&self) -> usize {
        self.positions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.positions.is_empty()
    }

    /// `SHA-256("ghost/v1/layout" || (kind || epoch || slot) for every position)`.
    pub fn digest(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(LAYOUT_DOMAIN);
        for p in &self.positions {
            h.update(p.encode());
        }
        h.finalize().into()
    }

    /// Compares the recomputed layout with the digest stored at purchase time (before every send
    /// and every finalization).
    pub fn check_digest(&self, stored: &[u8]) -> Result<(), BatchError> {
        (self.digest().as_slice() == stored)
            .then_some(())
            .ok_or(BatchError::LayoutDigest)
    }
}

fn access_positions(
    schedule: &Schedule,
    base_week: u64,
    weeks: u64,
    per_slot: u8,
) -> Result<Vec<Position>, BatchError> {
    let end = base_week.checked_add(weeks).ok_or(BatchError::Layout)?;
    let mut positions = Vec::new();
    for week in base_week..end {
        let slots = schedule.slots_in_week(week);
        if slots.is_empty() {
            return Err(BatchError::Layout);
        }
        for slot in slots {
            let p = Position {
                kind: Kind::Access,
                epoch: week,
                slot: Some(slot),
            };
            positions.extend(std::iter::repeat_n(p, usize::from(per_slot)));
        }
    }
    Ok(positions)
}

/// Everything derived for one position. `r`, `inv`, the nonce and the salt are blinding secrets.
pub struct DerivedPosition {
    pub position: Position,
    pub nonce: [u8; NONCE_LEN],
    pub salt: [u8; SALT_LEN],
    pub r: BigUint,
    pub input: [u8; TOKEN_INPUT_LEN],
    pub blinded: [u8; AUTHENTICATOR_LEN],
    pub inv: BigUint,
}

impl std::fmt::Debug for DerivedPosition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DerivedPosition({:?}, ..)", self.position)
    }
}

/// Derives position `j` of `layout` from `seed`.
pub fn derive(
    schedule: &Schedule,
    seed: &[u8; SEED_LEN],
    layout: &Layout,
    j: usize,
) -> Result<DerivedPosition, BatchError> {
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, PRK_SALT).extract(seed);
    derive_with_prk(schedule, &prk, layout, j)
}

fn derive_with_prk(
    schedule: &Schedule,
    prk: &hkdf::Prk,
    layout: &Layout,
    j: usize,
) -> Result<DerivedPosition, BatchError> {
    let position = *layout.positions.get(j).ok_or(BatchError::Layout)?;
    let key = schedule
        .key(position.kind, position.epoch)
        .ok_or(BatchError::MissingKey)?;
    let pk = &key.public_key;
    let index = u16::try_from(j).map_err(|_| BatchError::Layout)?;
    let mut info = [0u8; 12];
    info[..10].copy_from_slice(&position.encode());
    info[10..].copy_from_slice(&index.to_be_bytes());

    let okm = expand(prk, &[&info, b"n"], NONCE_LEN + SALT_LEN)?;
    let mut nonce = [0u8; NONCE_LEN];
    let mut salt = [0u8; SALT_LEN];
    nonce.copy_from_slice(&okm[..NONCE_LEN]);
    salt.copy_from_slice(&okm[NONCE_LEN..]);

    let one = BigUint::from(1u32);
    let mut r = None;
    for c in 0..R_TRIES {
        let candidate =
            BigUint::from_bytes_be(&expand(prk, &[&info, b"r", &[c as u8]], AUTHENTICATOR_LEN)?);
        if candidate > one
            && &candidate < pk.n()
            && ghost_blind_rsa::mod_inv(&candidate, pk.n()).is_some()
        {
            r = Some(candidate);
            break;
        }
    }
    let r = r.ok_or(BatchError::Derivation)?;

    let digest = schedule.challenge_digest(position.kind, position.epoch, position.slot)?;
    let input = token::token_input(&nonce, &digest, &key.key_id);
    let (blinded, inv) = token::blind_input(pk, &input, &salt, &r)?;
    Ok(DerivedPosition {
        position,
        nonce,
        salt,
        r,
        input,
        blinded,
        inv,
    })
}

/// The blinded request `B_0 || ... || B_{N-1}` (N x 256 bytes).
pub fn blind(
    schedule: &Schedule,
    seed: &[u8; SEED_LEN],
    layout: &Layout,
) -> Result<Vec<u8>, BatchError> {
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, PRK_SALT).extract(seed);
    let mut request = Vec::with_capacity(layout.len() * AUTHENTICATOR_LEN);
    for j in 0..layout.len() {
        request.extend_from_slice(&derive_with_prk(schedule, &prk, layout, j)?.blinded);
    }
    Ok(request)
}

/// Finalizes a response of N blind signatures: every `s'^e == B` is checked, every signature is
/// unblinded and verified by `ring`. One bad position refuses the whole response.
pub fn finalize(
    schedule: &Schedule,
    seed: &[u8; SEED_LEN],
    layout: &Layout,
    blind_sigs: &[u8],
) -> Result<Vec<Token>, BatchError> {
    if blind_sigs.len() != layout.len() * AUTHENTICATOR_LEN {
        return Err(BatchError::ResponseLength);
    }
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, PRK_SALT).extract(seed);
    let mut tokens = Vec::with_capacity(layout.len());
    let (sigs, _) = blind_sigs.as_chunks::<AUTHENTICATOR_LEN>();
    for (j, sig) in sigs.iter().enumerate() {
        let d = derive_with_prk(schedule, &prk, layout, j)?;
        let key = schedule
            .key(d.position.kind, d.position.epoch)
            .ok_or(BatchError::MissingKey)?;
        if !ghost_blind_rsa::check_blind_signature(&key.public_key, &d.blinded, sig) {
            return Err(BatchError::BlindSignature);
        }
        tokens.push(token::finalize_input(
            &key.public_key,
            &d.input,
            sig,
            &d.inv,
        )?);
    }
    Ok(tokens)
}

/// `D = SHA-256("ghost/v1/blindsign" || invoice_id || request)`: the issuer's idempotency digest.
pub fn request_digest(invoice_id: &[u8; 16], request: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(BLINDSIGN_DOMAIN);
    h.update(invoice_id);
    h.update(request);
    h.finalize().into()
}

/// `claim_hash = SHA-256("ghost/v1/issuer-claim" || claim_key)` (design §5.2): the client sends
/// the hash with `RequestInvoice` and the 32-byte key itself as the bearer proof of `BlindSign`.
pub fn claim_hash(claim_key: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(CLAIM_DOMAIN);
    h.update(claim_key);
    h.finalize().into()
}

/// `SHA-256("ghost/v1/trial" || invite_nullifier || base_week(8, BE) || request)`.
pub fn trial_digest(invite_nullifier: &[u8; 32], base_week: u64, request: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(TRIAL_DOMAIN);
    h.update(invite_nullifier);
    h.update(base_week.to_be_bytes());
    h.update(request);
    h.finalize().into()
}

struct OkmLen(usize);

impl hkdf::KeyType for OkmLen {
    fn len(&self) -> usize {
        self.0
    }
}

fn expand(prk: &hkdf::Prk, info: &[&[u8]], len: usize) -> Result<Vec<u8>, BatchError> {
    let mut out = vec![0u8; len];
    prk.expand(info, OkmLen(len))
        .and_then(|okm| okm.fill(&mut out))
        .map_err(|_| BatchError::Derivation)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claim_hash_is_the_domain_separated_sha256_of_the_key() {
        let key = [7u8; 32];
        let mut h = Sha256::new();
        h.update(b"ghost/v1/issuer-claim");
        h.update(key);
        let expected: [u8; 32] = h.finalize().into();
        assert_eq!(claim_hash(&key), expected);
        assert_ne!(claim_hash(&key), claim_hash(&[8u8; 32]));
        // Distinct from the other issuer digests over the same bytes.
        assert_ne!(claim_hash(&key), request_digest(&[7; 16], &[7; 16]));
    }
}
