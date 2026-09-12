//! TokenChallenge (RFC 9577 §2.1), built by the client inside the blinded message and recomputed by
//! every verifier (Phase 8 design §2.2). For ACCESS tokens `origin_info` names a relay slot of the
//! Entitlement Schedule, so a token is valid at exactly one relay.

use sha2::{Digest, Sha256};

use crate::grid::{epoch_id, Kind};
use crate::FormatError;

/// Privacy Pass token type 0x0002: Blind RSA (2048-bit), RFC 9578 §6.
pub const TOKEN_TYPE: u16 = 0x0002;
/// `origin_info` of INVITE tokens (verified by the issuer's `RedeemInvite`).
pub const ORIGIN_INVITE: &str = "issuer-invite";
/// `origin_info` of CREDIT tokens (verified by the issuer).
pub const ORIGIN_CREDIT: &str = "issuer-credit";
/// Largest relay slot number (the ES slot table allows slots 0..31).
pub const MAX_SLOT: u8 = 31;

const REDEMPTION_CONTEXT_DOMAIN: &[u8] = b"ghost/v1/redemption-context";

/// A decoded TokenChallenge. `redemption_context` is empty or exactly 32 bytes (RFC 9577 §2.1.1.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenChallenge {
    pub token_type: u16,
    pub issuer_name: Vec<u8>,
    pub redemption_context: Vec<u8>,
    pub origin_info: Vec<u8>,
}

impl TokenChallenge {
    /// The TLS presentation encoding: `u16 token_type || issuer_name<1..2^16-1> ||
    /// redemption_context<0..32> || origin_info<0..2^16-1>`.
    pub fn encode(&self) -> Result<Vec<u8>, FormatError> {
        if self.issuer_name.is_empty()
            || self.issuer_name.len() > usize::from(u16::MAX)
            || !matches!(self.redemption_context.len(), 0 | 32)
            || self.origin_info.len() > usize::from(u16::MAX)
        {
            return Err(FormatError::Challenge);
        }
        let mut out = Vec::with_capacity(7 + self.issuer_name.len() + 32 + self.origin_info.len());
        out.extend_from_slice(&self.token_type.to_be_bytes());
        out.extend_from_slice(&(self.issuer_name.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.issuer_name);
        out.push(self.redemption_context.len() as u8);
        out.extend_from_slice(&self.redemption_context);
        out.extend_from_slice(&(self.origin_info.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.origin_info);
        Ok(out)
    }

    /// Strict decoding: exact lengths, no trailing bytes.
    pub fn parse(bytes: &[u8]) -> Result<Self, FormatError> {
        let mut r = Reader(bytes);
        let token_type =
            u16::from_be_bytes(r.take(2)?.try_into().map_err(|_| FormatError::Challenge)?);
        let name_len = usize::from(u16::from_be_bytes(
            r.take(2)?.try_into().map_err(|_| FormatError::Challenge)?,
        ));
        let issuer_name = r.take(name_len)?.to_vec();
        let rc_len = usize::from(r.take(1)?[0]);
        let redemption_context = r.take(rc_len)?.to_vec();
        let origin_len = usize::from(u16::from_be_bytes(
            r.take(2)?.try_into().map_err(|_| FormatError::Challenge)?,
        ));
        let origin_info = r.take(origin_len)?.to_vec();
        if !r.0.is_empty() {
            return Err(FormatError::Challenge);
        }
        let challenge = Self {
            token_type,
            issuer_name,
            redemption_context,
            origin_info,
        };
        // encode() re-applies the length rules (issuer_name non-empty, context 0 or 32 bytes).
        challenge.encode()?;
        Ok(challenge)
    }

    /// `challenge_digest = SHA-256(TokenChallenge)`.
    pub fn digest(&self) -> Result<[u8; 32], FormatError> {
        Ok(Sha256::digest(self.encode()?).into())
    }

    /// The GHOST challenge of a (kind, epoch, slot) under the ES issuer name. `slot` is required
    /// for ACCESS (0..=31) and must be absent for INVITE and CREDIT.
    pub fn ghost(
        issuer_name: &str,
        kind: Kind,
        epoch: u64,
        slot: Option<u8>,
    ) -> Result<Self, FormatError> {
        Ok(Self {
            token_type: TOKEN_TYPE,
            issuer_name: issuer_name.as_bytes().to_vec(),
            redemption_context: redemption_context(kind, epoch).to_vec(),
            origin_info: origin_info(kind, slot)?.into_bytes(),
        })
    }
}

/// `SHA-256("ghost/v1/redemption-context" || kind_byte || epoch_id(8, BE))`: binds kind and epoch
/// of an honest client's token (it does not replace distinct keys per (kind, epoch), §19.2).
pub fn redemption_context(kind: Kind, epoch: u64) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(REDEMPTION_CONTEXT_DOMAIN);
    h.update([kind.byte()]);
    h.update(epoch_id(epoch));
    h.finalize().into()
}

/// `origin_info` per kind: `"relay-slot-NN"` (two decimal digits) for ACCESS, `"issuer-invite"`,
/// `"issuer-credit"`.
pub fn origin_info(kind: Kind, slot: Option<u8>) -> Result<String, FormatError> {
    match (kind, slot) {
        (Kind::Access, Some(s)) if s <= MAX_SLOT => Ok(format!("relay-slot-{s:02}")),
        (Kind::Invite, None) => Ok(ORIGIN_INVITE.to_string()),
        (Kind::Credit, None) => Ok(ORIGIN_CREDIT.to_string()),
        _ => Err(FormatError::Slot),
    }
}

/// `challenge_digest` of the GHOST challenge of (kind, epoch, slot).
pub fn challenge_digest(
    issuer_name: &str,
    kind: Kind,
    epoch: u64,
    slot: Option<u8>,
) -> Result<[u8; 32], FormatError> {
    TokenChallenge::ghost(issuer_name, kind, epoch, slot)?.digest()
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], FormatError> {
        if self.0.len() < n {
            return Err(FormatError::Challenge);
        }
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        Ok(head)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origins_per_kind() {
        assert_eq!(origin_info(Kind::Access, Some(3)).unwrap(), "relay-slot-03");
        assert_eq!(
            origin_info(Kind::Access, Some(31)).unwrap(),
            "relay-slot-31"
        );
        assert_eq!(origin_info(Kind::Access, Some(32)), Err(FormatError::Slot));
        assert_eq!(origin_info(Kind::Access, None), Err(FormatError::Slot));
        assert_eq!(origin_info(Kind::Invite, None).unwrap(), "issuer-invite");
        assert_eq!(origin_info(Kind::Invite, Some(1)), Err(FormatError::Slot));
        assert_eq!(origin_info(Kind::Credit, None).unwrap(), "issuer-credit");
    }

    #[test]
    fn encoding_round_trips_and_is_strict() {
        let c = TokenChallenge::ghost("ghost-issuer-v1", Kind::Access, 2957, Some(0)).unwrap();
        let bytes = c.encode().unwrap();
        assert_eq!(&bytes[..2], &[0x00, 0x02]);
        assert_eq!(TokenChallenge::parse(&bytes).unwrap(), c);
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert_eq!(
            TokenChallenge::parse(&trailing),
            Err(FormatError::Challenge)
        );
        assert_eq!(
            TokenChallenge::parse(&bytes[..bytes.len() - 1]),
            Err(FormatError::Challenge)
        );
        // A 31-byte redemption context is neither empty nor 32 bytes.
        let bad = TokenChallenge {
            redemption_context: vec![0; 31],
            ..c.clone()
        };
        assert_eq!(bad.encode(), Err(FormatError::Challenge));
        let unnamed = TokenChallenge {
            issuer_name: Vec::new(),
            ..c
        };
        assert_eq!(unnamed.encode(), Err(FormatError::Challenge));
    }

    #[test]
    fn distinct_contexts_give_distinct_digests() {
        let a = challenge_digest("ghost-issuer-v1", Kind::Access, 2957, Some(0)).unwrap();
        let b = challenge_digest("ghost-issuer-v1", Kind::Access, 2957, Some(1)).unwrap();
        let c = challenge_digest("ghost-issuer-v1", Kind::Access, 2958, Some(0)).unwrap();
        let d = challenge_digest("ghost-issuer-v2", Kind::Access, 2957, Some(0)).unwrap();
        assert!(a != b && a != c && a != d && b != c);
        assert_ne!(
            redemption_context(Kind::Invite, 739),
            redemption_context(Kind::Credit, 739)
        );
    }
}
