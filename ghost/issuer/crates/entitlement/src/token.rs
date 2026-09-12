//! Privacy Pass token type 0x0002 (RFC 9578 §6), 354 bytes, and its nullifier (Phase 8 design
//! §2.1, §2.3). Only 2048-bit keys with e = 65537 are accepted here (Nk = 256).
//!
//! | offset | bytes | field |
//! |---|---|---|
//! | 0 | 2 | `token_type` = 0x0002 |
//! | 2 | 32 | `nonce` |
//! | 34 | 32 | `challenge_digest` |
//! | 66 | 32 | `token_key_id` = SHA-256(SPKI) |
//! | 98 | 256 | `authenticator`: RSASSA-PSS-SHA384 over bytes 0..98 |

use ghost_blind_rsa::{BigUint, PublicKey, SALT_LEN};
use sha2::{Digest, Sha256};

use crate::challenge::TOKEN_TYPE;
use crate::FormatError;

pub const TOKEN_LEN: usize = 354;
pub const TOKEN_INPUT_LEN: usize = 98;
pub const NONCE_LEN: usize = 32;
/// Nk of type 0x0002: the modulus, blinded message and signature length.
pub const AUTHENTICATOR_LEN: usize = 256;
/// Modulus size of type 0x0002 keys.
pub const MODULUS_BITS: usize = 2048;
/// The only public exponent of type 0x0002 keys in the Entitlement Schedule.
pub const PUBLIC_EXPONENT: u32 = 65_537;

const NULLIFIER_DOMAIN: &[u8] = b"ghost/v1/nullifier";

/// A parsed type-0x0002 token (length and type checked; the signature is not).
#[derive(Clone, PartialEq, Eq)]
pub struct Token {
    bytes: [u8; TOKEN_LEN],
}

impl std::fmt::Debug for Token {
    // Tokens are bearer value: never printed.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Token(..)")
    }
}

impl Token {
    pub fn parse(bytes: &[u8]) -> Result<Self, FormatError> {
        let bytes: [u8; TOKEN_LEN] = bytes.try_into().map_err(|_| FormatError::TokenLength)?;
        if bytes[..2] != TOKEN_TYPE.to_be_bytes() {
            return Err(FormatError::TokenType);
        }
        Ok(Self { bytes })
    }

    pub fn from_parts(
        input: &[u8; TOKEN_INPUT_LEN],
        authenticator: &[u8; AUTHENTICATOR_LEN],
    ) -> Self {
        let mut bytes = [0u8; TOKEN_LEN];
        bytes[..TOKEN_INPUT_LEN].copy_from_slice(input);
        bytes[TOKEN_INPUT_LEN..].copy_from_slice(authenticator);
        Self { bytes }
    }

    pub fn as_bytes(&self) -> &[u8; TOKEN_LEN] {
        &self.bytes
    }

    /// `token_input` = bytes 0..98, the signed message.
    pub fn token_input(&self) -> &[u8; TOKEN_INPUT_LEN] {
        self.bytes[..TOKEN_INPUT_LEN]
            .try_into()
            .unwrap_or(&[0; TOKEN_INPUT_LEN])
    }

    pub fn nonce(&self) -> &[u8] {
        &self.bytes[2..34]
    }

    pub fn challenge_digest(&self) -> &[u8] {
        &self.bytes[34..66]
    }

    pub fn key_id(&self) -> &[u8] {
        &self.bytes[66..98]
    }

    pub fn authenticator(&self) -> &[u8] {
        &self.bytes[TOKEN_INPUT_LEN..]
    }

    /// The nullifier of this token (computed by the verifier, never read from the wire).
    pub fn nullifier(&self) -> [u8; 32] {
        nullifier(self.token_input())
    }

    /// RSASSA-PSS verification of the authenticator by `ring` (key checks included).
    pub fn verify_signature(&self, pk: &PublicKey) -> Result<(), FormatError> {
        check_key(pk)?;
        ghost_blind_rsa::verify(pk, self.token_input(), self.authenticator())
            .map_err(|_| FormatError::Signature)
    }
}

/// `token_input = 0x0002 || nonce || challenge_digest || token_key_id`.
pub fn token_input(
    nonce: &[u8; NONCE_LEN],
    challenge_digest: &[u8; 32],
    key_id: &[u8; 32],
) -> [u8; TOKEN_INPUT_LEN] {
    let mut out = [0u8; TOKEN_INPUT_LEN];
    out[..2].copy_from_slice(&TOKEN_TYPE.to_be_bytes());
    out[2..34].copy_from_slice(nonce);
    out[34..66].copy_from_slice(challenge_digest);
    out[66..].copy_from_slice(key_id);
    out
}

/// `nullifier = SHA-256("ghost/v1/nullifier" || token_input)`.
pub fn nullifier(token_input: &[u8; TOKEN_INPUT_LEN]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(NULLIFIER_DOMAIN);
    h.update(token_input);
    h.finalize().into()
}

/// `token_key_id = SHA-256(SPKI DER)` (RFC 9578 §6.5).
pub fn key_id(spki: &[u8]) -> [u8; 32] {
    Sha256::digest(spki).into()
}

/// Type 0x0002 keys: exactly 2048 bits and e = 65537.
pub fn check_key(pk: &PublicKey) -> Result<(), FormatError> {
    if pk.modulus_bits() != MODULUS_BITS || pk.e() != &BigUint::from(PUBLIC_EXPONENT) {
        return Err(FormatError::KeySize);
    }
    Ok(())
}

/// Blinds one token input (RFC 9474 §4.2 with the Deterministic preparation: the message is the
/// token input itself): EMSA-PSS with `salt` for emBits = 2047, then `em * r^e mod n`. Returns
/// the 256-byte blinded message and `inv = r^-1 mod n`.
pub fn blind_input(
    pk: &PublicKey,
    input: &[u8; TOKEN_INPUT_LEN],
    salt: &[u8; SALT_LEN],
    r: &BigUint,
) -> Result<([u8; AUTHENTICATOR_LEN], BigUint), FormatError> {
    check_key(pk)?;
    let em = ghost_blind_rsa::emsa_pss_encode_sha384(input, salt, MODULUS_BITS - 1)
        .map_err(|_| FormatError::Blind)?;
    let (blinded, inv) = ghost_blind_rsa::blind_raw(pk, &em, r).map_err(|_| FormatError::Blind)?;
    let blinded: [u8; AUTHENTICATOR_LEN] = blinded.try_into().map_err(|_| FormatError::Blind)?;
    Ok((blinded, inv))
}

/// Finalizes one position (RFC 9474 §4.4): unblinds, verifies with `ring`, returns the token. A
/// blind signature that does not finalize into a valid signature is refused.
pub fn finalize_input(
    pk: &PublicKey,
    input: &[u8; TOKEN_INPUT_LEN],
    blind_sig: &[u8],
    inv: &BigUint,
) -> Result<Token, FormatError> {
    check_key(pk)?;
    let sig = ghost_blind_rsa::finalize_raw(pk, input, blind_sig, inv)
        .map_err(|_| FormatError::Signature)?;
    let sig: [u8; AUTHENTICATOR_LEN] = sig.try_into().map_err(|_| FormatError::Signature)?;
    Ok(Token::from_parts(input, &sig))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_checks_length_and_type() {
        let mut bytes = [0u8; TOKEN_LEN];
        bytes[1] = 2;
        assert!(Token::parse(&bytes).is_ok());
        assert_eq!(
            Token::parse(&bytes[..TOKEN_LEN - 1]).err(),
            Some(FormatError::TokenLength)
        );
        assert_eq!(
            Token::parse(&[bytes.as_slice(), &[0]].concat()).err(),
            Some(FormatError::TokenLength)
        );
        bytes[1] = 1;
        assert_eq!(Token::parse(&bytes).err(), Some(FormatError::TokenType));
    }

    #[test]
    fn fields_and_nullifier() {
        let input = token_input(&[1; 32], &[2; 32], &[3; 32]);
        let token = Token::from_parts(&input, &[4; AUTHENTICATOR_LEN]);
        assert_eq!(token.nonce(), &[1; 32]);
        assert_eq!(token.challenge_digest(), &[2; 32]);
        assert_eq!(token.key_id(), &[3; 32]);
        assert_eq!(token.authenticator(), &[4; AUTHENTICATOR_LEN]);
        assert_eq!(token.nullifier(), nullifier(&input));
        // The nullifier ignores the authenticator (design §2.3).
        let other = Token::from_parts(&input, &[5; AUTHENTICATOR_LEN]);
        assert_eq!(other.nullifier(), token.nullifier());
        assert_eq!(format!("{token:?}"), "Token(..)");
    }
}
