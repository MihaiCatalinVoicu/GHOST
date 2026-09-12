//! Monero address validation and the payment URI (Phase 8 design §7.7, §7.8). One implementation
//! for the issuer, the operator tools and the client (through JNI): the client refuses an invoice
//! whose subaddress fails here and builds the `monero:` URI itself from validated values.
//!
//! Rules, in order: (1) exactly 95 characters of the Monero Base58 alphabet (integrated addresses,
//! 106 characters, are refused); (2) block-wise decoding to 69 bytes with non-canonical blocks
//! refused; (3) the network byte: a subaddress for invoices (mainnet and regtest 42, stagenet 36),
//! a standard address or subaddress for payouts (mainnet 18/42, stagenet 24/36); (4)
//! `Keccak-256(bytes[0..65])[0..4] == bytes[65..69]` (original Keccak padding, not SHA3-256);
//! (5) both 32-byte keys are canonical encodings of Ed25519 points (Monero's `check_key`).

use curve25519_dalek::edwards::CompressedEdwardsY;
use sha3::{Digest, Keccak256};

/// Length of a standard address or subaddress.
pub const ADDRESS_LEN: usize = 95;
/// Length of an integrated address (always refused).
pub const INTEGRATED_ADDRESS_LEN: usize = 106;
/// Decoded length: network byte, spend key, view key, checksum.
pub const DECODED_LEN: usize = 69;
/// Atomic units per XMR (the URI amount has 12 decimal places).
pub const ATOMIC_PER_XMR: u64 = 1_000_000_000_000;

const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const FULL_BLOCK_LEN: usize = 8;
const FULL_ENCODED_BLOCK_LEN: usize = 11;
/// Encoded characters per decoded block length 0..=8 (`encoded_block_sizes`, monero
/// src/common/base58.cpp).
const ENCODED_BLOCK_SIZES: [usize; 9] = [0, 2, 3, 5, 6, 7, 9, 10, 11];

const PREFIX_MAINNET_STANDARD: u8 = 18;
const PREFIX_MAINNET_INTEGRATED: u8 = 19;
const PREFIX_MAINNET_SUBADDRESS: u8 = 42;
const PREFIX_TESTNET_STANDARD: u8 = 53;
const PREFIX_TESTNET_INTEGRATED: u8 = 54;
const PREFIX_TESTNET_SUBADDRESS: u8 = 63;
const PREFIX_STAGENET_STANDARD: u8 = 24;
const PREFIX_STAGENET_INTEGRATED: u8 = 25;
const PREFIX_STAGENET_SUBADDRESS: u8 = 36;

/// The Monero network of an Entitlement Schedule (`network` byte 1, 2, 3). Regtest (FAKECHAIN)
/// uses the mainnet prefixes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MoneroNetwork {
    Mainnet,
    Stagenet,
    Regtest,
}

impl MoneroNetwork {
    pub fn from_schedule_byte(b: u8) -> Option<Self> {
        match b {
            1 => Some(Self::Mainnet),
            2 => Some(Self::Stagenet),
            3 => Some(Self::Regtest),
            _ => None,
        }
    }

    /// The `network` byte of the Entitlement Schedule (inverse of [`Self::from_schedule_byte`]).
    pub fn schedule_byte(self) -> u8 {
        match self {
            Self::Mainnet => 1,
            Self::Stagenet => 2,
            Self::Regtest => 3,
        }
    }

    fn standard_prefix(self) -> u8 {
        match self {
            Self::Mainnet | Self::Regtest => PREFIX_MAINNET_STANDARD,
            Self::Stagenet => PREFIX_STAGENET_STANDARD,
        }
    }

    fn subaddress_prefix(self) -> u8 {
        match self {
            Self::Mainnet | Self::Regtest => PREFIX_MAINNET_SUBADDRESS,
            Self::Stagenet => PREFIX_STAGENET_SUBADDRESS,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AddressType {
    Standard,
    Subaddress,
}

/// What an address is for: an invoice takes a subaddress only; a payout a standard address or a
/// subaddress.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AddressPurpose {
    Invoice,
    Payout,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AddressError {
    /// Not 95 characters.
    Length,
    /// 106 characters: an integrated address (it carries a payment id).
    Integrated,
    /// A character outside the Monero Base58 alphabet.
    Alphabet,
    /// A block does not decode canonically (value overflows the block).
    Encoding,
    /// A known Monero prefix of another network (or of testnet, which GHOST never uses).
    WrongNetwork,
    /// The right network but a type the purpose does not take (a standard address for an invoice).
    WrongType,
    /// Not a known standard, integrated or subaddress prefix.
    Prefix,
    /// Keccak-256 checksum mismatch.
    Checksum,
    /// A public key is not the canonical encoding of an Ed25519 point.
    InvalidKey,
    /// A payment URI needs a subaddress and a non-zero amount.
    UriInput,
}

impl std::fmt::Display for AddressError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Length => "monero address must be 95 characters",
            Self::Integrated => "integrated monero addresses are refused",
            Self::Alphabet => "character outside the monero base58 alphabet",
            Self::Encoding => "non-canonical monero base58 block",
            Self::WrongNetwork => "monero address of another network",
            Self::WrongType => "monero address type not accepted for this purpose",
            Self::Prefix => "unknown monero address prefix",
            Self::Checksum => "monero address checksum mismatch",
            Self::InvalidKey => "monero address key is not an ed25519 point",
            Self::UriInput => "payment uri needs a subaddress and a non-zero amount",
        })
    }
}

impl std::error::Error for AddressError {}

/// A validated standard address or subaddress.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MoneroAddress {
    text: String,
    network: MoneroNetwork,
    kind: AddressType,
    spend_key: [u8; 32],
    view_key: [u8; 32],
}

impl MoneroAddress {
    /// Validates `text` for `network` and `purpose` (rules 1-5 of the module documentation).
    pub fn parse(
        text: &str,
        network: MoneroNetwork,
        purpose: AddressPurpose,
    ) -> Result<Self, AddressError> {
        let bytes = decode_address(text)?;
        let kind = match bytes[0] {
            p if p == network.subaddress_prefix() => AddressType::Subaddress,
            p if p == network.standard_prefix() => match purpose {
                AddressPurpose::Payout => AddressType::Standard,
                AddressPurpose::Invoice => return Err(AddressError::WrongType),
            },
            // An integrated prefix in a 95-character body: never a payment id, whatever the network.
            PREFIX_MAINNET_INTEGRATED | PREFIX_STAGENET_INTEGRATED | PREFIX_TESTNET_INTEGRATED => {
                return Err(AddressError::Integrated)
            }
            PREFIX_MAINNET_STANDARD
            | PREFIX_MAINNET_SUBADDRESS
            | PREFIX_STAGENET_STANDARD
            | PREFIX_STAGENET_SUBADDRESS
            | PREFIX_TESTNET_STANDARD
            | PREFIX_TESTNET_SUBADDRESS => return Err(AddressError::WrongNetwork),
            _ => return Err(AddressError::Prefix),
        };
        let check = Keccak256::digest(&bytes[..65]);
        if check[..4] != bytes[65..69] {
            return Err(AddressError::Checksum);
        }
        let spend_key: [u8; 32] = bytes[1..33].try_into().map_err(|_| AddressError::Length)?;
        let view_key: [u8; 32] = bytes[33..65].try_into().map_err(|_| AddressError::Length)?;
        for key in [&spend_key, &view_key] {
            if !is_canonical_point(key) {
                return Err(AddressError::InvalidKey);
            }
        }
        Ok(Self {
            text: text.to_string(),
            network,
            kind,
            spend_key,
            view_key,
        })
    }

    pub fn as_str(&self) -> &str {
        &self.text
    }

    pub fn network(&self) -> MoneroNetwork {
        self.network
    }

    pub fn kind(&self) -> AddressType {
        self.kind
    }

    pub fn spend_key(&self) -> &[u8; 32] {
        &self.spend_key
    }

    pub fn view_key(&self) -> &[u8; 32] {
        &self.view_key
    }
}

/// `monero:<subaddress>?tx_amount=<amount with 12 decimal places>`, nothing else (no
/// `tx_description`, `recipient_name` or `tx_payment_id`, design §7.7).
pub fn payment_uri(subaddress: &MoneroAddress, amount_atomic: u64) -> Result<String, AddressError> {
    if subaddress.kind != AddressType::Subaddress || amount_atomic == 0 {
        return Err(AddressError::UriInput);
    }
    Ok(format!(
        "monero:{}?tx_amount={}.{:012}",
        subaddress.text,
        amount_atomic / ATOMIC_PER_XMR,
        amount_atomic % ATOMIC_PER_XMR
    ))
}

/// Rule 5, with Monero's `check_key` semantics (`ge_frombytes_vartime == 0`): the key decompresses
/// and is the canonical encoding of its point. `curve25519-dalek` alone also accepts y >= p and
/// x = 0 with the sign bit set, which wallet-rpc refuses; re-compressing yields the reduced y and a
/// zero sign bit for x = 0, so comparing with the input refuses both.
fn is_canonical_point(key: &[u8; 32]) -> bool {
    CompressedEdwardsY(*key)
        .decompress()
        .is_some_and(|point| point.compress().to_bytes() == *key)
}

/// Rules 1 and 2: length, alphabet and canonical block decoding to 69 bytes.
fn decode_address(text: &str) -> Result<[u8; DECODED_LEN], AddressError> {
    match text.len() {
        ADDRESS_LEN => {}
        INTEGRATED_ADDRESS_LEN => return Err(AddressError::Integrated),
        _ => return Err(AddressError::Length),
    }
    if !text.bytes().all(|b| ALPHABET.contains(&b)) {
        return Err(AddressError::Alphabet);
    }
    let decoded = base58_decode(text).ok_or(AddressError::Encoding)?;
    decoded.try_into().map_err(|_| AddressError::Encoding)
}

/// Monero Base58 (8-byte blocks into 11 characters, a final partial block per
/// `ENCODED_BLOCK_SIZES`).
pub fn base58_encode(data: &[u8]) -> String {
    let mut out = String::new();
    for block in data.chunks(FULL_BLOCK_LEN) {
        let mut num = block.iter().fold(0u64, |acc, &b| (acc << 8) | u64::from(b));
        let mut chars = vec![ALPHABET[0]; ENCODED_BLOCK_SIZES[block.len()]];
        for c in chars.iter_mut().rev() {
            *c = ALPHABET[(num % 58) as usize];
            num /= 58;
        }
        out.extend(chars.into_iter().map(char::from));
    }
    out
}

/// Inverse of [`base58_encode`]; None for a length no block size produces, a character outside the
/// alphabet, or a block whose value does not fit its byte length (non-canonical).
pub fn base58_decode(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    let mut out =
        Vec::with_capacity(bytes.len() * FULL_BLOCK_LEN / FULL_ENCODED_BLOCK_LEN + FULL_BLOCK_LEN);
    for block in bytes.chunks(FULL_ENCODED_BLOCK_LEN) {
        let len = ENCODED_BLOCK_SIZES.iter().position(|&s| s == block.len())?;
        if len == 0 {
            return None;
        }
        let mut num: u128 = 0;
        for &c in block {
            let digit = ALPHABET.iter().position(|&a| a == c)? as u128;
            num = num * 58 + digit;
        }
        if num >= 1u128 << (8 * len) {
            return None;
        }
        out.extend_from_slice(&(num as u64).to_be_bytes()[FULL_BLOCK_LEN - len..]);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // monero-docs, public-address/standard-address.md: the example address and its decoding.
    const DOC_ADDRESS: &str =
        "4AdUndXHHZ6cfufTMvppY6JwXNouMBzSkbLYfpAV5Usx3skxNgYeYTRj5UzqtReoS44qo9mtmXCqY45DJ852K5Jv2684Rge";
    const DOC_HEX: &str = "12eda9fe8dfcdd25d5430ea64229d04f6b41b2e5a1587c29cd499a63eb79d117113076a02b73d130fb904c9e91075fcd16f735c6850dfadb125eb826d96a113f09a57120a3";

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn base58_matches_the_documented_decoding() {
        assert_eq!(base58_decode(DOC_ADDRESS).unwrap(), unhex(DOC_HEX));
        assert_eq!(base58_encode(&unhex(DOC_HEX)), DOC_ADDRESS);
    }

    #[test]
    fn overflowing_blocks_are_not_canonical() {
        // "zzzzzzz" is 58^7 - 1 > 2^40 - 1: it cannot encode 5 bytes.
        let text = format!("{}zzzzzzz", &DOC_ADDRESS[..88]);
        assert_eq!(base58_decode(&text), None);
        // Eleven 'z' exceed 2^64 - 1.
        assert_eq!(base58_decode("zzzzzzzzzzz"), None);
        assert_eq!(base58_decode("1"), None);
    }

    #[test]
    fn uri_has_twelve_decimals_and_nothing_else() {
        // monero-docs subaddress example key material is not needed: any valid subaddress works.
        let sub = MoneroAddress {
            text: "8".repeat(95),
            network: MoneroNetwork::Mainnet,
            kind: AddressType::Subaddress,
            spend_key: [0; 32],
            view_key: [0; 32],
        };
        let uri = payment_uri(&sub, 200_000_000_000).unwrap();
        assert_eq!(
            uri,
            format!("monero:{}?tx_amount=0.200000000000", "8".repeat(95))
        );
        assert!(payment_uri(&sub, 1)
            .unwrap()
            .ends_with("tx_amount=0.000000000001"));
        assert!(payment_uri(&sub, 12_345_000_000_000_001)
            .unwrap()
            .ends_with("tx_amount=12345.000000000001"));
        assert_eq!(payment_uri(&sub, 0), Err(AddressError::UriInput));
        let std_addr = MoneroAddress {
            kind: AddressType::Standard,
            ..sub
        };
        assert_eq!(payment_uri(&std_addr, 5), Err(AddressError::UriInput));
    }
}
