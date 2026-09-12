//! Custody of the issuer's private signing keys (Phase 8 design §3.3, §19.1; ADR-26 point 4): one
//! sealed file per (kind, epoch), ChaCha20-Poly1305 from `ring` under
//!
//! ```text
//! k_seal(kind, epoch) = HKDF-SHA256(ikm = custody_secret, salt = none,
//!                                   info = "ghost/v1/key-seal" || kind u8 || epoch u64)
//! ```
//!
//! The 32-byte custody secret exists only on removable media at the offline machine (runbook K1).
//! The issuer host keeps the sealed files of the whole horizon on its encrypted disk and receives,
//! at every key load (K3), a load file holding the `k_seal` values of the epochs it must hold; it
//! never receives the custody secret.
//!
//! ```text
//! sealed key file := "GHKS" || version u8 = 1 || kind u8 || epoch u64 || nonce (12)
//!                    || ChaCha20-Poly1305(k_seal, nonce, aad = the 14 header bytes, PKCS #8 DER)
//! load file       := "GHKL" || version u8 = 1 || count u16 (1..)
//!                    || count x (kind u8 || epoch u64 || k_seal (32)), (kind, epoch) ascending
//! ```
//! Big-endian fixed fields. The header is the AEAD's associated data, so a sealed file cannot be
//! presented under another (kind, epoch); the nonce is drawn from the operating system for every
//! file, so re-sealing a (kind, epoch) never reuses a nonce under its `k_seal`.

use std::collections::BTreeMap;

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305, NONCE_LEN};
use ring::hkdf;
use ring::rand::SecureRandom;

use crate::signer::{ReferenceSigner, SignError};
use ghost_entitlement::Kind;

/// Domain label of the seal-key derivation.
pub const SEAL_KEY_LABEL: &[u8] = b"ghost/v1/key-seal";
/// Length of the custody secret and of every `k_seal`.
pub const SECRET_LEN: usize = 32;
const SEALED_MAGIC: &[u8; 4] = b"GHKS";
const LOAD_MAGIC: &[u8; 4] = b"GHKL";
const FORMAT_VERSION: u8 = 1;
/// magic (4) || version (1) || kind (1) || epoch (8).
const SEALED_HEADER_LEN: usize = 14;
const TAG_LEN: usize = 16;
const LOAD_ENTRY_LEN: usize = 1 + 8 + SECRET_LEN;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CustodyError {
    /// Not a sealed key file or load file of this version (magic, version, lengths, order).
    Format,
    /// The file names another (kind, epoch) than the one asked for.
    WrongKey,
    /// Authentication failed: another `k_seal`, or the file was altered.
    Open,
    /// The operating system's random source failed.
    Random,
    /// The plaintext is not a valid RSA-2048 key with e = 65537.
    Key(SignError),
}

impl std::fmt::Display for CustodyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CustodyError::Format => f.write_str("not a sealed key or load file of version 1"),
            CustodyError::WrongKey => f.write_str("sealed file of another (kind, epoch)"),
            CustodyError::Open => f.write_str("sealed file does not open under this seal key"),
            CustodyError::Random => f.write_str("random source failed"),
            CustodyError::Key(e) => write!(f, "sealed key invalid: {e}"),
        }
    }
}

impl std::error::Error for CustodyError {}

/// The 32-byte custody secret of the offline machine. `Debug` never shows it.
pub struct CustodySecret([u8; SECRET_LEN]);

impl CustodySecret {
    pub fn from_bytes(bytes: [u8; SECRET_LEN]) -> Self {
        Self(bytes)
    }

    /// A fresh secret from the operating system's random source.
    pub fn generate(rng: &dyn SecureRandom) -> Result<Self, CustodyError> {
        let mut bytes = [0u8; SECRET_LEN];
        rng.fill(&mut bytes).map_err(|_| CustodyError::Random)?;
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; SECRET_LEN] {
        &self.0
    }

    /// `k_seal(kind, epoch)`.
    pub fn seal_key(&self, kind: Kind, epoch: u64) -> SealKey {
        let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, &[]).extract(&self.0);
        let (kind_byte, epoch_bytes) = ([kind.byte()], epoch.to_be_bytes());
        let info: [&[u8]; 3] = [SEAL_KEY_LABEL, &kind_byte, &epoch_bytes];
        let mut out = [0u8; SECRET_LEN];
        // Expanding 32 bytes from HKDF-SHA256 is always within the RFC 5869 limit (255 * 32).
        prk.expand(&info, SealKeyLen)
            .and_then(|okm| okm.fill(&mut out))
            .unwrap_or_else(|_| unreachable!("HKDF-SHA256 expands 32 bytes"));
        SealKey(out)
    }
}

impl Drop for CustodySecret {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

impl std::fmt::Debug for CustodySecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CustodySecret(redacted)")
    }
}

struct SealKeyLen;

impl hkdf::KeyType for SealKeyLen {
    fn len(&self) -> usize {
        SECRET_LEN
    }
}

/// `k_seal` of one (kind, epoch): opens that epoch's sealed key file only. `Debug` never shows it.
#[derive(Clone, PartialEq, Eq)]
pub struct SealKey([u8; SECRET_LEN]);

impl SealKey {
    pub fn from_bytes(bytes: [u8; SECRET_LEN]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; SECRET_LEN] {
        &self.0
    }

    fn aead(&self) -> LessSafeKey {
        LessSafeKey::new(
            UnboundKey::new(&CHACHA20_POLY1305, &self.0)
                .unwrap_or_else(|_| unreachable!("ChaCha20-Poly1305 takes a 32-byte key")),
        )
    }
}

impl Drop for SealKey {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

impl std::fmt::Debug for SealKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SealKey(redacted)")
    }
}

/// The file name of the sealed key of (kind, epoch), e.g. `access-2957.ghks`.
pub fn sealed_file_name(kind: Kind, epoch: u64) -> String {
    format!("{}-{epoch}.ghks", kind_name(kind))
}

/// The lowercase name of a kind as the operator tools and file names spell it.
pub fn kind_name(kind: Kind) -> &'static str {
    match kind {
        Kind::Access => "access",
        Kind::Invite => "invite",
        Kind::Credit => "credit",
    }
}

fn sealed_header(kind: Kind, epoch: u64) -> [u8; SEALED_HEADER_LEN] {
    let mut h = [0u8; SEALED_HEADER_LEN];
    h[..4].copy_from_slice(SEALED_MAGIC);
    h[4] = FORMAT_VERSION;
    h[5] = kind.byte();
    h[6..].copy_from_slice(&epoch.to_be_bytes());
    h
}

/// Seals the PKCS #8 DER of the private key of (kind, epoch) under its `k_seal`.
pub fn seal(
    key: &SealKey,
    kind: Kind,
    epoch: u64,
    pkcs8_der: &[u8],
    rng: &dyn SecureRandom,
) -> Result<Vec<u8>, CustodyError> {
    let header = sealed_header(kind, epoch);
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill(&mut nonce).map_err(|_| CustodyError::Random)?;
    let mut body = pkcs8_der.to_vec();
    key.aead()
        .seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(header),
            &mut body,
        )
        .map_err(|_| CustodyError::Format)?;
    let mut out = Vec::with_capacity(SEALED_HEADER_LEN + NONCE_LEN + body.len());
    out.extend_from_slice(&header);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&body);
    body.fill(0);
    Ok(out)
}

/// Opens the sealed key file of (kind, epoch) into a signer. The caller still proves the key
/// matches its ES entry (`CheckedSigner::new`).
pub fn unseal(
    key: &SealKey,
    kind: Kind,
    epoch: u64,
    sealed: &[u8],
) -> Result<ReferenceSigner, CustodyError> {
    if sealed.len() < SEALED_HEADER_LEN + NONCE_LEN + TAG_LEN
        || &sealed[..4] != SEALED_MAGIC
        || sealed[4] != FORMAT_VERSION
    {
        return Err(CustodyError::Format);
    }
    let (header, rest) = sealed.split_at(SEALED_HEADER_LEN);
    if header != sealed_header(kind, epoch) {
        return Err(CustodyError::WrongKey);
    }
    let (nonce, ciphertext) = rest.split_at(NONCE_LEN);
    let nonce: [u8; NONCE_LEN] = nonce.try_into().map_err(|_| CustodyError::Format)?;
    let mut body = ciphertext.to_vec();
    let result = match key.aead().open_in_place(
        Nonce::assume_unique_for_key(nonce),
        Aad::from(header),
        &mut body,
    ) {
        Ok(der) => ReferenceSigner::from_pkcs8_der(kind, epoch, der).map_err(CustodyError::Key),
        Err(_) => Err(CustodyError::Open),
    };
    body.fill(0);
    result
}

/// The `k_seal` values handed to the issuer at one key load (runbook K3).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SealLoad {
    entries: BTreeMap<(Kind, u64), SealKey>,
}

impl SealLoad {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds the `k_seal` of (kind, epoch); a (kind, epoch) is listed once.
    pub fn insert(&mut self, kind: Kind, epoch: u64, key: SealKey) -> Result<(), CustodyError> {
        match self.entries.insert((kind, epoch), key) {
            None => Ok(()),
            Some(_) => Err(CustodyError::Format),
        }
    }

    pub fn get(&self, kind: Kind, epoch: u64) -> Option<&SealKey> {
        self.entries.get(&(kind, epoch))
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The (kind, epoch) pairs listed, ascending.
    pub fn keys(&self) -> impl Iterator<Item = (Kind, u64)> + '_ {
        self.entries.keys().copied()
    }

    pub fn encode(&self) -> Result<Vec<u8>, CustodyError> {
        let count = u16::try_from(self.entries.len()).map_err(|_| CustodyError::Format)?;
        if count == 0 {
            return Err(CustodyError::Format);
        }
        let mut out = Vec::with_capacity(7 + self.entries.len() * LOAD_ENTRY_LEN);
        out.extend_from_slice(LOAD_MAGIC);
        out.push(FORMAT_VERSION);
        out.extend_from_slice(&count.to_be_bytes());
        for ((kind, epoch), key) in &self.entries {
            out.push(kind.byte());
            out.extend_from_slice(&epoch.to_be_bytes());
            out.extend_from_slice(&key.0);
        }
        Ok(out)
    }

    /// Parses a load file: exact length, known kinds, entries strictly ascending (so each
    /// (kind, epoch) appears once and the encoding is canonical).
    pub fn parse(bytes: &[u8]) -> Result<Self, CustodyError> {
        if bytes.len() < 7 || &bytes[..4] != LOAD_MAGIC || bytes[4] != FORMAT_VERSION {
            return Err(CustodyError::Format);
        }
        let count = usize::from(u16::from_be_bytes([bytes[5], bytes[6]]));
        let body = &bytes[7..];
        if count == 0 || body.len() != count * LOAD_ENTRY_LEN {
            return Err(CustodyError::Format);
        }
        let mut load = Self::new();
        let mut previous = None;
        for entry in body.as_chunks::<LOAD_ENTRY_LEN>().0 {
            let kind = Kind::from_byte(entry[0]).ok_or(CustodyError::Format)?;
            let epoch =
                u64::from_be_bytes(entry[1..9].try_into().map_err(|_| CustodyError::Format)?);
            if previous.is_some_and(|p| p >= (kind, epoch)) {
                return Err(CustodyError::Format);
            }
            previous = Some((kind, epoch));
            let key: [u8; SECRET_LEN] = entry[9..].try_into().map_err(|_| CustodyError::Format)?;
            load.insert(kind, epoch, SealKey(key))?;
        }
        Ok(load)
    }
}
