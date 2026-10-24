//! Signed statements and signature blocks, §4.2.

use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::FormatError;
use crate::Reader;

pub const KEY_ID_BYTES: usize = 32;
pub const SIGNATURE_BYTES: usize = 64;
pub const SIGBLOCK_MAX_ENTRIES: usize = 16;

/// The three statement types (§4.2). Sizes of the domain separator prefix are 55/59/60 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatementType {
    ReleaseRoot,
    ReleaseManifest,
    BuildAttestation,
}

impl StatementType {
    fn domain(self) -> &'static [u8] {
        match self {
            StatementType::ReleaseRoot => b"release-root",
            StatementType::ReleaseManifest => b"release-manifest",
            StatementType::BuildAttestation => b"build-attestation",
        }
    }
}

/// `statement(type, network, body) := "ghost/v1/" ‖ type ‖ 0x00 ‖ u8 network ‖ SHA-256(body)`.
pub fn statement_bytes(ty: StatementType, network: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(7 + 64 + 1 + 1 + 32);
    out.extend_from_slice(b"ghost/v1/");
    out.extend_from_slice(ty.domain());
    out.push(0x00);
    out.push(network);
    out.extend_from_slice(&Sha256::digest(body));
    out
}

/// A SHA-256 key id of a 32-byte Ed25519 public key (§4.1, the Sigsum key hash).
pub fn key_id(pk: &[u8; 32]) -> [u8; 32] {
    Sha256::digest(pk).into()
}

/// One signature-block entry: `key_id[32] ‖ signature[64]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SigEntry {
    pub key_id: [u8; 32],
    pub signature: [u8; 64],
}

/// `sigblock := u8 n (1..16) ‖ n × ( key_id[32] ‖ signature[64] )`, key ids strictly ascending.
/// `n = 0` is allowed where the grammar says `sigblock_or_empty` (the manifest's attestation block).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigBlock {
    pub entries: Vec<SigEntry>,
}

impl SigBlock {
    pub fn parse(r: &mut Reader<'_>, allow_empty: bool) -> Result<Self, FormatError> {
        let n = r.u8()? as usize;
        if n > SIGBLOCK_MAX_ENTRIES || (!allow_empty && n == 0) {
            return Err(FormatError::Count);
        }
        let mut entries = Vec::with_capacity(n);
        for _ in 0..n {
            let key_id: [u8; 32] = r.take(32)?.try_into().expect("32 bytes");
            let signature: [u8; 64] = r.take(64)?.try_into().expect("64 bytes");
            entries.push(SigEntry { key_id, signature });
        }
        // Ascending by key id (a block cannot hold two entries for one key).
        for w in entries.windows(2) {
            match w[0].key_id.cmp(&w[1].key_id) {
                std::cmp::Ordering::Less => {}
                std::cmp::Ordering::Equal => return Err(FormatError::Duplicate),
                std::cmp::Ordering::Greater => return Err(FormatError::Ordering),
            }
        }
        Ok(SigBlock { entries })
    }

    pub fn write(&self, out: &mut Vec<u8>) {
        out.push(self.entries.len() as u8);
        for e in &self.entries {
            out.extend_from_slice(&e.key_id);
            out.extend_from_slice(&e.signature);
        }
    }

    pub fn meets(&self, keys: &[[u8; 32]], t: usize, msg: &[u8]) -> Result<(), FormatError> {
        if sigblock_meets(self, keys, t, msg) {
            Ok(())
        } else {
            Err(FormatError::Threshold)
        }
    }
}

/// §4.2's rule: at least `t` entries name a key id in `keys` and verify with `verify_strict`;
/// entries naming other keys or failing verification are ignored, never an error.
pub fn sigblock_meets(block: &SigBlock, keys: &[[u8; 32]], t: usize, msg: &[u8]) -> bool {
    let mut good = 0usize;
    'entries: for e in &block.entries {
        for k in keys {
            if e.key_id == key_id(k) {
                let sig = Signature::from_slice(&e.signature);
                let key = VerifyingKey::from_bytes(k);
                match (sig, key) {
                    (Ok(sig), Ok(key)) => {
                        if key.verify_strict(msg, &sig).is_ok() {
                            good += 1;
                            if good >= t {
                                return true;
                            }
                        }
                    }
                    _ => {}
                }
                continue 'entries;
            }
        }
    }
    good >= t
}

/// Sign `statement(type, network, body)` with one key and return the signature-block entry.
/// Used by the round-trip tests and, in S2, by `ghost-release-ops` (the real signer, RK1, talks
/// to the hardware tokens; this helper covers software keys in tests and stagenet tooling).
pub fn sign_entry(
    sk: &ed25519_dalek::SigningKey,
    ty: StatementType,
    network: u8,
    body: &[u8],
) -> SigEntry {
    use ed25519_dalek::Signer;
    let msg = statement_bytes(ty, network, body);
    SigEntry {
        key_id: key_id(&sk.verifying_key().to_bytes()),
        signature: sk.sign(&msg).to_bytes(),
    }
}

