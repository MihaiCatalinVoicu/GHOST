//! GHOST release distribution formats, Phase 14 design §4 (normative; ADR-49).
//!
//! Pure encode/parse/verify: no I/O, no clock, no randomness. Every parser is total — it never
//! panics and never reads past its input — and refuses unknown versions, trailing bytes, unsorted
//! sets, out-of-range counts and oversized documents (the §4.1 conventions and §4.8 bounds).
//!
//! Documents are byte strings; `parse_*` validates structure and the signature block's shape, and
//! `verify_*` checks the statement signatures against a key set (ed25519-dalek `verify_strict`,
//! TUF's ignore-don't-error rule for unknown or failing entries).

pub mod onion;
pub mod statement;
pub mod root;
pub mod manifest;
pub mod attestation;
pub mod proof;
pub mod chain;
pub mod bundle;

pub use onion::{CanonicalOnion, OnionRef};
pub use statement::{SigBlock, SigEntry, StatementType, key_id, statement_bytes, sigblock_meets};
pub use root::{GHRT, KeySet, Network};
pub use manifest::{GHRM, Release, ArtifactKind};
pub use attestation::GHRA;
pub use proof::{GHRP, leaf_checksum, leaf_hash, check_inclusion};
pub use chain::GHRC;
pub use bundle::{GHRB, BUNDLE_MAX, ROOT_MAX, MANIFEST_MAX, PROOF_MAX};


/// Every parse/verify failure, one enum (no panics, no partial reads).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FormatError {
    #[error("truncated input")]
    Truncated,
    #[error("trailing bytes after the document")]
    Trailing,
    #[error("unknown document version")]
    Version,
    #[error("bad magic or wrong document type")]
    Magic,
    #[error("count out of range")]
    Count,
    #[error("set not strictly ascending in its canonical key")]
    Ordering,
    #[error("duplicate element in a set")]
    Duplicate,
    #[error("a key appears in more than one keyset")]
    KeyReuse,
    #[error("value out of range")]
    Range,
    #[error("non-canonical onion spelling")]
    Onion,
    #[error("document larger than its fixed bound")]
    TooLarge,
    #[error("ext bytes must be zero in version 1")]
    Ext,
    #[error("signature block does not meet the threshold")]
    Threshold,
    #[error("bad signature or unknown key in a block entry")]
    Signature,
    #[error("Merkle path does not reconstruct the tree head")]
    Inclusion,
    #[error("log signature does not verify on the checkpoint body")]
    LogSignature,
    #[error("cosignature time too far in the future")]
    CosignatureTime,
    #[error("network mismatch between documents")]
    Network,
}

/// SHA-256 of a byte string, the document-digest helper shared by the formats.
pub fn sha256_of(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(data).into()
}

/// A bounds-checked, position-tracking reader: every `take` is exact, and `done` enforces
/// "no trailing bytes". Total by construction.
pub(crate) struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }
    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8], FormatError> {
        if self.buf.len() - self.pos < n {
            return Err(FormatError::Truncated);
        }
        let out = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }
    pub(crate) fn u8(&mut self) -> Result<u8, FormatError> {
        Ok(self.take(1)?[0])
    }
    pub(crate) fn u16(&mut self) -> Result<u16, FormatError> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().expect("2 bytes")))
    }
    pub(crate) fn u32(&mut self) -> Result<u32, FormatError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().expect("4 bytes")))
    }
    pub(crate) fn u64(&mut self) -> Result<u64, FormatError> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().expect("8 bytes")))
    }
    /// A `<u16>`-length-prefixed byte string (§4.1).
    pub(crate) fn lp16(&mut self) -> Result<&'a [u8], FormatError> {
        let n = self.u16()? as usize;
        self.take(n)
    }
    /// A `<u32>`-length-prefixed byte string (§4.1).
    pub(crate) fn lp32(&mut self) -> Result<&'a [u8], FormatError> {
        let n = self.u32()? as usize;
        self.take(n)
    }
    pub(crate) fn done(&self) -> Result<(), FormatError> {
        if self.pos == self.buf.len() {
            Ok(())
        } else {
            Err(FormatError::Trailing)
        }
    }
    pub(crate) fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }
}

pub(crate) fn check_ext(r: &mut Reader<'_>) -> Result<(), FormatError> {
    if r.u8()? != 0 {
        return Err(FormatError::Ext);
    }
    Ok(())
}

/// Strictly-ascending check for a sequence of canonical keys (§4.1: one canonical encoding per
/// value; equal neighbours are duplicates).
pub(crate) fn check_ascending(items: &[[u8; 32]]) -> Result<(), FormatError> {
    for w in items.windows(2) {
        match w[0].cmp(&w[1]) {
            std::cmp::Ordering::Less => {}
            std::cmp::Ordering::Equal => return Err(FormatError::Duplicate),
            std::cmp::Ordering::Greater => return Err(FormatError::Ordering),
        }
    }
    Ok(())
}

/// The same for variable-length canonical keys (onion bytes, key-id-prefixed entries).
pub(crate) fn check_ascending_bytes(items: &[impl AsRef<[u8]>]) -> Result<(), FormatError> {
    for w in items.windows(2) {
        match w[0].as_ref().cmp(w[1].as_ref()) {
            std::cmp::Ordering::Less => {}
            std::cmp::Ordering::Equal => return Err(FormatError::Duplicate),
            std::cmp::Ordering::Greater => return Err(FormatError::Ordering),
        }
    }
    Ok(())
}
