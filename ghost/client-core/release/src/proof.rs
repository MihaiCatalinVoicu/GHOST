//! Log proof `GHRP`, §4.7 — the Sigsum v1 components in a GHOST container, with the RFC 6962
//! inclusion check and the C2SP checkpoint tree head.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::FormatError;
use crate::Reader;
use crate::statement::key_id;

pub const PROOF_MAX_PATH: usize = 63;
pub const PROOF_MAX_COSIGNATURES: usize = 32;
pub const PROOF_MAX_BYTES: usize = crate::PROOF_MAX;
pub const SIGSUM_LEAF_DOMAIN: &[u8] = b"sigsum.org/v1/tree-leaf";
pub const COSIGNATURE_DOMAIN: &[u8] = b"cosignature/v1";

/// `SHA-256(SHA-256(file))` — what the log stores as the leaf checksum (§5.1).
pub fn leaf_checksum(file: &[u8]) -> [u8; 32] {
    Sha256::digest(Sha256::digest(file)).into()
}

/// The tree hash of a leaf: `SHA-256(0x00 ‖ leaf)` (RFC 6962 §2).
pub fn leaf_hash(leaf: &[u8; 128]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x00]);
    h.update(leaf);
    h.finalize().into()
}

/// RFC 6962 inclusion: fold `leaf_hash` with the path nodes from `leaf_index` up to the root.
pub fn check_inclusion(
    leaf: [u8; 32],
    leaf_index: u64,
    path: &[[u8; 32]],
    root_hash: &[u8; 32],
) -> Result<(), FormatError> {
    let mut idx = leaf_index;
    let mut cur = leaf;
    for node in path {
        let mut h = Sha256::new();
        if idx % 2 == 0 {
            h.update([0x01]);
            h.update(cur);
            h.update(node);
        } else {
            h.update([0x01]);
            h.update(node);
            h.update(cur);
        }
        cur = h.finalize().into();
        idx /= 2;
    }
    if cur == *root_hash {
        Ok(())
    } else {
        Err(FormatError::Inclusion)
    }
}

/// One witness cosignature: `witness_key_id[32] ‖ u64 time ‖ cosignature[64]`, ascending by key id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cosignature {
    pub witness_key_id: [u8; 32],
    pub time: u64,
    pub signature: [u8; 64],
}

/// A parsed `GHRP v1` document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GHRP {
    pub message: [u8; 32],
    pub log: u8,
    pub leaf_signature: [u8; 64],
    pub leaf_key_id: [u8; 32],
    pub tree_size: u64,
    pub leaf_index: u64,
    pub path: Vec<[u8; 32]>,
    pub root_hash: [u8; 32],
    pub log_signature: [u8; 64],
    pub cosignatures: Vec<Cosignature>,
}

impl GHRP {
    pub fn parse(doc: &[u8]) -> Result<Self, FormatError> {
        if doc.len() > PROOF_MAX_BYTES {
            return Err(FormatError::TooLarge);
        }
        let mut r = Reader::new(doc);
        if r.take(4)? != b"GHRP" {
            return Err(FormatError::Magic);
        }
        if r.u8()? != 1 {
            return Err(FormatError::Version);
        }
        let message: [u8; 32] = r.take(32)?.try_into().expect("32 bytes");
        let log = r.u8()?;
        let leaf_signature: [u8; 64] = r.take(64)?.try_into().expect("64 bytes");
        let leaf_key_id: [u8; 32] = r.take(32)?.try_into().expect("32 bytes");
        let tree_size = r.u64()?;
        let leaf_index = r.u64()?;
        if leaf_index >= tree_size {
            return Err(FormatError::Range);
        }
        let npath = r.u8()? as usize;
        if npath > PROOF_MAX_PATH {
            return Err(FormatError::Count);
        }
        let mut path = Vec::with_capacity(npath);
        for _ in 0..npath {
            path.push(r.take(32)?.try_into().expect("32 bytes"));
        }
        let root_hash: [u8; 32] = r.take(32)?.try_into().expect("32 bytes");
        let log_signature: [u8; 64] = r.take(64)?.try_into().expect("64 bytes");
        let ncos = r.u8()? as usize;
        if ncos > PROOF_MAX_COSIGNATURES {
            return Err(FormatError::Count);
        }
        let mut cosignatures = Vec::with_capacity(ncos);
        for _ in 0..ncos {
            let witness_key_id: [u8; 32] = r.take(32)?.try_into().expect("32 bytes");
            let time = r.u64()?;
            let signature: [u8; 64] = r.take(64)?.try_into().expect("64 bytes");
            cosignatures.push(Cosignature {
                witness_key_id,
                time,
                signature,
            });
        }
        for w in cosignatures.windows(2) {
            match w[0].witness_key_id.cmp(&w[1].witness_key_id) {
                std::cmp::Ordering::Less => {}
                std::cmp::Ordering::Equal => return Err(FormatError::Duplicate),
                std::cmp::Ordering::Greater => return Err(FormatError::Ordering),
            }
        }
        r.done()?;
        Ok(GHRP {
            message,
            log,
            leaf_signature,
            leaf_key_id,
            tree_size,
            leaf_index,
            path,
            root_hash,
            log_signature,
            cosignatures,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"GHRP");
        out.push(1);
        out.extend_from_slice(&self.message);
        out.push(self.log);
        out.extend_from_slice(&self.leaf_signature);
        out.extend_from_slice(&self.leaf_key_id);
        out.extend_from_slice(&self.tree_size.to_be_bytes());
        out.extend_from_slice(&self.leaf_index.to_be_bytes());
        out.push(self.path.len() as u8);
        for n in &self.path {
            out.extend_from_slice(n);
        }
        out.extend_from_slice(&self.root_hash);
        out.extend_from_slice(&self.log_signature);
        out.push(self.cosignatures.len() as u8);
        for c in &self.cosignatures {
            out.extend_from_slice(&c.witness_key_id);
            out.extend_from_slice(&c.time.to_be_bytes());
            out.extend_from_slice(&c.signature);
        }
        out
    }

    /// The 128-byte Sigsum leaf: `checksum ‖ leaf_signature ‖ leaf_key_id` (§4.7/§5.1).
    pub fn leaf(&self, file: &[u8]) -> [u8; 128] {
        let mut leaf = [0u8; 128];
        leaf[..32].copy_from_slice(&leaf_checksum(file));
        leaf[32..96].copy_from_slice(&self.leaf_signature);
        leaf[96..].copy_from_slice(&self.leaf_key_id);
        leaf
    }

    /// Verify the leaf signature over the Sigsum leaf statement with the given signing key
    /// (`"sigsum.org/v1/tree-leaf" ‖ 0x00 ‖ checksum`, §4.7).
    pub fn verify_leaf(&self, file: &[u8], signer_pk: &[u8; 32]) -> Result<(), FormatError> {
        if key_id(signer_pk) != self.leaf_key_id {
            return Err(FormatError::Signature);
        }
        let mut msg = Vec::with_capacity(SIGSUM_LEAF_DOMAIN.len() + 1 + 32);
        msg.extend_from_slice(SIGSUM_LEAF_DOMAIN);
        msg.push(0x00);
        msg.extend_from_slice(&leaf_checksum(file));
        let sig = Signature::from_slice(&self.leaf_signature).map_err(|_| FormatError::Signature)?;
        let key = VerifyingKey::from_bytes(signer_pk).map_err(|_| FormatError::Signature)?;
        key.verify_strict(&msg, &sig)
            .map_err(|_| FormatError::Signature)
    }

    /// The C2SP checkpoint body the log signs (§4.7): the sigsum.org tree-checkpoint framing.
    pub fn checkpoint_body(&self, log_key_id: &[u8; 32]) -> Vec<u8> {
        format!(
            "sigsum.org/v1/tree/{}\n{}\n{}\n",
            hex::encode(log_key_id),
            self.tree_size,
            hex::encode(self.root_hash)
        )
        .into_bytes()
    }

    /// Verify the log's signature on its tree head.
    pub fn verify_log_signature(&self, log_pk: &[u8; 32]) -> Result<(), FormatError> {
        let body = self.checkpoint_body(&key_id(log_pk));
        let sig = Signature::from_slice(&self.log_signature).map_err(|_| FormatError::LogSignature)?;
        let key = VerifyingKey::from_bytes(log_pk).map_err(|_| FormatError::LogSignature)?;
        key.verify_strict(&body, &sig)
            .map_err(|_| FormatError::LogSignature)
    }

    /// Verify one witness cosignature over `"cosignature/v1\ntime <t>\n" ‖ checkpoint body`.
    pub fn verify_cosignature(
        &self,
        cos: &Cosignature,
        witness_pk: &[u8; 32],
        log_pk: &[u8; 32],
    ) -> Result<(), FormatError> {
        if key_id(witness_pk) != cos.witness_key_id {
            return Err(FormatError::Signature);
        }
        let body = self.checkpoint_body(&key_id(log_pk));
        let mut msg = Vec::new();
        msg.extend_from_slice(COSIGNATURE_DOMAIN);
        msg.extend_from_slice(b"\ntime ");
        msg.extend_from_slice(cos.time.to_string().as_bytes());
        msg.extend_from_slice(b"\n");
        msg.extend_from_slice(&body);
        let sig = Signature::from_slice(&cos.signature).map_err(|_| FormatError::Signature)?;
        let key = VerifyingKey::from_bytes(witness_pk).map_err(|_| FormatError::Signature)?;
        key.verify_strict(&msg, &sig).map_err(|_| FormatError::Signature)
    }

    /// The §4.7 time sanity bound: no cosignature may exceed the device's trusted time by more
    /// than σ + 1 day = 4 days (σ = 3 days). There is no lower bound.
    pub fn check_cosignature_times(&self, device_now: u64) -> Result<(), FormatError> {
        const SIGMA_PLUS_DAY_SECS: u64 = 4 * 86_400;
        for c in &self.cosignatures {
            if c.time > device_now + SIGMA_PLUS_DAY_SECS {
                return Err(FormatError::CosignatureTime);
            }
        }
        Ok(())
    }
}
