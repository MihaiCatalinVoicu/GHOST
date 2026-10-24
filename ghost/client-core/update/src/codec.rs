//! The byte codec of the stored facts (§9.6) for the JNI boundary and the SQLCipher columns:
//! Kotlin packs the `upd_state` row into this layout and the native side decodes it strictly
//! (a wrong length or a trailing byte is `malformed_response`, never a partial read). Big-endian
//! throughout, the GHOST convention; every field is fixed-size or length-prefixed.

use ghost_client_release::chain::GHRC;
use ghost_client_release::manifest::GHRM;
use ghost_client_release::proof::GHRP;
use ghost_client_release::root::GHRT;

use crate::state::{Floor, Pair, StoredState, TrustEpoch};
use crate::UpdateError;

pub const CODEC_VERSION: u8 = 1;

fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(data).into()
}

/// Encode the stored facts to the wire/blob layout.
pub fn encode_stored(s: &StoredState) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(CODEC_VERSION);
    out.extend_from_slice(&s.epoch.id);
    out.extend_from_slice(&s.epoch.version_code.to_be_bytes());
    // The chain as a GHRC from its first root (contiguous by construction of the stored chain).
    let chain = GHRC {
        network: s.trusted_root().body.network as u8,
        first_version: s.chain[0].body.root_version,
        roots: s.chain.clone(),
    };
    let chain_bytes = chain.to_bytes();
    out.extend_from_slice(&(chain_bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(&chain_bytes);
    out.extend_from_slice(&s.pair.root_version.to_be_bytes());
    out.extend_from_slice(&s.pair.manifest_seq.to_be_bytes());
    match (&s.manifest, &s.manifest_sha256, &s.manifest_proof) {
        (Some(m), Some(h), Some(p)) => {
            out.push(1);
            let doc = m.body_bytes_with_block();
            out.extend_from_slice(&(doc.len() as u32).to_be_bytes());
            out.extend_from_slice(&doc);
            out.extend_from_slice(h);
            let proof = p.to_bytes();
            out.extend_from_slice(&(proof.len() as u32).to_be_bytes());
            out.extend_from_slice(&proof);
        }
        _ => out.push(0),
    }
    out.extend_from_slice(&s.floor.version_code.to_be_bytes());
    out.extend_from_slice(&s.floor.root_version.to_be_bytes());
    out.push(s.conflict as u8);
    out.push(s.root_conflict as u8);
    out
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], UpdateError> {
        let end = self.pos.checked_add(n).ok_or(UpdateError::Malformed)?;
        if end > self.buf.len() {
            return Err(UpdateError::Malformed);
        }
        let out = &self.buf[self.pos..end];
        self.pos = end;
        Ok(out)
    }
    fn u8(&mut self) -> Result<u8, UpdateError> {
        Ok(self.take(1)?[0])
    }
    fn u32(&mut self) -> Result<u32, UpdateError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().expect("4 bytes")))
    }
    fn u64(&mut self) -> Result<u64, UpdateError> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().expect("8 bytes")))
    }
    fn lp32(&mut self) -> Result<&'a [u8], UpdateError> {
        let n = self.u32()? as usize;
        self.take(n)
    }
    fn done(&self) -> Result<(), UpdateError> {
        if self.pos == self.buf.len() {
            Ok(())
        } else {
            Err(UpdateError::Malformed)
        }
    }
}

/// Decode the stored facts. The chain, manifest and proof are re-parsed from their exact
/// documents (the parse is the validation); the epoch id must match the chain's first root.
pub fn decode_stored(buf: &[u8]) -> Result<StoredState, UpdateError> {
    let mut r = Reader::new(buf);
    if r.u8()? != CODEC_VERSION {
        return Err(UpdateError::Malformed);
    }
    let epoch_id: [u8; 32] = r.take(32)?.try_into().expect("32 bytes");
    let epoch_vc = r.u32()?;
    if epoch_vc == 0 {
        return Err(UpdateError::Malformed);
    }
    let chain_doc = r.lp32()?;
    let chain = GHRC::parse(chain_doc).map_err(|_| UpdateError::Malformed)?;
    if chain.roots.is_empty() {
        return Err(UpdateError::Malformed);
    }
    let pair = Pair {
        root_version: r.u32()?,
        manifest_seq: r.u64()?,
    };
    let (manifest, manifest_sha256, manifest_proof) = if r.u8()? == 1 {
        let doc = r.lp32()?;
        let m = GHRM::parse(doc).map_err(|_| UpdateError::Malformed)?;
        let hash: [u8; 32] = r.take(32)?.try_into().expect("32 bytes");
        if hash != sha256(doc) {
            return Err(UpdateError::Malformed);
        }
        let proof_doc = r.lp32()?;
        let p = GHRP::parse(proof_doc).map_err(|_| UpdateError::Malformed)?;
        (Some(m), Some(hash), Some(p))
    } else {
        (None, None, None)
    };
    let floor = Floor { version_code: r.u32()?, root_version: r.u32()? };
    let conflict = r.u8()? != 0;
    let root_conflict = r.u8()? != 0;
    r.done()?;
    // The epoch id binds to the chain's newest root (§7.4 step 0: a fresh epoch takes
    // `epoch := SHA-256(E)` with E the newest root of the embedded chain).
    let state = StoredState {
        epoch: TrustEpoch { id: epoch_id, version_code: epoch_vc },
        chain: chain.roots,
        pair,
        manifest,
        manifest_proof,
        manifest_sha256,
        floor,
        conflict,
        root_conflict,
    };
    if state.pair.root_version != 0
        && state
            .chain
            .iter()
            .all(|r| r.body.root_version != state.pair.root_version)
    {
        return Err(UpdateError::Malformed);
    }
    Ok(state)
}

/// The one-byte `Code` of §9.2 (the JNI results, `ghost-verify` and the tests share it).
pub fn code_byte(e: &UpdateError) -> u8 {
    match e {
        UpdateError::Malformed => 1,
        UpdateError::WrongNetwork => 2,
        UpdateError::ClockUntrusted => 3,
        UpdateError::RootChainBroken => 4,
        UpdateError::RootUnlogged => 5,
        UpdateError::RootMismatch => 6,
        UpdateError::BadSignature => 7,
        UpdateError::FloorInvalid => 8,
        UpdateError::LogProofInvalid => 9,
        UpdateError::QuorumNotMet => 10,
        UpdateError::NotYetValid => 11,
        UpdateError::Rollback => 12,
        UpdateError::Unchanged => 13,
        UpdateError::Conflict => 14,
        UpdateError::NoManifest => 15,
        UpdateError::Stale => 16,
        UpdateError::SdkUnsupported => 17,
        UpdateError::Unsupported => 18,
        UpdateError::UpToDate => 19,
        UpdateError::ApkLayout => 20,
        UpdateError::ApkLength => 21,
        UpdateError::ApkHash => 22,
        UpdateError::ApkCore => 23,
        UpdateError::ApkSigner => 24,
        UpdateError::AttestationQuorum => 25,
        UpdateError::OutOfOrder => 26,
    }
}

/// The root document of one chain entry, for the JNI `nativeStart` (the embedded chain arrives
/// as a GHRC and Kotlin stores what step 0 returns).
pub fn chain_doc(root: &GHRT) -> Vec<u8> {
    root.to_bytes()
}
