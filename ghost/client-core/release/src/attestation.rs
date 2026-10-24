//! Attestation statement `GHRA`, §4.6 — rebuilt by the client from the release record's own
//! fields; an attester never sees or signs the signed APK.

use crate::FormatError;
use crate::Reader;
use crate::manifest::ArtifactKind;

/// `GHRA v1 := "GHRA" ‖ u8 version = 1 ‖ u8 network ‖ commit[20] ‖ u32 version_code ‖ u8 flavor
///   ‖ u32 anchor_root ‖ unsigned_sha256[32] ‖ u64 unsigned_length ‖ u64 es_seq ‖ es_sha256[32]
///   ‖ u8 nart ‖ nart × ( u8 kind ‖ sha256[32] ‖ u64 length )`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GHRA {
    pub network: u8,
    pub commit: [u8; 20],
    pub version_code: u32,
    pub flavor: u8,
    pub anchor_root: u32,
    pub unsigned_sha256: [u8; 32],
    pub unsigned_length: u64,
    pub es_seq: u64,
    pub es_sha256: [u8; 32],
    pub artifacts: Vec<(ArtifactKind, [u8; 32], u64)>,
}

impl GHRA {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"GHRA");
        out.push(1);
        out.push(self.network);
        out.extend_from_slice(&self.commit);
        out.extend_from_slice(&self.version_code.to_be_bytes());
        out.push(self.flavor);
        out.extend_from_slice(&self.anchor_root.to_be_bytes());
        out.extend_from_slice(&self.unsigned_sha256);
        out.extend_from_slice(&self.unsigned_length.to_be_bytes());
        out.extend_from_slice(&self.es_seq.to_be_bytes());
        out.extend_from_slice(&self.es_sha256);
        out.push(self.artifacts.len() as u8);
        for (kind, sha, length) in &self.artifacts {
            out.push(*kind as u8);
            out.extend_from_slice(sha);
            out.extend_from_slice(&length.to_be_bytes());
        }
        out
    }

    pub fn parse(doc: &[u8]) -> Result<Self, FormatError> {
        let mut r = Reader::new(doc);
        if r.take(4)? != b"GHRA" {
            return Err(FormatError::Magic);
        }
        if r.u8()? != 1 {
            return Err(FormatError::Version);
        }
        let network = r.u8()?;
        let commit: [u8; 20] = r.take(20)?.try_into().expect("20 bytes");
        let version_code = r.u32()?;
        let flavor = r.u8()?;
        let anchor_root = r.u32()?;
        let unsigned_sha256: [u8; 32] = r.take(32)?.try_into().expect("32 bytes");
        let unsigned_length = r.u64()?;
        let es_seq = r.u64()?;
        let es_sha256: [u8; 32] = r.take(32)?.try_into().expect("32 bytes");
        let nart = r.u8()? as usize;
        if nart == 0 {
            return Err(FormatError::Count);
        }
        let mut artifacts = Vec::with_capacity(nart);
        for _ in 0..nart {
            let kind = ArtifactKind::from_u8(r.u8()?).ok_or(FormatError::Version)?;
            let sha: [u8; 32] = r.take(32)?.try_into().expect("32 bytes");
            let length = r.u64()?;
            artifacts.push((kind, sha, length));
        }
        for w in artifacts.windows(2) {
            match w[0].0.cmp(&w[1].0) {
                std::cmp::Ordering::Less => {}
                std::cmp::Ordering::Equal => return Err(FormatError::Duplicate),
                std::cmp::Ordering::Greater => return Err(FormatError::Ordering),
            }
        }
        r.done()?;
        Ok(GHRA {
            network,
            commit,
            version_code,
            flavor,
            anchor_root,
            unsigned_sha256,
            unsigned_length,
            es_seq,
            es_sha256,
            artifacts,
        })
    }
}
