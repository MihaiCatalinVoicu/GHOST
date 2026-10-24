//! Bundle `GHRB`, §4.8 — what a mirror serves, with the fixed bounds checked before reading.

use crate::chain::GHRC;
use crate::manifest::GHRM;
use crate::proof::GHRP;
use crate::root::GHRT;
use crate::FormatError;
use crate::Reader;

pub const BUNDLE_MAX: usize = 1_048_576;
pub const ROOT_MAX: usize = 16_384;
pub const MANIFEST_MAX: usize = 65_536;
pub const PROOF_MAX: usize = 16_384;

/// `GHRB v1 := "GHRB" ‖ u8 version = 1 ‖ u8 network ‖ <u32 GHRC>
///   ‖ u16 nroot ‖ nroot × <u32 GHRP>     (one proof per chain entry after the first, ascending)
///   ‖ <u32 GHRM> ‖ <u32 GHRP>            (the manifest and its proof)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GHRB {
    pub network: u8,
    pub chain: GHRC,
    pub root_proofs: Vec<GHRP>,
    pub manifest: GHRM,
    pub manifest_proof: GHRP,
}

impl GHRB {
    pub fn parse(doc: &[u8]) -> Result<Self, FormatError> {
        if doc.len() > BUNDLE_MAX {
            return Err(FormatError::TooLarge);
        }
        let mut r = Reader::new(doc);
        if r.take(4)? != b"GHRB" {
            return Err(FormatError::Magic);
        }
        if r.u8()? != 1 {
            return Err(FormatError::Version);
        }
        let network = r.u8()?;
        crate::root::Network::from_u8(network)?;
        let chain_doc = r.lp32()?;
        if chain_doc.len() > ROOT_MAX.saturating_mul(64) {
            return Err(FormatError::TooLarge);
        }
        let chain = GHRC::parse(chain_doc)?;
        if chain.network != network {
            return Err(FormatError::Network);
        }
        let nroot = r.u16()? as usize;
        if nroot != chain.roots.len().saturating_sub(1) {
            return Err(FormatError::Count); // one proof per chain entry after the first
        }
        let mut root_proofs = Vec::with_capacity(nroot);
        for _ in 0..nroot {
            let p = r.lp32()?;
            if p.len() > PROOF_MAX {
                return Err(FormatError::TooLarge);
            }
            root_proofs.push(GHRP::parse(p)?);
        }
        let mdoc = r.lp32()?;
        if mdoc.len() > MANIFEST_MAX {
            return Err(FormatError::TooLarge);
        }
        let manifest = GHRM::parse(mdoc)?;
        if manifest.body.network != network {
            return Err(FormatError::Network);
        }
        let pdoc = r.lp32()?;
        if pdoc.len() > PROOF_MAX {
            return Err(FormatError::TooLarge);
        }
        let manifest_proof = GHRP::parse(pdoc)?;
        r.done()?;
        Ok(GHRB {
            network,
            chain,
            root_proofs,
            manifest,
            manifest_proof,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"GHRB");
        out.push(1);
        out.push(self.network);
        let c = self.chain.to_bytes();
        out.extend_from_slice(&(c.len() as u32).to_be_bytes());
        out.extend_from_slice(&c);
        out.extend_from_slice(&(self.root_proofs.len() as u16).to_be_bytes());
        for p in &self.root_proofs {
            let d = p.to_bytes();
            out.extend_from_slice(&(d.len() as u32).to_be_bytes());
            out.extend_from_slice(&d);
        }
        let m = self.manifest.body_bytes_with_block();
        out.extend_from_slice(&(m.len() as u32).to_be_bytes());
        out.extend_from_slice(&m);
        let mp = self.manifest_proof.to_bytes();
        out.extend_from_slice(&(mp.len() as u32).to_be_bytes());
        out.extend_from_slice(&mp);
        out
    }
}

impl GHRM {
    /// The full document bytes: body (with per-release attestation blocks, §4.5) plus the
    /// release signature block — exactly what `parse` consumes and what a bundle stores.
    pub fn body_bytes_with_block(&self) -> Vec<u8> {
        let mut out = self.body_bytes();
        self.block.write(&mut out);
        out
    }
}

// Keep GHRT referenced for docs builds that dead-strip.
#[allow(dead_code)]
fn _types(_: &GHRT) {}
