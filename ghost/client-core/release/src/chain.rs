//! Root chain `GHRC`, §4.4.

use crate::FormatError;
use crate::Reader;
use crate::root::GHRT;

pub const CHAIN_MAX: usize = 64;

/// `GHRC v1 := "GHRC" ‖ u8 version = 1 ‖ u8 network ‖ u32 first_version ‖ u16 count
///            ‖ count × <u32 GHRT>` (root versions contiguous from first_version).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GHRC {
    pub network: u8,
    pub first_version: u32,
    pub roots: Vec<GHRT>,
}

impl GHRC {
    pub fn parse(doc: &[u8]) -> Result<Self, FormatError> {
        let mut r = Reader::new(doc);
        if r.take(4)? != b"GHRC" {
            return Err(FormatError::Magic);
        }
        if r.u8()? != 1 {
            return Err(FormatError::Version);
        }
        let network = r.u8()?;
        crate::root::Network::from_u8(network)?; // well-formed network value
        let first_version = r.u32()?;
        if first_version == 0 {
            return Err(FormatError::Range);
        }
        let count = r.u16()? as usize;
        if count == 0 || count > CHAIN_MAX {
            return Err(FormatError::Count);
        }
        let mut roots = Vec::with_capacity(count);
        for i in 0..count {
            let doc = r.lp32()?;
            let root = GHRT::parse(doc)?;
            if root.body.network as u8 != network {
                return Err(FormatError::Network);
            }
            let expected = first_version + i as u32;
            if root.body.root_version != expected {
                return Err(FormatError::Range); // contiguous by construction of the chain
            }
            roots.push(root);
        }
        r.done()?;
        Ok(GHRC {
            network,
            first_version,
            roots,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"GHRC");
        out.push(1);
        out.push(self.network);
        out.extend_from_slice(&self.first_version.to_be_bytes());
        out.extend_from_slice(&(self.roots.len() as u16).to_be_bytes());
        for r in &self.roots {
            let d = r.to_bytes();
            out.extend_from_slice(&(d.len() as u32).to_be_bytes());
            out.extend_from_slice(&d);
        }
        out
    }
}
