//! Root `GHRT`, §4.3.

use crate::onion::{canonical_onion, OnionRef};
use crate::statement::{SigBlock, StatementType};
use crate::{FormatError, Reader, check_ascending, check_ascending_bytes, check_ext};

pub const KEYSET_MAX: usize = 8;
pub const ATTEST_KEYSET_MAX: usize = 16;
pub const APK_SIGNERS_MAX: usize = 4;
pub const LOGS_MAX: usize = 4;
pub const WITNESSES_MAX: usize = 32;
pub const ANCHOR_MIRRORS_MIN: usize = 2;
pub const ANCHOR_MIRRORS_MAX: usize = 8;
pub const ROOT_MAX_BYTES: usize = crate::ROOT_MAX;

/// The three networks (§4.3): mainnet, stagenet, regtest (vectors/test worlds only).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    Mainnet = 1,
    Stagenet = 2,
    Regtest = 3,
}

impl Network {
    pub fn from_u8(v: u8) -> Result<Self, FormatError> {
        match v {
            1 => Ok(Network::Mainnet),
            2 => Ok(Network::Stagenet),
            3 => Ok(Network::Regtest),
            _ => Err(FormatError::Version),
        }
    }
}

/// `keyset := u8 n ‖ n × pk[32] ‖ u8 t` — keys ascending by key id, a key in at most one keyset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeySet {
    pub keys: Vec<[u8; 32]>,
    pub threshold: usize,
}

impl KeySet {
    fn parse(r: &mut Reader<'_>, max: usize) -> Result<Self, FormatError> {
        let n = r.u8()? as usize;
        if n > max {
            return Err(FormatError::Count);
        }
        let mut keys = Vec::with_capacity(n);
        for _ in 0..n {
            keys.push(r.take(32)?.try_into().expect("32 bytes"));
        }
        let mut ids: Vec<[u8; 32]> = keys.iter().map(|k| crate::key_id(k)).collect();
        check_ascending(&mut ids)?;
        let t = r.u8()? as usize;
        if t > n {
            return Err(FormatError::Count);
        }
        Ok(KeySet { keys, threshold: t })
    }

    fn write(&self, out: &mut Vec<u8>) {
        out.push(self.keys.len() as u8);
        for k in &self.keys {
            out.extend_from_slice(k);
        }
        out.push(self.threshold as u8);
    }

    pub fn key_ids(&self) -> Vec<[u8; 32]> {
        self.keys.iter().map(|k| crate::key_id(k)).collect()
    }
}

/// `logs := u8 n ‖ n × ( pk[32] ‖ <u16 ASCII origin> )`, ascending by key id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogEntry {
    pub pk: [u8; 32],
    pub origin: Vec<u8>,
}

/// `anchor_mirrors := u8 n ‖ n × ( onion ‖ operator_id[16] )`, strictly ascending canonical onion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorMirror {
    pub onion: Vec<u8>,
    pub operator_id: [u8; 16],
}

/// The parsed body of a `GHRT v1` (everything before the signature block).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootBody {
    pub network: Network,
    pub root_version: u32,
    pub root: KeySet,
    pub release: KeySet,
    pub attest: KeySet,
    pub apk_signers: Vec<[u8; 32]>,
    pub logs: Vec<LogEntry>,
    pub witnesses: Vec<[u8; 32]>,
    pub quorum: usize,
    pub anchor_mirrors: Vec<AnchorMirror>,
}

/// A full `GHRT` document: body bytes plus the parsed block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GHRT {
    pub body: RootBody,
    pub block: SigBlock,
}

impl GHRT {
    pub fn parse(doc: &[u8]) -> Result<Self, FormatError> {
        if doc.len() > ROOT_MAX_BYTES {
            return Err(FormatError::TooLarge);
        }
        let mut r = Reader::new(doc);
        if r.take(4)? != b"GHRT" {
            return Err(FormatError::Magic);
        }
        if r.u8()? != 1 {
            return Err(FormatError::Version);
        }
        let network = Network::from_u8(r.u8()?)?;
        let root_version = r.u32()?;
        if root_version == 0 {
            return Err(FormatError::Range);
        }
        let root = KeySet::parse(&mut r, KEYSET_MAX)?;
        if root.threshold == 0 {
            return Err(FormatError::Count);
        }
        let release = KeySet::parse(&mut r, KEYSET_MAX)?;
        if release.threshold == 0 {
            return Err(FormatError::Count);
        }
        let attest = KeySet::parse(&mut r, ATTEST_KEYSET_MAX)?;
        let apk_n = r.u8()? as usize;
        if apk_n == 0 || apk_n > APK_SIGNERS_MAX {
            return Err(FormatError::Count);
        }
        let mut apk_signers = Vec::with_capacity(apk_n);
        for _ in 0..apk_n {
            apk_signers.push(r.take(32)?.try_into().expect("32 bytes"));
        }
        check_ascending(&mut apk_signers)?;
        let logs_n = r.u8()? as usize;
        if logs_n == 0 || logs_n > LOGS_MAX {
            return Err(FormatError::Count);
        }
        let mut logs = Vec::with_capacity(logs_n);
        for _ in 0..logs_n {
            let pk: [u8; 32] = r.take(32)?.try_into().expect("32 bytes");
            let origin = r.lp16()?.to_vec();
            logs.push(LogEntry { pk, origin });
        }
        {
            let mut ids: Vec<[u8; 32]> = logs.iter().map(|l| crate::key_id(&l.pk)).collect();
            check_ascending(&mut ids)?;
        }
        let wit_n = r.u8()? as usize;
        if wit_n > WITNESSES_MAX {
            return Err(FormatError::Count);
        }
        let mut witnesses = Vec::with_capacity(wit_n);
        for _ in 0..wit_n {
            witnesses.push(r.take(32)?.try_into().expect("32 bytes"));
        }
        // Ascending by key id (§4.3), not by raw public key bytes.
        let mut witness_ids: Vec<[u8; 32]> = witnesses.iter().map(|w| crate::key_id(w)).collect();
        check_ascending(&mut witness_ids)?;
        let quorum = r.u8()? as usize;
        if quorum > wit_n {
            return Err(FormatError::Count);
        }
        let am_n = r.u8()? as usize;
        if am_n < ANCHOR_MIRRORS_MIN || am_n > ANCHOR_MIRRORS_MAX {
            return Err(FormatError::Count);
        }
        let mut anchor_mirrors = Vec::with_capacity(am_n);
        for _ in 0..am_n {
            let onion = r.lp16()?;
            canonical_onion(onion)?;
            let operator_id: [u8; 16] = r.take(16)?.try_into().expect("16 bytes");
            anchor_mirrors.push(AnchorMirror {
                onion: onion.to_vec(),
                operator_id,
            });
        }
        check_ascending_bytes(&anchor_mirrors.iter().map(|a| OnionRef(&a.onion)).collect::<Vec<_>>())?;
        check_ext(&mut r)?;
        // A key appears in at most one keyset of a root.
        let mut all: Vec<[u8; 32]> = root
            .keys
            .iter()
            .chain(release.keys.iter())
            .chain(attest.keys.iter())
            .map(|k| crate::key_id(k))
            .collect();
        all.sort();
        for w in all.windows(2) {
            if w[0] == w[1] {
                return Err(FormatError::KeyReuse);
            }
        }
        let body = RootBody {
            network,
            root_version,
            root,
            release,
            attest,
            apk_signers,
            logs,
            witnesses,
            quorum,
            anchor_mirrors,
        };
        // Network-specific rules (§4.3).
        match network {
            Network::Mainnet => {
                if body.root.threshold < 2 || body.root.keys.len() < 3 {
                    return Err(FormatError::Count);
                }
                if body.attest.threshold < 1 {
                    return Err(FormatError::Count);
                }
                if body.quorum < 2 || body.witnesses.len() < 3 {
                    return Err(FormatError::Count);
                }
                let ops: std::collections::HashSet<[u8; 16]> = body
                    .anchor_mirrors
                    .iter()
                    .map(|a| a.operator_id)
                    .collect();
                if ops.len() < 2 {
                    return Err(FormatError::Count);
                }
            }
            Network::Stagenet => {
                if body.quorum < 1 {
                    return Err(FormatError::Count);
                }
            }
            Network::Regtest => {}
        }
        let block = SigBlock::parse(&mut r, false)?;
        r.done()?;
        Ok(GHRT { body, block })
    }

    pub fn body_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"GHRT");
        out.push(1);
        out.push(self.body.network as u8);
        out.extend_from_slice(&self.body.root_version.to_be_bytes());
        self.body.root.write(&mut out);
        self.body.release.write(&mut out);
        self.body.attest.write(&mut out);
        out.push(self.body.apk_signers.len() as u8);
        for s in &self.body.apk_signers {
            out.extend_from_slice(s);
        }
        out.push(self.body.logs.len() as u8);
        for l in &self.body.logs {
            out.extend_from_slice(&l.pk);
            out.extend_from_slice(&(l.origin.len() as u16).to_be_bytes());
            out.extend_from_slice(&l.origin);
        }
        out.push(self.body.witnesses.len() as u8);
        for w in &self.body.witnesses {
            out.extend_from_slice(w);
        }
        out.push(self.body.quorum as u8);
        out.push(self.body.anchor_mirrors.len() as u8);
        for a in &self.body.anchor_mirrors {
            out.extend_from_slice(&(a.onion.len() as u16).to_be_bytes());
            out.extend_from_slice(&a.onion);
            out.extend_from_slice(&a.operator_id);
        }
        out.push(0);
        out
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = self.body_bytes();
        self.block.write(&mut out);
        out
    }

    pub fn statement(&self) -> Vec<u8> {
        crate::statement_bytes(
            StatementType::ReleaseRoot,
            self.body.network as u8,
            &self.body_bytes(),
        )
    }

    /// The chain rule's signature half (§4.3): the block must meet `(keys, t)`. `keys` are the
    /// raw 32-byte Ed25519 public keys (matching is by SHA-256 key id, §4.1).
    pub fn verify_block(&self, keys: &[[u8; 32]], t: usize) -> Result<(), FormatError> {
        let msg = self.statement();
        self.block.meets(keys, t, &msg)
    }
}
