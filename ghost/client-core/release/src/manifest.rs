//! Release manifest `GHRM`, §4.5.

use crate::attestation::GHRA;
use crate::onion::{canonical_onion, OnionRef};
use crate::statement::{SigBlock, StatementType};
use crate::{FormatError, Reader, check_ascending_bytes, check_ext};

pub const RELEASES_MAX: usize = 4;
pub const MIRRORS_MAX: usize = 16;
pub const RELAYS_MAX: usize = 512;
pub const ARTIFACTS_MIN: usize = 1;
pub const ARTIFACTS_MAX: usize = 32;
pub const MANIFEST_MAX_BYTES: usize = crate::MANIFEST_MAX;
pub const VERSION_NAME_MIN: usize = 1;
pub const VERSION_NAME_MAX: usize = 32;
pub const MAX_APK_LENGTH: u64 = 268_435_456;
pub const MAX_FLOOR_VERSION_CODE: u32 = 2_147_483_647;
pub const MAX_VERSION_CODE: u32 = 2_147_483_647;
pub const MAX_VALIDITY_DAYS: u32 = 91;
pub const ROLLOUT_MAX: u16 = 1000;

/// Artifact kinds (§4.5 / §6.1). 16 is required in every release.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum ArtifactKind {
    NativeArm64 = 1,
    NativeX86_64 = 2,
    SymbolsArm64 = 3,
    SymbolsX86_64 = 4,
    Relay = 5,
    Issuer = 6,
    IssuerOps = 7,
    ReleaseOps = 8,
    ApkNotices = 9,
    RelayNotices = 10,
    IssuerNotices = 11,
    SbomClient = 12,
    SbomRelay = 13,
    SbomIssuer = 14,
    MplSource = 15,
    SourceEscrow = 16,
    EsFile = 17,
    BuilderRecipe = 18,
    PublicSource = 19,
    VerifyX86_64Linux = 20,
    VerifyAarch64Linux = 21,
    VerifyX86_64Windows = 22,
    PerVersionEvidence = 23,
    WireTranscript = 24,
}

impl ArtifactKind {
    pub fn from_u8(v: u8) -> Option<Self> {
        use ArtifactKind::*;
        Some(match v {
            1 => NativeArm64,
            2 => NativeX86_64,
            3 => SymbolsArm64,
            4 => SymbolsX86_64,
            5 => Relay,
            6 => Issuer,
            7 => IssuerOps,
            8 => ReleaseOps,
            9 => ApkNotices,
            10 => RelayNotices,
            11 => IssuerNotices,
            12 => SbomClient,
            13 => SbomRelay,
            14 => SbomIssuer,
            15 => MplSource,
            16 => SourceEscrow,
            17 => EsFile,
            18 => BuilderRecipe,
            19 => PublicSource,
            20 => VerifyX86_64Linux,
            21 => VerifyAarch64Linux,
            22 => VerifyX86_64Windows,
            23 => PerVersionEvidence,
            24 => WireTranscript,
            _ => return None,
        })
    }
}

/// `release := u32 version_code ‖ <u16 ASCII version_name> ‖ u8 min_sdk ‖ u8 flavor ‖ u32 anchor_root
///   ‖ u8 release_flags ‖ apk_sha256[32] ‖ u64 apk_length ‖ unsigned_sha256[32] ‖ u64 unsigned_length
///   ‖ u16 rollout_permille ‖ rollout_salt[16] ‖ commit[20] ‖ u64 es_seq ‖ es_sha256[32]
///   ‖ u8 nart ‖ nart × ( u8 kind ‖ sha256[32] ‖ u64 length )`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Release {
    pub version_code: u32,
    pub version_name: Vec<u8>,
    pub min_sdk: u8,
    pub flavor: u8,
    pub anchor_root: u32,
    pub wire_changing: bool,
    pub apk_sha256: [u8; 32],
    pub apk_length: u64,
    pub unsigned_sha256: [u8; 32],
    pub unsigned_length: u64,
    pub rollout_permille: u16,
    pub rollout_salt: [u8; 16],
    pub commit: [u8; 20],
    pub es_seq: u64,
    pub es_sha256: [u8; 32],
    pub artifacts: Vec<(ArtifactKind, [u8; 32], u64)>,
}

impl Release {
    fn parse(r: &mut Reader<'_>) -> Result<Self, FormatError> {
        let version_code = r.u32()?;
        if version_code == 0 || version_code > MAX_VERSION_CODE {
            return Err(FormatError::Range);
        }
        let version_name = r.lp16()?;
        if version_name.len() < VERSION_NAME_MIN
            || version_name.len() > VERSION_NAME_MAX
            || !version_name.is_ascii()
        {
            return Err(FormatError::Range);
        }
        let min_sdk = r.u8()?;
        let flavor = r.u8()?;
        if flavor != 1 {
            return Err(FormatError::Version);
        }
        let anchor_root = r.u32()?;
        let flags = r.u8()?;
        if flags & !0x01 != 0 {
            return Err(FormatError::Ext);
        }
        let apk_sha256: [u8; 32] = r.take(32)?.try_into().expect("32 bytes");
        let apk_length = r.u64()?;
        if apk_length == 0 || apk_length > MAX_APK_LENGTH {
            return Err(FormatError::Range);
        }
        let unsigned_sha256: [u8; 32] = r.take(32)?.try_into().expect("32 bytes");
        let unsigned_length = r.u64()?;
        if unsigned_length == 0 {
            return Err(FormatError::Range);
        }
        let rollout_permille = r.u16()?;
        if rollout_permille > ROLLOUT_MAX {
            return Err(FormatError::Range);
        }
        let rollout_salt: [u8; 16] = r.take(16)?.try_into().expect("16 bytes");
        let commit: [u8; 20] = r.take(20)?.try_into().expect("20 bytes");
        let es_seq = r.u64()?;
        let es_sha256: [u8; 32] = r.take(32)?.try_into().expect("32 bytes");
        let nart = r.u8()? as usize;
        if nart < ARTIFACTS_MIN || nart > ARTIFACTS_MAX {
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
        if !artifacts.iter().any(|a| a.0 == ArtifactKind::SourceEscrow) {
            return Err(FormatError::Count); // kind 16 is required in every release
        }
        Ok(Release {
            version_code,
            version_name: version_name.to_vec(),
            min_sdk,
            flavor,
            anchor_root,
            wire_changing: flags & 0x01 != 0,
            apk_sha256,
            apk_length,
            unsigned_sha256,
            unsigned_length,
            rollout_permille,
            rollout_salt,
            commit,
            es_seq,
            es_sha256,
            artifacts,
        })
    }

    fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.version_code.to_be_bytes());
        out.extend_from_slice(&(self.version_name.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.version_name);
        out.push(self.min_sdk);
        out.push(self.flavor);
        out.extend_from_slice(&self.anchor_root.to_be_bytes());
        out.push(if self.wire_changing { 0x01 } else { 0x00 });
        out.extend_from_slice(&self.apk_sha256);
        out.extend_from_slice(&self.apk_length.to_be_bytes());
        out.extend_from_slice(&self.unsigned_sha256);
        out.extend_from_slice(&self.unsigned_length.to_be_bytes());
        out.extend_from_slice(&self.rollout_permille.to_be_bytes());
        out.extend_from_slice(&self.rollout_salt);
        out.extend_from_slice(&self.commit);
        out.extend_from_slice(&self.es_seq.to_be_bytes());
        out.extend_from_slice(&self.es_sha256);
        out.push(self.artifacts.len() as u8);
        for (kind, sha, length) in &self.artifacts {
            out.push(*kind as u8);
            out.extend_from_slice(sha);
            out.extend_from_slice(&length.to_be_bytes());
        }
    }

    /// The attestation statement this release would be attested by (§4.6): rebuilt from the
    /// release record's own fields, every kind except 23.
    pub fn attestation(&self, network: u8) -> GHRA {
        GHRA {
            network,
            commit: self.commit,
            version_code: self.version_code,
            flavor: self.flavor,
            anchor_root: self.anchor_root,
            unsigned_sha256: self.unsigned_sha256,
            unsigned_length: self.unsigned_length,
            es_seq: self.es_seq,
            es_sha256: self.es_sha256,
            artifacts: self
                .artifacts
                .iter()
                .filter(|a| a.0 != ArtifactKind::PerVersionEvidence)
                .map(|(k, s, l)| (*k, *s, *l))
                .collect(),
        }
    }
}

/// The parsed body of a `GHRM v1`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestBody {
    pub network: u8,
    pub manifest_seq: u64,
    pub root_version: u32,
    pub root_sha256: [u8; 32],
    pub issued_day: u32,
    pub not_after_day: u32,
    pub floor_version_code: u32,
    pub releases: Vec<Release>,
    pub extra_mirrors: Vec<(Vec<u8>, [u8; 16])>,
    pub relays: Vec<(Vec<u8>, [u8; 16])>,
}

/// A full `GHRM` document: body bytes, the attestation `sigblock_or_empty`, the release sigblock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GHRM {
    pub body: ManifestBody,
    /// Per-release attestation blocks (sigblock_or_empty), one per release, in order.
    pub attestations: Vec<SigBlock>,
    pub block: SigBlock,
}

impl GHRM {
    pub fn parse(doc: &[u8]) -> Result<Self, FormatError> {
        if doc.len() > MANIFEST_MAX_BYTES {
            return Err(FormatError::TooLarge);
        }
        let mut r = Reader::new(doc);
        if r.take(4)? != b"GHRM" {
            return Err(FormatError::Magic);
        }
        if r.u8()? != 1 {
            return Err(FormatError::Version);
        }
        let network = r.u8()?;
        crate::root::Network::from_u8(network)?; // well-formed network value
        let manifest_seq = r.u64()?;
        if manifest_seq == 0 {
            return Err(FormatError::Range);
        }
        let root_version = r.u32()?;
        if root_version == 0 {
            return Err(FormatError::Range);
        }
        let root_sha256: [u8; 32] = r.take(32)?.try_into().expect("32 bytes");
        let issued_day = r.u32()?;
        let not_after_day = r.u32()?;
        if issued_day >= not_after_day || not_after_day > issued_day + MAX_VALIDITY_DAYS {
            return Err(FormatError::Range);
        }
        let floor_version_code = r.u32()?;
        if floor_version_code > MAX_FLOOR_VERSION_CODE {
            return Err(FormatError::Range);
        }
        let nrel = r.u8()? as usize;
        if nrel == 0 || nrel > RELEASES_MAX {
            return Err(FormatError::Count);
        }
        let mut releases = Vec::with_capacity(nrel);
        let mut attestations = Vec::with_capacity(nrel);
        for _ in 0..nrel {
            let rel = Release::parse(&mut r)?;
            let at = SigBlock::parse(&mut r, true)?;
            releases.push(rel);
            attestations.push(at);
        }
        for w in releases.windows(2) {
            match w[0].version_code.cmp(&w[1].version_code) {
                std::cmp::Ordering::Less => {}
                std::cmp::Ordering::Equal => return Err(FormatError::Duplicate),
                std::cmp::Ordering::Greater => return Err(FormatError::Ordering),
            }
        }
        // Every release of one manifest has the same min_sdk (§4.5).
        if releases.windows(2).any(|w| w[0].min_sdk != w[1].min_sdk) {
            return Err(FormatError::Range);
        }
        // The floor is 0 or no higher than the lowest attested flavor-1 version_code below.
        let lowest = releases.iter().map(|x| x.version_code).min().unwrap_or(0);
        if floor_version_code != 0 && floor_version_code > lowest {
            return Err(FormatError::Range);
        }
        let nmirror = r.u8()? as usize;
        if nmirror > MIRRORS_MAX {
            return Err(FormatError::Count);
        }
        let mut extra_mirrors = Vec::with_capacity(nmirror);
        for _ in 0..nmirror {
            let onion = r.lp16()?;
            canonical_onion(onion)?;
            let op: [u8; 16] = r.take(16)?.try_into().expect("16 bytes");
            extra_mirrors.push((onion.to_vec(), op));
        }
        check_ascending_bytes(
            &extra_mirrors
                .iter()
                .map(|(o, _)| OnionRef(o))
                .collect::<Vec<_>>(),
        )?;
        let nrelay = r.u16()? as usize;
        if nrelay > RELAYS_MAX {
            return Err(FormatError::Count);
        }
        let mut relays = Vec::with_capacity(nrelay);
        for _ in 0..nrelay {
            let onion = r.lp16()?;
            canonical_onion(onion)?;
            let op: [u8; 16] = r.take(16)?.try_into().expect("16 bytes");
            let flags = r.u8()?;
            if flags != 0 {
                return Err(FormatError::Ext);
            }
            relays.push((onion.to_vec(), op));
        }
        check_ascending_bytes(
            &relays.iter().map(|(o, _)| OnionRef(o)).collect::<Vec<_>>(),
        )?;
        let nbridge = r.u16()?;
        if nbridge != 0 {
            return Err(FormatError::Count); // reserved for ADR-16 (Phase 12); must be 0 in v1
        }
        check_ext(&mut r)?;
        let body = ManifestBody {
            network,
            manifest_seq,
            root_version,
            root_sha256,
            issued_day,
            not_after_day,
            floor_version_code,
            releases,
            extra_mirrors,
            relays,
        };
        let block = SigBlock::parse(&mut r, false)?;
        r.done()?;
        Ok(GHRM {
            body,
            attestations,
            block,
        })
    }

    pub fn body_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"GHRM");
        out.push(1);
        out.push(self.body.network);
        out.extend_from_slice(&self.body.manifest_seq.to_be_bytes());
        out.extend_from_slice(&self.body.root_version.to_be_bytes());
        out.extend_from_slice(&self.body.root_sha256);
        out.extend_from_slice(&self.body.issued_day.to_be_bytes());
        out.extend_from_slice(&self.body.not_after_day.to_be_bytes());
        out.extend_from_slice(&self.body.floor_version_code.to_be_bytes());
        out.push(self.body.releases.len() as u8);
        for (rel, at) in self.body.releases.iter().zip(&self.attestations) {
            rel.write(&mut out);
            at.write(&mut out);
        }
        out.push(self.body.extra_mirrors.len() as u8);
        for (o, op) in &self.body.extra_mirrors {
            out.extend_from_slice(&(o.len() as u16).to_be_bytes());
            out.extend_from_slice(o);
            out.extend_from_slice(op);
        }
        out.extend_from_slice(&(self.body.relays.len() as u16).to_be_bytes());
        for (o, op) in &self.body.relays {
            out.extend_from_slice(&(o.len() as u16).to_be_bytes());
            out.extend_from_slice(o);
            out.extend_from_slice(op);
            out.push(0);
        }
        out.extend_from_slice(&0u16.to_be_bytes()); // nbridge reserved
        out.push(0);
        out
    }

    pub fn statement(&self) -> Vec<u8> {
        crate::statement_bytes(StatementType::ReleaseManifest, self.body.network, &self.body_bytes())
    }

    /// Verify the release signature block. `keys` are raw Ed25519 public keys of the release set.
    pub fn verify_block(&self, keys: &[[u8; 32]], t: usize) -> Result<(), FormatError> {
        let msg = self.statement();
        self.block.meets(keys, t, &msg)
    }

    /// Verify one release's attestation block against attester keys (§4.5's block binds the GHRA).
    pub fn verify_attestation(
        &self,
        index: usize,
        keys: &[[u8; 32]],
        t: usize,
    ) -> Result<(), FormatError> {
        let rel = self.body.releases.get(index).ok_or(FormatError::Count)?;
        let at = self.attestations.get(index).ok_or(FormatError::Count)?;
        let ghra = rel.attestation(self.body.network);
        let msg = crate::statement_bytes(
            StatementType::BuildAttestation,
            self.body.network,
            &ghra.to_bytes(),
        );
        at.meets(keys, t, &msg)
    }
}
