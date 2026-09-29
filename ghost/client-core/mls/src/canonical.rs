//! The canonical GHOST KeyPackage and leaves (design §6.2.4 (B), S0-4, S0-5, §19.29.1): one
//! definition used by `key_package`, the admission policy, CO-2 (A), the `JoinRequest` codec and
//! the joiner's tree check.
//!
//! An `MlsMessage` carrying a KeyPackage with: protocol version mls10; suite 0x0003; X25519 init
//! and encryption keys, each canonical and not of low order (review H1, §19.31); the leaf signature
//! key equal to the `BasicCredential` identity (the
//! pseudonym key); **leaf capabilities exactly** versions [mls10], suites [0x0003], extensions
//! [0xF0A1, 0xF0A2, 0xF0A4], proposals [], credentials [Basic], no GREASE; the leaf node source
//! `key_package` with the **constant lifetime `[0, 2⁶⁴ − 1]`** (Q42 (a)); leaf extensions exactly
//! [`GhostLeaf` with a valid `box_pk` and `refresh_epoch = 0`]; KeyPackage extensions exactly
//! [`GhostKpBind(channel_id, purpose, d)`]. Its encoding is **395 bytes** (E-62).

use openmls::prelude::tls_codec::{Deserialize as _, Serialize as _};
use openmls::prelude::*;
use openmls::treesync::{LeafNodeSource, ParentNode, RatchetTree};

use crate::ext::{self, GhostLeaf, KpBind};
use crate::join::KEY_PACKAGE_LEN;
use crate::result::{Code, MlsError, MlsResult};

/// The P0 suite (D3).
pub const SUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;

/// The constant lifetime of every KeyPackage and of the creator's leaf (Q42 (a), §19.29.1).
pub fn constant_lifetime() -> Lifetime {
    Lifetime::init(0, u64::MAX)
}

pub fn is_constant_lifetime(l: &Lifetime) -> bool {
    l.not_before() == 0 && l.not_after() == u64::MAX
}

/// The canonical leaf capabilities (§3.5, §6.2.4 (B)): 0xF0A4 must be listed, or OpenMLS builds a
/// KeyPackage its own `validate` refuses (V10-13).
pub fn canonical_capabilities() -> Capabilities {
    Capabilities::new(
        Some(&[ProtocolVersion::Mls10]),
        Some(&[SUITE]),
        Some(&[
            ExtensionType::Unknown(ext::EXT_CHANNEL_CONTEXT),
            ExtensionType::Unknown(ext::EXT_LEAF),
            ExtensionType::Unknown(ext::EXT_KP_BIND),
        ]),
        Some(&[]),
        Some(&[CredentialType::Basic]),
    )
}

fn capabilities_bytes(c: &Capabilities) -> Option<Vec<u8>> {
    c.tls_serialize_detached().ok()
}

/// `RequiredCapabilities` of every channel: 0xF0A1 and 0xF0A2 (§5.3).
pub fn required_capabilities() -> Extension {
    Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(
        &[
            ExtensionType::Unknown(ext::EXT_CHANNEL_CONTEXT),
            ExtensionType::Unknown(ext::EXT_LEAF),
        ],
        &[],
        &[CredentialType::Basic],
    ))
}

pub fn leaf_extensions(leaf: &GhostLeaf) -> MlsResult<Extensions<LeafNode>> {
    Extensions::single(Extension::Unknown(
        ext::EXT_LEAF,
        UnknownExtension(leaf.encode()),
    ))
    .map_err(|_| MlsError::new(Code::Internal))
}

/// Whether a 32-byte X25519 public key is acceptable as a `box_pk` (§5.4, the F9 §22.8.2 rule):
/// the canonical encoding of a point (below `p = 2^255 − 19`) that is not low-order (a trial
/// agreement is contributory).
pub fn valid_box_pk(pk: &[u8; 32]) -> bool {
    const P: [u8; 32] = [
        0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ];
    let mut canonical = false;
    for i in (0..32).rev() {
        if pk[i] != P[i] {
            canonical = pk[i] < P[i];
            break;
        }
    }
    canonical && x25519_dalek::x25519([0x5a; 32], *pk) != [0u8; 32]
}

/// The X25519 public key of a box secret (the scalar is clamped by X25519, as HPKE's DHKEM does).
pub fn box_public(sk: &[u8; 32]) -> [u8; 32] {
    x25519_dalek::x25519(*sk, x25519_dalek::X25519_BASEPOINT_BYTES)
}

/// Whether an HPKE public key of suite 0x0003 (an `init_key`, a leaf's or a parent node's
/// `encryption_key`) is acceptable: 32 bytes and [`valid_box_pk`]. OpenMLS checks only that a
/// KeyPackage's two keys differ (`KeyPackageIn::validate`); a low-order key it admits makes every
/// later HPKE encryption to that node fail (HACL refuses the all-zero shared secret), so one admitted
/// KeyPackage, or one update path, would stop every later commit that encrypts to it (review of
/// S2a, H1; §19.31).
pub fn valid_hpke_key(key: &[u8]) -> bool {
    <[u8; 32]>::try_from(key).is_ok_and(|k| valid_box_pk(&k))
}

/// The key of a TLS-encoded `HPKEPublicKey` at the start of `tls` (RFC 9420 §7.1: a one-byte
/// vector length, 32 for X25519, then the key): an `EncryptionKey`, or a `ParentNode`, whose first
/// field it is. OpenMLS 0.9.0 keeps both accessors crate-private.
fn leading_hpke_key(tls: &[u8]) -> Option<[u8; 32]> {
    match tls.split_first() {
        Some((32, rest)) if rest.len() >= 32 => rest[..32].try_into().ok(),
        _ => None,
    }
}

/// A leaf's `encryption_key`.
pub fn leaf_encryption_key(leaf: &LeafNode) -> Option<[u8; 32]> {
    let tls = leaf.encryption_key().tls_serialize_detached().ok()?;
    (tls.len() == 33).then(|| leading_hpke_key(&tls)).flatten()
}

/// A parent node's `encryption_key`.
pub fn parent_encryption_key(node: &ParentNode) -> Option<[u8; 32]> {
    leading_hpke_key(&node.tls_serialize_detached().ok()?)
}

/// Every HPKE key of a ratchet tree — each leaf's and each parent node's — is valid
/// ([`valid_hpke_key`]): what CO-2 requires of the tree a commit produces and the joiner of the tree
/// it joins (H1, §19.31). Every member computes it alike from the commit and the pre-commit tree.
pub fn tree_keys_valid(tree: &RatchetTree) -> bool {
    tree.leaves()
        .all(|l| leaf_encryption_key(l).is_some_and(|k| valid_box_pk(&k)))
        && tree
            .parents()
            .all(|p| parent_encryption_key(p).is_some_and(|k| valid_box_pk(&k)))
}

/// The pseudonym key a `BasicCredential` names (its 32-byte identity), the author of a message as
/// OpenMLS verified it (`ProcessedMessage::credential`: the sender's leaf **in the message's
/// epoch**, H2).
pub fn basic_identity(credential: &Credential) -> Option<[u8; 32]> {
    BasicCredential::try_from(credential.clone())
        .ok()?
        .identity()
        .try_into()
        .ok()
}

/// Why a leaf or KeyPackage is not canonical (tests and summaries; every one is
/// `INVALID_KEYPACKAGE` or `INVALID_COMMIT(non-canonical leaf)` at the API).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fault {
    Size,
    Parse,
    Signature,
    Suite,
    Capabilities,
    Lifetime,
    Source,
    LeafExtensions,
    BoxKey,
    /// An `init_key` or `encryption_key` that is not a valid X25519 key ([`valid_hpke_key`]).
    HpkeKey,
    RefreshEpoch,
    Credential,
    KpExtensions,
    Binding,
}

/// The GHOST fields of a leaf.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeafFacts {
    pub signature_key: [u8; 32],
    pub leaf: GhostLeaf,
}

/// The canonical form of a leaf node except its source (§6.2.4 (B), S0-5): the canonical
/// capabilities, exactly one extension (`GhostLeaf` with a valid `box_pk`), a valid X25519
/// `encryption_key` (H1), and a `BasicCredential` whose identity is the 32-byte signature key.
pub fn check_leaf(leaf: &LeafNode) -> Result<LeafFacts, Fault> {
    let want = capabilities_bytes(&canonical_capabilities()).ok_or(Fault::Capabilities)?;
    if capabilities_bytes(leaf.capabilities()).as_deref() != Some(want.as_slice()) {
        return Err(Fault::Capabilities);
    }
    let exts: Vec<&Extension> = leaf.extensions().iter().collect();
    let [Extension::Unknown(ext::EXT_LEAF, UnknownExtension(bytes))] = exts.as_slice() else {
        return Err(Fault::LeafExtensions);
    };
    let gl = GhostLeaf::decode(bytes).ok_or(Fault::LeafExtensions)?;
    if !valid_box_pk(&gl.box_pk) {
        return Err(Fault::BoxKey);
    }
    if !leaf_encryption_key(leaf).is_some_and(|k| valid_box_pk(&k)) {
        return Err(Fault::HpkeKey);
    }
    let signature_key: [u8; 32] = leaf
        .signature_key()
        .as_slice()
        .try_into()
        .map_err(|_| Fault::Credential)?;
    let basic =
        BasicCredential::try_from(leaf.credential().clone()).map_err(|_| Fault::Credential)?;
    if basic.identity() != signature_key.as_slice() {
        return Err(Fault::Credential);
    }
    Ok(LeafFacts {
        signature_key,
        leaf: gl,
    })
}

/// A KeyPackage-source leaf with the constant lifetime (the joiner's tree check, §6.2.5, and a
/// KeyPackage's leaf).
pub fn check_key_package_source(leaf: &LeafNode) -> Result<(), Fault> {
    match leaf.leaf_node_source() {
        LeafNodeSource::KeyPackage(l) if is_constant_lifetime(l) => Ok(()),
        LeafNodeSource::KeyPackage(_) => Err(Fault::Lifetime),
        _ => Err(Fault::Source),
    }
}

/// A parsed, verified, canonical KeyPackage.
#[derive(Clone, Debug)]
pub struct CanonicalKeyPackage {
    pub key_package: KeyPackage,
    pub bytes: Vec<u8>,
    pub kp_ref: Vec<u8>,
    pub pseudonym: [u8; 32],
    pub box_pk: [u8; 32],
    pub bind: KpBind,
}

/// The canonical checks of a KeyPackage that OpenMLS already parsed and verified (an Add of a
/// received commit, or one built here): lifetime, capabilities, leaf, extensions, binding.
pub fn check_key_package(kp: &KeyPackage) -> Result<(LeafFacts, KpBind), Fault> {
    if kp.ciphersuite() != SUITE {
        return Err(Fault::Suite);
    }
    if !is_constant_lifetime(kp.life_time()) {
        return Err(Fault::Lifetime);
    }
    check_key_package_source(kp.leaf_node())?;
    let facts = check_leaf(kp.leaf_node())?;
    if facts.leaf.refresh_epoch != 0 {
        return Err(Fault::RefreshEpoch);
    }
    // Valid X25519 keys: the leaf's encryption key in `check_leaf`, the init key here (H1).
    if !valid_hpke_key(kp.hpke_init_key().as_slice()) {
        return Err(Fault::HpkeKey);
    }
    let exts: Vec<&Extension> = kp.extensions().iter().collect();
    let [Extension::Unknown(ext::EXT_KP_BIND, UnknownExtension(bytes))] = exts.as_slice() else {
        return Err(Fault::KpExtensions);
    };
    let bind = KpBind::decode(bytes).ok_or(Fault::KpExtensions)?;
    Ok((facts, bind))
}

/// Parses the 395-byte `MlsMessage` of a join request (§5.6) or a commit request, verifies it with
/// OpenMLS (`KeyPackageIn::validate`: signatures, and the lifetime against the device clock, which
/// the constant lifetime always passes) and checks the canonical form. `channel_id` and `purpose`,
/// when given, must be the binding's.
pub fn parse_key_package(
    crypto: &impl OpenMlsCrypto,
    bytes: &[u8],
    channel_id: Option<&[u8; 32]>,
) -> Result<CanonicalKeyPackage, Fault> {
    if bytes.len() != KEY_PACKAGE_LEN {
        return Err(Fault::Size);
    }
    let m = MlsMessageIn::tls_deserialize_exact(bytes).map_err(|_| Fault::Parse)?;
    let kp_in = match m.extract() {
        MlsMessageBodyIn::KeyPackage(k) => k,
        _ => return Err(Fault::Parse),
    };
    let kp = kp_in
        .validate(crypto, ProtocolVersion::Mls10)
        .map_err(|_| Fault::Signature)?;
    let (facts, bind) = check_key_package(&kp)?;
    if let Some(ch) = channel_id {
        if &bind.channel_id != ch {
            return Err(Fault::Binding);
        }
    }
    // One encoding: re-serialised, the KeyPackage is the input.
    let again = MlsMessageOut::from(kp.clone())
        .tls_serialize_detached()
        .map_err(|_| Fault::Parse)?;
    if again != bytes {
        return Err(Fault::Parse);
    }
    let kp_ref = kp
        .hash_ref(crypto)
        .map_err(|_| Fault::Parse)?
        .as_slice()
        .to_vec();
    Ok(CanonicalKeyPackage {
        key_package: kp,
        bytes: bytes.to_vec(),
        kp_ref,
        pseudonym: facts.signature_key,
        box_pk: facts.leaf.box_pk,
        bind,
    })
}

impl From<Fault> for MlsError {
    fn from(_: Fault) -> Self {
        MlsError::new(Code::InvalidKeyPackage)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn box_keys_refuse_low_order_and_non_canonical_points() {
        assert!(valid_box_pk(&box_public(&[7; 32])));
        // The 8-torsion u-coordinates (0, 1, p − 1 and the two points of order 8), p and p + 1.
        let mut p = [0xffu8; 32];
        p[0] = 0xed;
        p[31] = 0x7f;
        let mut p_minus_1 = p;
        p_minus_1[0] = 0xec;
        let mut p_plus_1 = p;
        p_plus_1[0] = 0xee;
        let mut one = [0u8; 32];
        one[0] = 1;
        for bad in [[0u8; 32], one, p_minus_1, p, p_plus_1] {
            assert!(!valid_box_pk(&bad));
        }
        let order8a = hex_arr("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800");
        let order8b = hex_arr("5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157");
        assert!(!valid_box_pk(&order8a));
        assert!(!valid_box_pk(&order8b));
        // The top bit set on a valid key: non-canonical.
        let mut top = box_public(&[7; 32]);
        top[31] |= 0x80;
        assert!(!valid_box_pk(&top));
    }

    fn hex_arr(s: &str) -> [u8; 32] {
        let v = hex::decode(s).unwrap();
        let mut a = [0u8; 32];
        a.copy_from_slice(&v);
        a
    }
}
