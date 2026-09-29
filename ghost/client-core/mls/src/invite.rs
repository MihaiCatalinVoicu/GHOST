//! Channel invites: the body fields of design §5.9 sealed as `ChannelInviteV2` (§19.28.3 as
//! corrected by §19.29.3). Every invite, open or password-sealed, is 335 bytes.
//!
//! ```text
//! header = version(1) = 0x02 || kdf_code(1) || salt(16)                                    18 bytes, in clear
//! sealed = ChaCha20-Poly1305(k, nonce = 0^12, AD, inner)                                  301 + 16 bytes
//! inner  = suite(u16) || size_class(1) || handshake_ttl_code(1) || channel_id(32) || generation(u32)
//!          || ns(32) || read_base(32) || deposit_base(32) || join_key(32) || invite_id(16)
//!          || invite_seed(32) || committers_digest(32) || expiry_day(u32) || name_len(1) || name(0..48),
//!          zero-padded to 301
//! AD     = "ghost/v1/ch/invite-v2" || header
//! k      = HKDF-SHA256(ikm, salt = salt, info = "ghost/v1/ch/invite-seal" || kdf_code, L = 32)
//! ikm    = Argon2id(NFKD(password), salt, profile(kdf_code), T = 32)   kdf_code >= 1
//!        = salt                                                         kdf_code = 0 (OpenInviteSalt)
//! link   = "ghost://channel/" || base32(header || sealed), lowercase, unpadded     16 + 536 characters
//! ```
//!
//! `handshake_ttl_code` is named by §5.9 without a code table; S2a encodes the channel's
//! `timer_code` at issue (0 … 5), from which §5.8's handshake TTL follows (§19.30).

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use zeroize::Zeroizing;

use crate::codec::{base32_lower, base32_lower_decode, put_u16, put_u32, Reader};
use crate::derive::{
    argon2id_profile, derive_invite_password_key, derive_invite_seal_key,
    derive_open_invite_seal_key, DepositBase, InvitePassword, InviteSeed, JoinKey, OpenInviteSalt,
    ReadBase, SealKey,
};
use crate::result::{Code, MlsError, MlsResult};

pub const INNER_LEN: usize = 301;
pub const HEADER_LEN: usize = 18;
pub const LINK_LEN: usize = HEADER_LEN + INNER_LEN + 16;
pub const FIELDS_MIN_LEN: usize = 253;
pub const AD_LABEL: &[u8] = b"ghost/v1/ch/invite-v2";
pub const LINK_PREFIX: &str = "ghost://channel/";
/// The only suite of P0 (D3).
pub const SUITE: u16 = 0x0003;
/// The domain of `sponsor_sig` (§5.5 TLV 0x0013, §19.2).
pub const SPONSOR_SIG_LABEL: &[u8] = b"ghost/v1/ch/invite";

/// The invite's fields (§5.9), what the sealed body carries.
#[derive(Clone, PartialEq, Eq)]
pub struct InviteFields {
    pub suite: u16,
    pub size_class: u8,
    pub handshake_ttl_code: u8,
    pub channel_id: [u8; 32],
    pub generation: u32,
    pub ns: [u8; 32],
    pub read_base: ReadBase,
    pub deposit_base: DepositBase,
    pub join_key: JoinKey,
    pub invite_id: [u8; 16],
    pub invite_seed: InviteSeed,
    pub committers_digest: [u8; 32],
    pub expiry_day: u32,
    pub name: Vec<u8>,
}

impl core::fmt::Debug for InviteFields {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("InviteFields")
            .field("generation", &self.generation)
            .field("expiry_day", &self.expiry_day)
            .finish_non_exhaustive()
    }
}

impl InviteFields {
    pub(crate) fn encode(&self) -> MlsResult<Zeroizing<Vec<u8>>> {
        if self.name.len() > 48 || self.size_class > 1 || self.handshake_ttl_code > 5 {
            return Err(MlsError::new(Code::NonCanonical));
        }
        let mut o = Zeroizing::new(Vec::with_capacity(INNER_LEN));
        put_u16(&mut o, self.suite);
        o.push(self.size_class);
        o.push(self.handshake_ttl_code);
        o.extend_from_slice(&self.channel_id);
        put_u32(&mut o, self.generation);
        o.extend_from_slice(&self.ns);
        o.extend_from_slice(self.read_base.as_bytes());
        o.extend_from_slice(self.deposit_base.as_bytes());
        o.extend_from_slice(self.join_key.as_bytes());
        o.extend_from_slice(&self.invite_id);
        o.extend_from_slice(self.invite_seed.as_bytes());
        o.extend_from_slice(&self.committers_digest);
        put_u32(&mut o, self.expiry_day);
        o.push(self.name.len() as u8);
        o.extend_from_slice(&self.name);
        debug_assert_eq!(o.len(), FIELDS_MIN_LEN + self.name.len());
        o.resize(INNER_LEN, 0);
        Ok(o)
    }

    pub(crate) fn decode(inner: &[u8]) -> MlsResult<Self> {
        let nc = MlsError::new(Code::NonCanonical);
        if inner.len() != INNER_LEN {
            return Err(nc);
        }
        let mut r = Reader::new(inner);
        let suite = r.u16().ok_or(nc)?;
        if suite != SUITE {
            return Err(MlsError::new(Code::UnsupportedSuite));
        }
        let size_class = r.u8().ok_or(nc)?;
        let handshake_ttl_code = r.u8().ok_or(nc)?;
        if size_class > 1 || handshake_ttl_code > 5 {
            return Err(nc);
        }
        let channel_id = r.fixed::<32>().ok_or(nc)?;
        let generation = r.u32().ok_or(nc)?;
        let ns = r.fixed::<32>().ok_or(nc)?;
        let read_base = ReadBase::from_bytes(r.fixed::<32>().ok_or(nc)?);
        let deposit_base = DepositBase::from_bytes(r.fixed::<32>().ok_or(nc)?);
        let join_key = JoinKey::from_bytes(r.fixed::<32>().ok_or(nc)?);
        let invite_id = r.fixed::<16>().ok_or(nc)?;
        let invite_seed = InviteSeed::from_bytes(r.fixed::<32>().ok_or(nc)?);
        let committers_digest = r.fixed::<32>().ok_or(nc)?;
        let expiry_day = r.u32().ok_or(nc)?;
        let name_len = usize::from(r.u8().ok_or(nc)?);
        if name_len > 48 {
            return Err(nc);
        }
        let name = r.take(name_len).ok_or(nc)?.to_vec();
        if core::str::from_utf8(&name).is_err() || r.rest().iter().any(|&b| b != 0) {
            return Err(nc);
        }
        Ok(Self {
            suite,
            size_class,
            handshake_ttl_code,
            channel_id,
            generation,
            ns,
            read_base,
            deposit_base,
            join_key,
            invite_id,
            invite_seed,
            committers_digest,
            expiry_day,
            name,
        })
    }

    /// The invite key's public half (`invite_pk`, §5.2).
    pub fn invite_pk(&self) -> [u8; 32] {
        crate::derive::derive_invite_signing_key(&self.invite_seed)
            .verifying_key()
            .to_bytes()
    }
}

fn header(kdf_code: u8, salt: &[u8; 16]) -> [u8; HEADER_LEN] {
    let mut h = [0u8; HEADER_LEN];
    h[0] = 2;
    h[1] = kdf_code;
    h[2..].copy_from_slice(salt);
    h
}

fn ad(header: &[u8]) -> Vec<u8> {
    let mut a = AD_LABEL.to_vec();
    a.extend_from_slice(header);
    a
}

fn seal_key(
    kdf_code: u8,
    password: Option<&InvitePassword>,
    salt: &[u8; 16],
) -> MlsResult<SealKey> {
    match (kdf_code, password) {
        (0, _) => Ok(derive_open_invite_seal_key(&OpenInviteSalt::from_bytes(
            *salt,
        ))),
        (c, Some(pw)) if argon2id_profile(c).is_some() => {
            let ikm = derive_invite_password_key(pw, salt, c)?;
            Ok(derive_invite_seal_key(&ikm, salt, c))
        }
        (c, None) if argon2id_profile(c).is_some() => Err(MlsError::new(Code::PasswordRequired)),
        _ => Err(MlsError::new(Code::NonCanonical)),
    }
}

/// Seals `fields` as a `ChannelInviteV2` (§19.28.3). `kdf_code` 0 is an open invite (no
/// password); 1 is a password invite (`PASSWORD_REQUIRED` without one). `salt` comes from the
/// provider's CSPRNG.
pub fn build_v2(
    fields: &InviteFields,
    kdf_code: u8,
    password: Option<&InvitePassword>,
    salt: [u8; 16],
) -> MlsResult<Vec<u8>> {
    if kdf_code == 0 && password.is_some() {
        return Err(MlsError::new(Code::InvalidPolicy));
    }
    let inner = fields.encode()?;
    let h = header(kdf_code, &salt);
    let k = seal_key(kdf_code, password, &salt)?;
    let ct = ChaCha20Poly1305::new(k.as_bytes().into())
        .encrypt(
            &Nonce::from([0u8; 12]),
            Payload {
                msg: &inner,
                aad: &ad(&h),
            },
        )
        .map_err(|_| MlsError::new(Code::Internal))?;
    let mut link = h.to_vec();
    link.extend_from_slice(&ct);
    debug_assert_eq!(link.len(), LINK_LEN);
    Ok(link)
}

/// What a link shows without opening it: its `kdf_code` (whether it needs a password) and salt.
pub fn peek_header(bytes: &[u8]) -> MlsResult<(u8, [u8; 16])> {
    if bytes.len() != LINK_LEN || bytes[0] != 2 {
        return Err(MlsError::new(Code::NonCanonical));
    }
    let kdf_code = bytes[1];
    if kdf_code != 0 && argon2id_profile(kdf_code).is_none() {
        return Err(MlsError::new(Code::NonCanonical));
    }
    let mut salt = [0u8; 16];
    salt.copy_from_slice(&bytes[2..HEADER_LEN]);
    Ok((kdf_code, salt))
}

/// `inviteParse` (§10.2 fn 14): `NON_CANONICAL` (length, version, unknown `kdf_code`, fields),
/// `PASSWORD_REQUIRED` (`kdf_code ≥ 1` without a password), `WRONG_PASSWORD` (the AEAD refused: a
/// wrong password or a tampered link), `UNSUPPORTED_SUITE`. An open link opens from its own salt;
/// a password typed for it is ignored.
pub fn parse_v2(bytes: &[u8], password: Option<&InvitePassword>) -> MlsResult<(u8, InviteFields)> {
    let (kdf_code, salt) = peek_header(bytes)?;
    let pw = if kdf_code == 0 { None } else { password };
    let k = seal_key(kdf_code, pw, &salt)?;
    let inner = Zeroizing::new(
        ChaCha20Poly1305::new(k.as_bytes().into())
            .decrypt(
                &Nonce::from([0u8; 12]),
                Payload {
                    msg: &bytes[HEADER_LEN..],
                    aad: &ad(&bytes[..HEADER_LEN]),
                },
            )
            .map_err(|_| MlsError::new(Code::WrongPassword))?,
    );
    Ok((kdf_code, InviteFields::decode(&inner)?))
}

/// `ghost://channel/` ‖ base32(bytes), lowercase, unpadded.
pub fn to_link(bytes: &[u8]) -> String {
    format!("{LINK_PREFIX}{}", base32_lower(bytes))
}

pub fn from_link(link: &str) -> MlsResult<Vec<u8>> {
    link.strip_prefix(LINK_PREFIX)
        .and_then(base32_lower_decode)
        .filter(|b| b.len() == LINK_LEN)
        .ok_or(MlsError::new(Code::NonCanonical))
}

/// `sponsor_sig` (§5.5 TLV 0x0013): the sponsor's pseudonym signature over
/// `"ghost/v1/ch/invite" ‖ channel_id ‖ invite_id ‖ invite_pk ‖ u32(expiry_day)`.
pub fn sponsor_message(
    channel_id: &[u8; 32],
    invite_id: &[u8; 16],
    invite_pk: &[u8; 32],
    expiry_day: u32,
) -> Vec<u8> {
    let mut m = SPONSOR_SIG_LABEL.to_vec();
    m.extend_from_slice(channel_id);
    m.extend_from_slice(invite_id);
    m.extend_from_slice(invite_pk);
    m.extend_from_slice(&expiry_day.to_be_bytes());
    m
}

pub fn sign_sponsor(key: &SigningKey, message: &[u8]) -> [u8; 64] {
    key.sign(message).to_bytes()
}

/// Strict Ed25519 verification (RFC 8032 with the small-order and malleability checks of
/// `verify_strict`); a key that does not decompress is a failed verification.
pub fn verify_ed25519(public: &[u8; 32], message: &[u8], sig: &[u8; 64]) -> bool {
    VerifyingKey::from_bytes(public)
        .map(|k| {
            k.verify_strict(message, &Signature::from_bytes(sig))
                .is_ok()
        })
        .unwrap_or(false)
}

/// Non-strict verification is never used; `Verifier` is imported for the trait bound only.
#[allow(dead_code)]
fn _verifier_bound(k: &VerifyingKey, m: &[u8], s: &Signature) -> bool {
    k.verify(m, s).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fields(name_len: usize) -> InviteFields {
        InviteFields {
            suite: SUITE,
            size_class: 0,
            handshake_ttl_code: 4,
            channel_id: [1; 32],
            generation: 3,
            ns: [2; 32],
            read_base: ReadBase::from_bytes([3; 32]),
            deposit_base: DepositBase::from_bytes([4; 32]),
            join_key: JoinKey::from_bytes([5; 32]),
            invite_id: [6; 16],
            invite_seed: InviteSeed::from_bytes([7; 32]),
            committers_digest: [8; 32],
            expiry_day: 20_730,
            name: vec![b'n'; name_len],
        }
    }

    #[test]
    fn open_invites_are_335_bytes_and_open_from_their_salt() {
        for n in [0, 48] {
            let link = build_v2(&fields(n), 0, None, [9; 16]).unwrap();
            assert_eq!(link.len(), 335);
            let (code, f) = parse_v2(&link, None).unwrap();
            assert_eq!((code, f), (0, fields(n)));
            // A password typed for an open link is ignored (§19.28.4 step 3).
            let pw = InvitePassword::from_bytes(b"typed".to_vec());
            assert_eq!(parse_v2(&link, Some(&pw)).unwrap().1, fields(n));
            let s = to_link(&link);
            assert_eq!(s.len(), 16 + 536);
            assert_eq!(from_link(&s).unwrap(), link);
        }
    }

    #[test]
    fn open_invite_refusals() {
        let link = build_v2(&fields(0), 0, None, [9; 16]).unwrap();
        let mut flip = link.clone();
        flip[40] ^= 1;
        assert_eq!(
            parse_v2(&flip, None),
            Err(MlsError::new(Code::WrongPassword))
        );
        let mut version = link.clone();
        version[0] = 1;
        assert_eq!(
            parse_v2(&version, None),
            Err(MlsError::new(Code::NonCanonical))
        );
        let mut kdf = link.clone();
        kdf[1] = 2;
        assert_eq!(parse_v2(&kdf, None), Err(MlsError::new(Code::NonCanonical)));
        // An open link turned into a "password" one: password required, then the AEAD refuses.
        let mut up = link.clone();
        up[1] = 1;
        assert_eq!(
            parse_v2(&up, None),
            Err(MlsError::new(Code::PasswordRequired))
        );
        assert!(parse_v2(&link[..334], None).is_err());
        let mut suite = fields(0);
        suite.suite = 1;
        let other = build_v2(&suite, 0, None, [9; 16]).unwrap();
        assert_eq!(
            parse_v2(&other, None),
            Err(MlsError::new(Code::UnsupportedSuite))
        );
        assert!(build_v2(&fields(49), 0, None, [9; 16]).is_err());
        let pw = InvitePassword::from_bytes(b"pw".to_vec());
        assert_eq!(
            build_v2(&fields(0), 0, Some(&pw), [9; 16]),
            Err(MlsError::new(Code::InvalidPolicy))
        );
    }

    #[test]
    fn sponsor_signatures_verify_strictly() {
        let k = SigningKey::from_bytes(&[3; 32]);
        let m = sponsor_message(&[1; 32], &[2; 16], &[4; 32], 20_000);
        let s = sign_sponsor(&k, &m);
        assert!(verify_ed25519(&k.verifying_key().to_bytes(), &m, &s));
        let mut bad = s;
        bad[0] ^= 1;
        assert!(!verify_ed25519(&k.verifying_key().to_bytes(), &m, &bad));
        assert!(!verify_ed25519(&[0; 32], &m, &s));
    }
}
