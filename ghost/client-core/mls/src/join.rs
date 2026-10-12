//! Join traffic (design §5.6, §19.3): the `JoinRequest` sealed in mode 0x12 and the `WelcomeBlob`
//! sealed in mode 0x13, with the invite and rejoin signatures.
//!
//! ```text
//! JoinRequest = version(1) = 1 || type(1) ∈ {0x01 join, 0x02 rejoin, 0x03 restore}
//!             || kp_len(u16_be) || key_package (the canonical KeyPackage MlsMessage; kp_len = 395)
//!             || auth
//! auth        = invite_id(16) || invite_sig(64)                                          (join, restore)
//!             | day(u32_be) || last_epoch(u64_be) || last_hash(32) || rejoin_sig(64)       (rejoin)
//! invite_sig  = Ed25519(invite key, "ghost/v1/ch/join" || channel_id || invite_id || SHA-256(key_package))
//! rejoin_sig  = Ed25519(pseudonym key, "ghost/v1/ch/rejoin" || channel_id || u32_be(generation) || u32_be(day)
//!                       || u64_be(last_epoch) || last_hash || SHA-256(key_package))
//! WelcomeBlob = version(1) = 1 || kp_ref_len(u8) || kp_ref || welcome_len(u24_be) || welcome
//! ```

use sha2::{Digest, Sha256};

use crate::codec::{put_u16, put_u24, put_u32, put_u64, Reader};
use crate::result::{Code, MlsError, MlsResult};

/// The canonical KeyPackage's size for suite 0x0003 (S0-4, E-62); any other length is refused.
pub const KEY_PACKAGE_LEN: usize = 395;
pub const JOIN_LABEL: &[u8] = b"ghost/v1/ch/join";
pub const REJOIN_LABEL: &[u8] = b"ghost/v1/ch/rejoin";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestType {
    Join = 1,
    Rejoin = 2,
    Restore = 3,
}

/// One live invite's verification material for `joinVerify` (fn 15, slice S13b): the invite id the
/// invitee signs (`auth.INVITE_ID`, inside the signature) and the invite key the signature is
/// verified under. The request **names** its invite before the signature check: the native side
/// reads `invite_id` from the authenticated body, finds this record, and verifies under exactly
/// this key — the per-key scan of F-S4-3/F-S4-14 is gone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InviteCandidate {
    pub invite_id: [u8; 16],
    pub invite_pk: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JoinAuth {
    /// Join and restore: authorized by an invite.
    Invite {
        invite_id: [u8; 16],
        invite_sig: [u8; 64],
    },
    /// Rejoin: signed by the member's pseudonym key (§19.3).
    Rejoin {
        day: u32,
        last_epoch: u64,
        last_hash: [u8; 32],
        rejoin_sig: [u8; 64],
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JoinRequest {
    pub request_type: RequestType,
    pub key_package: Vec<u8>,
    pub auth: JoinAuth,
}

impl JoinRequest {
    pub fn encode(&self) -> MlsResult<Vec<u8>> {
        let kind_ok = matches!(
            (self.request_type, &self.auth),
            (
                RequestType::Join | RequestType::Restore,
                JoinAuth::Invite { .. }
            ) | (RequestType::Rejoin, JoinAuth::Rejoin { .. })
        );
        if !kind_ok || self.key_package.len() != KEY_PACKAGE_LEN {
            return Err(MlsError::new(Code::NonCanonical));
        }
        let mut o = Vec::with_capacity(4 + KEY_PACKAGE_LEN + 108);
        o.push(1);
        o.push(self.request_type as u8);
        put_u16(&mut o, KEY_PACKAGE_LEN as u16);
        o.extend_from_slice(&self.key_package);
        match &self.auth {
            JoinAuth::Invite {
                invite_id,
                invite_sig,
            } => {
                o.extend_from_slice(invite_id);
                o.extend_from_slice(invite_sig);
            }
            JoinAuth::Rejoin {
                day,
                last_epoch,
                last_hash,
                rejoin_sig,
            } => {
                put_u32(&mut o, *day);
                put_u64(&mut o, *last_epoch);
                o.extend_from_slice(last_hash);
                o.extend_from_slice(rejoin_sig);
            }
        }
        Ok(o)
    }

    /// Strict decoding: version 1, a known type, `kp_len = 395`, the auth of the type, nothing
    /// after it. The KeyPackage's own form is `canonical::parse_key_package`'s.
    pub fn decode(b: &[u8]) -> MlsResult<Self> {
        let nc = MlsError::new(Code::NonCanonical);
        let mut r = Reader::new(b);
        if r.u8().ok_or(nc)? != 1 {
            return Err(nc);
        }
        let request_type = match r.u8().ok_or(nc)? {
            1 => RequestType::Join,
            2 => RequestType::Rejoin,
            3 => RequestType::Restore,
            _ => return Err(nc),
        };
        let kp_len = usize::from(r.u16().ok_or(nc)?);
        if kp_len != KEY_PACKAGE_LEN {
            return Err(MlsError::new(Code::InvalidKeyPackage));
        }
        let key_package = r.take(kp_len).ok_or(nc)?.to_vec();
        let auth = match request_type {
            RequestType::Join | RequestType::Restore => JoinAuth::Invite {
                invite_id: r.fixed().ok_or(nc)?,
                invite_sig: r.fixed().ok_or(nc)?,
            },
            RequestType::Rejoin => JoinAuth::Rejoin {
                day: r.u32().ok_or(nc)?,
                last_epoch: r.u64().ok_or(nc)?,
                last_hash: r.fixed().ok_or(nc)?,
                rejoin_sig: r.fixed().ok_or(nc)?,
            },
        };
        if !r.done() {
            return Err(nc);
        }
        Ok(Self {
            request_type,
            key_package,
            auth,
        })
    }
}

/// The message `invite_sig` signs.
pub fn invite_sig_message(
    channel_id: &[u8; 32],
    invite_id: &[u8; 16],
    key_package: &[u8],
) -> Vec<u8> {
    let mut m = JOIN_LABEL.to_vec();
    m.extend_from_slice(channel_id);
    m.extend_from_slice(invite_id);
    m.extend_from_slice(&Sha256::digest(key_package));
    m
}

/// The message `rejoin_sig` signs (`generation`: of the namespace the request is sealed into).
pub fn rejoin_sig_message(
    channel_id: &[u8; 32],
    generation: u32,
    day: u32,
    last_epoch: u64,
    last_hash: &[u8; 32],
    key_package: &[u8],
) -> Vec<u8> {
    let mut m = REJOIN_LABEL.to_vec();
    m.extend_from_slice(channel_id);
    m.extend_from_slice(&generation.to_be_bytes());
    m.extend_from_slice(&day.to_be_bytes());
    m.extend_from_slice(&last_epoch.to_be_bytes());
    m.extend_from_slice(last_hash);
    m.extend_from_slice(&Sha256::digest(key_package));
    m
}

/// `WelcomeBlob` (§5.6; the bootstrap travels only in the Welcome's GroupInfo, S0-9).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WelcomeBlob {
    pub kp_ref: Vec<u8>,
    pub welcome: Vec<u8>,
}

impl WelcomeBlob {
    pub fn encode(&self) -> MlsResult<Vec<u8>> {
        let kp_ref_len =
            u8::try_from(self.kp_ref.len()).map_err(|_| MlsError::new(Code::NonCanonical))?;
        if self.kp_ref.is_empty() || self.welcome.len() >= 1 << 24 || self.welcome.is_empty() {
            return Err(MlsError::new(Code::NonCanonical));
        }
        let mut o = Vec::with_capacity(5 + self.kp_ref.len() + self.welcome.len());
        o.push(1);
        o.push(kp_ref_len);
        o.extend_from_slice(&self.kp_ref);
        put_u24(&mut o, self.welcome.len() as u32);
        o.extend_from_slice(&self.welcome);
        Ok(o)
    }

    pub fn decode(b: &[u8]) -> MlsResult<Self> {
        let nc = MlsError::new(Code::NonCanonical);
        let mut r = Reader::new(b);
        if r.u8().ok_or(nc)? != 1 {
            return Err(nc);
        }
        let n = usize::from(r.u8().ok_or(nc)?);
        if n == 0 {
            return Err(nc);
        }
        let kp_ref = r.take(n).ok_or(nc)?.to_vec();
        let w = r.u24().ok_or(nc)? as usize;
        if w == 0 {
            return Err(nc);
        }
        let welcome = r.take(w).ok_or(nc)?.to_vec();
        if !r.done() {
            return Err(nc);
        }
        Ok(Self { kp_ref, welcome })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn join_requests_round_trip_strictly() {
        let join = JoinRequest {
            request_type: RequestType::Join,
            key_package: vec![7; KEY_PACKAGE_LEN],
            auth: JoinAuth::Invite {
                invite_id: [1; 16],
                invite_sig: [2; 64],
            },
        };
        let e = join.encode().unwrap();
        assert_eq!(e.len(), 4 + 395 + 80);
        assert_eq!(JoinRequest::decode(&e).unwrap(), join);
        let rejoin = JoinRequest {
            request_type: RequestType::Rejoin,
            key_package: vec![7; KEY_PACKAGE_LEN],
            auth: JoinAuth::Rejoin {
                day: 20_700,
                last_epoch: 9,
                last_hash: [3; 32],
                rejoin_sig: [4; 64],
            },
        };
        let e2 = rejoin.encode().unwrap();
        assert_eq!(e2.len(), 4 + 395 + 108);
        assert_eq!(JoinRequest::decode(&e2).unwrap(), rejoin);
        // A mismatched type and auth, a KeyPackage of another length, trailing bytes, types.
        let mixed = JoinRequest {
            request_type: RequestType::Rejoin,
            ..join.clone()
        };
        assert!(mixed.encode().is_err());
        let mut long = e.clone();
        long.push(0);
        assert_eq!(
            JoinRequest::decode(&long),
            Err(MlsError::new(Code::NonCanonical))
        );
        let mut kp = e.clone();
        kp[3] = 0x8c; // kp_len 396
        assert_eq!(
            JoinRequest::decode(&kp),
            Err(MlsError::new(Code::InvalidKeyPackage))
        );
        for t in [0u8, 4] {
            let mut b = e.clone();
            b[1] = t;
            assert!(JoinRequest::decode(&b).is_err());
        }
    }

    #[test]
    fn welcome_blobs_round_trip_strictly() {
        let w = WelcomeBlob {
            kp_ref: vec![1; 32],
            welcome: vec![2; 9000],
        };
        let e = w.encode().unwrap();
        assert_eq!(WelcomeBlob::decode(&e).unwrap(), w);
        assert!(WelcomeBlob::decode(&e[..e.len() - 1]).is_err());
        let mut t = e.clone();
        t.push(9);
        assert!(WelcomeBlob::decode(&t).is_err());
    }
}
