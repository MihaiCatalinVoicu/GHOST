//! Relay-local capabilities (FR-5.3, plan Annex B) and the relay-keyed values of redemption
//! (Phase 8 design §10.2, §10.3, ADR-25).
//!
//! A capability is a MAC-authenticated statement, keyed with a secret only this relay holds, in
//! one of two public layouts defined once in [`ghost_relay_api::capability_header`] (clients read
//! the header to bind a token to the namespace of their circuit); this crate adds the MAC:
//!
//! ```text
//! v1 (82 bytes, CLI-minted): 1 || kind(1) || namespace(32) || quota(8, BE) || expiry(8, BE) || mac(32)
//! v2 (98 bytes, redeemed):   2 || kind(1) || namespace(32) || quota(8, BE) || expiry(8, BE) || serial(16) || mac(32)
//! mac = HMAC-SHA256(relay_key, body)
//! ```
//!
//! It names a namespace and a right (read or write), never a user. Because the MAC key is local,
//! a capability is worthless at any other relay, so relays cannot correlate a client across nodes
//! through its capabilities.
//!
//! The same key derives, under their own labels, the 16-byte binding tag a redemption stores next
//! to its nullifier and the deterministic serial of the v2 capability it mints, so an identical
//! retry receives identical bytes, even after a restart, without any capability being stored.
//! Domain separation: a MAC input starts with a version byte (1 or 2); the labels start with 'g'.

use ghost_relay_api::{
    capability_format, capability_header, CapabilityHeader, CAPABILITY_MAC_BYTES,
    CAPABILITY_SERIAL_BYTES, CAPABILITY_TOKEN_BYTES, CAPABILITY_V2_TOKEN_BYTES,
};
use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};

use sha2::{Digest, Sha256};
use std::collections::HashMap;

type HmacSha256 = Hmac<Sha256>;

/// Length of a CLI-minted (v1) capability.
pub const TOKEN_BYTES: usize = CAPABILITY_TOKEN_BYTES;
/// Length of a redeemed (v2) capability.
pub const TOKEN_V2_BYTES: usize = CAPABILITY_V2_TOKEN_BYTES;
/// Length of a redemption binding tag (design §10.4).
pub const BINDING_TAG_BYTES: usize = 16;

/// Label of the binding tag stored with a redemption's nullifier (design §10.2 step 8).
pub const REDEEM_BINDING_LABEL: &[u8] = b"ghost/v1/redeem-binding";
/// Label of the deterministic serial of a redeemed capability (design §10.2 step 10).
pub const CAP_SERIAL_LABEL: &[u8] = b"ghost/v1/cap-serial";

/// Right granted by a capability (the API crate's [`ghost_relay_api::CapabilityKind`]).
pub use ghost_relay_api::CapabilityKind as Kind;

/// The statement a capability makes: its public header, once the MAC has been checked.
pub type Capability = CapabilityHeader;

#[derive(Debug, PartialEq, Eq)]
pub enum CapError {
    Malformed,
    BadMac,
    Expired,
    WrongScope,
    QuotaExceeded,
}

/// The relay's capability-signing secret. Generated at first start and kept on the relay's
/// encrypted disk; rotating it invalidates outstanding capabilities (FR-5.7 key rotation) and
/// changes every binding tag, so a relay whose key changes must also reset its nullifier store
/// (runbook O1).
#[derive(Clone)]
pub struct RelayKey([u8; 32]);

impl RelayKey {
    pub fn generate() -> Self {
        RelayKey(rand::random::<[u8; 32]>())
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        RelayKey(bytes)
    }

    /// Mints a v1 capability (the operator CLI's format).
    pub fn mint(&self, cap: &Capability) -> Vec<u8> {
        self.seal(&cap.encode_body())
    }

    /// Mints a v2 capability with `serial` (the format `RedeemToken` answers with).
    pub fn mint_v2(&self, cap: &Capability, serial: &[u8; CAPABILITY_SERIAL_BYTES]) -> Vec<u8> {
        self.seal(&cap.encode_body_v2(serial))
    }

    fn seal(&self, body: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(body.len() + CAPABILITY_MAC_BYTES);
        out.extend_from_slice(body);
        out.extend_from_slice(&self.hmac(&[body]));
        out
    }

    /// Verifies a token of either layout for `required` on `namespace` at time `now`. Checks run
    /// in this order: length and version, MAC, header fields, expiry, scope.
    pub fn verify(
        &self,
        token: &[u8],
        required: Kind,
        namespace: &[u8; 32],
        now: u64,
    ) -> Result<Capability, CapError> {
        let format = capability_format(token).ok_or(CapError::Malformed)?;
        let (body, mac) = token.split_at(format.body_len());
        let mut verifier =
            HmacSha256::new_from_slice(&self.0).expect("HMAC accepts any key length");
        verifier.update(body);
        verifier.verify_slice(mac).map_err(|_| CapError::BadMac)?;
        let cap = capability_header(token).ok_or(CapError::Malformed)?;
        if cap.expiry_unix <= now {
            return Err(CapError::Expired);
        }
        // A write capability also grants read on the same namespace; read never grants write.
        let scope_ok = cap.namespace == *namespace
            && (cap.kind == required || (cap.kind == Kind::Write && required == Kind::Read));
        if !scope_ok {
            return Err(CapError::WrongScope);
        }
        Ok(cap)
    }

    /// Verifies MAC and expiry only and returns the capability with its own namespace; callers
    /// then compare that namespace against what they are about to reveal (GetBlob, CheckBlobs).
    pub fn verify_any(&self, token: &[u8], now: u64) -> Result<Capability, CapError> {
        let header = capability_header(token).ok_or(CapError::Malformed)?;
        self.verify(token, header.kind, &header.namespace, now)
    }

    /// The binding tag of a redemption: `HMAC-SHA256(relay_key, "ghost/v1/redeem-binding" ||
    /// period(8, BE) || nullifier || kind || namespace)[0..16]`. Stored next to the nullifier, it
    /// tells an identical retry (same tag) from a replay for another namespace or right.
    pub fn redeem_binding(
        &self,
        period: u64,
        nullifier: &[u8; 32],
        kind: Kind,
        namespace: &[u8; 32],
    ) -> [u8; BINDING_TAG_BYTES] {
        let mac = self.hmac(&[
            REDEEM_BINDING_LABEL,
            &period.to_be_bytes(),
            nullifier,
            &[kind as u8],
            namespace,
        ]);
        truncate(&mac)
    }

    /// The serial of the capability minted for a redemption: `HMAC-SHA256(relay_key,
    /// "ghost/v1/cap-serial" || period(8, BE) || nullifier)[0..16]`. One per token, and the same
    /// on every identical retry.
    pub fn capability_serial(
        &self,
        period: u64,
        nullifier: &[u8; 32],
    ) -> [u8; CAPABILITY_SERIAL_BYTES] {
        let mac = self.hmac(&[CAP_SERIAL_LABEL, &period.to_be_bytes(), nullifier]);
        truncate(&mac)
    }

    fn hmac(&self, parts: &[&[u8]]) -> [u8; 32] {
        let mut m = HmacSha256::new_from_slice(&self.0).expect("HMAC accepts any key length");
        for part in parts {
            m.update(part);
        }
        m.finalize().into_bytes().into()
    }
}

fn truncate<const N: usize>(mac: &[u8; 32]) -> [u8; N] {
    let mut out = [0u8; N];
    out.copy_from_slice(&mac[..N]);
    out
}

/// What a relay is allowed to record about a capability: its hash, never the token (threat model
/// §6, `capability_scope`).
pub fn scope_hash(token: &[u8]) -> [u8; 32] {
    let d = Sha256::digest(token);
    let mut out = [0u8; 32];
    out.copy_from_slice(&d);
    out
}

/// Write-quota accounting per capability (keyed by scope hash), bounded by the capability expiry.
/// It stays in memory (design §10.4, RC G4): a writer may exceed its quota once per restart,
/// bounded by the capability's week-aligned expiry (declared in ADR-25).
#[derive(Default)]
pub struct QuotaLedger {
    used: HashMap<[u8; 32], (u64, u64)>, // scope hash -> (used bytes, expiry)
}

impl QuotaLedger {
    /// Charges `bytes` against the capability; fails without charging if the quota would be exceeded.
    pub fn charge(&mut self, token: &[u8], cap: &Capability, bytes: u64) -> Result<(), CapError> {
        let key = scope_hash(token);
        let entry = self.used.entry(key).or_insert((0, cap.expiry_unix));
        if entry.0.saturating_add(bytes) > cap.quota_bytes {
            return Err(CapError::QuotaExceeded);
        }
        entry.0 += bytes;
        Ok(())
    }

    /// Returns `bytes` previously charged to the capability, for a write that did not commit.
    pub fn refund(&mut self, token: &[u8], bytes: u64) {
        if let Some(entry) = self.used.get_mut(&scope_hash(token)) {
            entry.0 = entry.0.saturating_sub(bytes);
        }
    }

    /// Forgets ledgers of expired capabilities (bounded memory, §11.2).
    pub fn prune(&mut self, now: u64) -> usize {
        let before = self.used.len();
        self.used.retain(|_, (_, expiry)| *expiry > now);
        before - self.used.len()
    }

    pub fn len(&self) -> usize {
        self.used.len()
    }

    pub fn is_empty(&self) -> bool {
        self.used.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ns(b: u8) -> [u8; 32] {
        [b; 32]
    }

    #[test]
    fn mint_verify_round_trip_and_scope_rules() {
        let key = RelayKey::generate();
        let cap = Capability {
            kind: Kind::Write,
            namespace: ns(1),
            quota_bytes: 1_000,
            expiry_unix: 2_000,
        };
        let token = key.mint(&cap);
        assert_eq!(token.len(), TOKEN_BYTES);
        // The public header of a minted token is exactly what was minted (one layout, two users).
        assert_eq!(capability_header(&token), Some(cap.clone()));
        assert_eq!(key.verify(&token, Kind::Write, &ns(1), 1_000).unwrap(), cap);
        assert_eq!(key.verify_any(&token, 1_000).unwrap(), cap);
        // write grants read on the same namespace
        assert!(key.verify(&token, Kind::Read, &ns(1), 1_000).is_ok());
        assert_eq!(
            key.verify(&token, Kind::Write, &ns(2), 1_000),
            Err(CapError::WrongScope)
        );
        assert_eq!(
            key.verify(&token, Kind::Write, &ns(1), 2_000),
            Err(CapError::Expired)
        );
        let read = key.mint(&Capability {
            kind: Kind::Read,
            namespace: ns(1),
            quota_bytes: 0,
            expiry_unix: 2_000,
        });
        assert_eq!(
            key.verify(&read, Kind::Write, &ns(1), 1_000),
            Err(CapError::WrongScope)
        );
    }

    #[test]
    fn v2_capabilities_verify_and_their_serial_is_authenticated() {
        let key = RelayKey::generate();
        let cap = Capability {
            kind: Kind::Write,
            namespace: ns(1),
            quota_bytes: 268_435_456,
            expiry_unix: 2_000,
        };
        let token = key.mint_v2(&cap, &[7; CAPABILITY_SERIAL_BYTES]);
        assert_eq!(token.len(), TOKEN_V2_BYTES);
        assert_eq!(capability_header(&token), Some(cap.clone()));
        assert_eq!(key.verify(&token, Kind::Write, &ns(1), 1_000).unwrap(), cap);
        assert_eq!(key.verify_any(&token, 1_000).unwrap(), cap);
        assert!(key.verify(&token, Kind::Read, &ns(1), 1_000).is_ok());
        // Another serial is another capability (its own quota ledger), with its own MAC.
        let other = key.mint_v2(&cap, &[8; CAPABILITY_SERIAL_BYTES]);
        assert_ne!(scope_hash(&token), scope_hash(&other));
        // Every byte is covered, the serial included; a foreign key fails the MAC.
        for i in 0..token.len() {
            let mut t = token.clone();
            t[i] ^= 1;
            assert!(
                key.verify(&t, Kind::Write, &ns(1), 1_000).is_err(),
                "byte {i}"
            );
        }
        assert_eq!(
            RelayKey::generate().verify(&token, Kind::Write, &ns(1), 1_000),
            Err(CapError::BadMac)
        );
        // A v2 body sealed as if it were v1 (or the reverse) never verifies.
        let mut relabelled = token.clone();
        relabelled[0] = 1;
        assert_eq!(
            key.verify(&relabelled, Kind::Write, &ns(1), 1_000),
            Err(CapError::Malformed)
        );
    }

    #[test]
    fn binding_tags_and_serials_are_keyed_and_separate_their_inputs() {
        let key = RelayKey::from_bytes([3; 32]);
        let n = [9u8; 32];
        let tag = key.redeem_binding(2959, &n, Kind::Write, &ns(1));
        assert_eq!(tag, key.redeem_binding(2959, &n, Kind::Write, &ns(1)));
        for other in [
            key.redeem_binding(2960, &n, Kind::Write, &ns(1)),
            key.redeem_binding(2959, &[8; 32], Kind::Write, &ns(1)),
            key.redeem_binding(2959, &n, Kind::Read, &ns(1)),
            key.redeem_binding(2959, &n, Kind::Write, &ns(2)),
            RelayKey::from_bytes([4; 32]).redeem_binding(2959, &n, Kind::Write, &ns(1)),
        ] {
            assert_ne!(tag, other);
        }
        let serial = key.capability_serial(2959, &n);
        assert_eq!(serial, key.capability_serial(2959, &n));
        assert_ne!(serial, key.capability_serial(2960, &n));
        assert_ne!(serial, key.capability_serial(2959, &[8; 32]));
        assert_ne!(
            serial,
            RelayKey::from_bytes([4; 32]).capability_serial(2959, &n)
        );
        // Independent recomputation of the documented formulas.
        let mut m = HmacSha256::new_from_slice(&[3; 32]).unwrap();
        m.update(b"ghost/v1/cap-serial");
        m.update(&2959u64.to_be_bytes());
        m.update(&n);
        assert_eq!(serial[..], m.finalize().into_bytes()[..16]);
        let mut m = HmacSha256::new_from_slice(&[3; 32]).unwrap();
        m.update(b"ghost/v1/redeem-binding");
        m.update(&2959u64.to_be_bytes());
        m.update(&n);
        m.update(&[2]);
        m.update(&ns(1));
        assert_eq!(tag[..], m.finalize().into_bytes()[..16]);
    }

    #[test]
    fn tamper_and_foreign_key_are_rejected() {
        let key = RelayKey::generate();
        let token = key.mint(&Capability {
            kind: Kind::Write,
            namespace: ns(1),
            quota_bytes: 1,
            expiry_unix: 2_000,
        });
        for i in 0..token.len() {
            let mut t = token.clone();
            t[i] ^= 1;
            assert!(
                key.verify(&t, Kind::Write, &ns(1), 1_000).is_err(),
                "byte {i}"
            );
        }
        assert_eq!(
            RelayKey::generate().verify(&token, Kind::Write, &ns(1), 1_000),
            Err(CapError::BadMac)
        );
        assert_eq!(
            key.verify(&token[..10], Kind::Write, &ns(1), 1_000),
            Err(CapError::Malformed)
        );
    }

    #[test]
    fn quota_ledger_charges_and_prunes() {
        let key = RelayKey::generate();
        let cap = Capability {
            kind: Kind::Write,
            namespace: ns(1),
            quota_bytes: 10_000,
            expiry_unix: 100,
        };
        let token = key.mint(&cap);
        let mut ledger = QuotaLedger::default();
        assert!(ledger.charge(&token, &cap, 6_000).is_ok());
        assert_eq!(
            ledger.charge(&token, &cap, 5_000),
            Err(CapError::QuotaExceeded)
        );
        assert!(ledger.charge(&token, &cap, 4_000).is_ok());
        ledger.refund(&token, 4_000);
        assert!(
            ledger.charge(&token, &cap, 4_000).is_ok(),
            "refund restores the quota"
        );
        ledger.refund(b"unknown token", 1); // no ledger: no-op
        assert_eq!(ledger.prune(50), 0);
        assert_eq!(ledger.prune(100), 1);
        assert!(ledger.is_empty());
    }
}
