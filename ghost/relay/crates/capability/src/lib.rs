//! Relay-local capabilities (FR-5.3, plan Annex B) and per-period nullifiers (ADR-02).
//!
//! A capability is a MAC-authenticated statement, keyed with a secret only this relay holds:
//! `version(1) || kind(1) || namespace(32) || quota_bytes(8) || expiry_unix(8) || mac(32)`.
//! It names a namespace and a right (read or write), never a user. Because the MAC key is local,
//! a capability is worthless at any other relay, so relays cannot correlate a client across nodes
//! through its capabilities.

use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};

use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

type HmacSha256 = Hmac<Sha256>;

pub const TOKEN_BYTES: usize = 1 + 1 + 32 + 8 + 8 + 32;
const VERSION: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Read = 1,
    Write = 2,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capability {
    pub kind: Kind,
    pub namespace: [u8; 32],
    pub quota_bytes: u64,
    pub expiry_unix: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub enum CapError {
    Malformed,
    BadMac,
    Expired,
    WrongScope,
    QuotaExceeded,
}

/// The relay's capability-signing secret. Generated at first start and kept on the relay's
/// encrypted disk; rotating it invalidates outstanding capabilities (FR-5.7 key rotation).
#[derive(Clone)]
pub struct RelayKey([u8; 32]);

impl RelayKey {
    pub fn generate() -> Self {
        RelayKey(rand::random::<[u8; 32]>())
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        RelayKey(bytes)
    }

    pub fn mint(&self, cap: &Capability) -> Vec<u8> {
        let mut out = Vec::with_capacity(TOKEN_BYTES);
        out.push(VERSION);
        out.push(cap.kind as u8);
        out.extend_from_slice(&cap.namespace);
        out.extend_from_slice(&cap.quota_bytes.to_be_bytes());
        out.extend_from_slice(&cap.expiry_unix.to_be_bytes());
        let mac = self.mac(&out);
        out.extend_from_slice(&mac);
        out
    }

    /// Verifies a token for `required` on `namespace` at time `now`.
    pub fn verify(
        &self,
        token: &[u8],
        required: Kind,
        namespace: &[u8; 32],
        now: u64,
    ) -> Result<Capability, CapError> {
        if token.len() != TOKEN_BYTES || token[0] != VERSION {
            return Err(CapError::Malformed);
        }
        let (body, mac) = token.split_at(TOKEN_BYTES - 32);
        let mut verifier =
            HmacSha256::new_from_slice(&self.0).expect("HMAC accepts any key length");
        verifier.update(body);
        verifier.verify_slice(mac).map_err(|_| CapError::BadMac)?;
        let kind = match body[1] {
            1 => Kind::Read,
            2 => Kind::Write,
            _ => return Err(CapError::Malformed),
        };
        let mut ns = [0u8; 32];
        ns.copy_from_slice(&body[2..34]);
        let quota_bytes = u64::from_be_bytes(body[34..42].try_into().unwrap());
        let expiry_unix = u64::from_be_bytes(body[42..50].try_into().unwrap());
        if expiry_unix <= now {
            return Err(CapError::Expired);
        }
        // A write capability also grants read on the same namespace; read never grants write.
        let scope_ok = ns == *namespace
            && (kind == required || (kind == Kind::Write && required == Kind::Read));
        if !scope_ok {
            return Err(CapError::WrongScope);
        }
        Ok(Capability {
            kind,
            namespace: ns,
            quota_bytes,
            expiry_unix,
        })
    }

    /// Verifies MAC and expiry only and returns the capability with its own namespace; callers
    /// then compare that namespace against what they are about to reveal (GetBlob, CheckBlobs).
    pub fn verify_any(&self, token: &[u8], now: u64) -> Result<Capability, CapError> {
        if token.len() != TOKEN_BYTES {
            return Err(CapError::Malformed);
        }
        let mut ns = [0u8; 32];
        ns.copy_from_slice(&token[2..34]);
        let required = match token[1] {
            1 => Kind::Read,
            2 => Kind::Write,
            _ => return Err(CapError::Malformed),
        };
        self.verify(token, required, &ns, now)
    }

    fn mac(&self, body: &[u8]) -> [u8; 32] {
        let mut m = HmacSha256::new_from_slice(&self.0).expect("HMAC accepts any key length");
        m.update(body);
        let out = m.finalize().into_bytes();
        let mut mac = [0u8; 32];
        mac.copy_from_slice(&out);
        mac
    }
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

/// One-time-token nullifiers per validity period (ADR-02). Only the current and previous period
/// are kept, in memory, so the set stays small and nothing outlives the tokens it protects.
#[derive(Default)]
pub struct NullifierSet {
    periods: HashMap<Vec<u8>, HashSet<[u8; 32]>>,
}

impl NullifierSet {
    /// Records the nullifier; returns false if it was already seen in that period (replay).
    pub fn record_if_fresh(&mut self, period_id: &[u8], nullifier: [u8; 32]) -> bool {
        self.periods
            .entry(period_id.to_vec())
            .or_default()
            .insert(nullifier)
    }

    /// Drops every period not in `keep`.
    pub fn retain_periods(&mut self, keep: &[&[u8]]) {
        self.periods.retain(|p, _| keep.contains(&p.as_slice()));
    }

    pub fn len(&self) -> usize {
        self.periods.values().map(HashSet::len).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
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
        assert_eq!(key.verify(&token, Kind::Write, &ns(1), 1_000).unwrap(), cap);
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

    #[test]
    fn nullifiers_detect_replay_per_period() {
        let mut set = NullifierSet::default();
        assert!(set.record_if_fresh(b"p1", [7; 32]));
        assert!(!set.record_if_fresh(b"p1", [7; 32]));
        assert!(set.record_if_fresh(b"p2", [7; 32]));
        set.retain_periods(&[b"p2"]);
        assert_eq!(set.len(), 1);
    }
}
