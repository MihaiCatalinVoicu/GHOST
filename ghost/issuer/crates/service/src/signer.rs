//! The issuer's blind-signing boundary (Phase 8 design §2.7, §2.8). Exactly one `Signer`
//! implementation lives here, the reference signer on blind-rsa-signatures =0.17.2 (rsa
//! 0.10.0-rc.18 hazmat `rsa_decrypt_and_check`: CRT on crypto-bigint's constant-time Montgomery
//! exponentiation, base blinding, re-encryption check). The service never uses a `Signer`
//! directly: `CheckedSigner` recomputes `s'^e mod n` with `num-bigint-dig`, an implementation
//! independent of the signer's, and refuses to release a mismatch (RFC 9474 §4.3 fault check,
//! which also stops Bellcore-style CRT fault attacks).

use std::sync::atomic::{AtomicU64, Ordering};

use blind_rsa_signatures::{Deterministic, KeyPair, SecretKey, Sha384, PSS};
use ghost_blind_rsa::{BigUint, PublicKey};
use ghost_entitlement::token::{self, AUTHENTICATOR_LEN, MODULUS_BITS};
use ghost_entitlement::Kind;

/// A blind signer for one (kind, epoch) key of the Entitlement Schedule.
pub trait Signer: Send + Sync {
    /// (kind, epoch) this signer holds; its public key must equal the ES entry (checked at load).
    fn key(&self) -> (Kind, u64);
    /// Deterministic in (key, blinded). Must fail on 0, n and values >= n.
    fn blind_sign(
        &self,
        blinded: &[u8; AUTHENTICATOR_LEN],
    ) -> Result<[u8; AUTHENTICATOR_LEN], SignError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SignError {
    /// The blinded value is 0 or not below n.
    InvalidInput,
    /// The key is not a valid RSA-2048 key with e = 65537, or does not match its public key.
    Key,
    /// The signing library failed (including its own re-encryption check).
    Internal,
    /// `s'^e != B (mod n)`: the signature is withheld (alarm counter `SIGN_FAULT`).
    Fault,
}

impl std::fmt::Display for SignError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            SignError::InvalidInput => "blinded value out of range",
            SignError::Key => "signing key invalid or mismatched",
            SignError::Internal => "signing failed",
            SignError::Fault => "blind signature failed the fault check",
        })
    }
}

impl std::error::Error for SignError {}

type RefSecretKey = SecretKey<Sha384, PSS, Deterministic>;

/// The default signer: blind-rsa-signatures =0.17.2, RSABSSA-SHA384-PSS-Deterministic.
pub struct ReferenceSigner {
    kind: Kind,
    epoch: u64,
    secret: RefSecretKey,
    public_key: PublicKey,
}

impl ReferenceSigner {
    /// A key from its PKCS #8 (or PKCS #1) DER. The library validates the key and precomputes
    /// the CRT values.
    pub fn from_pkcs8_der(kind: Kind, epoch: u64, der: &[u8]) -> Result<Self, SignError> {
        Self::new(
            kind,
            epoch,
            RefSecretKey::from_der(der).map_err(|_| SignError::Key)?,
        )
    }

    /// A key from its PEM (PKCS #8 or PKCS #1).
    pub fn from_pkcs8_pem(kind: Kind, epoch: u64, pem: &str) -> Result<Self, SignError> {
        Self::new(
            kind,
            epoch,
            RefSecretKey::from_pem(pem).map_err(|_| SignError::Key)?,
        )
    }

    /// A fresh RSA-2048 key from the library's key generation (`crypto-primes`).
    pub fn generate(kind: Kind, epoch: u64) -> Result<Self, SignError> {
        let kp = KeyPair::<Sha384, PSS, Deterministic>::generate(
            &mut blind_rsa_signatures::DefaultRng,
            MODULUS_BITS,
        )
        .map_err(|_| SignError::Key)?;
        Self::new(kind, epoch, kp.sk)
    }

    fn new(kind: Kind, epoch: u64, secret: RefSecretKey) -> Result<Self, SignError> {
        let public = secret.public_key().map_err(|_| SignError::Key)?;
        let c = public.components();
        let public_key = PublicKey::from_components(&c.n(), &c.e()).map_err(|_| SignError::Key)?;
        token::check_key(&public_key).map_err(|_| SignError::Key)?;
        Ok(Self {
            kind,
            epoch,
            secret,
            public_key,
        })
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// The private key as PKCS #8 DER (for the operator tools that seal it).
    pub fn to_pkcs8_der(&self) -> Result<Vec<u8>, SignError> {
        self.secret.to_der().map_err(|_| SignError::Key)
    }
}

impl Signer for ReferenceSigner {
    fn key(&self) -> (Kind, u64) {
        (self.kind, self.epoch)
    }

    fn blind_sign(
        &self,
        blinded: &[u8; AUTHENTICATOR_LEN],
    ) -> Result<[u8; AUTHENTICATOR_LEN], SignError> {
        // The library refuses values >= n but signs 0 (to 0): refuse it here.
        let b = BigUint::from_bytes_be(blinded);
        if b.bits() == 0 || &b >= self.public_key.n() {
            return Err(SignError::InvalidInput);
        }
        let sig = self
            .secret
            .blind_sign(blinded)
            .map_err(|_| SignError::Internal)?;
        sig.0.as_slice().try_into().map_err(|_| SignError::Internal)
    }
}

/// Wraps a `Signer`: input range check, then the independent `s'^e == B` check on every output.
/// A mismatch is counted and never released.
pub struct CheckedSigner<S: Signer> {
    inner: S,
    public_key: PublicKey,
    faults: AtomicU64,
}

impl<S: Signer> CheckedSigner<S> {
    /// `public_key` is the ES entry of `inner.key()`. The pair is proven to match before use: one
    /// checked signature over the key's first permutation-proof challenge (a hash-derived value).
    pub fn new(inner: S, public_key: PublicKey) -> Result<Self, SignError> {
        token::check_key(&public_key).map_err(|_| SignError::Key)?;
        let signer = Self {
            inner,
            public_key,
            faults: AtomicU64::new(0),
        };
        let challenges = ghost_blind_rsa::permutation_proof_challenges(&signer.public_key)
            .map_err(|_| SignError::Key)?;
        match signer.blind_sign(&challenges[0]) {
            Ok(_) => Ok(signer),
            Err(SignError::Fault) => Err(SignError::Key),
            Err(e) => Err(e),
        }
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Signatures withheld by the fault check since construction (alarm counter `SIGN_FAULT`).
    pub fn faults(&self) -> u64 {
        self.faults.load(Ordering::Relaxed)
    }
}

impl<S: Signer> Signer for CheckedSigner<S> {
    fn key(&self) -> (Kind, u64) {
        self.inner.key()
    }

    fn blind_sign(
        &self,
        blinded: &[u8; AUTHENTICATOR_LEN],
    ) -> Result<[u8; AUTHENTICATOR_LEN], SignError> {
        let b = BigUint::from_bytes_be(blinded);
        if b.bits() == 0 || &b >= self.public_key.n() {
            return Err(SignError::InvalidInput);
        }
        let sig = self.inner.blind_sign(blinded)?;
        if !ghost_blind_rsa::check_blind_signature(&self.public_key, blinded, &sig) {
            self.faults.fetch_add(1, Ordering::Relaxed);
            return Err(SignError::Fault);
        }
        Ok(sig)
    }
}
