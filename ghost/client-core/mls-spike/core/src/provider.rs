//! The provider composition of design §3.3: libcrux's `CryptoProvider` for crypto and randomness,
//! `GhostKv` for storage, and the pseudonym signer (ed25519-dalek over the 32-byte seed).

use ed25519_dalek::{Signer as _, SigningKey};
use openmls_libcrux_crypto::CryptoProvider;
use openmls_traits::signatures::{Signer, SignerError};
use openmls_traits::types::SignatureScheme;
use openmls_traits::OpenMlsProvider;

use crate::kv::GhostKv;

/// `GhostProvider { crypto: CryptoProvider, storage: GhostKv }`. The crypto provider lives as long
/// as the member's context (`ctxOpen`); the adapter lives for one call.
pub struct GhostProvider<'a> {
    pub crypto: &'a CryptoProvider,
    pub storage: GhostKv,
}

impl<'a> OpenMlsProvider for GhostProvider<'a> {
    type CryptoProvider = CryptoProvider;
    type RandProvider = CryptoProvider;
    type StorageProvider = GhostKv;

    fn storage(&self) -> &GhostKv {
        &self.storage
    }
    fn crypto(&self) -> &CryptoProvider {
        self.crypto
    }
    fn rand(&self) -> &CryptoProvider {
        self.crypto
    }
}

/// `PseudonymSigner`: Ed25519 (RFC 8032) over the pseudonym seed; the public key is the leaf's
/// signature key and the `BasicCredential` identity (D12).
pub struct PseudonymSigner {
    key: SigningKey,
    /// Test hook (V10-11 ordering probe): when non-zero, the n-th signature from now is returned
    /// with one byte flipped (1 = the next one).
    pub corrupt_nth: std::cell::Cell<u32>,
}

impl PseudonymSigner {
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            key: SigningKey::from_bytes(seed),
            corrupt_nth: std::cell::Cell::new(0),
        }
    }

    pub fn public(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }
}

impl Signer for PseudonymSigner {
    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, SignerError> {
        let mut s = self.key.sign(payload).to_bytes().to_vec();
        match self.corrupt_nth.get() {
            0 => {}
            1 => {
                self.corrupt_nth.set(0);
                s[0] ^= 1;
            }
            n => self.corrupt_nth.set(n - 1),
        }
        Ok(s)
    }

    fn signature_scheme(&self) -> SignatureScheme {
        SignatureScheme::ED25519
    }
}
