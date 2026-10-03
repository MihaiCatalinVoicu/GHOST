//! The provider composition of design §3.3: the libcrux provider's `CryptoProvider` for crypto and
//! randomness (an HMAC-DRBG seeded from `SysRng`, which reaches `getrandom`: the process-global
//! seeded stream in host builds, §12.1), `GhostKv` for storage, and the pseudonym signer.
//! `openmls_libcrux_crypto::Provider` (whose storage is the memory provider) is never used, and no
//! GHOST code names `openmls_memory_storage` or `openmls_basic_credential` (gate G-M2).

use ed25519_dalek::{Signer as _, SigningKey};
use openmls_libcrux_crypto::CryptoProvider;
use openmls_traits::signatures::{Signer, SignerError};
use openmls_traits::types::SignatureScheme;
use openmls_traits::OpenMlsProvider;

use crate::derive::PseudonymSeed;
use crate::kv::GhostKv;

/// `GhostProvider { crypto: CryptoProvider, storage: GhostKv }`. The crypto provider lives as long
/// as the member's context (`ctxOpen`); the adapter lives for one call.
pub struct GhostProvider<'a> {
    pub crypto: &'a CryptoProvider,
    pub storage: GhostKv,
}

impl OpenMlsProvider for GhostProvider<'_> {
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

/// `PseudonymSigner` (§3.3): Ed25519 (RFC 8032, the workspace `ed25519-dalek` 2.2.0) over the
/// 32-byte pseudonym seed. Its public key is the leaf's signature key and the `BasicCredential`
/// identity (D12); `:identity` computes the same key with BouncyCastle (ADR-17), and the shared
/// vector in `ch_derive.txt` is replayed by both.
pub struct PseudonymSigner {
    key: SigningKey,
}

impl PseudonymSigner {
    pub fn from_seed(seed: &PseudonymSeed) -> Self {
        Self {
            key: SigningKey::from_bytes(seed.as_bytes()),
        }
    }

    /// The pseudonym key `P`.
    pub fn public(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    /// A GHOST-level signature (`sponsor_sig`, `rejoin_sig`) under the pseudonym key.
    pub fn sign_raw(&self, message: &[u8]) -> [u8; 64] {
        self.key.sign(message).to_bytes()
    }
}

impl Signer for PseudonymSigner {
    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, SignerError> {
        Ok(self.key.sign(payload).to_bytes().to_vec())
    }

    fn signature_scheme(&self) -> SignatureScheme {
        SignatureScheme::ED25519
    }
}
