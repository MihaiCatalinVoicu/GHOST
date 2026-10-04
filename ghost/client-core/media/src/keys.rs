//! Keys and derivations (design §3.2, X-M3): `K_p`, `K_m` and the key commitment from the file key
//! `K_f` and the object identifier, and `op_id` (§6.4).
//!
//! `K_f` and `object_id` are **inputs**: the crate draws no randomness (§13.1). The S2 native
//! surface draws both from the OS CSPRNG per object and per destination, and no key is ever derived
//! from content (§3.2 "Per destination").

use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::labels;

/// The length of `K_f` and of every derived key.
pub const KEY_BYTES: usize = 32;
/// The length of `object_id`.
pub const OBJECT_ID_BYTES: usize = 16;
/// The ordinal of the manifest blob in `op_id` and in the store (§6.3 step 3).
pub const MANIFEST_ORDINAL: i16 = -1;

macro_rules! secret_key {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, Zeroize, ZeroizeOnDrop)]
        pub struct $name([u8; KEY_BYTES]);

        impl $name {
            /// Wraps 32 raw bytes as this key kind.
            pub fn from_bytes(bytes: [u8; KEY_BYTES]) -> Self {
                Self(bytes)
            }

            /// The raw bytes, for the one primitive that consumes this key kind.
            pub fn as_bytes(&self) -> &[u8; KEY_BYTES] {
                &self.0
            }
        }

        impl core::fmt::Debug for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                // A key never renders: a Debug of a key would put it in a panic payload.
                f.write_str(concat!(stringify!($name), "(..)"))
            }
        }
    };
}

secret_key!(
    /// `K_f`, the file key: 32 random bytes per object and per destination, never derived and never
    /// reused (§3.2). Its only durable form is `key_env` (§4.2, slice S2).
    FileKey
);
secret_key!(
    /// `K_p`, the payload key every chunk of one object is sealed under (§3.3).
    PayloadKey
);
secret_key!(
    /// `K_m`, the key the one manifest of one object is sealed under (§3.5).
    ManifestKey
);

/// `object_id`: 16 random bytes per object and per destination, the spec's "random file
/// identifier" and the file nonce of §7.4 step 3 (it salts the derivations, X-M3).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ObjectId([u8; OBJECT_ID_BYTES]);

impl ObjectId {
    /// Wraps 16 bytes.
    pub fn from_bytes(bytes: [u8; OBJECT_ID_BYTES]) -> Self {
        ObjectId(bytes)
    }

    /// The bytes.
    pub fn as_bytes(&self) -> &[u8; OBJECT_ID_BYTES] {
        &self.0
    }
}

impl core::fmt::Debug for ObjectId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ObjectId(")?;
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        f.write_str(")")
    }
}

/// The 32-byte key commitment at the head of every manifest blob (§3.4, §3.5): two keys with one
/// commitment need an HMAC-SHA256 collision.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Commitment([u8; KEY_BYTES]);

impl Commitment {
    /// Wraps 32 bytes.
    pub fn from_bytes(bytes: [u8; KEY_BYTES]) -> Self {
        Commitment(bytes)
    }

    /// The bytes.
    pub fn as_bytes(&self) -> &[u8; KEY_BYTES] {
        &self.0
    }
}

/// The three values one `(K_f, object_id)` derives.
#[derive(Debug)]
pub struct Derived {
    /// `K_p`.
    pub payload: PayloadKey,
    /// `K_m`.
    pub manifest: ManifestKey,
    /// `commit`.
    pub commitment: Commitment,
}

/// `HKDF-SHA256(ikm = K_f, salt = object_id, info = label, L = 32)`.
fn hkdf32(file_key: &FileKey, object_id: &ObjectId, label: &str) -> [u8; KEY_BYTES] {
    let hkdf = Hkdf::<Sha256>::new(Some(object_id.as_bytes()), file_key.as_bytes());
    let mut out = [0u8; KEY_BYTES];
    // Not reachable from any input: L is the constant 32, far inside HKDF-SHA256's 255 × 32-byte
    // output limit, and every input has a fixed size.
    #[allow(clippy::expect_used)]
    hkdf.expand(label.as_bytes(), &mut out)
        .expect("HKDF-SHA256 with L = 32 is inside the 8 160-byte output limit");
    out
}

/// `K_p`, `K_m` and `commit` of one object (§3.2).
pub fn derive(file_key: &FileKey, object_id: &ObjectId) -> Derived {
    let mut payload = hkdf32(file_key, object_id, labels::PAYLOAD);
    let mut manifest = hkdf32(file_key, object_id, labels::MANIFEST);
    let commitment = Commitment(hkdf32(file_key, object_id, labels::COMMIT));
    let derived = Derived {
        payload: PayloadKey::from_bytes(payload),
        manifest: ManifestKey::from_bytes(manifest),
        commitment,
    };
    payload.zeroize();
    manifest.zeroize();
    derived
}

/// `op_id = SHA-256("ghost/v1/media/op" || object_id || i16_be(ordinal) || u8(retry_gen) ||
/// u8(resend_count))[0..16]` (§6.4); the manifest's ordinal is [`MANIFEST_ORDINAL`].
pub fn op_id(object_id: &ObjectId, ordinal: i16, retry_gen: u8, resend_count: u8) -> [u8; 16] {
    let digest: [u8; 32] = Sha256::new()
        .chain_update(labels::OP_ID.as_bytes())
        .chain_update(object_id.as_bytes())
        .chain_update(ordinal.to_be_bytes())
        .chain_update([retry_gen, resend_count])
        .finalize()
        .into();
    let mut out = [0u8; 16];
    for (o, d) in out.iter_mut().zip(digest.iter()) {
        *o = *d;
    }
    out
}

/// SHA-256 of `data`.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derivations_are_separated_by_label_and_salt() {
        let k = FileKey::from_bytes([7; 32]);
        let a = derive(&k, &ObjectId::from_bytes([1; 16]));
        let b = derive(&k, &ObjectId::from_bytes([2; 16]));
        assert_ne!(a.payload.as_bytes(), a.manifest.as_bytes());
        assert_ne!(a.payload.as_bytes(), a.commitment.as_bytes());
        assert_ne!(a.payload.as_bytes(), b.payload.as_bytes());
        assert_ne!(a.commitment, b.commitment);
        assert_eq!(format!("{k:?}"), "FileKey(..)");
    }

    #[test]
    fn rfc5869_case_1_through_the_same_primitive() {
        // RFC 5869 A.1 (salt and info given): checks the HKDF this module calls with values
        // neither GHOST implementation chose.
        let ikm = [0x0b; 22];
        let salt: Vec<u8> = (0x00..=0x0c).collect();
        let info: Vec<u8> = (0xf0..=0xf9).collect();
        let mut okm = [0u8; 42];
        Hkdf::<Sha256>::new(Some(&salt), &ikm)
            .expand(&info, &mut okm)
            .expect("42 bytes");
        assert_eq!(
            hex::encode(okm),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );
    }
}
