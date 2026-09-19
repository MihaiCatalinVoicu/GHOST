//! PQ-B key provenance (design §9.3, invariant T35).
//!
//! Every symmetric key that seals relay-stored DM bytes is card-derived, KEM-derived, or a random
//! secret that was transported only under keys of those two kinds. By induction over transport
//! order, a passive adversary that breaks every X25519 instance but not ML-KEM-768 opens no DM
//! envelope, and therefore never sees an Olm header of a session it could attack.
//!
//! The invariant is carried by [`SealKey`]: every seal key is built with the tag of where it came
//! from, and each seal mode accepts only the kinds §9.3 allows. The assertion is compiled into the
//! crate's own tests and into the `provenance` feature (the DM worlds and the mutants PM-32 and
//! PM-33 build with it); production builds carry the tag and skip the check.

use crate::derive::SECRET_BYTES;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// How a card reached this device (§9.3 kind 1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CardSource {
    /// Scanned in person: never on a network.
    InPerson,
    /// Received as a `ghost://contact/` link over another channel, which a future quantum
    /// adversary may have recorded (PQ-R8).
    Link,
    /// Carried inside an X-Wing-keyed intro inner layer (the sender's card, §6.4).
    Transported,
}

/// Where a seal key came from (§9.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyProvenance {
    /// Derived from a contact card.
    Card(CardSource),
    /// Derived from an X-Wing shared secret.
    Kem,
    /// A random secret transported inside an envelope of the named provenance.
    Transported(Box<KeyProvenance>),
}

impl KeyProvenance {
    /// A random secret transported under a key of this provenance.
    pub fn transported_under(self) -> Self {
        KeyProvenance::Transported(Box::new(self))
    }

    /// True when nothing on the path to this key rests on X25519 alone: a KEM secret, or a chain
    /// of transports that ends in one.
    pub fn post_quantum(&self) -> bool {
        match self {
            KeyProvenance::Card(_) => false,
            KeyProvenance::Kem => true,
            KeyProvenance::Transported(inner) => inner.post_quantum(),
        }
    }

    /// The card source this provenance rests on, if any: `Link` is the declared PQ-R8 exception.
    pub fn card_source(&self) -> Option<CardSource> {
        match self {
            KeyProvenance::Card(source) => Some(*source),
            KeyProvenance::Kem => None,
            KeyProvenance::Transported(inner) => inner.card_source(),
        }
    }
}

/// A 32-byte symmetric seal key and the tag T35 checks.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SealKey {
    material: [u8; SECRET_BYTES],
    #[zeroize(skip)]
    provenance: KeyProvenance,
}

impl core::fmt::Debug for SealKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SealKey")
            .field("provenance", &self.provenance)
            .finish_non_exhaustive()
    }
}

impl SealKey {
    /// A seal key with its provenance.
    pub fn new(material: [u8; SECRET_BYTES], provenance: KeyProvenance) -> Self {
        Self {
            material,
            provenance,
        }
    }

    /// The key material, for the one primitive that consumes it.
    pub fn as_bytes(&self) -> &[u8; SECRET_BYTES] {
        &self.material
    }

    /// The tag.
    pub fn provenance(&self) -> &KeyProvenance {
        &self.provenance
    }
}

/// The kinds of key a seal mode accepts (§9.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SealRequirement {
    /// Bundles and the intro outer layer: a card-derived key only.
    Card,
    /// Pair and provisional: a KEM secret, or a secret transported under one.
    PostQuantum,
}

/// The T35 check. `Err` names the provenance that failed, so a mutant reports what it used.
pub fn check(requirement: SealRequirement, provenance: &KeyProvenance) -> Result<(), String> {
    let ok = match requirement {
        SealRequirement::Card => matches!(provenance, KeyProvenance::Card(_)),
        SealRequirement::PostQuantum => provenance.post_quantum(),
    };
    if ok {
        Ok(())
    } else {
        Err(format!("T35: {requirement:?} sealed with {provenance:?}"))
    }
}

/// The T35 assertion the seal modes run. It is a no-op unless the crate is built for tests or with
/// the `provenance` feature.
#[inline]
pub(crate) fn assert_seal(requirement: SealRequirement, key: &SealKey) {
    #[cfg(any(test, feature = "provenance"))]
    if let Err(reason) = check(requirement, key.provenance()) {
        panic!("{reason}");
    }
    #[cfg(not(any(test, feature = "provenance")))]
    {
        let _ = (requirement, key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn card_keys_are_not_post_quantum_and_kem_keys_are() {
        assert!(!KeyProvenance::Card(CardSource::InPerson).post_quantum());
        assert!(KeyProvenance::Kem.post_quantum());
        assert!(KeyProvenance::Kem.transported_under().post_quantum());
        assert!(KeyProvenance::Kem
            .transported_under()
            .transported_under()
            .post_quantum());
        assert!(!KeyProvenance::Card(CardSource::Link)
            .transported_under()
            .post_quantum());
    }

    #[test]
    fn the_seal_requirements_refuse_the_mutants() {
        // PM-32: an intro inner layer keyed without the KEM.
        assert!(check(
            SealRequirement::PostQuantum,
            &KeyProvenance::Card(CardSource::Link)
        )
        .is_err());
        // PM-33: a reply seed or root sent in a classical-only layer.
        assert!(check(
            SealRequirement::PostQuantum,
            &KeyProvenance::Card(CardSource::InPerson).transported_under()
        )
        .is_err());
        assert!(check(SealRequirement::Card, &KeyProvenance::Kem).is_err());
        assert!(check(
            SealRequirement::Card,
            &KeyProvenance::Card(CardSource::Transported)
        )
        .is_ok());
        assert!(check(
            SealRequirement::PostQuantum,
            &KeyProvenance::Kem.transported_under()
        )
        .is_ok());
    }

    #[test]
    fn a_link_card_is_the_declared_exception_and_stays_visible() {
        let key = SealKey::new([1u8; 32], KeyProvenance::Card(CardSource::Link));
        assert_eq!(key.provenance().card_source(), Some(CardSource::Link));
        assert!(check(SealRequirement::Card, key.provenance()).is_ok());
    }

    #[test]
    fn a_seal_key_does_not_render_its_material() {
        let key = SealKey::new([2u8; 32], KeyProvenance::Kem);
        let rendered = format!("{key:?}");
        assert!(rendered.contains("Kem"));
        assert!(!rendered.contains('2'));
    }
}
