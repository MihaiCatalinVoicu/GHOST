//! Sealed per-epoch key files and key load files (design §3.3, ADR-26 point 4).

mod common;

use ghost_entitlement::Kind;
use ghost_issuer::custody::{self, CustodyError, CustodySecret, SealKey, SealLoad, SEAL_KEY_LABEL};
use hmac::{Hmac, KeyInit, Mac};
use ring::rand::SystemRandom;
use sha2::{Digest, Sha256};

fn test_secret() -> CustodySecret {
    CustodySecret::from_bytes(Sha256::digest(b"ghost/test/custody-secret").into())
}

/// The first test keys of the committed test schedule: (kind, epoch, PKCS #8 DER).
fn test_keys(count: usize) -> Vec<(Kind, u64, Vec<u8>)> {
    let text = std::fs::read_to_string(common::fixture::dir().join("test_keys.txt")).unwrap();
    text.lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .take(count)
        .map(|line| {
            let f: Vec<&str> = line.split(' ').collect();
            (
                Kind::from_byte(f[0].parse().unwrap()).unwrap(),
                f[1].parse().unwrap(),
                hex::decode(f[2]).unwrap(),
            )
        })
        .collect()
}

fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key).unwrap();
    for p in parts {
        mac.update(p);
    }
    mac.finalize().into_bytes().into()
}

#[test]
fn seal_key_is_rfc5869_hkdf_sha256_of_the_custody_secret() {
    // Independent HKDF-SHA256 (RFC 5869, no salt = 32 zero bytes; one output block).
    let secret = test_secret();
    for (kind, epoch) in [
        (Kind::Access, 2957u64),
        (Kind::Access, 2958),
        (Kind::Invite, 739),
        (Kind::Credit, 227),
        (Kind::Credit, u64::MAX),
    ] {
        let prk = hmac_sha256(&[0u8; 32], &[secret.as_bytes()]);
        let expected = hmac_sha256(
            &prk,
            &[
                SEAL_KEY_LABEL,
                &[kind.byte()],
                &epoch.to_be_bytes(),
                &[0x01],
            ],
        );
        assert_eq!(secret.seal_key(kind, epoch).as_bytes(), &expected);
    }
    // Distinct (kind, epoch) give distinct keys.
    assert_ne!(
        secret.seal_key(Kind::Access, 739),
        secret.seal_key(Kind::Invite, 739)
    );
}

#[test]
fn seal_and_unseal_round_trip_and_refuse_every_alteration() {
    let rng = SystemRandom::new();
    let secret = test_secret();
    let (kind, epoch, der) = test_keys(1).remove(0);
    let key = secret.seal_key(kind, epoch);
    let sealed = custody::seal(&key, kind, epoch, &der, &rng).unwrap();
    assert_eq!(sealed.len(), 14 + 12 + der.len() + 16);
    assert_eq!(&sealed[..4], b"GHKS");
    let signer = custody::unseal(&key, kind, epoch, &sealed).unwrap();
    assert_eq!(signer.to_pkcs8_der().unwrap(), der);

    // Two seals of the same key never share a nonce.
    let again = custody::seal(&key, kind, epoch, &der, &rng).unwrap();
    assert_ne!(sealed[14..26], again[14..26]);

    // Another k_seal, another (kind, epoch) asked for, the header re-labelled, any body byte.
    let other = secret.seal_key(kind, epoch + 1);
    assert_eq!(
        custody::unseal(&other, kind, epoch, &sealed).err(),
        Some(CustodyError::Open)
    );
    assert_eq!(
        custody::unseal(&key, kind, epoch + 1, &sealed).err(),
        Some(CustodyError::WrongKey)
    );
    let mut relabelled = sealed.clone();
    relabelled[6..14].copy_from_slice(&(epoch + 1).to_be_bytes());
    assert_eq!(
        custody::unseal(&other, kind, epoch + 1, &relabelled).err(),
        Some(CustodyError::Open)
    );
    for at in [14, 20, 26, sealed.len() / 2, sealed.len() - 1] {
        let mut flipped = sealed.clone();
        flipped[at] ^= 0x01;
        assert_eq!(
            custody::unseal(&key, kind, epoch, &flipped).err(),
            Some(CustodyError::Open),
            "byte {at}"
        );
    }
    let mut version = sealed.clone();
    version[4] = 2;
    assert_eq!(
        custody::unseal(&key, kind, epoch, &version).err(),
        Some(CustodyError::Format)
    );
    assert_eq!(
        custody::unseal(&key, kind, epoch, &sealed[..14 + 12 + 15]).err(),
        Some(CustodyError::Format)
    );

    // A sealed plaintext that is not a key opens but is refused as a key.
    let junk = custody::seal(&key, kind, epoch, b"not a key", &rng).unwrap();
    assert!(matches!(
        custody::unseal(&key, kind, epoch, &junk).err(),
        Some(CustodyError::Key(_))
    ));
}

#[test]
fn load_file_round_trips_and_is_canonical() {
    let secret = test_secret();
    let mut load = SealLoad::new();
    for (kind, epoch) in [
        (Kind::Credit, 227),
        (Kind::Access, 2958),
        (Kind::Access, 2957),
    ] {
        load.insert(kind, epoch, secret.seal_key(kind, epoch))
            .unwrap();
    }
    assert_eq!(
        load.insert(Kind::Access, 2957, secret.seal_key(Kind::Access, 2957)),
        Err(CustodyError::Format)
    );
    let bytes = load.encode().unwrap();
    assert_eq!(bytes.len(), 7 + 3 * 41);
    let parsed = SealLoad::parse(&bytes).unwrap();
    assert_eq!(parsed, load);
    assert_eq!(
        parsed.keys().collect::<Vec<_>>(),
        [
            (Kind::Access, 2957),
            (Kind::Access, 2958),
            (Kind::Credit, 227)
        ]
    );
    assert_eq!(
        parsed.get(Kind::Credit, 227),
        Some(&secret.seal_key(Kind::Credit, 227))
    );

    let refused = |b: &[u8]| SealLoad::parse(b).err() == Some(CustodyError::Format);
    assert!(refused(&bytes[..bytes.len() - 1]));
    assert!(refused(&[bytes.as_slice(), &[0]].concat()));
    let mut unsorted = bytes.clone();
    let (a, b) = (7..48, 48..89);
    let first = unsorted[a.clone()].to_vec();
    let second = unsorted[b.clone()].to_vec();
    unsorted[a].copy_from_slice(&second);
    unsorted[b].copy_from_slice(&first);
    assert!(refused(&unsorted));
    let mut kind = bytes.clone();
    kind[7] = 9;
    assert!(refused(&kind));
    let mut magic = bytes.clone();
    magic[3] = b'S';
    assert!(refused(&magic));
    assert!(refused(b"GHKL\x01\x00\x00"));
    assert_eq!(SealLoad::new().encode(), Err(CustodyError::Format));
}

#[test]
fn secrets_never_show_in_debug() {
    let secret = test_secret();
    let key: SealKey = secret.seal_key(Kind::Access, 1);
    assert_eq!(format!("{secret:?}"), "CustodySecret(redacted)");
    assert_eq!(format!("{key:?}"), "SealKey(redacted)");
    assert_eq!(
        custody::sealed_file_name(Kind::Invite, 740),
        "invite-740.ghks"
    );
}
