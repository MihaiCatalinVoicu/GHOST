//! Round-trip and negative-case tests for the §4 formats (S1 slice 1). Golden test-vectors
//! (`ghost/protocol/test-vectors/release_*.txt`, §4.9) land with the ops tool in S2; these tests
//! pin the grammar rules with generated keys.

use ed25519_dalek::SigningKey;
use ghost_client_release::manifest::{ArtifactKind, GHRM, Release};
use ghost_client_release::root::{AnchorMirror, GHRT, KeySet, LogEntry, Network};
use ghost_client_release::statement::{SigBlock, SigEntry, StatementType, sign_entry};
use ghost_client_release::{FormatError, GHRA, GHRC, GHRB, GHRP};

const ONION_A: &str = "tfhsac26mfhbq6dm5rctfkjnll74xag6p7ehumcr7keqsnkqhp7no4id.onion:443";
const ONION_B: &str = "ls2jkm3tmxnaa3o3j3bbb63jx5csqdiaen6wdt3ls6wkpfejl3xlfoqd.onion:80";

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn sorted_keys(seeds: &[u8]) -> Vec<[u8; 32]> {
    let mut v: Vec<[u8; 32]> = seeds.iter().map(|s| key(*s).verifying_key().to_bytes()).collect();
    v.sort_by_key(|k| ghost_client_release::key_id(k));
    v
}

fn sample_root() -> GHRT {
    let root_keys = sorted_keys(&[1, 2, 3]);
    let rel_keys = sorted_keys(&[4, 5]);
    let att_keys = sorted_keys(&[6]);
    GHRT {
        body: ghost_client_release::root::RootBody {
            network: Network::Stagenet,
            root_version: 1,
            root: KeySet {
                keys: root_keys.clone(),
                threshold: 2,
            },
            release: KeySet {
                keys: rel_keys.clone(),
                threshold: 1,
            },
            attest: KeySet {
                keys: att_keys.clone(),
                threshold: 1,
            },
            apk_signers: vec![[0xAA; 32]],
            logs: vec![
                LogEntry {
                    pk: [0x11; 32],
                    origin: b"https://seasalp.glasklar.is".to_vec(),
                },
                LogEntry {
                    pk: [0x22; 32],
                    origin: b"https://ginkgo.tlog.mullvad.net".to_vec(),
                },
            ],
            witnesses: sorted_keys(&[7, 8, 9]),
            quorum: 2,
            anchor_mirrors: vec![
                AnchorMirror {
                    onion: ONION_B.as_bytes().to_vec(),
                    operator_id: [0xB2; 16],
                },
                AnchorMirror {
                    onion: ONION_A.as_bytes().to_vec(),
                    operator_id: [0xA1; 16],
                },
            ],
        },
        block: SigBlock { entries: vec![] },
    }
}

fn sign_root(root: &GHRT) -> GHRT {
    let mut r = root.clone();
    let sk = [key(1), key(2)];
    let entries: Vec<SigEntry> = sk
        .iter()
        .map(|k| sign_entry(k, StatementType::ReleaseRoot, 2, &r.body_bytes()))
        .collect();
    r.block = SigBlock { entries };
    r
}

fn sample_release() -> Release {
    Release {
        version_code: 7,
        version_name: b"0.7.0-staging".to_vec(),
        min_sdk: 29,
        flavor: 1,
        anchor_root: 1,
        wire_changing: false,
        apk_sha256: [0xC1; 32],
        apk_length: 8_268_175,
        unsigned_sha256: [0xC2; 32],
        unsigned_length: 8_268_175,
        rollout_permille: 1000,
        rollout_salt: [0xD1; 16],
        commit: [0xE1; 20],
        es_seq: 1,
        es_sha256: [0xF1; 32],
        artifacts: vec![
            (ArtifactKind::NativeArm64, [0x22; 32], 4_000_000),
            (ArtifactKind::SourceEscrow, [0x21; 32], 1_048_576),
        ],
    }
}

fn sign_manifest(m: &GHRM) -> GHRM {
    let mut x = m.clone();
    x.block = SigBlock {
        entries: vec![sign_entry(
            &key(4),
            StatementType::ReleaseManifest,
            2,
            &x.body_bytes(),
        )],
    };
    x
}

fn sample_manifest() -> GHRM {
    let root = sign_root(&sample_root());
    let rel = sample_release();
    let at = rel.attestation(2);
    let attestation_block = SigBlock {
        entries: vec![sign_entry(
            &key(6),
            StatementType::BuildAttestation,
            2,
            &at.to_bytes(),
        )],
    };
    GHRM {
        body: ghost_client_release::manifest::ManifestBody {
            network: 2,
            manifest_seq: 1,
            root_version: 1,
            root_sha256: ghost_client_release::sha256_of(&root.to_bytes()),
            issued_day: 20_000,
            not_after_day: 20_091,
            floor_version_code: 0,
            releases: vec![rel],
            extra_mirrors: vec![],
            relays: vec![],
        },
        attestations: vec![attestation_block],
        block: SigBlock { entries: vec![] },
    }
}

#[test]
fn root_roundtrip_and_verify() {
    let r = sign_root(&sample_root());
    let doc = r.to_bytes();
    let parsed = GHRT::parse(&doc).unwrap();
    assert_eq!(parsed, r);
    parsed
        .verify_block(&parsed.body.root.keys, parsed.body.root.threshold)
        .unwrap();
    // Wrong threshold fails.
    assert_eq!(
        parsed.verify_block(&parsed.body.root.keys, 3),
        Err(FormatError::Threshold)
    );
}

#[test]
fn root_rejects_unsorted_keyset() {
    let mut r = sample_root();
    let mut keys = r.body.root.keys.clone();
    keys.reverse(); // not ascending by key id
    r.body.root.keys = keys;
    let doc = r.to_bytes();
    assert_eq!(GHRT::parse(&doc), Err(FormatError::Ordering));
}

#[test]
fn root_rejects_key_reuse_across_keysets() {
    let mut r = sample_root();
    r.body.release.keys = vec![r.body.root.keys[0]];
    r.body.release.threshold = 1;
    let doc = r.to_bytes();
    assert_eq!(GHRT::parse(&doc), Err(FormatError::KeyReuse));
}

#[test]
fn root_mainnet_requires_three_root_keys_and_two_operators() {
    let mut r = sample_root();
    r.body.network = Network::Mainnet;
    // Stagenet-shaped root (3 root keys OK) but anchor mirrors share one operator.
    r.body.anchor_mirrors[1].operator_id = r.body.anchor_mirrors[0].operator_id;
    let doc = r.to_bytes();
    assert_eq!(GHRT::parse(&doc), Err(FormatError::Count));
}

#[test]
fn manifest_roundtrip_verify_and_attestation() {
    let m = sign_manifest(&sample_manifest());
    let doc = m.body_bytes_with_block();
    let parsed = GHRM::parse(&doc).unwrap();
    assert_eq!(parsed, m);
    parsed.verify_block(&sorted_keys(&[4, 5]), 1).unwrap();
    parsed.verify_attestation(0, &sorted_keys(&[6]), 1).unwrap();
}

#[test]
fn manifest_rejects_expiry_over_91_days() {
    let mut m = sample_manifest();
    m.body.not_after_day = m.body.issued_day + 92;
    let doc = m.body_bytes_with_block();
    assert_eq!(GHRM::parse(&doc), Err(FormatError::Range));
}

#[test]
fn manifest_rejects_missing_source_escrow() {
    let mut m = sample_manifest();
    m.body.releases[0].artifacts.retain(|a| a.0 != ArtifactKind::SourceEscrow);
    let doc = m.body_bytes_with_block();
    assert_eq!(GHRM::parse(&doc), Err(FormatError::Count));
}

#[test]
fn manifest_rejects_mixed_min_sdk() {
    let mut m = sample_manifest();
    let mut r2 = sample_release();
    r2.version_code = 8;
    r2.min_sdk = 30;
    m.body.releases.push(r2);
    m.attestations.push(SigBlock { entries: vec![] });
    let doc = m.body_bytes_with_block();
    assert_eq!(GHRM::parse(&doc), Err(FormatError::Range));
}

#[test]
fn manifest_rejects_floor_above_lowest_release() {
    let mut m = sample_manifest();
    m.body.floor_version_code = 99;
    let doc = m.body_bytes_with_block();
    assert_eq!(GHRM::parse(&doc), Err(FormatError::Range));
}

#[test]
fn ghra_rebuild_is_stable() {
    let rel = sample_release();
    let a1 = rel.attestation(2);
    let a2 = rel.attestation(2);
    assert_eq!(a1, a2);
    assert_eq!(GHRA::parse(&a1.to_bytes()).unwrap(), a1);
    // Kind 23 is excluded from the statement (§4.6).
    let mut rel23 = sample_release();
    rel23
        .artifacts
        .push((ArtifactKind::PerVersionEvidence, [0x33; 32], 10));
    let a = rel23.attestation(2);
    assert!(!a.artifacts.iter().any(|x| x.0 == ArtifactKind::PerVersionEvidence));
}

#[test]
fn ghrp_roundtrip_and_inclusion() {
    let p = GHRP {
        message: [0x1; 32],
        log: 0,
        leaf_signature: [0x2; 64],
        leaf_key_id: [0x3; 32],
        tree_size: 2,
        leaf_index: 1,
        path: vec![[0x4; 32]],
        root_hash: [0x5; 32],
        log_signature: [0x6; 64],
        cosignatures: vec![],
    };
    let parsed = GHRP::parse(&p.to_bytes()).unwrap();
    assert_eq!(parsed, p);
    // Inclusion of a made-up leaf against a made-up root must fail (never panics).
    assert_eq!(
        parsed.verify_leaf(&[0u8; 64], &[0x7; 32]),
        Err(FormatError::Signature)
    );
}

#[test]
fn chain_roundtrip() {
    let r1 = sign_root(&sample_root());
    let mut r2 = sample_root();
    r2.body.root_version = 2;
    let r2 = sign_root(&r2);
    let c = GHRC {
        network: 2,
        first_version: 1,
        roots: vec![r1, r2],
    };
    let parsed = GHRC::parse(&c.to_bytes()).unwrap();
    assert_eq!(parsed, c);
}

#[test]
fn chain_rejects_gap() {
    let r1 = sign_root(&sample_root());
    let mut r3 = sample_root();
    r3.body.root_version = 3;
    let r3 = sign_root(&r3);
    let c = GHRC {
        network: 2,
        first_version: 1,
        roots: vec![r1, r3],
    };
    assert_eq!(GHRC::parse(&c.to_bytes()), Err(FormatError::Range));
}

#[test]
fn bundle_roundtrip() {
    let root = sign_root(&sample_root());
    let manifest = sign_manifest(&sample_manifest());
    let proof = GHRP {
        message: ghost_client_release::sha256_of(&manifest.body_bytes_with_block()),
        log: 0,
        leaf_signature: [0x2; 64],
        leaf_key_id: ghost_client_release::key_id(&[0x11; 32]),
        tree_size: 1,
        leaf_index: 0,
        path: vec![],
        root_hash: [0x5; 32],
        log_signature: [0x6; 64],
        cosignatures: vec![],
    };
    let chain = GHRC {
        network: 2,
        first_version: 1,
        roots: vec![root],
    };
    let b = GHRB {
        network: 2,
        chain,
        root_proofs: vec![],
        manifest,
        manifest_proof: proof,
    };
    let parsed = GHRB::parse(&b.to_bytes()).unwrap();
    assert_eq!(parsed.network, 2);
    assert_eq!(parsed.manifest, b.manifest);
}

#[test]
fn parsers_refuse_trailing_bytes_and_unknown_versions() {
    let r = sign_root(&sample_root());
    let mut doc = r.to_bytes();
    doc.push(0);
    assert_eq!(GHRT::parse(&doc), Err(FormatError::Trailing));
    let mut bad = r.to_bytes();
    bad[4] = 2; // version byte
    assert_eq!(GHRT::parse(&bad), Err(FormatError::Version));
}
