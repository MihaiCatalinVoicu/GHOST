//! The `monitor` rule engine (Phase 14 design §5.3, rules a/b/f): leaves decoded by the caller
//! (the network half is a separate slice), findings pure in the input.

use std::path::PathBuf;

use ghost_client_release::root::GHRT;
use ghost_verify::monitor::{DecodedLeaf, Finding, LeafDoc, MonitorInput, Observation, Served, run};

const NOW: u64 = 1_900_000_000;
const DAY: u32 = (NOW / 86_400) as u32;

fn sha256(b: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(b).into()
}

fn onion(seed: &str) -> String {
    use sha2::Digest as _;
    use sha3::Digest;
    let pk: [u8; 32] = sha2::Sha256::digest(seed.as_bytes()).into();
    let mut h = sha3::Sha3_256::new();
    h.update(b".onion checksum");
    h.update(pk);
    h.update([3u8]);
    let sum = h.finalize();
    let mut raw = Vec::with_capacity(35);
    raw.extend_from_slice(&pk);
    raw.extend_from_slice(&sum[..2]);
    raw.push(3);
    const ALPH: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut out = String::with_capacity(56);
    let mut acc = 0u32;
    let mut nbits = 0u32;
    for b in &raw {
        acc = (acc << 8) | u32::from(*b);
        nbits += 8;
        while nbits >= 5 {
            nbits -= 5;
            out.push(ALPH[((acc >> nbits) & 31) as usize] as char);
        }
    }
    if nbits > 0 {
        out.push(ALPH[((acc << (5 - nbits)) & 31) as usize] as char);
    }
    format!("{out}.onion:443")
}

fn hex16(byte: u8) -> String {
    hex::encode([byte; 16])
}

fn write(path: &std::path::Path, text: impl AsRef<[u8]>) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

struct World {
    dir: tempfile::TempDir,
    keys: PathBuf,
    root: PathBuf,
}

impl World {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let keys = dir.path().join("keys");
        ghost_release_ops::build::keygen(&keys, "root:2,release:1,attest:1,apk:1,log:1,witness:2").unwrap();
        let oa = onion("anchor-a");
        let ob = onion("anchor-b");
        let (first, second) = if oa < ob { (oa, ob) } else { (ob, oa) };
        let cfg = dir.path().join("root-1.toml");
        write(
            &cfg,
            format!(
                r#"network = 2
version = 1
apk_signers = ["{digest}"]
witnesses = ["witness-1", "witness-2"]
quorum = 1
[root]
keys = ["root-1", "root-2"]
threshold = 2
[release]
keys = ["release-1"]
threshold = 1
[attest]
keys = ["attest-1"]
threshold = 1
[[logs]]
key = "log-1"
origin = "stg-log-1"
[[anchor_mirrors]]
onion = "{first}"
operator = "{}"
[[anchor_mirrors]]
onion = "{second}"
operator = "{}"
"#,
                hex16(0x11),
                hex16(0x22),
                digest = "77".repeat(32),
            ),
        );
        let root = dir.path().join("root-1.ghrt");
        ghost_release_ops::build::root_build(&cfg, &keys, &root).unwrap();
        World { dir, keys, root }
    }

    fn release_key_id(&self) -> [u8; 32] {
        let pub_hex = std::fs::read_to_string(self.keys.join("release-1.pub")).unwrap();
        let pub_key = hex::decode(pub_hex.trim()).unwrap();
        sha256(&pub_key)
    }

}

#[test]
fn clean_run_finds_nothing() {
    let w = World::new();
    let root = GHRT::parse(&std::fs::read(&w.root).unwrap()).unwrap();
    let key = w.release_key_id();
    let leaves = vec![
        DecodedLeaf { index: 0, checksum: [0; 32], key_hash: key, doc: LeafDoc::Manifest { pair: (1, 1), verifies: true } },
        DecodedLeaf { index: 1, checksum: [0; 32], key_hash: key, doc: LeafDoc::Manifest { pair: (1, 2), verifies: true } },
    ];
    let served = vec![Served {
        mirror: b"mirror-a".to_vec(),
        current: Some(((1, 2), [0; 32])),
    }];
    let observations = vec![
        Observation { pair: (1, 1), mirror: b"mirror-a".to_vec(), first_seen_day: DAY - 2, last_seen_day: DAY - 1 },
        Observation { pair: (1, 2), mirror: b"mirror-a".to_vec(), first_seen_day: DAY - 1, last_seen_day: DAY },
    ];
    let archive_day = vec![((1, 1), DAY - 2), ((1, 2), DAY - 1)];
    let input = MonitorInput {
        root: &root,
        logs: &[leaves],
        served: &served,
        observations: &observations,
        archive_day: &archive_day,
        today: DAY,
    };
    assert_eq!(run(&input), vec![]);
}

#[test]
fn the_rules_fire_one_by_one() {
    let w = World::new();
    let root = GHRT::parse(&std::fs::read(&w.root).unwrap()).unwrap();
    let key = w.release_key_id();
    let stranger = sha256(b"not a ghost key");
    let leaves = vec![
        DecodedLeaf { index: 0, checksum: [0; 32], key_hash: key, doc: LeafDoc::Unknown },
        DecodedLeaf { index: 1, checksum: [0; 32], key_hash: key, doc: LeafDoc::Manifest { pair: (1, 5), verifies: false } },
        DecodedLeaf { index: 2, checksum: [0; 32], key_hash: key, doc: LeafDoc::Manifest { pair: (1, 5), verifies: true } },
        DecodedLeaf { index: 3, checksum: [0; 32], key_hash: stranger, doc: LeafDoc::Unknown },
        DecodedLeaf { index: 4, checksum: [0; 32], key_hash: key, doc: LeafDoc::Manifest { pair: (1, 9), verifies: true } },
    ];
    let served = vec![Served { mirror: b"m".to_vec(), current: Some(((1, 5), [0; 32])) }];
    let observations = vec![
        Observation { pair: (1, 5), mirror: b"m".to_vec(), first_seen_day: DAY, last_seen_day: DAY },
    ];
    let archive_day = vec![((1, 5), DAY + 9)];
    let input = MonitorInput {
        root: &root,
        logs: &[leaves],
        served: &served,
        observations: &observations,
        archive_day: &archive_day,
        today: DAY,
    };
    let findings = run(&input);
    assert!(findings.contains(&Finding::UnmatchedLeaf { log: 0, index: 0, key_hash: key }));
    assert!(findings.contains(&Finding::BadDocument { log: 0, index: 1 }));
    assert!(findings.contains(&Finding::PairOrder { log: 0, lower_index: 2, higher_index: 1, pair: (1, 5) }));
    // The never-served (1,9) is flagged; the stranger's unknown leaf is not ours to flag.
    assert!(findings.contains(&Finding::UnservedManifest { pair: (1, 9) }));
    assert!(findings.contains(&Finding::ShortServed { pair: (1, 5), mirror: b"m".to_vec() }));
    assert!(findings.contains(&Finding::LateArchive { pair: (1, 5), days: 9 }));
    assert!(!findings.iter().any(|f| matches!(f, Finding::UnmatchedLeaf { index: 3, .. })));
}
