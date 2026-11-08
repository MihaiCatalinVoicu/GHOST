//! The `monitor` rule engine (Phase 14 design §5.3, rules a/b/f): leaves decoded by the caller
//! (the network half is a separate slice), findings pure in the input.

use std::path::PathBuf;

use ghost_client_release::root::GHRT;
use ghost_verify::monitor::{
    DecodedLeaf, Finding, LeafDoc, MonitorInput, Observation, Served, run,
};

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
        ghost_release_ops::build::keygen(&keys, "root:2,release:1,attest:1,apk:1,log:1,witness:2")
            .unwrap();
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
        DecodedLeaf {
            index: 0,
            checksum: [0; 32],
            key_hash: key,
            doc: LeafDoc::Manifest {
                pair: (1, 1),
                verifies: true,
            },
        },
        DecodedLeaf {
            index: 1,
            checksum: [0; 32],
            key_hash: key,
            doc: LeafDoc::Manifest {
                pair: (1, 2),
                verifies: true,
            },
        },
    ];
    let served = vec![Served {
        mirror: b"mirror-a".to_vec(),
        current: Some(((1, 2), [0; 32])),
    }];
    let observations = vec![
        Observation {
            pair: (1, 1),
            mirror: b"mirror-a".to_vec(),
            first_seen_day: DAY - 2,
            last_seen_day: DAY - 1,
        },
        Observation {
            pair: (1, 2),
            mirror: b"mirror-a".to_vec(),
            first_seen_day: DAY - 1,
            last_seen_day: DAY,
        },
    ];
    let archive_day = vec![((1, 1), DAY - 2), ((1, 2), DAY - 1)];
    let input = MonitorInput {
        root: &root,
        logs: &[leaves],
        served: &served,
        observations: &observations,
        archive_day: &archive_day,
        today: DAY,
        archive: &[],
        es: &[],
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
        DecodedLeaf {
            index: 0,
            checksum: [0; 32],
            key_hash: key,
            doc: LeafDoc::Unknown,
        },
        DecodedLeaf {
            index: 1,
            checksum: [0; 32],
            key_hash: key,
            doc: LeafDoc::Manifest {
                pair: (1, 5),
                verifies: false,
            },
        },
        DecodedLeaf {
            index: 2,
            checksum: [0; 32],
            key_hash: key,
            doc: LeafDoc::Manifest {
                pair: (1, 5),
                verifies: true,
            },
        },
        DecodedLeaf {
            index: 3,
            checksum: [0; 32],
            key_hash: stranger,
            doc: LeafDoc::Unknown,
        },
        DecodedLeaf {
            index: 4,
            checksum: [0; 32],
            key_hash: key,
            doc: LeafDoc::Manifest {
                pair: (1, 9),
                verifies: true,
            },
        },
    ];
    let served = vec![Served {
        mirror: b"m".to_vec(),
        current: Some(((1, 5), [0; 32])),
    }];
    let observations = vec![Observation {
        pair: (1, 5),
        mirror: b"m".to_vec(),
        first_seen_day: DAY,
        last_seen_day: DAY,
    }];
    let archive_day = vec![((1, 5), DAY + 9)];
    let input = MonitorInput {
        root: &root,
        logs: &[leaves],
        served: &served,
        observations: &observations,
        archive_day: &archive_day,
        today: DAY,
        archive: &[],
        es: &[],
    };
    let findings = run(&input);
    assert!(findings.contains(&Finding::UnmatchedLeaf {
        log: 0,
        index: 0,
        key_hash: key
    }));
    assert!(findings.contains(&Finding::BadDocument { log: 0, index: 1 }));
    assert!(findings.contains(&Finding::PairOrder {
        log: 0,
        lower_index: 2,
        higher_index: 1,
        pair: (1, 5)
    }));
    // The never-served (1,9) is flagged; the stranger's unknown leaf is not ours to flag.
    assert!(findings.contains(&Finding::UnservedManifest { pair: (1, 9) }));
    assert!(findings.contains(&Finding::ShortServed {
        pair: (1, 5),
        mirror: b"m".to_vec()
    }));
    assert!(findings.contains(&Finding::LateArchive {
        pair: (1, 5),
        days: 9
    }));
    assert!(
        !findings
            .iter()
            .any(|f| matches!(f, Finding::UnmatchedLeaf { index: 3, .. }))
    );
}

// ---------------------------------------------------------------------------
// Rules (c), (d), (e), (g), (h): the archive side. The fixtures walk the release
// record's layout (§5.3): manifests built by the real release-ops builder, the APK,
// symbol and ES files they name, one mutation per rule.
// ---------------------------------------------------------------------------

use ed25519_dalek::Signer as _;
use ghost_client_release::manifest::GHRM;
use ghost_client_release::{SigBlock, SigEntry};
use ghost_entitlement::Schedule;
use ghost_verify::monitor::{ArchiveManifest, ArchiveReleaseFiles};

fn le16v(v: u16) -> [u8; 2] {
    v.to_le_bytes()
}
fn le32v(v: u32) -> [u8; 4] {
    v.to_le_bytes()
}
fn le64v(v: u64) -> [u8; 8] {
    v.to_le_bytes()
}

fn eocd(cd_offset: u32, cd_size: u32) -> Vec<u8> {
    let mut v = b"PK\x05\x06".to_vec();
    v.extend_from_slice(&le16v(0));
    v.extend_from_slice(&le16v(0));
    v.extend_from_slice(&le16v(1));
    v.extend_from_slice(&le16v(1));
    v.extend_from_slice(&le32v(cd_size));
    v.extend_from_slice(&le32v(cd_offset));
    v.extend_from_slice(&le16v(0));
    v
}

/// A §6.5-conformant signed/unsigned APK pair with an EMPTY signing block: rule (c) hashes
/// the file and its core, and the core extraction never parses the pairs, so none are needed.
fn apk_pair(content_e: usize) -> (Vec<u8>, Vec<u8>) {
    let cd = b"fake-central-directory".to_vec();
    let mut unsigned = vec![0xA5u8; content_e];
    unsigned.extend_from_slice(&cd);
    unsigned.extend_from_slice(&eocd(content_e as u32, cd.len() as u32));
    let pad = (4096 - (content_e % 4096)) % 4096;
    let b = content_e + pad;
    let s = 24u64; // empty pairs: size2(8) + magic(16)
    let mut signed = vec![0xA5u8; content_e];
    signed.extend(std::iter::repeat(0u8).take(pad));
    signed.extend_from_slice(&le64v(s));
    signed.extend_from_slice(&le64v(s));
    signed.extend_from_slice(b"APK Sig Block 42");
    assert_eq!(signed.len(), b + 8 + s as usize);
    signed.extend_from_slice(&cd);
    signed.extend_from_slice(&eocd((b + 8 + s as usize) as u32, cd.len() as u32));
    (unsigned, signed)
}

/// A minimal 64-bit little-endian ELF carrying one `.note.gnu.build-id` section with `id` —
/// rule (e)'s hand fixture: no toolchain, no build.rs, both files parametric in one id.
fn tiny_elf(id: &[u8]) -> Vec<u8> {
    const SHSTRTAB: &[u8] = b"\0.note.gnu.build-id\0.shstrtab\0";
    let mut note = Vec::new();
    note.extend_from_slice(&le32v(4)); // namesz ("GNU\0")
    note.extend_from_slice(&le32v(id.len() as u32));
    note.extend_from_slice(&le32v(3)); // NT_GNU_BUILD_ID
    note.extend_from_slice(b"GNU\0");
    note.extend_from_slice(id);
    while note.len() % 4 != 0 {
        note.push(0);
    }
    let hdr = 64usize;
    let note_off = hdr;
    let note_size = note.len();
    let str_off = note_off + note_size;
    let shoff = str_off + SHSTRTAB.len();
    let mut elf = vec![0u8; hdr];
    elf[0..4].copy_from_slice(b"\x7fELF");
    elf[4] = 2; // EI_CLASS: 64-bit
    elf[5] = 1; // EI_DATA: little-endian
    elf[6] = 1; // EV_CURRENT
    elf[0x10..0x12].copy_from_slice(&le16v(3)); // ET_DYN
    elf[0x12..0x14].copy_from_slice(&le16v(62)); // EM_X86_64
    elf[0x28..0x30].copy_from_slice(&(shoff as u64).to_le_bytes()); // e_shoff
    elf[0x3a..0x3c].copy_from_slice(&le16v(64)); // e_shentsize
    elf[0x3c..0x3e].copy_from_slice(&le16v(3)); // e_shnum
    elf[0x3e..0x40].copy_from_slice(&le16v(2)); // e_shstrndx
    elf.extend_from_slice(&note);
    elf.extend_from_slice(SHSTRTAB);
    let mut sh = |name: u32, ty: u32, off: usize, size: usize| -> Vec<u8> {
        let mut s = vec![0u8; 64];
        s[0..4].copy_from_slice(&le32v(name));
        s[4..8].copy_from_slice(&le32v(ty));
        s[0x18..0x20].copy_from_slice(&(off as u64).to_le_bytes());
        s[0x20..0x28].copy_from_slice(&(size as u64).to_le_bytes());
        s[0x30..0x38].copy_from_slice(&1u64.to_le_bytes()); // sh_addralign
        s
    };
    elf.extend_from_slice(&sh(0, 0, 0, 0)); // the null section
    elf.extend_from_slice(&sh(1, 7, note_off, note_size)); // .note.gnu.build-id, SHT_NOTE
    elf.extend_from_slice(&sh(20, 3, str_off, SHSTRTAB.len())); // .shstrtab, SHT_STRTAB
    elf
}

/// The committed test ES (the entitlement crate's public fixture) and its public test key
/// (SHA-256("ghost/test/schedule-key") as the Ed25519 seed — test material, never pinned).
const TEST_ES: &[u8] =
    include_bytes!("../../../issuer/crates/entitlement/tests/fixtures/test_schedule.ghes");

fn test_schedule_signing_key() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&sha256(b"ghost/test/schedule-key"))
}

fn test_schedule_key() -> [u8; 32] {
    test_schedule_signing_key().verifying_key().to_bytes()
}

/// The committed test ES re-signed with the test key after `edit` — rule (d)'s engine input,
/// exactly what the caller produces from an archived ES file it verified.
fn es_doc(edit: impl FnOnce(&mut ghost_entitlement::schedule::ScheduleContent)) -> (u64, Schedule) {
    let base = Schedule::verify_with_key(TEST_ES, &test_schedule_key()).unwrap();
    let mut content = base.content().clone();
    edit(&mut content);
    let body = content.body().unwrap();
    let msg = [ghost_entitlement::schedule::SIGNATURE_DOMAIN, &body].concat();
    let sig = test_schedule_signing_key().sign(&msg);
    let mut doc = body.clone();
    doc.extend_from_slice(&sig.to_bytes());
    let schedule = Schedule::verify_with_key(&doc, &test_schedule_key()).unwrap();
    (content.seq, schedule)
}

struct RelCfg {
    version_code: u32,
    salt: u8,
    permille: u16,
    wire: bool,
    /// Declare a different unsigned build than the file names (rule (c)'s core mutation):
    /// the manifest's `unsigned_sha256`/`unsigned_length` overrides, no file read.
    unsigned_override: Option<([u8; 32], u64)>,
}

impl RelCfg {
    fn plain(version_code: u32) -> Self {
        RelCfg {
            version_code,
            salt: 0x33,
            permille: 1000,
            wire: false,
            unsigned_override: None,
        }
    }
}

impl World {
    /// Builds a manifest through the real release-ops builder and returns the document bytes.
    /// `apk_override` renames the APK in the manifest (rule (c)'s hash mutation) without the
    /// builder reading the file.
    fn build_manifest(
        &self,
        seq: u64,
        issued_day: u32,
        floor: u32,
        rels: &[RelCfg],
        attest: &[&str],
        apk_override: Option<([u8; 32], u64)>,
    ) -> Vec<u8> {
        let dir = self.dir.path().join(format!("am-{seq}"));
        std::fs::create_dir_all(&dir).unwrap();
        let escrow = dir.join("escrow.tar.gz");
        write(&escrow, "escrow");
        let lib = dir.join("lib.so");
        write(&lib, tiny_elf(&[7u8; 20]));
        let sym = dir.join("lib.so.debug");
        write(&sym, tiny_elf(&[7u8; 20]));
        let es_file = dir.join("es.ghes");
        write(&es_file, TEST_ES);
        let mut toml = format!(
            "seq = {seq}\nissued_day = {issued_day}\nnot_after_day = {}\nfloor_version_code = {floor}\n",
            issued_day + 30
        );
        for rel in rels {
            let vc = rel.version_code;
            let unsigned = dir.join(format!("app-{vc}-unsigned.apk"));
            let (u_bytes, s_bytes) = apk_pair(900 + vc as usize);
            write(&unsigned, &u_bytes);
            let apk = dir.join(format!("app-{vc}.apk"));
            write(&apk, &s_bytes);
            let unsigned_ov = rel
                .unsigned_override
                .map(|(sha, len)| {
                    format!(
                        "unsigned_sha256 = \"{}\"\nunsigned_length = {len}\n",
                        hex::encode(sha)
                    )
                })
                .unwrap_or_default();
            let apk_ov = apk_override
                .map(|(sha, len)| {
                    format!(
                        "apk_sha256 = \"{}\"\napk_length = {len}\n",
                        hex::encode(sha)
                    )
                })
                .unwrap_or_default();
            toml.push_str(&format!(
                r#"[[release]]
version_code = {vc}
version_name = "0.9.{vc}"
min_sdk = 29
anchor_root = 1
wire_changing = {wire}
apk = "{apk}"
{apk_ov}unsigned = "{unsigned}"
{unsigned_ov}rollout_permille = {permille}
rollout_salt = "{salt}"
commit = "{commit}"
es_seq = 2957
es_file = "{es_file}"
[[release.artifacts]]
kind = 1
file = "{lib}"
[[release.artifacts]]
kind = 3
file = "{sym}"
[[release.artifacts]]
kind = 16
file = "{escrow}"
"#,
                wire = rel.wire,
                permille = rel.permille,
                salt = hex16(rel.salt),
                commit = "ab".repeat(20),
                es_file = es_file.display(),
                lib = lib.display(),
                sym = sym.display(),
                escrow = escrow.display(),
                apk = apk.display(),
                unsigned = unsigned.display(),
            ));
        }
        let src = dir.join("manifest.toml");
        write(&src, toml);
        let out = dir.join("manifest.ghrm");
        ghost_release_ops::build::manifest_build(
            &src,
            &self.root,
            &self.keys,
            &attest.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
            None,
            &out,
        )
        .unwrap();
        std::fs::read(out).unwrap()
    }
}

/// Re-signs `doc`'s release block after `edit` mutates the parsed manifest. The honest
/// builder's structural guards model the vendor; a malicious release key signs whatever the
/// monitor must flag, so the wire and attestation mutations reach the engine re-signed.
fn resign_manifest(w: &World, doc: &[u8], edit: impl FnOnce(&mut GHRM)) -> Vec<u8> {
    let mut m = GHRM::parse(doc).unwrap();
    edit(&mut m);
    let msg = m.statement();
    let mut out = m.body_bytes();
    let seed = hex::decode(
        std::fs::read_to_string(w.keys.join("release-1.hex"))
            .unwrap()
            .trim(),
    )
    .unwrap();
    let seed: [u8; 32] = seed.try_into().unwrap();
    let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
    let entry = SigEntry {
        key_id: ghost_client_release::key_id(&sk.verifying_key().to_bytes()),
        signature: sk.sign(&msg).to_bytes(),
    };
    SigBlock {
        entries: vec![entry],
    }
    .write(&mut out);
    out
}

/// The green archive: one manifest (pair 1,1), one attested release with a conformant APK and
/// matching library/symbol build-ids, an append-only ES chain.
struct Green {
    manifest: Vec<u8>,
    root_doc: Vec<u8>,
    signed: Vec<u8>,
    lib: Vec<u8>,
    sym: Vec<u8>,
    es: Vec<(u64, Schedule)>,
}

fn green() -> (World, Green) {
    let w = World::new();
    let manifest = w.build_manifest(1, DAY, 0, &[RelCfg::plain(100)], &["attest-1"], None);
    let (_, signed) = apk_pair(900 + 100);
    let (es1_seq, es1) = es_doc(|_| {});
    let (es2_seq, es2) = es_doc(|c| c.seq = es1_seq + 1);
    let root_doc = std::fs::read(&w.root).unwrap();
    (
        w,
        Green {
            manifest,
            root_doc,
            signed,
            lib: tiny_elf(&[7u8; 20]),
            sym: tiny_elf(&[7u8; 20]),
            es: vec![(es1_seq, es1), (es2_seq, es2)],
        },
    )
}

/// The archive entry as the caller would assemble it: the manifest's releases in order, the
/// artifact files parallel to each release's artifact list (kinds 1, 3, 16 after the
/// builder's sort; kind 16's bytes are not rule (e)'s, so `None`).
fn green_entry<'a>(g: &'a Green, m: &'a GHRM, root: &'a GHRT) -> ArchiveManifest<'a> {
    ArchiveManifest {
        manifest: m,
        root,
        releases: vec![ArchiveReleaseFiles {
            apk: Some(&g.signed),
            artifacts: vec![Some(&g.lib), Some(&g.sym), None],
        }],
    }
}

/// Runs the engine over archive inputs with quiet (a)/(b)/(f) surroundings: `pairs` are the
/// logged manifest pairs (each leaf verified), one observation and archive day each.
fn archive_findings(
    w: &World,
    g: &Green,
    archive: &[ArchiveManifest<'_>],
    es: &[(u64, Schedule)],
    pairs: &[(u32, u64)],
) -> Vec<Finding> {
    let root = GHRT::parse(&g.root_doc).unwrap();
    let key = w.release_key_id();
    let leaves: Vec<DecodedLeaf> = pairs
        .iter()
        .enumerate()
        .map(|(i, pair)| DecodedLeaf {
            index: i as u64,
            checksum: [0; 32],
            key_hash: key,
            doc: LeafDoc::Manifest {
                pair: *pair,
                verifies: true,
            },
        })
        .collect();
    let served = vec![Served {
        mirror: b"m".to_vec(),
        current: Some((*pairs.last().unwrap(), [0; 32])),
    }];
    let observations: Vec<Observation> = pairs
        .iter()
        .map(|pair| Observation {
            pair: *pair,
            mirror: b"m".to_vec(),
            first_seen_day: DAY - 1,
            last_seen_day: DAY,
        })
        .collect();
    let archive_day: Vec<((u32, u64), u32)> = pairs.iter().map(|pair| (*pair, DAY - 1)).collect();
    let input = MonitorInput {
        root: &root,
        logs: &[leaves],
        served: &served,
        observations: &observations,
        archive_day: &archive_day,
        today: DAY,
        archive,
        es,
    };
    run(&input)
}

#[test]
fn archive_rules_green_run_finds_nothing() {
    let (w, g) = green();
    let root = GHRT::parse(&g.root_doc).unwrap();
    let m = GHRM::parse(&g.manifest).unwrap();
    let entry = green_entry(&g, &m, &root);
    assert_eq!(archive_findings(&w, &g, &[entry], &g.es, &[(1, 1)]), vec![]);
}

#[test]
fn rule_c_flags_a_missing_apk() {
    let (w, g) = green();
    let root = GHRT::parse(&g.root_doc).unwrap();
    let m = GHRM::parse(&g.manifest).unwrap();
    let mut entry = green_entry(&g, &m, &root);
    entry.releases[0].apk = None;
    let findings = archive_findings(&w, &g, &[entry], &g.es, &[(1, 1)]);
    assert!(findings.contains(&Finding::MissingApk {
        version_code: 100,
        apk_sha256: sha256(&g.signed)
    }));
}

#[test]
fn rule_c_flags_a_swapped_apk_on_every_clause_it_breaks() {
    let (w, g) = green();
    // The archive's file is another build's signed APK: its whole-file hash is not the
    // manifest's apk_sha256 and its core is not the attested unsigned_sha256.
    let (_, other) = apk_pair(900 + 100 + 4096);
    let root = GHRT::parse(&g.root_doc).unwrap();
    let m = GHRM::parse(&g.manifest).unwrap();
    let mut entry = green_entry(&g, &m, &root);
    entry.releases[0].apk = Some(&other);
    let findings = archive_findings(&w, &g, &[entry], &g.es, &[(1, 1)]);
    let unsigned: [u8; 32] = m.body.releases[0].unsigned_sha256;
    assert!(findings.contains(&Finding::ApkHashMismatch {
        version_code: 100,
        apk_sha256: m.body.releases[0].apk_sha256
    }));
    assert!(findings.contains(&Finding::CoreMismatch {
        version_code: 100,
        unsigned_sha256: unsigned
    }));
}

#[test]
fn rule_c_flags_an_apk_that_is_not_a_signed_apk() {
    let (w, g) = green();
    let garbage = vec![0x55u8; 5000];
    // The manifest names the garbage (hash + length overrides): the hash clause passes and
    // the layout clause alone fires.
    let manifest = w.build_manifest(
        1,
        DAY,
        0,
        &[RelCfg::plain(100)],
        &["attest-1"],
        Some((sha256(&garbage), garbage.len() as u64)),
    );
    let root = GHRT::parse(&g.root_doc).unwrap();
    let m = GHRM::parse(&manifest).unwrap();
    let mut entry = green_entry(&g, &m, &root);
    entry.releases[0].apk = Some(&garbage);
    let findings = archive_findings(&w, &g, &[entry], &g.es, &[(1, 1)]);
    assert!(
        findings
            .iter()
            .any(|f| matches!(f, Finding::ApkLayout { version_code: 100 }))
    );
    assert!(
        !findings
            .iter()
            .any(|f| matches!(f, Finding::ApkHashMismatch { .. }))
    );
}

#[test]
fn rule_c_flags_a_wrong_attested_core() {
    let (w, g) = green();
    // The manifest declares another build's unsigned hash+length while the archive holds the
    // real signed APK: the hash clause passes, the core clause fires.
    let (other_unsigned, _) = apk_pair(900 + 100 + 2048);
    let mut rel = RelCfg::plain(100);
    rel.unsigned_override = Some((sha256(&other_unsigned), other_unsigned.len() as u64));
    let manifest = w.build_manifest(1, DAY, 0, &[rel], &["attest-1"], None);
    let root = GHRT::parse(&g.root_doc).unwrap();
    let m = GHRM::parse(&manifest).unwrap();
    let entry = green_entry(&g, &m, &root);
    let findings = archive_findings(&w, &g, &[entry], &g.es, &[(1, 1)]);
    assert!(findings.contains(&Finding::CoreMismatch {
        version_code: 100,
        unsigned_sha256: m.body.releases[0].unsigned_sha256
    }));
    assert!(
        !findings
            .iter()
            .any(|f| matches!(f, Finding::ApkHashMismatch { .. }))
    );
}

#[test]
fn rule_c_flags_an_unattested_release() {
    let (w, g) = green();
    // The attestation block is emptied (a sigblock_or_empty): the manifest still parses and
    // its release block verifies, but no attester the root lists stands behind the release.
    let patched = resign_manifest(&w, &g.manifest, |m| {
        m.attestations[0] = SigBlock { entries: vec![] };
    });
    let root = GHRT::parse(&g.root_doc).unwrap();
    let m = GHRM::parse(&patched).unwrap();
    m.verify_block(&root.body.release.keys, root.body.release.threshold)
        .unwrap();
    let entry = green_entry(&g, &m, &root);
    let findings = archive_findings(&w, &g, &[entry], &g.es, &[(1, 1)]);
    assert!(findings.contains(&Finding::BadAttestation { version_code: 100 }));
}

#[test]
fn rule_d_accepts_an_append_only_es_chain() {
    let (w, g) = green();
    let root = GHRT::parse(&g.root_doc).unwrap();
    let m = GHRM::parse(&g.manifest).unwrap();
    let entry = green_entry(&g, &m, &root);
    let findings = archive_findings(&w, &g, &[entry], &g.es, &[(1, 1)]);
    assert!(
        !findings
            .iter()
            .any(|f| matches!(f, Finding::EsNotAppendOnly { .. }))
    );
}

#[test]
fn rule_d_flags_a_changed_price() {
    let (w, g) = green();
    let root = GHRT::parse(&g.root_doc).unwrap();
    let m = GHRM::parse(&g.manifest).unwrap();
    let entry = green_entry(&g, &m, &root);
    // The second ES changes a covered epoch's price: ADR-22 rule 5's "prices never change".
    let (es1_seq, _) = g.es[0].clone();
    let (es2_seq, es2) = es_doc(|c| {
        c.seq = es1_seq + 1;
        c.prices[0].pack_price_atomic += 1;
    });
    let findings = archive_findings(
        &w,
        &g,
        &[entry],
        &[(es1_seq, g.es[0].1.clone()), (es2_seq, es2)],
        &[(1, 1)],
    );
    assert!(findings.contains(&Finding::EsNotAppendOnly { es_seq: es2_seq }));
}

#[test]
fn rule_e_flags_a_build_id_mismatch_and_an_unreadable_file() {
    let (w, g) = green();
    let root = GHRT::parse(&g.root_doc).unwrap();
    let m = GHRM::parse(&g.manifest).unwrap();
    // Mutation 1: the symbol file describes another build.
    let other_sym = tiny_elf(&[9u8; 20]);
    let mut entry = green_entry(&g, &m, &root);
    entry.releases[0].artifacts[1] = Some(&other_sym);
    let findings = archive_findings(&w, &g, &[entry], &g.es, &[(1, 1)]);
    assert!(findings.contains(&Finding::BuildIdMismatch {
        version_code: 100,
        abi: "arm64-v8a"
    }));
    // Mutation 2: the symbol file is not an ELF at all.
    let junk = b"not an elf".to_vec();
    let mut entry = green_entry(&g, &m, &root);
    entry.releases[0].artifacts[1] = Some(&junk);
    let findings = archive_findings(&w, &g, &[entry], &g.es, &[(1, 1)]);
    assert!(findings.contains(&Finding::BuildIdUnreadable {
        version_code: 100,
        abi: "arm64-v8a"
    }));
    // Mutation 3: the archive holds no symbol file for the release.
    let mut entry = green_entry(&g, &m, &root);
    entry.releases[0].artifacts[1] = None;
    let findings = archive_findings(&w, &g, &[entry], &g.es, &[(1, 1)]);
    assert!(findings.contains(&Finding::MissingSymbols {
        version_code: 100,
        abi: "arm64-v8a"
    }));
}

#[test]
fn rule_g_flags_a_changed_salt_and_a_shared_salt() {
    let (w, g) = green();
    let root = GHRT::parse(&g.root_doc).unwrap();
    // Mutation 1: the same release (one apk_sha256) re-signed with another salt. The honest
    // builder refuses this with `--prev`; a malicious release key signs it, so the second
    // manifest is built unchained.
    let mut rel = RelCfg::plain(100);
    rel.salt = 0x44;
    let m2_bytes = w.build_manifest(2, DAY, 0, &[rel], &["attest-1"], None);
    let m1 = GHRM::parse(&g.manifest).unwrap();
    let m2 = GHRM::parse(&m2_bytes).unwrap();
    let e1 = green_entry(&g, &m1, &root);
    let e2 = green_entry(&g, &m2, &root);
    let findings = archive_findings(&w, &g, &[e1, e2], &g.es, &[(1, 1), (1, 2)]);
    assert!(findings.contains(&Finding::SaltChanged {
        apk_sha256: sha256(&g.signed)
    }));
    // Mutation 2: two distinct releases sharing one salt, in one manifest (each release's
    // archive APK is its own build, so the salt clause fires alone).
    let mut rel_a = RelCfg::plain(100);
    let mut rel_b = RelCfg::plain(200);
    rel_a.salt = 0x77;
    rel_b.salt = 0x77;
    let shared = w.build_manifest(1, DAY, 0, &[rel_a, rel_b], &["attest-1"], None);
    let m = GHRM::parse(&shared).unwrap();
    let (_, signed200) = apk_pair(900 + 200);
    let e = ArchiveManifest {
        manifest: &m,
        root: &root,
        releases: vec![
            ArchiveReleaseFiles {
                apk: Some(&g.signed),
                artifacts: vec![Some(&g.lib), Some(&g.sym), None],
            },
            ArchiveReleaseFiles {
                apk: Some(&signed200),
                artifacts: vec![Some(&g.lib), Some(&g.sym), None],
            },
        ],
    };
    let findings = archive_findings(&w, &g, &[e], &g.es, &[(1, 1)]);
    assert!(findings.contains(&Finding::SaltShared {
        salt: [0x77; 16],
        first_version_code: 100,
        second_version_code: 200
    }));
}

#[test]
fn rule_h_flags_a_staged_wire_change() {
    let (w, g) = green();
    // manifest-build refuses a wire-changing release at a staged permille; the malicious-key
    // path reaches the monitor re-signed.
    let patched = resign_manifest(&w, &g.manifest, |m| {
        m.body.releases[0].wire_changing = true;
        m.body.releases[0].rollout_permille = 500;
    });
    let root = GHRT::parse(&g.root_doc).unwrap();
    let m = GHRM::parse(&patched).unwrap();
    m.verify_block(&root.body.release.keys, root.body.release.threshold)
        .unwrap();
    let entry = green_entry(&g, &m, &root);
    let findings = archive_findings(&w, &g, &[entry], &g.es, &[(1, 1)]);
    assert!(findings.contains(&Finding::WireChangingStaged {
        version_code: 100,
        rollout_permille: 500
    }));
}

#[test]
fn rule_h_flags_a_floor_above_the_attested_max() {
    let (w, g) = green();
    // floor = the release's own version_code (parse's bound is ≤ the lowest release); the
    // attestation is then emptied, so §7.4 step 3's attested_max is 0 and the floor exceeds
    // it — exactly the decision the updater runs.
    let manifest = w.build_manifest(1, DAY, 100, &[RelCfg::plain(100)], &["attest-1"], None);
    let patched = resign_manifest(&w, &manifest, |m| {
        m.attestations[0] = SigBlock { entries: vec![] };
    });
    let root = GHRT::parse(&g.root_doc).unwrap();
    let m = GHRM::parse(&patched).unwrap();
    let entry = green_entry(&g, &m, &root);
    let findings = archive_findings(&w, &g, &[entry], &g.es, &[(1, 1)]);
    assert!(findings.contains(&Finding::FloorInvalid {
        root_version: 1,
        manifest_seq: 1,
        floor: 100,
        attested_max: 0
    }));
    assert!(findings.contains(&Finding::BadAttestation { version_code: 100 }));
}

#[test]
fn rule_h_flags_a_decreasing_issued_day() {
    let (w, g) = green();
    // The second manifest's issued_day is below the first's; without `--prev` the honest
    // builder does not see the pair, and the monitor catches what a release key signed.
    let m2_bytes = w.build_manifest(2, DAY - 5, 0, &[RelCfg::plain(100)], &["attest-1"], None);
    let root = GHRT::parse(&g.root_doc).unwrap();
    let m1 = GHRM::parse(&g.manifest).unwrap();
    let m2 = GHRM::parse(&m2_bytes).unwrap();
    let e1 = green_entry(&g, &m1, &root);
    let e2 = green_entry(&g, &m2, &root);
    let findings = archive_findings(&w, &g, &[e1, e2], &g.es, &[(1, 1), (1, 2)]);
    assert!(findings.contains(&Finding::IssuedDayDecreased {
        root_version: 1,
        manifest_seq: 2,
        issued_day: DAY - 5,
        previous_seq: 1,
        previous_day: DAY,
    }));
}
