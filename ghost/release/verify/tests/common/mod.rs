//! Shared fixture builders of `ghost-verify`'s integration tests: keys/roots via the real
//! release-ops builder, hand-built APK/ELF/ES documents. Used by `tests/monitor.rs` (the rule
//! engine) and `tests/archive.rs` (the archive walker).

use std::path::PathBuf;

use ed25519_dalek::Signer;

pub use ghost_client_release::manifest::GHRM;
pub use ghost_client_release::root::GHRT;
pub use ghost_client_release::{SigBlock, SigEntry};
pub use ghost_entitlement::Schedule;
pub use ghost_verify::monitor::{
    run, ArchiveManifest, ArchiveReleaseFiles, DecodedLeaf, Finding, LeafDoc, MonitorInput,
    Observation, Served,
};

pub const NOW: u64 = 1_900_000_000;
pub const DAY: u32 = (NOW / 86_400) as u32;

pub fn sha256(b: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(b).into()
}

pub fn onion(seed: &str) -> String {
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

pub fn hex16(byte: u8) -> String {
    hex::encode([byte; 16])
}

pub fn write(path: &std::path::Path, text: impl AsRef<[u8]>) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

pub struct World {
    pub dir: tempfile::TempDir,
    pub keys: PathBuf,
    pub root: PathBuf,
}

impl World {
    pub fn new() -> Self {
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

    pub fn release_key_id(&self) -> [u8; 32] {
        let pub_hex = std::fs::read_to_string(self.keys.join("release-1.pub")).unwrap();
        let pub_key = hex::decode(pub_hex.trim()).unwrap();
        sha256(&pub_key)
    }
}

pub fn le16v(v: u16) -> [u8; 2] {
    v.to_le_bytes()
}
pub fn le32v(v: u32) -> [u8; 4] {
    v.to_le_bytes()
}
pub fn le64v(v: u64) -> [u8; 8] {
    v.to_le_bytes()
}

pub fn eocd(cd_offset: u32, cd_size: u32) -> Vec<u8> {
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

/// A §6.5-conformant signed/unsigned APK pair with an EMPTY signing block: the rules hash
/// the file and its core, and the core extraction never parses the pairs, so none are needed.
pub fn apk_pair(content_e: usize) -> (Vec<u8>, Vec<u8>) {
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
/// the hand fixture: no toolchain, no build.rs, both files parametric in one id.
pub fn tiny_elf(id: &[u8]) -> Vec<u8> {
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
pub const TEST_ES: &[u8] =
    include_bytes!("../../../../issuer/crates/entitlement/tests/fixtures/test_schedule.ghes");

pub fn test_schedule_signing_key() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&sha256(b"ghost/test/schedule-key"))
}

pub fn test_schedule_key() -> [u8; 32] {
    test_schedule_signing_key().verifying_key().to_bytes()
}

/// The committed test ES re-signed with the test key after `edit` — rule (d)'s engine input,
/// exactly what the caller produces from an archived ES file it verified.
/// The committed test ES re-signed with an exact `seq` — the document bytes, for fixtures that
/// must hash to a name (the archive's files are named by SHA-256) or be embedded in a manifest.
pub fn es_bytes_with_seq(seq: u64) -> Vec<u8> {
    let base = Schedule::verify_with_key(TEST_ES, &test_schedule_key()).unwrap();
    let mut content = base.content().clone();
    content.seq = seq;
    let body = content.body().unwrap();
    let msg = [ghost_entitlement::schedule::SIGNATURE_DOMAIN, &body].concat();
    let sig = test_schedule_signing_key().sign(&msg);
    let mut doc = body.clone();
    doc.extend_from_slice(&sig.to_bytes());
    Schedule::verify_with_key(&doc, &test_schedule_key()).unwrap();
    doc
}

pub fn es_doc(
    edit: impl FnOnce(&mut ghost_entitlement::schedule::ScheduleContent),
) -> (u64, Schedule) {
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

pub struct RelCfg {
    pub version_code: u32,
    pub salt: u8,
    pub permille: u16,
    pub wire: bool,
    /// Declare a different unsigned build than the file names (rule (c)'s core mutation):
    /// the manifest's `unsigned_sha256`/`unsigned_length` overrides, no file read.
    pub unsigned_override: Option<([u8; 32], u64)>,
}

impl RelCfg {
    pub fn plain(version_code: u32) -> Self {
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
    pub fn build_manifest(
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
        // The manifest's es_seq is 2957 (below); embed a re-signed test ES at exactly that
        // seq so the archive walker's declared-vs-document check (rule (d)'s input) agrees.
        let es_file = dir.join("es.ghes");
        write(&es_file, es_bytes_with_seq(2957));
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
pub fn resign_manifest(w: &World, doc: &[u8], edit: impl FnOnce(&mut GHRM)) -> Vec<u8> {
    use ed25519_dalek::Signer as _;
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
pub struct Green {
    pub manifest: Vec<u8>,
    pub root_doc: Vec<u8>,
    pub signed: Vec<u8>,
    pub lib: Vec<u8>,
    pub sym: Vec<u8>,
    pub es: Vec<(u64, Schedule)>,
}

pub fn green() -> (World, Green) {
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
pub fn green_entry<'a>(g: &'a Green, m: &'a GHRM, root: &'a GHRT) -> ArchiveManifest<'a> {
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
pub fn archive_findings(
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
        drill_keys: &[],
    };
    run(&input)
}
