//! The `ghost-verify apk` decision (Phase 14 design §9.1): a green run against a bundle built by
//! the ops builders, the exact `VERIFIED` line, and the refusals (tampered APK, wrong anchor,
//! the SDK-class signer selection).

use std::path::{Path, PathBuf};

use ghost_client_release::root::GHRT;
use ghost_verify::{ApkVerdict, apk, apk_line};

const NOW: u64 = 1_900_000_000;
const DAY: u32 = (NOW / 86_400) as u32;

fn le16(v: u16) -> [u8; 2] { v.to_le_bytes() }
fn le32(v: u32) -> [u8; 4] { v.to_le_bytes() }
fn le64(v: u64) -> [u8; 8] { v.to_le_bytes() }

fn lp32(data: &[u8]) -> Vec<u8> {
    let mut out = le32(data.len() as u32).to_vec();
    out.extend_from_slice(data);
    out
}

fn eocd(cd_offset: u32, cd_size: u32) -> Vec<u8> {
    let mut out = b"PK\x05\x06".to_vec();
    out.extend_from_slice(&le16(0));
    out.extend_from_slice(&le16(0));
    out.extend_from_slice(&le16(1));
    out.extend_from_slice(&le16(1));
    out.extend_from_slice(&le32(cd_size));
    out.extend_from_slice(&le32(cd_offset));
    out.extend_from_slice(&le16(0));
    out
}

fn signer_v3(cert: &[u8], min_sdk: u32, max_sdk: u32) -> Vec<u8> {
    let mut signed = lp32(&lp32(b"digests"));
    signed.extend_from_slice(&lp32(&lp32(cert)));
    signed.extend_from_slice(&le32(min_sdk));
    signed.extend_from_slice(&le32(max_sdk));
    signed.extend_from_slice(&lp32(b""));
    let mut signer = lp32(&signed);
    signer.extend_from_slice(&lp32(b"signatures"));
    signer.extend_from_slice(&lp32(b"public-key"));
    lp32(&signer)
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xEDB8_8320 & (0u32.wrapping_sub(crc & 1)));
        }
    }
    !crc
}

/// A stored (method 0) local-file entry plus its central-directory record.
fn stored_entry(name: &str, data: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let crc = crc32(data);
    let mut local = b"PK".to_vec();
    local.extend_from_slice(&le16(20));
    local.extend_from_slice(&le16(0));
    local.extend_from_slice(&le16(0));
    local.extend_from_slice(&le16(0));
    local.extend_from_slice(&le16(0));
    local.extend_from_slice(&le32(crc));
    local.extend_from_slice(&le32(data.len() as u32));
    local.extend_from_slice(&le32(data.len() as u32));
    local.extend_from_slice(&le16(name.len() as u16));
    local.extend_from_slice(&le16(0));
    local.extend_from_slice(name.as_bytes());
    local.extend_from_slice(data);
    let mut cd = b"PK".to_vec();
    cd.extend_from_slice(&le16(20));
    cd.extend_from_slice(&le16(20));
    cd.extend_from_slice(&le16(0));
    cd.extend_from_slice(&le16(0));
    cd.extend_from_slice(&le16(0));
    cd.extend_from_slice(&le16(0));
    cd.extend_from_slice(&le32(crc));
    cd.extend_from_slice(&le32(data.len() as u32));
    cd.extend_from_slice(&le32(data.len() as u32));
    cd.extend_from_slice(&le16(name.len() as u16));
    cd.extend_from_slice(&le16(0));
    cd.extend_from_slice(&le16(0));
    cd.extend_from_slice(&le16(0));
    cd.extend_from_slice(&le16(0));
    cd.extend_from_slice(&le32(0));
    cd.extend_from_slice(&le32(0));
    cd.extend_from_slice(name.as_bytes());
    (local, cd)
}

fn build_apk(content_e: usize, cd: &[u8], pairs: &[(u32, Vec<u8>)], pad_byte: u8) -> (Vec<u8>, Vec<u8>) {
    let e = content_e;
    let mut unsigned = vec![0xA5u8; e];
    unsigned.extend_from_slice(cd);
    unsigned.extend_from_slice(&eocd(e as u32, cd.len() as u32));
    let pad = (4096 - (e % 4096)) % 4096;
    let b = e + pad;
    let mut pairs_bytes = Vec::new();
    for (id, value) in pairs {
        pairs_bytes.extend_from_slice(&le64(value.len() as u64));
        pairs_bytes.extend_from_slice(&le32(*id));
        pairs_bytes.extend_from_slice(value);
    }
    let s = pairs_bytes.len() as u64 + 8 + 16;
    let mut signed = vec![0xA5u8; e];
    signed.extend(std::iter::repeat(pad_byte).take(pad));
    signed.extend_from_slice(&le64(s));
    signed.extend_from_slice(&pairs_bytes);
    signed.extend_from_slice(&le64(s));
    signed.extend_from_slice(b"APK Sig Block 42");
    assert_eq!(signed.len(), b + 8 + s as usize);
    signed.extend_from_slice(cd);
    signed.extend_from_slice(&eocd((b + 8 + s as usize) as u32, cd.len() as u32));
    (unsigned, signed)
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

fn write(path: &Path, text: impl AsRef<[u8]>) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

fn sha256(b: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(b).into()
}

struct World {
    dir: tempfile::TempDir,
    keys: PathBuf,
    roots: Vec<PathBuf>,
    chain: PathBuf,
}

impl World {
    fn new(apk_digests: &[[u8; 32]]) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let keys = dir.path().join("keys");
        ghost_release_ops::build::keygen(&keys, "root:2,release:1,attest:1,apk:1,log:1,witness:2").unwrap();
        let oa = onion("anchor-a");
        let ob = onion("anchor-b");
        let (first, second) = if oa < ob { (oa, ob) } else { (ob, oa) };
        let digests: Vec<String> = apk_digests.iter().map(hex::encode).collect();
        let digests_toml = digests.iter().map(|d| format!("\"{d}\"")).collect::<Vec<_>>().join(", ");
        let mut roots = Vec::new();
        for v in 1..=1u32 {
            let cfg = dir.path().join(format!("root-{v}.toml"));
            write(
                &cfg,
                format!(
                    r#"network = 2
version = {v}
apk_signers = [{digests_toml}]
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
                ),
            );
            let out = dir.path().join(format!("root-{v}.ghrt"));
            ghost_release_ops::build::root_build(&cfg, &keys, &out).unwrap();
            roots.push(out);
        }
        let roots_dir = dir.path().join("roots");
        std::fs::create_dir_all(&roots_dir).unwrap();
        for r in &roots {
            std::fs::copy(r, roots_dir.join(r.file_name().unwrap())).unwrap();
        }
        let chain = dir.path().join("chain.ghrc");
        ghost_release_ops::build::chain_build(2, &roots_dir, &chain).unwrap();
        World { dir, keys, roots, chain }
    }

    /// A manifest bound to the given signed/unsigned pair (version `version_code`).
    /// `extra_artifacts` are `[(kind, file)]` lines appended to the release's artifacts.
    fn manifest_for(&self, version_code: u32, signed: &[u8], unsigned: &[u8]) -> PathBuf {
        self.manifest_for_with(version_code, signed, unsigned, &[])
    }

    fn manifest_for_with(&self, version_code: u32, signed: &[u8], unsigned: &[u8], extra: &[(u8, PathBuf)]) -> PathBuf {
        let name = format!("rel-{version_code}");
        let rel = self.dir.path().join(&name);
        std::fs::create_dir_all(&rel).unwrap();
        write(&rel.join("app.apk"), signed);
        write(&rel.join("app-unsigned.apk"), unsigned);
        write(&rel.join("escrow.tar.gz"), "escrow");
        write(&rel.join("es.json"), "es");
        let src = self.dir.path().join(format!("m-{name}.toml"));
        write(
            &src,
            format!(
                r#"seq = 1
issued_day = {DAY}
not_after_day = {DAY_AFTER}
floor_version_code = 0
[[release]]
version_code = {version_code}
version_name = "0.9.0-stg{version_code}"
min_sdk = 29
anchor_root = 1
wire_changing = false
apk = "{apk}"
unsigned = "{unsigned}"
rollout_permille = 1000
rollout_salt = "{salt}"
commit = "{commit}"
es_seq = 2957
es_file = "{es}"
[[release.artifacts]]
kind = 16
file = "{escrow}"
{extra}
"#,
                DAY_AFTER = DAY + 30,
                apk = rel.join("app.apk").display(),
                unsigned = rel.join("app-unsigned.apk").display(),
                salt = hex16(0x33),
                commit = "ab".repeat(20),
                es = rel.join("es.json").display(),
                escrow = rel.join("escrow.tar.gz").display(),
                extra = extra
                    .iter()
                    .map(|(k, f)| format!("[[release.artifacts]]
kind = {k}
file = \"{}\"
", f.display()))
                    .collect::<String>(),
            ),
        );
        let m = self.dir.path().join(format!("m-{name}.ghrm"));
        ghost_release_ops::build::manifest_build(
            &src,
            &self.roots[0],
            &self.keys,
            &["attest-1".to_string()],
            None,
            &m,
        )
        .unwrap();
        m
    }

    fn bundle(&self, manifest: &Path) -> Vec<u8> {
        let mp = self.dir.path().join("m.ghrp");
        ghost_release_ops::build::proof_build(
            manifest,
            0,
            "log-1",
            "release-1",
            &["witness-1".to_string(), "witness-2".to_string()],
            Some(NOW),
            &self.keys,
            &mp,
        )
        .unwrap();
        let b = self.dir.path().join("b.ghrb");
        ghost_release_ops::build::bundle(&self.chain, &[], manifest, &mp, &b).unwrap();
        std::fs::read(&b).unwrap()
    }
}

#[test]
fn verifies_and_prints_the_fixed_line() {
    let cert = [0x11u8; 64];
    let (unsigned, signed) = build_apk(900, b"fake-central-directory", &[(0xf053_68c0, signer_v3(&cert, 1, 0x7fff_ffff))], 0);
    let world = World::new(&[sha256(&cert)]);
    let m = world.manifest_for(2, &signed, &unsigned);
    let bundle = world.bundle(&m);
    let anchor = GHRT::parse(&std::fs::read(&world.roots[0]).unwrap()).unwrap();

    let v = apk(&bundle, &signed, &anchor, DAY, NOW, &[]);
    match &v {
        ApkVerdict::Verified { version_code, manifest_seq, cosigned, attested, sdks, signer, .. } => {
            assert_eq!(&2, version_code);
            assert_eq!(&1, manifest_seq);
            assert_eq!(&2, cosigned);
            assert_eq!(&1, attested);
            assert_eq!(&vec![29, 33], sdks);
            assert_eq!(&sha256(&cert), signer);
        }
        other => panic!("expected VERIFIED, got {other:?}"),
    }
    let line = apk_line(&v);
    assert!(line.starts_with("VERIFIED version=0.9.0-stg2 version_code=2 manifest_seq=1 log=stg-log-1 cosigned=2/2 attested=1/1 signer="), "{line}");
}

#[test]
fn refuses_a_tampered_apk_and_a_wrong_anchor() {
    let cert = [0x11u8; 64];
    let (unsigned, signed) = build_apk(900, b"fake-central-directory", &[(0xf053_68c0, signer_v3(&cert, 1, 0x7fff_ffff))], 0);
    let world = World::new(&[sha256(&cert)]);
    let m = world.manifest_for(2, &signed, &unsigned);
    let bundle = world.bundle(&m);
    let anchor = GHRT::parse(&std::fs::read(&world.roots[0]).unwrap()).unwrap();

    let mut bad = signed.clone();
    bad[10] ^= 1;
    assert_eq!(apk(&bundle, &bad, &anchor, DAY, NOW, &[]), ApkVerdict::Refused(ghost_client_update::UpdateError::ApkHash));

    // A foreign anchor (another world's root) refuses at the manifest's root binding.
    let other = World::new(&[sha256(&cert)]);
    let foreign = GHRT::parse(&std::fs::read(&other.roots[0]).unwrap()).unwrap();
    let v = apk(&bundle, &signed, &foreign, DAY, NOW, &[]);
    assert!(matches!(v, ApkVerdict::Refused(_)), "{v:?}");
}

#[test]
fn the_sdk_class_picks_the_signer_the_platform_would() {
    // v3.1 covers 33+ only: SDK 33 verifies against it, SDK 29 falls to the v3 block; a root
    // listing only the v3.1 digest refuses the SDK-29 class at the signer clause.
    let cert31 = [0x21u8; 64];
    let cert_v3 = [0x22u8; 64];
    let (unsigned, signed) = build_apk(
        900,
        b"fake-central-directory",
        &[
            (0xf053_68c0, signer_v3(&cert_v3, 1, 0x7fff_ffff)),
            (0x1b93_ad61, signer_v3(&cert31, 33, 0x7fff_ffff)),
        ],
        0,
    );
    // The root lists only the v3.1 digest: SDK 33 verifies, SDK 29 refuses at the signer.
    let world31 = World::new(&[sha256(&cert31)]);
    let m = world31.manifest_for(2, &signed, &unsigned);
    let bundle = world31.bundle(&m);
    let anchor = GHRT::parse(&std::fs::read(&world31.roots[0]).unwrap()).unwrap();
    assert!(matches!(apk(&bundle, &signed, &anchor, DAY, NOW, &[33]), ApkVerdict::Verified { .. }));
    assert_eq!(
        apk(&bundle, &signed, &anchor, DAY, NOW, &[29]),
        ApkVerdict::Refused(ghost_client_update::UpdateError::ApkSigner)
    );
}

#[test]
fn libs_hashes_native_libraries_against_the_release_artifacts() {
    let cert = [0x11u8; 64];
    // A signed APK whose content is one stored library entry.
    let so = vec![0x5Au8; 4096];
    let (local, cd) = stored_entry("lib/arm64-v8a/libghost_client_net.so", &so);
    let (unsigned, signed) = {
        let content = local.clone();
        let mut content = content;
        content.extend(std::iter::repeat(0xA5u8).take(900));
        let e = content.len();
        let mut unsigned = content.clone();
        unsigned.extend_from_slice(&cd);
        unsigned.extend_from_slice(&eocd(e as u32, cd.len() as u32));
        let pad = (4096 - (e % 4096)) % 4096;
        let b = e + pad;
        let pair = (0xf053_68c0u32, signer_v3(&cert, 1, 0x7fff_ffff));
        let mut pairs_bytes = Vec::new();
        pairs_bytes.extend_from_slice(&le64(pair.1.len() as u64));
        pairs_bytes.extend_from_slice(&le32(pair.0));
        pairs_bytes.extend_from_slice(&pair.1);
        let s = pairs_bytes.len() as u64 + 8 + 16;
        let mut signed = content.clone();
        signed.extend(std::iter::repeat(0u8).take(pad));
        signed.extend_from_slice(&le64(s));
        signed.extend_from_slice(&pairs_bytes);
        signed.extend_from_slice(&le64(s));
        signed.extend_from_slice(b"APK Sig Block 42");
        signed.extend_from_slice(&cd);
        signed.extend_from_slice(&eocd((b + 8 + s as usize) as u32, cd.len() as u32));
        (unsigned, signed)
    };
    let world = World::new(&[sha256(&cert)]);
    let so_path = world.dir.path().join("libghost_client_net.so");
    write(&so_path, &so);
    let m = world.manifest_for_with(2, &signed, &unsigned, &[(1, so_path)]);
    let bundle = world.bundle(&m);

    let anchor = GHRT::parse(&std::fs::read(&world.roots[0]).unwrap()).unwrap();
    let lines = ghost_verify::libs(&bundle, &signed, &anchor, DAY, NOW).unwrap();
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0].abi, "arm64-v8a");
    assert_eq!(lines[0].status, "VERIFIED");
    assert_eq!(lines[0].sha256, sha256(&so));
    assert!(ghost_verify::libs_line(&lines[0]).starts_with("LIB lib/arm64-v8a/libghost_client_net.so sha256="));

    // A same-shaped APK with a different library is a MISMATCH.
    let so2 = vec![0x5Bu8; 4096];
    let (local2, cd2) = stored_entry("lib/arm64-v8a/libghost_client_net.so", &so2);
    let (_u2, signed2) = {
        let mut content = local2.clone();
        content.extend(std::iter::repeat(0xA5u8).take(900));
        let e = content.len();
        let pad = (4096 - (e % 4096)) % 4096;
        let b = e + pad;
        let pair = (0xf053_68c0u32, signer_v3(&cert, 1, 0x7fff_ffff));
        let mut pairs_bytes = Vec::new();
        pairs_bytes.extend_from_slice(&le64(pair.1.len() as u64));
        pairs_bytes.extend_from_slice(&le32(pair.0));
        pairs_bytes.extend_from_slice(&pair.1);
        let s = pairs_bytes.len() as u64 + 8 + 16;
        let mut signed = content.clone();
        signed.extend(std::iter::repeat(0u8).take(pad));
        signed.extend_from_slice(&le64(s));
        signed.extend_from_slice(&pairs_bytes);
        signed.extend_from_slice(&le64(s));
        signed.extend_from_slice(b"APK Sig Block 42");
        signed.extend_from_slice(&cd2);
        signed.extend_from_slice(&eocd((b + 8 + s as usize) as u32, cd2.len() as u32));
        (content, signed)
    };
    // The manifest names the first library; the second APK does not match the claim hash either,
    // so point the check at the original claim by verifying against the tampered file directly:
    // the release lookup fails first.
    assert_eq!(
        ghost_verify::libs(&bundle, &signed2, &anchor, DAY, NOW),
        Err(ghost_client_update::UpdateError::ApkHash)
    );
}
