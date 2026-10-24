//! End-to-end test of the stagenet channel builders: keygen → root-build (two roots) →
//! chain-build → proof-build → manifest-build (with the refusal rules exercised) → bundle.
//! Uses only software keys and synthetic single-leaf proofs (the real log submission is
//! RK1/V-D11b); every document is re-parsed and self-verified by the builders themselves.

use std::path::Path;
use std::process::Command;

use ghost_client_release::bundle::GHRB;
use ghost_client_release::chain::GHRC;
use ghost_client_release::manifest::GHRM;
use ghost_client_release::root::GHRT;
use ghost_release_ops::build;

fn bin() -> Command {
    // The same logic is linked into the lib; the binary wiring is exercised separately in CI.
    Command::new(env!("CARGO_BIN_EXE_ghost-release-ops"))
}

/// A valid v3 onion string for `seed`, port 443 (RFC 4648 base32 of pubkey‖checksum‖version).
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
    // Base32 without padding, lowercase.
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

fn hex16_of(byte: u8) -> String {
    hex::encode([byte; 16])
}

fn write(path: &Path, text: impl AsRef<[u8]>) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

fn root_config(version: u32, onion_a: &str, onion_b: &str) -> String {
    format!(
        r#"network = 2
version = {version}
apk_signers = ["7777777777777777777777777777777777777777777777777777777777777777"]
witnesses = ["witness-1"]
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
onion = "{onion_a}"
operator = "{}"
[[anchor_mirrors]]
onion = "{onion_b}"
operator = "{}"
"#,
        hex16_of(0x11),
        hex16_of(0x22)
    )
}

fn setup_release_files(dir: &Path) {
    write(&dir.join("app.apk"), b"fake-signed-apk");
    write(&dir.join("app-unsigned.apk"), b"fake-unsigned-apk");
    write(&dir.join("escrow.tar.gz"), b"fake-escrow");
    write(&dir.join("es.json"), b"fake-es-file");
}

fn manifest_source(dir: &Path, seq: u64, issued: u32, relay_onion: &str, mirror_onion: &str) -> String {
    let rel = dir.join("rel");
    format!(
        r#"seq = {seq}
issued_day = {issued}
not_after_day = {issued_after}
floor_version_code = 0
[[release]]
version_code = 1
version_name = "0.9.0-stg1"
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
[[mirror]]
onion = "{mirror}"
operator = "{mop}"
[[relay]]
onion = "{relay}"
operator = "{rop}"
"#,
        issued_after = issued + 30,
        apk = rel.join("app.apk").display(),
        unsigned = rel.join("app-unsigned.apk").display(),
        salt = hex16_of(0x33),
        commit = "ab".repeat(20),
        es = rel.join("es.json").display(),
        escrow = rel.join("escrow.tar.gz").display(),
        mirror = mirror_onion,
        mop = hex16_of(0x44),
        relay = relay_onion,
        rop = hex16_of(0x55),
    )
}

#[test]
fn full_channel_build() {
    let dir = tempfile::tempdir().unwrap();
    let dir = dir.path();
    let keys = dir.join("keys");
    let rel = dir.join("rel");
    std::fs::create_dir_all(&rel).unwrap();
    setup_release_files(&rel);

    let out = build::keygen(&keys, "root:2,release:1,attest:1,apk:1,log:1,witness:1").unwrap();
    assert!(out.starts_with("KEYS_BUILT n=7"), "{out}");

    let onion_a = onion("mirror-a");
    let onion_b = onion("mirror-b");
    let (first, second) = if onion_a < onion_b { (onion_a, onion_b) } else { (onion_b, onion_a) };

    // Two roots (v1, v2), each signed by the root set.
    let roots = dir.join("roots");
    std::fs::create_dir_all(&roots).unwrap();
    let cfg1 = dir.join("root-1.toml");
    write(&cfg1, &root_config(1, &first, &second));
    let out = build::root_build(&cfg1, &keys, &roots.join("root-1.ghrt")).unwrap();
    assert!(out.starts_with("ROOT_BUILT version=1"), "{out}");
    let cfg2 = dir.join("root-2.toml");
    write(&cfg2, &root_config(2, &first, &second));
    let out = build::root_build(&cfg2, &keys, &roots.join("root-2.ghrt")).unwrap();
    assert!(out.starts_with("ROOT_BUILT version=2"), "{out}");

    let chain_path = dir.join("chain.ghrc");
    let out = build::chain_build(2, &roots, &chain_path).unwrap();
    assert!(out.starts_with("CHAIN_BUILT first=1 count=2"), "{out}");

    // Proof over the second root (the first needs no proof — the client trusts it).
    let root_proof = dir.join("root-2.ghrp");
    let out = build::proof_build(
        &roots.join("root-2.ghrt"),
        0,
        "log-1",
        "release-1",
        &["witness-1".to_string()],
        Some(1_900_000_000),
        &keys,
        &root_proof,
    )
    .unwrap();
    assert!(out.starts_with("PROOF_BUILT log=0"), "{out}");

    // Manifest: seq 1, then seq 2 over the second root.
    let src1 = dir.join("manifest-1.toml");
    write(&src1, &manifest_source(dir, 1, 20_600, &onion("relay-a"), &onion("mirror-x")));
    let m1 = dir.join("m1.ghrm");
    let out = build::manifest_build(
        &src1,
        &roots.join("root-1.ghrt"),
        &keys,
        &["attest-1".to_string()],
        None,
        &m1,
    )
    .unwrap();
    assert!(out.starts_with("MANIFEST_BUILT seq=1"), "{out}");

    let src2 = dir.join("manifest-2.toml");
    write(&src2, &manifest_source(dir, 2, 20_601, &onion("relay-a"), &onion("mirror-x")));
    let m2 = dir.join("m2.ghrm");
    let out = build::manifest_build(
        &src2,
        &roots.join("root-2.ghrt"),
        &keys,
        &["attest-1".to_string()],
        Some(&m1),
        &m2,
    )
    .unwrap();
    assert!(out.starts_with("MANIFEST_BUILT seq=2"), "{out}");

    // Refusals: a non-increasing sequence and a below-previous issued day.
    let bad_seq = dir.join("bad-seq.toml");
    write(&bad_seq, &manifest_source(dir, 2, 20_602, &onion("relay-a"), &onion("mirror-x")));
    let err = build::manifest_build(
        &bad_seq,
        &roots.join("root-2.ghrt"),
        &keys,
        &["attest-1".to_string()],
        Some(&m2),
        &dir.join("bad.ghrm"),
    )
    .unwrap_err();
    assert!(err.contains("manifest_seq"), "{err}");
    let bad_day = dir.join("bad-day.toml");
    write(&bad_day, &manifest_source(dir, 3, 20_500, &onion("relay-a"), &onion("mirror-x")));
    let err = build::manifest_build(
        &bad_day,
        &roots.join("root-2.ghrt"),
        &keys,
        &["attest-1".to_string()],
        Some(&m2),
        &dir.join("bad2.ghrm"),
    )
    .unwrap_err();
    assert!(err.contains("issued_day"), "{err}");

    // Manifest proof and the bundle.
    let m2_proof = dir.join("m2.ghrp");
    let out = build::proof_build(
        &m2,
        0,
        "log-1",
        "release-1",
        &["witness-1".to_string()],
        Some(1_900_000_000),
        &keys,
        &m2_proof,
    )
    .unwrap();
    assert!(out.starts_with("PROOF_BUILT"), "{out}");

    let bundle_path = dir.join("current.ghrb");
    let out = build::bundle(
        &chain_path,
        &[root_proof],
        &m2,
        &m2_proof,
        &bundle_path,
    )
    .unwrap();
    assert!(out.starts_with("BUNDLE_BUILT"), "{out}");

    // Everything a mirror serves re-parses from the exact bytes on disk.
    let bytes = std::fs::read(&bundle_path).unwrap();
    let bundle = GHRB::parse(&bytes).unwrap();
    assert_eq!(bundle.network, 2);
    assert_eq!(bundle.chain.roots.len(), 2);
    assert_eq!(bundle.manifest.body.manifest_seq, 2);
    GHRC::parse(&std::fs::read(&chain_path).unwrap()).unwrap();
    GHRM::parse(&std::fs::read(&m2).unwrap()).unwrap();
    GHRT::parse(&std::fs::read(&roots.join("root-2.ghrt")).unwrap()).unwrap();

    // The binary wiring answers on the same vocabulary.
    let out = bin()
        .arg("chain-build")
        .arg("--network")
        .arg("2")
        .arg("--roots")
        .arg(&roots)
        .arg("--out")
        .arg(dir.join("chain2.ghrc"))
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8(out.stdout).unwrap().starts_with("CHAIN_BUILT"));
}

#[test]
fn root_build_rejects_bad_onion() {
    let dir = tempfile::tempdir().unwrap();
    let keys = dir.path().join("keys");
    build::keygen(&keys, "root:2,release:1,attest:1,apk:1,log:1,witness:1").unwrap();
    let cfg = dir.path().join("bad.toml");
    write(
        &cfg,
        &root_config(1, "NOTANONION", &onion("mirror-b"))
            .replace(&onion("mirror-b"), &onion("mirror-a")),
    );
    let err = build::root_build(&cfg, &keys, &dir.path().join("out.ghrt")).unwrap_err();
    assert!(err.contains("anchor mirror"), "{err}");
}

#[test]
fn bundle_rejects_wrong_proof_count() {
    let dir = tempfile::tempdir().unwrap();
    let keys = dir.path().join("keys");
    build::keygen(&keys, "root:2,release:1,attest:1,apk:1,log:1,witness:1").unwrap();
    let roots = dir.path().join("roots");
    std::fs::create_dir_all(&roots).unwrap();
    let cfg = dir.path().join("root-1.toml");
    let oa = onion("m-a");
    let ob = onion("m-b");
    let (first, second) = if oa < ob { (oa, ob) } else { (ob, oa) };
    write(&cfg, &root_config(1, &first, &second));
    build::root_build(&cfg, &keys, &roots.join("root-1.ghrt")).unwrap();
    let chain = dir.path().join("c.ghrc");
    build::chain_build(2, &roots, &chain).unwrap();
    // Two roots are needed before a root proof exists; with one root any proof list is wrong.
    let err = build::bundle(
        &chain,
        &[dir.path().join("nonexistent.ghrp")],
        &roots.join("root-1.ghrt"), // not a manifest; the count check fires first
        &roots.join("root-1.ghrt"),
        &dir.path().join("b.ghrb"),
    )
    .unwrap_err();
    assert!(err.contains("root proofs"), "{err}");
}
