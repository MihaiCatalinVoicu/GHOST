//! `records-check` (G-D4 clauses (a)–(c)) over a synthetic network directory: the two-root
//! chain verifies, the committed certificate's digest is in the newest root's `apk_signers`,
//! and the committed `anchor-mirrors.txt` equals the root's mirror set. Every clause also gets
//! one mutation that must fail closed. Software keys only (keygen reads /dev/urandom, so the
//! suite runs where the other ops tests do).

use std::path::Path;

use ghost_release_ops::records::records_check;

/// A valid v3 onion string for `seed`, port 443 (same helper as tests/build.rs).
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

fn hex16_of(byte: u8) -> String {
    hex::encode([byte; 16])
}

fn sha256_hex(b: &[u8]) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(b))
}

fn write(path: impl AsRef<Path>, text: impl AsRef<[u8]>) {
    let path = path.as_ref();
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

/// Root config: `network`, `version`, the apk-signer digest list, and the anchor mirrors.
fn root_config(
    version: u32,
    network: u32,
    apk_signers: &[String],
    mirrors: &[(String, String)],
) -> String {
    let mut s = format!(
        r#"network = {network}
version = {version}
apk_signers = [{signers}]
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
"#,
        signers = apk_signers
            .iter()
            .map(|d| format!("\"{d}\""))
            .collect::<Vec<_>>()
            .join(", ")
    );
    for (on, op) in mirrors {
        s.push_str(&format!(
            "[[anchor_mirrors]]\nonion = \"{on}\"\noperator = \"{op}\"\n"
        ));
    }
    s
}

/// Root config for mainnet: the format's §4.3 mainnet rules require >= 3 root keys
/// (threshold >= 2), >= 3 witnesses with quorum >= 2.
fn mainnet_root_config(
    version: u32,
    apk_signers: &[String],
    mirrors: &[(String, String)],
) -> String {
    let mut s = format!(
        r#"network = 1
version = {version}
apk_signers = [{signers}]
witnesses = ["witness-1", "witness-2", "witness-3"]
quorum = 2
[root]
keys = ["root-1", "root-2", "root-3"]
threshold = 2
[release]
keys = ["release-1"]
threshold = 1
[attest]
keys = ["attest-1"]
threshold = 1
[[logs]]
key = "log-1"
origin = "m-log-1"
"#,
        signers = apk_signers
            .iter()
            .map(|d| format!("\"{d}\""))
            .collect::<Vec<_>>()
            .join(", ")
    );
    for (on, op) in mirrors {
        s.push_str(&format!(
            "[[anchor_mirrors]]\nonion = \"{on}\"\noperator = \"{op}\"\n"
        ));
    }
    s
}

/// The committed anchor-mirrors.txt: one `mirror <onion:port> <operator hex>` line per entry.
fn anchors_txt(mirrors: &[(String, String)]) -> String {
    mirrors
        .iter()
        .map(|(on, op)| format!("mirror {on} {op}"))
        .collect::<Vec<_>>()
        .join("\n")
        + "\n"
}

struct Fixture {
    tmp: tempfile::TempDir,
    netdir: std::path::PathBuf,
}

/// A `<tmp>/<network>/` directory with one keyset and two roots (v1 loose, v2 under roots/),
/// the certificate committed, and `apk_signers`/anchor mirrors per `signers`/`mirrors`.
fn fixture(network: &str, signers: &[String], mirrors: &[(String, String)]) -> Fixture {
    let tmp = tempfile::tempdir().unwrap();
    let netdir = tmp.path().join(network);
    std::fs::create_dir_all(&netdir).unwrap();
    let mainnet = network == "mainnet";
    let keys = tmp.path().join("keys");
    build_keygen(&keys, mainnet);

    let network_byte: u32 = match network {
        "mainnet" => 1,
        "stagenet" => 2,
        _ => 3,
    };
    let roots = netdir.join("roots");
    std::fs::create_dir_all(&roots).unwrap();
    for (version, out) in [
        (1u32, netdir.join("root-1.ghrt")),
        (2, roots.join("root-2.ghrt")),
    ] {
        let cfg = tmp.path().join(format!("root-{version}.toml"));
        let text = if mainnet {
            mainnet_root_config(version, signers, mirrors)
        } else {
            root_config(version, network_byte, signers, mirrors)
        };
        write(&cfg, text);
        build_root(&cfg, &keys, &out);
    }
    Fixture { tmp, netdir }
}

fn build_keygen(keys: &Path, mainnet: bool) {
    // Mainnet's format rules need a third root key and three witnesses.
    let spec = if mainnet {
        "root:3,release:1,attest:1,apk:1,log:1,witness:3"
    } else {
        "root:2,release:1,attest:1,apk:1,log:1,witness:1"
    };
    let out = ghost_release_ops::build::keygen(keys, spec).unwrap();
    assert!(out.starts_with("KEYS_BUILT"), "{out}");
}

fn build_root(cfg: &Path, keys: &Path, out: &Path) {
    let out_line = ghost_release_ops::build::root_build(cfg, keys, out).unwrap();
    assert!(out_line.starts_with("ROOT_BUILT"), "{out_line}");
}

fn two_mirrors() -> Vec<(String, String)> {
    let mut m = vec![
        (onion("mirror-a"), hex16_of(0x11)),
        (onion("mirror-b"), hex16_of(0x22)),
    ];
    m.sort();
    m
}

#[test]
fn chain_signers_anchors_pass() {
    let cert = b"-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n";
    let digest = sha256_hex(cert);
    let mirrors = two_mirrors();
    let f = fixture("stagenet", &[digest], &mirrors);
    write(f.netdir.join("apk-signer.crt"), cert);
    write(f.netdir.join("anchor-mirrors.txt"), anchors_txt(&mirrors));

    let out = records_check(&f.netdir).unwrap();
    assert!(out.contains("RECORDS_OK a roots=2 chain=1"), "{out}");
    assert!(out.contains("RECORDS_OK b signers=1"), "{out}");
    assert!(out.contains("RECORDS_OK c anchors=2 operators=2"), "{out}");
    assert!(
        out.contains("RECORDS_OK network=stagenet roots=2 newest=2 signers=1 anchors=2"),
        "{out}"
    );
}

#[test]
fn empty_directory_fails_closed() {
    let tmp = tempfile::tempdir().unwrap();
    let netdir = tmp.path().join("stagenet");
    std::fs::create_dir_all(&netdir).unwrap();

    let err = records_check(&netdir).unwrap_err();
    assert!(err.contains("RECORDS_FAIL a"), "{err}");
    assert!(!err.contains("RECORDS_OK network="), "{err}");
}

#[test]
fn rotated_root_keyset_fails() {
    let cert = b"fake-cert";
    let digest = sha256_hex(cert);
    let mirrors = two_mirrors();
    let f = fixture("stagenet", std::slice::from_ref(&digest), &mirrors);

    // Rebuild root v2 with a SECOND keyset: it no longer verifies under root v1's keyset.
    let keys2 = f.tmp.path().join("keys-rotated");
    build_keygen(&keys2, false);
    let cfg2 = f.tmp.path().join("root-2-rotated.toml");
    write(&cfg2, root_config(2, 2, &[digest], &mirrors));
    build_root(&cfg2, &keys2, &f.netdir.join("roots").join("root-2.ghrt"));

    let err = records_check(&f.netdir).unwrap_err();
    assert!(err.contains("RECORDS_FAIL a"), "{err}");
    assert!(err.contains("root 2 does not verify"), "{err}");
    assert!(!err.contains("RECORDS_OK network="), "{err}");
}

#[test]
fn unknown_certificate_fails_b() {
    let cert = b"fake-cert";
    let mirrors = two_mirrors();
    // The config lists a DIFFERENT digest than the committed certificate's.
    let f = fixture("stagenet", &["ab".repeat(32)], &mirrors);
    write(f.netdir.join("apk-signer.crt"), cert);

    let err = records_check(&f.netdir).unwrap_err();
    assert!(err.contains("RECORDS_FAIL b"), "{err}");
    assert!(!err.contains("RECORDS_OK network="), "{err}");
}

#[test]
fn drifted_anchor_mirrors_fail_c() {
    let cert = b"fake-cert";
    let digest = sha256_hex(cert);
    let mut mirrors = two_mirrors();
    let f = fixture("stagenet", &[digest], &mirrors);
    write(f.netdir.join("apk-signer.crt"), cert);
    // The file carries a mirror the newest root does not.
    mirrors.push((onion("mirror-c"), hex16_of(0x33)));
    write(f.netdir.join("anchor-mirrors.txt"), anchors_txt(&mirrors));

    let err = records_check(&f.netdir).unwrap_err();
    assert!(err.contains("RECORDS_FAIL c"), "{err}");
    assert!(err.contains("differ"), "{err}");
    assert!(!err.contains("RECORDS_OK network="), "{err}");
}

#[test]
fn embedded_chain_layout_passes() {
    // The layout of protocol/release/stagenet today: no loose *.ghrt, the roots live in
    // embedded-chain.ghrc only.
    let tmp = tempfile::tempdir().unwrap();
    let netdir = tmp.path().join("stagenet");
    std::fs::create_dir_all(&netdir).unwrap();
    let keys = tmp.path().join("keys");
    build_keygen(&keys, false);
    let mirrors = two_mirrors();

    let staged = tmp.path().join("staged-roots");
    std::fs::create_dir_all(&staged).unwrap();
    for v in [1u32, 2] {
        let cfg = tmp.path().join(format!("root-{v}.toml"));
        // The wire format requires >= 1 apk signer entry; clause (b) still skips (no *.crt).
        write(&cfg, root_config(v, 2, &["ab".repeat(32)], &mirrors));
        build_root(&cfg, &keys, &staged.join(format!("root-{v}.ghrt")));
    }
    let out =
        ghost_release_ops::build::chain_build(2, &staged, &netdir.join("embedded-chain.ghrc"))
            .unwrap();
    assert!(out.starts_with("CHAIN_BUILT first=1 count=2"), "{out}");

    let out = records_check(&netdir).unwrap();
    assert!(out.contains("RECORDS_OK a roots=2 chain=1"), "{out}");
    assert!(out.contains("RECORDS_SKIP b no-apk-signer-crt"), "{out}");
    assert!(
        out.contains("RECORDS_SKIP c no-anchor-mirrors-txt"),
        "{out}"
    );
    assert!(
        out.contains("RECORDS_OK network=stagenet roots=2 newest=2 signers=skip anchors=skip"),
        "{out}"
    );
}

#[test]
fn mainnet_two_operators_pass() {
    // GHRT::parse itself enforces the mainnet-only rules (>= 3 root keys, >= 2 operators,
    // §4.3), so a mainnet root with fewer operators is unbuildable — the format is the
    // negative test; records-check re-asserts the operator count defensively.
    let cert = b"fake-cert";
    let digest = sha256_hex(cert);
    let mirrors = two_mirrors();
    let f = fixture("mainnet", &[digest], &mirrors);
    write(f.netdir.join("apk-signer.crt"), cert);
    write(f.netdir.join("anchor-mirrors.txt"), anchors_txt(&mirrors));

    let out = records_check(&f.netdir).unwrap();
    assert!(out.contains("RECORDS_OK c anchors=2 operators=2"), "{out}");
    assert!(
        out.contains("RECORDS_OK network=mainnet roots=2 newest=2 signers=1 anchors=2"),
        "{out}"
    );
}
