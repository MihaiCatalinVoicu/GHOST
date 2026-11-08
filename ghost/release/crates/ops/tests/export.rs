//! `export-public` (design §6.1's `src/ghost-public-<tag>.tar`, D21, Q28): the exported
//! tree's file set, the MIT licence, the scrubbed identity surface, the pruned lock, the
//! fixed mtimes and entry order — and byte-identical output at one tag. The exported tree's
//! real `cargo build --locked` is the parent's cross-check (V-D2's A/B comparison).

use std::collections::BTreeMap;

use ghost_release_ops::export::export_public;

/// Walks the tar (the ustar subset export-public writes) into a name -> content map, in
/// entry order.
fn untar(bytes: &[u8]) -> Vec<(String, Vec<u8>, u64, u32)> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while off + 512 <= bytes.len() {
        let h = &bytes[off..off + 512];
        if h.iter().all(|&b| b == 0) {
            break;
        }
        let name = String::from_utf8_lossy(&h[..100])
            .trim_end_matches('\0')
            .to_string();
        let parse_octal = |f: &[u8]| -> u64 {
            let s = String::from_utf8_lossy(f)
                .trim_end_matches('\0')
                .trim()
                .to_string();
            u64::from_str_radix(&s, 8).unwrap()
        };
        let mode = parse_octal(&h[100..108]) as u32;
        let size = parse_octal(&h[124..136]) as usize;
        let mtime = parse_octal(&h[136..148]);
        let typeflag = h[156];
        off += 512;
        if typeflag == b'0' {
            out.push((name, bytes[off..off + size].to_vec(), mtime, mode));
        }
        off += size.div_ceil(512) * 512;
    }
    out
}

fn export_twice() -> (Vec<u8>, Vec<u8>) {
    let dir = tempfile::tempdir().unwrap();
    let a = export_public("v9.9.9-test", dir.path(), Some(1_234_567)).unwrap();
    let first = std::fs::read(dir.path().join("ghost-public-v9.9.9-test.tar")).unwrap();
    let b = export_public("v9.9.9-test", dir.path(), Some(1_234_567)).unwrap();
    let second = std::fs::read(dir.path().join("ghost-public-v9.9.9-test.tar")).unwrap();
    assert!(a.starts_with("EXPORT_PUBLIC path=") && a.contains("sha256="));
    assert_eq!(a, b, "the summary line is deterministic too");
    (first, second)
}

#[test]
fn two_exports_of_one_tag_are_byte_identical() {
    let (a, b) = export_twice();
    assert_eq!(a, b);
}

#[test]
fn the_tree_is_what_the_design_names() {
    let (tar, _) = export_twice();
    let entries = untar(&tar);
    let files: BTreeMap<String, (Vec<u8>, u64, u32)> = entries
        .iter()
        .map(|(n, b, m, mode)| (n.clone(), (b.clone(), *m, *mode)))
        .collect();

    // Fixed mtimes and modes on every entry, names sorted.
    for (name, (_, mtime, mode)) in &files {
        assert_eq!(*mtime, 1_234_567, "mtime of {name}");
        assert!(*mode == 0o644, "mode of {name}");
    }
    let names: Vec<&String> = files.keys().collect();
    let mut sorted = names.clone();
    sorted.sort();
    assert_eq!(names, sorted, "entries are sorted by path");

    // The file set: the workspace root files and the five members' sources.
    for expected in [
        "Cargo.toml",
        "Cargo.lock",
        "LICENSE",
        "README.md",
        "client-core/update/Cargo.toml",
        "client-core/update/src/lib.rs",
        "client-core/release/Cargo.toml",
        "client-core/release/src/lib.rs",
        "issuer/crates/blind-rsa/Cargo.toml",
        "issuer/crates/blind-rsa/src/lib.rs",
        "issuer/crates/entitlement/Cargo.toml",
        "issuer/crates/entitlement/src/lib.rs",
        "release/verify/Cargo.toml",
        "release/verify/src/lib.rs",
        "release/verify/src/main.rs",
    ] {
        assert!(files.contains_key(expected), "missing {expected}");
    }
    assert!(
        files
            .keys()
            .all(|n| !n.contains("tests/") && !n.contains("examples/")),
        "tests and examples stay private"
    );

    // The licence is MIT; no proprietary expression, no private repository anywhere.
    let license = &files["LICENSE"].0;
    assert!(String::from_utf8_lossy(license).contains("MIT License"));
    for (name, (body, _, _)) in &files {
        let text = String::from_utf8_lossy(body);
        assert!(
            !text.contains("LicenseRef-GHOST-Proprietary"),
            "proprietary licence in {name}"
        );
        assert!(!text.contains("MihaiCatalinVoicu"), "identity in {name}");
        assert!(
            !text.to_lowercase().contains("mihayyy175@gmail.com"),
            "email in {name}"
        );
        assert!(!text.contains("/home/runner/"), "runner path in {name}");
    }

    // The workspace root: MIT override, repository dropped, the members, no unused deps.
    let root = String::from_utf8_lossy(&files["Cargo.toml"].0).to_string();
    assert!(root.contains("resolver = \"2\""));
    assert!(root.contains("license = \"MIT\""));
    assert!(
        !root.contains("repository ="),
        "the private repository URL is dropped"
    );
    for member in [
        "client-core/update",
        "client-core/release",
        "issuer/crates/blind-rsa",
        "issuer/crates/entitlement",
        "release/verify",
    ] {
        assert!(root.contains(member), "member {member}");
    }
    for used in [
        "sha2",
        "hex",
        "ed25519-dalek",
        "hmac",
        "thiserror",
        "sha3",
        "ring",
        "num-bigint-dig",
        "curve25519-dalek",
    ] {
        assert!(root.contains(used), "workspace dependency {used}");
    }
    assert!(!root.contains("tonic"), "no dep the closure does not use");

    // Member manifests: dev-dependencies stripped (the public tree builds the tool).
    let verify_toml = String::from_utf8_lossy(&files["release/verify/Cargo.toml"].0).to_string();
    assert!(!verify_toml.contains("[dev-dependencies]"));
    assert!(!verify_toml.contains("ghost-release-ops"));

    // The pruned lock: the closure is in, the rest of the workspace is out.
    let lock = String::from_utf8_lossy(&files["Cargo.lock"].0).to_string();
    for present in [
        "ghost-verify",
        "ghost-client-update",
        "ghost-client-release",
        "ghost-entitlement",
        "ghost-blind-rsa",
        "ureq",
        "rustls",
    ] {
        assert!(lock.contains(present), "lock keeps {present}");
    }
    for absent in [
        "ghost-release-ops",
        "tokio",
        "arti-client",
        "tonic",
        // Dev-dependency edges of the original lock do not reach the public manifests
        // (ghost-blind-rsa's dev-only signer crate and its issuer-crypto tree).
        "blind-rsa-signatures",
        "crypto-bigint",
        "base16ct",
    ] {
        assert!(!lock.contains(absent), "lock drops {absent}");
    }
}
