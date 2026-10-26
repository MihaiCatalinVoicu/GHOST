//! `sums-compare` (RK1 step 2, CR-M5): the three SHA256SUMS of a release agree or the ceremony
//! stops; `b_digest` is the value the owner compares on an independent device.

use std::path::Path;

use ghost_release_ops::build::sums_compare;

fn write(path: &Path, text: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, text).unwrap();
}

fn sums_line(tag: &str, name: &str) -> String {
    let digest: [u8; 32] = {
        use sha2::Digest;
        sha2::Sha256::digest(format!("{tag}-{name}").as_bytes()).into()
    };
    format!("{}  {name}\n", hex::encode(digest))
}

fn three(dir: &Path, a: &str, b: &str) -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
    let al = dir.join("a-local/SHA256SUMS");
    let aj = dir.join("a-job/SHA256SUMS");
    let bj = dir.join("b-job/SHA256SUMS");
    write(&al, a);
    write(&aj, a);
    write(&bj, b);
    (al, aj, bj)
}

#[test]
fn equal_sums_print_the_vocabulary_and_the_b_digest() {
    let dir = tempfile::tempdir().unwrap();
    let content = format!("{}{}", sums_line("h", "app.apk"), sums_line("h", "ghost-relay"));
    let (al, aj, bj) = three(dir.path(), &content, &content);
    let out = sums_compare(&al, &aj, &bj).unwrap();
    assert!(out.starts_with("SUMS_EQUAL files=2 b_digest="), "{out}");
    let digest = out.trim_start_matches("SUMS_EQUAL files=2 b_digest=");
    assert_eq!(digest.len(), 16);
    // b_digest is the first 16 hex of SHA-256 of B's bytes, so the owner can recompute it on an
    // independent device from B's printed summary.
    let b_raw = std::fs::read(&bj).unwrap();
    let want: [u8; 32] = {
        use sha2::Digest;
        sha2::Sha256::digest(&b_raw).into()
    };
    assert_eq!(digest, &hex::encode(want)[..16]);
}

#[test]
fn any_difference_stops_the_ceremony() {
    let dir = tempfile::tempdir().unwrap();
    let content = format!("{}{}", sums_line("h", "app.apk"), sums_line("h", "ghost-relay"));
    // B's sums carry a different relay hash.
    let b = format!("{}{}", sums_line("h", "app.apk"), sums_line("EVIL", "ghost-relay"));
    let (al, aj, bj) = three(dir.path(), &content, &b);
    let err = sums_compare(&al, &aj, &bj).unwrap_err();
    assert!(err.starts_with("SUMS_DIFFER b-job ghost-relay"), "{err}");

    // A local list with an extra file refuses on the count.
    let a = format!("{}{}", content, sums_line("h", "extra"));
    let (al2, aj2, _) = three(dir.path(), &a, &content);
    let err = sums_compare(&al2, &aj2, &bj).unwrap_err();
    assert!(err.starts_with("SUMS_DIFFER"), "{err}");

    // A malformed line is a refusal, not a guess.
    let bad = dir.path().join("bad/SHA256SUMS");
    write(&bad, "not-a-sums-line\n");
    let err = sums_compare(&bad, &aj, &bj).unwrap_err();
    assert!(err.contains("does not parse"), "{err}");

    // A duplicate name is a refusal.
    let dup = dir.path().join("dup/SHA256SUMS");
    let l = sums_line("h", "x");
    write(&dup, &format!("{l}{l}"));
    let err = sums_compare(&dup, &aj, &bj).unwrap_err();
    assert!(err.contains("duplicate"), "{err}");
}
