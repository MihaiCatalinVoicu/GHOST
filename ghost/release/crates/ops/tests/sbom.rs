//! `sbom` (design §6.1's `sbom/{client,relay,issuer}.cdx.json` row): the CycloneDX document's
//! shape and determinism. Runs `cargo metadata` like the recipe does; skipped when cargo is
//! absent (the in-image selfcheck always has it).

use ghost_release_ops::sbom::sbom_json;

fn cargo_available() -> bool {
    std::process::Command::new("cargo")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[test]
fn the_sbom_is_deterministic_and_shaped() {
    if !cargo_available() {
        eprintln!("sbom test skipped: cargo not on PATH");
        return;
    }
    // ghost-client-release: a small pure closure — fast metadata, few components.
    let a = sbom_json("ghost-client-release").expect("cargo metadata + the SBOM build");
    let b = sbom_json("ghost-client-release").expect("twice");
    assert_eq!(a, b, "two runs byte-identical");

    // The envelope: CycloneDX 1.7, no timestamp, no serial number (C-08).
    assert!(a.starts_with(
        "{\n  \"bomFormat\": \"CycloneDX\",\n  \"specVersion\": \"1.7\",\n  \"version\": 1,\n"
    ));
    assert!(!a.contains("timestamp"), "no timestamp");
    assert!(!a.contains("serialNumber"), "no serial number");
    assert!(a.ends_with("}\n"));

    // The root component is the named package.
    assert!(a.contains("\"metadata\": {\n    \"component\": {\n      \"bom-ref\": \"pkg:cargo/ghost-client-release@"));
    assert!(a.contains("\"name\": \"ghost-client-release\""));

    // Components: the closure's registry packages, sorted by purl, hashes where cargo has a
    // checksum; the root package itself is not among them.
    let purls: Vec<&str> = a
        .lines()
        .filter(|l| l.trim_start().starts_with("\"purl\": \"pkg:cargo/"))
        .skip(1) // the root's purl comes first, in metadata
        .map(|l| l.split('"').nth(3).unwrap())
        .collect();
    assert!(!purls.is_empty(), "components present");
    let mut sorted = purls.clone();
    sorted.sort();
    assert_eq!(purls, sorted, "components sorted by purl");
    assert!(
        purls.iter().any(|p| p.starts_with("pkg:cargo/sha2@")),
        "a registry component by purl"
    );
    assert!(
        purls.iter().all(|p| !p.contains("ghost-client-release")),
        "the root is not a component"
    );
    assert!(
        a.contains("\"alg\": \"SHA-256\""),
        "registry components carry the checksum"
    );

    // The document is well-formed: brackets balance outside strings.
    let mut depth = 0i32;
    let mut in_str = false;
    let mut esc = false;
    for c in a.chars() {
        if in_str {
            if esc {
                esc = false;
            } else if c == '\\' {
                esc = true;
            } else if c == '"' {
                in_str = false;
            }
            continue;
        }
        match c {
            '"' => in_str = true,
            '{' | '[' => depth += 1,
            '}' | ']' => depth -= 1,
            _ => {}
        }
        assert!(depth >= 0, "brackets never close early");
    }
    assert_eq!(depth, 0, "brackets balance");
}
