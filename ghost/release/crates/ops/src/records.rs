//! `records-check` (design faza14-distribution.md §12.1 row G-D4, §4.3, §4.9): verifies the
//! committed release records of one network directory (`protocol/release/<network>/`), the
//! (a)–(c) clauses the gate's bash half cannot parse:
//!
//!   (a) the root chain verifies by the chain rule from its first entry: roots sorted by
//!       `root_version` (contiguous — a gap fails closed), each root after the first
//!       `verify_block` under its PREDECESSOR's root keyset and threshold (§4.3; the exact
//!       `GHRT::verify_block`, no crypto reimplementation). The first root is the trust
//!       anchor: the client pins its bytes, so the clause starts at its successor.
//!   (b) the newest root lists every committed signing certificate's digest: the SHA-256 of
//!       each `*.crt` in the directory is an entry of the newest root's `apk_signers`.
//!   (c) the newest root's anchor mirrors equal the committed `anchor-mirrors.txt`: both
//!       parsed to canonical `<onion:port>` + operator-id lists, compared exactly
//!       (order-insensitive, duplicates not allowed on either side); mainnet additionally
//!       requires ≥ 2 distinct operator ids — the design's rule is mainnet-only, so
//!       stagenet checks the equality alone (documented here, the row's words).
//!
//! Roots are read where the committed layout keeps them: `<dir>/roots/*.ghrt` and
//! `<dir>/*.ghrt` first; with none, the embedded chain `<dir>/embedded-chain.ghrc` (the
//! layout of protocol/release/stagenet today) — `GHRC::parse` yields the same roots.
//! Zero roots is a failure, never a vacuous pass.
//!
//! Fixed verdict vocabulary, one line per clause, then the summary:
//!   RECORDS_OK a roots=<n> chain=<edges verified>
//!   RECORDS_OK b signers=<n>            | RECORDS_SKIP b no-apk-signer-crt
//!   RECORDS_OK c anchors=<n> operators=<m>
//!   RECORDS_OK network=<name> roots=<n> newest=<v> signers=<n|skip> anchors=<n|skip>
//! Any failure: `RECORDS_FAIL <clause> <detail>` lines, exit 1, no summary.

use std::path::Path;

use ghost_client_release::chain::GHRC;
use ghost_client_release::root::{Network, GHRT};

use crate::build::Outcome;

fn sha256(b: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(b).into()
}

/// The network byte the directory's NAME claims (GHRC/GHRT network encoding).
fn dir_network(name: &str) -> Option<u8> {
    match name {
        "mainnet" => Some(1),
        "stagenet" => Some(2),
        "stagenet-drill" => Some(3),
        _ => None,
    }
}

/// Every root, sorted by version: loose `*.ghrt` at the top level and under `roots/`, else
/// the roots of `embedded-chain.ghrc`. Parse errors fail closed with the file named.
fn load_roots(dir: &Path) -> Result<Vec<GHRT>, String> {
    let mut roots: Vec<GHRT> = Vec::new();
    for sub in ["", "roots"] {
        let d = if sub.is_empty() {
            dir.to_path_buf()
        } else {
            dir.join(sub)
        };
        let entries = match std::fs::read_dir(&d) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries {
            let path = entry.map_err(|e| format!("read_dir: {e}"))?.path();
            if path.extension().is_some_and(|e| e == "ghrt") {
                let doc = std::fs::read(&path)
                    .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
                roots.push(GHRT::parse(&doc).map_err(|e| format!("{}: {e}", path.display()))?);
            }
        }
    }
    if roots.is_empty() {
        let chain = dir.join("embedded-chain.ghrc");
        if chain.is_file() {
            let doc = std::fs::read(&chain)
                .map_err(|e| format!("cannot read {}: {e}", chain.display()))?;
            roots = GHRC::parse(&doc)
                .map_err(|e| format!("{}: {e}", chain.display()))?
                .roots;
        }
    }
    roots.sort_by_key(|r| r.body.root_version);
    Ok(roots)
}

fn canonical_mirror(onion: &[u8], operator: &[u8; 16]) -> String {
    // Onion names are already lowercase base32; lowercasing both sides makes the
    // comparison spelling-proof. The operator is rendered as lowercase hex.
    format!(
        "{}:{}",
        String::from_utf8_lossy(onion).to_lowercase(),
        hex::encode(operator)
    )
}

/// `records-check --network <dir>`: the (a)–(c) clauses over one network directory.
pub fn records_check(dir: &Path) -> Outcome {
    let name = dir
        .canonicalize()
        .map_err(|e| format!("cannot resolve {}: {e}", dir.display()))?
        .file_name()
        .and_then(|s| s.to_str())
        .map(str::to_string)
        .ok_or_else(|| format!("{} has no directory name", dir.display()))?;
    let net = dir_network(&name).ok_or_else(|| {
        format!("network directory {name} is not mainnet|stagenet|stagenet-drill")
    })?;
    if !dir.is_dir() {
        return Err(format!("{} is not a directory", dir.display()));
    }

    let mut out: Vec<String> = Vec::new();
    let mut fails = 0usize;
    fn fail(out: &mut Vec<String>, fails: &mut usize, clause: &str, detail: String) {
        out.push(format!("RECORDS_FAIL {clause} {detail}"));
        *fails += 1;
    }

    // (a) the chain rule from the first entry.
    let roots = load_roots(dir)?;
    if roots.is_empty() {
        fail(
            &mut out,
            &mut fails,
            "a",
            format!("{name}: no roots (no *.ghrt, roots/*.ghrt or embedded-chain.ghrc)"),
        );
        return Err(out.join("\n")); // no summary on failure; the caller prints the FAIL lines, exit 1
    }
    let mut chain_edges = 0usize;
    for w in roots.windows(2) {
        if w[1].body.root_version != w[0].body.root_version + 1 {
            fail(
                &mut out,
                &mut fails,
                "a",
                format!(
                    "root versions not contiguous: {} then {}",
                    w[0].body.root_version, w[1].body.root_version
                ),
            );
            continue;
        }
        if let Err(e) = w[1].verify_block(&w[0].body.root.keys, w[0].body.root.threshold) {
            fail(
                &mut out,
                &mut fails,
                "a",
                format!(
                    "root {} does not verify under root {}'s keyset ({}/{}): {e}",
                    w[1].body.root_version,
                    w[0].body.root_version,
                    w[0].body.root.threshold,
                    w[0].body.root.keys.len()
                ),
            );
            continue;
        }
        chain_edges += 1;
    }
    for r in &roots {
        if r.body.network as u8 != net {
            fail(
                &mut out,
                &mut fails,
                "a",
                format!(
                    "root {} is network {}, the directory is {name}",
                    r.body.root_version, r.body.network as u8
                ),
            );
        }
        // Sanity: the format's own network spelling.
        if Network::from_u8(r.body.network as u8).is_err() {
            fail(
                &mut out,
                &mut fails,
                "a",
                format!(
                    "root {} carries an unknown network byte",
                    r.body.root_version
                ),
            );
        }
    }
    if fails == 0 {
        out.push(format!(
            "RECORDS_OK a roots={} chain={chain_edges}",
            roots.len()
        ));
    }
    let newest = roots.last().expect("roots is not empty");

    // (b) the newest root lists every committed signing certificate.
    let mut crts: Vec<(String, [u8; 32])> = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|e| e == "crt") && path.is_file() {
                let bytes = std::fs::read(&path)
                    .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
                crts.push((
                    path.file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .into_owned(),
                    sha256(&bytes),
                ));
            }
        }
    }
    crts.sort_by(|a, b| a.0.cmp(&b.0));
    if crts.is_empty() {
        out.push("RECORDS_SKIP b no-apk-signer-crt".to_string());
    } else {
        let mut missing = Vec::new();
        for (file, digest) in &crts {
            if !newest.body.apk_signers.contains(digest) {
                missing.push(format!("{file} ({})", hex::encode(digest)));
            }
        }
        if missing.is_empty() {
            out.push(format!("RECORDS_OK b signers={}", crts.len()));
        } else {
            fail(
                &mut out,
                &mut fails,
                "b",
                format!("the newest root lists none of: {}", missing.join(", ")),
            );
        }
    }

    // (c) the newest root's anchor mirrors equal the committed file.
    let mirrors_file = dir.join("anchor-mirrors.txt");
    if !mirrors_file.is_file() {
        out.push("RECORDS_SKIP c no-anchor-mirrors-txt".to_string());
    } else {
        let text = std::fs::read_to_string(&mirrors_file)
            .map_err(|e| format!("cannot read {}: {e}", mirrors_file.display()))?;
        let mut from_file: Vec<String> = Vec::new();
        for (n, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() != 3 || parts[0] != "mirror" {
                fail(
                    &mut out,
                    &mut fails,
                    "c",
                    format!(
                        "anchor-mirrors.txt line {} is not `mirror <onion:port> <operator hex>`",
                        n + 1
                    ),
                );
                continue;
            }
            ghost_client_release::CanonicalOnion::parse(parts[1].as_bytes())
                .map_err(|e| format!("anchor-mirrors.txt line {}: {e}", n + 1))?;
            let op = hex::decode(parts[2]).map_err(|_| {
                format!("anchor-mirrors.txt line {}: operator id is not hex", n + 1)
            })?;
            let op: [u8; 16] = op.try_into().map_err(|_| {
                format!(
                    "anchor-mirrors.txt line {}: operator id is not 16 bytes",
                    n + 1
                )
            })?;
            from_file.push(canonical_mirror(parts[1].as_bytes(), &op));
        }
        from_file.sort();
        let mut from_root: Vec<String> = newest
            .body
            .anchor_mirrors
            .iter()
            .map(|m| canonical_mirror(&m.onion, &m.operator_id))
            .collect();
        from_root.sort();
        if from_file == from_root {
            let operators = newest
                .body
                .anchor_mirrors
                .iter()
                .map(|m| hex::encode(m.operator_id))
                .collect::<std::collections::BTreeSet<_>>()
                .len();
            let c_failed = out.iter().any(|l| l.starts_with("RECORDS_FAIL c"));
            if net == 1 && operators < 2 {
                fail(
                    &mut out,
                    &mut fails,
                    "c",
                    format!(
                        "mainnet anchor mirrors span {operators} operators, and the rule is >= 2"
                    ),
                );
            } else if !c_failed {
                out.push(format!(
                    "RECORDS_OK c anchors={} operators={operators}",
                    from_root.len()
                ));
            }
        } else {
            fail(
                &mut out,
                &mut fails,
                "c",
                format!(
                    "the newest root's anchor mirrors and anchor-mirrors.txt differ (root: {}; file: {})",
                    from_root.join(","),
                    from_file.join(",")
                ),
            );
        }
    }

    if fails > 0 {
        return Err(out.join("\n"));
    }
    let signers = if crts.is_empty() {
        "skip".to_string()
    } else {
        crts.len().to_string()
    };
    let anchors = if !mirrors_file.is_file() {
        "skip".to_string()
    } else {
        newest.body.anchor_mirrors.len().to_string()
    };
    out.push(format!(
        "RECORDS_OK network={name} roots={} newest={} signers={signers} anchors={anchors}",
        roots.len(),
        newest.body.root_version
    ));
    Ok(out.join("\n"))
}
