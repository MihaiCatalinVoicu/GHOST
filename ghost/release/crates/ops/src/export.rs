//! `export-public` (design faza14-distribution.md §6.1's `bin/ghost-verify-…` row, §6.4's
//! `src/ghost-public-<tag>.tar`, D21, Q28): writes the deterministic public source tree —
//! `ghost-verify` and its dependency closure **in source**, plus the permissive licence —
//! as `ghost-public-<tag>.tar` in the release output. The public repository receives this
//! tree; `ghost-verify`'s three release binaries build from it (§6.4 step 4), which is what
//! makes the verifier "the one GHOST component users can read" and reproduce.
//!
//! The tree (original subpaths kept, so the member manifests' relative `path =` deps resolve
//! unchanged):
//!
//! ```text
//! Cargo.toml            the new workspace root ([workspace] + [workspace.package] +
//!                       [workspace.dependencies], derived from the private root — with the
//!                       licence overridden to MIT and `repository` dropped, see below)
//! Cargo.lock            pruned to the closure (verbatim [[package]] blocks of the private
//!                       lock, so `cargo build --locked` works standalone; dev-dependencies
//!                       are stripped from the manifests and stay out)
//! LICENSE               MIT (Q28's permissive licence; the design names none, MIT chosen —
//!                       the copyright holder is Q45, counsel-bound, so the line names the
//!                       project, not a person; G-D9 lists this file's identity patterns)
//! README.md             what the tree is and how to build the verifier from it
//! client-core/update/   ghost-client-update (src + manifest, dev-dependencies stripped)
//! client-core/release/  ghost-client-release
//! issuer/crates/entitlement/  ghost-entitlement
//! issuer/crates/blind-rsa/    ghost-blind-rsa
//! release/verify/       ghost-verify (the CLI and library; tests/examples stay private —
//!                       `cargo test` is not supported in the public tree)
//! ```
//!
//! Determinism: entries sorted by path, fixed owner (0) and modes (0644/0755), mtimes all
//! `SOURCE_DATE_EPOCH` (`--mtime`, defaulting to the env of the same name, then 0). Two
//! exports of one tag are byte-identical (the test proves it); the cross-environment proof
//! is the recipe's A/B comparison (V-D2).
//!
//! Identity (D25, G-D9): every file's bytes are swept against
//! `scripts/gates/identity-patterns.txt` and a hit refuses the export — an identity leak
//! must never reach the public repository, and a refusal here is build-time, not gate-time.

use std::path::{Path, PathBuf};

/// The exported members: (path in the tree, package name). The closure of `ghost-verify`'s
/// path dependencies; kept in dependency order for the workspace `members` list.
const MEMBERS: [(&str, &str); 5] = [
    ("client-core/update", "ghost-client-update"),
    ("client-core/release", "ghost-client-release"),
    ("issuer/crates/blind-rsa", "ghost-blind-rsa"),
    ("issuer/crates/entitlement", "ghost-entitlement"),
    ("release/verify", "ghost-verify"),
];

const LICENSE: &str = "\
MIT License

Copyright (c) 2026 GHOST contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the \"Software\"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
";

const README: &str = "\
# GHOST public source

The public source tree of `ghost-verify`, GHOST's public verifier (design
faza14-distribution.md §5.4): the §7.4 update decision offline (`apk`, `libs`,
`operator`, `monitor`), built from the same `ghost-client-update` the app
links. Exported at each release by `ghost-release-ops export-public` (artifact
kind 19); the release's `ghost-verify` binaries for Linux (x86_64, aarch64,
static) and Windows (x86_64) build from this tree — reproducibly, which is the
point: this is the one GHOST component you can read before you run it.

Build:

    cargo build --release --locked -p ghost-verify

`Cargo.lock` is pruned to this tree's closure; `--locked` fails closed. Tests
and examples are not part of the public tree (`cargo test` is not supported
here). Licence: MIT.
";

fn ws_root() -> PathBuf {
    // release/crates/ops -> the workspace root (the private tree export-public runs in).
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .expect("the workspace root resolves")
}

/// One file going into the tar.
struct Entry {
    path: String,
    body: Vec<u8>,
    mode: u32,
}

/// `export-public --tag <tag> --out <dir> [--mtime <unix>]`; writes
/// `<dir>/ghost-public-<tag>.tar` and returns the fixed summary line.
pub fn export_public(tag: &str, out_dir: &Path, mtime: Option<u64>) -> Result<String, String> {
    if tag.is_empty()
        || !tag
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_' || b == b'/')
    {
        return Err("TAG the tag names the tar and may carry only [A-Za-z0-9._/-]".into());
    }
    let mtime = mtime
        .or_else(|| {
            std::env::var("SOURCE_DATE_EPOCH")
                .ok()
                .and_then(|v| v.parse().ok())
        })
        .unwrap_or(0);
    let root = ws_root();
    let patterns = identity_patterns(&root)?;
    let mut entries = Vec::new();
    for (dir, _pkg) in MEMBERS {
        let base = root.join(dir);
        let manifest = strip_dev_sections(
            &std::fs::read_to_string(base.join("Cargo.toml"))
                .map_err(|e| format!("cannot read {dir}/Cargo.toml: {e}"))?,
        );
        entries.push(Entry {
            path: format!("{dir}/Cargo.toml"),
            body: manifest.into_bytes(),
            mode: 0o644,
        });
        let mut files = Vec::new();
        collect_src(&root, &base.join("src"), dir, &mut files)?;
        files.sort();
        for rel in files {
            let body =
                std::fs::read(root.join(&rel)).map_err(|e| format!("cannot read {rel}: {e}"))?;
            entries.push(Entry {
                path: rel,
                body,
                mode: 0o644,
            });
        }
    }
    entries.push(Entry {
        path: "Cargo.toml".into(),
        body: root_toml(&root)?.into_bytes(),
        mode: 0o644,
    });
    entries.push(Entry {
        path: "Cargo.lock".into(),
        body: resolved_lock(&root, &entries)?,
        mode: 0o644,
    });
    entries.push(Entry {
        path: "LICENSE".into(),
        body: LICENSE.into(),
        mode: 0o644,
    });
    entries.push(Entry {
        path: "README.md".into(),
        body: README.into(),
        mode: 0o644,
    });

    // G-D9 as a build-time refusal: no identity pattern in any byte of the tree.
    for entry in &entries {
        for (n, pattern) in patterns.iter().enumerate() {
            if contains_ignore_ascii_case(&entry.body, pattern.as_bytes()) {
                return Err(format!(
                    "IDENTITY_PATTERN pattern#{n} path={} (scripts/gates/identity-patterns.txt)",
                    entry.path
                ));
            }
        }
    }

    entries.sort_by(|a, b| a.path.cmp(&b.path));
    let tar = build_tar(&entries, mtime);
    let out = out_dir.join(format!("ghost-public-{tag}.tar"));
    std::fs::write(&out, &tar).map_err(|e| format!("cannot write {}: {e}", out.display()))?;
    Ok(format!(
        "EXPORT_PUBLIC path={} sha256={} bytes={} entries={}",
        out.display(),
        sha256_hex(&tar),
        tar.len(),
        entries.len()
    ))
}

/// The tree's Cargo.lock, generated by cargo itself: the tree is assembled in a scratch
/// directory, seeded with the workspace lock, and `cargo metadata --offline` re-resolves it to
/// exactly this workspace — pruning the seed's packages the public manifests do not reach
/// (lock entries carry the ORIGINAL workspace's dev-dependency edges; a lock with extra or
/// missing packages is refused by `cargo build --locked`, so only cargo's own resolution is
/// trustworthy). Deterministic: the seed pins every version cargo can keep, and `--offline`
/// admits no new fetch.
fn resolved_lock(root: &Path, entries: &[Entry]) -> Result<Vec<u8>, String> {
    static SCRATCH_SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let seq = SCRATCH_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let tmp = std::env::temp_dir().join(format!("ghost-export-lock-{}-{seq}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    for e in entries {
        let p = tmp.join(&e.path);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).map_err(|err| format!("export scratch tree: {err}"))?;
        }
        std::fs::write(&p, &e.body)
            .map_err(|err| format!("export scratch tree {}: {err}", e.path))?;
    }
    std::fs::copy(root.join("Cargo.lock"), tmp.join("Cargo.lock"))
        .map_err(|e| format!("export lock seed: {e}"))?;
    // `cargo check` performs the minimal update of the seeded lock: cargo's own resolver
    // keeps every version the seed pins (the reviewed set) and prunes what the public
    // manifests do not reach. (`generate-lockfile` would re-resolve from scratch and could
    // drift to unreviewed versions; `cargo metadata` does not write the lock.) Compilation
    // itself is irrelevant — the lock is written at resolution — so the outcome is not
    // checked; only the lock's existence is.
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let run = std::process::Command::new(&cargo)
        .args(["check", "--offline", "-p", "ghost-verify"])
        .current_dir(&tmp)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .output();
    let lock = std::fs::read(tmp.join("Cargo.lock")).map_err(|e| {
        let detail = run
            .as_ref()
            .map(|r| {
                String::from_utf8_lossy(&r.stderr)
                    .trim()
                    .lines()
                    .take(3)
                    .collect::<Vec<_>>()
                    .join(" | ")
            })
            .unwrap_or_default();
        format!("cargo did not produce the public tree's lock: {e}; cargo said: {detail}")
    })?;
    let _ = std::fs::remove_dir_all(&tmp);
    Ok(lock)
}

fn sha256_hex(b: &[u8]) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(b))
}

fn contains_ignore_ascii_case(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    let lower: Vec<u8> = needle.iter().map(u8::to_ascii_lowercase).collect();
    haystack
        .windows(needle.len())
        .any(|w| w.eq_ignore_ascii_case(&lower))
}

/// The G-D9 patterns (one per line; `#` comments and blanks skipped). The file ships in the
/// private tree; export-public reads it at run time — the exported tree never does.
fn identity_patterns(root: &Path) -> Result<Vec<String>, String> {
    let text = std::fs::read_to_string(root.join("scripts/gates/identity-patterns.txt"))
        .map_err(|e| format!("cannot read scripts/gates/identity-patterns.txt: {e}"))?;
    Ok(text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_string)
        .collect())
}

/// Drops `[dev-dependencies]` sections (and their `key.workspace = true` table sub-forms):
/// the public tree carries the library and CLI sources; tests stay private, and their
/// dev-only path dependencies (ghost-release-ops) do not exist here.
fn strip_dev_sections(toml: &str) -> String {
    let mut out = String::with_capacity(toml.len());
    let mut in_dev = false;
    for line in toml.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            in_dev = t == "[dev-dependencies]" || t.starts_with("[dev-dependencies.");
        }
        if !in_dev {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

/// Recursively lists `src/**` files under `dir`, as tree-relative paths (`{member}/src/…`).
fn collect_src(root: &Path, dir: &Path, member: &str, out: &mut Vec<String>) -> Result<(), String> {
    for item in std::fs::read_dir(dir).map_err(|e| format!("cannot list {}: {e}", dir.display()))? {
        let item = item.map_err(|e| e.to_string())?;
        let path = item.path();
        // Root-relative: `path` is already under root/<member>/src; prefixing the member again
        // would double it (client-core/update/client-core/update/...).
        let rel = path
            .strip_prefix(root)
            .map_err(|_| "PATH_TRAVERSAL a source path is outside the workspace")?
            .display()
            .to_string();
        if path.is_dir() {
            collect_src(root, &path, member, out)?;
        } else {
            out.push(rel);
        }
    }
    Ok(())
}

/// The keys the member manifests take from `[workspace.dependencies]` (both inheritance
/// spellings: `key = { workspace = true }` and `key.workspace = true`). Only lines inside a
/// dependency section count — `[package]` fields like `version.workspace = true` inherit
/// from `[workspace.package]`, not here.
fn used_workspace_deps(member_tomls: &[String]) -> Result<Vec<String>, String> {
    let mut used: Vec<String> = Vec::new();
    for toml in member_tomls {
        let mut in_deps = false;
        for line in toml.lines() {
            let t = line.trim();
            if t.starts_with('[') {
                in_deps = t == "[dependencies]"
                    || t.starts_with("[dependencies.")
                    || t == "[build-dependencies]"
                    || t.starts_with("[build-dependencies.");
                continue;
            }
            if !in_deps || !t.contains("workspace = true") {
                continue;
            }
            let key = t
                .split_once('=')
                .map(|(k, _)| k.trim().trim_end_matches(".workspace").trim().to_string())
                .filter(|k| !k.is_empty())
                .ok_or_else(|| "WORKSPACE_KEY a workspace-inherited line has no key".to_string())?;
            if !used.contains(&key) {
                used.push(key);
            }
        }
    }
    Ok(used)
}

/// The exported workspace root. `[workspace.package]` is derived, not copied: `license`
/// becomes MIT (Q28; the private tree's proprietary expression must not reach the public
/// repository) and `repository` is dropped (it names the private repo — an identity
/// pattern, D25). Every key the members inherit must be present, or the export refuses.
fn root_toml(root: &Path) -> Result<String, String> {
    let main = std::fs::read_to_string(root.join("Cargo.toml"))
        .map_err(|e| format!("cannot read the workspace root Cargo.toml: {e}"))?;
    let section = |name: &str| -> Result<Vec<String>, String> {
        let mut lines = main.lines();
        let _start = lines
            .position(|l| l.trim() == name)
            .ok_or_else(|| format!("SECTION_MISSING the private root has no {name}"))?;
        let body: Vec<&str> = lines
            .by_ref()
            .take_while(|l| !l.trim().starts_with('['))
            .collect();
        Ok(body.iter().map(|s| s.to_string()).collect())
    };
    let resolver = section("[workspace]")?
        .iter()
        .find_map(|l| l.split_once('='))
        .filter(|(k, _)| k.trim() == "resolver")
        .map(|(_, v)| v.trim().to_string())
        .ok_or_else(|| "RESOLVER_MISSING the private root pins no resolver".to_string())?;

    let members: Vec<String> = MEMBERS.iter().map(|(d, _)| format!("\"{d}\"")).collect();
    let mut package = String::new();
    for line in section("[workspace.package]")? {
        let key = line.split_once('=').map(|(k, _)| k.trim()).unwrap_or("");
        match key {
            "license" => package.push_str("license = \"MIT\"\n"),
            "repository" | "homepage" | "documentation" | "authors" | "publish" => {}
            _ => {
                package.push_str(&line);
                package.push('\n');
            }
        }
    }

    let used = used_workspace_deps(
        &MEMBERS
            .iter()
            .map(|(d, _)| {
                std::fs::read_to_string(root.join(d).join("Cargo.toml"))
                    .map(|t| strip_dev_sections(&t))
                    .map_err(|e| format!("cannot read {d}/Cargo.toml: {e}"))
            })
            .collect::<Result<Vec<_>, _>>()?,
    )?;
    let mut deps = String::new();
    for line in section("[workspace.dependencies]")? {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        let key = t.split_once('=').map(|(k, _)| k.trim()).unwrap_or("");
        if used.iter().any(|u| u == key) {
            deps.push_str(&line);
            deps.push('\n');
        }
    }
    for key in &used {
        if !deps
            .lines()
            .any(|l| l.split_once('=').map(|(k, _)| k.trim()) == Some(key.as_str()))
        {
            return Err(format!("WORKSPACE_DEP_MISSING key={key}"));
        }
    }

    Ok(format!(
        "# GHOST public source tree (design faza14-distribution.md §6.1, D21, Q28):\n\
         # ghost-verify and its dependency closure in source, exported by\n\
         # ghost-release-ops export-public. Licence: MIT. Build:\n\
         #   cargo build --release --locked -p ghost-verify\n\
         [workspace]\nresolver = {resolver}\nmembers = [\n    {}\n]\n\n[workspace.package]\n{package}\n[workspace.dependencies]\n{deps}",
        members.join(",\n    ")
    ))
}

/// One `[[package]]` block of the private lock, kept verbatim.

/// The closure of the five exported packages over the private lock, kept as verbatim blocks
/// in the private lock's (name-sorted) order. Workspace path packages outside the exported
/// set (ghost-release-ops, a dev-only dep) are neither kept nor traversed. External
/// dev-time entries reachable from the kept manifests stay — extra lock entries are
/// tolerated, a missing one would break `--locked`.
/// Re-emit one kept package block, dropping `dependencies` edges that point at pruned packages
/// (a lock whose kept packages name a missing package is incomplete and `cargo build --locked`
/// refuses it — dev-dependency edges of the exported crates are the usual case: their targets
/// stay in the private workspace).

// ---------------------------------------------------------------------------
// The deterministic tar writer (the subset the export needs: regular files and
// directories, ustar, fixed owner 0 and modes, one mtime for every entry).
// ---------------------------------------------------------------------------

fn octal(field: &mut [u8], value: u64) {
    let digits = field.len() - 1;
    let s = format!("{:0width$o}", value, width = digits - 1);
    let b = s.as_bytes();
    field[..b.len()].copy_from_slice(b);
    field[field.len() - 1] = 0;
}

fn tar_header(name: &str, size: usize, mode: u32, mtime: u64, typeflag: u8) -> [u8; 512] {
    assert!(name.len() < 100, "tar entry name too long: {name}");
    let mut h = [0u8; 512];
    h[..name.len()].copy_from_slice(name.as_bytes());
    octal(&mut h[100..108], u64::from(mode));
    octal(&mut h[108..116], 0); // uid
    octal(&mut h[116..124], 0); // gid
    octal(&mut h[124..136], size as u64);
    octal(&mut h[136..148], mtime);
    h[156] = typeflag;
    h[257..263].copy_from_slice(b"ustar\0");
    h[263..265].copy_from_slice(b"00");
    // chksum: field as spaces, then the sum, then NUL, then space.
    for b in &mut h[148..156] {
        *b = b' ';
    }
    let sum: u64 = h.iter().map(|&b| u64::from(b)).sum();
    let s = format!("{:06o}", sum);
    h[148..154].copy_from_slice(s.as_bytes());
    h[154] = 0;
    h[155] = b' ';
    h
}

fn pad512(n: usize) -> usize {
    (512 - (n % 512)) % 512
}

/// Assembles the tar: explicit sorted directory entries (mode 0755) for every directory
/// level, then the files (sorted), two zero blocks at the end.
fn build_tar(entries: &[Entry], mtime: u64) -> Vec<u8> {
    let mut names: Vec<String> = Vec::new();
    let mut dirs: Vec<String> = Vec::new();
    for e in entries {
        names.push(e.path.clone());
        let mut path = e.path.as_str();
        while let Some((dir, _)) = path.rsplit_once('/') {
            if !dirs.contains(&dir.to_string()) {
                dirs.push(dir.to_string());
            }
            path = dir;
        }
    }
    dirs.sort();
    let mut out = Vec::new();
    for d in &dirs {
        out.extend_from_slice(&tar_header(d, 0, 0o755, mtime, b'5'));
    }
    for e in entries {
        out.extend_from_slice(&tar_header(&e.path, e.body.len(), e.mode, mtime, b'0'));
        out.extend_from_slice(&e.body);
        out.extend(std::iter::repeat(0u8).take(pad512(e.body.len())));
    }
    out.extend(std::iter::repeat(0u8).take(1024));
    out
}
