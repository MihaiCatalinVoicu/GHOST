//! `sbom` (design faza14-distribution.md §6.1's `sbom/{client,relay,issuer}.cdx.json` row,
//! ADR-37 point 8, C-08): a CycloneDX 1.7 SBOM of one shipped package's resolved dependency
//! graph, from `cargo metadata --locked --offline`. CycloneDX 1.7 (released 2025-10-21);
//! every object's keys sorted, `components` sorted by purl, **no timestamp, no serial
//! number** — two runs byte-identical.
//!
//! The target mapping (design §6.1 rows 12–14 name the three SBOMs per shipped target; the
//! shipped graphs are `ghost/licenses/graphs.txt`'s rows): `client` = `ghost-client-net`
//! (the shipped Android library's crate), `relay` = `ghost-relay-node`, `issuer` =
//! `ghost-issuer`. The recipe passes the package; this module stays generic.
//!
//! Hashes: registry components carry the SHA-256 from `Cargo.lock`'s per-package `checksum`
//! (cargo metadata no longer reports per-package checksums itself; the lock is the same
//! source of truth `--locked` enforces). Workspace/path packages have no lock entry and no
//! hash — their bytes are the release itself, named in SHA256SUMS — so such components have
//! no `hashes` entry, by design.
//!
//! No new dependency: cargo metadata's JSON is parsed by the minimal parser below (the
//! fixed shape it needs — objects, arrays, strings — with numbers skipped unread), and the
//! SBOM is emitted by hand for its fixed shape.

use std::path::Path;

fn ws_root() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .expect("the workspace root resolves")
}

// ---------------------------------------------------------------------------
// A minimal JSON reader: exactly what cargo metadata needs. Numbers are
// scanned and dropped; strings unescape the common set (\uXXXX becomes U+FFFD
// unless a BMP scalar — cargo metadata paths are plain).
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
enum J {
    Null,
    Bool,
    Str(String),
    Arr(Vec<J>),
    Obj(Vec<(String, J)>),
}

struct Reader<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Reader<'a> {
    fn new(s: &'a str) -> Self {
        Reader {
            b: s.as_bytes(),
            i: 0,
        }
    }

    fn ws(&mut self) {
        while self.b.get(self.i).is_some_and(|c| c.is_ascii_whitespace()) {
            self.i += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }

    fn expect(&mut self, lit: &str) -> Result<(), String> {
        if self.b[self.i..].starts_with(lit.as_bytes()) {
            self.i += lit.len();
            Ok(())
        } else {
            Err(format!("JSON: wanted {lit} at byte {}", self.i))
        }
    }

    fn value(&mut self) -> Result<J, String> {
        self.ws();
        match self
            .peek()
            .ok_or_else(|| "JSON: unexpected end".to_string())?
        {
            b'n' => {
                self.expect("null")?;
                Ok(J::Null)
            }
            b't' => {
                self.expect("true")?;
                Ok(J::Bool)
            }
            b'f' => {
                self.expect("false")?;
                Ok(J::Bool)
            }
            b'"' => Ok(J::Str(self.string()?)),
            b'[' => {
                self.i += 1;
                let mut items = Vec::new();
                self.ws();
                if self.peek() == Some(b']') {
                    self.i += 1;
                    return Ok(J::Arr(items));
                }
                loop {
                    items.push(self.value()?);
                    self.ws();
                    match self.peek() {
                        Some(b',') => self.i += 1,
                        Some(b']') => {
                            self.i += 1;
                            return Ok(J::Arr(items));
                        }
                        other => return Err(format!("JSON: wanted , or ], got {other:?}")),
                    }
                }
            }
            b'{' => {
                self.i += 1;
                let mut entries = Vec::new();
                self.ws();
                if self.peek() == Some(b'}') {
                    self.i += 1;
                    return Ok(J::Obj(entries));
                }
                loop {
                    self.ws();
                    let key = self.string()?;
                    self.ws();
                    self.expect(":")?;
                    let value = self.value()?;
                    entries.push((key, value));
                    self.ws();
                    match self.peek() {
                        Some(b',') => self.i += 1,
                        Some(b'}') => {
                            self.i += 1;
                            return Ok(J::Obj(entries));
                        }
                        other => return Err(format!("JSON: wanted , or }}, got {other:?}")),
                    }
                }
            }
            // number: scan and drop
            _ => {
                let start = self.i;
                while self.peek().is_some_and(|c| {
                    c.is_ascii_digit() || matches!(c, b'-' | b'+' | b'.' | b'e' | b'E')
                }) {
                    self.i += 1;
                }
                if self.i == start {
                    return Err(format!("JSON: bad value at byte {start}"));
                }
                Ok(J::Null)
            }
        }
    }

    fn string(&mut self) -> Result<String, String> {
        self.expect("\"")?;
        let mut out = String::new();
        loop {
            match self
                .peek()
                .ok_or_else(|| "JSON: string runs off the end".to_string())?
            {
                b'"' => {
                    self.i += 1;
                    return Ok(out);
                }
                b'\\' => {
                    self.i += 1;
                    match self.peek().ok_or_else(|| "JSON: bad escape".to_string())? {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'n' => out.push('\n'),
                        b't' => out.push('\t'),
                        b'r' => out.push('\r'),
                        b'b' => out.push('\u{0008}'),
                        b'f' => out.push('\u{000C}'),
                        b'u' => {
                            let hex: String = self.b[self.i + 1..]
                                .iter()
                                .take(4)
                                .map(|&c| c as char)
                                .collect();
                            let _code: u32 = u32::from_str_radix(&hex, 16)
                                .map_err(|_| "JSON: bad \\u escape".to_string())?;
                            out.push('\u{FFFD}'); // cargo metadata carries no astral escapes
                            self.i += 4;
                        }
                        other => return Err(format!("JSON: bad escape {other:?}")),
                    }
                    self.i += 1;
                }
                c if c < 0x80 => {
                    out.push(c as char);
                    self.i += 1;
                }
                _ => {
                    // UTF-8 multibyte: copy the full scalar.
                    let len = utf8_len(self.b[self.i]);
                    let end = (self.i + len).min(self.b.len());
                    out.push_str(
                        std::str::from_utf8(&self.b[self.i..end]).map_err(|_| "JSON: bad UTF-8")?,
                    );
                    self.i = end;
                }
            }
        }
    }
}

fn utf8_len(first: u8) -> usize {
    match first {
        0x00..=0x7F => 1,
        0xC0..=0xDF => 2,
        0xE0..=0xEF => 3,
        _ => 4,
    }
}

impl J {
    fn get(&self, key: &str) -> Option<&J> {
        match self {
            J::Obj(entries) => entries.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }
    fn as_str(&self) -> Option<&str> {
        match self {
            J::Str(s) => Some(s),
            _ => None,
        }
    }
    fn as_arr(&self) -> Option<&[J]> {
        match self {
            J::Arr(items) => Some(items),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// The SBOM itself.
// ---------------------------------------------------------------------------

/// The SBOM itself.
// ---------------------------------------------------------------------------

/// One resolved package of interest.
struct Pkg {
    id: String,
    version: String,
    checksum: Option<String>,
}

/// `(name, version) -> SHA-256` from the workspace lock: the checksums cargo enforces under
/// `--locked`. Workspace path packages have no entry — no hash, by design.
fn lock_checksums(
    root: &Path,
) -> Result<std::collections::BTreeMap<(String, String), String>, String> {
    let text = std::fs::read_to_string(root.join("Cargo.lock"))
        .map_err(|e| format!("cannot read Cargo.lock: {e}"))?;
    let mut out = std::collections::BTreeMap::new();
    for block in text.split("[[package]]").skip(1) {
        let value = |key: &str| -> Option<String> {
            block.lines().find_map(|l| {
                let (k, v) = l.split_once('=')?;
                (k.trim() == key).then(|| v.trim().trim_matches('"').to_string())
            })
        };
        let (name, version, checksum) = match (value("name"), value("version"), value("checksum")) {
            (Some(n), Some(v), Some(c)) => (n, v, c),
            _ => continue,
        };
        out.insert((name, version), checksum);
    }
    Ok(out)
}

fn purl(name: &str, version: &str) -> String {
    format!("pkg:cargo/{name}@{version}")
}

/// Builds the CycloneDX 1.7 document for `package`'s resolved graph. Deterministic:
/// components sorted by purl, fixed key order, no timestamp or serial number.
pub fn sbom_json(package: &str) -> Result<String, String> {
    let output = std::process::Command::new("cargo")
        .args(["metadata", "--locked", "--offline", "--format-version", "1"])
        .current_dir(ws_root())
        .output()
        .map_err(|e| format!("cannot run cargo metadata: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "cargo metadata refused (exit {}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let text = String::from_utf8(output.stdout)
        .map_err(|_| "cargo metadata answered non-UTF-8".to_string())?;
    let doc = Reader::new(&text)
        .value()
        .map_err(|e| format!("cargo metadata's JSON: {e}"))?;
    let checksums = lock_checksums(&ws_root())?;

    let mut by_id: Vec<Pkg> = Vec::new();
    let mut root: Option<String> = None;
    for pkg in doc
        .get("packages")
        .and_then(J::as_arr)
        .ok_or_else(|| "metadata has no packages[]".to_string())?
    {
        let name = pkg
            .get("name")
            .and_then(J::as_str)
            .ok_or_else(|| "a package has no name".to_string())?;
        let id = pkg
            .get("id")
            .and_then(J::as_str)
            .ok_or_else(|| "a package has no id".to_string())?
            .to_string();
        if name == package {
            root = Some(id.clone());
        }
        let version = pkg
            .get("version")
            .and_then(J::as_str)
            .unwrap_or("0")
            .to_string();
        // cargo metadata no longer carries per-package checksums; the lock does.
        let checksum = checksums.get(&(name.to_string(), version.clone())).cloned();
        by_id.push(Pkg {
            id,
            version,
            checksum,
        });
    }
    let root_id = root.ok_or_else(|| format!("SBOM no workspace package named {package}"))?;
    let root_pkg = by_id
        .iter()
        .find(|p| p.id == root_id)
        .expect("root is in packages");

    // The resolve graph: BFS over nodes' dep edges from the root.
    let mut edges: Vec<(String, String)> = Vec::new();
    for node in doc
        .get("resolve")
        .and_then(|r| r.get("nodes"))
        .and_then(J::as_arr)
        .ok_or_else(|| "metadata has no resolve.nodes[]".to_string())?
    {
        let from = node
            .get("id")
            .and_then(J::as_str)
            .ok_or_else(|| "a node has no id".to_string())?;
        for dep in node.get("deps").and_then(J::as_arr).into_iter().flatten() {
            if let Some(to) = dep.get("pkg").and_then(J::as_str) {
                edges.push((from.to_string(), to.to_string()));
            }
        }
    }
    let mut seen = vec![root_id.clone()];
    let mut queue = vec![root_id.clone()];
    while let Some(from) = queue.pop() {
        for (a, b) in &edges {
            if *a == from && !seen.contains(b) {
                seen.push(b.clone());
                queue.push(b.clone());
            }
        }
    }

    let mut components: Vec<&Pkg> = by_id
        .iter()
        .filter(|p| p.id != root_pkg.id && seen.contains(&p.id))
        .collect();
    components.sort_by(|a, b| purl_of(a).cmp(&purl_of(b)));

    let name_of = |p: &Pkg| p.id.split(' ').next().unwrap_or(&p.id).to_string();
    let mut out = String::new();
    out.push_str(
        "{\n  \"bomFormat\": \"CycloneDX\",\n  \"specVersion\": \"1.7\",\n  \"version\": 1,\n",
    );
    out.push_str("  \"metadata\": {\n    \"component\": {\n");
    out.push_str(&format!(
        "      \"bom-ref\": \"{r}\",\n      \"name\": \"{n}\",\n      \"purl\": \"{r}\",\n      \"type\": \"library\",\n      \"version\": \"{v}\"\n",
        r = purl(&name_of(root_pkg), &root_pkg.version),
        n = name_of(root_pkg),
        v = root_pkg.version
    ));
    out.push_str("    }\n  },\n  \"components\": [");
    for (i, p) in components.iter().enumerate() {
        let name = name_of(p);
        let purl = purl(&name, &p.version);
        out.push_str(if i == 0 { "\n" } else { ",\n" });
        out.push_str("    {\n");
        out.push_str(&format!("      \"bom-ref\": \"{purl}\",\n"));
        if let Some(sha) = &p.checksum {
            out.push_str(&format!(
                "      \"hashes\": [ {{ \"alg\": \"SHA-256\", \"content\": \"{sha}\" }} ],\n"
            ));
        }
        out.push_str(&format!(
            "      \"name\": \"{name}\",\n      \"purl\": \"{purl}\",\n      \"type\": \"library\",\n      \"version\": \"{}\"\n",
            p.version
        ));
        out.push_str("    }");
    }
    out.push_str("\n  ]\n}\n");
    Ok(out)
}

fn purl_of(p: &Pkg) -> String {
    let name = p.id.split(' ').next().unwrap_or(&p.id);
    purl(name, &p.version)
}

/// `sbom --package <name> --out <path>`: writes the document and returns the fixed line.
pub fn sbom(package: &str, out: &Path) -> Result<String, String> {
    let doc = sbom_json(package)?;
    std::fs::write(out, &doc).map_err(|e| format!("cannot write {}: {e}", out.display()))?;
    Ok(format!(
        "SBOM path={} sha256={} components={}",
        out.display(),
        sha256_hex(doc.as_bytes()),
        doc.matches("\"purl\"").count() - 1
    ))
}

fn sha256_hex(b: &[u8]) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(b))
}
