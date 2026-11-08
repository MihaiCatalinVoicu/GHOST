//! The archive walker of `ghost-verify monitor` (design §5.3's release record): reads a local
//! archive directory into the monitor engine's input, so anyone can run the rules against what
//! a mirror publishes. Everything the walker refuses is an [`ArchiveError`] — a fixed
//! vocabulary, never a panic; the CLI prints it as `REFUSED ARCHIVE_<WORD> …` and exits 1
//! (a broken archive must never read as "no findings").
//!
//! # The archive layout (§5.3)
//!
//! Every file is named by its SHA-256 (`<64 lowercase hex>`), in the directory given by
//! `monitor --archive`. `archive-index.txt` names the logged manifests and is the walker's
//! entry point: only manifests the index claims are monitored (scanning the directory for
//! documents the index does not claim would let an archive steer the monitor). Per release the
//! walker loads the APK (named by `apk_sha256`), every artifact file (named by the artifact's
//! hash — the build-id pairs of kinds 1–4 among them) and the ES file (named by `es_sha256`).
//! Every loaded file's bytes are hashed and compared with its name: a sha-named file whose
//! bytes hash otherwise is refused, not worked around — the check subsumes rule (c)'s hash
//! clause (a swapped APK refuses the archive as `ARCHIVE_FILE_HASH_MISMATCH` before the rules
//! run; the engine's `ApkHashMismatch` finding remains for other callers of the pure rules).
//!
//! ## `archive-index.txt` — the line grammar
//!
//! §5.3 names a line's content — "pair, SHA-256, log, leaf index, releases with their
//! `apk_sha256` and salt" — but not its spelling; where the design is silent this walker
//! defines it, strict:
//!
//! ```text
//! <root_version>:<manifest_seq> <manifest_sha256> <log_key_hash> <leaf_index> <apk_sha256>:<rollout_salt_hex>…
//! ```
//!
//! - one line per logged manifest, LF-terminated, no blank lines and no comments;
//! - lowercase hex, single spaces (a double space or a trailing one is refused);
//! - at least one `<apk_sha256>:<rollout_salt_hex>` release field, in the manifest's release
//!   order.
//!
//! The walker cross-checks every line against the manifest it names: the pair must match, the
//! release list must match the parsed manifest's `(apk_sha256, rollout_salt)` in order, the
//! manifest's signature block must verify under its binding root's release keyset, and the
//! leaf the line claims at `<leaf_index>` must carry `SHA-256(SHA-256(manifest))` as its
//! checksum (the log stores the checksum of the message, §5.1).
//!
//! ## The served record (`monitor --served-record`)
//!
//! The "what was served" fetch loop is a separate daemon concern (§5.3 (f)); this walker reads
//! its hand-off, NDJSON — one observation per line, this exact flat shape (no whitespace
//! tolerance, no escapes; an onion id is `[a-z0-9.:]`):
//!
//! ```json
//! {"pair":[<root_version>,<seq>],"mirror":"<onion:port>","first_seen_day":<day>,"last_seen_day":<day>}
//! ```
//!
//! Each line becomes one engine [`Observation`]. The record does not carry when a pair's
//! archive copy appeared, so rule (f)'s `LateArchive` clause stays silent on this input; the
//! daemon's future hand-off would add it.
//!
//! ## What the walker does not do
//!
//! GHRP proofs are not consumed: inclusion proofs are the client's acceptance check (§7.4 step
//! 4), while the monitor's log linkage is rule (a)'s double-hash match — the design's rules
//! (a)–(i) name no proof check. Leaf *signatures* are not verified either (rule (a) binds a
//! leaf to the archive by checksum and to a watched key by key hash; submitter-key signature
//! verification is the log's admission job, §5.1). Root leaves match the anchor and the
//! binding roots the manifests name; a root's `verifies` is the chain rule with one hop (the
//! anchor signs the next root, §4.3) — deeper chains need the chain slice and read as
//! `BAD_DOCUMENT` until then.

use std::collections::HashMap;
use std::path::Path;

use ghost_client_release::manifest::GHRM;
use ghost_client_release::root::GHRT;
use ghost_entitlement::Schedule;

use crate::monitor::{
    ArchiveManifest, ArchiveReleaseFiles, DecodedLeaf, Finding, LeafDoc, MonitorInput, Observation,
};
use crate::sigsum::RawLeaf;

fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(data).into()
}

fn hex32(s: &str) -> Result<[u8; 32], &'static str> {
    let b = hex::decode(s).map_err(|_| "not-hex")?;
    b.try_into().map_err(|_| "not-32-bytes")
}

fn hex16(s: &str) -> Result<[u8; 16], &'static str> {
    let b = hex::decode(s).map_err(|_| "not-hex")?;
    b.try_into().map_err(|_| "not-16-bytes")
}

fn dec_u32(s: &str) -> Result<u32, &'static str> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err("not-decimal");
    }
    s.parse().map_err(|_| "out-of-range")
}

fn dec_u64(s: &str) -> Result<u64, &'static str> {
    dec_u32(s).map(u64::from)
}

/// Why an archive was refused, in fixed words (the CLI prints `REFUSED ARCHIVE_<WORD> …`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArchiveError {
    IndexMissing,
    IndexUnreadable,
    IndexLine {
        line: usize,
        reason: &'static str,
    },
    FileUnreadable {
        word: &'static str,
        sha256: [u8; 32],
    },
    FileHashMismatch {
        sha256: [u8; 32],
    },
    ManifestParse,
    PairMismatch,
    ReleaseListMismatch,
    RootBinding,
    RootParse,
    EsMissing {
        es_sha256: [u8; 32],
    },
    EsVerify,
    LeafLine {
        line: usize,
    },
    LeafBeyond {
        leaf_index: u64,
        leaves: usize,
    },
    LeafMismatch {
        leaf_index: u64,
    },
}

impl std::fmt::Display for ArchiveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ArchiveError::IndexMissing => write!(f, "ARCHIVE_INDEX_MISSING archive-index.txt"),
            ArchiveError::IndexUnreadable => write!(f, "ARCHIVE_INDEX_UNREADABLE"),
            ArchiveError::IndexLine { line, reason } => {
                write!(f, "ARCHIVE_INDEX_LINE line={line} reason={reason}")
            }
            ArchiveError::FileUnreadable { word, sha256 } => write!(
                f,
                "ARCHIVE_FILE_UNREADABLE what={word} sha256={}",
                hex::encode(sha256)
            ),
            ArchiveError::FileHashMismatch { sha256 } => write!(
                f,
                "ARCHIVE_FILE_HASH_MISMATCH sha256={}",
                hex::encode(sha256)
            ),
            ArchiveError::ManifestParse => write!(f, "ARCHIVE_MANIFEST_PARSE"),
            ArchiveError::PairMismatch => write!(f, "ARCHIVE_PAIR_MISMATCH"),
            ArchiveError::ReleaseListMismatch => write!(f, "ARCHIVE_RELEASE_LIST_MISMATCH"),
            ArchiveError::RootBinding => write!(f, "ARCHIVE_ROOT_BINDING"),
            ArchiveError::RootParse => write!(f, "ARCHIVE_ROOT_PARSE"),
            ArchiveError::EsMissing { es_sha256 } => {
                write!(f, "ARCHIVE_ES_MISSING es_sha256={}", hex::encode(es_sha256))
            }
            ArchiveError::EsVerify => write!(f, "ARCHIVE_ES_VERIFY"),
            ArchiveError::LeafLine { line } => write!(f, "ARCHIVE_LEAF_LINE line={line}"),
            ArchiveError::LeafBeyond { leaf_index, leaves } => write!(
                f,
                "ARCHIVE_LEAF_BEYOND leaf_index={leaf_index} leaves={leaves}"
            ),
            ArchiveError::LeafMismatch { leaf_index } => {
                write!(f, "ARCHIVE_LEAF_MISMATCH leaf_index={leaf_index}")
            }
        }
    }
}

#[derive(Debug)]
struct LoadedManifest {
    doc: GHRM,
    double_sha: [u8; 32],
    root_idx: usize,
    verifies: bool,
    pair: (u32, u64),
    leaf_index: u64,
}

#[derive(Debug)]
struct RootMeta {
    root: GHRT,
    double_sha: [u8; 32],
    verifies: bool,
}

/// A prepared monitor run: the archive loaded, leaves and observations attached. Build it with
/// [`Monitor::load`], attach the log's leaves (offline file or live fetch), then [`Monitor::run`].
#[derive(Debug)]
pub struct Monitor {
    today: u32,
    root: GHRT,
    anchor_bytes: Vec<u8>,
    anchor_double_sha: [u8; 32],
    manifests: Vec<LoadedManifest>,
    roots: Vec<GHRT>,
    roots_by_sha: HashMap<[u8; 32], usize>,
    root_metas: Vec<RootMeta>,
    files: Vec<Vec<u8>>,
    by_name: HashMap<[u8; 32], usize>,
    es: Vec<(u64, Schedule)>,
    leaves: Vec<DecodedLeaf>,
    observations: Vec<Observation>,
    archive_day: Vec<((u32, u64), u32)>,
    drill_keys: Vec<[u8; 32]>,
}

impl Monitor {
    /// Loads the archive under `dir`, anchored at `anchor` (the policy's trusted root bytes).
    /// ES files verify under the pinned schedule key, or under `schedule_key` where the design
    /// allows an explicit one (test/regtest archives — `ghost-issuer-ops schedule-verify
    /// --schedule-public-key`'s precedent); production archives pass `None`.
    pub fn load(
        dir: &Path,
        anchor: &[u8],
        schedule_key: Option<&[u8; 32]>,
        today: u32,
    ) -> Result<Monitor, ArchiveError> {
        let root = GHRT::parse(anchor).map_err(|_| ArchiveError::RootParse)?;
        let anchor_bytes = anchor.to_vec();
        let anchor_double_sha = sha256(&sha256(&anchor_bytes));
        let index = std::fs::read(dir.join("archive-index.txt")).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                ArchiveError::IndexMissing
            } else {
                ArchiveError::IndexUnreadable
            }
        })?;
        let text = String::from_utf8(index).map_err(|_| ArchiveError::IndexUnreadable)?;
        let mut m = Monitor {
            today,
            root,
            anchor_bytes,
            anchor_double_sha,
            manifests: Vec::new(),
            roots: Vec::new(),
            roots_by_sha: HashMap::new(),
            root_metas: Vec::new(),
            files: Vec::new(),
            by_name: HashMap::new(),
            es: Vec::new(),
            leaves: Vec::new(),
            observations: Vec::new(),
            archive_day: Vec::new(),
            drill_keys: Vec::new(),
        };
        // The anchor answers root leaves itself.
        m.root_metas.push(RootMeta {
            double_sha: m.anchor_double_sha,
            verifies: true,
            root: m.root.clone(),
        });
        for (n, line) in text.lines().enumerate() {
            let line_no = n + 1;
            if line.is_empty() {
                return Err(ArchiveError::IndexLine {
                    line: line_no,
                    reason: "blank-line",
                });
            }
            m.load_index_line(dir, line, line_no, schedule_key)?;
        }
        Ok(m)
    }

    /// Reads one file named by its SHA-256; `required` distinguishes a refusal from an absent
    /// file the engine reports as a finding. Every returned file's bytes hash to its name.
    fn take_file(
        &mut self,
        dir: &Path,
        sha: [u8; 32],
        word: &'static str,
        required: bool,
    ) -> Result<Option<usize>, ArchiveError> {
        if let Some(&i) = self.by_name.get(&sha) {
            return Ok(Some(i));
        }
        let path = dir.join(hex::encode(sha));
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) => {
                return if required || e.kind() != std::io::ErrorKind::NotFound {
                    Err(ArchiveError::FileUnreadable { word, sha256: sha })
                } else {
                    Ok(None)
                };
            }
        };
        if sha256(&bytes) != sha {
            return Err(ArchiveError::FileHashMismatch { sha256: sha });
        }
        let i = self.files.len();
        self.files.push(bytes);
        self.by_name.insert(sha, i);
        Ok(Some(i))
    }

    fn load_index_line(
        &mut self,
        dir: &Path,
        line: &str,
        line_no: usize,
        schedule_key: Option<&[u8; 32]>,
    ) -> Result<(), ArchiveError> {
        let bad = |reason: &'static str| ArchiveError::IndexLine {
            line: line_no,
            reason,
        };
        let fields: Vec<&str> = line.split(' ').collect();
        if fields.iter().any(|f| f.is_empty()) {
            return Err(bad("empty-field"));
        }
        if fields.len() < 5 {
            return Err(bad("too-few-fields"));
        }
        let (rv, seq) = fields[0].split_once(':').ok_or(bad("pair"))?;
        let pair = (
            dec_u32(rv).map_err(|_| bad("pair"))?,
            dec_u64(seq).map_err(|_| bad("pair"))?,
        );
        let doc_sha = hex32(fields[1]).map_err(|_| bad("sha256"))?;
        let _log_key_hash = hex32(fields[2]).map_err(|_| bad("log-key-hash"))?;
        let leaf_index = dec_u64(fields[3]).map_err(|_| bad("leaf-index"))?;
        let mut releases: Vec<([u8; 32], [u8; 16])> = Vec::new();
        for field in &fields[4..] {
            let (apk, salt) = field.split_once(':').ok_or(bad("release"))?;
            releases.push((
                hex32(apk).map_err(|_| bad("release"))?,
                hex16(salt).map_err(|_| bad("release"))?,
            ));
        }
        let doc_i = self
            .take_file(dir, doc_sha, "manifest", true)?
            .expect("required");
        let doc = GHRM::parse(&self.files[doc_i]).map_err(|_| ArchiveError::ManifestParse)?;
        if (doc.body.root_version, doc.body.manifest_seq) != pair {
            return Err(ArchiveError::PairMismatch);
        }
        let listed: Vec<([u8; 32], [u8; 16])> = doc
            .body
            .releases
            .iter()
            .map(|r| (r.apk_sha256, r.rollout_salt))
            .collect();
        if listed != releases {
            return Err(ArchiveError::ReleaseListMismatch);
        }
        // The binding root the manifest's root_sha256 names; its signatures must verify under
        // the root keyset it binds to (one chain hop from the anchor, §4.3 — see the module doc).
        let root_sha = doc.body.root_sha256;
        let root_i = match self.roots_by_sha.get(&root_sha) {
            Some(&i) => i,
            None => {
                let ri = self
                    .take_file(dir, root_sha, "root", true)?
                    .expect("required");
                let bytes = self.files[ri].clone();
                let root = GHRT::parse(&bytes).map_err(|_| ArchiveError::RootParse)?;
                if root.body.root_version != doc.body.root_version || sha256(&bytes) != root_sha {
                    return Err(ArchiveError::RootBinding);
                }
                let verifies = bytes == self.anchor_bytes
                    || (root.body.root_version == self.root.body.root_version + 1
                        && root
                            .verify_block(&self.root.body.root.keys, self.root.body.root.threshold)
                            .is_ok());
                let double_sha = sha256(&sha256(&bytes));
                self.roots.push(root.clone());
                self.root_metas.push(RootMeta {
                    root,
                    double_sha,
                    verifies,
                });
                let i = self.roots.len() - 1;
                self.roots_by_sha.insert(root_sha, i);
                i
            }
        };
        let root = &self.roots[root_i];
        let verifies = doc
            .verify_block(&root.body.release.keys, root.body.release.threshold)
            .is_ok();
        let double_sha = sha256(&sha256(&self.files[doc_i]));
        // The release files the engine hashes and compares: absence stays an engine finding.
        for rel in &doc.body.releases {
            self.take_file(dir, rel.apk_sha256, "apk", false)?;
            for (_, sha, _) in &rel.artifacts {
                self.take_file(dir, *sha, "artifact", false)?;
            }
            let es_i = self
                .take_file(dir, rel.es_sha256, "es", true)
                .map_err(|e| match e {
                    ArchiveError::FileUnreadable { .. } => ArchiveError::EsMissing {
                        es_sha256: rel.es_sha256,
                    },
                    other => other,
                })?
                .expect("required");
            let schedule = match schedule_key {
                Some(key) => Schedule::verify_with_key(&self.files[es_i], key),
                None => Schedule::verify(&self.files[es_i]),
            }
            .map_err(|_| ArchiveError::EsVerify)?;
            let entry = (rel.es_seq, schedule);
            if !self
                .es
                .iter()
                .any(|(s, d)| *s == entry.0 && d.digest() == entry.1.digest())
            {
                self.es.push(entry);
            }
        }
        self.manifests.push(LoadedManifest {
            doc,
            double_sha,
            root_idx: root_i,
            verifies,
            pair,
            leaf_index,
        });
        Ok(())
    }

    /// Attaches the log's leaves (offline `--leaves` file or the live fetch), matching each to
    /// the archive: manifests and loaded roots by the leaf checksum's double hash, anything
    /// else `Unknown` — rule (a) then decides what a watched key may claim.
    pub fn attach_leaves(&mut self, leaves: &[RawLeaf]) -> Result<(), ArchiveError> {
        for m in &self.manifests {
            let at = m.leaf_index as usize;
            if at >= leaves.len() {
                return Err(ArchiveError::LeafBeyond {
                    leaf_index: m.leaf_index,
                    leaves: leaves.len(),
                });
            }
            if leaves[at].checksum != m.double_sha {
                return Err(ArchiveError::LeafMismatch {
                    leaf_index: m.leaf_index,
                });
            }
        }
        self.leaves = leaves
            .iter()
            .enumerate()
            .map(|(i, leaf)| {
                let doc = if let Some(m) = self
                    .manifests
                    .iter()
                    .find(|m| m.double_sha == leaf.checksum)
                {
                    LeafDoc::Manifest {
                        pair: m.pair,
                        verifies: m.verifies,
                    }
                } else if let Some(r) = self
                    .root_metas
                    .iter()
                    .find(|r| r.double_sha == leaf.checksum)
                {
                    LeafDoc::Root {
                        version: r.root.body.root_version,
                        verifies: r.verifies,
                    }
                } else {
                    LeafDoc::Unknown
                };
                DecodedLeaf {
                    index: i as u64,
                    checksum: leaf.checksum,
                    key_hash: leaf.key_hash,
                    doc,
                }
            })
            .collect();
        Ok(())
    }

    /// Attaches the offline `--leaves` record: one base64 C2SP leaf per line (see
    /// [`crate::sigsum::parse_leaf_line`]).
    pub fn attach_leaves_from_text(&mut self, text: &str) -> Result<(), ArchiveError> {
        let mut leaves = Vec::new();
        for (n, line) in text.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            let leaf = crate::sigsum::parse_leaf_line(line)
                .map_err(|_| ArchiveError::LeafLine { line: n + 1 })?;
            leaves.push(leaf);
        }
        self.attach_leaves(&leaves)
    }

    /// Attaches the served-observation record (the NDJSON hand-off; see the module doc).
    pub fn attach_served_record(&mut self, text: &str) -> Result<(), String> {
        for (n, line) in text.lines().enumerate() {
            if line.is_empty() {
                continue;
            }
            self.observations.push(
                parse_served_line(line)
                    .map_err(|e| format!("served record line {}: {e}", n + 1))?,
            );
        }
        Ok(())
    }

    /// The engine's archive view: one [`ArchiveManifest`] per loaded manifest, the artifact
    /// bytes looked up by their stated hashes (absent files are `None`, the engine's findings).
    pub fn archive_view(&self) -> Vec<ArchiveManifest<'_>> {
        self.manifests
            .iter()
            .map(|m| {
                let releases = m
                    .doc
                    .body
                    .releases
                    .iter()
                    .map(|rel| {
                        let file = |sha: &[u8; 32]| {
                            self.by_name.get(sha).map(|&i| self.files[i].as_slice())
                        };
                        ArchiveReleaseFiles {
                            apk: file(&rel.apk_sha256),
                            artifacts: rel.artifacts.iter().map(|(_, sha, _)| file(sha)).collect(),
                        }
                    })
                    .collect();
                ArchiveManifest {
                    manifest: &m.doc,
                    root: &self.roots[m.root_idx],
                    releases,
                }
            })
            .collect()
    }

    /// Registers a drill root's release/root key hash (rule (i); repeatable as the CLI's
    /// `--drill-key`). Leaves under registered drill keys report as drills, never as releases.
    pub fn register_drill_key(&mut self, key_hash: [u8; 32]) {
        if !self.drill_keys.contains(&key_hash) {
            self.drill_keys.push(key_hash);
        }
    }

    /// Runs the rules and returns the findings (deterministic in input order). Drill findings
    /// ([`Finding::DrillLeaf`]) are informational: the CLI counts them separately and they
    /// alone never set its exit code.
    pub fn run(&self) -> Vec<Finding> {
        let views = self.archive_view();
        crate::monitor::run(&MonitorInput {
            root: &self.root,
            logs: std::slice::from_ref(&self.leaves),
            served: &[],
            observations: &self.observations,
            archive_day: &self.archive_day,
            today: self.today,
            archive: &views,
            es: &self.es,
            drill_keys: &self.drill_keys,
        })
    }
}

/// Parses one served-record line — the fixed flat JSON shape documented in the module header.
pub fn parse_served_line(line: &str) -> Result<Observation, &'static str> {
    let mut cur = line;
    let expect = |cur: &mut &str, lit: &str| -> Result<(), &'static str> {
        if let Some(rest) = cur.strip_prefix(lit) {
            *cur = rest;
            Ok(())
        } else {
            Err("shape")
        }
    };
    let number = |cur: &mut &str, max: u64| -> Result<u64, &'static str> {
        let digits: usize = cur.bytes().take_while(|b| b.is_ascii_digit()).count();
        if digits == 0 {
            return Err("number");
        }
        let (num, rest) = cur.split_at(digits);
        *cur = rest;
        let v: u64 = num.parse().map_err(|_| "number")?;
        if v > max {
            return Err("range");
        }
        Ok(v)
    };
    expect(&mut cur, "{\"pair\":[")?;
    let rv = number(&mut cur, u32::MAX as u64)?;
    expect(&mut cur, ",")?;
    let seq = number(&mut cur, u64::MAX)?;
    expect(&mut cur, "],\"mirror\":\"")?;
    let end = cur.find('"').ok_or("mirror")?;
    let mirror = &cur[..end];
    if mirror.bytes().any(|b| b < 0x21 || b == b'\\' || b == b'"') {
        return Err("mirror");
    }
    cur = &cur[end..];
    expect(&mut cur, "\",\"first_seen_day\":")?;
    let first = number(&mut cur, u32::MAX as u64)?;
    expect(&mut cur, ",\"last_seen_day\":")?;
    let last = number(&mut cur, u32::MAX as u64)?;
    expect(&mut cur, "}")?;
    if !cur.is_empty() {
        return Err("trailing");
    }
    Ok(Observation {
        pair: (rv as u32, seq),
        mirror: mirror.as_bytes().to_vec(),
        first_seen_day: first as u32,
        last_seen_day: last as u32,
    })
}

/// The record after one more observation: `first_seen_day` is the minimum, `last_seen_day`
/// the maximum over every sighting of the same `(pair, mirror)`; a new (pair, mirror) appends
/// its own line. One line per `(pair, mirror)`, the record's invariant.
pub fn merge_observation(record: &mut Vec<Observation>, pair: (u32, u64), mirror: &[u8], day: u32) {
    match record
        .iter_mut()
        .find(|o| o.pair == pair && o.mirror == mirror)
    {
        Some(o) => {
            o.first_seen_day = o.first_seen_day.min(day);
            o.last_seen_day = o.last_seen_day.max(day);
        }
        None => record.push(Observation {
            pair,
            mirror: mirror.to_vec(),
            first_seen_day: day,
            last_seen_day: day,
        }),
    }
}

/// The record as NDJSON — the exact line shape [`parse_served_line`] reads.
pub fn record_text(record: &[Observation]) -> String {
    let mut out = String::new();
    for o in record {
        out.push_str(&format!(
            "{{\"pair\":[{},{}],\"mirror\":\"{}\",\"first_seen_day\":{},\"last_seen_day\":{}}}\n",
            o.pair.0,
            o.pair.1,
            String::from_utf8_lossy(&o.mirror),
            o.first_seen_day,
            o.last_seen_day
        ));
    }
    out
}

/// Reads a record file (absent = empty; malformed = refused).
pub fn parse_record(text: &str) -> Result<Vec<Observation>, String> {
    let mut out = Vec::new();
    for (n, line) in text.lines().enumerate() {
        if line.is_empty() {
            continue;
        }
        out.push(parse_served_line(line).map_err(|e| format!("record line {}: {e}", n + 1))?);
    }
    Ok(out)
}

/// Writes the record atomically (a sibling temp file + rename), so a reader never sees a
/// half-written record.
pub fn write_record_atomic(path: &Path, record: &[Observation]) -> Result<(), String> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, record_text(record))
        .map_err(|e| format!("cannot write {}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, path).map_err(|e| format!("cannot rename the record into place: {e}"))
}

/// The `--served-once` core (design §5.3 rule (f)'s buildable half): for every mirror, fetch
/// `current.ghrb` through `fetch`, parse the manifest's pair, merge the sighting at `day`
/// into the record at `record_path`, and write it back atomically. All-or-nothing: a mirror
/// that fails refuses the run before anything is written. Returns the observed
/// `(mirror, pair)` list.
///
/// `fetch` is the seam: the CLI wires the crate's SOCKS fetch (or the `--bundle-file`
/// fixture), tests close over fixture bytes — no Tor anywhere in tests.
pub fn served_once(
    mirrors: &[String],
    record_path: &Path,
    day: u32,
    fetch: &dyn Fn(&str) -> Result<Vec<u8>, String>,
) -> Result<Vec<(String, (u32, u64))>, String> {
    let mut record = match std::fs::read_to_string(record_path) {
        Ok(text) => parse_record(&text)?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(format!("cannot read {}: {e}", record_path.display())),
    };
    let mut seen = Vec::new();
    for mirror in mirrors {
        let bytes = fetch(mirror).map_err(|e| format!("mirror {mirror}: {e}"))?;
        let bundle = ghost_client_release::bundle::GHRB::parse(&bytes)
            .map_err(|e| format!("mirror {mirror}: the bundle does not parse: {e}"))?;
        let pair = crate::monitor::manifest_pair(&bundle.manifest);
        merge_observation(&mut record, pair, mirror.as_bytes(), day);
        seen.push((mirror.clone(), pair));
    }
    if let Some(parent) = record_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
        }
    }
    write_record_atomic(record_path, &record)?;
    Ok(seen)
}
