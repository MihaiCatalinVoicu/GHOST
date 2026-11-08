//! `monitor` of `ghost-verify` (Phase 14 design §5.3): the rules an independent party runs at
//! least weekly. This module is the **pure rule engine**: the log's leaves arrive decoded (the
//! network half — Sigsum's get-leaves over TLS — is a separate slice), and the rules are pure
//! functions of what was logged, what the archive holds and what the mirrors serve now.
//!
//! Rules implemented here: (a) a leaf whose key hash is a release or root key of a GHOST root
//! must decode to a document whose message checksum it carries; (b) no two manifests share a
//! `(root_version, manifest_seq)` pair, and within one log pairs increase with the leaf index;
//! (c) every release's APK is in the archive with the stated `apk_sha256`, its core (§6.5)
//! matches the attested `unsigned_sha256` and every attestation verifies against the root's
//! attestation keyset; (d) the ES of consecutive releases is append-only (ADR-22 rule 5, the
//! same comparison `ghost-issuer-ops schedule-verify --previous` runs); (e) each symbol file's
//! GNU build-id equals its library's; (f) a logged manifest that no mirror serves now is
//! flagged (the short-window half of (f) needs the observation series, which the caller passes
//! in); (g) each release's `rollout_salt` is unchanged across re-signings and unique across
//! distinct releases; (h) the floor of every manifest respects §7.4 step 3, `issued_day` never
//! decreases with the manifest sequence within a root, and a release flagged wire-changing
//! never sits strictly between 0 and 1000 permille (§7.6's wire rule).
//!
//! The engine stays pure: the caller reads the archive's files (the file names are the
//! documents' SHA-256, §5.3's release record) and passes their bytes in [`MonitorInput`]. Rules
//! (c) and (e) hash and parse those bytes here; rule (d) takes the ES documents already
//! signature-verified (against the pinned schedule key, exactly as the client's `Schedule::
//! verify`), one `(declared es_seq, schedule)` pair per archived ES file.

use ghost_client_release::manifest::GHRM;
use ghost_client_release::root::GHRT;
use ghost_client_release::{ArtifactKind, StatementType};
use ghost_entitlement::{Schedule, ScheduleMemory};
use sha2::{Digest, Sha256};

use crate::buildid;

fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// One decoded leaf of a policy log.
#[derive(Debug, Clone)]
pub struct DecodedLeaf {
    pub index: u64,
    /// The log's stored leaf checksum: `SHA-256(message)`, the message being the file's SHA-256.
    pub checksum: [u8; 32],
    /// The key hash (Sigsum's leaf identity) of the submitter.
    pub key_hash: [u8; 32],
    /// What the archive holds for this checksum.
    pub doc: LeafDoc,
}

#[derive(Debug, Clone)]
pub enum LeafDoc {
    /// A release manifest: the pair it claims and whether its signatures verified against the
    /// newest root that lists its key (the archive check, §5.3 (a)).
    Manifest { pair: (u32, u64), verifies: bool },
    /// A root document.
    Root { version: u32, verifies: bool },
    /// The archive has no document for this leaf.
    Unknown,
}

/// What one mirror serves at `monitor` run time.
#[derive(Debug, Clone)]
pub struct Served {
    pub mirror: Vec<u8>,
    /// The pair and hash of its `current.ghrb`, if it answered.
    pub current: Option<((u32, u64), [u8; 32])>,
}

/// The observation series behind rule (f)'s short-window clause: the days a pair was observed
/// served, per mirror.
#[derive(Debug, Clone)]
pub struct Observation {
    pub pair: (u32, u64),
    pub mirror: Vec<u8>,
    pub first_seen_day: u32,
    pub last_seen_day: u32,
}

/// The archive's bytes for one release of one archived manifest (rules (c) and (e)): the APK
/// file and, parallel to the release's `artifacts` list, each artifact file the archive holds
/// (`None` where the archive has no file with the stated hash).
#[derive(Debug, Clone, Default)]
pub struct ArchiveReleaseFiles<'a> {
    /// The release's signed APK as the archive holds it (`None` = not archived).
    pub apk: Option<&'a [u8]>,
    /// Parallel to `Release.artifacts`: the artifact file's bytes, `None` where absent.
    pub artifacts: Vec<Option<&'a [u8]>>,
}

/// One archived manifest (rules (c), (e), (g), (h)): the parsed document, the root it binds
/// and verifies against (its attestation keyset is what rules (c) and (h) check against), and
/// the archive's file bytes per release.
#[derive(Debug, Clone)]
pub struct ArchiveManifest<'a> {
    pub manifest: &'a GHRM,
    /// The root this manifest's `root_version` binds (the caller walks the chain; the rules
    /// never trust a manifest's own claim of its root).
    pub root: &'a GHRT,
    /// Parallel to `manifest.body.releases`.
    pub releases: Vec<ArchiveReleaseFiles<'a>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Finding {
    /// (a) a key the policy watches submitted a leaf the archive cannot stand behind.
    UnmatchedLeaf {
        log: usize,
        index: u64,
        key_hash: [u8; 32],
    },
    /// (a) the archive's document fails the signature check.
    BadDocument { log: usize, index: u64 },
    /// (b) the same pair logged twice with different content.
    PairCollision {
        pair: (u32, u64),
        first: (usize, u64),
        second: (usize, u64),
    },
    /// (b) a log's pairs do not increase with the leaf index.
    PairOrder {
        log: usize,
        lower_index: u64,
        higher_index: u64,
        pair: (u32, u64),
    },
    /// (c) the archive holds no APK with the release's stated `apk_sha256`.
    MissingApk {
        version_code: u32,
        apk_sha256: [u8; 32],
    },
    /// (c) the archived APK's whole-file hash is not the manifest's `apk_sha256`.
    ApkHashMismatch {
        version_code: u32,
        apk_sha256: [u8; 32],
    },
    /// (c) the archived APK does not parse as a signed APK (§6.5's layout rule refuses it), so
    /// its core cannot be compared.
    ApkLayout { version_code: u32 },
    /// (c) the APK's §6.5 core hash is not the attested `unsigned_sha256`.
    CoreMismatch {
        version_code: u32,
        unsigned_sha256: [u8; 32],
    },
    /// (c) the release's attestation block does not verify against its root's attestation
    /// keyset (§4.5's block binds the GHRA; `GHRM::verify_attestation`).
    BadAttestation { version_code: u32 },
    /// (d) two archived ES files claim one `es_seq` with different contents.
    EsSeqConflict { es_seq: u64 },
    /// (d) the archived ES file's own `seq` is not the `es_seq` the release that names it
    /// declares (`Release.es_seq` binds the document).
    EsSeqMismatch { declared: u64, schedule_seq: u64 },
    /// (d) the ES's network changes between consecutive archived releases.
    EsNetworkChange { es_seq: u64 },
    /// (d) the ES of a release is not append-only against every earlier archived ES (ADR-22
    /// rule 5: keys, prices, the slot set of any covered week and revocations never change or
    /// disappear, and `seq` never decreases — `Schedule::check_memory` over the memory the
    /// earlier documents built).
    EsNotAppendOnly { es_seq: u64 },
    /// (e) the release lists a library and a symbol file of an ABI but the archive holds no
    /// file with one of the stated hashes (the build-id comparison has nothing to run on).
    MissingSymbols {
        version_code: u32,
        abi: &'static str,
    },
    /// (e) the library's and the symbol file's GNU build-ids differ (the symbol file does not
    /// describe the shipped binary).
    BuildIdMismatch {
        version_code: u32,
        abi: &'static str,
    },
    /// (e) a file's `.note.gnu.build-id` cannot be read (not a 64-bit little-endian ELF carrying
    /// the note — a truncated or foreign file sits in the archive under the stated hash).
    BuildIdUnreadable {
        version_code: u32,
        abi: &'static str,
    },
    /// (f) a logged manifest no mirror serves at run time.
    UnservedManifest { pair: (u32, u64) },
    /// (f) a pair observed served for less than 24 hours.
    ShortServed { pair: (u32, u64), mirror: Vec<u8> },
    /// (f) the pair's archive copy appeared more than 7 days after its leaf.
    LateArchive { pair: (u32, u64), days: u32 },
    /// (g) the same release (one `apk_sha256`) is listed with two different `rollout_salt`s
    /// across manifests — §7.6: the salt is fixed for the release's life.
    SaltChanged { apk_sha256: [u8; 32] },
    /// (g) two distinct releases (different `version_code`) share one `rollout_salt` — §7.6:
    /// each release's salt is drawn once and unique across releases.
    SaltShared {
        salt: [u8; 16],
        first_version_code: u32,
        second_version_code: u32,
    },
    /// (h) the manifest's floor is above the highest attested release of its own manifest
    /// (§7.4 step 3, the `attested_max` rule of `client-core/update/src/decision.rs`: the floor
    /// may not exceed the highest release whose attestation meets the root's attestation
    /// keyset).
    FloorInvalid {
        root_version: u32,
        manifest_seq: u64,
        floor: u32,
        attested_max: u32,
    },
    /// (h) a manifest's `issued_day` is below the previous manifest's of the same root.
    IssuedDayDecreased {
        root_version: u32,
        manifest_seq: u64,
        issued_day: u32,
        previous_seq: u64,
        previous_day: u32,
    },
    /// (h) a release flagged wire-changing (`release_flags` bit 0, §7.6's wire rule) sits at a
    /// rollout strictly between 0 (halt) and 1000 (everyone) — a wire change may stage only
    /// 0 → 1000, never a cohort.
    WireChangingStaged {
        version_code: u32,
        rollout_permille: u16,
    },
}

/// The alarm line (RK4's public alarm): `FLAG <NAME> k=v …`, hashes lowercase hex, byte
/// strings lossy UTF-8 — one line per finding, the only vocabulary `monitor` prints.
impl std::fmt::Display for Finding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let pair = |f: &mut std::fmt::Formatter<'_>, pair: (u32, u64)| {
            write!(f, "pair={}:{}", pair.0, pair.1)
        };
        match self {
            Finding::UnmatchedLeaf {
                log,
                index,
                key_hash,
            } => {
                write!(
                    f,
                    "FLAG UNMATCHED_LEAF log={log} index={index} key_hash={}",
                    hex::encode(key_hash)
                )
            }
            Finding::BadDocument { log, index } => {
                write!(f, "FLAG BAD_DOCUMENT log={log} index={index}")
            }
            Finding::PairCollision {
                pair: p,
                first,
                second,
            } => {
                write!(f, "FLAG PAIR_COLLISION ")?;
                pair(f, *p)?;
                write!(
                    f,
                    " first={}:{} second={}:{}",
                    first.0, first.1, second.0, second.1
                )
            }
            Finding::PairOrder {
                log,
                lower_index,
                higher_index,
                pair: p,
            } => {
                write!(f, "FLAG PAIR_ORDER log={log} lower_index={lower_index} higher_index={higher_index} ")?;
                pair(f, *p)
            }
            Finding::MissingApk {
                version_code,
                apk_sha256,
            } => {
                write!(
                    f,
                    "FLAG MISSING_APK version_code={version_code} apk_sha256={}",
                    hex::encode(apk_sha256)
                )
            }
            Finding::ApkHashMismatch {
                version_code,
                apk_sha256,
            } => {
                write!(
                    f,
                    "FLAG APK_HASH_MISMATCH version_code={version_code} apk_sha256={}",
                    hex::encode(apk_sha256)
                )
            }
            Finding::ApkLayout { version_code } => {
                write!(f, "FLAG APK_LAYOUT version_code={version_code}")
            }
            Finding::CoreMismatch {
                version_code,
                unsigned_sha256,
            } => {
                write!(
                    f,
                    "FLAG CORE_MISMATCH version_code={version_code} unsigned_sha256={}",
                    hex::encode(unsigned_sha256)
                )
            }
            Finding::BadAttestation { version_code } => {
                write!(f, "FLAG BAD_ATTESTATION version_code={version_code}")
            }
            Finding::EsSeqConflict { es_seq } => write!(f, "FLAG ES_SEQ_CONFLICT es_seq={es_seq}"),
            Finding::EsSeqMismatch {
                declared,
                schedule_seq,
            } => {
                write!(
                    f,
                    "FLAG ES_SEQ_MISMATCH declared={declared} schedule_seq={schedule_seq}"
                )
            }
            Finding::EsNetworkChange { es_seq } => {
                write!(f, "FLAG ES_NETWORK_CHANGE es_seq={es_seq}")
            }
            Finding::EsNotAppendOnly { es_seq } => {
                write!(f, "FLAG ES_NOT_APPEND_ONLY es_seq={es_seq}")
            }
            Finding::MissingSymbols { version_code, abi } => {
                write!(
                    f,
                    "FLAG MISSING_SYMBOLS version_code={version_code} abi={abi}"
                )
            }
            Finding::BuildIdMismatch { version_code, abi } => {
                write!(
                    f,
                    "FLAG BUILD_ID_MISMATCH version_code={version_code} abi={abi}"
                )
            }
            Finding::BuildIdUnreadable { version_code, abi } => {
                write!(
                    f,
                    "FLAG BUILD_ID_UNREADABLE version_code={version_code} abi={abi}"
                )
            }
            Finding::UnservedManifest { pair: p } => {
                write!(f, "FLAG UNSERVED_MANIFEST ")?;
                pair(f, *p)
            }
            Finding::ShortServed { pair: p, mirror } => {
                write!(f, "FLAG SHORT_SERVED ")?;
                pair(f, *p)?;
                write!(f, " mirror={}", String::from_utf8_lossy(mirror))
            }
            Finding::LateArchive { pair: p, days } => {
                write!(f, "FLAG LATE_ARCHIVE ")?;
                pair(f, *p)?;
                write!(f, " days={days}")
            }
            Finding::SaltChanged { apk_sha256 } => {
                write!(
                    f,
                    "FLAG SALT_CHANGED apk_sha256={}",
                    hex::encode(apk_sha256)
                )
            }
            Finding::SaltShared {
                salt,
                first_version_code,
                second_version_code,
            } => {
                write!(f, "FLAG SALT_SHARED salt={} first_version_code={first_version_code} second_version_code={second_version_code}", hex::encode(salt))
            }
            Finding::FloorInvalid {
                root_version,
                manifest_seq,
                floor,
                attested_max,
            } => {
                write!(f, "FLAG FLOOR_INVALID root_version={root_version} manifest_seq={manifest_seq} floor={floor} attested_max={attested_max}")
            }
            Finding::IssuedDayDecreased {
                root_version,
                manifest_seq,
                issued_day,
                previous_seq,
                previous_day,
            } => {
                write!(f, "FLAG ISSUED_DAY_DECREASED root_version={root_version} manifest_seq={manifest_seq} issued_day={issued_day} previous_seq={previous_seq} previous_day={previous_day}")
            }
            Finding::WireChangingStaged {
                version_code,
                rollout_permille,
            } => {
                write!(f, "FLAG WIRE_CHANGING_STAGED version_code={version_code} rollout_permille={rollout_permille}")
            }
        }
    }
}

/// The engine's whole input.
pub struct MonitorInput<'a> {
    /// The trusted root (the policy's anchor).
    pub root: &'a GHRT,
    /// One decoded-leaf list per policy log, in `root.logs` order.
    pub logs: &'a [Vec<DecodedLeaf>],
    /// What the mirrors serve now.
    pub served: &'a [Served],
    /// The observation series (rule (f)): every (pair, mirror) serving window the monitor saw.
    pub observations: &'a [Observation],
    /// When each logged pair's archive copy appeared (pair, day); pairs absent here were never
    /// archived. The leaf's day is the observation's first_seen_day minus its serving window.
    pub archive_day: &'a [((u32, u64), u32)],
    /// Today, for the (f) windows.
    pub today: u32,
    /// The archived manifests (rules (c), (e), (g), (h)), in any order — (h) orders by pair.
    pub archive: &'a [ArchiveManifest<'a>],
    /// Rule (d): one entry per archived ES file — the `es_seq` the release naming it declares
    /// and the document, signature-verified by the caller (exactly the client's `Schedule::
    /// verify`). Any order; the rule walks it in `es_seq`.
    pub es: &'a [(u64, Schedule)],
}

/// The ABIs whose library/symbol build-id pairs rule (e) checks.
const ABI_PAIRS: [(ArtifactKind, ArtifactKind, &str); 2] = [
    (
        ArtifactKind::NativeArm64,
        ArtifactKind::SymbolsArm64,
        "arm64-v8a",
    ),
    (
        ArtifactKind::NativeX86_64,
        ArtifactKind::SymbolsX86_64,
        "x86_64",
    ),
];

/// Runs the rules this module owns. Findings are deterministic in input order.
pub fn run(input: &MonitorInput<'_>) -> Vec<Finding> {
    let mut out = Vec::new();
    let watched: Vec<[u8; 32]> = input
        .root
        .body
        .release
        .keys
        .iter()
        .chain(input.root.body.root.keys.iter())
        .map(ghost_client_release::key_id)
        .collect();

    // (a): watched keys' leaves must stand on the archive.
    for (log, leaves) in input.logs.iter().enumerate() {
        for leaf in leaves {
            if watched.contains(&leaf.key_hash) {
                match &leaf.doc {
                    LeafDoc::Unknown => out.push(Finding::UnmatchedLeaf {
                        log,
                        index: leaf.index,
                        key_hash: leaf.key_hash,
                    }),
                    LeafDoc::Manifest {
                        verifies: false, ..
                    }
                    | LeafDoc::Root {
                        verifies: false, ..
                    } => out.push(Finding::BadDocument {
                        log,
                        index: leaf.index,
                    }),
                    _ => {}
                }
            }
        }
    }

    // (b): pairs strictly increase with the index inside one log; globally unique per content.
    let mut seen: Vec<((u32, u64), usize, u64)> = Vec::new();
    for (log, leaves) in input.logs.iter().enumerate() {
        let mut last: Option<((u32, u64), u64)> = None;
        for leaf in leaves {
            let pair = match &leaf.doc {
                LeafDoc::Manifest { pair, .. } => Some(*pair),
                _ => None,
            };
            if let Some(pair) = pair {
                if let Some((prev_pair, prev_index)) = last {
                    if pair <= prev_pair {
                        out.push(Finding::PairOrder {
                            log,
                            lower_index: leaf.index,
                            higher_index: prev_index,
                            pair,
                        });
                    }
                }
                last = Some((pair, leaf.index));
                if let Some((_, flog, findex)) = seen.iter().find(|entry| entry.0 == pair) {
                    out.push(Finding::PairCollision {
                        pair,
                        first: (*flog, *findex),
                        second: (log, leaf.index),
                    });
                } else {
                    seen.push((pair, log, leaf.index));
                }
            }
        }
    }

    // (c): every release's APK stands on the archive with the stated hash, its §6.5 core matches
    // the attested unsigned build, and its attestation verifies against the root's keyset.
    for entry in input.archive {
        let m = entry.manifest;
        for (i, rel) in m.body.releases.iter().enumerate() {
            match entry.releases.get(i).and_then(|r| r.apk) {
                None => out.push(Finding::MissingApk {
                    version_code: rel.version_code,
                    apk_sha256: rel.apk_sha256,
                }),
                Some(bytes) => {
                    if sha256(bytes) != rel.apk_sha256 {
                        out.push(Finding::ApkHashMismatch {
                            version_code: rel.version_code,
                            apk_sha256: rel.apk_sha256,
                        });
                    }
                    match core_sha256(bytes, rel.unsigned_length) {
                        Ok(core) if core == rel.unsigned_sha256 => {}
                        Ok(_) => out.push(Finding::CoreMismatch {
                            version_code: rel.version_code,
                            unsigned_sha256: rel.unsigned_sha256,
                        }),
                        Err(_) => out.push(Finding::ApkLayout {
                            version_code: rel.version_code,
                        }),
                    }
                }
            }
            if m.verify_attestation(
                i,
                &entry.root.body.attest.keys,
                entry.root.body.attest.threshold,
            )
            .is_err()
            {
                out.push(Finding::BadAttestation {
                    version_code: rel.version_code,
                });
            }
        }
    }

    // (d): the ES of consecutive releases is append-only (ADR-22 rule 5) — the same comparison
    // `ghost-issuer-ops schedule-verify --previous` runs: each document against the memory the
    // earlier ones built, in es_seq order.
    let mut es: Vec<&(u64, Schedule)> = input.es.iter().collect();
    es.sort_by_key(|(seq, _)| *seq);
    for w in es.windows(2) {
        if w[0].0 == w[1].0 && w[0].1.digest() != w[1].1.digest() {
            out.push(Finding::EsSeqConflict { es_seq: w[0].0 });
        }
    }
    let mut memory = ScheduleMemory::default();
    let mut prev: Option<&Schedule> = None;
    for (declared, schedule) in es {
        if schedule.seq() != *declared {
            out.push(Finding::EsSeqMismatch {
                declared: *declared,
                schedule_seq: schedule.seq(),
            });
            continue;
        }
        if let Some(last) = prev {
            if last.network() != schedule.network() {
                out.push(Finding::EsNetworkChange { es_seq: *declared });
                continue;
            }
            // A violating document must not enter the memory the later ones are checked
            // against: one bad ES is one finding, not a cascade.
            if schedule.check_memory(&memory).is_err() {
                out.push(Finding::EsNotAppendOnly { es_seq: *declared });
                continue;
            }
        }
        schedule.remember(&mut memory);
        prev = Some(schedule);
    }

    // (e): a release's symbol file and its library carry one GNU build-id (§6.3's split keeps
    // the note in both; a mismatch means the symbols describe another build).
    for entry in input.archive {
        for (i, rel) in entry.manifest.body.releases.iter().enumerate() {
            for (lib_kind, sym_kind, abi) in ABI_PAIRS {
                let (Some(lib_at), Some(sym_at)) = (
                    rel.artifacts.iter().position(|(k, _, _)| *k == lib_kind),
                    rel.artifacts.iter().position(|(k, _, _)| *k == sym_kind),
                ) else {
                    continue; // the manifest lists only one half: nothing to compare
                };
                let files = entry.releases.get(i);
                let lib = files.and_then(|f| f.artifacts.get(lib_at).copied().flatten());
                let sym = files.and_then(|f| f.artifacts.get(sym_at).copied().flatten());
                if lib.is_none() || sym.is_none() {
                    out.push(Finding::MissingSymbols {
                        version_code: rel.version_code,
                        abi,
                    });
                    continue;
                }
                match (
                    buildid::gnu_build_id(lib.unwrap_or_default()),
                    buildid::gnu_build_id(sym.unwrap_or_default()),
                ) {
                    (Ok(a), Ok(b)) if a == b => {}
                    (Ok(_), Ok(_)) => out.push(Finding::BuildIdMismatch {
                        version_code: rel.version_code,
                        abi,
                    }),
                    _ => out.push(Finding::BuildIdUnreadable {
                        version_code: rel.version_code,
                        abi,
                    }),
                }
            }
        }
    }

    // (f): a logged manifest that was never observed served is flagged (an old, superseded
    // pair that was served in its day is fine — the observation series says so); the window and
    // the archive's latency are bounded by the series and the archive days.
    for (pair, _, _) in &seen {
        if !input.observations.iter().any(|o| o.pair == *pair) {
            out.push(Finding::UnservedManifest { pair: *pair });
        }
    }
    for obs in input.observations {
        if obs.last_seen_day < obs.first_seen_day + 1 {
            out.push(Finding::ShortServed {
                pair: obs.pair,
                mirror: obs.mirror.clone(),
            });
        }
    }
    for (pair, day) in input.archive_day {
        if let Some(obs) = input.observations.iter().find(|o| o.pair == *pair) {
            // The leaf predates the first observation (the serving window starts at it), so the
            // archive's latency is measured from the window's start.
            if *day > obs.first_seen_day + 7 {
                out.push(Finding::LateArchive {
                    pair: *pair,
                    days: *day - obs.first_seen_day,
                });
            }
        }
    }

    // (g): a release's salt never changes across re-signings (one apk_sha256, one salt) and no
    // salt is shared by two distinct releases.
    let mut by_apk: Vec<([u8; 32], [u8; 16])> = Vec::new();
    let mut by_salt: Vec<([u8; 16], u32)> = Vec::new();
    for entry in input.archive {
        for rel in &entry.manifest.body.releases {
            if let Some((_, salt)) = by_apk.iter().find(|(a, _)| *a == rel.apk_sha256) {
                if *salt != rel.rollout_salt {
                    out.push(Finding::SaltChanged {
                        apk_sha256: rel.apk_sha256,
                    });
                }
            } else {
                by_apk.push((rel.apk_sha256, rel.rollout_salt));
            }
            if let Some((_, vc)) = by_salt.iter().find(|(s, _)| *s == rel.rollout_salt) {
                if *vc != rel.version_code {
                    out.push(Finding::SaltShared {
                        salt: rel.rollout_salt,
                        first_version_code: *vc,
                        second_version_code: rel.version_code,
                    });
                }
            } else {
                by_salt.push((rel.rollout_salt, rel.version_code));
            }
        }
    }

    // (h): floor bound (§7.4 step 3), the wire rule (§7.6) and the issued-day order, over the
    // manifests in pair order.
    let mut order: Vec<&ArchiveManifest<'_>> = input.archive.iter().collect();
    order.sort_by_key(|e| (e.manifest.body.root_version, e.manifest.body.manifest_seq));
    let mut last_day: Vec<(u32, u64, u32)> = Vec::new(); // (root_version, seq, issued_day)
    for entry in &order {
        let m = entry.manifest;
        // §7.4 step 3's floor bound, the attested_max rule of decision.rs verbatim: the highest
        // release whose attestation meets the root's attestation keyset; the floor may not
        // exceed it (with threshold 0 every release counts).
        let attested_max = m
            .body
            .releases
            .iter()
            .enumerate()
            .filter(|(i, _)| {
                m.attestations.get(*i).is_some_and(|at| {
                    at.meets(
                        &entry.root.body.attest.keys,
                        entry.root.body.attest.threshold,
                        &ghost_client_release::statement_bytes(
                            StatementType::BuildAttestation,
                            m.body.network,
                            &m.body.releases[*i].attestation(m.body.network).to_bytes(),
                        ),
                    )
                    .is_ok()
                })
            })
            .map(|(_, rel)| rel.version_code)
            .max()
            .unwrap_or(0);
        if m.body.floor_version_code > attested_max {
            out.push(Finding::FloorInvalid {
                root_version: m.body.root_version,
                manifest_seq: m.body.manifest_seq,
                floor: m.body.floor_version_code,
                attested_max,
            });
        }
        for rel in &m.body.releases {
            if rel.wire_changing && rel.rollout_permille > 0 && rel.rollout_permille < 1000 {
                out.push(Finding::WireChangingStaged {
                    version_code: rel.version_code,
                    rollout_permille: rel.rollout_permille,
                });
            }
        }
        match last_day
            .iter_mut()
            .find(|(rv, _, _)| *rv == m.body.root_version)
        {
            Some((_, prev_seq, prev_day)) => {
                if m.body.issued_day < *prev_day {
                    out.push(Finding::IssuedDayDecreased {
                        root_version: m.body.root_version,
                        manifest_seq: m.body.manifest_seq,
                        issued_day: m.body.issued_day,
                        previous_seq: *prev_seq,
                        previous_day: *prev_day,
                    });
                }
                *prev_seq = m.body.manifest_seq;
                *prev_day = m.body.issued_day;
            }
            None => last_day.push((m.body.root_version, m.body.manifest_seq, m.body.issued_day)),
        }
    }
    out
}

/// The pair a parsed manifest claims (the monitor's view of it).
pub fn manifest_pair(m: &GHRM) -> (u32, u64) {
    (m.body.root_version, m.body.manifest_seq)
}

/// The §6.5 core rule's hash half: extract the unsigned core of `file` given the attested
/// `unsigned_length` and hash it, so rule (c) can compare with the attested `unsigned_sha256`.
/// The layout rule is the normative one of §6.5 (and `ghost-release-ops`' `apkcore.rs`, the
/// same code the client's install step runs): the central directory runs to the end record,
/// the signing block's footer and sizes agree, `E = unsigned_length − cd_size − 22` satisfies
/// `0 < E ≤ B` with `B = E` aligned to 4096, the padding `[E, B)` is all zero, and the core is
/// `file[0,E) ‖ file[cd_offset, len)` with the EOCD cd-offset field set to `E`.
fn core_sha256(file: &[u8], unsigned_length: u64) -> Result<[u8; 32], CoreError> {
    const EOCD_LEN: u64 = 22;
    const PAGE: u64 = 4096;
    let length = file.len() as u64;
    if length < EOCD_LEN + 16 + 8 + 8 {
        return Err(CoreError::TooSmall);
    }
    let eocd_at = (length - EOCD_LEN) as usize;
    if &file[eocd_at..eocd_at + 4] != b"PK\x05\x06"
        || file[eocd_at + 20] != 0
        || file[eocd_at + 21] != 0
    {
        return Err(CoreError::Eocd); // comment length must be 0 (the signature sits at length − 22)
    }
    let cd_size = u32::from_le_bytes(
        file[eocd_at + 12..eocd_at + 16]
            .try_into()
            .expect("4 bytes"),
    ) as u64;
    let cd_offset = u32::from_le_bytes(
        file[eocd_at + 16..eocd_at + 20]
            .try_into()
            .expect("4 bytes"),
    ) as u64;
    if cd_offset + cd_size + EOCD_LEN != length {
        return Err(CoreError::CdLayout);
    }
    if cd_offset < 8 + 24 {
        return Err(CoreError::BlockFooter);
    }
    let footer = cd_offset as usize - 24;
    if &file[footer + 8..footer + 24] != b"APK Sig Block 42" {
        return Err(CoreError::BlockFooter);
    }
    let s = u64::from_le_bytes(file[footer..footer + 8].try_into().expect("8 bytes"));
    let block_start = cd_offset
        .checked_sub(8)
        .and_then(|x| x.checked_sub(s))
        .ok_or(CoreError::Bounds)?;
    if block_start + 8 > footer as u64
        || u64::from_le_bytes(
            file[block_start as usize..block_start as usize + 8]
                .try_into()
                .expect("8 bytes"),
        ) != s
    {
        return Err(CoreError::BlockSize);
    }
    let e = unsigned_length
        .checked_sub(cd_size)
        .and_then(|x| x.checked_sub(EOCD_LEN))
        .ok_or(CoreError::Bounds)?;
    let b = block_start;
    if !(0 < e && e <= b) || b != e + ((PAGE - e % PAGE) % PAGE) {
        return Err(CoreError::Rule);
    }
    if file[e as usize..b as usize].iter().any(|&x| x != 0) {
        return Err(CoreError::Padding);
    }
    let mut core = Vec::with_capacity(e as usize + (length - cd_offset) as usize);
    core.extend_from_slice(&file[..e as usize]);
    core.extend_from_slice(&file[cd_offset as usize..]);
    let tail = core.len() - EOCD_LEN as usize;
    core[tail + 16..tail + 20].copy_from_slice(&(e as u32).to_le_bytes());
    Ok(sha256(&core))
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CoreError {
    TooSmall,
    Eocd,
    CdLayout,
    BlockFooter,
    BlockSize,
    Bounds,
    Rule,
    Padding,
}
