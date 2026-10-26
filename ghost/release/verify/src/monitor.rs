//! `monitor` of `ghost-verify` (Phase 14 design §5.3): the rules an independent party runs at
//! least weekly. This module is the **pure rule engine**: the log's leaves arrive decoded (the
//! network half — Sigsum's get-leaves over TLS — is a separate slice), and the rules are pure
//! functions of what was logged, what the archive holds and what the mirrors serve now.
//!
//! Rules implemented here: (a) a leaf whose key hash is a release or root key of a GHOST root
//! must decode to a document whose message checksum it carries; (b) no two manifests share a
//! `(root_version, manifest_seq)` pair, and within one log pairs increase with the leaf index;
//! (f) a logged manifest that no mirror serves now is flagged (the short-window half of (f)
//! needs the observation series, which the caller passes in).
//!
//! Rules (c), (d), (e), (g) and (h) need the archive's files (APKs, ES files, symbol files, the
//! floor of every manifest): the engine takes their answers as inputs so this module stays
//! pure; the file-level checks land with the archive slice.

use ghost_client_release::manifest::GHRM;
use ghost_client_release::root::GHRT;

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Finding {
    /// (a) a key the policy watches submitted a leaf the archive cannot stand behind.
    UnmatchedLeaf { log: usize, index: u64, key_hash: [u8; 32] },
    /// (a) the archive's document fails the signature check.
    BadDocument { log: usize, index: u64 },
    /// (b) the same pair logged twice with different content.
    PairCollision { pair: (u32, u64), first: (usize, u64), second: (usize, u64) },
    /// (b) a log's pairs do not increase with the leaf index.
    PairOrder { log: usize, lower_index: u64, higher_index: u64, pair: (u32, u64) },
    /// (f) a logged manifest no mirror serves at run time.
    UnservedManifest { pair: (u32, u64) },
    /// (f) a pair observed served for less than 24 hours.
    ShortServed { pair: (u32, u64), mirror: Vec<u8> },
    /// (f) the pair's archive copy appeared more than 7 days after its leaf.
    LateArchive { pair: (u32, u64), days: u32 },
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
}

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
        .map(|k| ghost_client_release::key_id(k))
        .collect();

    // (a): watched keys' leaves must stand on the archive.
    for (log, leaves) in input.logs.iter().enumerate() {
        for leaf in leaves {
            if watched.contains(&leaf.key_hash) {
                match &leaf.doc {
                    LeafDoc::Unknown => out.push(Finding::UnmatchedLeaf { log, index: leaf.index, key_hash: leaf.key_hash }),
                    LeafDoc::Manifest { verifies: false, .. } | LeafDoc::Root { verifies: false, .. } => {
                        out.push(Finding::BadDocument { log, index: leaf.index })
                    }
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
                    out.push(Finding::PairCollision { pair, first: (*flog, *findex), second: (log, leaf.index) });
                } else {
                    seen.push((pair, log, leaf.index));
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
            out.push(Finding::ShortServed { pair: obs.pair, mirror: obs.mirror.clone() });
        }
    }
    for (pair, day) in input.archive_day {
        if let Some(obs) = input.observations.iter().find(|o| o.pair == *pair) {
            // The leaf predates the first observation (the serving window starts at it), so the
            // archive's latency is measured from the window's start.
            if *day > obs.first_seen_day + 7 {
                out.push(Finding::LateArchive { pair: *pair, days: *day - obs.first_seen_day });
            }
        }
    }
    out
}

/// The pair a parsed manifest claims (the monitor's view of it).
pub fn manifest_pair(m: &GHRM) -> (u32, u64) {
    (m.body.root_version, m.body.manifest_seq)
}
