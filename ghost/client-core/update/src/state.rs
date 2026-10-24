//! The stored facts (design §9.6) as the pure crate sees them: what the SQLCipher tables hold,
//! passed in and returned out; persistence itself is `:update`'s job, in one transaction.

/// The trust epoch (§7.4 step 0): `id = SHA-256(newest embedded root)` for a recovery lineage, or
/// the lineage marker the first start established. The crate treats it as opaque bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustEpoch {
    pub id: [u8; 32],
    /// The installed `versionCode` the epoch was established under; step 0 reruns when it changes.
    pub version_code: u32,
}

/// The append-only `(root_version, manifest_seq)` pair (§7.4 step 6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Pair {
    pub root_version: u32,
    pub manifest_seq: u64,
}

/// The floor and the root version whose scope it belongs to (§7.5: append-only within a root
/// version; a new root starts a new floor scope).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Floor {
    pub version_code: u32,
    pub root_version: u32,
}

/// The time input (§7.4): trusted (from `:sync`'s clock trust) or not. With an untrusted clock
/// every time-dependent step stops with `CLOCK_UNTRUSTED` and nothing changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Time {
    Trusted { day: u32, now_secs: u64 },
    Untrusted,
}

impl Time {
    pub fn day(self) -> Option<u32> {
        match self {
            Time::Trusted { day, .. } => Some(day),
            Time::Untrusted => None,
        }
    }
}

/// The directory facts a fresh, current acceptance may change (§7.4 step 7, §7.8). The engine
/// applies these in the same transaction as the manifest persist, and on top of them enforces
/// two rules with its own knowledge of the existing directory: operator ids are write-once per
/// onion (a manifest's new value for a known onion is ignored), and relays the new manifest does
/// not list are retired (Phase 7 semantics).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PersistedChange {
    /// A relay directory entry to upsert (onion, operator id).
    RelayUpsert(Vec<u8>, [u8; 16]),
    /// The mirror set of the fresh current manifest (its extra mirrors); the anchor mirrors come
    /// from the root, never from here.
    MirrorsFromManifest(Vec<(Vec<u8>, [u8; 16])>),
}

/// The channel status Phase 13 shows and the copy names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelStatus {
    /// A fresh, current manifest: offers can come from it.
    Current,
    /// The manifest is expired (or none): the app works on its last directory, no offers.
    Stale,
    /// No manifest names the trusted root (e.g. right after a newer root was adopted).
    NoManifest,
}

/// The stored state the decision reads and returns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredState {
    /// The epoch the facts belong to.
    pub epoch: TrustEpoch,
    /// The trusted root version and the stored chain's roots, in ascending version order. The
    /// chain always contains the trusted root as its last element.
    pub chain: Vec<ghost_client_release::root::GHRT>,
    /// The stored pair and the accepted manifest with its proof (§9.6); `None` before the first
    /// acceptance. The stored manifest is "current" only while its `root_version` equals the
    /// trusted root's.
    pub pair: Pair,
    pub manifest: Option<ghost_client_release::manifest::GHRM>,
    pub manifest_proof: Option<ghost_client_release::proof::GHRP>,
    pub manifest_sha256: Option<[u8; 32]>,
    /// The floor.
    pub floor: Floor,
    /// `CONFLICT` for the root version at which it was seen (cleared when the root version rises).
    pub conflict: bool,
    /// `ROOT_CONFLICT` (§4.4): evidence of root-key equivocation; lasts for the epoch.
    pub root_conflict: bool,
}

impl StoredState {
    /// The trusted root: the last root of the stored chain.
    pub fn trusted_root(&self) -> &ghost_client_release::root::GHRT {
        self.chain.last().expect("stored chain is never empty")
    }
}
