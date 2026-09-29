//! `GhostKv`, the value-semantics storage adapter of design §3.4 (answers SRLabs S1-3; S0-6, S0-17).
//!
//! 1. **Scope.** Every method that takes a `GroupId` is group-scoped (`mls_kv`), the others are
//!    global (`mls_global_kv`, tagged by Kotlin with the channel of the call). A group-scoped
//!    method called for a group other than the call's channel is refused, and a stored row whose
//!    key matches neither scope's layout is `STATE_CORRUPT` at load, never a guess.
//! 2. **Load.** A call's rows come through [`RowSource`], the cache seam of S0-17: today
//!    [`WrappedRows`], the rows Kotlin passes, each value `nonce(12) ‖ ChaCha20-Poly1305(state key,
//!    AD = "ghost/v1/mls-kv" ‖ scope ‖ channel_id ‖ SHA-256(k), v)`; a row that does not open is
//!    `STATE_CORRUPT`. Q18's version-checked native cache can implement the trait later.
//! 3. **Run.** OpenMLS runs over the in-memory map; every write and delete updates it and the
//!    net change-set.
//! 4. **Return.** On success the caller takes the change-set, wrapped under the state key; on any
//!    error nothing is returned. [`GhostKv::checkpoint`] and [`GhostKv::restore`] give a batched
//!    call per-item rollback (§3.4 point 9).
//! 5. **Day rewrite.** `write_message_secrets` replaces every `added_at` stamp OpenMLS took from
//!    `SystemTime::now()` by the start of the call's Kotlin-supplied day (§3.4 point 5, corrected
//!    §19.4); a missing or renamed field is `STATE_CORRUPT` (a recorded deviation, pinned by G-M7).
//! 8. **Past epochs, one row each.** The `MessageSecretsStore` is stored as a head row (the store
//!    with `past_epoch_trees` replaced by its epoch numbers) and one row per retained past epoch;
//!    an unchanged row is not rewritten (S0-6; a second recorded deviation like point 5).
//!
//! Values are OpenMLS's serde entities as JSON (the memory provider's format).

use std::collections::BTreeMap;
use std::sync::Mutex;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use openmls_traits::storage::{traits, StorageProvider, CURRENT_VERSION};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::derive::StateKey;
use crate::result::{Code, MlsError, MlsResult};

/// `mls_kv` (group-scoped) or `mls_global_kv` (global, tagged with the channel).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Scope {
    Group = 1,
    Global = 2,
}

impl Scope {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Scope::Group),
            2 => Some(Scope::Global),
            _ => None,
        }
    }
}

pub type RowKey = (Scope, Vec<u8>);

/// Errors of the adapter; every one is `STATE_CORRUPT` at the API (a failure inside OpenMLS's
/// storage calls surfaces as an OpenMLS error, which the operation maps).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KvError {
    /// A group-scoped method was called for a group other than the call's channel.
    ForeignGroup,
    /// A value did not (de)serialise.
    Serde,
    /// OpenMLS's serde layout moved (the day rewrite or the per-epoch split could not find a field).
    LayoutDrift(&'static str),
}

impl core::fmt::Display for KvError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for KvError {}

impl From<serde_json::Error> for KvError {
    fn from(_: serde_json::Error) -> Self {
        KvError::Serde
    }
}

/// A stored row as Kotlin passes it (§3.4 point 2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WrappedRow {
    pub scope: Scope,
    pub key: Vec<u8>,
    pub env: Vec<u8>,
}

/// One entry of a change-set: a wrapped value to put, or a delete (§3.4 point 4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Change {
    pub scope: Scope,
    pub key: Vec<u8>,
    /// `Some(env)` put, `None` delete.
    pub env: Option<Vec<u8>>,
}

pub type ChangeSet = Vec<Change>;

/// Where a call's plaintext rows come from: the cache seam of S0-17 (§3.4 point 4).
pub trait RowSource {
    fn load(
        &self,
        channel_id: &[u8; 32],
        state_key: &StateKey,
    ) -> MlsResult<Vec<(RowKey, Vec<u8>)>>;
}

/// The rows Kotlin passes, wrapped under the state key.
pub struct WrappedRows<'a>(pub &'a [WrappedRow]);

impl RowSource for WrappedRows<'_> {
    fn load(
        &self,
        channel_id: &[u8; 32],
        state_key: &StateKey,
    ) -> MlsResult<Vec<(RowKey, Vec<u8>)>> {
        let mut out = Vec::with_capacity(self.0.len());
        for r in self.0 {
            let v = unwrap(state_key, r.scope, channel_id, &r.key, &r.env)?;
            out.push(((r.scope, r.key.clone()), v));
        }
        Ok(out)
    }
}

/// How the `MessageSecretsStore` is laid out: one head row and one row per past epoch (S0-6, the
/// product layout), or OpenMLS's single value (kept for the byte-identity oracle of the WG replay,
/// design §3.4 point 8 and V10-12).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PastLayout {
    Split,
    Whole,
}

#[derive(Default, Clone)]
struct State {
    rows: BTreeMap<RowKey, Vec<u8>>,
    /// Net change-set: `Some(v)` put, `None` delete.
    dirty: BTreeMap<RowKey, Option<Vec<u8>>>,
}

/// A saved state of the map, for per-item rollback inside a batched call (§3.4 point 9).
pub struct Checkpoint(State);

impl Checkpoint {
    /// A copy (a loop that restores the same base repeatedly).
    pub fn duplicate(&self) -> Checkpoint {
        Checkpoint(self.0.clone())
    }
}

/// The adapter. One instance per call (value semantics).
pub struct GhostKv {
    channel_id: [u8; 32],
    group_key: Vec<u8>,
    day: u32,
    layout: PastLayout,
    state: Mutex<State>,
}

const DAY_SECS: u64 = 86_400;

impl GhostKv {
    /// An adapter for one call on `channel_id` (the MLS group id) on the Kotlin-supplied `day`.
    pub fn new(channel_id: [u8; 32], day: u32) -> Self {
        Self::for_group(&channel_id, channel_id, day)
    }

    /// An adapter for a group id of any length (the WG vectors' groups, V10-12); `ad_id` is what
    /// the wrapping AD binds (the channel id, or SHA-256 of a foreign group id).
    pub fn for_group(group_id: &[u8], ad_id: [u8; 32], day: u32) -> Self {
        let group_key = serde_json::to_vec(&openmls::group::GroupId::from_slice(group_id))
            .expect("a group id serialises");
        Self {
            channel_id: ad_id,
            group_key,
            day,
            layout: PastLayout::Split,
            state: Mutex::new(State::default()),
        }
    }

    pub fn with_layout(mut self, layout: PastLayout) -> Self {
        self.layout = layout;
        self
    }

    pub fn channel_id(&self) -> &[u8; 32] {
        &self.channel_id
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        // The map holds no invariant a panic could break halfway: a poisoned lock is recovered.
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Loads plaintext rows as the state before the call. Every key must match its scope's layout
    /// (a known label, and for a group-scoped row the call's group), or the call is
    /// `STATE_CORRUPT` (§3.4 point 1).
    pub fn load(&self, rows: Vec<(RowKey, Vec<u8>)>) -> MlsResult<()> {
        for ((scope, k), _) in &rows {
            if !self.key_in_scope(*scope, k) {
                return Err(MlsError::new(Code::StateCorrupt));
            }
        }
        let mut s = self.lock();
        s.rows = rows.into_iter().collect();
        s.dirty.clear();
        Ok(())
    }

    fn key_in_scope(&self, scope: Scope, k: &[u8]) -> bool {
        let Some(nul) = k.iter().position(|&b| b == 0) else {
            return false;
        };
        let (label, rest) = (&k[..nul], &k[nul + 1..]);
        let group = GROUP_LABELS.contains(&label);
        let global = GLOBAL_LABELS.contains(&label);
        match scope {
            // A group-scoped key is the group id, or a tuple whose first element is the group id.
            Scope::Group => {
                group
                    && (rest == self.group_key.as_slice()
                        || (rest.first() == Some(&b'[')
                            && rest[1..].starts_with(&self.group_key)
                            && rest.get(1 + self.group_key.len()) == Some(&b',')))
            }
            Scope::Global => global,
        }
    }

    /// The current in-memory rows (plaintext).
    pub fn rows(&self) -> BTreeMap<RowKey, Vec<u8>> {
        self.lock().rows.clone()
    }

    pub fn checkpoint(&self) -> Checkpoint {
        Checkpoint(self.lock().clone())
    }

    pub fn restore(&self, c: Checkpoint) {
        *self.lock() = c.0;
    }

    /// The net change-set in plaintext (key order), leaving the map clean.
    pub fn take_plain_changes(&self) -> BTreeMap<RowKey, Option<Vec<u8>>> {
        std::mem::take(&mut self.lock().dirty)
    }

    fn key(&self, label: &[u8], k: &impl Serialize) -> Result<Vec<u8>, KvError> {
        let mut o = label.to_vec();
        o.push(0);
        o.extend_from_slice(&serde_json::to_vec(k)?);
        Ok(o)
    }

    fn check_group(&self, group_id: &impl Serialize) -> Result<(), KvError> {
        if serde_json::to_vec(group_id)? == self.group_key {
            Ok(())
        } else {
            Err(KvError::ForeignGroup)
        }
    }

    fn put_raw(&self, scope: Scope, k: Vec<u8>, v: Vec<u8>) {
        let mut s = self.lock();
        s.rows.insert((scope, k.clone()), v.clone());
        s.dirty.insert((scope, k), Some(v));
    }

    fn del_raw(&self, scope: Scope, k: Vec<u8>) {
        let mut s = self.lock();
        let existed = s.rows.remove(&(scope, k.clone())).is_some();
        // A delete of a row that exists neither before the call nor in its writes changes nothing;
        // a delete after a put in the same call cancels the put (and still deletes a stored row).
        if existed || s.dirty.contains_key(&(scope, k.clone())) {
            s.dirty.insert((scope, k), None);
        }
    }

    fn get_raw(&self, scope: Scope, k: &[u8]) -> Option<Vec<u8>> {
        self.lock().rows.get(&(scope, k.to_vec())).cloned()
    }

    fn put<V: Serialize>(&self, scope: Scope, k: Vec<u8>, v: &V) -> Result<(), KvError> {
        let v = serde_json::to_vec(v)?;
        self.put_raw(scope, k, v);
        Ok(())
    }

    fn get<V: serde::de::DeserializeOwned>(
        &self,
        scope: Scope,
        k: &[u8],
    ) -> Result<Option<V>, KvError> {
        match self.get_raw(scope, k) {
            Some(v) => Ok(Some(serde_json::from_slice(&v)?)),
            None => Ok(None),
        }
    }

    fn list_get<V: serde::de::DeserializeOwned>(
        &self,
        scope: Scope,
        k: &[u8],
    ) -> Result<Vec<V>, KvError> {
        let items: Vec<Vec<u8>> = match self.get_raw(scope, k) {
            Some(v) => serde_json::from_slice(&v)?,
            None => Vec::new(),
        };
        items
            .iter()
            .map(|i| serde_json::from_slice(i).map_err(KvError::from))
            .collect()
    }

    fn list_append<V: Serialize>(&self, scope: Scope, k: Vec<u8>, v: &V) -> Result<(), KvError> {
        let mut items: Vec<Vec<u8>> = match self.get_raw(scope, &k) {
            Some(v) => serde_json::from_slice(&v)?,
            None => Vec::new(),
        };
        items.push(serde_json::to_vec(v)?);
        self.put(scope, k, &items)
    }

    fn list_remove<V: Serialize>(&self, scope: Scope, k: Vec<u8>, v: &V) -> Result<(), KvError> {
        let mut items: Vec<Vec<u8>> = match self.get_raw(scope, &k) {
            Some(v) => serde_json::from_slice(&v)?,
            None => Vec::new(),
        };
        let needle = serde_json::to_vec(v)?;
        if let Some(p) = items.iter().position(|i| *i == needle) {
            items.remove(p);
        }
        self.put(scope, k, &items)
    }

    /// Group-scoped key for `label`.
    fn gk(&self, label: &[u8], group_id: &impl Serialize) -> Result<Vec<u8>, KvError> {
        self.check_group(group_id)?;
        self.key(label, group_id)
    }

    /// The day rewrite of §3.4 point 5: every `added_at` stamp that is not the start of a UTC day
    /// with zero nanoseconds (OpenMLS stamps `SystemTime::now()`) becomes the start of the call's
    /// day. A store without `message_secrets.added_at` is layout drift.
    fn rewrite_days(&self, v: &mut serde_json::Value) -> Result<(), KvError> {
        let day_secs = u64::from(self.day) * DAY_SECS;
        let current = v
            .get("message_secrets")
            .and_then(|m| m.get("added_at"))
            .ok_or(KvError::LayoutDrift("message_secrets.added_at"))?;
        if !current.is_null()
            && (current.get("secs_since_epoch").is_none()
                || current.get("nanos_since_epoch").is_none())
        {
            return Err(KvError::LayoutDrift("added_at.secs_since_epoch"));
        }
        fn walk(v: &mut serde_json::Value, day_secs: u64) {
            match v {
                serde_json::Value::Object(m) => {
                    if let Some(a) = m.get_mut("added_at") {
                        if let (Some(s), Some(ns)) = (
                            a.get("secs_since_epoch").and_then(|x| x.as_u64()),
                            a.get("nanos_since_epoch").and_then(|x| x.as_u64()),
                        ) {
                            if s % DAY_SECS != 0 || ns != 0 {
                                *a = serde_json::json!({
                                    "secs_since_epoch": day_secs,
                                    "nanos_since_epoch": 0
                                });
                            }
                        }
                    }
                    for (_, c) in m.iter_mut() {
                        walk(c, day_secs);
                    }
                }
                serde_json::Value::Array(a) => {
                    for c in a {
                        walk(c, day_secs);
                    }
                }
                _ => {}
            }
        }
        walk(v, day_secs);
        Ok(())
    }

    /// The epochs the split head row lists (empty if there is no head).
    fn split_epochs(&self, g: &impl Serialize) -> Result<Vec<u64>, KvError> {
        let head: Option<serde_json::Value> =
            self.get(Scope::Group, &self.gk(L_MESSAGE_SECRETS, g)?)?;
        let Some(head) = head else {
            return Ok(Vec::new());
        };
        head.get("past_epoch_trees")
            .and_then(|a| a.as_array())
            .ok_or(KvError::LayoutDrift("past_epoch_trees"))?
            .iter()
            .map(|e| e.as_u64().ok_or(KvError::LayoutDrift("past_epoch_trees[]")))
            .collect()
    }

    /// Writes the head (the store with `past_epoch_trees` replaced by its epoch numbers) and one
    /// row per past epoch, skipping rows whose bytes are unchanged and deleting dropped epochs.
    fn write_split(
        &self,
        g: &impl Serialize,
        head_key: Vec<u8>,
        mut v: serde_json::Value,
    ) -> Result<(), KvError> {
        let old = self.split_epochs(g)?;
        let trees = v
            .get_mut("past_epoch_trees")
            .map(serde_json::Value::take)
            .and_then(|a| match a {
                serde_json::Value::Array(a) => Some(a),
                _ => None,
            })
            .ok_or(KvError::LayoutDrift("past_epoch_trees"))?;
        let mut epochs = Vec::with_capacity(trees.len());
        for t in &trees {
            let e = t
                .get("epoch")
                .and_then(|e| e.as_u64())
                .ok_or(KvError::LayoutDrift("past_epoch_trees[].epoch"))?;
            epochs.push(e);
            let k = self.key(L_MESSAGE_SECRETS_PAST, &(g, e))?;
            let bytes = serde_json::to_vec(t)?;
            if self.get_raw(Scope::Group, &k).as_deref() != Some(bytes.as_slice()) {
                self.put_raw(Scope::Group, k, bytes);
            }
        }
        for e in old.iter().filter(|e| !epochs.contains(e)) {
            self.del_raw(Scope::Group, self.key(L_MESSAGE_SECRETS_PAST, &(g, *e))?);
        }
        v["past_epoch_trees"] = serde_json::json!(epochs);
        self.put(Scope::Group, head_key, &v)
    }

    fn read_split<M: serde::de::DeserializeOwned>(
        &self,
        g: &impl Serialize,
    ) -> Result<Option<M>, KvError> {
        let Some(mut head): Option<serde_json::Value> =
            self.get(Scope::Group, &self.gk(L_MESSAGE_SECRETS, g)?)?
        else {
            return Ok(None);
        };
        let epochs: Vec<u64> = head
            .get("past_epoch_trees")
            .and_then(|a| a.as_array())
            .ok_or(KvError::LayoutDrift("past_epoch_trees"))?
            .iter()
            .map(|e| e.as_u64().ok_or(KvError::LayoutDrift("past_epoch_trees[]")))
            .collect::<Result<_, _>>()?;
        let mut trees = Vec::with_capacity(epochs.len());
        for e in epochs {
            let t: serde_json::Value = self
                .get(Scope::Group, &self.key(L_MESSAGE_SECRETS_PAST, &(g, e))?)?
                .ok_or(KvError::LayoutDrift("missing past epoch row"))?;
            trees.push(t);
        }
        head["past_epoch_trees"] = serde_json::Value::Array(trees);
        Ok(Some(serde_json::from_value(head)?))
    }
}

/// The wrapping AD of §3.4 point 2.
fn ad(scope: Scope, channel_id: &[u8; 32], k: &[u8]) -> Vec<u8> {
    let mut ad = b"ghost/v1/mls-kv".to_vec();
    ad.push(scope as u8);
    ad.extend_from_slice(channel_id);
    ad.extend_from_slice(&Sha256::digest(k));
    ad
}

/// Wraps a plaintext row for Kotlin: `nonce(12) ‖ ChaCha20-Poly1305(state key, AD, v)`.
pub fn wrap(
    state_key: &StateKey,
    nonce: [u8; 12],
    scope: Scope,
    channel_id: &[u8; 32],
    k: &[u8],
    v: &[u8],
) -> Vec<u8> {
    let ct = ChaCha20Poly1305::new(state_key.as_bytes().into())
        .encrypt(
            &Nonce::from(nonce),
            Payload {
                msg: v,
                aad: &ad(scope, channel_id, k),
            },
        )
        .expect("ChaCha20-Poly1305 encrypts any length a row has");
    let mut o = Vec::with_capacity(12 + ct.len());
    o.extend_from_slice(&nonce);
    o.extend_from_slice(&ct);
    o
}

/// Opens a wrapped row; a row that does not open is `STATE_CORRUPT`.
pub fn unwrap(
    state_key: &StateKey,
    scope: Scope,
    channel_id: &[u8; 32],
    k: &[u8],
    env: &[u8],
) -> MlsResult<Vec<u8>> {
    if env.len() < 12 + 16 {
        return Err(MlsError::new(Code::StateCorrupt));
    }
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&env[..12]);
    ChaCha20Poly1305::new(state_key.as_bytes().into())
        .decrypt(
            &Nonce::from(nonce),
            Payload {
                msg: &env[12..],
                aad: &ad(scope, channel_id, k),
            },
        )
        .map_err(|_| MlsError::new(Code::StateCorrupt))
}

// Labels (GHOST's own schema; stable: they are the stored keys).
const L_JOIN_CONFIG: &[u8] = b"MlsGroupJoinConfig";
const L_OWN_LEAF_NODES: &[u8] = b"OwnLeafNodes";
const L_QUEUED_PROPOSAL: &[u8] = b"QueuedProposal";
const L_PROPOSAL_REFS: &[u8] = b"ProposalQueueRefs";
const L_TREE: &[u8] = b"Tree";
const L_INTERIM: &[u8] = b"InterimTranscriptHash";
const L_CONTEXT: &[u8] = b"GroupContext";
const L_CONF_TAG: &[u8] = b"ConfirmationTag";
const L_GROUP_STATE: &[u8] = b"GroupState";
const L_MESSAGE_SECRETS: &[u8] = b"MessageSecrets";
const L_MESSAGE_SECRETS_PAST: &[u8] = b"MessageSecretsPast";
const L_RESUMPTION_PSK: &[u8] = b"ResumptionPsk";
const L_OWN_LEAF_INDEX: &[u8] = b"OwnLeafNodeIndex";
const L_EPOCH_SECRETS: &[u8] = b"EpochSecrets";
const L_EPOCH_KEY_PAIRS: &[u8] = b"EpochKeyPairs";
const L_SIGNATURE_KEY_PAIR: &[u8] = b"SignatureKeyPair";
const L_ENCRYPTION_KEY_PAIR: &[u8] = b"EncryptionKeyPair";
const L_KEY_PACKAGE: &[u8] = b"KeyPackage";
const L_PSK: &[u8] = b"Psk";

const GROUP_LABELS: [&[u8]; 15] = [
    L_JOIN_CONFIG,
    L_OWN_LEAF_NODES,
    L_QUEUED_PROPOSAL,
    L_PROPOSAL_REFS,
    L_TREE,
    L_INTERIM,
    L_CONTEXT,
    L_CONF_TAG,
    L_GROUP_STATE,
    L_MESSAGE_SECRETS,
    L_MESSAGE_SECRETS_PAST,
    L_RESUMPTION_PSK,
    L_OWN_LEAF_INDEX,
    L_EPOCH_SECRETS,
    L_EPOCH_KEY_PAIRS,
];
const GLOBAL_LABELS: [&[u8]; 4] = [
    L_SIGNATURE_KEY_PAIR,
    L_ENCRYPTION_KEY_PAIR,
    L_KEY_PACKAGE,
    L_PSK,
];

/// The label of a stored key (for tests and the KAT's reassembly).
pub fn label_of(k: &[u8]) -> &[u8] {
    k.iter().position(|&b| b == 0).map_or(k, |n| &k[..n])
}

/// Every method of the trait in the P0 feature set, with its scope (`GhostKvScopeTest`, design
/// §12.2; V10-5, S0-6). `tests::the_scope_list_is_the_implementation` checks it against this file.
pub const METHOD_SCOPES: &[(&str, Scope)] = &[
    ("write_mls_join_config", Scope::Group),
    ("append_own_leaf_node", Scope::Group),
    ("queue_proposal", Scope::Group),
    ("write_tree", Scope::Group),
    ("write_interim_transcript_hash", Scope::Group),
    ("write_context", Scope::Group),
    ("write_confirmation_tag", Scope::Group),
    ("write_group_state", Scope::Group),
    ("write_message_secrets", Scope::Group),
    ("write_resumption_psk_store", Scope::Group),
    ("write_own_leaf_index", Scope::Group),
    ("write_group_epoch_secrets", Scope::Group),
    ("write_signature_key_pair", Scope::Global),
    ("write_encryption_key_pair", Scope::Global),
    ("write_encryption_epoch_key_pairs", Scope::Group),
    ("write_key_package", Scope::Global),
    ("write_psk", Scope::Global),
    ("mls_group_join_config", Scope::Group),
    ("own_leaf_nodes", Scope::Group),
    ("queued_proposal_refs", Scope::Group),
    ("queued_proposals", Scope::Group),
    ("tree", Scope::Group),
    ("group_context", Scope::Group),
    ("interim_transcript_hash", Scope::Group),
    ("confirmation_tag", Scope::Group),
    ("group_state", Scope::Group),
    ("message_secrets", Scope::Group),
    ("resumption_psk_store", Scope::Group),
    ("own_leaf_index", Scope::Group),
    ("group_epoch_secrets", Scope::Group),
    ("signature_key_pair", Scope::Global),
    ("encryption_key_pair", Scope::Global),
    ("encryption_epoch_key_pairs", Scope::Group),
    ("key_package", Scope::Global),
    ("psk", Scope::Global),
    ("remove_proposal", Scope::Group),
    ("delete_own_leaf_nodes", Scope::Group),
    ("delete_group_config", Scope::Group),
    ("delete_tree", Scope::Group),
    ("delete_confirmation_tag", Scope::Group),
    ("delete_group_state", Scope::Group),
    ("delete_context", Scope::Group),
    ("delete_interim_transcript_hash", Scope::Group),
    ("delete_message_secrets", Scope::Group),
    ("delete_all_resumption_psk_secrets", Scope::Group),
    ("delete_own_leaf_index", Scope::Group),
    ("delete_group_epoch_secrets", Scope::Group),
    ("clear_proposal_queue", Scope::Group),
    ("delete_signature_key_pair", Scope::Global),
    ("delete_encryption_key_pair", Scope::Global),
    ("delete_encryption_epoch_key_pairs", Scope::Group),
    ("delete_key_package", Scope::Global),
    ("delete_psk", Scope::Global),
];

type R<T> = Result<T, KvError>;

// The impl below must implement every required method of the trait in the enabled feature set:
// a feature (or a bump) that adds one fails the build here (design §3.4 point 1's compile-time
// check, S0-6).
impl StorageProvider<CURRENT_VERSION> for GhostKv {
    type Error = KvError;

    fn write_mls_join_config<
        G: traits::GroupId<CURRENT_VERSION>,
        C: traits::MlsGroupJoinConfig<CURRENT_VERSION>,
    >(
        &self,
        g: &G,
        c: &C,
    ) -> R<()> {
        self.put(Scope::Group, self.gk(L_JOIN_CONFIG, g)?, c)
    }
    fn append_own_leaf_node<
        G: traits::GroupId<CURRENT_VERSION>,
        L: traits::LeafNode<CURRENT_VERSION>,
    >(
        &self,
        g: &G,
        l: &L,
    ) -> R<()> {
        self.list_append(Scope::Group, self.gk(L_OWN_LEAF_NODES, g)?, l)
    }
    fn queue_proposal<
        G: traits::GroupId<CURRENT_VERSION>,
        P: traits::ProposalRef<CURRENT_VERSION>,
        Q: traits::QueuedProposal<CURRENT_VERSION>,
    >(
        &self,
        g: &G,
        r: &P,
        q: &Q,
    ) -> R<()> {
        self.check_group(g)?;
        self.put(Scope::Group, self.key(L_QUEUED_PROPOSAL, &(g, r))?, q)?;
        self.list_append(Scope::Group, self.gk(L_PROPOSAL_REFS, g)?, r)
    }
    fn write_tree<G: traits::GroupId<CURRENT_VERSION>, T: traits::TreeSync<CURRENT_VERSION>>(
        &self,
        g: &G,
        t: &T,
    ) -> R<()> {
        self.put(Scope::Group, self.gk(L_TREE, g)?, t)
    }
    fn write_interim_transcript_hash<
        G: traits::GroupId<CURRENT_VERSION>,
        H: traits::InterimTranscriptHash<CURRENT_VERSION>,
    >(
        &self,
        g: &G,
        h: &H,
    ) -> R<()> {
        self.put(Scope::Group, self.gk(L_INTERIM, g)?, h)
    }
    fn write_context<
        G: traits::GroupId<CURRENT_VERSION>,
        C: traits::GroupContext<CURRENT_VERSION>,
    >(
        &self,
        g: &G,
        c: &C,
    ) -> R<()> {
        self.put(Scope::Group, self.gk(L_CONTEXT, g)?, c)
    }
    fn write_confirmation_tag<
        G: traits::GroupId<CURRENT_VERSION>,
        C: traits::ConfirmationTag<CURRENT_VERSION>,
    >(
        &self,
        g: &G,
        c: &C,
    ) -> R<()> {
        self.put(Scope::Group, self.gk(L_CONF_TAG, g)?, c)
    }
    fn write_group_state<
        S: traits::GroupState<CURRENT_VERSION>,
        G: traits::GroupId<CURRENT_VERSION>,
    >(
        &self,
        g: &G,
        s: &S,
    ) -> R<()> {
        self.put(Scope::Group, self.gk(L_GROUP_STATE, g)?, s)
    }
    fn write_message_secrets<
        G: traits::GroupId<CURRENT_VERSION>,
        M: traits::MessageSecrets<CURRENT_VERSION>,
    >(
        &self,
        g: &G,
        m: &M,
    ) -> R<()> {
        let k = self.gk(L_MESSAGE_SECRETS, g)?;
        let mut v = serde_json::to_value(m)?;
        self.rewrite_days(&mut v)?;
        match self.layout {
            PastLayout::Split => self.write_split(g, k, v),
            PastLayout::Whole => self.put(Scope::Group, k, &v),
        }
    }
    fn write_resumption_psk_store<
        G: traits::GroupId<CURRENT_VERSION>,
        P: traits::ResumptionPskStore<CURRENT_VERSION>,
    >(
        &self,
        g: &G,
        p: &P,
    ) -> R<()> {
        self.put(Scope::Group, self.gk(L_RESUMPTION_PSK, g)?, p)
    }
    fn write_own_leaf_index<
        G: traits::GroupId<CURRENT_VERSION>,
        L: traits::LeafNodeIndex<CURRENT_VERSION>,
    >(
        &self,
        g: &G,
        l: &L,
    ) -> R<()> {
        self.put(Scope::Group, self.gk(L_OWN_LEAF_INDEX, g)?, l)
    }
    fn write_group_epoch_secrets<
        G: traits::GroupId<CURRENT_VERSION>,
        S: traits::GroupEpochSecrets<CURRENT_VERSION>,
    >(
        &self,
        g: &G,
        s: &S,
    ) -> R<()> {
        self.put(Scope::Group, self.gk(L_EPOCH_SECRETS, g)?, s)
    }
    fn write_signature_key_pair<
        K: traits::SignaturePublicKey<CURRENT_VERSION>,
        P: traits::SignatureKeyPair<CURRENT_VERSION>,
    >(
        &self,
        k: &K,
        p: &P,
    ) -> R<()> {
        self.put(Scope::Global, self.key(L_SIGNATURE_KEY_PAIR, k)?, p)
    }
    fn write_encryption_key_pair<
        K: traits::EncryptionKey<CURRENT_VERSION>,
        P: traits::HpkeKeyPair<CURRENT_VERSION>,
    >(
        &self,
        k: &K,
        p: &P,
    ) -> R<()> {
        self.put(Scope::Global, self.key(L_ENCRYPTION_KEY_PAIR, k)?, p)
    }
    fn write_encryption_epoch_key_pairs<
        G: traits::GroupId<CURRENT_VERSION>,
        E: traits::EpochKey<CURRENT_VERSION>,
        P: traits::HpkeKeyPair<CURRENT_VERSION>,
    >(
        &self,
        g: &G,
        e: &E,
        leaf: u32,
        ps: &[P],
    ) -> R<()> {
        self.check_group(g)?;
        self.put(
            Scope::Group,
            self.key(L_EPOCH_KEY_PAIRS, &(g, e, leaf))?,
            &ps,
        )
    }
    fn write_key_package<
        H: traits::HashReference<CURRENT_VERSION>,
        K: traits::KeyPackage<CURRENT_VERSION>,
    >(
        &self,
        h: &H,
        k: &K,
    ) -> R<()> {
        self.put(Scope::Global, self.key(L_KEY_PACKAGE, h)?, k)
    }
    fn write_psk<P: traits::PskId<CURRENT_VERSION>, B: traits::PskBundle<CURRENT_VERSION>>(
        &self,
        p: &P,
        b: &B,
    ) -> R<()> {
        self.put(Scope::Global, self.key(L_PSK, p)?, b)
    }

    fn mls_group_join_config<
        G: traits::GroupId<CURRENT_VERSION>,
        C: traits::MlsGroupJoinConfig<CURRENT_VERSION>,
    >(
        &self,
        g: &G,
    ) -> R<Option<C>> {
        self.get(Scope::Group, &self.gk(L_JOIN_CONFIG, g)?)
    }
    fn own_leaf_nodes<G: traits::GroupId<CURRENT_VERSION>, L: traits::LeafNode<CURRENT_VERSION>>(
        &self,
        g: &G,
    ) -> R<Vec<L>> {
        self.list_get(Scope::Group, &self.gk(L_OWN_LEAF_NODES, g)?)
    }
    fn queued_proposal_refs<
        G: traits::GroupId<CURRENT_VERSION>,
        P: traits::ProposalRef<CURRENT_VERSION>,
    >(
        &self,
        g: &G,
    ) -> R<Vec<P>> {
        self.list_get(Scope::Group, &self.gk(L_PROPOSAL_REFS, g)?)
    }
    fn queued_proposals<
        G: traits::GroupId<CURRENT_VERSION>,
        P: traits::ProposalRef<CURRENT_VERSION>,
        Q: traits::QueuedProposal<CURRENT_VERSION>,
    >(
        &self,
        g: &G,
    ) -> R<Vec<(P, Q)>> {
        let refs: Vec<P> = self.list_get(Scope::Group, &self.gk(L_PROPOSAL_REFS, g)?)?;
        refs.into_iter()
            .map(|r| {
                let q = self
                    .get(Scope::Group, &self.key(L_QUEUED_PROPOSAL, &(g, &r))?)?
                    .ok_or(KvError::Serde)?;
                Ok((r, q))
            })
            .collect()
    }
    fn tree<G: traits::GroupId<CURRENT_VERSION>, T: traits::TreeSync<CURRENT_VERSION>>(
        &self,
        g: &G,
    ) -> R<Option<T>> {
        self.get(Scope::Group, &self.gk(L_TREE, g)?)
    }
    fn group_context<
        G: traits::GroupId<CURRENT_VERSION>,
        C: traits::GroupContext<CURRENT_VERSION>,
    >(
        &self,
        g: &G,
    ) -> R<Option<C>> {
        self.get(Scope::Group, &self.gk(L_CONTEXT, g)?)
    }
    fn interim_transcript_hash<
        G: traits::GroupId<CURRENT_VERSION>,
        H: traits::InterimTranscriptHash<CURRENT_VERSION>,
    >(
        &self,
        g: &G,
    ) -> R<Option<H>> {
        self.get(Scope::Group, &self.gk(L_INTERIM, g)?)
    }
    fn confirmation_tag<
        G: traits::GroupId<CURRENT_VERSION>,
        C: traits::ConfirmationTag<CURRENT_VERSION>,
    >(
        &self,
        g: &G,
    ) -> R<Option<C>> {
        self.get(Scope::Group, &self.gk(L_CONF_TAG, g)?)
    }
    fn group_state<S: traits::GroupState<CURRENT_VERSION>, G: traits::GroupId<CURRENT_VERSION>>(
        &self,
        g: &G,
    ) -> R<Option<S>> {
        self.get(Scope::Group, &self.gk(L_GROUP_STATE, g)?)
    }
    fn message_secrets<
        G: traits::GroupId<CURRENT_VERSION>,
        M: traits::MessageSecrets<CURRENT_VERSION>,
    >(
        &self,
        g: &G,
    ) -> R<Option<M>> {
        match self.layout {
            PastLayout::Split => self.read_split(g),
            PastLayout::Whole => self.get(Scope::Group, &self.gk(L_MESSAGE_SECRETS, g)?),
        }
    }
    fn resumption_psk_store<
        G: traits::GroupId<CURRENT_VERSION>,
        P: traits::ResumptionPskStore<CURRENT_VERSION>,
    >(
        &self,
        g: &G,
    ) -> R<Option<P>> {
        self.get(Scope::Group, &self.gk(L_RESUMPTION_PSK, g)?)
    }
    fn own_leaf_index<
        G: traits::GroupId<CURRENT_VERSION>,
        L: traits::LeafNodeIndex<CURRENT_VERSION>,
    >(
        &self,
        g: &G,
    ) -> R<Option<L>> {
        self.get(Scope::Group, &self.gk(L_OWN_LEAF_INDEX, g)?)
    }
    fn group_epoch_secrets<
        G: traits::GroupId<CURRENT_VERSION>,
        S: traits::GroupEpochSecrets<CURRENT_VERSION>,
    >(
        &self,
        g: &G,
    ) -> R<Option<S>> {
        self.get(Scope::Group, &self.gk(L_EPOCH_SECRETS, g)?)
    }
    fn signature_key_pair<
        K: traits::SignaturePublicKey<CURRENT_VERSION>,
        P: traits::SignatureKeyPair<CURRENT_VERSION>,
    >(
        &self,
        k: &K,
    ) -> R<Option<P>> {
        self.get(Scope::Global, &self.key(L_SIGNATURE_KEY_PAIR, k)?)
    }
    fn encryption_key_pair<
        P: traits::HpkeKeyPair<CURRENT_VERSION>,
        K: traits::EncryptionKey<CURRENT_VERSION>,
    >(
        &self,
        k: &K,
    ) -> R<Option<P>> {
        self.get(Scope::Global, &self.key(L_ENCRYPTION_KEY_PAIR, k)?)
    }
    fn encryption_epoch_key_pairs<
        G: traits::GroupId<CURRENT_VERSION>,
        E: traits::EpochKey<CURRENT_VERSION>,
        P: traits::HpkeKeyPair<CURRENT_VERSION>,
    >(
        &self,
        g: &G,
        e: &E,
        leaf: u32,
    ) -> R<Vec<P>> {
        self.check_group(g)?;
        Ok(self
            .get::<Vec<P>>(Scope::Group, &self.key(L_EPOCH_KEY_PAIRS, &(g, e, leaf))?)?
            .unwrap_or_default())
    }
    fn key_package<
        H: traits::HashReference<CURRENT_VERSION>,
        K: traits::KeyPackage<CURRENT_VERSION>,
    >(
        &self,
        h: &H,
    ) -> R<Option<K>> {
        self.get(Scope::Global, &self.key(L_KEY_PACKAGE, h)?)
    }
    fn psk<B: traits::PskBundle<CURRENT_VERSION>, P: traits::PskId<CURRENT_VERSION>>(
        &self,
        p: &P,
    ) -> R<Option<B>> {
        self.get(Scope::Global, &self.key(L_PSK, p)?)
    }

    fn remove_proposal<
        G: traits::GroupId<CURRENT_VERSION>,
        P: traits::ProposalRef<CURRENT_VERSION>,
    >(
        &self,
        g: &G,
        r: &P,
    ) -> R<()> {
        self.check_group(g)?;
        self.list_remove(Scope::Group, self.gk(L_PROPOSAL_REFS, g)?, r)?;
        self.del_raw(Scope::Group, self.key(L_QUEUED_PROPOSAL, &(g, r))?);
        Ok(())
    }
    fn delete_own_leaf_nodes<G: traits::GroupId<CURRENT_VERSION>>(&self, g: &G) -> R<()> {
        self.del_raw(Scope::Group, self.gk(L_OWN_LEAF_NODES, g)?);
        Ok(())
    }
    fn delete_group_config<G: traits::GroupId<CURRENT_VERSION>>(&self, g: &G) -> R<()> {
        self.del_raw(Scope::Group, self.gk(L_JOIN_CONFIG, g)?);
        Ok(())
    }
    fn delete_tree<G: traits::GroupId<CURRENT_VERSION>>(&self, g: &G) -> R<()> {
        self.del_raw(Scope::Group, self.gk(L_TREE, g)?);
        Ok(())
    }
    fn delete_confirmation_tag<G: traits::GroupId<CURRENT_VERSION>>(&self, g: &G) -> R<()> {
        self.del_raw(Scope::Group, self.gk(L_CONF_TAG, g)?);
        Ok(())
    }
    fn delete_group_state<G: traits::GroupId<CURRENT_VERSION>>(&self, g: &G) -> R<()> {
        self.del_raw(Scope::Group, self.gk(L_GROUP_STATE, g)?);
        Ok(())
    }
    fn delete_context<G: traits::GroupId<CURRENT_VERSION>>(&self, g: &G) -> R<()> {
        self.del_raw(Scope::Group, self.gk(L_CONTEXT, g)?);
        Ok(())
    }
    fn delete_interim_transcript_hash<G: traits::GroupId<CURRENT_VERSION>>(&self, g: &G) -> R<()> {
        self.del_raw(Scope::Group, self.gk(L_INTERIM, g)?);
        Ok(())
    }
    fn delete_message_secrets<G: traits::GroupId<CURRENT_VERSION>>(&self, g: &G) -> R<()> {
        if self.layout == PastLayout::Split {
            for e in self.split_epochs(g)? {
                self.del_raw(Scope::Group, self.key(L_MESSAGE_SECRETS_PAST, &(g, e))?);
            }
        }
        self.del_raw(Scope::Group, self.gk(L_MESSAGE_SECRETS, g)?);
        Ok(())
    }
    fn delete_all_resumption_psk_secrets<G: traits::GroupId<CURRENT_VERSION>>(
        &self,
        g: &G,
    ) -> R<()> {
        self.del_raw(Scope::Group, self.gk(L_RESUMPTION_PSK, g)?);
        Ok(())
    }
    fn delete_own_leaf_index<G: traits::GroupId<CURRENT_VERSION>>(&self, g: &G) -> R<()> {
        self.del_raw(Scope::Group, self.gk(L_OWN_LEAF_INDEX, g)?);
        Ok(())
    }
    fn delete_group_epoch_secrets<G: traits::GroupId<CURRENT_VERSION>>(&self, g: &G) -> R<()> {
        self.del_raw(Scope::Group, self.gk(L_EPOCH_SECRETS, g)?);
        Ok(())
    }
    fn clear_proposal_queue<
        G: traits::GroupId<CURRENT_VERSION>,
        P: traits::ProposalRef<CURRENT_VERSION>,
    >(
        &self,
        g: &G,
    ) -> R<()> {
        let refs: Vec<P> = self.list_get(Scope::Group, &self.gk(L_PROPOSAL_REFS, g)?)?;
        for r in refs {
            self.del_raw(Scope::Group, self.key(L_QUEUED_PROPOSAL, &(g, &r))?);
        }
        self.del_raw(Scope::Group, self.gk(L_PROPOSAL_REFS, g)?);
        Ok(())
    }
    fn delete_signature_key_pair<K: traits::SignaturePublicKey<CURRENT_VERSION>>(
        &self,
        k: &K,
    ) -> R<()> {
        self.del_raw(Scope::Global, self.key(L_SIGNATURE_KEY_PAIR, k)?);
        Ok(())
    }
    fn delete_encryption_key_pair<K: traits::EncryptionKey<CURRENT_VERSION>>(
        &self,
        k: &K,
    ) -> R<()> {
        self.del_raw(Scope::Global, self.key(L_ENCRYPTION_KEY_PAIR, k)?);
        Ok(())
    }
    fn delete_encryption_epoch_key_pairs<
        G: traits::GroupId<CURRENT_VERSION>,
        E: traits::EpochKey<CURRENT_VERSION>,
    >(
        &self,
        g: &G,
        e: &E,
        leaf: u32,
    ) -> R<()> {
        self.check_group(g)?;
        self.del_raw(Scope::Group, self.key(L_EPOCH_KEY_PAIRS, &(g, e, leaf))?);
        Ok(())
    }
    fn delete_key_package<H: traits::HashReference<CURRENT_VERSION>>(&self, h: &H) -> R<()> {
        self.del_raw(Scope::Global, self.key(L_KEY_PACKAGE, h)?);
        Ok(())
    }
    fn delete_psk<P: traits::PskId<CURRENT_VERSION>>(&self, p: &P) -> R<()> {
        self.del_raw(Scope::Global, self.key(L_PSK, p)?);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `GhostKvScopeTest` (design §12.2, S0-6): 53 methods, 41 group-scoped and 12 global; the list
    /// equals the methods this file implements, and a method is group-scoped exactly when its
    /// generics name a `GroupId` (the rule of point 1). The compiler checks that the impl covers
    /// every required method of the trait in the enabled feature set.
    #[test]
    fn the_scope_list_is_the_implementation() {
        let src = include_str!("kv.rs");
        let body = &src[src
            .find("impl StorageProvider<CURRENT_VERSION> for GhostKv")
            .unwrap()..];
        let body = &body[..body.find("#[cfg(test)]").unwrap()];
        let mut implemented: Vec<(String, bool)> = Vec::new();
        for chunk in body.split("    fn ").skip(1) {
            let name: String = chunk
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            let sig = &chunk[..chunk.find(") -> R<").unwrap_or(chunk.len())];
            implemented.push((name, sig.contains("traits::GroupId<")));
        }
        let listed: Vec<(String, bool)> = METHOD_SCOPES
            .iter()
            .map(|(n, s)| (n.to_string(), *s == Scope::Group))
            .collect();
        let mut a = implemented.clone();
        let mut b = listed.clone();
        a.sort();
        b.sort();
        assert_eq!(
            a, b,
            "METHOD_SCOPES differs from the implemented methods or their scopes"
        );
        let group = METHOD_SCOPES
            .iter()
            .filter(|(_, s)| *s == Scope::Group)
            .count();
        assert_eq!((METHOD_SCOPES.len(), group), (53, 41));
    }

    #[test]
    fn keys_outside_both_scopes_are_state_corrupt() {
        let kv = GhostKv::new([1; 32], 20_000);
        let gk = kv
            .key(L_TREE, &openmls::group::GroupId::from_slice(&[1; 32]))
            .unwrap();
        let other = kv
            .key(L_TREE, &openmls::group::GroupId::from_slice(&[2; 32]))
            .unwrap();
        let global = kv.key(L_KEY_PACKAGE, &[9u8; 3]).unwrap();
        assert!(kv.load(vec![((Scope::Group, gk.clone()), vec![1])]).is_ok());
        assert!(kv
            .load(vec![((Scope::Global, global.clone()), vec![1])])
            .is_ok());
        for bad in [
            (Scope::Group, other),
            (Scope::Global, gk.clone()),
            (Scope::Group, global),
            (Scope::Group, b"Unknown\0x".to_vec()),
            (Scope::Group, b"no-separator".to_vec()),
        ] {
            assert_eq!(
                kv.load(vec![(bad, vec![1])]),
                Err(MlsError::new(Code::StateCorrupt))
            );
        }
        // A group-scoped method for another group is refused, never guessed.
        assert_eq!(
            kv.gk(L_TREE, &openmls::group::GroupId::from_slice(&[2; 32])),
            Err(KvError::ForeignGroup)
        );
    }

    #[test]
    fn wrapping_binds_scope_channel_and_key() {
        let sk = StateKey::from_bytes([3; 32]);
        let env = wrap(&sk, [1; 12], Scope::Group, &[1; 32], b"Tree\0k", b"value");
        assert_eq!(
            unwrap(&sk, Scope::Group, &[1; 32], b"Tree\0k", &env).unwrap(),
            b"value"
        );
        let corrupt = Err(MlsError::new(Code::StateCorrupt));
        assert_eq!(
            unwrap(&sk, Scope::Global, &[1; 32], b"Tree\0k", &env),
            corrupt
        );
        assert_eq!(
            unwrap(&sk, Scope::Group, &[2; 32], b"Tree\0k", &env),
            corrupt
        );
        assert_eq!(
            unwrap(&sk, Scope::Group, &[1; 32], b"Tree\0j", &env),
            corrupt
        );
        assert_eq!(
            unwrap(
                &StateKey::from_bytes([4; 32]),
                Scope::Group,
                &[1; 32],
                b"Tree\0k",
                &env
            ),
            corrupt
        );
    }

    #[test]
    fn the_day_rewrite_stamps_the_call_day_and_detects_drift() {
        let kv = GhostKv::new([1; 32], 20_000);
        let mut v = serde_json::json!({
            "message_secrets": {"added_at": {"secs_since_epoch": 1_727_000_123u64, "nanos_since_epoch": 5}},
            "past_epoch_trees": [{"epoch": 3, "message_secrets": {"added_at": {"secs_since_epoch": 1_728_000_000u64, "nanos_since_epoch": 0}}}]
        });
        kv.rewrite_days(&mut v).unwrap();
        assert_eq!(
            v["message_secrets"]["added_at"]["secs_since_epoch"],
            20_000u64 * 86_400
        );
        assert_eq!(v["message_secrets"]["added_at"]["nanos_since_epoch"], 0);
        // A stamp already on a day boundary (an earlier call's day) is kept.
        assert_eq!(
            v["past_epoch_trees"][0]["message_secrets"]["added_at"]["secs_since_epoch"],
            1_728_000_000u64
        );
        let mut drift = serde_json::json!({"message_secrets": {"created": 1}});
        assert_eq!(
            kv.rewrite_days(&mut drift),
            Err(KvError::LayoutDrift("message_secrets.added_at"))
        );
    }

    #[test]
    fn checkpoints_roll_back_writes() {
        let kv = GhostKv::new([1; 32], 1);
        let g = openmls::group::GroupId::from_slice(&[1; 32]);
        kv.put(Scope::Group, kv.gk(L_TREE, &g).unwrap(), &1u8)
            .unwrap();
        let c = kv.checkpoint();
        kv.put(Scope::Group, kv.gk(L_CONTEXT, &g).unwrap(), &2u8)
            .unwrap();
        kv.restore(c);
        let changes = kv.take_plain_changes();
        assert_eq!(changes.len(), 1);
        assert!(changes.keys().all(|(_, k)| label_of(k) == L_TREE));
        // A delete of a row that never existed is not a change.
        kv.del_raw(Scope::Group, kv.gk(L_GROUP_STATE, &g).unwrap());
        assert!(kv.take_plain_changes().is_empty());
    }
}
