//! `GhostKv`: the value-semantics storage adapter of design §3.4, as S0 evidence (V10-5, V10-11,
//! V10-12). OpenMLS runs over an in-memory map loaded from the channel's stored rows; every write,
//! append and delete updates the map and is recorded, so the call can return a change-set that the
//! caller applies only on success. Values leave the adapter wrapped under the state key
//! (`nonce(12) ‖ ChaCha20-Poly1305(key, AD = "ghost/v1/mls-kv" ‖ scope ‖ channel_id ‖ SHA-256(k), v)`).
//!
//! Scope is static per method: every method that takes a `GroupId` is group-scoped (`mls_kv`),
//! the others are global (`mls_global_kv`, tagged with the channel of the call). A group-scoped
//! method called with a group id other than the call's channel is refused, never guessed.

use std::collections::BTreeMap;
use std::sync::Mutex;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use openmls_traits::storage::{
    traits, Entity, Key as StorageKey, StorageProvider, CURRENT_VERSION,
};
use serde::Serialize;
use sha2::{Digest, Sha256};

/// `mls_kv` (group-scoped) or `mls_global_kv` (global, tagged with the channel).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Scope {
    Group = 1,
    Global = 2,
}

pub type RowKey = (Scope, Vec<u8>);

/// Errors of the adapter. Every one of them is `STATE_CORRUPT` or `INTERNAL` at the JNI surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KvError {
    /// A group-scoped method was called for a group other than the call's channel.
    ForeignGroup,
    /// A value did not (de)serialise.
    Serde,
    /// The pinned `MessageSecretsStore` layout moved (the day rewrite could not find `added_at`).
    LayoutDrift(&'static str),
    /// A stored row did not open under the state key.
    Unwrap,
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

/// Per-call counters (V10-5).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CallStats {
    /// Raw write operations the library issued (put, append, remove-item).
    pub raw_puts: u64,
    /// Raw delete operations.
    pub raw_deletes: u64,
    /// Bytes of plaintext values the raw writes carried.
    pub raw_put_bytes: u64,
    /// Read calls and the bytes of plaintext they returned.
    pub reads: u64,
    pub read_bytes: u64,
    /// `added_at` stamps rewritten to the call's day.
    pub day_rewrites: u64,
}

#[derive(Default)]
struct State {
    rows: BTreeMap<RowKey, Vec<u8>>,
    /// Net change-set: `Some(v)` put, `None` delete.
    dirty: BTreeMap<RowKey, Option<Vec<u8>>>,
    stats: CallStats,
}

/// The adapter. One instance per native call (value semantics).
pub struct GhostKv {
    channel_id: [u8; 32],
    group_key: Vec<u8>,
    day: u32,
    /// V10-5 candidate fix: store each retained past epoch of the `MessageSecretsStore` as its own
    /// row, so a post rewrites only the current epoch's secrets (a further read of OpenMLS's
    /// serde layout, like the day rewrite).
    split_past: bool,
    state: Mutex<State>,
}

const DAY: u64 = 86_400;

impl GhostKv {
    /// An adapter for one call on `channel_id` (the MLS group id) on the Kotlin-supplied `day`.
    pub fn new(channel_id: [u8; 32], day: u32) -> Self {
        let group_key = serde_json::to_vec(&openmls::group::GroupId::from_slice(&channel_id))
            .expect("group id serialises");
        Self {
            channel_id,
            group_key,
            day,
            split_past: false,
            state: Mutex::new(State::default()),
        }
    }

    /// An adapter for a group id of any length (the WG vectors' groups, V10-12); the wrapping AD
    /// uses SHA-256 of the id in place of the 32-byte channel id.
    pub fn for_group(group_id: &[u8], day: u32) -> Self {
        let group_key = serde_json::to_vec(&openmls::group::GroupId::from_slice(group_id))
            .expect("group id serialises");
        let channel_id: [u8; 32] = Sha256::digest(group_id).into();
        Self {
            channel_id,
            group_key,
            day,
            split_past: false,
            state: Mutex::new(State::default()),
        }
    }

    pub fn channel_id(&self) -> &[u8; 32] {
        &self.channel_id
    }

    pub fn set_day(&mut self, day: u32) {
        self.day = day;
    }

    pub fn set_split_past(&mut self, on: bool) {
        self.split_past = on;
    }

    /// Loads plaintext rows (after unwrapping) as the state before the call.
    pub fn load_plain(&self, rows: impl IntoIterator<Item = (RowKey, Vec<u8>)>) {
        let mut s = self.state.lock().unwrap();
        s.rows = rows.into_iter().collect();
        s.dirty.clear();
        s.stats = CallStats::default();
    }

    /// The current in-memory rows (plaintext).
    pub fn rows(&self) -> BTreeMap<RowKey, Vec<u8>> {
        self.state.lock().unwrap().rows.clone()
    }

    /// Takes the net change-set and the counters, leaving the adapter clean for the next call.
    pub fn take_changes(&self) -> (BTreeMap<RowKey, Option<Vec<u8>>>, CallStats) {
        let mut s = self.state.lock().unwrap();
        let d = std::mem::take(&mut s.dirty);
        let st = std::mem::take(&mut s.stats);
        (d, st)
    }

    /// Drops the change-set without applying it (a failed call, a validation or trial run).
    pub fn discard(&self, committed: &BTreeMap<RowKey, Vec<u8>>) {
        let mut s = self.state.lock().unwrap();
        s.rows = committed.clone();
        s.dirty.clear();
        s.stats = CallStats::default();
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
        let mut s = self.state.lock().unwrap();
        s.stats.raw_puts += 1;
        s.stats.raw_put_bytes += v.len() as u64;
        s.rows.insert((scope, k.clone()), v.clone());
        s.dirty.insert((scope, k), Some(v));
    }

    fn del_raw(&self, scope: Scope, k: Vec<u8>) {
        let mut s = self.state.lock().unwrap();
        s.stats.raw_deletes += 1;
        s.rows.remove(&(scope, k.clone()));
        s.dirty.insert((scope, k), None);
    }

    fn get_raw(&self, scope: Scope, k: &[u8]) -> Option<Vec<u8>> {
        let mut s = self.state.lock().unwrap();
        let v = s.rows.get(&(scope, k.to_vec())).cloned();
        s.stats.reads += 1;
        s.stats.read_bytes += v.as_ref().map_or(0, |v| v.len() as u64);
        v
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

    /// The day rewrite of §3.4 point 5: every `added_at` stamp that is not a whole UTC day
    /// (OpenMLS stamps `SystemTime::now()`) becomes the start of the call's Kotlin-supplied day.
    /// A store without the expected stamp at `message_secrets.added_at` is layout drift.
    fn rewrite_days(&self, v: &mut serde_json::Value) -> Result<u64, KvError> {
        let day_secs = u64::from(self.day) * DAY;
        let current = v
            .get("message_secrets")
            .and_then(|m| m.get("added_at"))
            .ok_or(KvError::LayoutDrift("message_secrets.added_at"))?;
        if !current.is_null() && current.get("secs_since_epoch").is_none() {
            return Err(KvError::LayoutDrift("added_at.secs_since_epoch"));
        }
        let mut n = 0;
        fn walk(v: &mut serde_json::Value, day_secs: u64, n: &mut u64) {
            match v {
                serde_json::Value::Object(m) => {
                    if let Some(a) = m.get_mut("added_at") {
                        if let (Some(s), Some(ns)) = (
                            a.get("secs_since_epoch").and_then(|x| x.as_u64()),
                            a.get("nanos_since_epoch").and_then(|x| x.as_u64()),
                        ) {
                            if s % DAY != 0 || ns != 0 {
                                *a = serde_json::json!({"secs_since_epoch": day_secs, "nanos_since_epoch": 0});
                                *n += 1;
                            }
                        }
                    }
                    for (_, c) in m.iter_mut() {
                        walk(c, day_secs, n);
                    }
                }
                serde_json::Value::Array(a) => {
                    for c in a {
                        walk(c, day_secs, n);
                    }
                }
                _ => {}
            }
        }
        walk(v, day_secs, &mut n);
        Ok(n)
    }
}

impl GhostKv {
    /// The epochs the split head row lists (empty if there is no head).
    fn split_epochs(&self, g: &impl Serialize) -> Result<Vec<u64>, KvError> {
        let head: Option<serde_json::Value> =
            self.get(Scope::Group, &self.gk(L_MESSAGE_SECRETS, g)?)?;
        Ok(head
            .and_then(|h| {
                h.get("past_epoch_trees")
                    .and_then(|a| a.as_array().cloned())
            })
            .unwrap_or_default()
            .iter()
            .filter_map(|e| e.as_u64())
            .collect())
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
            .and_then(|a| a.as_array().cloned())
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
            let same = self
                .state
                .lock()
                .unwrap()
                .rows
                .get(&(Scope::Group, k.clone()))
                == Some(&bytes);
            if !same {
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

/// Wraps a plaintext row for Kotlin (the §3.4 point 2 envelope).
pub fn wrap(
    state_key: &[u8; 32],
    nonce: [u8; 12],
    scope: Scope,
    channel_id: &[u8; 32],
    k: &[u8],
    v: &[u8],
) -> Vec<u8> {
    let aead = ChaCha20Poly1305::new_from_slice(state_key).expect("32-byte key");
    let ad = ad(scope, channel_id, k);
    let ct = aead
        .encrypt(&Nonce::from(nonce), Payload { msg: v, aad: &ad })
        .expect("chacha20poly1305 encrypt");
    let mut o = Vec::with_capacity(12 + ct.len());
    o.extend_from_slice(&nonce);
    o.extend_from_slice(&ct);
    o
}

/// Opens a wrapped row; a row that does not open is `STATE_CORRUPT`.
pub fn unwrap(
    state_key: &[u8; 32],
    scope: Scope,
    channel_id: &[u8; 32],
    k: &[u8],
    env: &[u8],
) -> Result<Vec<u8>, KvError> {
    if env.len() < 12 + 16 {
        return Err(KvError::Unwrap);
    }
    let aead = ChaCha20Poly1305::new_from_slice(state_key).expect("32-byte key");
    let ad = ad(scope, channel_id, k);
    aead.decrypt(
        &Nonce::from(<[u8; 12]>::try_from(&env[..12]).map_err(|_| KvError::Unwrap)?),
        Payload {
            msg: &env[12..],
            aad: &ad,
        },
    )
    .map_err(|_| KvError::Unwrap)
}

fn ad(scope: Scope, channel_id: &[u8; 32], k: &[u8]) -> Vec<u8> {
    let mut ad = b"ghost/v1/mls-kv".to_vec();
    ad.push(scope as u8);
    ad.extend_from_slice(channel_id);
    ad.extend_from_slice(&Sha256::digest(k));
    ad
}

// Labels (the memory provider's names; any stable label set works, it is GHOST's own schema).
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

/// Every method of the trait in the P0 feature set, with its scope (the `GhostKvScopeTest` list of
/// design §12.2; V10-5 counts them).
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
        // Spike switch (V10-6): GHOST_SPIKE_NO_DAY_REWRITE=1 keeps OpenMLS's wall-clock stamps, to show
        // that byte-identical state needs the rewrite.
        let n = if std::env::var_os("GHOST_SPIKE_NO_DAY_REWRITE").is_some() {
            0
        } else {
            self.rewrite_days(&mut v)?
        };
        self.state.lock().unwrap().stats.day_rewrites += n;
        if self.split_past {
            return self.write_split(g, k, v);
        }
        self.put(Scope::Group, k, &v)
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
        if self.split_past {
            return self.read_split(g);
        }
        self.get(Scope::Group, &self.gk(L_MESSAGE_SECRETS, g)?)
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
        if self.split_past {
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

// Silence the unused-import lint for the marker traits the generic bounds name.
#[allow(dead_code)]
fn _markers<K: StorageKey<CURRENT_VERSION>, E: Entity<CURRENT_VERSION>>() {}
