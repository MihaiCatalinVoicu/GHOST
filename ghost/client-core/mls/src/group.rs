//! The channel operations over OpenMLS 0.9.0 (design §10.2's function list as a Rust API; the JNI
//! export is slice S2b). Every operation that touches MLS state runs under **value semantics**
//! (§3.4): the channel's rows are loaded into a fresh [`GhostKv`], OpenMLS runs, and only on
//! success does the operation return its outputs with the change-set wrapped under the state key.
//! On any error nothing is returned, so the caller writes nothing.
//!
//! The configuration of §3.5: suite 0x0003; pure-ciphertext wire format; `padding_size` 0; the
//! ratchet tree in every Welcome; `SenderRatchetConfiguration::new(16, 1000)`; `max_past_epochs(16)`;
//! the constant KeyPackage lifetime; the canonical capabilities; `RequiredCapabilities` naming 0xF0A1
//! and 0xF0A2; no exported GroupInfo (`create_group_info(false)` after the bootstrap, S0-9); never
//! `build_with_new_signer`, `store_pending_proposal`, `export_group_info` or `into_group_info*`
//! (gate G-M2).

use std::time::UNIX_EPOCH;

use openmls::prelude::tls_codec::{Deserialize as _, Serialize as _};
use openmls::prelude::*;
use openmls_libcrux_crypto::CryptoProvider;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::canonical::{self, CanonicalKeyPackage, LeafFacts, SUITE};
use crate::check::{self, CommitSummary, PreState};
use crate::content::ChannelContent;
use crate::derive::{
    self, committers_digest, derive_deposit_base, derive_deposit_secret, derive_epoch_recognition,
    derive_join_key, derive_join_recognition, derive_namespace, derive_read_base,
    derive_read_secret, CredentialKind, EpochExport, GenerationSecret, InvitePassword, JoinKey,
    PseudonymSeed, StateKey,
};
use crate::ext::{
    self, AdmitEvidence, Bootstrap, ChannelContext, ChannelOrder, CommitAad, GhostLeaf, KpBind,
    Purpose, SwapEvidence, FLAG_MEMBERS_MAY_INVITE, FLAG_PASSWORD,
};
use crate::invite::{self, InviteFields};
use crate::join::{self, JoinAuth, JoinRequest, RequestType, WelcomeBlob};
use crate::kv::{self, Change, ChangeSet, GhostKv, RowSource, Scope};
use crate::provider::{GhostProvider, PseudonymSigner};
use crate::result::{Code, CommitReason, MlsError, MlsResult};
use crate::seal::{self, Order, SealKeyInput};

/// Most application messages one `receive` call takes (S0-17).
pub const RECEIVE_BATCH_MAX: usize = 32;
/// Most held blobs one `trial_count` call tries (CO-3, S0-17).
pub const TRIAL_HELD_MAX: usize = 32;
/// Most Adds and swaps one `commit` request carries together: the bound on a channel's pending
/// join, restore and rejoin requests (§6.3.5, CS-C8: "≤ 64 per channel"), so a pass can hand every
/// pending request to one call and let §5.7's deferral choose (review of S2b).
pub const COMMIT_JOINERS_MAX: usize = 64;
/// `max_past_epochs` (§3.5, S0-6).
pub const MAX_PAST_EPOCHS: usize = 16;

/// Pins `rayon`'s global pool to one worker (design §3.6), once per process, and reports the
/// number of threads the pool has afterwards (1, or the call is `CRYPTO_UNAVAILABLE`).
pub fn pin_rayon_single_worker() -> usize {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        // A pool built earlier by someone else is detected below, never replaced.
        let _ = rayon::ThreadPoolBuilder::new()
            .num_threads(1)
            .build_global();
    });
    rayon::current_num_threads()
}

/// The join configuration of every channel (§3.5).
pub fn join_config() -> MlsGroupJoinConfig {
    MlsGroupJoinConfig::builder()
        .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
        .padding_size(0)
        .use_ratchet_tree_extension(true)
        .sender_ratchet_configuration(SenderRatchetConfiguration::new(16, 1000))
        .max_past_epochs(MAX_PAST_EPOCHS)
        .build()
}

fn ser(m: &MlsMessageOut) -> MlsResult<Vec<u8>> {
    m.tls_serialize_detached()
        .map_err(|_| MlsError::new(Code::Internal))
}

fn corrupt<E>(_: E) -> MlsError {
    MlsError::new(Code::StateCorrupt)
}

fn internal<E>(_: E) -> MlsError {
    MlsError::new(Code::Internal)
}

/// The kinds of key envelope (§3.4's wrapping applied to single keys; the byte format is fixed by
/// S2a, §19.30 item 14, amended §19.31): `nonce(12) ‖ ChaCha20-Poly1305(state key, AD =
/// "ghost/v1/ch-key" ‖ class ‖ channel_id, key(32))`, 60 bytes; an **epoch** key's plaintext is
/// `key(32) ‖ u64_be(e)`, 68 bytes, so the envelope names the epoch `K_ep(e)` belongs to and
/// `open_blob` refuses a blob whose MLS header is of another epoch (review M1).
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyClass {
    /// `K_ep(e)`.
    Epoch = 1,
    /// `G_g`.
    Generation = 2,
    /// `JK_g`.
    Join = 3,
    /// A box secret key `b_sk` (§5.1, §19.17).
    Box = 4,
    /// An invite's `invite_seed` (§5.9), held by the invitee between `inviteParse` and
    /// `joinRequest` (slice S2b, §19.32): the invite key is a signing secret, so Kotlin keeps it
    /// wrapped like every other key of the channel (CS-S6's rule applied to it).
    Invite = 5,
    /// `JK_g` **as an invite carries it** (`inviteParse`'s `JK_ENV`; review of S2b, §19.36): the
    /// invitee's copy, which seals its join or restore request (mode 0x12) and opens its Welcome
    /// blob (mode 0x13), and nothing else. Anyone can write an invite naming any channel, so an
    /// envelope minted from one must never pass for that channel's own `JK_g` (class 3), and never
    /// open the join requests a member reads.
    InviteJoin = 6,
}

impl KeyClass {
    /// The class byte of a JNI argument or a test vector, 1 … 6. Only 1 (`K_ep`), 3 (`JK_g`) and 6
    /// (an invite's `JK_g`) are seal keys: `seal` and `open` refuse the others (`INVALID_POLICY`).
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(KeyClass::Epoch),
            2 => Some(KeyClass::Generation),
            3 => Some(KeyClass::Join),
            4 => Some(KeyClass::Box),
            5 => Some(KeyClass::Invite),
            6 => Some(KeyClass::InviteJoin),
            _ => None,
        }
    }
}

const KEY_ENV_LABEL: &[u8] = b"ghost/v1/ch-key";

/// A member's context (`ctxOpen`, fn 1): the crypto provider and the state key.
pub struct MlsContext {
    crypto: CryptoProvider,
    state_key: StateKey,
}

/// An open channel (`channelOpen`, fn 2): its id and the pseudonym signer.
pub struct ChannelHandle {
    channel_id: [u8; 32],
    signer: PseudonymSigner,
}

impl ChannelHandle {
    pub fn open(channel_id: [u8; 32], seed: &PseudonymSeed) -> Self {
        Self {
            channel_id,
            signer: PseudonymSigner::from_seed(seed),
        }
    }

    pub fn channel_id(&self) -> &[u8; 32] {
        &self.channel_id
    }

    /// `P`, which Kotlin compares with `:identity`'s value (fn 2).
    pub fn pseudonym(&self) -> [u8; 32] {
        self.signer.public()
    }

    /// A GHOST-level signature under the channel's pseudonym key (§6.9's `sig_ps`; the same
    /// signer as `sponsor_sig` and `rejoin_sig`).
    pub fn sign_raw(&self, message: &[u8]) -> [u8; 64] {
        self.signer.sign_raw(message)
    }

    fn credential(&self) -> CredentialWithKey {
        let p = self.pseudonym();
        CredentialWithKey {
            credential: BasicCredential::new(p.to_vec()).into(),
            signature_key: p.to_vec().into(),
        }
    }
}

/// An epoch's keys as Kotlin stores them (§9 `ch_epoch`): `K_ep` wrapped, `R_ep` in clear (CS-S6).
#[derive(Clone, PartialEq, Eq)]
pub struct EpochKeys {
    pub epoch: u64,
    pub k_env: Vec<u8>,
    pub r_ep: [u8; 32],
    pub epoch_authenticator: Vec<u8>,
}

/// A generation's values (§5.2, fn 13): `G_g` and `JK_g` wrapped, `ns` and `R_join` in clear.
#[derive(Clone, PartialEq, Eq)]
pub struct GenerationValues {
    pub generation: u32,
    pub open_epoch: u64,
    pub g_env: Vec<u8>,
    pub ns: [u8; 32],
    pub jk_env: Vec<u8>,
    pub r_join: [u8; 32],
}

// Secrets never render (derive.rs's rule; review of S2a, §19.31): the recognition keys, the bearer
// credentials and an invite link are left out of every `Debug` of an output, which a panic
// payload can carry; the public fields and the lengths stay.
impl core::fmt::Debug for EpochKeys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EpochKeys")
            .field("epoch", &self.epoch)
            .field("k_env_len", &self.k_env.len())
            .finish_non_exhaustive()
    }
}

impl core::fmt::Debug for GenerationValues {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GenerationValues")
            .field("generation", &self.generation)
            .field("open_epoch", &self.open_epoch)
            .finish_non_exhaustive()
    }
}

/// A member of the roster (fn 18).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RosterEntry {
    pub pseudonym: [u8; 32],
    pub leaf: u32,
    pub box_pk: Option<[u8; 32]>,
    pub refresh_epoch: Option<u64>,
}

#[derive(Clone, Debug)]
pub struct CreateOut {
    pub changes: ChangeSet,
    pub epoch: EpochKeys,
    pub generation: GenerationValues,
    pub box_pk: [u8; 32],
    pub box_env: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct KeyPackageOut {
    /// The canonical KeyPackage `MlsMessage` (395 bytes).
    pub key_package: Vec<u8>,
    pub kp_ref: Vec<u8>,
    /// The global rows (the KeyPackage bundle and its private keys).
    pub changes: ChangeSet,
    pub box_pk: [u8; 32],
    pub box_env: Vec<u8>,
}

/// The joiner's anchor (§6.2.5, S0-15, §19.27 TR-7, §19.29.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Anchor {
    /// A join or restore: the invite's `committers_digest`.
    Invite { committers_digest: [u8; 32] },
    /// A rejoin: the committers of the member's last final epoch (no digest comparison).
    Rejoin { last_committers: Vec<[u8; 32]> },
}

#[derive(Clone, Debug)]
pub struct JoinOut {
    pub changes: ChangeSet,
    pub context: ChannelContext,
    pub roster: Vec<RosterEntry>,
    pub leaf: u32,
    pub epoch: EpochKeys,
    pub generation: GenerationValues,
}

/// One message of a `receive` batch (fn 6). A batch holds at most 32, so the size difference
/// between the variants costs nothing worth a box. An application message's `sender` is the
/// pseudonym of the leaf that signed it in the message's own epoch (`ProcessedMessage::credential`;
/// review H2), never the current holder of its leaf index.
#[derive(Clone, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum ReceiveItem {
    App {
        content: ChannelContent,
        sender: [u8; 32],
        order: ChannelOrder,
    },
    /// A commit's validation summary (no change-set; §6.4 CO-2).
    Commit(Box<CommitSummary>),
    /// A proposal, dropped unprocessed (§6.3.2, §19.16).
    Proposal,
    /// An `OwnPrivateMessage` result: evidence of nothing (§6.3.2, §19.13).
    Own,
    Failed(MlsError),
}

#[derive(Clone, Debug)]
pub struct ReceiveOut {
    pub items: Vec<ReceiveItem>,
    pub changes: ChangeSet,
}

/// A settle's winner (fn 7, fn 20): another member's commit, or the member's own pending commit
/// (its bytes, from which the `GhostCommitAad` is read without decryption).
#[derive(Clone, Copy, Debug)]
pub enum Winner<'a> {
    Foreign(&'a [u8]),
    Own(&'a [u8]),
}

/// Where a settle leaves the member (§6.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Standing {
    /// Still a member, at the new epoch.
    Member,
    /// The commit removed the member's leaf (a Remove, a leave, an eviction): OpenMLS marks the
    /// group inactive; Kotlin sets `state = removed`, deletes the MLS state and keeps listening
    /// until the drain ends (§6.5, §6.6).
    Removed,
    /// The commit removed the member's leaf and added its own pseudonym with a KeyPackage of
    /// another device (a restore or rejoin swap): `state = replaced` (§6.6, §6.7).
    Replaced,
}

#[derive(Clone, Debug)]
pub struct SettleOut {
    pub changes: ChangeSet,
    /// The new epoch's keys; `None` when the commit removed or replaced the member (an inactive
    /// group exports nothing).
    pub epoch: Option<EpochKeys>,
    pub commit_minute: u32,
    /// Whether the commit opens a new generation (§6.5): what a removed member needs to end its
    /// drain on the same day as everyone.
    pub rotates: bool,
    /// The new generation when the commit rotates and the member stays (§6.5).
    pub rotated: Option<GenerationValues>,
    pub added: Vec<[u8; 32]>,
    pub removed: Vec<[u8; 32]>,
    pub standing: Standing,
}

/// What a commit carries (fn 9).
#[derive(Clone, Debug, Default)]
pub struct CommitRequest {
    pub adds: Vec<(Vec<u8>, AdmitEvidence)>,
    pub removes: Vec<[u8; 32]>,
    pub swaps: Vec<([u8; 32], Vec<u8>, SwapEvidence)>,
    pub context: Option<ChannelContext>,
    pub rotate: bool,
    pub commit_minute: u32,
    /// The size class's floor bucket (§5.7): the commit's body must fit `C(floor)`. It must be the
    /// floor of the pre-commit context's class, the one every member's CO-2 applies
    /// (`INVALID_POLICY` otherwise, checked before it is used; review M2).
    pub floor: usize,
    /// The current generation (the Welcome's bootstrap, §5.4).
    pub generation: u32,
    pub generation_open_epoch: u64,
    pub g_env: Vec<u8>,
}

/// How much of the requested context change a commit kept (§5.7's deferral order).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContextKept {
    NotRequested,
    Full,
    /// Only the drops of the keys of pseudonyms the commit removes.
    DropsOnly,
}

#[derive(Clone, Debug)]
pub struct CommitOut {
    pub commit: Vec<u8>,
    pub welcome: Option<Vec<u8>>,
    pub joiners: Vec<Vec<u8>>,
    /// Indices into the request's lists of what the commit carries; the rest is deferred.
    pub kept_adds: Vec<usize>,
    pub kept_swaps: Vec<usize>,
    pub kept_removes: Vec<usize>,
    pub context: ContextKept,
    pub rotates: bool,
    pub box_pk: [u8; 32],
    pub box_env: Vec<u8>,
    pub changes: ChangeSet,
    /// The committer's own validation of its pending commit (CO-2 as members will run it).
    pub summary: Box<CommitSummary>,
}

#[derive(Clone, Debug)]
pub struct EncryptOut {
    pub mls: Vec<u8>,
    pub epoch: u64,
    pub sender_leaf: u32,
    pub changes: ChangeSet,
}

/// The per-slot credentials of a generation (fn 13).
#[derive(Clone, PartialEq, Eq)]
pub struct SlotCredentials {
    pub slot: u8,
    pub read_credential: Vec<u8>,
    pub read_verifier: [u8; 32],
    pub deposit_credential: Vec<u8>,
    pub deposit_verifier: [u8; 32],
}

impl core::fmt::Debug for SlotCredentials {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // The credentials are bearer secrets (F9 §4.3): left out.
        f.debug_struct("SlotCredentials")
            .field("slot", &self.slot)
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
pub struct InviteOut {
    /// `ChannelInviteV2`, 335 bytes.
    pub invite: Vec<u8>,
    pub issued: crate::content::InviteIssued,
}

impl core::fmt::Debug for InviteOut {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // An open link is a bearer secret (§5.9): left out.
        f.debug_struct("InviteOut")
            .field("invite_len", &self.invite.len())
            .field("issued", &self.issued)
            .finish()
    }
}

/// `inviteParse` with a context (fn 14 as slice S2b maps it, §19.32): the invite's public fields,
/// its secrets **wrapped** under the state key (`JK_g` as an invite join-key envelope, class 6 —
/// never the channel's own class 3, §19.36 —, `invite_seed` as an invite envelope, both bound to
/// the invite's channel), `R_join` (a recognition key, CS-S6) and the READ and DEPOSIT credentials
/// of the requested slots, which the invitee presents to the relays of `ns_g` to deposit its join
/// request and to listen for its Welcome.
#[derive(Clone)]
pub struct ParsedInvite {
    pub kdf_code: u8,
    pub suite: u16,
    pub size_class: u8,
    pub handshake_ttl_code: u8,
    pub channel_id: [u8; 32],
    pub generation: u32,
    pub ns: [u8; 32],
    pub invite_id: [u8; 16],
    pub invite_pk: [u8; 32],
    pub committers_digest: [u8; 32],
    pub expiry_day: u32,
    pub name: Vec<u8>,
    pub jk_env: Vec<u8>,
    pub r_join: [u8; 32],
    pub seed_env: Vec<u8>,
    pub slots: Vec<SlotCredentials>,
}

impl core::fmt::Debug for ParsedInvite {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // `R_join` and the credentials are left out, like every output's secrets (§19.31 row 13).
        f.debug_struct("ParsedInvite")
            .field("kdf_code", &self.kdf_code)
            .field("generation", &self.generation)
            .field("expiry_day", &self.expiry_day)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug)]
pub struct VerifiedJoin {
    pub request_type: RequestType,
    pub key_package: CanonicalKeyPackage,
    pub auth: JoinAuth,
}

#[derive(Clone, Debug)]
pub struct RosterOut {
    pub members: Vec<RosterEntry>,
    pub epoch: u64,
    pub epoch_authenticator: Vec<u8>,
    pub tree_hash: Vec<u8>,
    pub context: ChannelContext,
    pub own_leaf: u32,
    /// The digest of the context's `committers` (S0-15): the invite anchor and CO-2 (A)'s equality
    /// input, returned here so Kotlin stops learning it from a throwaway `inviteBuild` (§19.37
    /// F-S4-2, closed in S5a).
    pub committers_digest: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrialOut {
    /// The candidate's committer.
    pub committer: [u8; 32],
    /// The distinct authenticated senders, other than the member, of the held blobs that open
    /// under the trial state (CO-3; the successor count is this minus the committer).
    pub senders: Vec<[u8; 32]>,
}

/// A group loaded into a fresh adapter (value semantics).
struct Loaded<'a> {
    p: GhostProvider<'a>,
    channel_id: [u8; 32],
}

impl MlsContext {
    /// `ctxOpen` (fn 1). `CRYPTO_UNAVAILABLE` when the provider's DRBG cannot be seeded or the
    /// global `rayon` pool is not one worker.
    pub fn open(state_key: StateKey) -> MlsResult<Self> {
        if pin_rayon_single_worker() != 1 {
            return Err(MlsError::new(Code::CryptoUnavailable));
        }
        let crypto = CryptoProvider::new().map_err(|_| MlsError::new(Code::CryptoUnavailable))?;
        Ok(Self { crypto, state_key })
    }

    pub fn crypto(&self) -> &CryptoProvider {
        &self.crypto
    }

    fn random<const N: usize>(&self) -> MlsResult<[u8; N]> {
        self.crypto
            .random_array()
            .map_err(|_| MlsError::new(Code::CryptoUnavailable))
    }

    // ---- key envelopes ------------------------------------------------------------------------

    fn key_env_ad(class: KeyClass, channel_id: &[u8; 32]) -> Vec<u8> {
        let mut a = KEY_ENV_LABEL.to_vec();
        a.push(class as u8);
        a.extend_from_slice(channel_id);
        a
    }

    fn env_plain_len(class: KeyClass) -> usize {
        match class {
            KeyClass::Epoch => 40,
            _ => 32,
        }
    }

    fn seal_env(&self, class: KeyClass, channel_id: &[u8; 32], plain: &[u8]) -> MlsResult<Vec<u8>> {
        use chacha20poly1305::aead::{Aead, KeyInit, Payload};
        if plain.len() != Self::env_plain_len(class) {
            return Err(MlsError::new(Code::InvalidPolicy));
        }
        let nonce: [u8; 12] = self.random()?;
        let ct = chacha20poly1305::ChaCha20Poly1305::new(self.state_key.as_bytes().into())
            .encrypt(
                &chacha20poly1305::Nonce::from(nonce),
                Payload {
                    msg: plain,
                    aad: &Self::key_env_ad(class, channel_id),
                },
            )
            .map_err(internal)?;
        let mut o = nonce.to_vec();
        o.extend_from_slice(&ct);
        Ok(o)
    }

    fn open_env(
        &self,
        class: KeyClass,
        channel_id: &[u8; 32],
        env: &[u8],
    ) -> MlsResult<Zeroizing<Vec<u8>>> {
        use chacha20poly1305::aead::{Aead, KeyInit, Payload};
        if env.len() != 12 + Self::env_plain_len(class) + 16 {
            return Err(MlsError::new(Code::StateCorrupt));
        }
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&env[..12]);
        Ok(Zeroizing::new(
            chacha20poly1305::ChaCha20Poly1305::new(self.state_key.as_bytes().into())
                .decrypt(
                    &chacha20poly1305::Nonce::from(nonce),
                    Payload {
                        msg: &env[12..],
                        aad: &Self::key_env_ad(class, channel_id),
                    },
                )
                .map_err(corrupt)?,
        ))
    }

    /// Wraps a 32-byte key of any class but the epoch's under the state key; an epoch key goes
    /// through [`MlsContext::wrap_epoch_key`] (`INVALID_POLICY` here).
    pub fn wrap_key(
        &self,
        class: KeyClass,
        channel_id: &[u8; 32],
        key: &[u8; 32],
    ) -> MlsResult<Vec<u8>> {
        self.seal_env(class, channel_id, key)
    }

    /// Wraps `K_ep(e)` with its epoch (68 bytes).
    pub fn wrap_epoch_key(
        &self,
        channel_id: &[u8; 32],
        epoch: u64,
        key: &[u8; 32],
    ) -> MlsResult<Vec<u8>> {
        let mut plain = Zeroizing::new([0u8; 40]);
        plain[..32].copy_from_slice(key);
        plain[32..].copy_from_slice(&epoch.to_be_bytes());
        self.seal_env(KeyClass::Epoch, channel_id, &plain[..])
    }

    /// Opens a key envelope (for an epoch key, the key without its epoch); one that does not open
    /// is `STATE_CORRUPT`.
    pub fn unwrap_key(
        &self,
        class: KeyClass,
        channel_id: &[u8; 32],
        env: &[u8],
    ) -> MlsResult<Zeroizing<[u8; 32]>> {
        let pt = self.open_env(class, channel_id, env)?;
        let mut k = Zeroizing::new([0u8; 32]);
        k.copy_from_slice(&pt[..32]);
        Ok(k)
    }

    /// Opens an epoch key's envelope: `K_ep(e)` and e.
    pub fn unwrap_epoch_key(
        &self,
        channel_id: &[u8; 32],
        env: &[u8],
    ) -> MlsResult<(Zeroizing<[u8; 32]>, u64)> {
        let pt = self.open_env(KeyClass::Epoch, channel_id, env)?;
        let mut k = Zeroizing::new([0u8; 32]);
        k.copy_from_slice(&pt[..32]);
        let mut e = [0u8; 8];
        e.copy_from_slice(&pt[32..40]);
        Ok((k, u64::from_be_bytes(e)))
    }

    // ---- value semantics ------------------------------------------------------------------------

    fn load<'a>(
        &'a self,
        channel_id: &[u8; 32],
        rows: &dyn RowSource,
        day: u32,
    ) -> MlsResult<Loaded<'a>> {
        let storage = GhostKv::new(*channel_id, day);
        storage.load(rows.load(channel_id, &self.state_key)?)?;
        Ok(Loaded {
            p: GhostProvider {
                crypto: &self.crypto,
                storage,
            },
            channel_id: *channel_id,
        })
    }

    fn fresh<'a>(&'a self, channel_id: &[u8; 32], day: u32) -> Loaded<'a> {
        Loaded {
            p: GhostProvider {
                crypto: &self.crypto,
                storage: GhostKv::new(*channel_id, day),
            },
            channel_id: *channel_id,
        }
    }

    /// The net change-set of a successful call, each value wrapped with a fresh nonce.
    fn finish(&self, l: &Loaded<'_>) -> MlsResult<ChangeSet> {
        let mut out = Vec::new();
        for ((scope, key), v) in l.p.storage.take_plain_changes() {
            let env = match v {
                Some(v) => Some(kv::wrap(
                    &self.state_key,
                    self.random()?,
                    scope,
                    &l.channel_id,
                    &key,
                    &v,
                )),
                None => None,
            };
            out.push(Change { scope, key, env });
        }
        Ok(out)
    }

    fn group(l: &Loaded<'_>) -> MlsResult<MlsGroup> {
        MlsGroup::load(l.p.storage(), &GroupId::from_slice(&l.channel_id))
            .map_err(corrupt)?
            .ok_or(MlsError::new(Code::StateCorrupt))
    }

    // ---- derived values -------------------------------------------------------------------------

    fn export_epoch_key(&self, g: &MlsGroup, channel_id: &[u8; 32]) -> MlsResult<EpochExport> {
        // The exporter's output is a key: zeroized when dropped, like every copy (review ML2).
        let v = Zeroizing::new(
            g.export_secret(&self.crypto, derive::LABEL_EPOCH, channel_id, 32)
                .map_err(internal)?,
        );
        let mut k = Zeroizing::new([0u8; 32]);
        k.copy_from_slice(&v);
        Ok(EpochExport::from_bytes(*k))
    }

    fn export_generation_secret(
        &self,
        g: &MlsGroup,
        channel_id: &[u8; 32],
    ) -> MlsResult<GenerationSecret> {
        let v = Zeroizing::new(
            g.export_secret(&self.crypto, derive::LABEL_GENERATION, channel_id, 32)
                .map_err(internal)?,
        );
        let mut k = Zeroizing::new([0u8; 32]);
        k.copy_from_slice(&v);
        Ok(GenerationSecret::from_bytes(*k))
    }

    fn epoch_keys(&self, g: &MlsGroup, channel_id: &[u8; 32]) -> MlsResult<EpochKeys> {
        let k = self.export_epoch_key(g, channel_id)?;
        let epoch = g.epoch().as_u64();
        Ok(EpochKeys {
            epoch,
            k_env: self.wrap_epoch_key(channel_id, epoch, k.as_bytes())?,
            r_ep: *derive_epoch_recognition(&k).as_bytes(),
            epoch_authenticator: g.epoch_authenticator().as_slice().to_vec(),
        })
    }

    fn generation_values(
        &self,
        channel_id: &[u8; 32],
        generation: u32,
        open_epoch: u64,
        g: &GenerationSecret,
    ) -> MlsResult<GenerationValues> {
        let jk = derive_join_key(g);
        Ok(GenerationValues {
            generation,
            open_epoch,
            g_env: self.wrap_key(KeyClass::Generation, channel_id, g.as_bytes())?,
            ns: derive_namespace(g),
            jk_env: self.wrap_key(KeyClass::Join, channel_id, jk.as_bytes())?,
            r_join: *derive_join_recognition(&jk).as_bytes(),
        })
    }

    /// A fresh box key (§5.1, §19.17): X25519 from 32 CSPRNG bytes, returned wrapped.
    fn box_key(&self, channel_id: &[u8; 32]) -> MlsResult<([u8; 32], Vec<u8>)> {
        let sk = zeroize::Zeroizing::new(self.random::<32>()?);
        let pk = canonical::box_public(&sk);
        if !canonical::valid_box_pk(&pk) {
            return Err(MlsError::new(Code::Internal));
        }
        Ok((pk, self.wrap_key(KeyClass::Box, channel_id, &sk)?))
    }

    fn context_of(g: &MlsGroup) -> MlsResult<ChannelContext> {
        g.extensions()
            .unknown(ext::EXT_CHANNEL_CONTEXT)
            .and_then(|u| ChannelContext::decode(&u.0))
            .ok_or(MlsError::new(Code::StateCorrupt))
    }

    fn roster_of(g: &MlsGroup) -> Vec<RosterEntry> {
        g.members()
            .map(|m| {
                let leaf = g.public_group().leaf(m.index);
                let gl = leaf.and_then(|l| {
                    l.extensions()
                        .unknown(ext::EXT_LEAF)
                        .and_then(|u| GhostLeaf::decode(&u.0))
                });
                let mut pseudonym = [0u8; 32];
                if m.signature_key.len() == 32 {
                    pseudonym.copy_from_slice(&m.signature_key);
                }
                RosterEntry {
                    pseudonym,
                    leaf: m.index.u32(),
                    box_pk: gl.map(|g| g.box_pk),
                    refresh_epoch: gl.map(|g| g.refresh_epoch),
                }
            })
            .collect()
    }

    // ---- fn 3: groupCreate ----------------------------------------------------------------------

    /// `groupCreate` (fn 3, §6.1). `INVALID_POLICY` for a context §5.3 refuses for a one-member
    /// group whose only leaf is the creator (committers = funders = [P] at creation).
    pub fn group_create(
        &self,
        ch: &ChannelHandle,
        policy: &ChannelContext,
        day: u32,
    ) -> MlsResult<CreateOut> {
        let channel_id = ch.channel_id;
        policy
            .check(&channel_id, &[ch.pseudonym()])
            .map_err(|_| MlsError::new(Code::InvalidPolicy))?;
        let (box_pk, box_env) = self.box_key(&channel_id)?;
        let l = self.fresh(&channel_id, day);
        let exts = Extensions::from_vec(vec![
            Extension::Unknown(ext::EXT_CHANNEL_CONTEXT, UnknownExtension(policy.encode())),
            canonical::required_capabilities(),
        ])
        .map_err(|_| MlsError::new(Code::InvalidPolicy))?;
        let leaf = GhostLeaf {
            box_pk,
            refresh_epoch: 0,
        };
        let g = MlsGroup::builder()
            .with_group_id(GroupId::from_slice(&channel_id))
            .ciphersuite(SUITE)
            .with_wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
            .padding_size(0)
            .use_ratchet_tree_extension(true)
            .sender_ratchet_configuration(SenderRatchetConfiguration::new(16, 1000))
            .max_past_epochs(MAX_PAST_EPOCHS)
            .lifetime(canonical::constant_lifetime())
            .with_capabilities(canonical::canonical_capabilities())
            .with_group_context_extensions(exts)
            .with_leaf_node_extensions(canonical::leaf_extensions(&leaf)?)
            .map_err(|_| MlsError::new(Code::InvalidPolicy))?
            .build(&l.p, &ch.signer, ch.credential())
            .map_err(|_| MlsError::new(Code::InvalidPolicy))?;
        let epoch = self.epoch_keys(&g, &channel_id)?;
        let g0 = self.export_generation_secret(&g, &channel_id)?;
        let generation = self.generation_values(&channel_id, 0, 0, &g0)?;
        Ok(CreateOut {
            changes: self.finish(&l)?,
            epoch,
            generation,
            box_pk,
            box_env,
        })
    }

    // ---- fn 4: keyPackage -----------------------------------------------------------------------

    /// `keyPackage` (fn 4): the canonical KeyPackage of §6.2.4 (B) for `purpose`, bound to the
    /// channel and the caller's trusted `day` (its only date: the lifetime is constant).
    pub fn key_package(
        &self,
        ch: &ChannelHandle,
        purpose: Purpose,
        day: u32,
    ) -> MlsResult<KeyPackageOut> {
        let channel_id = ch.channel_id;
        let (box_pk, box_env) = self.box_key(&channel_id)?;
        let l = self.fresh(&channel_id, day);
        let bind = KpBind {
            channel_id,
            purpose,
            day,
        };
        let bundle = KeyPackage::builder()
            .key_package_lifetime(canonical::constant_lifetime())
            .leaf_node_capabilities(canonical::canonical_capabilities())
            .leaf_node_extensions(canonical::leaf_extensions(&GhostLeaf {
                box_pk,
                refresh_epoch: 0,
            })?)
            .key_package_extensions(
                Extensions::single(Extension::Unknown(
                    ext::EXT_KP_BIND,
                    UnknownExtension(bind.encode()),
                ))
                .map_err(internal)?,
            )
            .build(SUITE, &l.p, &ch.signer, ch.credential())
            .map_err(internal)?;
        let bytes = ser(&MlsMessageOut::from(bundle.key_package().clone()))?;
        // The builder's output must be the canonical KeyPackage (G-M7's golden: 395 bytes).
        let parsed = canonical::parse_key_package(&self.crypto, &bytes, Some(&channel_id))
            .map_err(internal)?;
        Ok(KeyPackageOut {
            key_package: bytes,
            kp_ref: parsed.kp_ref,
            changes: self.finish(&l)?,
            box_pk,
            box_env,
        })
    }

    // ---- fn 5: welcomeJoin ----------------------------------------------------------------------

    /// `welcomeJoin` (fn 5, §6.2.5). The committers anchor is checked on the **unverified**
    /// GroupInfo before `JoinBuilder::build()` (§19.27 TR-7; a rejoin checks the signature only,
    /// §19.29.2); then OpenMLS's join with `skip_lifetime_validation()`, GHOST's check of the
    /// constant lifetime on every KeyPackage-source leaf (§19.29.1), §5.3's validity of the joined
    /// context and the bootstrap (§5.4). On any failure nothing is returned, so the KeyPackage and
    /// its private keys stay (`new_from_welcome` deletes them inside the discarded change-set).
    /// `expected`: the generation and namespace the Welcome arrived in (the invite's for a join or
    /// restore).
    pub fn welcome_join(
        &self,
        ch: &ChannelHandle,
        rows: &dyn RowSource,
        welcome_blob: &[u8],
        day: u32,
        expected: (u32, [u8; 32]),
        anchor: &Anchor,
    ) -> MlsResult<JoinOut> {
        let channel_id = ch.channel_id;
        let invalid = MlsError::new(Code::InvalidWelcome);
        let blob = WelcomeBlob::decode(welcome_blob).map_err(|_| invalid)?;
        let m = MlsMessageIn::tls_deserialize_exact(&blob.welcome).map_err(|_| invalid)?;
        let welcome = match m.extract() {
            MlsMessageBodyIn::Welcome(w) => w,
            _ => return Err(invalid),
        };
        let l = self.load(&channel_id, rows, day)?;
        let pw = match ProcessedWelcome::new_from_welcome(&l.p, &join_config(), welcome) {
            Ok(pw) => pw,
            Err(WelcomeError::NoMatchingKeyPackage) => return Err(MlsError::new(Code::NotForMe)),
            Err(_) => return Err(invalid),
        };
        // The anchor, on the unverified GroupInfo, before any tree validation.
        let gi = pw.unverified_group_info();
        if gi.group_id().as_slice() != channel_id {
            return Err(invalid);
        }
        let ctx = gi
            .group_context()
            .extensions()
            .unknown(ext::EXT_CHANNEL_CONTEXT)
            .and_then(|u| ChannelContext::decode(&u.0))
            .ok_or(invalid)?;
        let signers: &[[u8; 32]] = match anchor {
            Anchor::Invite {
                committers_digest: d,
            } => {
                if committers_digest(&channel_id, &ctx.committers) != Some(*d) {
                    return Err(invalid);
                }
                &ctx.committers
            }
            Anchor::Rejoin { last_committers } => last_committers,
        };
        let signed_by_anchor = signers.iter().any(|k| {
            OpenMlsSignaturePublicKey::new(k.to_vec().into(), SignatureScheme::ED25519)
                .map(|pk| gi.verify_no_out(&self.crypto, &pk).is_ok())
                .unwrap_or(false)
        });
        if !signed_by_anchor {
            return Err(invalid);
        }
        let boot = gi
            .extensions()
            .unknown(ext::EXT_BOOTSTRAP)
            .and_then(|u| Bootstrap::decode(&u.0))
            .ok_or(MlsError::new(Code::InvalidBootstrap))?;
        // OpenMLS's join, lifetimes checked by GHOST (the constant form), not by the device clock.
        let staged = JoinBuilder::new(&l.p, pw)
            .skip_lifetime_validation()
            .build()
            .map_err(|_| invalid)?;
        let g = staged.into_group(&l.p).map_err(|_| invalid)?;
        // Every leaf of the joined tree is canonical (S0-5: capabilities, `GhostLeaf`, the credential
        // naming the signature key) with a valid X25519 key, the KeyPackage-source ones with the
        // constant lifetime (§19.29.1), and every parent node's key is valid too (H1): a joiner never
        // enters a tree to which some later commit could not encrypt.
        let mut leaves = Vec::new();
        for m in g.members() {
            let leaf = g.public_group().leaf(m.index).ok_or(invalid)?;
            let facts = canonical::check_leaf(leaf).map_err(|_| invalid)?;
            if let openmls::treesync::LeafNodeSource::KeyPackage(_) = leaf.leaf_node_source() {
                canonical::check_key_package_source(leaf).map_err(|_| invalid)?;
            }
            leaves.push(facts.signature_key);
        }
        if !canonical::tree_keys_valid(&g.export_ratchet_tree()) {
            return Err(invalid);
        }
        let joined_ctx = Self::context_of(&g).map_err(|_| invalid)?;
        if joined_ctx != ctx {
            return Err(invalid);
        }
        joined_ctx
            .check(&channel_id, &leaves)
            .map_err(|_| MlsError::new(Code::InvalidPolicy))?;
        // The bootstrap (§5.4): the generation of the namespace the Welcome arrived in must match
        // it; a newer one is accepted from this (anchored) Welcome; an older one is refused.
        let epoch_now = g.epoch().as_u64();
        let (exp_gen, exp_ns) = expected;
        if boot.generation < exp_gen || boot.open_epoch > epoch_now {
            return Err(MlsError::new(Code::InvalidBootstrap));
        }
        let gsec = if boot.open_epoch == epoch_now {
            // The Welcome's own commit opened the generation: G is exported here and the carried
            // one must be zero (a rotating commit cannot know G before it exists; §19.30).
            if boot.g != [0u8; 32] {
                return Err(MlsError::new(Code::InvalidBootstrap));
            }
            self.export_generation_secret(&g, &channel_id)?
        } else {
            GenerationSecret::from_bytes(boot.g)
        };
        if boot.generation == exp_gen && derive_namespace(&gsec) != exp_ns {
            return Err(MlsError::new(Code::InvalidBootstrap));
        }
        let epoch = self.epoch_keys(&g, &channel_id)?;
        let generation =
            self.generation_values(&channel_id, boot.generation, boot.open_epoch, &gsec)?;
        Ok(JoinOut {
            context: joined_ctx,
            roster: Self::roster_of(&g),
            leaf: g.own_leaf_index().u32(),
            epoch,
            generation,
            changes: self.finish(&l)?,
        })
    }

    // ---- fn 6: receive --------------------------------------------------------------------------

    /// `receive` (fn 6, S0-17): up to 32 application messages of one epoch in peek order, or one
    /// commit or proposal alone. Each application message runs from a checkpoint and a failed one
    /// is rolled back; the change-set is the net of the successful ones. A commit is validated
    /// (CO-2) and its change-set discarded.
    pub fn receive(
        &self,
        ch: &ChannelHandle,
        rows: &dyn RowSource,
        epoch: u64,
        msgs: &[Vec<u8>],
        day: u32,
    ) -> MlsResult<ReceiveOut> {
        if msgs.is_empty() || msgs.len() > RECEIVE_BATCH_MAX {
            return Err(MlsError::new(Code::InvalidPolicy));
        }
        let l = self.load(&ch.channel_id, rows, day)?;
        let mut items = Vec::with_capacity(msgs.len());
        let mut committed = false;
        for bytes in msgs {
            let cp = l.p.storage.checkpoint();
            let item = self.receive_one(&l, ch, epoch, bytes, msgs.len() == 1);
            match &item {
                ReceiveItem::App { .. } => {}
                ReceiveItem::Commit(_) => {
                    // The validation run's change-set is discarded (CO-2).
                    l.p.storage.restore(cp);
                    committed = true;
                }
                _ => l.p.storage.restore(cp),
            }
            items.push(item);
        }
        let changes = if committed {
            let _ = l.p.storage.take_plain_changes();
            Vec::new()
        } else {
            self.finish(&l)?
        };
        Ok(ReceiveOut { items, changes })
    }

    fn receive_one(
        &self,
        l: &Loaded<'_>,
        ch: &ChannelHandle,
        epoch: u64,
        bytes: &[u8],
        alone: bool,
    ) -> ReceiveItem {
        let fail = |c: Code| ReceiveItem::Failed(MlsError::new(c));
        let Ok(m) = MlsMessageIn::tls_deserialize_exact(bytes) else {
            return fail(Code::NonCanonical);
        };
        let pm = match m.extract() {
            MlsMessageBodyIn::PrivateMessage(pm) => pm,
            _ => return fail(Code::NonCanonical),
        };
        if pm.epoch().as_u64() != epoch {
            return fail(Code::WrongEpoch);
        }
        let content_type = pm.content_type();
        match content_type {
            ContentType::Proposal => return ReceiveItem::Proposal,
            ContentType::Commit if !alone => return fail(Code::InvalidPolicy),
            _ => {}
        }
        let Ok(mut g) = Self::group(l) else {
            return fail(Code::StateCorrupt);
        };
        // A commit is processed only at the current epoch (OpenMLS refuses others before
        // decrypting, valn1307); an application message may be of a retained past epoch (a late
        // post, decrypted with that epoch's secrets) but never of a future one.
        let current = g.epoch().as_u64();
        let epoch_ok = match content_type {
            ContentType::Commit => epoch == current,
            _ => epoch <= current,
        };
        if !epoch_ok {
            return fail(Code::WrongEpoch);
        }
        let pre = match content_type {
            ContentType::Commit => PreState::of_commit(&g),
            _ => PreState::of(&g),
        };
        let pre = match pre {
            Ok(p) => p,
            Err(e) => return ReceiveItem::Failed(e),
        };
        let processed = match g.process_message(&l.p, ProtocolMessage::from(pm)) {
            Ok(p) => p,
            Err(e) => {
                return ReceiveItem::Failed(match content_type {
                    ContentType::Commit => check::map_process_error(&e),
                    _ => MlsError::new(Code::Undecryptable),
                })
            }
        };
        let aad = processed.aad().to_vec();
        let sender = processed.sender().clone();
        // The author as OpenMLS verified it: the credential of the sender's leaf **in the message's
        // epoch** (a late post of a retained epoch is signed by that epoch's leaf; whoever holds the
        // leaf index now may be someone else, review H2).
        let author = canonical::basic_identity(processed.credential());
        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(a) => {
                // A post's plaintext: erased however this arm ends (review of S2b).
                let plain = Zeroizing::new(a.into_bytes());
                let Sender::Member(idx) = sender else {
                    return fail(Code::Undecryptable);
                };
                let Some(order) = ChannelOrder::decode(&aad) else {
                    return fail(Code::OrderMismatch);
                };
                if order.sender_leaf != idx.u32() {
                    return fail(Code::OrderMismatch);
                }
                let Some(key) = author else {
                    return fail(Code::Undecryptable);
                };
                match ChannelContent::decode(&plain) {
                    Ok(content) => ReceiveItem::App {
                        content,
                        sender: key,
                        order,
                    },
                    Err(e) => ReceiveItem::Failed(e),
                }
            }
            ProcessedMessageContent::StagedCommitMessage(sc) => {
                let floor = seal::floor(pre.context.size_class).unwrap_or(4096);
                match check::summarize(
                    &self.crypto,
                    &ch.channel_id,
                    &pre,
                    &sender,
                    &aad,
                    &sc,
                    bytes,
                    floor,
                ) {
                    Ok(s) => ReceiveItem::Commit(Box::new(s)),
                    Err(e) => ReceiveItem::Failed(e),
                }
            }
            ProcessedMessageContent::OwnPrivateMessage
            | ProcessedMessageContent::OwnPendingCommit => ReceiveItem::Own,
            ProcessedMessageContent::ProposalMessage(_)
            | ProcessedMessageContent::ExternalJoinProposalMessage(_) => ReceiveItem::Proposal,
        }
    }

    // ---- fn 7: settle ---------------------------------------------------------------------------

    /// `settle` (fn 7): re-processes the winner with persistence, **re-runs CO-2 on it** (a winner
    /// whose verdict is not `Ok` is `INVALID_COMMIT(reason)` and nothing is merged: CO-3 chooses
    /// among valid candidates only, and the settle enforces it natively), merges it (or merges the
    /// own pending commit), and returns the new epoch's keys and, when the commit rotates (§6.5),
    /// the next generation's values (`generation + 1`, opened at the new epoch). A commit that
    /// removes the member, or replaces its leaf, settles too: the member learns it is `Removed` or
    /// `Replaced` (§6.6), with no epoch keys (review of S2a, §19.31).
    pub fn settle(
        &self,
        ch: &ChannelHandle,
        rows: &dyn RowSource,
        winner: Winner<'_>,
        generation: u32,
        day: u32,
    ) -> MlsResult<SettleOut> {
        let channel_id = ch.channel_id;
        let l = self.load(&channel_id, rows, day)?;
        let mut g = Self::group(&l)?;
        let pre = PreState::of_commit(&g)?;
        let floor = seal::floor(pre.context.size_class).ok_or(MlsError::new(Code::StateCorrupt))?;
        let me = ch.pseudonym();
        let (aad, added, removed, rotates, standing) = match winner {
            Winner::Foreign(bytes) => {
                let m = MlsMessageIn::tls_deserialize_exact(bytes)
                    .map_err(|_| MlsError::commit(CommitReason::Refused))?;
                let pm = m
                    .try_into_protocol_message()
                    .map_err(|_| MlsError::commit(CommitReason::Refused))?;
                let processed = g
                    .process_message(&l.p, pm)
                    .map_err(|e| check::map_process_error(&e))?;
                let aad_bytes = processed.aad().to_vec();
                let sender = processed.sender().clone();
                let staged = match processed.into_content() {
                    ProcessedMessageContent::StagedCommitMessage(sc) => *sc,
                    _ => return Err(MlsError::commit(CommitReason::Refused)),
                };
                let summary = check::summarize(
                    &self.crypto,
                    &channel_id,
                    &pre,
                    &sender,
                    &aad_bytes,
                    &staged,
                    bytes,
                    floor,
                )?;
                if let Err(r) = summary.verdict {
                    return Err(MlsError::commit(r));
                }
                let aad =
                    CommitAad::decode(&aad_bytes).ok_or(MlsError::commit(CommitReason::Aad))?;
                let (added, removed, rotates) = check::membership_change(&pre, &staged, &aad);
                let standing = if !staged.self_removed() {
                    Standing::Member
                } else if staged.add_proposals().any(|a| {
                    a.add_proposal()
                        .key_package()
                        .leaf_node()
                        .signature_key()
                        .as_slice()
                        == me
                }) {
                    Standing::Replaced
                } else {
                    Standing::Removed
                };
                g.merge_staged_commit(&l.p, staged).map_err(corrupt)?;
                (aad, added, removed, rotates, standing)
            }
            Winner::Own(bytes) => {
                let aad_bytes = own_commit_aad(bytes)?;
                let aad =
                    CommitAad::decode(&aad_bytes).ok_or(MlsError::commit(CommitReason::Aad))?;
                let (added, removed, rotates) = {
                    let sc = g
                        .pending_commit()
                        .ok_or(MlsError::new(Code::StateCorrupt))?;
                    let summary = check::summarize(
                        &self.crypto,
                        &channel_id,
                        &pre,
                        &Sender::Member(g.own_leaf_index()),
                        &aad_bytes,
                        sc,
                        bytes,
                        floor,
                    )?;
                    if let Err(r) = summary.verdict {
                        return Err(MlsError::commit(r));
                    }
                    check::membership_change(&pre, sc, &aad)
                };
                g.merge_pending_commit(&l.p).map_err(corrupt)?;
                // A commit never removes its own committer (RFC 9420 §12.2).
                (aad, added, removed, rotates, Standing::Member)
            }
        };
        let (epoch, rotated) = if standing == Standing::Member {
            let epoch = self.epoch_keys(&g, &channel_id)?;
            let rotated = if rotates {
                let gs = self.export_generation_secret(&g, &channel_id)?;
                let next = generation
                    .checked_add(1)
                    .ok_or(MlsError::new(Code::InvalidPolicy))?;
                Some(self.generation_values(&channel_id, next, g.epoch().as_u64(), &gs)?)
            } else {
                None
            };
            (Some(epoch), rotated)
        } else {
            (None, None)
        };
        Ok(SettleOut {
            changes: self.finish(&l)?,
            epoch,
            commit_minute: aad.commit_minute,
            rotates,
            rotated,
            added,
            removed,
            standing,
        })
    }

    // ---- fn 8: clearOwn -------------------------------------------------------------------------

    pub fn clear_own(
        &self,
        ch: &ChannelHandle,
        rows: &dyn RowSource,
        day: u32,
    ) -> MlsResult<ChangeSet> {
        let l = self.load(&ch.channel_id, rows, day)?;
        let mut g = Self::group(&l)?;
        g.clear_pending_commit(l.p.storage()).map_err(corrupt)?;
        self.finish(&l)
    }

    // ---- fn 9: commit ---------------------------------------------------------------------------

    /// `commit` (fn 9): the proposals by value, `GhostCommitAad` through `set_aad`, a forced path
    /// whose leaf carries a fresh `box_pk` and `refresh_epoch` = the current epoch (§19.5), the
    /// bootstrap in the Welcome's GroupInfo and no exported GroupInfo (S0-9). Items that do not fit
    /// `C(floor)` are deferred in §5.7's order (S0-16); a commit of one proposal (or none, with a
    /// path) that still does not fit is `NO_FIT`. The committer validates its own pending commit
    /// with CO-2 before returning it.
    ///
    /// **Bounded (review of S2b).** A request carries at most [`COMMIT_JOINERS_MAX`] Adds and swaps
    /// together, and each Remove names a distinct member (`INVALID_POLICY` otherwise), and the
    /// deferral of Adds and swaps bisects (see [`defer_to_fit`]): S2b's first version rebuilt the
    /// whole commit once per deferred item, under the registry's one lock, so a 64-Add pass of the
    /// small class cost 60 builds (1.8 s on the review's host) and kept 5.
    pub fn commit(
        &self,
        ch: &ChannelHandle,
        rows: &dyn RowSource,
        req: &CommitRequest,
        day: u32,
    ) -> MlsResult<CommitOut> {
        if req.adds.len() + req.swaps.len() > COMMIT_JOINERS_MAX {
            return Err(MlsError::new(Code::InvalidPolicy));
        }
        let channel_id = ch.channel_id;
        let l = self.load(&channel_id, rows, day)?;
        let g0 = Self::group(&l)?;
        if g0.pending_commit().is_some() {
            return Err(MlsError::new(Code::PendingCommit));
        }
        let pre = PreState::of_commit(&g0)?;
        // The size rule is the class floor of the pre-commit context, the one every member applies
        // (CO-2, §5.7): a caller's other floor is refused before anything uses it (review M2; a floor
        // below 68 bytes used to underflow `capacity`).
        let floor = seal::floor(pre.context.size_class).ok_or(MlsError::new(Code::StateCorrupt))?;
        if req.floor != floor {
            return Err(MlsError::new(Code::InvalidPolicy));
        }
        let me = ch.pseudonym();
        let rank = pre.context.rank_of(&me);
        if req.rotate && rank == 255 {
            return Err(MlsError::new(Code::InvalidPolicy));
        }
        let commit_day = req.commit_minute / 1440;
        // The inputs, checked as CO-2 (A) will check them (the sponsor of an admission must not
        // be a pseudonym this commit removes).
        let mut removes: Vec<(LeafNodeIndex, [u8; 32])> = Vec::with_capacity(req.removes.len());
        for key in &req.removes {
            let leaf = pre.leaf_of(key).ok_or(MlsError::new(Code::InvalidPolicy))?;
            // A member is removed once: the Removes are bounded by the roster (review of S2b).
            if *key == me || removes.iter().any(|(_, k)| k == key) {
                return Err(MlsError::new(Code::InvalidPolicy));
            }
            removes.push((leaf, *key));
        }
        let removed_keys: Vec<[u8; 32]> = removes.iter().map(|r| r.1).collect();
        let mut adds = Vec::with_capacity(req.adds.len());
        for (i, (bytes, ev)) in req.adds.iter().enumerate() {
            let kp = canonical::parse_key_package(&self.crypto, bytes, Some(&channel_id))
                .map_err(|_| MlsError::at(Code::InvalidKeyPackage, i as u16))?;
            if kp.bind.purpose != Purpose::Join
                || !check::in_window(kp.bind.day, commit_day)
                || pre.is_member(&kp.pseudonym)
            {
                return Err(MlsError::at(Code::InvalidKeyPackage, i as u16));
            }
            check::verify_admit(&channel_id, &pre, &removed_keys, ev, &kp)
                .map_err(|_| MlsError::at(Code::InvalidEvidence, i as u16))?;
            adds.push((kp, ev.clone()));
        }
        let mut swaps = Vec::with_capacity(req.swaps.len());
        for (i, (key, bytes, ev)) in req.swaps.iter().enumerate() {
            let at = (req.adds.len() + i) as u16;
            let kp = canonical::parse_key_package(&self.crypto, bytes, Some(&channel_id))
                .map_err(|_| MlsError::at(Code::InvalidKeyPackage, at))?;
            if kp.pseudonym != *key || !check::in_window(kp.bind.day, commit_day) {
                return Err(MlsError::at(Code::InvalidKeyPackage, at));
            }
            let leaf = pre.leaf_of(key).ok_or(MlsError::new(Code::InvalidPolicy))?;
            check::verify_swap(&channel_id, &pre, key, &removed_keys, ev, &kp)
                .map_err(|_| MlsError::at(Code::InvalidEvidence, at))?;
            swaps.push((leaf, kp, ev.clone()));
        }
        if let Some(c) = &req.context {
            if c.channel_id != channel_id {
                return Err(MlsError::new(Code::InvalidPolicy));
            }
        }
        let gsec = GenerationSecret::from_bytes(*self.unwrap_key(
            KeyClass::Generation,
            &channel_id,
            &req.g_env,
        )?);
        let cap = seal::capacity(floor);
        let base = l.p.storage.checkpoint();
        // One build of a plan: its outputs when the commit fits `C(floor)`, with the commit staged
        // in `l`'s storage; `None`, with the storage restored, when it does not.
        let attempt = |plan: &Plan| -> MlsResult<Option<Built>> {
            let effective = plan.effective_context(&pre.context, req.context.as_ref(), &removes);
            if let Some(c) = &effective {
                c.check_password_change(&pre.context, rank)
                    .map_err(|_| MlsError::new(Code::InvalidPolicy))?;
            }
            let rotates = req.rotate
                || !plan.removes.is_empty()
                || plan
                    .swaps
                    .iter()
                    .any(|&i| matches!(swaps[i].2, SwapEvidence::Restore(_)))
                || effective
                    .as_ref()
                    .is_some_and(|c| c.size_class != pre.context.size_class);
            let aad = CommitAad {
                commit_minute: req.commit_minute,
                rotate: req.rotate,
                admits: plan.adds.iter().map(|&i| adds[i].1.clone()).collect(),
                swaps: plan.swaps.iter().map(|&i| swaps[i].2.clone()).collect(),
            };
            let (box_pk, box_env) = self.box_key(&channel_id)?;
            let mut g = Self::group(&l)?;
            let epoch = g.epoch().as_u64();
            g.set_aad(aad.encode());
            let mut b = g
                .commit_builder()
                .consume_proposal_store(false)
                .force_self_update(true)
                .propose_removals(
                    plan.removes
                        .iter()
                        .map(|&i| removes[i].0)
                        .chain(plan.swaps.iter().map(|&i| swaps[i].0)),
                )
                .propose_adds(
                    plan.adds
                        .iter()
                        .map(|&i| adds[i].0.key_package.clone())
                        .chain(plan.swaps.iter().map(|&i| swaps[i].1.key_package.clone())),
                );
            if let Some(c) = &effective {
                let exts = Extensions::from_vec(vec![
                    Extension::Unknown(ext::EXT_CHANNEL_CONTEXT, UnknownExtension(c.encode())),
                    canonical::required_capabilities(),
                ])
                .map_err(|_| MlsError::new(Code::InvalidPolicy))?;
                b = b
                    .propose_group_context_extensions(exts)
                    .map_err(|_| MlsError::new(Code::InvalidPolicy))?;
            }
            let params = LeafNodeParameters::builder()
                .with_capabilities(canonical::canonical_capabilities())
                .with_extensions(canonical::leaf_extensions(&GhostLeaf {
                    box_pk,
                    refresh_epoch: epoch,
                })?)
                .build();
            let mut b = b
                .leaf_node_parameters(params)
                .load_psks(l.p.storage())
                .map_err(corrupt)?;
            let joiners = plan.adds.len() + plan.swaps.len();
            if joiners > 0 {
                let boot = if rotates {
                    Bootstrap {
                        generation: req
                            .generation
                            .checked_add(1)
                            .ok_or(MlsError::new(Code::InvalidPolicy))?,
                        open_epoch: epoch + 1,
                        g: [0u8; 32],
                    }
                } else {
                    Bootstrap {
                        generation: req.generation,
                        open_epoch: req.generation_open_epoch,
                        g: *gsec.as_bytes(),
                    }
                };
                b = b
                    .create_group_info_with_extensions(vec![Extension::Unknown(
                        ext::EXT_BOOTSTRAP,
                        UnknownExtension(boot.encode()),
                    )])
                    .map_err(internal)?;
            }
            let b = b.create_group_info(false);
            let bundle = b
                .build(l.p.rand(), l.p.crypto(), &ch.signer, |_| true)
                .map_err(|_| MlsError::new(Code::InvalidPolicy))?
                .stage_commit(&l.p)
                .map_err(|_| MlsError::new(Code::InvalidPolicy))?;
            let (c, w, gi) = bundle.into_messages();
            if gi.is_some() {
                return Err(MlsError::new(Code::Internal)); // S0-9: never an exported GroupInfo
            }
            let commit = ser(&c)?;
            if commit.len() > cap {
                l.p.storage.restore(base.duplicate());
                return Ok(None);
            }
            Ok(Some(Built {
                welcome: w.map(|w| ser(&w)).transpose()?,
                commit,
                aad,
                rotates,
                box_pk,
                box_env,
            }))
        };
        // §5.7's deferral order: Adds from the end, then swaps, then the context change except the
        // drops of keys the commit removes, then Removes beyond the first (each with its drop).
        let full = Plan {
            adds: (0..adds.len()).collect(),
            swaps: (0..swaps.len()).collect(),
            removes: (0..removes.len()).collect(),
            context: if req.context.is_some() {
                ContextKept::Full
            } else {
                ContextKept::NotRequested
            },
        };
        let (plan, built) = match attempt(&full)? {
            Some(built) => (full, built),
            None => {
                // The plan of the last build, when its commit fitted and is still staged.
                let mut staged: Option<(Plan, Built)> = None;
                let plan = defer_to_fit(&full, |p| {
                    if staged.take().is_some() {
                        l.p.storage.restore(base.duplicate());
                    }
                    Ok(match attempt(p)? {
                        Some(built) => {
                            staged = Some((p.clone(), built));
                            true
                        }
                        None => false,
                    })
                })?
                .ok_or(MlsError::new(Code::NoFit))?;
                let built = match staged {
                    Some((p, built)) if p == plan => built,
                    other => {
                        if other.is_some() {
                            l.p.storage.restore(base.duplicate());
                        }
                        // A commit's size is a function of its plan alone (every key, signature and
                        // ciphertext GHOST's suite draws has a fixed length): the plan the search
                        // found fits again.
                        attempt(&plan)?.ok_or(MlsError::new(Code::Internal))?
                    }
                };
                (plan, built)
            }
        };
        // The committer's own CO-2, over its pending commit (what every member will run).
        let g2 = Self::group(&l)?;
        let pending = g2.pending_commit().ok_or(MlsError::new(Code::Internal))?;
        let summary = check::summarize(
            &self.crypto,
            &channel_id,
            &pre,
            &Sender::Member(g0.own_leaf_index()),
            &built.aad.encode(),
            pending,
            &built.commit,
            floor,
        )?;
        if let Err(r) = summary.verdict {
            return Err(MlsError::commit(r));
        }
        let joiners_refs = plan
            .adds
            .iter()
            .map(|&i| adds[i].0.kp_ref.clone())
            .chain(plan.swaps.iter().map(|&i| swaps[i].1.kp_ref.clone()))
            .collect();
        Ok(CommitOut {
            welcome: built.welcome,
            commit: built.commit,
            joiners: joiners_refs,
            kept_adds: plan.adds,
            kept_swaps: plan.swaps,
            kept_removes: plan.removes,
            context: plan.context,
            rotates: built.rotates,
            box_pk: built.box_pk,
            box_env: built.box_env,
            changes: self.finish(&l)?,
            summary: Box::new(summary),
        })
    }

    // ---- fn 10: encrypt -------------------------------------------------------------------------

    /// `encrypt` (fn 10): `ChannelOrder(sender_leaf, seq)` as the MLS AAD of exactly this message.
    /// `PENDING_COMMIT` when the own pending commit removes a leaf — a Remove, a leave, an eviction
    /// **or a swap**, whose replaced leaf (a seized device's, for a restore) could read the post
    /// (§6.3.1, CO-13, §19.13; review ML1); `NON_CANONICAL` for a content `contentDecode` refuses.
    pub fn encrypt(
        &self,
        ch: &ChannelHandle,
        rows: &dyn RowSource,
        content: &[u8],
        seq: u32,
        day: u32,
    ) -> MlsResult<EncryptOut> {
        ChannelContent::decode(content)?;
        let l = self.load(&ch.channel_id, rows, day)?;
        let mut g = Self::group(&l)?;
        if g.pending_commit()
            .is_some_and(|pc| pc.remove_proposals().next().is_some())
        {
            return Err(MlsError::new(Code::PendingCommit));
        }
        let sender_leaf = g.own_leaf_index().u32();
        g.set_aad(ChannelOrder { sender_leaf, seq }.encode());
        let m = g
            .create_message(&l.p, &ch.signer, content)
            .map_err(|_| MlsError::new(Code::StateCorrupt))?;
        Ok(EncryptOut {
            mls: ser(&m)?,
            epoch: g.epoch().as_u64(),
            sender_leaf,
            changes: self.finish(&l)?,
        })
    }

    // ---- fns 11, 12: seal, open -----------------------------------------------------------------

    fn seal_key_env(
        &self,
        class: KeyClass,
        channel_id: &[u8; 32],
        env: &[u8],
    ) -> MlsResult<SealSecret> {
        match class {
            KeyClass::Epoch => {
                let (k, epoch) = self.unwrap_epoch_key(channel_id, env)?;
                Ok(SealSecret::Epoch(EpochExport::from_bytes(*k), epoch))
            }
            KeyClass::Join | KeyClass::InviteJoin => {
                let k = self.unwrap_key(class, channel_id, env)?;
                Ok(SealSecret::Join(JoinKey::from_bytes(*k)))
            }
            _ => Err(MlsError::new(Code::InvalidPolicy)),
        }
    }

    /// `seal` (fn 11): the key comes wrapped (`K_ep` for mode 0x11, `JK_g` for 0x12 and 0x13, an
    /// invite's `JK_g` for 0x12 only); the salt from the provider's CSPRNG. A mode-0x11 `order` must
    /// name the envelope's epoch (`INVALID_POLICY` otherwise).
    #[allow(clippy::too_many_arguments)]
    pub fn seal_blob(
        &self,
        channel_id: &[u8; 32],
        key_env: &[u8],
        class: KeyClass,
        ns: &[u8; 32],
        bucket: usize,
        mode: u8,
        order: &Order,
        body: &[u8],
    ) -> MlsResult<Vec<u8>> {
        // An invitee seals its join or restore request (review of S2b, §19.36).
        if class == KeyClass::InviteJoin && mode != seal::MODE_JOIN {
            return Err(MlsError::new(Code::InvalidPolicy));
        }
        let k = self.seal_key_env(class, channel_id, key_env)?;
        seal::seal(&k.input(), ns, bucket, mode, order, body, self.random()?)
    }

    /// `open` (fn 12). A mode-0x11 blob whose MLS header is of another epoch than the envelope's is
    /// `NON_CANONICAL` (review M1: a re-sealed message of an older epoch is not one of this epoch).
    /// An invite's `JK_g` opens the invitee's Welcome blob (mode 0x13) only: a join request is read
    /// by a member, under the channel's own `JK_g` (`INVALID_POLICY`; review of S2b, §19.36).
    pub fn open_blob(
        &self,
        channel_id: &[u8; 32],
        key_env: &[u8],
        class: KeyClass,
        ns: &[u8; 32],
        mode: u8,
        blob: &[u8],
    ) -> MlsResult<seal::Opened> {
        if class == KeyClass::InviteJoin && mode != seal::MODE_WELCOME {
            return Err(MlsError::new(Code::InvalidPolicy));
        }
        let k = self.seal_key_env(class, channel_id, key_env)?;
        seal::open(&k.input(), ns, mode, blob)
    }

    // ---- fn 13: generation ----------------------------------------------------------------------

    /// `generation` (fn 13): `ns`, the per-slot READ and DEPOSIT credentials v3 and verifiers,
    /// `JK` wrapped and `R_join`. A slot named twice is `NON_CANONICAL`.
    pub fn generation(
        &self,
        channel_id: &[u8; 32],
        g_env: &[u8],
        generation: u32,
        open_epoch: u64,
        slots: &[u8],
    ) -> MlsResult<(GenerationValues, Vec<SlotCredentials>)> {
        check_slots(slots)?;
        let g = GenerationSecret::from_bytes(*self.unwrap_key(
            KeyClass::Generation,
            channel_id,
            g_env,
        )?);
        let values = self.generation_values(channel_id, generation, open_epoch, &g)?;
        let (rb, db) = (derive_read_base(&g), derive_deposit_base(&g));
        let creds = slot_credentials(&rb, &db, &values.ns, slots);
        Ok((values, creds))
    }

    // ---- fn 14: inviteBuild / inviteParse -------------------------------------------------------

    /// `inviteBuild` (fn 14, §19.28.3 corrected by §19.29.3). Reads the policy from the channel's
    /// own state: `INVALID_POLICY` when the sponsor may not invite (not a committer and
    /// `members_may_invite` clear; in a password channel only committers, Q46 (b)), or when
    /// `kdf_code` does not match flag bit 2, or when `expiry_day` is not within `[day, day + 7]`
    /// (§5.9: an invite expires at `expiry_day ≤ issue day + 7`; review of S2a, §19.31). A password
    /// invite with an empty password is `PASSWORD_REQUIRED` (`invite::build_v2`). The salt,
    /// `invite_id` and `invite_seed` come from the provider's CSPRNG; the name travels only when
    /// `carry_name` (Q29's default is not to).
    #[allow(clippy::too_many_arguments)]
    pub fn invite_build(
        &self,
        ch: &ChannelHandle,
        rows: &dyn RowSource,
        g_env: &[u8],
        generation: u32,
        expiry_day: u32,
        kdf_code: u8,
        password: Option<&InvitePassword>,
        carry_name: bool,
        day: u32,
    ) -> MlsResult<InviteOut> {
        let channel_id = ch.channel_id;
        if expiry_day < day || expiry_day > day.saturating_add(7) {
            return Err(MlsError::new(Code::InvalidPolicy));
        }
        let l = self.load(&channel_id, rows, day)?;
        let g = Self::group(&l)?;
        let ctx = Self::context_of(&g)?;
        let me = ch.pseudonym();
        let committer = ctx.rank_of(&me) != 255;
        let password_channel = ctx.flags & FLAG_PASSWORD != 0;
        let may = committer || (!password_channel && ctx.flags & FLAG_MEMBERS_MAY_INVITE != 0);
        if !may || (kdf_code >= 1) != password_channel {
            return Err(MlsError::new(Code::InvalidPolicy));
        }
        let gsec = GenerationSecret::from_bytes(*self.unwrap_key(
            KeyClass::Generation,
            &channel_id,
            g_env,
        )?);
        let fields = InviteFields {
            suite: invite::SUITE,
            size_class: ctx.size_class,
            handshake_ttl_code: ctx.timer_code,
            channel_id,
            generation,
            ns: derive_namespace(&gsec),
            read_base: derive_read_base(&gsec),
            deposit_base: derive_deposit_base(&gsec),
            join_key: derive_join_key(&gsec),
            invite_id: self.random()?,
            invite_seed: derive::InviteSeed::from_bytes(self.random()?),
            committers_digest: committers_digest(&channel_id, &ctx.committers)
                .ok_or(MlsError::new(Code::StateCorrupt))?,
            expiry_day,
            name: if carry_name {
                ctx.name.clone()
            } else {
                Vec::new()
            },
        };
        let bytes = invite::build_v2(&fields, kdf_code, password, self.random()?)?;
        let invite_pk = fields.invite_pk();
        let msg = invite::sponsor_message(&channel_id, &fields.invite_id, &invite_pk, expiry_day);
        Ok(InviteOut {
            invite: bytes,
            issued: crate::content::InviteIssued {
                invite_id: fields.invite_id,
                invite_pk,
                expiry_day,
                sponsor_sig: ch.signer.sign_raw(&msg),
                committers_digest: fields.committers_digest,
                pw_version: password_channel.then_some(ctx.pw_version),
            },
        })
    }

    // ---- fn 15: joinRequest / rejoinRequest / joinVerify ----------------------------------------

    /// `inviteParse` with a context (fn 14 as slice S2b maps it, §19.32): [`invite::parse_v2`]
    /// (its codes unchanged: `NON_CANONICAL`, `UNSUPPORTED_SUITE`, `PASSWORD_REQUIRED` without
    /// running Argon2id, `WRONG_PASSWORD`), then the invite's secrets wrapped under the state key
    /// and bound to the invite's channel — the join key in its own class, [`KeyClass::InviteJoin`]
    /// (§19.36) —, `R_join`, and the credentials of `slots` from the invite's read and deposit
    /// bases (§5.2: the invite carries `RB_g` and `DB_g`, never `G_g`). A slot named twice is
    /// `NON_CANONICAL`, before any Argon2id runs.
    pub fn invite_parse(
        &self,
        bytes: &[u8],
        password: Option<&InvitePassword>,
        slots: &[u8],
    ) -> MlsResult<ParsedInvite> {
        check_slots(slots)?;
        let (kdf_code, f) = invite::parse_v2(bytes, password)?;
        Ok(ParsedInvite {
            kdf_code,
            suite: f.suite,
            size_class: f.size_class,
            handshake_ttl_code: f.handshake_ttl_code,
            channel_id: f.channel_id,
            generation: f.generation,
            ns: f.ns,
            invite_id: f.invite_id,
            invite_pk: f.invite_pk(),
            committers_digest: f.committers_digest,
            expiry_day: f.expiry_day,
            name: f.name.clone(),
            // Class 6, not the channel's own class 3: the invite, not a member, vouches for this
            // key (review of S2b, §19.36).
            jk_env: self.wrap_key(KeyClass::InviteJoin, &f.channel_id, f.join_key.as_bytes())?,
            r_join: *derive_join_recognition(&f.join_key).as_bytes(),
            seed_env: self.wrap_key(KeyClass::Invite, &f.channel_id, f.invite_seed.as_bytes())?,
            slots: slot_credentials(&f.read_base, &f.deposit_base, &f.ns, slots),
        })
    }

    /// `joinRequest` (fn 15): the canonical KeyPackage (purpose join or restore, bound to the
    /// invite's channel) signed with the invite key.
    pub fn join_request(&self, invite: &InviteFields, key_package: &[u8]) -> MlsResult<Vec<u8>> {
        self.join_request_seeded(
            &invite.channel_id,
            &invite.invite_id,
            &invite.invite_seed,
            key_package,
        )
    }

    /// `joinRequest` as the JNI surface calls it (slice S2b, §19.32): the invite seed comes back as
    /// the envelope [`MlsContext::invite_parse`] made (`STATE_CORRUPT` when it does not open under
    /// this context's state key for this channel).
    pub fn join_request_wrapped(
        &self,
        channel_id: &[u8; 32],
        invite_id: &[u8; 16],
        seed_env: &[u8],
        key_package: &[u8],
    ) -> MlsResult<Vec<u8>> {
        let seed = derive::InviteSeed::from_bytes(*self.unwrap_key(
            KeyClass::Invite,
            channel_id,
            seed_env,
        )?);
        self.join_request_seeded(channel_id, invite_id, &seed, key_package)
    }

    fn join_request_seeded(
        &self,
        channel_id: &[u8; 32],
        invite_id: &[u8; 16],
        seed: &derive::InviteSeed,
        key_package: &[u8],
    ) -> MlsResult<Vec<u8>> {
        let kp = canonical::parse_key_package(&self.crypto, key_package, Some(channel_id))?;
        let request_type = match kp.bind.purpose {
            Purpose::Join => RequestType::Join,
            Purpose::Restore => RequestType::Restore,
            Purpose::Rejoin => return Err(MlsError::new(Code::WrongPurpose)),
        };
        let key = derive::derive_invite_signing_key(seed);
        let msg = join::invite_sig_message(channel_id, invite_id, key_package);
        JoinRequest {
            request_type,
            key_package: key_package.to_vec(),
            auth: JoinAuth::Invite {
                invite_id: *invite_id,
                invite_sig: invite::sign_sponsor(&key, &msg),
            },
        }
        .encode()
    }

    /// `rejoinRequest` (fn 15, §19.3): signed with the pseudonym key.
    #[allow(clippy::too_many_arguments)]
    pub fn rejoin_request(
        &self,
        ch: &ChannelHandle,
        generation: u32,
        day: u32,
        last_epoch: u64,
        last_hash: &[u8; 32],
        key_package: &[u8],
    ) -> MlsResult<Vec<u8>> {
        let kp = canonical::parse_key_package(&self.crypto, key_package, Some(&ch.channel_id))?;
        if kp.bind.purpose != Purpose::Rejoin || kp.pseudonym != ch.pseudonym() {
            return Err(MlsError::new(Code::WrongPurpose));
        }
        let msg = join::rejoin_sig_message(
            &ch.channel_id,
            generation,
            day,
            last_epoch,
            last_hash,
            key_package,
        );
        JoinRequest {
            request_type: RequestType::Rejoin,
            key_package: key_package.to_vec(),
            auth: JoinAuth::Rejoin {
                day,
                last_epoch,
                last_hash: *last_hash,
                rejoin_sig: ch.signer.sign_raw(&msg),
            },
        }
        .encode()
    }

    /// `joinVerify` (fn 15): the request's KeyPackage is canonical and bound to the channel with
    /// the purpose of the request type (`WRONG_PURPOSE`), and its signature verifies under the
    /// invite key (join, restore) or the member's pseudonym key (rejoin; `generation` is the
    /// namespace's the request came from). `BAD_SIGNATURE` otherwise.
    pub fn join_verify(
        &self,
        channel_id: &[u8; 32],
        body: &[u8],
        invite_pk: Option<&[u8; 32]>,
        member: Option<&[u8; 32]>,
        generation: u32,
    ) -> MlsResult<VerifiedJoin> {
        let req = JoinRequest::decode(body)?;
        let kp = canonical::parse_key_package(&self.crypto, &req.key_package, Some(channel_id))?;
        let purpose_ok = matches!(
            (req.request_type, kp.bind.purpose),
            (RequestType::Join, Purpose::Join)
                | (RequestType::Rejoin, Purpose::Rejoin)
                | (RequestType::Restore, Purpose::Restore)
        );
        if !purpose_ok {
            return Err(MlsError::new(Code::WrongPurpose));
        }
        let ok = match (&req.auth, invite_pk, member) {
            (
                JoinAuth::Invite {
                    invite_id,
                    invite_sig,
                },
                Some(pk),
                _,
            ) => invite::verify_ed25519(
                pk,
                &join::invite_sig_message(channel_id, invite_id, &req.key_package),
                invite_sig,
            ),
            (
                JoinAuth::Rejoin {
                    day,
                    last_epoch,
                    last_hash,
                    rejoin_sig,
                },
                _,
                Some(p),
            ) => {
                kp.pseudonym == *p
                    && invite::verify_ed25519(
                        p,
                        &join::rejoin_sig_message(
                            channel_id,
                            generation,
                            *day,
                            *last_epoch,
                            last_hash,
                            &req.key_package,
                        ),
                        rejoin_sig,
                    )
            }
            _ => false,
        };
        if !ok {
            return Err(MlsError::new(Code::BadSignature));
        }
        Ok(VerifiedJoin {
            request_type: req.request_type,
            key_package: kp,
            auth: req.auth,
        })
    }

    // ---- fn 18: roster --------------------------------------------------------------------------

    pub fn roster(
        &self,
        ch: &ChannelHandle,
        rows: &dyn RowSource,
        day: u32,
    ) -> MlsResult<RosterOut> {
        let l = self.load(&ch.channel_id, rows, day)?;
        let g = Self::group(&l)?;
        let context = Self::context_of(&g)?;
        let committers_digest = committers_digest(&ch.channel_id, &context.committers)
            .ok_or(MlsError::new(Code::StateCorrupt))?;
        Ok(RosterOut {
            members: Self::roster_of(&g),
            epoch: g.epoch().as_u64(),
            epoch_authenticator: g.epoch_authenticator().as_slice().to_vec(),
            // `MlsGroup::tree_hash` is test-utils only at 0.9.0; the context carries the same hash.
            tree_hash: g.public_group().group_context().tree_hash().to_vec(),
            context,
            own_leaf: g.own_leaf_index().u32(),
            committers_digest,
        })
    }

    // ---- test-only builders (MM-30 / MM-46; §19.37 F-S4-6, the Kotlin suites' test entries) -----

    /// A real MLS **Proposal** built by this member (test libraries only; F-S4-6): GHOST never
    /// proposes, so no `MlsNative` function builds one — but MM-30's killer needs a decryptable
    /// proposal a mutant could store (the engine's drop is by the header, §6.3.2). A self-update
    /// proposal (an Update of the member's own leaf, `propose_self_update`): signed and encrypted
    /// like any handshake message, so a receiver classifies it `ContentType::Proposal`. The build
    /// touches only the loaded state; nothing is persisted (value semantics, like every call).
    #[cfg(any(test, feature = "test-vectors"))]
    pub fn test_proposal(
        &self,
        ch: &ChannelHandle,
        rows: &dyn RowSource,
        day: u32,
    ) -> MlsResult<Vec<u8>> {
        let l = self.load(&ch.channel_id, rows, day)?;
        let mut g = Self::group(&l)?;
        let (box_pk, _) = self.box_key(&ch.channel_id)?;
        let params = LeafNodeParameters::builder()
            .with_capabilities(canonical::canonical_capabilities())
            .with_extensions(canonical::leaf_extensions(&GhostLeaf {
                box_pk,
                refresh_epoch: g.epoch().as_u64(),
            })?)
            .build();
        let (msg, _) = g
            .propose_self_update(&l.p, &ch.signer, params)
            .map_err(internal)?;
        ser(&msg)
    }

    /// A **commit carrying a finite-lifetime (non-canonical) KeyPackage**, built by this member
    /// (test libraries only; MM-46 and SCN-CM's lifetime cases, E-69/E-70): the KeyPackage is
    /// canonical in every field but its lifetime — `[not_before, not_after]` as given. OpenMLS
    /// validates the Add at commit-build time, so the lifetime must still hold **now**; the caller
    /// seals and stores the commit and has it received once `not_after` has passed, when every
    /// member with a correct clock refuses the Add (`LifetimeError` on OpenMLS's refusal branch,
    /// `INVALID_COMMIT(lifetime)`, §19.29.1). Returns `(key_package bytes, commit bytes)`; nothing
    /// is persisted, and the commit is not staged for the builder (it goes out as a foreign blob).
    #[cfg(any(test, feature = "test-vectors"))]
    pub fn test_finite_lifetime_commit(
        &self,
        ch: &ChannelHandle,
        rows: &dyn RowSource,
        day: u32,
        not_before: u64,
        not_after: u64,
    ) -> MlsResult<(Vec<u8>, Vec<u8>)> {
        if not_before >= not_after {
            return Err(MlsError::new(Code::InvalidPolicy));
        }
        let channel_id = ch.channel_id;
        // The attacker's KeyPackage: a fresh pseudonym, canonical everywhere but the lifetime.
        let seed = PseudonymSeed::from_bytes(self.random()?);
        let signer = PseudonymSigner::from_seed(&seed);
        let p = signer.public();
        let l = self.load(&channel_id, rows, day)?;
        let build = self.fresh(&channel_id, day);
        let (box_pk, _) = self.box_key(&channel_id)?;
        let bind = KpBind {
            channel_id,
            purpose: Purpose::Join,
            day,
        };
        let bundle = KeyPackage::builder()
            .key_package_lifetime(Lifetime::init(not_before, not_after))
            .leaf_node_capabilities(canonical::canonical_capabilities())
            .leaf_node_extensions(canonical::leaf_extensions(&GhostLeaf {
                box_pk,
                refresh_epoch: 0,
            })?)
            .key_package_extensions(
                Extensions::single(Extension::Unknown(
                    ext::EXT_KP_BIND,
                    UnknownExtension(bind.encode()),
                ))
                .map_err(internal)?,
            )
            .build(
                SUITE,
                &build.p,
                &signer,
                CredentialWithKey {
                    credential: BasicCredential::new(p.to_vec()).into(),
                    signature_key: p.to_vec().into(),
                },
            )
            .map_err(internal)?;
        let kp = bundle.key_package().clone();
        let kp_bytes = ser(&MlsMessageOut::from(kp.clone()))?;
        // The commit adding it: built like `commit`'s plan, without the Welcome machinery (the
        // commit is refused by every receiver on the lifetime; nothing is ever joined).
        let mut g = Self::group(&l)?;
        let aad = CommitAad {
            commit_minute: day * 1440,
            rotate: false,
            admits: Vec::new(),
            swaps: Vec::new(),
        };
        g.set_aad(aad.encode());
        let (path_box_pk, _) = self.box_key(&channel_id)?;
        let params = LeafNodeParameters::builder()
            .with_capabilities(canonical::canonical_capabilities())
            .with_extensions(canonical::leaf_extensions(&GhostLeaf {
                box_pk: path_box_pk,
                refresh_epoch: g.epoch().as_u64(),
            })?)
            .build();
        let bundle = g
            .commit_builder()
            .consume_proposal_store(false)
            .force_self_update(true)
            .propose_adds([kp])
            .leaf_node_parameters(params)
            .load_psks(l.p.storage())
            .map_err(corrupt)?
            .create_group_info(false)
            .build(l.p.rand(), l.p.crypto(), &ch.signer, |_| true)
            .map_err(|_| MlsError::new(Code::InvalidPolicy))?
            .stage_commit(&l.p)
            .map_err(|_| MlsError::new(Code::InvalidPolicy))?;
        let (c, _welcome, gi) = bundle.into_messages();
        // A Welcome exists (the commit has Adds); it is dropped — the commit is refused on the
        // lifetime before any joiner could use one. An exported GroupInfo never exists (S0-9).
        if gi.is_some() {
            return Err(MlsError::new(Code::Internal));
        }
        Ok((kp_bytes, ser(&c)?))
    }

    /// A **commit whose update-path leaf carries a mismatched credential** (test libraries only;
    /// MM-31 / §19.14's NEW_SIGNER): the member's own empty commit with a path — signed with its
    /// own key, so every MLS check passes and the leaf's self-signature verifies — but the new
    /// leaf's `BasicCredential` identity is [wrong_identity], not the leaf's signature key. CO-2's
    /// leaf-continuity check (`CommitReason::Continuity`) refuses it at every member. (§19.14's
    /// changed-signature-key half needs `CommitBuilder::build_with_new_signer`, whose symbol the
    /// G-M2 source scan refuses in any GHOST code — finding F-S5-9, §19.39; both halves fault at
    /// the same native site, and the mismatched credential is the half a modified client can also
    /// reach through `LeafNodeParameters` alone.) Nothing is persisted.
    #[cfg(any(test, feature = "test-vectors"))]
    pub fn test_new_signer(
        &self,
        ch: &ChannelHandle,
        rows: &dyn RowSource,
        day: u32,
        wrong_identity: [u8; 32],
    ) -> MlsResult<Vec<u8>> {
        let channel_id = ch.channel_id;
        let l = self.load(&channel_id, rows, day)?;
        let mut g = Self::group(&l)?;
        let aad = CommitAad {
            commit_minute: day * 1440,
            rotate: false,
            admits: Vec::new(),
            swaps: Vec::new(),
        };
        g.set_aad(aad.encode());
        let (path_box_pk, _) = self.box_key(&channel_id)?;
        let params = LeafNodeParameters::builder()
            .with_credential_with_key(CredentialWithKey {
                credential: BasicCredential::new(wrong_identity.to_vec()).into(),
                signature_key: ch.signer.public().to_vec().into(),
            })
            .with_capabilities(canonical::canonical_capabilities())
            .with_extensions(canonical::leaf_extensions(&GhostLeaf {
                box_pk: path_box_pk,
                refresh_epoch: g.epoch().as_u64(),
            })?)
            .build();
        let bundle = g
            .commit_builder()
            .consume_proposal_store(false)
            .force_self_update(true)
            .leaf_node_parameters(params)
            .load_psks(l.p.storage())
            .map_err(corrupt)?
            .create_group_info(false)
            .build(l.p.rand(), l.p.crypto(), &ch.signer, |_| true)
            .map_err(|_| MlsError::new(Code::InvalidPolicy))?
            .stage_commit(&l.p)
            .map_err(|_| MlsError::new(Code::InvalidPolicy))?;
        let (c, welcome, gi) = bundle.into_messages();
        // No Adds: no Welcome; an exported GroupInfo never exists (S0-9).
        if welcome.is_some() || gi.is_some() {
            return Err(MlsError::new(Code::Internal));
        }
        ser(&c)
    }

    // ---- fn 19: sweepPast -----------------------------------------------------------------------

    /// `sweepPast` (fn 19, §8.3): count-based deletion; `before_timestamp(UNIX_EPOCH)` is the
    /// constant that leaves only the count rule (no clock is read).
    pub fn sweep_past(
        &self,
        ch: &ChannelHandle,
        rows: &dyn RowSource,
        keep: usize,
        day: u32,
    ) -> MlsResult<ChangeSet> {
        let l = self.load(&ch.channel_id, rows, day)?;
        let mut g = Self::group(&l)?;
        g.delete_past_epoch_secrets(
            &l.p,
            PastEpochDeletion::before_timestamp(UNIX_EPOCH)
                .max_past_epochs(keep.min(MAX_PAST_EPOCHS)),
        )
        .map_err(corrupt)?;
        self.finish(&l)
    }

    // ---- fn 20: trialCount ----------------------------------------------------------------------

    /// `trialCount` (fn 20, CO-3, S0-17): the candidate settled in memory, every held blob (with
    /// the namespace it came from) opened under `K_ep(e + 1)` of the trial state and tried from
    /// the post-merge checkpoint; nothing is written. **Only a message of epoch e + 1 counts**: a
    /// held blob whose MLS header is of another epoch — a message of epoch e re-sealed under
    /// `K_ep(e + 1)` by any holder of that key — says nothing about who saw the candidate (review
    /// M1); and the sender is the credential OpenMLS verified the message under (H2). A candidate
    /// that removes the member leaves it nothing to open: no senders.
    pub fn trial_count(
        &self,
        ch: &ChannelHandle,
        rows: &dyn RowSource,
        candidate: Winner<'_>,
        held: &[([u8; 32], Vec<u8>)],
        day: u32,
    ) -> MlsResult<TrialOut> {
        if held.len() > TRIAL_HELD_MAX {
            return Err(MlsError::new(Code::InvalidPolicy));
        }
        let channel_id = ch.channel_id;
        let l = self.load(&channel_id, rows, day)?;
        let mut g = Self::group(&l)?;
        let pre = PreState::of(&g)?;
        let committer = match candidate {
            Winner::Foreign(bytes) => {
                let m = MlsMessageIn::tls_deserialize_exact(bytes)
                    .map_err(|_| MlsError::commit(CommitReason::Refused))?;
                let pm = m
                    .try_into_protocol_message()
                    .map_err(|_| MlsError::commit(CommitReason::Refused))?;
                let processed = g
                    .process_message(&l.p, pm)
                    .map_err(|e| check::map_process_error(&e))?;
                let Sender::Member(idx) = processed.sender().clone() else {
                    return Err(MlsError::commit(CommitReason::NotAMember));
                };
                let key = pre
                    .key_of(idx.u32())
                    .ok_or(MlsError::commit(CommitReason::NotAMember))?;
                match processed.into_content() {
                    ProcessedMessageContent::StagedCommitMessage(sc) => {
                        g.merge_staged_commit(&l.p, *sc).map_err(corrupt)?
                    }
                    _ => return Err(MlsError::commit(CommitReason::Refused)),
                }
                key
            }
            Winner::Own(_) => {
                g.merge_pending_commit(&l.p).map_err(corrupt)?;
                ch.pseudonym()
            }
        };
        if !g.is_active() {
            // The candidate removes the member: nothing opens under a state it no longer has.
            let _ = l.p.storage.take_plain_changes();
            return Ok(TrialOut {
                committer,
                senders: Vec::new(),
            });
        }
        let k = self.export_epoch_key(&g, &channel_id)?;
        let trial_epoch = g.epoch().as_u64();
        let after = l.p.storage.checkpoint();
        let me = ch.pseudonym();
        let mut senders: Vec<[u8; 32]> = Vec::new();
        for (ns, blob) in held {
            l.p.storage.restore(after.duplicate());
            let key = SealKeyInput::Epoch {
                key: &k,
                epoch: trial_epoch,
            };
            // `open` refuses a header of another epoch than the key's (M1).
            let Ok(opened) = seal::open(&key, ns, seal::MODE_EPOCH, blob) else {
                continue;
            };
            let Ok(mut tg) = Self::group(&l) else {
                continue;
            };
            let Ok(m) = MlsMessageIn::tls_deserialize_exact(&opened.body) else {
                continue;
            };
            let Ok(pm) = m.try_into_protocol_message() else {
                continue;
            };
            if pm.epoch().as_u64() != trial_epoch {
                continue;
            }
            if let Ok(p) = tg.process_message(&l.p, pm) {
                if let Some(key) = canonical::basic_identity(p.credential()) {
                    if key != me && !senders.contains(&key) {
                        senders.push(key);
                    }
                }
            }
        }
        // Nothing of the trial is written.
        let _ = l.p.storage.take_plain_changes();
        Ok(TrialOut { committer, senders })
    }
}

enum SealSecret {
    Epoch(EpochExport, u64),
    Join(JoinKey),
}

impl SealSecret {
    fn input(&self) -> SealKeyInput<'_> {
        match self {
            SealSecret::Epoch(key, epoch) => SealKeyInput::Epoch { key, epoch: *epoch },
            SealSecret::Join(k) => SealKeyInput::Join(k),
        }
    }
}

/// The `GhostCommitAad` of an own commit, read from its PrivateMessage without decryption.
fn own_commit_aad(bytes: &[u8]) -> MlsResult<Vec<u8>> {
    let m = MlsMessageIn::tls_deserialize_exact(bytes)
        .map_err(|_| MlsError::new(Code::NonCanonical))?;
    match m.extract() {
        MlsMessageBodyIn::PrivateMessage(pm) if pm.content_type() == ContentType::Commit => {
            Ok(pm.aad().to_vec())
        }
        _ => Err(MlsError::new(Code::NonCanonical)),
    }
}

/// One build of a commit whose body fits the floor (fn 9): what `commit` returns of it.
struct Built {
    commit: Vec<u8>,
    welcome: Option<Vec<u8>>,
    aad: CommitAad,
    rotates: bool,
    box_pk: [u8; 32],
    box_env: Vec<u8>,
}

/// The deferral state of a commit (§5.7, S0-16).
#[derive(Clone, PartialEq, Eq)]
struct Plan {
    adds: Vec<usize>,
    swaps: Vec<usize>,
    removes: Vec<usize>,
    context: ContextKept,
}

/// The plan §5.7's deferral reaches from `full`, whose commit does not fit: the first plan of the
/// order — Adds from the end, then swaps, then the context change (its drops of removed keys
/// kept), then Removes beyond the first — whose commit fits, or `None` (`NO_FIT`). `fits` builds a
/// plan and answers whether its commit fits `C(floor)`.
///
/// **Adds and swaps are bisected** (review of S2b): deferring one never makes a commit larger — each
/// is a proposal by value of a canonical KeyPackage (395 bytes, S0-4) with fixed-size evidence in
/// the AAD, and RFC 9420 §12.4.2 encrypts no path secret to a joiner (a swap's Remove can only add
/// path ciphertexts, which go with it) — so "the first fitting plan" of the one-at-a-time order is
/// the longest prefix that fits, found in ⌈log₂(n + 1)⌉ builds where the order took up to n. The
/// context change is one step, and the Removes stay one at a time: a Remove blanks a direct path,
/// so deferring one can make a commit larger as well as smaller; they are bounded by the roster.
fn defer_to_fit(
    full: &Plan,
    mut fits: impl FnMut(&Plan) -> MlsResult<bool>,
) -> MlsResult<Option<Plan>> {
    let mut plan = full.clone();
    if !plan.adds.is_empty() {
        match longest_fitting(plan.adds.len(), |k| fits(&plan.with_adds(k)))? {
            Some(k) => {
                plan.adds.truncate(k);
                return Ok(Some(plan));
            }
            None => plan.adds.clear(),
        }
    }
    if !plan.swaps.is_empty() {
        match longest_fitting(plan.swaps.len(), |k| fits(&plan.with_swaps(k)))? {
            Some(k) => {
                plan.swaps.truncate(k);
                return Ok(Some(plan));
            }
            None => plan.swaps.clear(),
        }
    }
    while plan.defer_one() {
        if fits(&plan)? {
            return Ok(Some(plan));
        }
    }
    Ok(None)
}

/// The largest `k < n` with `fits(k)`, for a `fits` that holds up to some point and fails after it
/// (`fits(n)` is known to fail), or `None` when even `fits(0)` fails: a bisection, at most
/// ⌈log₂(n + 1)⌉ calls, never with `k ≥ n`.
fn longest_fitting(
    n: usize,
    mut fits: impl FnMut(usize) -> MlsResult<bool>,
) -> MlsResult<Option<usize>> {
    // Every k ≥ `above` fails; every k ≤ `best` fits.
    let (mut best, mut above): (Option<usize>, usize) = (None, n);
    loop {
        let from = best.map_or(0, |b| b + 1);
        if from >= above {
            return Ok(best);
        }
        let mid = from + (above - from) / 2;
        if fits(mid)? {
            best = Some(mid);
        } else {
            above = mid;
        }
    }
}

impl Plan {
    /// The plan with only the first `k` of its Adds.
    fn with_adds(&self, k: usize) -> Plan {
        Plan {
            adds: self.adds[..k].to_vec(),
            ..self.clone()
        }
    }

    /// The plan with only the first `k` of its swaps.
    fn with_swaps(&self, k: usize) -> Plan {
        Plan {
            swaps: self.swaps[..k].to_vec(),
            ..self.clone()
        }
    }

    /// Defers the next item in §5.7's order; `false` when nothing more may be deferred.
    fn defer_one(&mut self) -> bool {
        if self.adds.pop().is_some() || self.swaps.pop().is_some() {
            return true;
        }
        if self.context == ContextKept::Full {
            self.context = ContextKept::DropsOnly;
            return true;
        }
        if self.removes.len() > 1 {
            self.removes.pop();
            return true;
        }
        false
    }

    /// The context the commit proposes: the requested one (Full), or the previous one with the
    /// keys of the pseudonyms it removes dropped from `committers` and `funders` (a Remove and the
    /// drop of its key are one unit; also when no change was requested), or none.
    fn effective_context(
        &self,
        prev: &ChannelContext,
        requested: Option<&ChannelContext>,
        removes: &[(LeafNodeIndex, [u8; 32])],
    ) -> Option<ChannelContext> {
        if let (ContextKept::Full, Some(c)) = (self.context, requested) {
            return Some(c.clone());
        }
        let gone: Vec<[u8; 32]> = self.removes.iter().map(|&i| removes[i].1).collect();
        let mut c = prev.clone();
        c.committers.retain(|k| !gone.contains(k));
        c.funders.retain(|k| !gone.contains(k));
        (c != *prev).then_some(c)
    }
}

/// A `slots` argument (fn 13, fn 14): each relay slot at most once (`NON_CANONICAL`), so a reply
/// carries at most 256 slots' credentials. The review of S2b turned 64 KiB of slots into a
/// 15 MB reply; the relay set itself has no fixed size (a reader lists the union of the sets
/// across a slot-table change, §19.23), so the bound is the slot byte's.
fn check_slots(slots: &[u8]) -> MlsResult<()> {
    let mut seen = [false; 256];
    for &s in slots {
        if std::mem::replace(&mut seen[usize::from(s)], true) {
            return Err(MlsError::new(Code::NonCanonical));
        }
    }
    Ok(())
}

/// The READ and DEPOSIT credentials v3 and verifiers of `slots` (§5.2), from a generation's bases:
/// a member's (`generation`, fn 13) or an invitee's (`invite_parse`, fn 14).
fn slot_credentials(
    rb: &derive::ReadBase,
    db: &derive::DepositBase,
    ns: &[u8; 32],
    slots: &[u8],
) -> Vec<SlotCredentials> {
    slots
        .iter()
        .map(|&s| {
            let rs = Zeroizing::new(derive_read_secret(rb, s));
            let ds = Zeroizing::new(derive_deposit_secret(db, s));
            SlotCredentials {
                slot: s,
                read_credential: derive::credential_v3(CredentialKind::Read, s, ns, &rs),
                read_verifier: derive::credential_verifier(CredentialKind::Read, s, ns, &rs),
                deposit_credential: derive::credential_v3(CredentialKind::Deposit, s, ns, &ds),
                deposit_verifier: derive::credential_verifier(CredentialKind::Deposit, s, ns, &ds),
            }
        })
        .collect()
}

/// The digest of an MLS message (a candidate's hash, CO-3).
pub fn message_hash(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// The leaf facts of the own leaf (tests).
pub fn leaf_facts(leaf: &LeafNode) -> Option<LeafFacts> {
    canonical::check_leaf(leaf).ok()
}

/// `Scope` is part of the change-set API.
pub type RowScope = Scope;

#[cfg(test)]
mod tests {
    use super::*;

    /// ⌈log₂(n + 1)⌉, the bisection's bound.
    fn bits(n: usize) -> usize {
        (usize::BITS - n.leading_zeros()) as usize
    }

    /// The bisection of §5.7's deferral (review of S2b): for every count n up to the request bound
    /// and every point t where a monotone fit stops holding, `longest_fitting` answers t − 1 (none
    /// when nothing fits), never probes a k ≥ n, and probes at most ⌈log₂(n + 1)⌉ times — where
    /// S2b's first version built the commit once per deferred item, up to n times.
    #[test]
    fn the_deferral_bisects_a_monotone_fit() {
        for n in 1..=COMMIT_JOINERS_MAX {
            for t in 0..=n {
                let mut probes = 0;
                let got = longest_fitting(n, |k| {
                    assert!(k < n, "probed {k} of {n}");
                    probes += 1;
                    Ok(k < t)
                })
                .expect("no error");
                assert_eq!(got, t.checked_sub(1), "n {n}, t {t}");
                assert!(probes <= bits(n), "n {n}, t {t}: {probes} probes");
            }
        }
        assert_eq!(bits(64), 7);
        // An error of a build is the call's.
        assert_eq!(
            longest_fitting(8, |_| Err(MlsError::new(Code::InvalidPolicy))),
            Err(MlsError::new(Code::InvalidPolicy))
        );
    }

    fn plan(adds: usize, swaps: usize, removes: usize, context: ContextKept) -> Plan {
        Plan {
            adds: (0..adds).collect(),
            swaps: (0..swaps).collect(),
            removes: (0..removes).collect(),
            context,
        }
    }

    /// The one-at-a-time order of S0-16 (S2b's first version): the reference the search must agree
    /// with whenever deferring an Add or a swap never makes a commit larger.
    fn one_at_a_time(full: &Plan, fits: &dyn Fn(&Plan) -> bool) -> Option<Plan> {
        let mut p = full.clone();
        while p.defer_one() {
            if fits(&p) {
                return Some(p);
            }
        }
        None
    }

    /// `defer_to_fit` reaches the plan the one-at-a-time order reaches — Adds from the end, then
    /// swaps, then the context change, then Removes beyond the first — for fits that stop at every
    /// possible point of that order, in a bounded number of builds; and `None` when nothing fits.
    #[test]
    fn the_deferral_reaches_the_plan_of_the_one_at_a_time_order() {
        let full = plan(10, 3, 3, ContextKept::Full);
        // The order's plans, from the full one to the last; a "fits" that holds from the i-th on
        // (every plan of the order is smaller than the one before it, here by construction).
        let mut order = vec![full.clone()];
        let mut p = full.clone();
        while p.defer_one() {
            order.push(p.clone());
        }
        assert_eq!(order.len(), 1 + 10 + 3 + 1 + 2);
        let size = |q: &Plan| -> usize {
            q.adds.len() * 1000
                + q.swaps.len() * 100
                + usize::from(q.context == ContextKept::Full) * 10
                + q.removes.len()
        };
        for first in 1..=order.len() {
            let limit = order.get(first).map_or(0, size);
            let fits = |q: &Plan| order.len() > first && size(q) <= limit;
            let expected = one_at_a_time(&full, &fits);
            let mut builds = 0;
            let got = defer_to_fit(&full, |q| {
                builds += 1;
                Ok(fits(q))
            })
            .expect("no error");
            assert!(got == expected, "stop {first}");
            assert!(
                builds <= bits(10) + bits(3) + 1 + 2,
                "stop {first}: {builds} builds"
            );
        }
    }
}
