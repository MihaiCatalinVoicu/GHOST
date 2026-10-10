//! The closed JNI surface `org.ghost.crypto.bridge.MlsNative` (design §10.2, gate G-M6; slice S2b).
//!
//! **Shape.** Every function is `static native`, takes byte arrays, ints and longs, and returns
//! **one** byte array `code(1) ‖ field*`, which Kotlin's `MlsResult` decodes. No function performs
//! I/O, reads a clock (a `day` or a minute is always an argument), logs, or keeps state between
//! calls other than the context handle and the channels opened on it; none throws. A Rust panic is
//! caught under a silent panic hook installed once per process and returned as [`Code::Internal`]
//! — the default hook prints the panic message and its location to stderr, which the no-logging
//! rule forbids (T3), and `hpke-rs/hazmat` makes the provider's `Debug` print secrets (§19.30
//! F-3), so no panic payload is ever formatted.
//!
//! **The wire (§10.2: "`code(1) ‖ TLV fields`").** A field is `tag(1) ‖ len(u32_be) ‖ value`
//! ([`Field`]). A **record** — a change, a row, a roster member, a receive item, a commit summary,
//! a context — is a field whose value is itself a field list; a **list** is its tag repeated, in
//! order, and only the tags [`Field::repeatable`] names may repeat. Arguments that carry lists or
//! records (`rows`, a batch of messages, a policy, a commit request, a content) use the same
//! encoding, and an argument that does not decode strictly — an unknown tag, a repeated scalar, a
//! length past the end, a missing field — is [`Code::NonCanonical`]. An error reply is the code
//! alone, or the code and one detail field: [`Field::Reason`] for `INVALID_COMMIT(reason)`,
//! [`Field::Index`] for `INVALID_KEYPACKAGE(index)` and `INVALID_EVIDENCE(index)`.
//!
//! **Value state (§3.4).** Every secret Kotlin stores or passes back crosses wrapped under the
//! context's state key: the rows (`mls_kv`, `mls_global_kv`), the key envelopes (`K_ep`, `G_g`,
//! `JK_g`, the box keys, an invite's seed). An envelope that does not open is
//! [`Code::StateCorrupt`]; nothing is cached across calls. What Kotlin holds in clear is what
//! §3.4 and CS-S6 let it hold: recognition keys, namespaces, bearer credentials it presents, and
//! the content of posts.
//!
//! **The registry.** A handle names one context — the crypto provider and the state key — behind
//! a pointer (Phase 9 review CRY-P9-02: a registry that held contexts by value left their secrets
//! in the hash table's buckets after `ctxClose`) with its own lock (review of S2b: calls on
//! different contexts never wait for each other), and each channel opened on it holds its
//! pseudonym signer behind a pointer too. `ctxClose` and `channelClose` drop them in place, which
//! runs every key's `ZeroizeOnDrop` (the state key, the pseudonym seed's signing key, the
//! provider's HMAC-DRBG state) before the allocation is freed. A closed or foreign handle is
//! [`Code::CryptoUnavailable`], and so is a channel not open on the handle for the thirteen
//! functions that run on an open channel (its signer or its MLS state); `seal`, `open`,
//! `generation`, `inviteParse`, `joinRequest` and `joinVerify` take envelopes bound to a channel id
//! and need no open channel. The native state a call needs is not there (a lock or a wipe closed
//! it), never a crash.
//!
//! **The closed list.** [`CLOSED_LIST`] is §10.2's table; G-M6 checks both directions — no export
//! outside the list, every entry marked [`Availability::Exported`] exported by every library it
//! reads. Function 16 (`revealSeal`/`revealOpen`, slice S9) is exported since S9; its `dmHandle`
//! argument names a DM context of the same process (the identity key never crosses to Kotlin).

use std::collections::HashMap;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Once, OnceLock, PoisonError};

use jni::objects::{JByteArray, JClass};
use jni::sys::{jbyteArray, jint, jlong};
use jni::JNIEnv;
use zeroize::{Zeroize, Zeroizing};

use crate::canonical::LeafFacts;
use crate::check::{AddSummary, CommitSummary, RemoveSummary, SwapKind, SwapSummary};
use crate::content::{Body, ChannelContent, InviteIssued};
use crate::derive::{InvitePassword, PseudonymSeed, StateKey};
use crate::ext::{AdmitEvidence, ChannelContext, CommitAad, KpBind, Purpose, SwapEvidence};
use crate::group::{
    Anchor, ChannelHandle, CommitRequest, ContextKept, EpochKeys, GenerationValues, KeyClass,
    MlsContext, ReceiveItem, RosterEntry, SlotCredentials, Standing, Winner,
};
use crate::join::{JoinAuth, RequestType, WelcomeBlob};
use crate::kv::{ChangeSet, Scope, WrappedRow, WrappedRows};
use crate::result::{Code, Detail, MlsError, MlsResult};
use crate::seal::{EpochContent, Order};

/// Whether a function of the closed list is exported by the current build.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Availability {
    /// Exported from `libghost_client_net.so` today.
    Exported,
    /// On the closed list, delivered by a later slice; nothing may export it before then.
    Declared(&'static str),
}

/// The closed list of §10.2: `(function number, name, availability)`. A name that appears twice in
/// one row of the design's table (`ctxOpen`/`ctxClose`) is one entry each.
pub const CLOSED_LIST: &[(u8, &str, Availability)] = &[
    (1, "ctxOpen", Availability::Exported),
    (1, "ctxClose", Availability::Exported),
    (2, "channelOpen", Availability::Exported),
    (2, "channelClose", Availability::Exported),
    (3, "groupCreate", Availability::Exported),
    (4, "keyPackage", Availability::Exported),
    (5, "welcomeJoin", Availability::Exported),
    (6, "receive", Availability::Exported),
    (7, "settle", Availability::Exported),
    (8, "clearOwn", Availability::Exported),
    (9, "commit", Availability::Exported),
    (10, "encrypt", Availability::Exported),
    (11, "seal", Availability::Exported),
    (12, "open", Availability::Exported),
    (13, "generation", Availability::Exported),
    (14, "inviteBuild", Availability::Exported),
    (14, "inviteParse", Availability::Exported),
    (15, "joinRequest", Availability::Exported),
    (15, "rejoinRequest", Availability::Exported),
    (15, "joinVerify", Availability::Exported),
    // Function 16 is the reveal of §6.9 and §19.17 (HPKE to the per-leaf box keys, the card
    // through the DM context's `dmHandle`): slice S9. The identity-key signature and the strict
    // verification of both signatures and the card are `ghost-client-dm`'s (ADR-35's X-21 rule);
    // `dmHandle` names a DM context on the same process.
    (16, "revealSeal", Availability::Exported),
    (16, "revealOpen", Availability::Exported),
    (17, "contentEncode", Availability::Exported),
    (17, "contentDecode", Availability::Exported),
    (18, "roster", Availability::Exported),
    (19, "sweepPast", Availability::Exported),
    (20, "trialCount", Availability::Exported),
];

/// The codes each exported function can return besides [`Code::Ok`]: §10.2's protocol codes and
/// the codes the JNI layer itself produces — [`Code::NonCanonical`] for an argument of the wrong
/// width or form (a negative day, a malformed field list, a slot named twice), [`Code::InvalidKey`]
/// for a key input of the wrong length, [`Code::CryptoUnavailable`] for a closed or foreign handle
/// or, where the function runs on an open channel, a channel not open on it,
/// [`Code::StateCorrupt`] for a row or an envelope that does not open. A `receive`
/// item's own code travels inside its record (`ITEM`), not here. [`Code::Internal`] is not listed:
/// it is a caught panic, it belongs to every function, and it is the one outcome the typed facade
/// throws on. `MlsResultCodesTest` reads this table and checks the facade's arms against it.
pub const FUNCTION_CODES: &[(&str, &[Code])] = &[
    ("ctxOpen", &[Code::InvalidKey, Code::CryptoUnavailable]),
    ("ctxClose", &[Code::CryptoUnavailable]),
    (
        "channelOpen",
        &[
            Code::NonCanonical,
            Code::InvalidKey,
            Code::CryptoUnavailable,
        ],
    ),
    (
        "channelClose",
        &[Code::NonCanonical, Code::CryptoUnavailable],
    ),
    (
        "groupCreate",
        &[
            Code::NonCanonical,
            Code::InvalidPolicy,
            Code::CryptoUnavailable,
        ],
    ),
    ("keyPackage", &[Code::NonCanonical, Code::CryptoUnavailable]),
    (
        "welcomeJoin",
        &[
            Code::NonCanonical,
            Code::NotForMe,
            Code::InvalidWelcome,
            Code::InvalidBootstrap,
            Code::InvalidPolicy,
            Code::StateCorrupt,
            Code::CryptoUnavailable,
        ],
    ),
    (
        "receive",
        &[
            Code::NonCanonical,
            Code::InvalidPolicy,
            Code::StateCorrupt,
            Code::CryptoUnavailable,
        ],
    ),
    (
        "settle",
        &[
            Code::NonCanonical,
            Code::InvalidCommit,
            Code::InvalidPolicy,
            Code::WrongEpoch,
            Code::StateCorrupt,
            Code::CryptoUnavailable,
        ],
    ),
    (
        "clearOwn",
        &[
            Code::NonCanonical,
            Code::StateCorrupt,
            Code::CryptoUnavailable,
        ],
    ),
    (
        "commit",
        &[
            Code::NonCanonical,
            Code::NoFit,
            Code::InvalidKeyPackage,
            Code::InvalidEvidence,
            Code::InvalidPolicy,
            Code::InvalidCommit,
            Code::PendingCommit,
            Code::StateCorrupt,
            Code::CryptoUnavailable,
        ],
    ),
    (
        "encrypt",
        &[
            Code::NonCanonical,
            Code::PendingCommit,
            Code::StateCorrupt,
            Code::CryptoUnavailable,
        ],
    ),
    (
        "seal",
        &[
            Code::NonCanonical,
            Code::NoFit,
            Code::InvalidPolicy,
            Code::StateCorrupt,
            Code::CryptoUnavailable,
        ],
    ),
    (
        "open",
        &[
            Code::NonCanonical,
            Code::NotOpen,
            Code::InvalidPolicy,
            Code::StateCorrupt,
            Code::CryptoUnavailable,
        ],
    ),
    (
        "generation",
        &[
            Code::NonCanonical,
            Code::StateCorrupt,
            Code::CryptoUnavailable,
        ],
    ),
    (
        "inviteBuild",
        &[
            Code::NonCanonical,
            Code::InvalidPolicy,
            Code::PasswordRequired,
            Code::StateCorrupt,
            Code::CryptoUnavailable,
        ],
    ),
    (
        "inviteParse",
        &[
            Code::NonCanonical,
            Code::UnsupportedSuite,
            Code::PasswordRequired,
            Code::WrongPassword,
            Code::CryptoUnavailable,
        ],
    ),
    (
        "joinRequest",
        &[
            Code::NonCanonical,
            Code::InvalidKeyPackage,
            Code::WrongPurpose,
            Code::StateCorrupt,
            Code::CryptoUnavailable,
        ],
    ),
    (
        "rejoinRequest",
        &[
            Code::NonCanonical,
            Code::InvalidKeyPackage,
            Code::WrongPurpose,
            Code::CryptoUnavailable,
        ],
    ),
    (
        "joinVerify",
        &[
            Code::NonCanonical,
            Code::InvalidKeyPackage,
            Code::WrongPurpose,
            Code::BadSignature,
            Code::CryptoUnavailable,
        ],
    ),
    ("revealSeal", &[Code::NonCanonical, Code::CryptoUnavailable]),
    (
        "revealOpen",
        &[
            Code::NonCanonical,
            Code::NotOpen,
            Code::BadSignature,
            Code::StateCorrupt,
            Code::CryptoUnavailable,
        ],
    ),
    ("contentEncode", &[Code::NonCanonical]),
    ("contentDecode", &[Code::NonCanonical]),
    (
        "roster",
        &[
            Code::NonCanonical,
            Code::StateCorrupt,
            Code::CryptoUnavailable,
        ],
    ),
    (
        "sweepPast",
        &[
            Code::NonCanonical,
            Code::StateCorrupt,
            Code::CryptoUnavailable,
        ],
    ),
    (
        "trialCount",
        &[
            Code::NonCanonical,
            Code::InvalidCommit,
            Code::InvalidPolicy,
            Code::WrongEpoch,
            Code::StateCorrupt,
            Code::CryptoUnavailable,
        ],
    ),
];

/// The field tags of the wire (see the module header). Kotlin's `MlsField` holds the same list;
/// `MlsResultCodesTest` reads this enumeration out of this file and compares, so a tag added,
/// removed, renumbered or made repeatable on one side only fails there.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Field {
    /// `ctxOpen`: the context handle, `i64` big-endian.
    Handle = 0x01,
    /// A pseudonym key `P` (32): the channel's own (`channelOpen`), a member's, a KeyPackage's.
    Pseudonym = 0x02,
    /// A change of the change-set (record: [`Field::Scope`], [`Field::Key`], [`Field::Env`] for a
    /// put, no `Env` for a delete; §3.4 point 3). Repeatable.
    Change = 0x03,
    /// A stored row passed in (record: `Scope`, `Key`, `Env`; §3.4 point 2). Repeatable.
    Row = 0x04,
    /// A row's scope, one byte: 1 `mls_kv`, 2 `mls_global_kv`.
    Scope = 0x05,
    /// A storage key.
    Key = 0x06,
    /// A row's wrapped value.
    Env = 0x07,
    /// An epoch, `u64`.
    Epoch = 0x08,
    /// `K_ep(e)` wrapped with its epoch (68 bytes).
    KEnv = 0x09,
    /// `R_ep(e)` (32), a recognition key Kotlin holds (CS-S6).
    REp = 0x0a,
    /// An `epoch_authenticator`.
    EpochAuthenticator = 0x0b,
    /// A generation number, `u32`.
    Generation = 0x0c,
    /// The epoch that opened a generation, `u64`.
    OpenEpoch = 0x0d,
    /// `G_g` wrapped (60 bytes).
    GEnv = 0x0e,
    /// A namespace `ns_g` (32).
    Ns = 0x0f,
    /// `JK_g` wrapped (60 bytes).
    JkEnv = 0x10,
    /// `R_join(g)` (32).
    RJoin = 0x11,
    /// A slot's credentials (record: `SlotIndex`, the READ and DEPOSIT credentials v3 and their
    /// verifiers). Repeatable.
    Slot = 0x12,
    /// A relay slot, one byte.
    SlotIndex = 0x13,
    /// A READ credential v3 (67 bytes, a bearer secret Kotlin presents).
    ReadCredential = 0x14,
    /// Its verifier (32).
    ReadVerifier = 0x15,
    /// A DEPOSIT credential v3 (67 bytes).
    DepositCredential = 0x16,
    /// Its verifier (32).
    DepositVerifier = 0x17,
    /// A box public key (32; §5.1, §19.17).
    BoxPk = 0x18,
    /// The new box secret key wrapped (60 bytes).
    BoxEnv = 0x19,
    /// A canonical KeyPackage `MlsMessage` (395 bytes).
    KeyPackage = 0x1a,
    /// A `KeyPackageRef`.
    KpRef = 0x1b,
    /// A `GhostChannelContext` (record: `ChannelId` … `Funder`), in and out; the TLS encoding of
    /// §5.3 stays native.
    Context = 0x1c,
    /// A channel id (32).
    ChannelId = 0x1d,
    /// `size_class`, one byte.
    SizeClass = 0x1e,
    /// `timer_code`, one byte.
    TimerCode = 0x1f,
    /// `timer_version`, `u16`.
    TimerVersion = 0x20,
    /// `history_policy`, one byte.
    HistoryPolicy = 0x21,
    /// `flags`, one byte.
    Flags = 0x22,
    /// `idle_evict_days`, `u16`.
    IdleEvictDays = 0x23,
    /// `pw_version`, `u16`.
    PwVersion = 0x24,
    /// A channel name (UTF-8, ≤ 48 bytes).
    Name = 0x25,
    /// A committer key, in rank order. Repeatable.
    Committer = 0x26,
    /// A funder key, in order. Repeatable.
    Funder = 0x27,
    /// A roster member (record: `Pseudonym`, `Leaf`, `BoxPk`, `RefreshEpoch`). Repeatable.
    Member = 0x28,
    /// A leaf index, `u32`.
    Leaf = 0x29,
    /// `GhostLeaf.refresh_epoch`, `u64`.
    RefreshEpoch = 0x2a,
    /// The ratchet tree hash.
    TreeHash = 0x2b,
    /// An MLS message of a `receive` batch, in peek order. Repeatable.
    Message = 0x2c,
    /// A `receive` result per message (record). Repeatable.
    Item = 0x2d,
    /// An item's kind, one byte: 1 APP, 2 COMMIT, 3 PROPOSAL, 4 OWN, 5 FAILED.
    ItemKind = 0x2e,
    /// A decoded `ChannelContent` (record: `Kind` … `Ciphertext`).
    Content = 0x2f,
    /// An application message's author `P`, as OpenMLS verified it in the message's epoch.
    Sender = 0x30,
    /// `ChannelOrder.seq`, `u32`.
    Seq = 0x31,
    /// A commit's validation summary (record; §6.4 CO-2).
    Summary = 0x32,
    /// A failed item's code, one byte.
    ErrorCode = 0x33,
    /// An `INVALID_COMMIT` reason, one byte.
    Reason = 0x34,
    /// An `INVALID_KEYPACKAGE` or `INVALID_EVIDENCE` index, `u16`.
    Index = 0x35,
    /// SHA-256 of a commit's bytes (CO-3's tie-break).
    Hash = 0x36,
    /// A commit's size in bytes, `u32`.
    Size = 0x37,
    /// The sender's rank, one byte (255 for a non-committer).
    Rank = 0x38,
    /// A commit's `GhostCommitAad` (record: `CommitMinute`, `Rotate`, `Evidence`,
    /// `SwapEvidence`).
    Aad = 0x39,
    /// `commit_minute`, `u32`.
    CommitMinute = 0x3a,
    /// The rotation flag of an AAD or a request, one byte (0 or 1).
    Rotate = 0x3b,
    /// An `AdmitEvidence` (record). Repeatable.
    Evidence = 0x3c,
    /// A `SwapEvidence` (record). Repeatable.
    SwapEvidence = 0x3d,
    /// An Add: in a request (record: `KeyPackage`, `Evidence`), in a summary (record: `KpRef`,
    /// `Pseudonym`, `KpBind`, `BoxPk`, `ConstantLifetime`, `Canonical`). Repeatable.
    Add = 0x3e,
    /// A Remove: in a request (record: `Pseudonym`), in a summary (record: `Leaf`,
    /// `Pseudonym`). Repeatable.
    Remove = 0x3f,
    /// A swap: in a request (record: `Pseudonym`, `KeyPackage`, `SwapEvidence`), in a summary
    /// (record: `Leaf`, `Pseudonym`, `SwapKind`). Repeatable.
    Swap = 0x40,
    /// A `GhostKpBind` (record: `ChannelId`, `Purpose`, `Day`).
    KpBind = 0x41,
    /// A KeyPackage purpose, one byte: 1 join, 2 rejoin, 3 restore.
    Purpose = 0x42,
    /// A day, `u32`.
    Day = 0x43,
    /// One byte: the KeyPackage's lifetime is the constant `[0, 2⁶⁴ − 1]`.
    ConstantLifetime = 0x44,
    /// One byte: the KeyPackage is the canonical one.
    Canonical = 0x45,
    /// A swap's kind, one byte: 1 rejoin, 2 restore.
    SwapKind = 0x46,
    /// One byte: the commit opens a new generation.
    Rotates = 0x47,
    /// The update-path leaf's GHOST facts (record: `SignatureKey`, `BoxPk`, `RefreshEpoch`).
    UpdateLeaf = 0x48,
    /// A leaf's signature key (32).
    SignatureKey = 0x49,
    /// The sender leaf's `refresh_epoch` before the commit, `u64` (CO-14's input).
    SenderRefreshEpoch = 0x4a,
    /// The member count `n` before the commit, `u32`.
    MemberCount = 0x4b,
    /// CO-2's verdict, one byte: 0 valid, else the [`CommitReason`] it breaks.
    Verdict = 0x4c,
    /// An `invite_id` (16).
    InviteId = 0x4d,
    /// An `invite_pk` (32).
    InvitePk = 0x4e,
    /// An `expiry_day`, `u32`.
    ExpiryDay = 0x4f,
    /// A sponsor's pseudonym key (32).
    Sponsor = 0x50,
    /// A `sponsor_sig` (64).
    SponsorSig = 0x51,
    /// An `invite_sig` (64).
    InviteSig = 0x52,
    /// A rejoin's `last_epoch`, `u64`.
    LastEpoch = 0x53,
    /// A rejoin's `last_hash` (32).
    LastHash = 0x54,
    /// A `rejoin_sig` (64).
    RejoinSig = 0x55,
    /// An MLS message: a commit (`commit`) or an application message (`encrypt`).
    Mls = 0x56,
    /// A joiner's `WelcomeBlob` body (§5.6: `kp_ref` and the commit's Welcome), one per joiner
    /// in [`Field::Joiner`]'s order, kept by Kotlin until the commit wins and then sealed per
    /// joiner in mode 0x13 (the codec stays native). Repeatable.
    Welcome = 0x57,
    /// A joiner's `KeyPackageRef`, in the Welcome's order. Repeatable.
    Joiner = 0x58,
    /// The index of a requested Add the commit carries, `u32`. Repeatable.
    KeptAdd = 0x59,
    /// The index of a requested swap the commit carries, `u32`. Repeatable.
    KeptSwap = 0x5a,
    /// The index of a requested Remove the commit carries, `u32`. Repeatable.
    KeptRemove = 0x5b,
    /// How much of the requested context change the commit kept, one byte: 0 not requested,
    /// 1 full, 2 the drops of removed keys only (§5.7).
    ContextKept = 0x5c,
    /// The class floor bucket of a commit request, `u32`.
    Floor = 0x5d,
    /// Where a settle leaves the member, one byte: 1 member, 2 removed, 3 replaced.
    Standing = 0x5e,
    /// A pseudonym the settled commit added. Repeatable.
    Added = 0x5f,
    /// A pseudonym the settled commit removed. Repeatable.
    Removed = 0x60,
    /// The sender leaf of an own application message, `u32`.
    SenderLeaf = 0x61,
    /// A sealed blob of a bucket size.
    Blob = 0x62,
    /// The seal's `order.epoch`, `u64`.
    OrderEpoch = 0x63,
    /// The seal's `order.sender_leaf`, `u32`.
    OrderLeaf = 0x64,
    /// The seal's `order.seq`, `u32`.
    OrderSeq = 0x65,
    /// An opened blob's body, a join request's body.
    Body = 0x66,
    /// Mode 0x11: the PrivateMessage header's epoch, `u64`.
    HeaderEpoch = 0x67,
    /// Mode 0x11: the PrivateMessage's content type, one byte: 1 application, 2 commit, 3 proposal.
    ContentType = 0x68,
    /// Mode 0x11, an application message: `ChannelOrder.sender_leaf` of its MLS AAD, `u32`.
    AadLeaf = 0x69,
    /// Mode 0x11, an application message: `ChannelOrder.seq` of its MLS AAD, `u32`.
    AadSeq = 0x6a,
    /// A `ChannelInviteV2` (335 bytes).
    Invite = 0x6b,
    /// An invite's `kdf_code`, one byte.
    KdfCode = 0x6c,
    /// An invite's suite, `u16`.
    Suite = 0x6d,
    /// An invite's `handshake_ttl_code`, one byte.
    HandshakeTtlCode = 0x6e,
    /// A `committers_digest` (32).
    CommittersDigest = 0x6f,
    /// An invite's `invite_seed` wrapped (60 bytes; class 5).
    InviteSeedEnv = 0x70,
    /// A join request's type, one byte: 1 join, 2 rejoin, 3 restore.
    RequestType = 0x71,
    /// A content's `kind`, one byte.
    Kind = 0x72,
    /// A content's `op_id` (16).
    OpId = 0x73,
    /// A content's `author_minute`, `u32`.
    AuthorMinute = 0x74,
    /// A post's text (UTF-8).
    Text = 0x75,
    /// A post's `reply_to` (16).
    ReplyTo = 0x76,
    /// A reaction's target (16).
    Target = 0x77,
    /// A reaction's grapheme (UTF-8; empty withdraws it).
    Grapheme = 0x78,
    /// A reveal's `hpke_enc` (32).
    HpkeEnc = 0x79,
    /// A reveal's ciphertext.
    Ciphertext = 0x7a,
    /// A held blob of `trialCount` (record: `Ns`, `Blob`). Repeatable.
    Held = 0x7b,
    /// `trialCount`: the candidate's committer (32).
    Candidate = 0x7c,
    /// `trialCount`: a distinct authenticated sender under the trial state. Repeatable.
    TrialSender = 0x7d,
    /// `contentEncode`: the canonical `ChannelContent` bytes.
    Encoded = 0x7e,
    /// A contact card v2 (131 bytes; §6.9's reveal: `revealOpen`'s verified card, the offer
    /// `Messaging.addContact` takes).
    Card = 0x7f,
}

impl Field {
    /// Every tag, in wire order (contiguous from 0x01; a test checks it).
    pub const ALL: &'static [Field] = &[
        Field::Handle,
        Field::Pseudonym,
        Field::Change,
        Field::Row,
        Field::Scope,
        Field::Key,
        Field::Env,
        Field::Epoch,
        Field::KEnv,
        Field::REp,
        Field::EpochAuthenticator,
        Field::Generation,
        Field::OpenEpoch,
        Field::GEnv,
        Field::Ns,
        Field::JkEnv,
        Field::RJoin,
        Field::Slot,
        Field::SlotIndex,
        Field::ReadCredential,
        Field::ReadVerifier,
        Field::DepositCredential,
        Field::DepositVerifier,
        Field::BoxPk,
        Field::BoxEnv,
        Field::KeyPackage,
        Field::KpRef,
        Field::Context,
        Field::ChannelId,
        Field::SizeClass,
        Field::TimerCode,
        Field::TimerVersion,
        Field::HistoryPolicy,
        Field::Flags,
        Field::IdleEvictDays,
        Field::PwVersion,
        Field::Name,
        Field::Committer,
        Field::Funder,
        Field::Member,
        Field::Leaf,
        Field::RefreshEpoch,
        Field::TreeHash,
        Field::Message,
        Field::Item,
        Field::ItemKind,
        Field::Content,
        Field::Sender,
        Field::Seq,
        Field::Summary,
        Field::ErrorCode,
        Field::Reason,
        Field::Index,
        Field::Hash,
        Field::Size,
        Field::Rank,
        Field::Aad,
        Field::CommitMinute,
        Field::Rotate,
        Field::Evidence,
        Field::SwapEvidence,
        Field::Add,
        Field::Remove,
        Field::Swap,
        Field::KpBind,
        Field::Purpose,
        Field::Day,
        Field::ConstantLifetime,
        Field::Canonical,
        Field::SwapKind,
        Field::Rotates,
        Field::UpdateLeaf,
        Field::SignatureKey,
        Field::SenderRefreshEpoch,
        Field::MemberCount,
        Field::Verdict,
        Field::InviteId,
        Field::InvitePk,
        Field::ExpiryDay,
        Field::Sponsor,
        Field::SponsorSig,
        Field::InviteSig,
        Field::LastEpoch,
        Field::LastHash,
        Field::RejoinSig,
        Field::Mls,
        Field::Welcome,
        Field::Joiner,
        Field::KeptAdd,
        Field::KeptSwap,
        Field::KeptRemove,
        Field::ContextKept,
        Field::Floor,
        Field::Standing,
        Field::Added,
        Field::Removed,
        Field::SenderLeaf,
        Field::Blob,
        Field::OrderEpoch,
        Field::OrderLeaf,
        Field::OrderSeq,
        Field::Body,
        Field::HeaderEpoch,
        Field::ContentType,
        Field::AadLeaf,
        Field::AadSeq,
        Field::Invite,
        Field::KdfCode,
        Field::Suite,
        Field::HandshakeTtlCode,
        Field::CommittersDigest,
        Field::InviteSeedEnv,
        Field::RequestType,
        Field::Kind,
        Field::OpId,
        Field::AuthorMinute,
        Field::Text,
        Field::ReplyTo,
        Field::Target,
        Field::Grapheme,
        Field::HpkeEnc,
        Field::Ciphertext,
        Field::Held,
        Field::Candidate,
        Field::TrialSender,
        Field::Encoded,
        Field::Card,
    ];

    /// The tags that may repeat in one field list: the lists of the wire. Kotlin's `MlsField`
    /// marks the same ones.
    pub const REPEATABLE: &'static [Field] = &[
        Field::Change,
        Field::Row,
        Field::Slot,
        Field::Committer,
        Field::Funder,
        Field::Member,
        Field::Message,
        Field::Item,
        Field::Evidence,
        Field::SwapEvidence,
        Field::Add,
        Field::Remove,
        Field::Swap,
        Field::Joiner,
        Field::Welcome,
        Field::KeptAdd,
        Field::KeptSwap,
        Field::KeptRemove,
        Field::Added,
        Field::Removed,
        Field::Held,
        Field::TrialSender,
    ];

    /// The tags whose value is itself a field list (a record). Kotlin's `MlsField` marks the same
    /// ones and decodes them eagerly, so a malformed record anywhere in a reply is `STATE_CORRUPT`.
    pub const RECORDS: &'static [Field] = &[
        Field::Change,
        Field::Row,
        Field::Slot,
        Field::Context,
        Field::Member,
        Field::Item,
        Field::Content,
        Field::Summary,
        Field::Aad,
        Field::Evidence,
        Field::SwapEvidence,
        Field::Add,
        Field::Remove,
        Field::Swap,
        Field::KpBind,
        Field::UpdateLeaf,
        Field::Held,
    ];

    /// The wire tag.
    pub const fn tag(self) -> u8 {
        self as u8
    }

    /// The field of a wire tag, or `None` for a tag this version does not define.
    pub fn from_tag(tag: u8) -> Option<Field> {
        Field::ALL.iter().copied().find(|f| f.tag() == tag)
    }

    /// Whether the tag may repeat in one field list.
    pub fn repeatable(self) -> bool {
        Field::REPEATABLE.contains(&self)
    }
}

// -------------------------------------------------------------------------------------------
// The codec
// -------------------------------------------------------------------------------------------

fn nc() -> MlsError {
    MlsError::new(Code::NonCanonical)
}

/// A field list under construction: `(tag(1) ‖ len(u32_be) ‖ value)*`, with an optional leading
/// code byte. A reply carries post plaintexts, bearer credentials and recognition keys, so the
/// buffer grows by hand — the old allocation is erased before it is freed (Phase 9 review
/// CRY-P9-04) — and the list erases itself when it is dropped; a record embedded in its parent is
/// erased once copied.
struct Tlv(Vec<u8>);

impl Tlv {
    fn new() -> Self {
        Self(Vec::new())
    }

    fn ok() -> Self {
        Self(vec![Code::Ok.as_u8()])
    }

    fn reserve(&mut self, more: usize) {
        let needed = self.0.len() + more;
        if needed > self.0.capacity() {
            let mut grown = Vec::with_capacity(needed.max(2 * self.0.capacity()).max(64));
            grown.extend_from_slice(&self.0);
            self.0.zeroize();
            self.0 = grown;
        }
    }

    fn put(&mut self, tag: Field, value: &[u8]) {
        self.reserve(5 + value.len());
        self.0.push(tag.tag());
        // A value is at most a few hundred KiB (a commit with its Welcome is below 64 KiB).
        let len = u32::try_from(value.len()).unwrap_or(u32::MAX);
        self.0.extend_from_slice(&len.to_be_bytes());
        self.0.extend_from_slice(value);
    }

    fn u8(&mut self, tag: Field, v: u8) {
        self.put(tag, &[v]);
    }

    fn flag(&mut self, tag: Field, v: bool) {
        self.put(tag, &[u8::from(v)]);
    }

    fn u16(&mut self, tag: Field, v: u16) {
        self.put(tag, &v.to_be_bytes());
    }

    fn u32(&mut self, tag: Field, v: u32) {
        self.put(tag, &v.to_be_bytes());
    }

    fn u64(&mut self, tag: Field, v: u64) {
        self.put(tag, &v.to_be_bytes());
    }

    fn record(&mut self, tag: Field, record: Tlv) {
        self.put(tag, &record.0);
    }

    fn into_bytes(mut self) -> Vec<u8> {
        std::mem::take(&mut self.0)
    }
}

impl Drop for Tlv {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// A strict reading of a field list (an argument): every tag known, a non-repeatable tag at most
/// once, every length inside the buffer. Anything else is `NON_CANONICAL`.
struct Fields<'a> {
    items: Vec<(Field, &'a [u8])>,
}

impl<'a> Fields<'a> {
    fn parse(b: &'a [u8], allowed: &[Field]) -> MlsResult<Self> {
        let mut items: Vec<(Field, &'a [u8])> = Vec::new();
        let mut rest = b;
        while !rest.is_empty() {
            let (head, tail) = rest.split_at_checked(5).ok_or_else(nc)?;
            let field = Field::from_tag(head[0]).ok_or_else(nc)?;
            if !allowed.contains(&field) {
                return Err(nc());
            }
            let len = usize::try_from(u32::from_be_bytes([head[1], head[2], head[3], head[4]]))
                .map_err(|_| nc())?;
            let (value, after) = tail.split_at_checked(len).ok_or_else(nc)?;
            if !field.repeatable() && items.iter().any(|(f, _)| *f == field) {
                return Err(nc());
            }
            items.push((field, value));
            rest = after;
        }
        Ok(Self { items })
    }

    fn opt(&self, f: Field) -> Option<&'a [u8]> {
        self.items.iter().find(|(g, _)| *g == f).map(|(_, v)| *v)
    }

    fn req(&self, f: Field) -> MlsResult<&'a [u8]> {
        self.opt(f).ok_or_else(nc)
    }

    fn all(&self, f: Field) -> impl Iterator<Item = &'a [u8]> + '_ {
        self.items
            .iter()
            .filter(move |(g, _)| *g == f)
            .map(|(_, v)| *v)
    }

    fn fixed<const N: usize>(&self, f: Field) -> MlsResult<[u8; N]> {
        <[u8; N]>::try_from(self.req(f)?).map_err(|_| nc())
    }

    fn opt_fixed<const N: usize>(&self, f: Field) -> MlsResult<Option<[u8; N]>> {
        self.opt(f)
            .map(|v| <[u8; N]>::try_from(v).map_err(|_| nc()))
            .transpose()
    }

    fn u8(&self, f: Field) -> MlsResult<u8> {
        Ok(self.fixed::<1>(f)?[0])
    }

    fn flag(&self, f: Field) -> MlsResult<bool> {
        match self.u8(f)? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(nc()),
        }
    }

    fn u16(&self, f: Field) -> MlsResult<u16> {
        Ok(u16::from_be_bytes(self.fixed(f)?))
    }

    fn opt_u16(&self, f: Field) -> MlsResult<Option<u16>> {
        Ok(self.opt_fixed::<2>(f)?.map(u16::from_be_bytes))
    }

    fn u32(&self, f: Field) -> MlsResult<u32> {
        Ok(u32::from_be_bytes(self.fixed(f)?))
    }

    fn u64(&self, f: Field) -> MlsResult<u64> {
        Ok(u64::from_be_bytes(self.fixed(f)?))
    }
}

fn keys32<'a>(values: impl Iterator<Item = &'a [u8]>) -> MlsResult<Vec<[u8; 32]>> {
    values
        .map(|v| <[u8; 32]>::try_from(v).map_err(|_| nc()))
        .collect()
}

// ---- records in --------------------------------------------------------------------------------

/// `rows`: the TLV array of wrapped rows (§3.4 point 2).
fn rows_in(b: &[u8]) -> MlsResult<Vec<WrappedRow>> {
    let list = Fields::parse(b, &[Field::Row])?;
    list.all(Field::Row)
        .map(|r| {
            let f = Fields::parse(r, &[Field::Scope, Field::Key, Field::Env])?;
            Ok(WrappedRow {
                scope: Scope::from_u8(f.u8(Field::Scope)?).ok_or_else(nc)?,
                key: f.req(Field::Key)?.to_vec(),
                env: f.req(Field::Env)?.to_vec(),
            })
        })
        .collect()
}

const CONTEXT_FIELDS: &[Field] = &[
    Field::ChannelId,
    Field::SizeClass,
    Field::TimerCode,
    Field::TimerVersion,
    Field::HistoryPolicy,
    Field::Flags,
    Field::IdleEvictDays,
    Field::PwVersion,
    Field::Name,
    Field::Committer,
    Field::Funder,
];

/// A `GhostChannelContext` from its record. §5.3's validity is the caller's (`groupCreate`,
/// CO-2): this reads the fields only.
fn context_in(b: &[u8]) -> MlsResult<ChannelContext> {
    let f = Fields::parse(b, CONTEXT_FIELDS)?;
    Ok(ChannelContext {
        channel_id: f.fixed(Field::ChannelId)?,
        size_class: f.u8(Field::SizeClass)?,
        timer_code: f.u8(Field::TimerCode)?,
        timer_version: f.u16(Field::TimerVersion)?,
        history_policy: f.u8(Field::HistoryPolicy)?,
        flags: f.u8(Field::Flags)?,
        idle_evict_days: f.u16(Field::IdleEvictDays)?,
        pw_version: f.u16(Field::PwVersion)?,
        name: f.opt(Field::Name).unwrap_or_default().to_vec(),
        committers: keys32(f.all(Field::Committer))?,
        funders: keys32(f.all(Field::Funder))?,
    })
}

const ADMIT_FIELDS: &[Field] = &[
    Field::KpRef,
    Field::InviteId,
    Field::InvitePk,
    Field::ExpiryDay,
    Field::Sponsor,
    Field::SponsorSig,
    Field::InviteSig,
];

fn admit_in(b: &[u8]) -> MlsResult<AdmitEvidence> {
    let f = Fields::parse(b, ADMIT_FIELDS)?;
    Ok(AdmitEvidence {
        kp_ref: f.req(Field::KpRef)?.to_vec(),
        invite_id: f.fixed(Field::InviteId)?,
        invite_pk: f.fixed(Field::InvitePk)?,
        expiry_day: f.u32(Field::ExpiryDay)?,
        sponsor: f.fixed(Field::Sponsor)?,
        sponsor_sig: f.fixed(Field::SponsorSig)?,
        invite_sig: f.fixed(Field::InviteSig)?,
    })
}

fn swap_evidence_in(b: &[u8]) -> MlsResult<SwapEvidence> {
    let f = Fields::parse(
        b,
        &[
            Field::SwapKind,
            Field::KpRef,
            Field::Generation,
            Field::Day,
            Field::LastEpoch,
            Field::LastHash,
            Field::RejoinSig,
            Field::Evidence,
        ],
    )?;
    match f.u8(Field::SwapKind)? {
        1 => {
            if f.opt(Field::Evidence).is_some() {
                return Err(nc());
            }
            Ok(SwapEvidence::Rejoin {
                kp_ref: f.req(Field::KpRef)?.to_vec(),
                generation: f.u32(Field::Generation)?,
                day: f.u32(Field::Day)?,
                last_epoch: f.u64(Field::LastEpoch)?,
                last_hash: f.fixed(Field::LastHash)?,
                rejoin_sig: f.fixed(Field::RejoinSig)?,
            })
        }
        2 => {
            let rejoin_only = [
                Field::KpRef,
                Field::Generation,
                Field::Day,
                Field::LastEpoch,
                Field::LastHash,
                Field::RejoinSig,
            ];
            if rejoin_only.iter().any(|g| f.opt(*g).is_some()) {
                return Err(nc());
            }
            let mut evidence = f.all(Field::Evidence);
            let first = evidence.next().ok_or_else(nc)?;
            if evidence.next().is_some() {
                return Err(nc());
            }
            Ok(SwapEvidence::Restore(admit_in(first)?))
        }
        _ => Err(nc()),
    }
}

/// `commit`'s request (fn 9): the proposals by value and the generation the Welcome bootstraps.
fn request_in(b: &[u8]) -> MlsResult<CommitRequest> {
    let f = Fields::parse(
        b,
        &[
            Field::Add,
            Field::Remove,
            Field::Swap,
            Field::Context,
            Field::Rotate,
            Field::CommitMinute,
            Field::Floor,
            Field::Generation,
            Field::OpenEpoch,
            Field::GEnv,
        ],
    )?;
    let adds = f
        .all(Field::Add)
        .map(|a| {
            let a = Fields::parse(a, &[Field::KeyPackage, Field::Evidence])?;
            Ok((
                a.req(Field::KeyPackage)?.to_vec(),
                admit_in(a.req(Field::Evidence)?)?,
            ))
        })
        .collect::<MlsResult<Vec<_>>>()?;
    let removes = f
        .all(Field::Remove)
        .map(|r| Fields::parse(r, &[Field::Pseudonym])?.fixed(Field::Pseudonym))
        .collect::<MlsResult<Vec<_>>>()?;
    let swaps = f
        .all(Field::Swap)
        .map(|s| {
            let s = Fields::parse(
                s,
                &[Field::Pseudonym, Field::KeyPackage, Field::SwapEvidence],
            )?;
            Ok((
                s.fixed(Field::Pseudonym)?,
                s.req(Field::KeyPackage)?.to_vec(),
                swap_evidence_in(s.req(Field::SwapEvidence)?)?,
            ))
        })
        .collect::<MlsResult<Vec<_>>>()?;
    Ok(CommitRequest {
        adds,
        removes,
        swaps,
        context: f.opt(Field::Context).map(context_in).transpose()?,
        rotate: f.flag(Field::Rotate)?,
        commit_minute: f.u32(Field::CommitMinute)?,
        floor: usize::try_from(f.u32(Field::Floor)?).map_err(|_| nc())?,
        generation: f.u32(Field::Generation)?,
        generation_open_epoch: f.u64(Field::OpenEpoch)?,
        g_env: f.req(Field::GEnv)?.to_vec(),
    })
}

const CONTENT_FIELDS: &[Field] = &[
    Field::Kind,
    Field::OpId,
    Field::AuthorMinute,
    Field::TimerCode,
    Field::Text,
    Field::ReplyTo,
    Field::Target,
    Field::Grapheme,
    Field::InviteId,
    Field::InvitePk,
    Field::ExpiryDay,
    Field::SponsorSig,
    Field::CommittersDigest,
    Field::PwVersion,
    Field::HpkeEnc,
    Field::Ciphertext,
];

/// A `ChannelContent` from its record (`contentEncode`). Each kind takes exactly its own fields;
/// the canonical rules themselves (lengths, UTF-8, the kinds GHOST refuses) are the codec's.
fn content_in(b: &[u8]) -> MlsResult<ChannelContent> {
    let f = Fields::parse(b, CONTENT_FIELDS)?;
    let kind = f.u8(Field::Kind)?;
    let own: &[Field] = match kind {
        crate::content::KIND_POST => &[Field::Text, Field::ReplyTo],
        crate::content::KIND_REACTION => &[Field::Target, Field::Grapheme],
        crate::content::KIND_INVITE_ISSUED => &[
            Field::InviteId,
            Field::InvitePk,
            Field::ExpiryDay,
            Field::SponsorSig,
            Field::CommittersDigest,
            Field::PwVersion,
        ],
        crate::content::KIND_LEAVE => &[],
        crate::content::KIND_REVEAL => &[Field::HpkeEnc, Field::Ciphertext],
        _ => return Err(nc()),
    };
    let header = [
        Field::Kind,
        Field::OpId,
        Field::AuthorMinute,
        Field::TimerCode,
    ];
    if f.items
        .iter()
        .any(|(g, _)| !header.contains(g) && !own.contains(g))
    {
        return Err(nc());
    }
    // The header first, and a value checked before it is copied: no refusal leaves a copy of a post
    // outside the content, which erases its own when dropped (review of S2b).
    let op_id = f.fixed(Field::OpId)?;
    let author_minute = f.u32(Field::AuthorMinute)?;
    let timer_code = f.u8(Field::TimerCode)?;
    let utf8 = |v: &[u8]| core::str::from_utf8(v).map(str::to_owned).map_err(|_| nc());
    let body = match kind {
        crate::content::KIND_POST => Body::Post {
            reply_to: f.opt_fixed(Field::ReplyTo)?,
            text: utf8(f.req(Field::Text)?)?,
        },
        crate::content::KIND_REACTION => Body::Reaction {
            target: f.fixed(Field::Target)?,
            grapheme: utf8(f.req(Field::Grapheme)?)?,
        },
        crate::content::KIND_INVITE_ISSUED => Body::InviteIssued(InviteIssued {
            invite_id: f.fixed(Field::InviteId)?,
            invite_pk: f.fixed(Field::InvitePk)?,
            expiry_day: f.u32(Field::ExpiryDay)?,
            sponsor_sig: f.fixed(Field::SponsorSig)?,
            committers_digest: f.fixed(Field::CommittersDigest)?,
            pw_version: f.opt_u16(Field::PwVersion)?,
        }),
        crate::content::KIND_LEAVE => Body::Leave,
        _ => Body::Reveal {
            hpke_enc: f.fixed(Field::HpkeEnc)?,
            ciphertext: f.req(Field::Ciphertext)?.to_vec(),
        },
    };
    Ok(ChannelContent {
        kind,
        op_id,
        author_minute,
        timer_code,
        body,
    })
}

/// A list argument whose items are one tag repeated (`receive`'s messages).
fn list_in(b: &[u8], tag: Field) -> MlsResult<Vec<Vec<u8>>> {
    Ok(Fields::parse(b, &[tag])?
        .all(tag)
        .map(<[u8]>::to_vec)
        .collect())
}

/// `trialCount`'s held blobs, each with the namespace it came from.
fn held_in(b: &[u8]) -> MlsResult<Vec<([u8; 32], Vec<u8>)>> {
    Fields::parse(b, &[Field::Held])?
        .all(Field::Held)
        .map(|h| {
            let h = Fields::parse(h, &[Field::Ns, Field::Blob])?;
            Ok((h.fixed(Field::Ns)?, h.req(Field::Blob)?.to_vec()))
        })
        .collect()
}

// ---- records out -------------------------------------------------------------------------------

fn changes_out(t: &mut Tlv, changes: &ChangeSet) {
    for c in changes {
        let mut r = Tlv::new();
        r.u8(Field::Scope, c.scope as u8);
        r.put(Field::Key, &c.key);
        if let Some(env) = &c.env {
            r.put(Field::Env, env);
        }
        t.record(Field::Change, r);
    }
}

fn epoch_out(t: &mut Tlv, e: &EpochKeys) {
    t.u64(Field::Epoch, e.epoch);
    t.put(Field::KEnv, &e.k_env);
    t.put(Field::REp, &e.r_ep);
    t.put(Field::EpochAuthenticator, &e.epoch_authenticator);
}

fn generation_out(t: &mut Tlv, g: &GenerationValues) {
    t.u32(Field::Generation, g.generation);
    t.u64(Field::OpenEpoch, g.open_epoch);
    t.put(Field::GEnv, &g.g_env);
    t.put(Field::Ns, &g.ns);
    t.put(Field::JkEnv, &g.jk_env);
    t.put(Field::RJoin, &g.r_join);
}

fn slots_out(t: &mut Tlv, slots: &[SlotCredentials]) {
    for s in slots {
        let mut r = Tlv::new();
        r.u8(Field::SlotIndex, s.slot);
        r.put(Field::ReadCredential, &s.read_credential);
        r.put(Field::ReadVerifier, &s.read_verifier);
        r.put(Field::DepositCredential, &s.deposit_credential);
        r.put(Field::DepositVerifier, &s.deposit_verifier);
        t.record(Field::Slot, r);
    }
}

fn context_out(c: &ChannelContext) -> Tlv {
    let mut r = Tlv::new();
    r.put(Field::ChannelId, &c.channel_id);
    r.u8(Field::SizeClass, c.size_class);
    r.u8(Field::TimerCode, c.timer_code);
    r.u16(Field::TimerVersion, c.timer_version);
    r.u8(Field::HistoryPolicy, c.history_policy);
    r.u8(Field::Flags, c.flags);
    r.u16(Field::IdleEvictDays, c.idle_evict_days);
    r.u16(Field::PwVersion, c.pw_version);
    r.put(Field::Name, &c.name);
    for k in &c.committers {
        r.put(Field::Committer, k);
    }
    for k in &c.funders {
        r.put(Field::Funder, k);
    }
    r
}

fn members_out(t: &mut Tlv, members: &[RosterEntry]) {
    for m in members {
        let mut r = Tlv::new();
        r.put(Field::Pseudonym, &m.pseudonym);
        r.u32(Field::Leaf, m.leaf);
        if let Some(pk) = &m.box_pk {
            r.put(Field::BoxPk, pk);
        }
        if let Some(e) = m.refresh_epoch {
            r.u64(Field::RefreshEpoch, e);
        }
        t.record(Field::Member, r);
    }
}

/// The fields of a `ChannelContent` (`contentDecode`'s reply, a `receive` item's `CONTENT`).
fn content_out(t: &mut Tlv, c: &ChannelContent) {
    t.u8(Field::Kind, c.kind);
    t.put(Field::OpId, &c.op_id);
    t.u32(Field::AuthorMinute, c.author_minute);
    t.u8(Field::TimerCode, c.timer_code);
    match &c.body {
        Body::Post { text, reply_to } => {
            t.put(Field::Text, text.as_bytes());
            if let Some(r) = reply_to {
                t.put(Field::ReplyTo, r);
            }
        }
        Body::Reaction { target, grapheme } => {
            t.put(Field::Target, target);
            t.put(Field::Grapheme, grapheme.as_bytes());
        }
        Body::InviteIssued(i) => issued_out(t, i),
        Body::Leave => {}
        Body::Reveal {
            hpke_enc,
            ciphertext,
        } => {
            t.put(Field::HpkeEnc, hpke_enc);
            t.put(Field::Ciphertext, ciphertext);
        }
    }
}

fn issued_out(t: &mut Tlv, i: &InviteIssued) {
    t.put(Field::InviteId, &i.invite_id);
    t.put(Field::InvitePk, &i.invite_pk);
    t.u32(Field::ExpiryDay, i.expiry_day);
    t.put(Field::SponsorSig, &i.sponsor_sig);
    t.put(Field::CommittersDigest, &i.committers_digest);
    if let Some(v) = i.pw_version {
        t.u16(Field::PwVersion, v);
    }
}

fn admit_out(a: &AdmitEvidence) -> Tlv {
    let mut r = Tlv::new();
    r.put(Field::KpRef, &a.kp_ref);
    r.put(Field::InviteId, &a.invite_id);
    r.put(Field::InvitePk, &a.invite_pk);
    r.u32(Field::ExpiryDay, a.expiry_day);
    r.put(Field::Sponsor, &a.sponsor);
    r.put(Field::SponsorSig, &a.sponsor_sig);
    r.put(Field::InviteSig, &a.invite_sig);
    r
}

fn swap_evidence_out(s: &SwapEvidence) -> Tlv {
    let mut r = Tlv::new();
    match s {
        SwapEvidence::Rejoin {
            kp_ref,
            generation,
            day,
            last_epoch,
            last_hash,
            rejoin_sig,
        } => {
            r.u8(Field::SwapKind, 1);
            r.put(Field::KpRef, kp_ref);
            r.u32(Field::Generation, *generation);
            r.u32(Field::Day, *day);
            r.u64(Field::LastEpoch, *last_epoch);
            r.put(Field::LastHash, last_hash);
            r.put(Field::RejoinSig, rejoin_sig);
        }
        SwapEvidence::Restore(a) => {
            r.u8(Field::SwapKind, 2);
            r.record(Field::Evidence, admit_out(a));
        }
    }
    r
}

fn aad_out(a: &CommitAad) -> Tlv {
    let mut r = Tlv::new();
    r.u32(Field::CommitMinute, a.commit_minute);
    r.flag(Field::Rotate, a.rotate);
    for e in &a.admits {
        r.record(Field::Evidence, admit_out(e));
    }
    for s in &a.swaps {
        r.record(Field::SwapEvidence, swap_evidence_out(s));
    }
    r
}

fn kp_bind_out(b: &KpBind) -> Tlv {
    let mut r = Tlv::new();
    r.put(Field::ChannelId, &b.channel_id);
    r.u8(Field::Purpose, b.purpose as u8);
    r.u32(Field::Day, b.day);
    r
}

fn add_summary_out(a: &AddSummary) -> Tlv {
    let mut r = Tlv::new();
    r.put(Field::KpRef, &a.kp_ref);
    r.put(Field::Pseudonym, &a.pseudonym);
    if let Some(b) = &a.bind {
        r.record(Field::KpBind, kp_bind_out(b));
    }
    if let Some(pk) = &a.box_pk {
        r.put(Field::BoxPk, pk);
    }
    r.flag(Field::ConstantLifetime, a.constant_lifetime);
    r.flag(Field::Canonical, a.canonical);
    r
}

fn remove_summary_out(rm: &RemoveSummary) -> Tlv {
    let mut r = Tlv::new();
    r.u32(Field::Leaf, rm.leaf);
    r.put(Field::Pseudonym, &rm.pseudonym);
    r
}

fn swap_summary_out(s: &SwapSummary) -> Tlv {
    let mut r = Tlv::new();
    r.u32(Field::Leaf, s.leaf);
    r.put(Field::Pseudonym, &s.pseudonym);
    if let Some(k) = s.kind {
        r.u8(
            Field::SwapKind,
            match k {
                SwapKind::Rejoin => 1,
                SwapKind::Restore => 2,
            },
        );
    }
    r
}

fn leaf_facts_out(l: &LeafFacts) -> Tlv {
    let mut r = Tlv::new();
    r.put(Field::SignatureKey, &l.signature_key);
    r.put(Field::BoxPk, &l.leaf.box_pk);
    r.u64(Field::RefreshEpoch, l.leaf.refresh_epoch);
    r
}

/// `receive`'s COMMIT output (fn 6), every input of CO-1 … CO-14 the summary carries.
fn summary_out(s: &CommitSummary) -> Tlv {
    let mut r = Tlv::new();
    r.put(Field::Hash, &s.hash);
    r.u32(Field::Size, u32::try_from(s.size).unwrap_or(u32::MAX));
    r.u64(Field::Epoch, s.epoch);
    r.u32(Field::SenderLeaf, s.sender_leaf);
    r.put(Field::Sender, &s.sender);
    r.u8(Field::Rank, s.rank);
    if let Some(a) = &s.aad {
        r.record(Field::Aad, aad_out(a));
    }
    for a in &s.joins {
        r.record(Field::Add, add_summary_out(a));
    }
    for rm in &s.removes {
        r.record(Field::Remove, remove_summary_out(rm));
    }
    for sw in &s.swaps {
        r.record(Field::Swap, swap_summary_out(sw));
    }
    if let Some(c) = &s.context {
        r.record(Field::Context, context_out(c));
    }
    r.flag(Field::Rotates, s.rotates);
    if let Some(l) = &s.update_leaf {
        r.record(Field::UpdateLeaf, leaf_facts_out(l));
    }
    if let Some(e) = s.sender_refresh_epoch {
        r.u64(Field::SenderRefreshEpoch, e);
    }
    r.u32(
        Field::MemberCount,
        u32::try_from(s.members).unwrap_or(u32::MAX),
    );
    if let Some(a) = &s.epoch_authenticator {
        r.put(Field::EpochAuthenticator, a);
    }
    r.u8(
        Field::Verdict,
        match s.verdict {
            Ok(()) => 0,
            Err(reason) => reason as u8,
        },
    );
    r
}

/// The detail of an error, as a field of its reply.
fn detail_out(t: &mut Tlv, e: &MlsError) {
    match e.detail {
        Detail::None => {}
        Detail::Index(i) => t.u16(Field::Index, i),
        Detail::Reason(r) => t.u8(Field::Reason, r as u8),
    }
}

fn error_reply(e: &MlsError) -> Vec<u8> {
    let mut t = Tlv(vec![e.code.as_u8()]);
    detail_out(&mut t, e);
    t.into_bytes()
}

// -------------------------------------------------------------------------------------------
// The registry
// -------------------------------------------------------------------------------------------

/// What a handle names: the context (the crypto provider and the state key) and the channels
/// opened on it, each pseudonym signer behind its own pointer.
struct MlsJni {
    ctx: MlsContext,
    channels: HashMap<[u8; 32], Box<ChannelHandle>>,
}

/// One registry entry: the context **behind a pointer** (CRY-P9-02, see the module header) with
/// **its own lock** (review of S2b: one process-wide lock held across every call made `ctxClose`
/// of one context wait behind another context's Argon2id or commit). The registry's own lock is
/// held only to find or change an entry.
type ContextSlot = Arc<Mutex<MlsJni>>;

type Registry = HashMap<i64, ContextSlot>;

fn registry() -> &'static Mutex<Registry> {
    static REGISTRY: OnceLock<Mutex<Registry>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

/// The registry guard, **recovered from poisoning**, like each context's own guard: a panic caught
/// by [`guarded`] unwinds through the context's guard, and treating a poisoned mutex as an error
/// would make every later call on it — `ctxClose` included — `INTERNAL` for the life of the
/// process. Neither map can be left half-written by such a panic: inserts and removes run no user
/// code under a guard, and a call body only reads the context and its channel map.
fn registry_lock() -> MutexGuard<'static, Registry> {
    registry().lock().unwrap_or_else(PoisonError::into_inner)
}

/// The first handle. Never 0, never reused, and far from the DM surface's handles (which count
/// from 1), so a DM handle passed to `MlsNative` by mistake names nothing here.
const FIRST_HANDLE: i64 = 0x4d4c_5300_0000_0001;

fn next_handle() -> i64 {
    static NEXT: AtomicI64 = AtomicI64::new(FIRST_HANDLE);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

fn insert_context(context: MlsJni) -> i64 {
    let handle = next_handle();
    registry_lock().insert(handle, Arc::new(Mutex::new(context)));
    handle
}

/// Removes a context from the registry: no later call finds it. Dropping the last reference
/// zeroises it in place — here, or when a call that is still running on it on another thread
/// returns. False for a closed or foreign handle.
fn remove_context(handle: i64) -> bool {
    // The registry's guard is a temporary of this statement: the context is dropped after it.
    let slot = registry_lock().remove(&handle);
    slot.is_some()
}

/// Runs `body` with the named context, or reports `CRYPTO_UNAVAILABLE` for a closed or foreign
/// handle. The context's own guard is held across the body, the registry's only while the entry is
/// found, so calls on different contexts never wait for each other and no secret is copied out.
fn with_context<T>(handle: jlong, body: impl FnOnce(&mut MlsJni) -> MlsResult<T>) -> MlsResult<T> {
    let slot = registry_lock()
        .get(&handle)
        .cloned()
        .ok_or(MlsError::new(Code::CryptoUnavailable))?;
    let mut context = slot.lock().unwrap_or_else(PoisonError::into_inner);
    body(&mut context)
}

/// [`with_context`] for a channel open on the handle; a channel not open there is
/// `CRYPTO_UNAVAILABLE` (never opened, closed, or opened on another handle).
fn with_channel<T>(
    handle: jlong,
    channel_id: &[u8; 32],
    body: impl FnOnce(&MlsContext, &ChannelHandle) -> MlsResult<T>,
) -> MlsResult<T> {
    with_context(handle, |c| {
        let ch = c
            .channels
            .get(channel_id)
            .ok_or(MlsError::new(Code::CryptoUnavailable))?;
        body(&c.ctx, ch)
    })
}

/// The test libraries' planted panic (`MlsVectors.run` kind 12, slice S2b's lifecycle test): a
/// panic raised while the named context is held, the way a library panic inside a call would be.
/// Never compiled into a shipped library (`test-vectors`, G-M2).
#[cfg(feature = "test-vectors")]
pub fn panic_inside_context(handle: jlong) -> MlsResult<()> {
    with_context(handle, |_| -> MlsResult<()> { panic!("a planted panic") })
}

/// Installs the silent panic hook once per process (see the module header).
pub fn quiet_panics() {
    static QUIET: Once = Once::new();
    QUIET.call_once(|| std::panic::set_hook(Box::new(|_| {})));
}

/// Runs a JNI body and turns its outcome into the reply array: a panic becomes `INTERNAL`, an
/// error its code and detail. The reply is erased once the Java array holds its copy. A reply the
/// JVM cannot allocate returns null with the JVM's `OutOfMemoryError` pending, so the Kotlin call
/// **throws** it (measured by the review of S2b at `-Xmx48m`): an out-of-memory heap is the VM's
/// condition, not a channel code, and nothing here clears it.
fn guarded(env: &mut JNIEnv, body: impl FnOnce(&mut JNIEnv) -> MlsResult<Vec<u8>>) -> jbyteArray {
    quiet_panics();
    let reply = Zeroizing::new(match catch_unwind(AssertUnwindSafe(|| body(env))) {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(e)) => error_reply(&e),
        Err(_) => vec![Code::Internal.as_u8()],
    });
    match env.byte_array_from_slice(&reply) {
        Ok(array) => array.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

// ---- arguments ---------------------------------------------------------------------------------

/// The native copy of a Java byte array, **erased when it is dropped** (Phase 9 review R2-04: the
/// state key, a pseudonym seed, a password and every row cross this way). A null array is
/// `NON_CANONICAL`.
fn bytes(env: &JNIEnv, array: &JByteArray) -> MlsResult<Zeroizing<Vec<u8>>> {
    if array.is_null() {
        return Err(nc());
    }
    env.convert_byte_array(array)
        .map(Zeroizing::new)
        .map_err(|_| nc())
}

/// An optional array: null or empty is absent.
fn opt_bytes(env: &JNIEnv, array: &JByteArray) -> MlsResult<Option<Zeroizing<Vec<u8>>>> {
    if array.is_null() {
        return Ok(None);
    }
    let b = bytes(env, array)?;
    Ok((!b.is_empty()).then_some(b))
}

fn fixed<const N: usize>(env: &JNIEnv, array: &JByteArray) -> MlsResult<[u8; N]> {
    <[u8; N]>::try_from(bytes(env, array)?.as_slice()).map_err(|_| nc())
}

/// An optional 32-byte argument: null or empty is absent, anything else must be 32 bytes.
fn opt_fixed32(env: &JNIEnv, array: &JByteArray) -> MlsResult<Option<[u8; 32]>> {
    opt_bytes(env, array)?
        .map(|b| <[u8; 32]>::try_from(b.as_slice()).map_err(|_| nc()))
        .transpose()
}

/// A 32-byte key input (the state key, a pseudonym seed): another length is `INVALID_KEY`
/// (§10.2 fn 2).
fn key32(env: &JNIEnv, array: &JByteArray) -> MlsResult<Zeroizing<[u8; 32]>> {
    let b = bytes(env, array).map_err(|_| MlsError::new(Code::InvalidKey))?;
    let mut k = Zeroizing::new([0u8; 32]);
    if b.len() != 32 {
        return Err(MlsError::new(Code::InvalidKey));
    }
    k.copy_from_slice(&b);
    Ok(k)
}

/// The invite password: the NFKD UTF-8 bytes Kotlin built from a `CharArray` (§19.29.3). Null is
/// "no password"; an empty array is an empty password, which the codec refuses
/// (`PASSWORD_REQUIRED`). The copy moves into [`InvitePassword`], which zeroizes on drop.
fn password(env: &JNIEnv, array: &JByteArray) -> MlsResult<Option<InvitePassword>> {
    if array.is_null() {
        return Ok(None);
    }
    let mut b = bytes(env, array)?;
    Ok(Some(InvitePassword::from_bytes(std::mem::take(&mut *b))))
}

/// A `u32` argument (a day, a minute, a generation, a slot count): negative is `NON_CANONICAL`.
fn uint(v: jint) -> MlsResult<u32> {
    u32::try_from(v).map_err(|_| nc())
}

/// A `u64` argument (an epoch): negative is `NON_CANONICAL`.
fn ulong(v: jlong) -> MlsResult<u64> {
    u64::try_from(v).map_err(|_| nc())
}

fn small(v: jint) -> MlsResult<u8> {
    u8::try_from(v).map_err(|_| nc())
}

fn seal_class(v: jint) -> MlsResult<KeyClass> {
    small(v).and_then(|c| KeyClass::from_u8(c).ok_or_else(nc))
}

// -------------------------------------------------------------------------------------------
// Function bodies. `export_jni!` wraps each one in a `#[no_mangle] extern "system"` entry point
// inside the invoking crate (`ghost-client-net`, `ghost-dm-host`), so the closed list stays
// visible there (§10.1).
// -------------------------------------------------------------------------------------------

/// fn 1 `ctxOpen(stateKey32)`: the context handle. `CRYPTO_UNAVAILABLE` when the provider's DRBG
/// cannot be seeded or the `rayon` pool is not one worker (§3.6).
pub fn ctx_open(env: &mut JNIEnv, state_key: &JByteArray) -> MlsResult<Vec<u8>> {
    let key = key32(env, state_key)?;
    let ctx = MlsContext::open(StateKey::from_bytes(*key))?;
    let handle = insert_context(MlsJni {
        ctx,
        channels: HashMap::new(),
    });
    let mut r = Tlv::ok();
    r.put(Field::Handle, &handle.to_be_bytes());
    Ok(r.into_bytes())
}

/// fn 1 `ctxClose(h)`: drops the context and every channel opened on it in place (their keys
/// zeroize on drop) — at once, or as soon as a call still running on it on another thread returns;
/// no later call finds it. A second close is `CRYPTO_UNAVAILABLE`, never a crash.
pub fn ctx_close(handle: jlong) -> MlsResult<Vec<u8>> {
    if !remove_context(handle) {
        return Err(MlsError::new(Code::CryptoUnavailable));
    }
    Ok(Tlv::ok().into_bytes())
}

/// fn 2 `channelOpen(h, channelId, pseudonymSeed32)`: `P`, which Kotlin compares with
/// `:identity`'s value. Opening an open channel again with the same seed is a no-op; with another
/// seed it is `INVALID_KEY` (a channel's pseudonym never changes under an open handle; close it
/// first).
pub fn channel_open(
    env: &mut JNIEnv,
    handle: jlong,
    channel_id: &JByteArray,
    seed: &JByteArray,
) -> MlsResult<Vec<u8>> {
    let channel_id = fixed::<32>(env, channel_id)?;
    let seed = key32(env, seed)?;
    let ch = ChannelHandle::open(channel_id, &PseudonymSeed::from_bytes(*seed));
    let p = ch.pseudonym();
    with_context(handle, move |c| match c.channels.get(&channel_id) {
        Some(open) if open.pseudonym() == p => Ok(()),
        Some(_) => Err(MlsError::new(Code::InvalidKey)),
        None => {
            c.channels.insert(channel_id, Box::new(ch));
            Ok(())
        }
    })?;
    let mut r = Tlv::ok();
    r.put(Field::Pseudonym, &p);
    Ok(r.into_bytes())
}

/// fn 2 `channelClose(h, channelId)`: drops the channel's signer in place; closing a channel that
/// is not open is `CRYPTO_UNAVAILABLE`.
pub fn channel_close(
    env: &mut JNIEnv,
    handle: jlong,
    channel_id: &JByteArray,
) -> MlsResult<Vec<u8>> {
    let channel_id = fixed::<32>(env, channel_id)?;
    with_context(handle, |c| {
        c.channels
            .remove(&channel_id)
            .map(drop)
            .ok_or(MlsError::new(Code::CryptoUnavailable))
    })?;
    Ok(Tlv::ok().into_bytes())
}

/// fn 3 `groupCreate(h, channelId, policy, day)`: the change-set, epoch 0's keys, generation 0's
/// values and the creator's box key.
pub fn group_create(
    env: &mut JNIEnv,
    handle: jlong,
    channel_id: &JByteArray,
    policy: &JByteArray,
    day: jint,
) -> MlsResult<Vec<u8>> {
    let channel_id = fixed::<32>(env, channel_id)?;
    let policy = context_in(&bytes(env, policy)?)?;
    let day = uint(day)?;
    let out = with_channel(handle, &channel_id, |ctx, ch| {
        ctx.group_create(ch, &policy, day)
    })?;
    let mut r = Tlv::ok();
    changes_out(&mut r, &out.changes);
    epoch_out(&mut r, &out.epoch);
    generation_out(&mut r, &out.generation);
    r.put(Field::BoxPk, &out.box_pk);
    r.put(Field::BoxEnv, &out.box_env);
    Ok(r.into_bytes())
}

/// fn 4 `keyPackage(h, channelId, purpose, day)`: the canonical KeyPackage (395 bytes), its
/// reference, the global change-set and the new box key wrapped.
pub fn key_package(
    env: &mut JNIEnv,
    handle: jlong,
    channel_id: &JByteArray,
    purpose: jint,
    day: jint,
) -> MlsResult<Vec<u8>> {
    let channel_id = fixed::<32>(env, channel_id)?;
    let purpose = Purpose::from_u8(small(purpose)?).ok_or_else(nc)?;
    let day = uint(day)?;
    let out = with_channel(handle, &channel_id, |ctx, ch| {
        ctx.key_package(ch, purpose, day)
    })?;
    let mut r = Tlv::ok();
    r.put(Field::KeyPackage, &out.key_package);
    r.put(Field::KpRef, &out.kp_ref);
    changes_out(&mut r, &out.changes);
    r.put(Field::BoxPk, &out.box_pk);
    r.put(Field::BoxEnv, &out.box_env);
    Ok(r.into_bytes())
}

/// fn 5 `welcomeJoin(h, channelId, rows, welcomeBlob, day, expectedGeneration, expectedNs,
/// anchorKind, anchor)`. `anchorKind` 1: a join or restore, `anchor` the invite's 32-byte
/// `committers_digest`; 2: a rejoin, `anchor` the committers of the last final epoch, 32 bytes
/// each (S0-15, §19.29.2).
#[allow(clippy::too_many_arguments)]
pub fn welcome_join(
    env: &mut JNIEnv,
    handle: jlong,
    channel_id: &JByteArray,
    rows: &JByteArray,
    welcome_blob: &JByteArray,
    day: jint,
    expected_generation: jint,
    expected_ns: &JByteArray,
    anchor_kind: jint,
    anchor: &JByteArray,
) -> MlsResult<Vec<u8>> {
    let channel_id = fixed::<32>(env, channel_id)?;
    let rows = rows_in(&bytes(env, rows)?)?;
    let blob = bytes(env, welcome_blob)?;
    let day = uint(day)?;
    let expected = (uint(expected_generation)?, fixed::<32>(env, expected_ns)?);
    let anchor_bytes = bytes(env, anchor)?;
    let anchor = match anchor_kind {
        1 => Anchor::Invite {
            committers_digest: <[u8; 32]>::try_from(anchor_bytes.as_slice()).map_err(|_| nc())?,
        },
        2 => {
            let (keys, rest) = anchor_bytes.as_chunks::<32>();
            if keys.is_empty() || !rest.is_empty() {
                return Err(nc());
            }
            Anchor::Rejoin {
                last_committers: keys.to_vec(),
            }
        }
        _ => return Err(nc()),
    };
    let out = with_channel(handle, &channel_id, |ctx, ch| {
        ctx.welcome_join(ch, &WrappedRows(&rows), &blob, day, expected, &anchor)
    })?;
    let mut r = Tlv::ok();
    changes_out(&mut r, &out.changes);
    r.record(Field::Context, context_out(&out.context));
    members_out(&mut r, &out.roster);
    r.u32(Field::Leaf, out.leaf);
    epoch_out(&mut r, &out.epoch);
    generation_out(&mut r, &out.generation);
    Ok(r.into_bytes())
}

/// fn 6 `receive(h, channelId, rows, epoch, messages, day)`: one `ITEM` per message, in order,
/// and one change-set for the batch (S0-17).
pub fn receive(
    env: &mut JNIEnv,
    handle: jlong,
    channel_id: &JByteArray,
    rows: &JByteArray,
    epoch: jlong,
    messages: &JByteArray,
    day: jint,
) -> MlsResult<Vec<u8>> {
    let channel_id = fixed::<32>(env, channel_id)?;
    let rows = rows_in(&bytes(env, rows)?)?;
    let epoch = ulong(epoch)?;
    let msgs = list_in(&bytes(env, messages)?, Field::Message)?;
    let day = uint(day)?;
    let out = with_channel(handle, &channel_id, |ctx, ch| {
        ctx.receive(ch, &WrappedRows(&rows), epoch, &msgs, day)
    })?;
    let mut r = Tlv::ok();
    for item in &out.items {
        let mut i = Tlv::new();
        match item {
            ReceiveItem::App {
                content,
                sender,
                order,
            } => {
                i.u8(Field::ItemKind, 1);
                let mut c = Tlv::new();
                content_out(&mut c, content);
                i.record(Field::Content, c);
                i.put(Field::Sender, sender);
                i.u32(Field::SenderLeaf, order.sender_leaf);
                i.u32(Field::Seq, order.seq);
            }
            ReceiveItem::Commit(s) => {
                i.u8(Field::ItemKind, 2);
                i.record(Field::Summary, summary_out(s));
            }
            ReceiveItem::Proposal => i.u8(Field::ItemKind, 3),
            ReceiveItem::Own => i.u8(Field::ItemKind, 4),
            ReceiveItem::Failed(e) => {
                i.u8(Field::ItemKind, 5);
                i.u8(Field::ErrorCode, e.code.as_u8());
                detail_out(&mut i, e);
            }
        }
        r.record(Field::Item, i);
    }
    changes_out(&mut r, &out.changes);
    Ok(r.into_bytes())
}

/// The winner of `settle` and `trialCount`: 1 another member's commit, 2 the own pending commit
/// (its bytes either way).
fn winner(kind: jint, bytes: &[u8]) -> MlsResult<Winner<'_>> {
    match kind {
        1 => Ok(Winner::Foreign(bytes)),
        2 => Ok(Winner::Own(bytes)),
        _ => Err(nc()),
    }
}

/// fn 7 `settle(h, channelId, rows, winnerKind, winner, generation, day)`.
#[allow(clippy::too_many_arguments)]
pub fn settle(
    env: &mut JNIEnv,
    handle: jlong,
    channel_id: &JByteArray,
    rows: &JByteArray,
    winner_kind: jint,
    winner_bytes: &JByteArray,
    generation: jint,
    day: jint,
) -> MlsResult<Vec<u8>> {
    let channel_id = fixed::<32>(env, channel_id)?;
    let rows = rows_in(&bytes(env, rows)?)?;
    let w = bytes(env, winner_bytes)?;
    let won = winner(winner_kind, &w)?;
    let generation = uint(generation)?;
    let day = uint(day)?;
    let out = with_channel(handle, &channel_id, |ctx, ch| {
        ctx.settle(ch, &WrappedRows(&rows), won, generation, day)
    })?;
    let mut r = Tlv::ok();
    changes_out(&mut r, &out.changes);
    r.u8(
        Field::Standing,
        match out.standing {
            Standing::Member => 1,
            Standing::Removed => 2,
            Standing::Replaced => 3,
        },
    );
    if let Some(e) = &out.epoch {
        epoch_out(&mut r, e);
    }
    r.u32(Field::CommitMinute, out.commit_minute);
    r.flag(Field::Rotates, out.rotates);
    if let Some(g) = &out.rotated {
        generation_out(&mut r, g);
    }
    for p in &out.added {
        r.put(Field::Added, p);
    }
    for p in &out.removed {
        r.put(Field::Removed, p);
    }
    Ok(r.into_bytes())
}

/// fn 8 `clearOwn(h, channelId, rows, day)`.
pub fn clear_own(
    env: &mut JNIEnv,
    handle: jlong,
    channel_id: &JByteArray,
    rows: &JByteArray,
    day: jint,
) -> MlsResult<Vec<u8>> {
    let channel_id = fixed::<32>(env, channel_id)?;
    let rows = rows_in(&bytes(env, rows)?)?;
    let day = uint(day)?;
    let changes = with_channel(handle, &channel_id, |ctx, ch| {
        ctx.clear_own(ch, &WrappedRows(&rows), day)
    })?;
    let mut r = Tlv::ok();
    changes_out(&mut r, &changes);
    Ok(r.into_bytes())
}

/// fn 9 `commit(h, channelId, rows, request, day)`: the request is one record (`ADD`, `REMOVE`,
/// `SWAP`, `CONTEXT`, `ROTATE`, `COMMIT_MINUTE`, `FLOOR`, `GENERATION`, `OPEN_EPOCH`, `G_ENV`).
/// The Welcome comes back as one `WelcomeBlob` body per joiner (`WELCOME`, in `JOINER` order).
pub fn commit(
    env: &mut JNIEnv,
    handle: jlong,
    channel_id: &JByteArray,
    rows: &JByteArray,
    request: &JByteArray,
    day: jint,
) -> MlsResult<Vec<u8>> {
    let channel_id = fixed::<32>(env, channel_id)?;
    let rows = rows_in(&bytes(env, rows)?)?;
    let req = request_in(&bytes(env, request)?)?;
    let day = uint(day)?;
    let out = with_channel(handle, &channel_id, |ctx, ch| {
        ctx.commit(ch, &WrappedRows(&rows), &req, day)
    })?;
    let mut r = Tlv::ok();
    r.put(Field::Mls, &out.commit);
    if let Some(w) = &out.welcome {
        for j in &out.joiners {
            let blob = WelcomeBlob {
                kp_ref: j.clone(),
                welcome: w.clone(),
            }
            .encode()?;
            r.put(Field::Welcome, &blob);
        }
    }
    for j in &out.joiners {
        r.put(Field::Joiner, j);
    }
    let index = |i: usize| u32::try_from(i).unwrap_or(u32::MAX);
    for &i in &out.kept_adds {
        r.u32(Field::KeptAdd, index(i));
    }
    for &i in &out.kept_swaps {
        r.u32(Field::KeptSwap, index(i));
    }
    for &i in &out.kept_removes {
        r.u32(Field::KeptRemove, index(i));
    }
    r.u8(
        Field::ContextKept,
        match out.context {
            ContextKept::NotRequested => 0,
            ContextKept::Full => 1,
            ContextKept::DropsOnly => 2,
        },
    );
    r.flag(Field::Rotates, out.rotates);
    r.put(Field::BoxPk, &out.box_pk);
    r.put(Field::BoxEnv, &out.box_env);
    changes_out(&mut r, &out.changes);
    r.record(Field::Summary, summary_out(&out.summary));
    Ok(r.into_bytes())
}

/// fn 10 `encrypt(h, channelId, rows, content, seq, day)`: `content` is a canonical
/// `ChannelContent` (`contentEncode`'s output).
#[allow(clippy::too_many_arguments)]
pub fn encrypt(
    env: &mut JNIEnv,
    handle: jlong,
    channel_id: &JByteArray,
    rows: &JByteArray,
    content: &JByteArray,
    seq: jint,
    day: jint,
) -> MlsResult<Vec<u8>> {
    let channel_id = fixed::<32>(env, channel_id)?;
    let rows = rows_in(&bytes(env, rows)?)?;
    let content = bytes(env, content)?;
    let seq = uint(seq)?;
    let day = uint(day)?;
    let out = with_channel(handle, &channel_id, |ctx, ch| {
        ctx.encrypt(ch, &WrappedRows(&rows), &content, seq, day)
    })?;
    let mut r = Tlv::ok();
    r.put(Field::Mls, &out.mls);
    r.u64(Field::Epoch, out.epoch);
    r.u32(Field::SenderLeaf, out.sender_leaf);
    changes_out(&mut r, &out.changes);
    Ok(r.into_bytes())
}

/// fn 11 `seal(h, channelId, keyEnv, keyClass, ns, bucket, mode, orderEpoch, orderLeaf, orderSeq,
/// body)`: `keyClass` 1 (`K_ep`, mode 0x11), 3 (`JK_g`, modes 0x12 and 0x13) or 6 (an invite's
/// `JK_g`, mode 0x12 only; review of S2b, §19.36); the salt from the provider's CSPRNG.
#[allow(clippy::too_many_arguments)]
pub fn seal(
    env: &mut JNIEnv,
    handle: jlong,
    channel_id: &JByteArray,
    key_env: &JByteArray,
    key_class: jint,
    ns: &JByteArray,
    bucket: jint,
    mode: jint,
    order_epoch: jlong,
    order_leaf: jint,
    order_seq: jint,
    body: &JByteArray,
) -> MlsResult<Vec<u8>> {
    let channel_id = fixed::<32>(env, channel_id)?;
    let key_env = bytes(env, key_env)?;
    let class = seal_class(key_class)?;
    let ns = fixed::<32>(env, ns)?;
    let bucket = usize::try_from(uint(bucket)?).map_err(|_| nc())?;
    let mode = small(mode)?;
    let order = Order {
        epoch: ulong(order_epoch)?,
        sender_leaf: uint(order_leaf)?,
        seq: uint(order_seq)?,
    };
    let body = bytes(env, body)?;
    let blob = with_context(handle, |c| {
        c.ctx.seal_blob(
            &channel_id,
            &key_env,
            class,
            &ns,
            bucket,
            mode,
            &order,
            &body,
        )
    })?;
    let mut r = Tlv::ok();
    r.put(Field::Blob, &blob);
    Ok(r.into_bytes())
}

/// fn 12 `open(h, channelId, keyEnv, keyClass, ns, mode, blob)`: the order and the body, and for
/// mode 0x11 the PrivateMessage header's epoch and content type and, for an application message,
/// its `ChannelOrder` (CS-S7). An invite's `JK_g` (class 6) opens mode 0x13 only.
#[allow(clippy::too_many_arguments)]
pub fn open(
    env: &mut JNIEnv,
    handle: jlong,
    channel_id: &JByteArray,
    key_env: &JByteArray,
    key_class: jint,
    ns: &JByteArray,
    mode: jint,
    blob: &JByteArray,
) -> MlsResult<Vec<u8>> {
    let channel_id = fixed::<32>(env, channel_id)?;
    let key_env = bytes(env, key_env)?;
    let class = seal_class(key_class)?;
    let ns = fixed::<32>(env, ns)?;
    let mode = small(mode)?;
    let blob = bytes(env, blob)?;
    let opened = with_context(handle, |c| {
        c.ctx
            .open_blob(&channel_id, &key_env, class, &ns, mode, &blob)
    })?;
    let mut r = Tlv::ok();
    r.u64(Field::OrderEpoch, opened.order.epoch);
    r.u32(Field::OrderLeaf, opened.order.sender_leaf);
    r.u32(Field::OrderSeq, opened.order.seq);
    r.put(Field::Body, &opened.body);
    if let Some(h) = &opened.header {
        r.u64(Field::HeaderEpoch, h.epoch);
        r.u8(
            Field::ContentType,
            match h.content {
                EpochContent::Application => 1,
                EpochContent::Commit => 2,
                EpochContent::Proposal => 3,
            },
        );
        if let Some(o) = &h.channel_order {
            r.u32(Field::AadLeaf, o.sender_leaf);
            r.u32(Field::AadSeq, o.seq);
        }
    }
    Ok(r.into_bytes())
}

/// fn 13 `generation(h, channelId, gEnv, generation, openEpoch, slots)`: `slots` one byte per
/// relay slot, each at most once (`NON_CANONICAL`; review of S2b).
pub fn generation(
    env: &mut JNIEnv,
    handle: jlong,
    channel_id: &JByteArray,
    g_env: &JByteArray,
    generation: jint,
    open_epoch: jlong,
    slots: &JByteArray,
) -> MlsResult<Vec<u8>> {
    let channel_id = fixed::<32>(env, channel_id)?;
    let g_env = bytes(env, g_env)?;
    let generation = uint(generation)?;
    let open_epoch = ulong(open_epoch)?;
    let slots = bytes(env, slots)?;
    let (values, creds) = with_context(handle, |c| {
        c.ctx
            .generation(&channel_id, &g_env, generation, open_epoch, &slots)
    })?;
    let mut r = Tlv::ok();
    generation_out(&mut r, &values);
    slots_out(&mut r, &creds);
    Ok(r.into_bytes())
}

/// fn 14 `inviteBuild(h, channelId, rows, gEnv, generation, expiryDay, kdfCode, password,
/// carryName, day)`: the 335-byte invite and the `INVITE_ISSUED` fields (with `PW_VERSION` in a
/// password channel). `password` is null for an open invite.
#[allow(clippy::too_many_arguments)]
pub fn invite_build(
    env: &mut JNIEnv,
    handle: jlong,
    channel_id: &JByteArray,
    rows: &JByteArray,
    g_env: &JByteArray,
    generation: jint,
    expiry_day: jint,
    kdf_code: jint,
    password_bytes: &JByteArray,
    carry_name: jint,
    day: jint,
) -> MlsResult<Vec<u8>> {
    let channel_id = fixed::<32>(env, channel_id)?;
    let rows = rows_in(&bytes(env, rows)?)?;
    let g_env = bytes(env, g_env)?;
    let generation = uint(generation)?;
    let expiry_day = uint(expiry_day)?;
    let kdf_code = small(kdf_code)?;
    let pw = password(env, password_bytes)?;
    let carry_name = match carry_name {
        0 => false,
        1 => true,
        _ => return Err(nc()),
    };
    let day = uint(day)?;
    let out = with_channel(handle, &channel_id, |ctx, ch| {
        ctx.invite_build(
            ch,
            &WrappedRows(&rows),
            &g_env,
            generation,
            expiry_day,
            kdf_code,
            pw.as_ref(),
            carry_name,
            day,
        )
    })?;
    let mut r = Tlv::ok();
    r.put(Field::Invite, &out.invite);
    r.u8(Field::KdfCode, kdf_code);
    issued_out(&mut r, &out.issued);
    Ok(r.into_bytes())
}

/// fn 14 `inviteParse(h, invite, password, slots)`: the invite's public fields, its secrets
/// wrapped under the state key (`JK_ENV` in class 6, `INVITE_SEED_ENV`), `R_JOIN` and the
/// credentials of `slots` (each at most once). Without a password a password invite is
/// `PASSWORD_REQUIRED` and no Argon2id runs.
pub fn invite_parse(
    env: &mut JNIEnv,
    handle: jlong,
    invite: &JByteArray,
    password_bytes: &JByteArray,
    slots: &JByteArray,
) -> MlsResult<Vec<u8>> {
    let invite = bytes(env, invite)?;
    let pw = password(env, password_bytes)?;
    let slots = bytes(env, slots)?;
    let p = with_context(handle, |c| c.ctx.invite_parse(&invite, pw.as_ref(), &slots))?;
    let mut r = Tlv::ok();
    r.u8(Field::KdfCode, p.kdf_code);
    r.u16(Field::Suite, p.suite);
    r.u8(Field::SizeClass, p.size_class);
    r.u8(Field::HandshakeTtlCode, p.handshake_ttl_code);
    r.put(Field::ChannelId, &p.channel_id);
    r.u32(Field::Generation, p.generation);
    r.put(Field::Ns, &p.ns);
    r.put(Field::InviteId, &p.invite_id);
    r.put(Field::InvitePk, &p.invite_pk);
    r.put(Field::CommittersDigest, &p.committers_digest);
    r.u32(Field::ExpiryDay, p.expiry_day);
    r.put(Field::Name, &p.name);
    r.put(Field::JkEnv, &p.jk_env);
    r.put(Field::RJoin, &p.r_join);
    r.put(Field::InviteSeedEnv, &p.seed_env);
    slots_out(&mut r, &p.slots);
    Ok(r.into_bytes())
}

/// fn 15 `joinRequest(h, channelId, inviteId, inviteSeedEnv, keyPackage)`: the join or restore
/// request body, signed with the invite key `inviteParse` wrapped.
pub fn join_request(
    env: &mut JNIEnv,
    handle: jlong,
    channel_id: &JByteArray,
    invite_id: &JByteArray,
    seed_env: &JByteArray,
    key_package: &JByteArray,
) -> MlsResult<Vec<u8>> {
    let channel_id = fixed::<32>(env, channel_id)?;
    let invite_id = fixed::<16>(env, invite_id)?;
    let seed_env = bytes(env, seed_env)?;
    let kp = bytes(env, key_package)?;
    let body = with_context(handle, |c| {
        c.ctx
            .join_request_wrapped(&channel_id, &invite_id, &seed_env, &kp)
    })?;
    let mut r = Tlv::ok();
    r.put(Field::Body, &body);
    Ok(r.into_bytes())
}

/// fn 15 `rejoinRequest(h, channelId, generation, day, lastEpoch, lastHash, keyPackage)`: signed
/// with the channel's pseudonym key (§19.3).
#[allow(clippy::too_many_arguments)]
pub fn rejoin_request(
    env: &mut JNIEnv,
    handle: jlong,
    channel_id: &JByteArray,
    generation: jint,
    day: jint,
    last_epoch: jlong,
    last_hash: &JByteArray,
    key_package: &JByteArray,
) -> MlsResult<Vec<u8>> {
    let channel_id = fixed::<32>(env, channel_id)?;
    let generation = uint(generation)?;
    let day = uint(day)?;
    let last_epoch = ulong(last_epoch)?;
    let last_hash = fixed::<32>(env, last_hash)?;
    let kp = bytes(env, key_package)?;
    let body = with_channel(handle, &channel_id, |ctx, ch| {
        ctx.rejoin_request(ch, generation, day, last_epoch, &last_hash, &kp)
    })?;
    let mut r = Tlv::ok();
    r.put(Field::Body, &body);
    Ok(r.into_bytes())
}

/// fn 15 `joinVerify(h, channelId, body, invitePk, member, generation)`: `invitePk` for a join or
/// restore, `member` for a rejoin (null or empty when absent). The request's type, its canonical
/// KeyPackage and what it carries, and the verified authorization.
#[allow(clippy::too_many_arguments)]
pub fn join_verify(
    env: &mut JNIEnv,
    handle: jlong,
    channel_id: &JByteArray,
    body: &JByteArray,
    invite_pk: &JByteArray,
    member: &JByteArray,
    generation: jint,
) -> MlsResult<Vec<u8>> {
    let channel_id = fixed::<32>(env, channel_id)?;
    let body = bytes(env, body)?;
    let invite_pk = opt_fixed32(env, invite_pk)?;
    let member = opt_fixed32(env, member)?;
    let generation = uint(generation)?;
    let v = with_context(handle, |c| {
        c.ctx.join_verify(
            &channel_id,
            &body,
            invite_pk.as_ref(),
            member.as_ref(),
            generation,
        )
    })?;
    let mut r = Tlv::ok();
    r.u8(
        Field::RequestType,
        match v.request_type {
            RequestType::Join => 1,
            RequestType::Rejoin => 2,
            RequestType::Restore => 3,
        },
    );
    r.put(Field::KeyPackage, &v.key_package.bytes);
    r.put(Field::KpRef, &v.key_package.kp_ref);
    r.put(Field::Pseudonym, &v.key_package.pseudonym);
    r.put(Field::BoxPk, &v.key_package.box_pk);
    r.record(Field::KpBind, kp_bind_out(&v.key_package.bind));
    match &v.auth {
        JoinAuth::Invite {
            invite_id,
            invite_sig,
        } => {
            r.put(Field::InviteId, invite_id);
            r.put(Field::InviteSig, invite_sig);
        }
        JoinAuth::Rejoin {
            day,
            last_epoch,
            last_hash,
            rejoin_sig,
        } => {
            r.u32(Field::Day, *day);
            r.u64(Field::LastEpoch, *last_epoch);
            r.put(Field::LastHash, last_hash);
            r.put(Field::RejoinSig, rejoin_sig);
        }
    }
    Ok(r.into_bytes())
}

/// fn 16 `revealSeal(h, dmHandle, channelId, recipientP, recipientBoxPk, minute, opId)` (§6.9):
/// the HPKE-sealed `RevealPayload` for [recipient]. [dm_handle] names the DM context whose
/// identity key signs `sig_id` and whose own card v2 the payload carries (`ghost-client-dm`'s
/// `reveal_identity_material`, ADR-35's X-21 rule); a closed or foreign handle on either side is
/// `CRYPTO_UNAVAILABLE`. A non-canonical recipient box key is `NON_CANONICAL` (the F9 §22.8.2
/// rule, as for a leaf's key).
#[allow(clippy::too_many_arguments)]
pub fn reveal_seal(
    env: &mut JNIEnv,
    handle: jlong,
    dm_handle: jlong,
    channel_id: &JByteArray,
    recipient_p: &JByteArray,
    recipient_box_pk: &JByteArray,
    minute: jint,
    op_id: &JByteArray,
) -> MlsResult<Vec<u8>> {
    let channel_id = fixed::<32>(env, channel_id)?;
    let recipient_p = fixed::<32>(env, recipient_p)?;
    let recipient_box_pk = fixed::<32>(env, recipient_box_pk)?;
    let minute = uint(minute)?;
    let op_id = fixed::<16>(env, op_id)?;
    let (enc, ct) = with_channel(handle, &channel_id, |ctx, ch| {
        ctx.reveal_seal(
            ch,
            |transcript| ghost_client_dm::jni::reveal_identity_material(dm_handle, transcript).ok(),
            recipient_p,
            recipient_box_pk,
            minute,
            op_id,
        )
    })?;
    let mut r = Tlv::ok();
    r.put(Field::HpkeEnc, &enc);
    r.put(Field::Ciphertext, &ct);
    Ok(r.into_bytes())
}

/// fn 16 `revealOpen(h, channelId, boxEnv, enc, ct, opId, senderP)` (§6.9): one HPKE open with
/// the member's box key of the post's epoch, then every binding M must verify (see
/// [`MlsContext::reveal_open`]). `NOT_OPEN` is the expected answer of every non-recipient — one
/// open per reveal post, counted and dropped; `BAD_SIGNATURE` is a forgery, refused with nothing
/// returned; a [box_env] that does not open is `STATE_CORRUPT`. On `Ok`: the author's verified
/// card and pseudonym (the peer of the recipient's `ch_reveal` row and the offer
/// `Messaging.addContact` takes).
#[allow(clippy::too_many_arguments)]
pub fn reveal_open(
    env: &mut JNIEnv,
    handle: jlong,
    channel_id: &JByteArray,
    box_env: &JByteArray,
    enc: &JByteArray,
    ct: &JByteArray,
    op_id: &JByteArray,
    sender_p: &JByteArray,
) -> MlsResult<Vec<u8>> {
    let channel_id = fixed::<32>(env, channel_id)?;
    let box_env = bytes(env, box_env)?;
    let enc = fixed::<32>(env, enc)?;
    let ct = bytes(env, ct)?;
    let op_id = fixed::<16>(env, op_id)?;
    let sender_p = fixed::<32>(env, sender_p)?;
    let opened = with_channel(handle, &channel_id, |ctx, ch| {
        ctx.reveal_open(ch, &box_env, enc, &ct, op_id, sender_p)
    })?;
    let mut r = Tlv::ok();
    r.put(Field::Pseudonym, &opened.p_author);
    r.put(Field::Card, &opened.card);
    Ok(r.into_bytes())
}

/// fn 17 `contentEncode(fields)`: the canonical `ChannelContent` (§5.5).
pub fn content_encode(env: &mut JNIEnv, fields: &JByteArray) -> MlsResult<Vec<u8>> {
    let content = content_in(&bytes(env, fields)?)?;
    let encoded = Zeroizing::new(content.encode()?);
    let mut r = Tlv::ok();
    r.put(Field::Encoded, &encoded);
    Ok(r.into_bytes())
}

/// fn 17 `contentDecode(bytes)`: the content's fields (a strict decode: `NON_CANONICAL` for
/// anything §5.5 refuses).
pub fn content_decode(env: &mut JNIEnv, encoded: &JByteArray) -> MlsResult<Vec<u8>> {
    let content = ChannelContent::decode(&bytes(env, encoded)?)?;
    let mut r = Tlv::ok();
    content_out(&mut r, &content);
    Ok(r.into_bytes())
}

/// fn 18 `roster(h, channelId, rows, day)`.
pub fn roster(
    env: &mut JNIEnv,
    handle: jlong,
    channel_id: &JByteArray,
    rows: &JByteArray,
    day: jint,
) -> MlsResult<Vec<u8>> {
    let channel_id = fixed::<32>(env, channel_id)?;
    let rows = rows_in(&bytes(env, rows)?)?;
    let day = uint(day)?;
    let out = with_channel(handle, &channel_id, |ctx, ch| {
        ctx.roster(ch, &WrappedRows(&rows), day)
    })?;
    let mut r = Tlv::ok();
    members_out(&mut r, &out.members);
    r.u64(Field::Epoch, out.epoch);
    r.put(Field::EpochAuthenticator, &out.epoch_authenticator);
    r.put(Field::TreeHash, &out.tree_hash);
    r.record(Field::Context, context_out(&out.context));
    r.u32(Field::Leaf, out.own_leaf);
    r.put(Field::CommittersDigest, &out.committers_digest);
    Ok(r.into_bytes())
}

/// fn 19 `sweepPast(h, channelId, rows, keepCount, day)` (§8.3).
pub fn sweep_past(
    env: &mut JNIEnv,
    handle: jlong,
    channel_id: &JByteArray,
    rows: &JByteArray,
    keep: jint,
    day: jint,
) -> MlsResult<Vec<u8>> {
    let channel_id = fixed::<32>(env, channel_id)?;
    let rows = rows_in(&bytes(env, rows)?)?;
    let keep = usize::try_from(uint(keep)?).map_err(|_| nc())?;
    let day = uint(day)?;
    let changes = with_channel(handle, &channel_id, |ctx, ch| {
        ctx.sweep_past(ch, &WrappedRows(&rows), keep, day)
    })?;
    let mut r = Tlv::ok();
    changes_out(&mut r, &changes);
    Ok(r.into_bytes())
}

/// fn 20 `trialCount(h, channelId, rows, candidateKind, candidate, held, day)` (S0-17): writes
/// nothing; `held` is the TLV list of `HELD` records (`NS`, `BLOB`), at most 32.
#[allow(clippy::too_many_arguments)]
pub fn trial_count(
    env: &mut JNIEnv,
    handle: jlong,
    channel_id: &JByteArray,
    rows: &JByteArray,
    candidate_kind: jint,
    candidate: &JByteArray,
    held: &JByteArray,
    day: jint,
) -> MlsResult<Vec<u8>> {
    let channel_id = fixed::<32>(env, channel_id)?;
    let rows = rows_in(&bytes(env, rows)?)?;
    let c = bytes(env, candidate)?;
    let cand = winner(candidate_kind, &c)?;
    let held = held_in(&bytes(env, held)?)?;
    let day = uint(day)?;
    let out = with_channel(handle, &channel_id, |ctx, ch| {
        ctx.trial_count(ch, &WrappedRows(&rows), cand, &held, day)
    })?;
    let mut r = Tlv::ok();
    r.put(Field::Candidate, &out.committer);
    for s in &out.senders {
        r.put(Field::TrialSender, s);
    }
    Ok(r.into_bytes())
}

/// The JNI-typed shims `export_jni!` points its entry points at: each converts nothing and runs
/// its body under [`guarded`].
pub mod entry {
    use super::*;

    /// `ctxOpen`
    pub fn ctx_open<'l>(mut env: JNIEnv<'l>, _c: JClass<'l>, a: JByteArray<'l>) -> jbyteArray {
        guarded(&mut env, |env| super::ctx_open(env, &a))
    }

    /// `ctxClose`
    pub fn ctx_close<'l>(mut env: JNIEnv<'l>, _c: JClass<'l>, h: jlong) -> jbyteArray {
        guarded(&mut env, |_| super::ctx_close(h))
    }

    /// `channelOpen`
    pub fn channel_open<'l>(
        mut env: JNIEnv<'l>,
        _c: JClass<'l>,
        h: jlong,
        a: JByteArray<'l>,
        b: JByteArray<'l>,
    ) -> jbyteArray {
        guarded(&mut env, |env| super::channel_open(env, h, &a, &b))
    }

    /// `channelClose`
    pub fn channel_close<'l>(
        mut env: JNIEnv<'l>,
        _c: JClass<'l>,
        h: jlong,
        a: JByteArray<'l>,
    ) -> jbyteArray {
        guarded(&mut env, |env| super::channel_close(env, h, &a))
    }

    /// `groupCreate`
    pub fn group_create<'l>(
        mut env: JNIEnv<'l>,
        _c: JClass<'l>,
        h: jlong,
        a: JByteArray<'l>,
        b: JByteArray<'l>,
        day: jint,
    ) -> jbyteArray {
        guarded(&mut env, |env| super::group_create(env, h, &a, &b, day))
    }

    /// `keyPackage`
    pub fn key_package<'l>(
        mut env: JNIEnv<'l>,
        _c: JClass<'l>,
        h: jlong,
        a: JByteArray<'l>,
        purpose: jint,
        day: jint,
    ) -> jbyteArray {
        guarded(&mut env, |env| super::key_package(env, h, &a, purpose, day))
    }

    /// `welcomeJoin`
    #[allow(clippy::too_many_arguments)]
    pub fn welcome_join<'l>(
        mut env: JNIEnv<'l>,
        _c: JClass<'l>,
        h: jlong,
        a: JByteArray<'l>,
        b: JByteArray<'l>,
        c: JByteArray<'l>,
        day: jint,
        generation: jint,
        d: JByteArray<'l>,
        anchor_kind: jint,
        e: JByteArray<'l>,
    ) -> jbyteArray {
        guarded(&mut env, |env| {
            super::welcome_join(env, h, &a, &b, &c, day, generation, &d, anchor_kind, &e)
        })
    }

    /// `receive`
    #[allow(clippy::too_many_arguments)]
    pub fn receive<'l>(
        mut env: JNIEnv<'l>,
        _c: JClass<'l>,
        h: jlong,
        a: JByteArray<'l>,
        b: JByteArray<'l>,
        epoch: jlong,
        c: JByteArray<'l>,
        day: jint,
    ) -> jbyteArray {
        guarded(&mut env, |env| {
            super::receive(env, h, &a, &b, epoch, &c, day)
        })
    }

    /// `settle`
    #[allow(clippy::too_many_arguments)]
    pub fn settle<'l>(
        mut env: JNIEnv<'l>,
        _c: JClass<'l>,
        h: jlong,
        a: JByteArray<'l>,
        b: JByteArray<'l>,
        kind: jint,
        c: JByteArray<'l>,
        generation: jint,
        day: jint,
    ) -> jbyteArray {
        guarded(&mut env, |env| {
            super::settle(env, h, &a, &b, kind, &c, generation, day)
        })
    }

    /// `clearOwn`
    pub fn clear_own<'l>(
        mut env: JNIEnv<'l>,
        _c: JClass<'l>,
        h: jlong,
        a: JByteArray<'l>,
        b: JByteArray<'l>,
        day: jint,
    ) -> jbyteArray {
        guarded(&mut env, |env| super::clear_own(env, h, &a, &b, day))
    }

    /// `commit`
    pub fn commit<'l>(
        mut env: JNIEnv<'l>,
        _c: JClass<'l>,
        h: jlong,
        a: JByteArray<'l>,
        b: JByteArray<'l>,
        c: JByteArray<'l>,
        day: jint,
    ) -> jbyteArray {
        guarded(&mut env, |env| super::commit(env, h, &a, &b, &c, day))
    }

    /// `encrypt`
    #[allow(clippy::too_many_arguments)]
    pub fn encrypt<'l>(
        mut env: JNIEnv<'l>,
        _c: JClass<'l>,
        h: jlong,
        a: JByteArray<'l>,
        b: JByteArray<'l>,
        c: JByteArray<'l>,
        seq: jint,
        day: jint,
    ) -> jbyteArray {
        guarded(&mut env, |env| super::encrypt(env, h, &a, &b, &c, seq, day))
    }

    /// `seal`
    #[allow(clippy::too_many_arguments)]
    pub fn seal<'l>(
        mut env: JNIEnv<'l>,
        _c: JClass<'l>,
        h: jlong,
        a: JByteArray<'l>,
        b: JByteArray<'l>,
        class: jint,
        c: JByteArray<'l>,
        bucket: jint,
        mode: jint,
        order_epoch: jlong,
        order_leaf: jint,
        order_seq: jint,
        d: JByteArray<'l>,
    ) -> jbyteArray {
        guarded(&mut env, |env| {
            super::seal(
                env,
                h,
                &a,
                &b,
                class,
                &c,
                bucket,
                mode,
                order_epoch,
                order_leaf,
                order_seq,
                &d,
            )
        })
    }

    /// `open`
    #[allow(clippy::too_many_arguments)]
    pub fn open<'l>(
        mut env: JNIEnv<'l>,
        _c: JClass<'l>,
        h: jlong,
        a: JByteArray<'l>,
        b: JByteArray<'l>,
        class: jint,
        c: JByteArray<'l>,
        mode: jint,
        d: JByteArray<'l>,
    ) -> jbyteArray {
        guarded(&mut env, |env| {
            super::open(env, h, &a, &b, class, &c, mode, &d)
        })
    }

    /// `generation`
    #[allow(clippy::too_many_arguments)]
    pub fn generation<'l>(
        mut env: JNIEnv<'l>,
        _c: JClass<'l>,
        h: jlong,
        a: JByteArray<'l>,
        b: JByteArray<'l>,
        generation: jint,
        open_epoch: jlong,
        c: JByteArray<'l>,
    ) -> jbyteArray {
        guarded(&mut env, |env| {
            super::generation(env, h, &a, &b, generation, open_epoch, &c)
        })
    }

    /// `inviteBuild`
    #[allow(clippy::too_many_arguments)]
    pub fn invite_build<'l>(
        mut env: JNIEnv<'l>,
        _c: JClass<'l>,
        h: jlong,
        a: JByteArray<'l>,
        b: JByteArray<'l>,
        c: JByteArray<'l>,
        generation: jint,
        expiry_day: jint,
        kdf_code: jint,
        d: JByteArray<'l>,
        carry_name: jint,
        day: jint,
    ) -> jbyteArray {
        guarded(&mut env, |env| {
            super::invite_build(
                env, h, &a, &b, &c, generation, expiry_day, kdf_code, &d, carry_name, day,
            )
        })
    }

    /// `inviteParse`
    pub fn invite_parse<'l>(
        mut env: JNIEnv<'l>,
        _c: JClass<'l>,
        h: jlong,
        a: JByteArray<'l>,
        b: JByteArray<'l>,
        c: JByteArray<'l>,
    ) -> jbyteArray {
        guarded(&mut env, |env| super::invite_parse(env, h, &a, &b, &c))
    }

    /// `joinRequest`
    pub fn join_request<'l>(
        mut env: JNIEnv<'l>,
        _c: JClass<'l>,
        h: jlong,
        a: JByteArray<'l>,
        b: JByteArray<'l>,
        c: JByteArray<'l>,
        d: JByteArray<'l>,
    ) -> jbyteArray {
        guarded(&mut env, |env| super::join_request(env, h, &a, &b, &c, &d))
    }

    /// `rejoinRequest`
    #[allow(clippy::too_many_arguments)]
    pub fn rejoin_request<'l>(
        mut env: JNIEnv<'l>,
        _c: JClass<'l>,
        h: jlong,
        a: JByteArray<'l>,
        generation: jint,
        day: jint,
        last_epoch: jlong,
        b: JByteArray<'l>,
        c: JByteArray<'l>,
    ) -> jbyteArray {
        guarded(&mut env, |env| {
            super::rejoin_request(env, h, &a, generation, day, last_epoch, &b, &c)
        })
    }

    /// `joinVerify`
    #[allow(clippy::too_many_arguments)]
    pub fn join_verify<'l>(
        mut env: JNIEnv<'l>,
        _c: JClass<'l>,
        h: jlong,
        a: JByteArray<'l>,
        b: JByteArray<'l>,
        c: JByteArray<'l>,
        d: JByteArray<'l>,
        generation: jint,
    ) -> jbyteArray {
        guarded(&mut env, |env| {
            super::join_verify(env, h, &a, &b, &c, &d, generation)
        })
    }

    /// `revealSeal`
    #[allow(clippy::too_many_arguments)]
    pub fn reveal_seal<'l>(
        mut env: JNIEnv<'l>,
        _c: JClass<'l>,
        h: jlong,
        dm: jlong,
        a: JByteArray<'l>,
        b: JByteArray<'l>,
        c: JByteArray<'l>,
        minute: jint,
        d: JByteArray<'l>,
    ) -> jbyteArray {
        guarded(&mut env, |env| {
            super::reveal_seal(env, h, dm, &a, &b, &c, minute, &d)
        })
    }

    /// `revealOpen`
    #[allow(clippy::too_many_arguments)]
    pub fn reveal_open<'l>(
        mut env: JNIEnv<'l>,
        _c: JClass<'l>,
        h: jlong,
        a: JByteArray<'l>,
        b: JByteArray<'l>,
        c: JByteArray<'l>,
        d: JByteArray<'l>,
        e: JByteArray<'l>,
        f: JByteArray<'l>,
    ) -> jbyteArray {
        guarded(&mut env, |env| {
            super::reveal_open(env, h, &a, &b, &c, &d, &e, &f)
        })
    }

    /// `contentEncode`
    pub fn content_encode<'l>(
        mut env: JNIEnv<'l>,
        _c: JClass<'l>,
        a: JByteArray<'l>,
    ) -> jbyteArray {
        guarded(&mut env, |env| super::content_encode(env, &a))
    }

    /// `contentDecode`
    pub fn content_decode<'l>(
        mut env: JNIEnv<'l>,
        _c: JClass<'l>,
        a: JByteArray<'l>,
    ) -> jbyteArray {
        guarded(&mut env, |env| super::content_decode(env, &a))
    }

    /// `roster`
    pub fn roster<'l>(
        mut env: JNIEnv<'l>,
        _c: JClass<'l>,
        h: jlong,
        a: JByteArray<'l>,
        b: JByteArray<'l>,
        day: jint,
    ) -> jbyteArray {
        guarded(&mut env, |env| super::roster(env, h, &a, &b, day))
    }

    /// `sweepPast`
    pub fn sweep_past<'l>(
        mut env: JNIEnv<'l>,
        _c: JClass<'l>,
        h: jlong,
        a: JByteArray<'l>,
        b: JByteArray<'l>,
        keep: jint,
        day: jint,
    ) -> jbyteArray {
        guarded(&mut env, |env| super::sweep_past(env, h, &a, &b, keep, day))
    }

    /// `trialCount`
    #[allow(clippy::too_many_arguments)]
    pub fn trial_count<'l>(
        mut env: JNIEnv<'l>,
        _c: JClass<'l>,
        h: jlong,
        a: JByteArray<'l>,
        b: JByteArray<'l>,
        kind: jint,
        c: JByteArray<'l>,
        d: JByteArray<'l>,
        day: jint,
    ) -> jbyteArray {
        guarded(&mut env, |env| {
            super::trial_count(env, h, &a, &b, kind, &c, &d, day)
        })
    }
}

/// Exports the `MlsNative` entry points from the calling crate (design §10.1): `ghost-client-net`
/// invokes it in `jni_bridge.rs` beside the DM export, so the closed list stays visible in the
/// crate that produces `libghost_client_net.so`, and `ghost-dm-host` invokes it too so the JVM
/// tests call exactly the shipped code. Every name is written out literally (`#[no_mangle]` takes
/// no computed name, and no proc-macro crate is approved), one `pub extern "system" fn` per entry
/// of [`CLOSED_LIST`] marked exported — what G-M6 reads, in the source and in the built library.
#[macro_export]
macro_rules! export_jni {
    () => {
        /// `MlsNative.ctxOpen` (design §10.2 fn 1).
        #[no_mangle]
        pub extern "system" fn Java_org_ghost_crypto_bridge_MlsNative_ctxOpen<'l>(
            env: ::jni::JNIEnv<'l>,
            class: ::jni::objects::JClass<'l>,
            a: ::jni::objects::JByteArray<'l>,
        ) -> ::jni::sys::jbyteArray {
            $crate::jni::entry::ctx_open(env, class, a)
        }

        /// `MlsNative.ctxClose` (fn 1).
        #[no_mangle]
        pub extern "system" fn Java_org_ghost_crypto_bridge_MlsNative_ctxClose<'l>(
            env: ::jni::JNIEnv<'l>,
            class: ::jni::objects::JClass<'l>,
            h: ::jni::sys::jlong,
        ) -> ::jni::sys::jbyteArray {
            $crate::jni::entry::ctx_close(env, class, h)
        }

        /// `MlsNative.channelOpen` (fn 2).
        #[no_mangle]
        pub extern "system" fn Java_org_ghost_crypto_bridge_MlsNative_channelOpen<'l>(
            env: ::jni::JNIEnv<'l>,
            class: ::jni::objects::JClass<'l>,
            h: ::jni::sys::jlong,
            a: ::jni::objects::JByteArray<'l>,
            b: ::jni::objects::JByteArray<'l>,
        ) -> ::jni::sys::jbyteArray {
            $crate::jni::entry::channel_open(env, class, h, a, b)
        }

        /// `MlsNative.channelClose` (fn 2).
        #[no_mangle]
        pub extern "system" fn Java_org_ghost_crypto_bridge_MlsNative_channelClose<'l>(
            env: ::jni::JNIEnv<'l>,
            class: ::jni::objects::JClass<'l>,
            h: ::jni::sys::jlong,
            a: ::jni::objects::JByteArray<'l>,
        ) -> ::jni::sys::jbyteArray {
            $crate::jni::entry::channel_close(env, class, h, a)
        }

        /// `MlsNative.groupCreate` (fn 3).
        #[no_mangle]
        pub extern "system" fn Java_org_ghost_crypto_bridge_MlsNative_groupCreate<'l>(
            env: ::jni::JNIEnv<'l>,
            class: ::jni::objects::JClass<'l>,
            h: ::jni::sys::jlong,
            a: ::jni::objects::JByteArray<'l>,
            b: ::jni::objects::JByteArray<'l>,
            day: ::jni::sys::jint,
        ) -> ::jni::sys::jbyteArray {
            $crate::jni::entry::group_create(env, class, h, a, b, day)
        }

        /// `MlsNative.keyPackage` (fn 4).
        #[no_mangle]
        pub extern "system" fn Java_org_ghost_crypto_bridge_MlsNative_keyPackage<'l>(
            env: ::jni::JNIEnv<'l>,
            class: ::jni::objects::JClass<'l>,
            h: ::jni::sys::jlong,
            a: ::jni::objects::JByteArray<'l>,
            purpose: ::jni::sys::jint,
            day: ::jni::sys::jint,
        ) -> ::jni::sys::jbyteArray {
            $crate::jni::entry::key_package(env, class, h, a, purpose, day)
        }

        /// `MlsNative.welcomeJoin` (fn 5).
        #[no_mangle]
        #[allow(clippy::too_many_arguments)]
        pub extern "system" fn Java_org_ghost_crypto_bridge_MlsNative_welcomeJoin<'l>(
            env: ::jni::JNIEnv<'l>,
            class: ::jni::objects::JClass<'l>,
            h: ::jni::sys::jlong,
            a: ::jni::objects::JByteArray<'l>,
            b: ::jni::objects::JByteArray<'l>,
            c: ::jni::objects::JByteArray<'l>,
            day: ::jni::sys::jint,
            generation: ::jni::sys::jint,
            d: ::jni::objects::JByteArray<'l>,
            anchor_kind: ::jni::sys::jint,
            e: ::jni::objects::JByteArray<'l>,
        ) -> ::jni::sys::jbyteArray {
            $crate::jni::entry::welcome_join(
                env,
                class,
                h,
                a,
                b,
                c,
                day,
                generation,
                d,
                anchor_kind,
                e,
            )
        }

        /// `MlsNative.receive` (fn 6).
        #[no_mangle]
        #[allow(clippy::too_many_arguments)]
        pub extern "system" fn Java_org_ghost_crypto_bridge_MlsNative_receive<'l>(
            env: ::jni::JNIEnv<'l>,
            class: ::jni::objects::JClass<'l>,
            h: ::jni::sys::jlong,
            a: ::jni::objects::JByteArray<'l>,
            b: ::jni::objects::JByteArray<'l>,
            epoch: ::jni::sys::jlong,
            c: ::jni::objects::JByteArray<'l>,
            day: ::jni::sys::jint,
        ) -> ::jni::sys::jbyteArray {
            $crate::jni::entry::receive(env, class, h, a, b, epoch, c, day)
        }

        /// `MlsNative.settle` (fn 7).
        #[no_mangle]
        #[allow(clippy::too_many_arguments)]
        pub extern "system" fn Java_org_ghost_crypto_bridge_MlsNative_settle<'l>(
            env: ::jni::JNIEnv<'l>,
            class: ::jni::objects::JClass<'l>,
            h: ::jni::sys::jlong,
            a: ::jni::objects::JByteArray<'l>,
            b: ::jni::objects::JByteArray<'l>,
            kind: ::jni::sys::jint,
            c: ::jni::objects::JByteArray<'l>,
            generation: ::jni::sys::jint,
            day: ::jni::sys::jint,
        ) -> ::jni::sys::jbyteArray {
            $crate::jni::entry::settle(env, class, h, a, b, kind, c, generation, day)
        }

        /// `MlsNative.clearOwn` (fn 8).
        #[no_mangle]
        pub extern "system" fn Java_org_ghost_crypto_bridge_MlsNative_clearOwn<'l>(
            env: ::jni::JNIEnv<'l>,
            class: ::jni::objects::JClass<'l>,
            h: ::jni::sys::jlong,
            a: ::jni::objects::JByteArray<'l>,
            b: ::jni::objects::JByteArray<'l>,
            day: ::jni::sys::jint,
        ) -> ::jni::sys::jbyteArray {
            $crate::jni::entry::clear_own(env, class, h, a, b, day)
        }

        /// `MlsNative.commit` (fn 9).
        #[no_mangle]
        pub extern "system" fn Java_org_ghost_crypto_bridge_MlsNative_commit<'l>(
            env: ::jni::JNIEnv<'l>,
            class: ::jni::objects::JClass<'l>,
            h: ::jni::sys::jlong,
            a: ::jni::objects::JByteArray<'l>,
            b: ::jni::objects::JByteArray<'l>,
            c: ::jni::objects::JByteArray<'l>,
            day: ::jni::sys::jint,
        ) -> ::jni::sys::jbyteArray {
            $crate::jni::entry::commit(env, class, h, a, b, c, day)
        }

        /// `MlsNative.encrypt` (fn 10).
        #[no_mangle]
        #[allow(clippy::too_many_arguments)]
        pub extern "system" fn Java_org_ghost_crypto_bridge_MlsNative_encrypt<'l>(
            env: ::jni::JNIEnv<'l>,
            class: ::jni::objects::JClass<'l>,
            h: ::jni::sys::jlong,
            a: ::jni::objects::JByteArray<'l>,
            b: ::jni::objects::JByteArray<'l>,
            c: ::jni::objects::JByteArray<'l>,
            seq: ::jni::sys::jint,
            day: ::jni::sys::jint,
        ) -> ::jni::sys::jbyteArray {
            $crate::jni::entry::encrypt(env, class, h, a, b, c, seq, day)
        }

        /// `MlsNative.seal` (fn 11).
        #[no_mangle]
        #[allow(clippy::too_many_arguments)]
        pub extern "system" fn Java_org_ghost_crypto_bridge_MlsNative_seal<'l>(
            env: ::jni::JNIEnv<'l>,
            class: ::jni::objects::JClass<'l>,
            h: ::jni::sys::jlong,
            a: ::jni::objects::JByteArray<'l>,
            b: ::jni::objects::JByteArray<'l>,
            key_class: ::jni::sys::jint,
            c: ::jni::objects::JByteArray<'l>,
            bucket: ::jni::sys::jint,
            mode: ::jni::sys::jint,
            order_epoch: ::jni::sys::jlong,
            order_leaf: ::jni::sys::jint,
            order_seq: ::jni::sys::jint,
            d: ::jni::objects::JByteArray<'l>,
        ) -> ::jni::sys::jbyteArray {
            $crate::jni::entry::seal(
                env,
                class,
                h,
                a,
                b,
                key_class,
                c,
                bucket,
                mode,
                order_epoch,
                order_leaf,
                order_seq,
                d,
            )
        }

        /// `MlsNative.open` (fn 12).
        #[no_mangle]
        #[allow(clippy::too_many_arguments)]
        pub extern "system" fn Java_org_ghost_crypto_bridge_MlsNative_open<'l>(
            env: ::jni::JNIEnv<'l>,
            class: ::jni::objects::JClass<'l>,
            h: ::jni::sys::jlong,
            a: ::jni::objects::JByteArray<'l>,
            b: ::jni::objects::JByteArray<'l>,
            key_class: ::jni::sys::jint,
            c: ::jni::objects::JByteArray<'l>,
            mode: ::jni::sys::jint,
            d: ::jni::objects::JByteArray<'l>,
        ) -> ::jni::sys::jbyteArray {
            $crate::jni::entry::open(env, class, h, a, b, key_class, c, mode, d)
        }

        /// `MlsNative.generation` (fn 13).
        #[no_mangle]
        #[allow(clippy::too_many_arguments)]
        pub extern "system" fn Java_org_ghost_crypto_bridge_MlsNative_generation<'l>(
            env: ::jni::JNIEnv<'l>,
            class: ::jni::objects::JClass<'l>,
            h: ::jni::sys::jlong,
            a: ::jni::objects::JByteArray<'l>,
            b: ::jni::objects::JByteArray<'l>,
            generation: ::jni::sys::jint,
            open_epoch: ::jni::sys::jlong,
            c: ::jni::objects::JByteArray<'l>,
        ) -> ::jni::sys::jbyteArray {
            $crate::jni::entry::generation(env, class, h, a, b, generation, open_epoch, c)
        }

        /// `MlsNative.inviteBuild` (fn 14).
        #[no_mangle]
        #[allow(clippy::too_many_arguments)]
        pub extern "system" fn Java_org_ghost_crypto_bridge_MlsNative_inviteBuild<'l>(
            env: ::jni::JNIEnv<'l>,
            class: ::jni::objects::JClass<'l>,
            h: ::jni::sys::jlong,
            a: ::jni::objects::JByteArray<'l>,
            b: ::jni::objects::JByteArray<'l>,
            c: ::jni::objects::JByteArray<'l>,
            generation: ::jni::sys::jint,
            expiry_day: ::jni::sys::jint,
            kdf_code: ::jni::sys::jint,
            d: ::jni::objects::JByteArray<'l>,
            carry_name: ::jni::sys::jint,
            day: ::jni::sys::jint,
        ) -> ::jni::sys::jbyteArray {
            $crate::jni::entry::invite_build(
                env, class, h, a, b, c, generation, expiry_day, kdf_code, d, carry_name, day,
            )
        }

        /// `MlsNative.inviteParse` (fn 14).
        #[no_mangle]
        pub extern "system" fn Java_org_ghost_crypto_bridge_MlsNative_inviteParse<'l>(
            env: ::jni::JNIEnv<'l>,
            class: ::jni::objects::JClass<'l>,
            h: ::jni::sys::jlong,
            a: ::jni::objects::JByteArray<'l>,
            b: ::jni::objects::JByteArray<'l>,
            c: ::jni::objects::JByteArray<'l>,
        ) -> ::jni::sys::jbyteArray {
            $crate::jni::entry::invite_parse(env, class, h, a, b, c)
        }

        /// `MlsNative.joinRequest` (fn 15).
        #[no_mangle]
        pub extern "system" fn Java_org_ghost_crypto_bridge_MlsNative_joinRequest<'l>(
            env: ::jni::JNIEnv<'l>,
            class: ::jni::objects::JClass<'l>,
            h: ::jni::sys::jlong,
            a: ::jni::objects::JByteArray<'l>,
            b: ::jni::objects::JByteArray<'l>,
            c: ::jni::objects::JByteArray<'l>,
            d: ::jni::objects::JByteArray<'l>,
        ) -> ::jni::sys::jbyteArray {
            $crate::jni::entry::join_request(env, class, h, a, b, c, d)
        }

        /// `MlsNative.rejoinRequest` (fn 15).
        #[no_mangle]
        #[allow(clippy::too_many_arguments)]
        pub extern "system" fn Java_org_ghost_crypto_bridge_MlsNative_rejoinRequest<'l>(
            env: ::jni::JNIEnv<'l>,
            class: ::jni::objects::JClass<'l>,
            h: ::jni::sys::jlong,
            a: ::jni::objects::JByteArray<'l>,
            generation: ::jni::sys::jint,
            day: ::jni::sys::jint,
            last_epoch: ::jni::sys::jlong,
            b: ::jni::objects::JByteArray<'l>,
            c: ::jni::objects::JByteArray<'l>,
        ) -> ::jni::sys::jbyteArray {
            $crate::jni::entry::rejoin_request(env, class, h, a, generation, day, last_epoch, b, c)
        }

        /// `MlsNative.joinVerify` (fn 15).
        #[no_mangle]
        #[allow(clippy::too_many_arguments)]
        pub extern "system" fn Java_org_ghost_crypto_bridge_MlsNative_joinVerify<'l>(
            env: ::jni::JNIEnv<'l>,
            class: ::jni::objects::JClass<'l>,
            h: ::jni::sys::jlong,
            a: ::jni::objects::JByteArray<'l>,
            b: ::jni::objects::JByteArray<'l>,
            c: ::jni::objects::JByteArray<'l>,
            d: ::jni::objects::JByteArray<'l>,
            generation: ::jni::sys::jint,
        ) -> ::jni::sys::jbyteArray {
            $crate::jni::entry::join_verify(env, class, h, a, b, c, d, generation)
        }

        /// `MlsNative.revealSeal` (fn 16, §6.9; slice S9).
        #[no_mangle]
        #[allow(clippy::too_many_arguments)]
        pub extern "system" fn Java_org_ghost_crypto_bridge_MlsNative_revealSeal<'l>(
            env: ::jni::JNIEnv<'l>,
            class: ::jni::objects::JClass<'l>,
            h: ::jni::sys::jlong,
            dm: ::jni::sys::jlong,
            a: ::jni::objects::JByteArray<'l>,
            b: ::jni::objects::JByteArray<'l>,
            c: ::jni::objects::JByteArray<'l>,
            minute: ::jni::sys::jint,
            d: ::jni::objects::JByteArray<'l>,
        ) -> ::jni::sys::jbyteArray {
            $crate::jni::entry::reveal_seal(env, class, h, dm, a, b, c, minute, d)
        }

        /// `MlsNative.revealOpen` (fn 16, §6.9; slice S9).
        #[no_mangle]
        #[allow(clippy::too_many_arguments)]
        pub extern "system" fn Java_org_ghost_crypto_bridge_MlsNative_revealOpen<'l>(
            env: ::jni::JNIEnv<'l>,
            class: ::jni::objects::JClass<'l>,
            h: ::jni::sys::jlong,
            a: ::jni::objects::JByteArray<'l>,
            b: ::jni::objects::JByteArray<'l>,
            c: ::jni::objects::JByteArray<'l>,
            d: ::jni::objects::JByteArray<'l>,
            e: ::jni::objects::JByteArray<'l>,
            f: ::jni::objects::JByteArray<'l>,
        ) -> ::jni::sys::jbyteArray {
            $crate::jni::entry::reveal_open(env, class, h, a, b, c, d, e, f)
        }

        /// `MlsNative.contentEncode` (fn 17).
        #[no_mangle]
        pub extern "system" fn Java_org_ghost_crypto_bridge_MlsNative_contentEncode<'l>(
            env: ::jni::JNIEnv<'l>,
            class: ::jni::objects::JClass<'l>,
            a: ::jni::objects::JByteArray<'l>,
        ) -> ::jni::sys::jbyteArray {
            $crate::jni::entry::content_encode(env, class, a)
        }

        /// `MlsNative.contentDecode` (fn 17).
        #[no_mangle]
        pub extern "system" fn Java_org_ghost_crypto_bridge_MlsNative_contentDecode<'l>(
            env: ::jni::JNIEnv<'l>,
            class: ::jni::objects::JClass<'l>,
            a: ::jni::objects::JByteArray<'l>,
        ) -> ::jni::sys::jbyteArray {
            $crate::jni::entry::content_decode(env, class, a)
        }

        /// `MlsNative.roster` (fn 18).
        #[no_mangle]
        pub extern "system" fn Java_org_ghost_crypto_bridge_MlsNative_roster<'l>(
            env: ::jni::JNIEnv<'l>,
            class: ::jni::objects::JClass<'l>,
            h: ::jni::sys::jlong,
            a: ::jni::objects::JByteArray<'l>,
            b: ::jni::objects::JByteArray<'l>,
            day: ::jni::sys::jint,
        ) -> ::jni::sys::jbyteArray {
            $crate::jni::entry::roster(env, class, h, a, b, day)
        }

        /// `MlsNative.sweepPast` (fn 19).
        #[no_mangle]
        pub extern "system" fn Java_org_ghost_crypto_bridge_MlsNative_sweepPast<'l>(
            env: ::jni::JNIEnv<'l>,
            class: ::jni::objects::JClass<'l>,
            h: ::jni::sys::jlong,
            a: ::jni::objects::JByteArray<'l>,
            b: ::jni::objects::JByteArray<'l>,
            keep: ::jni::sys::jint,
            day: ::jni::sys::jint,
        ) -> ::jni::sys::jbyteArray {
            $crate::jni::entry::sweep_past(env, class, h, a, b, keep, day)
        }

        /// `MlsNative.trialCount` (fn 20).
        #[no_mangle]
        #[allow(clippy::too_many_arguments)]
        pub extern "system" fn Java_org_ghost_crypto_bridge_MlsNative_trialCount<'l>(
            env: ::jni::JNIEnv<'l>,
            class: ::jni::objects::JClass<'l>,
            h: ::jni::sys::jlong,
            a: ::jni::objects::JByteArray<'l>,
            b: ::jni::objects::JByteArray<'l>,
            kind: ::jni::sys::jint,
            c: ::jni::objects::JByteArray<'l>,
            d: ::jni::objects::JByteArray<'l>,
            day: ::jni::sys::jint,
        ) -> ::jni::sys::jbyteArray {
            $crate::jni::entry::trial_count(env, class, h, a, b, kind, c, d, day)
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::result::CommitReason;

    /// The crate's own source, read by the tests that compare the closed list with what the
    /// export macro writes (G-M6's Rust half).
    const SOURCE: &str = include_str!("jni.rs");

    fn exported() -> Vec<&'static str> {
        let mut names: Vec<&str> = CLOSED_LIST
            .iter()
            .filter(|(_, _, a)| *a == Availability::Exported)
            .map(|(_, n, _)| *n)
            .collect();
        names.sort_unstable();
        names
    }

    /// Every JNI symbol the export macro writes, read from this file: the name after the prefix
    /// of each of its entry points, the macro's text only (up to its closing brace).
    fn emitted() -> Vec<String> {
        let macro_body = SOURCE
            .split("macro_rules! export_jni {")
            .nth(1)
            .and_then(|rest| rest.split("\n}\n").next())
            .expect("the export macro is in this file");
        // Spelled in pieces: no string literal of this file is a JNI symbol, which G-M6's source
        // half reads as one (review of S2b).
        let prefix = concat!(
            "pub extern \"system\" fn ",
            "Java",
            "_org_ghost_crypto_bridge_"
        );
        let mut names: Vec<String> = macro_body
            .split(prefix)
            .skip(1)
            .map(|rest| {
                rest.split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                    .next()
                    .unwrap_or_default()
                    .to_string()
            })
            .collect();
        names.sort_unstable();
        names
    }

    /// G-M6's Rust half: the symbols the export macro writes are exactly §10.2's list — with
    /// function 16 exported since slice S9 — all of class `MlsNative`, each once.
    #[test]
    fn the_export_macro_writes_exactly_the_exported_entries_of_the_closed_list() {
        let emitted = emitted();
        let mut dedup = emitted.clone();
        dedup.dedup();
        assert_eq!(dedup.len(), emitted.len(), "a symbol is written twice");
        let expected: Vec<String> = exported()
            .iter()
            .map(|n| format!("MlsNative_{n}"))
            .collect();
        assert_eq!(emitted, expected);
        assert_eq!(
            emitted.len(),
            27,
            "§10.2 lists 27 names: the 25 of S2b plus function 16's two (S9)"
        );
    }

    #[test]
    fn the_closed_list_covers_every_function_number_and_names_each_once() {
        let mut names: Vec<&str> = CLOSED_LIST.iter().map(|(_, n, _)| *n).collect();
        let count = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(
            names.len(),
            count,
            "a name appears twice on the closed list"
        );
        for number in 1..=20u8 {
            assert!(
                CLOSED_LIST.iter().any(|(n, _, _)| *n == number),
                "function {number} of §10.2 is missing from the closed list"
            );
        }
        let declared: Vec<(u8, &str)> = CLOSED_LIST
            .iter()
            .filter(|(_, _, a)| *a != Availability::Exported)
            .map(|(n, name, _)| (*n, *name))
            .collect();
        assert!(
            declared.is_empty(),
            "every function of §10.2 is exported; {declared:?} is still declared"
        );
    }

    #[test]
    fn every_exported_function_declares_the_codes_it_can_return() {
        let exported = exported();
        let listed: Vec<&str> = FUNCTION_CODES.iter().map(|(n, _)| *n).collect();
        for name in &exported {
            assert_eq!(
                listed.iter().filter(|l| *l == name).count(),
                1,
                "{name} needs exactly one row in FUNCTION_CODES"
            );
        }
        for name in &listed {
            assert!(exported.contains(name), "FUNCTION_CODES names '{name}'");
        }
        for (name, codes) in FUNCTION_CODES {
            let mut seen = codes.to_vec();
            let n = seen.len();
            seen.sort_unstable();
            seen.dedup();
            assert_eq!(seen.len(), n, "{name} lists a code twice");
            assert!(
                !codes.contains(&Code::Ok) && !codes.contains(&Code::Internal),
                "{name} lists OK or INTERNAL"
            );
        }
    }

    /// Every tag of the wire: distinct, the contiguous run `0x01 ..= ALL.len()`, each its own
    /// discriminant; the repeatable ones are a subset.
    #[test]
    fn the_field_tags_are_the_closed_contiguous_set() {
        let mut tags: Vec<u8> = Field::ALL.iter().map(|f| f.tag()).collect();
        let n = tags.len();
        tags.sort_unstable();
        tags.dedup();
        assert_eq!(tags.len(), n);
        let expected: Vec<u8> = (1..=u8::try_from(n).expect("fits")).collect();
        assert_eq!(tags, expected);
        for f in Field::ALL {
            assert_eq!(Field::from_tag(f.tag()), Some(*f));
        }
        assert_eq!(Field::from_tag(0), None);
        assert_eq!(Field::from_tag(0xff), None);
        for f in Field::REPEATABLE.iter().chain(Field::RECORDS) {
            assert!(Field::ALL.contains(f));
        }
    }

    #[test]
    fn a_reply_is_a_code_then_length_prefixed_fields() {
        let mut r = Tlv::ok();
        r.u8(Field::Standing, 1);
        r.u32(Field::Leaf, 7);
        assert_eq!(
            r.into_bytes(),
            vec![0x00, 0x5e, 0, 0, 0, 1, 1, 0x29, 0, 0, 0, 4, 0, 0, 0, 7]
        );
        assert_eq!(
            error_reply(&MlsError::commit(CommitReason::Rate)),
            vec![Code::InvalidCommit.as_u8(), 0x34, 0, 0, 0, 1, 14]
        );
        assert_eq!(
            error_reply(&MlsError::at(Code::InvalidKeyPackage, 3)),
            vec![Code::InvalidKeyPackage.as_u8(), 0x35, 0, 0, 0, 2, 0, 3]
        );
        assert_eq!(error_reply(&MlsError::new(Code::NoFit)), vec![14]);
    }

    /// Arguments decode strictly: an unknown tag, a repeated scalar, a truncated length, a tag the
    /// record does not take and a missing field are all `NON_CANONICAL`.
    #[test]
    fn arguments_decode_strictly() {
        let mut row = Tlv::new();
        row.u8(Field::Scope, 1);
        row.put(Field::Key, b"k");
        row.put(Field::Env, b"v");
        let mut rows = Tlv::new();
        rows.record(Field::Row, row);
        let good = rows.into_bytes();
        let parsed = rows_in(&good).expect("a row list");
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].scope, Scope::Group);
        assert!(rows_in(&[]).expect("empty").is_empty());
        for cut in 1..good.len() {
            assert_eq!(rows_in(&good[..cut]).err(), Some(nc()), "prefix {cut}");
        }
        let mut unknown = good.clone();
        unknown[0] = 0x7f;
        assert_eq!(rows_in(&unknown).err(), Some(nc()));
        let mut twice = Tlv::new();
        twice.u8(Field::Scope, 1);
        twice.u8(Field::Scope, 2);
        assert!(Fields::parse(&twice.into_bytes(), &[Field::Scope]).is_err());
        let mut other = Tlv::new();
        other.u8(Field::Purpose, 1);
        assert!(Fields::parse(&other.into_bytes(), &[Field::Scope]).is_err());
        let mut missing = Tlv::new();
        missing.u8(Field::Scope, 1);
        let mut rows = Tlv::new();
        rows.record(Field::Row, missing);
        assert_eq!(rows_in(&rows.into_bytes()).err(), Some(nc()));
    }

    /// A content round-trips through its record: the fields of each kind, and no field another
    /// kind owns.
    #[test]
    fn contents_cross_as_their_fields() {
        let post = ChannelContent {
            kind: crate::content::KIND_POST,
            op_id: [7; 16],
            author_minute: 29_000_000,
            timer_code: 4,
            body: Body::Post {
                text: "salut".into(),
                reply_to: Some([9; 16]),
            },
        };
        let mut t = Tlv::new();
        content_out(&mut t, &post);
        let fields = t.into_bytes();
        assert_eq!(content_in(&fields).expect("decodes"), post);
        let mut t = Tlv(fields);
        t.put(Field::Target, &[1; 16]);
        assert_eq!(content_in(&t.into_bytes()).err(), Some(nc()));
    }

    /// The registry's table holds pointers, never contexts (CRY-P9-02); a closed handle is
    /// `CRYPTO_UNAVAILABLE`, a second close too, and a caught panic leaves the surface usable.
    #[test]
    fn the_registry_holds_pointers_and_survives_a_panic() {
        assert_eq!(
            std::mem::size_of::<ContextSlot>(),
            std::mem::size_of::<usize>()
        );
        assert_eq!(
            std::mem::size_of::<Box<ChannelHandle>>(),
            std::mem::size_of::<usize>()
        );
        fn zeroizes_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        zeroizes_on_drop::<StateKey>();
        zeroizes_on_drop::<PseudonymSeed>();
        zeroizes_on_drop::<InvitePassword>();
        zeroizes_on_drop::<Zeroizing<Vec<u8>>>();
        let ctx = MlsContext::open(StateKey::from_bytes([0x22; 32])).expect("context");
        let handle = insert_context(MlsJni {
            ctx,
            channels: HashMap::new(),
        });
        assert!(FIRST_HANDLE <= handle);
        let panicked = catch_unwind(AssertUnwindSafe(|| {
            with_context(handle, |_| -> MlsResult<()> { panic!("a library panic") })
        }));
        assert!(panicked.is_err());
        assert_eq!(with_context(handle, |_| Ok(())), Ok(()));
        assert!(ctx_close(handle).is_ok());
        assert_eq!(
            ctx_close(handle).err(),
            Some(MlsError::new(Code::CryptoUnavailable))
        );
        assert_eq!(
            with_channel(handle, &[0; 32], |_, _| Ok(())).err(),
            Some(MlsError::new(Code::CryptoUnavailable))
        );
    }

    /// Each context has its own lock (review of S2b): while a call holds one context — a commit or
    /// an Argon2id can take seconds on a phone —, a call on another context and `ctxClose` of a
    /// third run at once; and a context closed during a call on it stays valid for that call and
    /// is gone for the next.
    #[test]
    fn calls_on_different_contexts_never_wait_for_each_other() {
        use std::sync::mpsc::channel;
        use std::time::Duration;
        let open = |k: u8| {
            insert_context(MlsJni {
                ctx: MlsContext::open(StateKey::from_bytes([k; 32])).expect("context"),
                channels: HashMap::new(),
            })
        };
        let (busy, other, closing) = (open(0x31), open(0x32), open(0x33));
        let (entered_tx, entered) = channel();
        let (release, release_rx) = channel::<()>();
        let holder = std::thread::spawn(move || {
            with_context(busy, |_| {
                entered_tx.send(()).expect("signal");
                // Hold the context until the test lets go (or a minute: never in a passing run).
                let _ = release_rx.recv_timeout(Duration::from_secs(60));
                Ok(())
            })
        });
        entered.recv().expect("the holder is inside its call");
        let (done_tx, done) = channel();
        let other_thread = std::thread::spawn(move || {
            let r = (
                with_context(other, |_| Ok(())),
                ctx_close(closing).map(drop),
                ctx_close(busy).map(drop),
            );
            done_tx.send(r).expect("report");
        });
        // With one lock for every context these three wait for the holder, which waits for us.
        let finished = done.recv_timeout(Duration::from_secs(20));
        release.send(()).expect("release");
        let (other_ok, close_ok, busy_close) =
            finished.expect("a call on another context waited for a busy one");
        assert_eq!(other_ok, Ok(()));
        assert_eq!(close_ok, Ok(()));
        assert_eq!(busy_close, Ok(()), "a context in use can be closed");
        assert_eq!(
            holder.join().expect("holder"),
            Ok(()),
            "the running call finished"
        );
        other_thread.join().expect("other thread");
        assert_eq!(
            with_context(busy, |_| Ok(())).err(),
            Some(MlsError::new(Code::CryptoUnavailable))
        );
        assert_eq!(
            with_context(closing, |_| Ok(())).err(),
            Some(MlsError::new(Code::CryptoUnavailable))
        );
        assert!(ctx_close(other).is_ok());
    }
}
