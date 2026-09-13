//! The only module of the operator tools that writes to the console (design §14.1, §19.17;
//! ADR-26 point 7). A line is a fixed code followed by `field=value` pairs; codes and field names
//! are closed enums, and a value is a number, lowercase hex, a v3 onion host name rendered from its
//! 32-byte service key (`<56 base32>.onion`, what Tor writes to `HiddenServiceDir/hostname`), or a
//! word from a static table (kind, network, reason, flag name). No path, message or other runtime
//! string can reach the console.

use ghost_entitlement::monero::MoneroNetwork;
use ghost_entitlement::onion::hostname;
use ghost_entitlement::{Kind, ScheduleError};
use ghost_issuer::reconcile::Mismatch;

/// The first word of a report line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Code {
    Usage,
    IoError,
    InputRefused,
    CustodySecretCreated,
    ScheduleKeyCreated,
    KeyCreated,
    KeyRefused,
    KeyMissing,
    KeyConflict,
    SealKeyReady,
    SealLoadWritten,
    SealRefused,
    EsSigned,
    EsOk,
    EsRefused,
    EsAppendOnly,
    DirectoryOk,
    DirectoryRefused,
    OnionKeyCreated,
    OpsKeyCreated,
    PayoutAccepted,
    PayoutRefused,
    EntryState,
    AckWritten,
    ReconciliationOk,
    ReconciliationMismatch,
    CountersWritten,
    SegmentPruned,
    JournalPruned,
    PruneRefused,
    IssuerOnion,
    SlotOnion,
}

impl Code {
    pub const ALL: [Code; 32] = [
        Code::Usage,
        Code::IoError,
        Code::InputRefused,
        Code::CustodySecretCreated,
        Code::ScheduleKeyCreated,
        Code::KeyCreated,
        Code::KeyRefused,
        Code::KeyMissing,
        Code::KeyConflict,
        Code::SealKeyReady,
        Code::SealLoadWritten,
        Code::SealRefused,
        Code::EsSigned,
        Code::EsOk,
        Code::EsRefused,
        Code::EsAppendOnly,
        Code::DirectoryOk,
        Code::DirectoryRefused,
        Code::OnionKeyCreated,
        Code::OpsKeyCreated,
        Code::PayoutAccepted,
        Code::PayoutRefused,
        Code::EntryState,
        Code::AckWritten,
        Code::ReconciliationOk,
        Code::ReconciliationMismatch,
        Code::CountersWritten,
        Code::SegmentPruned,
        Code::JournalPruned,
        Code::PruneRefused,
        Code::IssuerOnion,
        Code::SlotOnion,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Code::Usage => "USAGE",
            Code::IoError => "IO_ERROR",
            Code::InputRefused => "INPUT_REFUSED",
            Code::CustodySecretCreated => "CUSTODY_SECRET_CREATED",
            Code::ScheduleKeyCreated => "SCHEDULE_KEY_CREATED",
            Code::KeyCreated => "KEY_CREATED",
            Code::KeyRefused => "KEY_REFUSED",
            Code::KeyMissing => "KEY_MISSING",
            Code::KeyConflict => "KEY_CONFLICT",
            Code::SealKeyReady => "SEAL_KEY_READY",
            Code::SealLoadWritten => "SEAL_LOAD_WRITTEN",
            Code::SealRefused => "SEAL_REFUSED",
            Code::EsSigned => "ES_SIGNED",
            Code::EsOk => "ES_OK",
            Code::EsRefused => "ES_REFUSED",
            Code::EsAppendOnly => "ES_APPEND_ONLY",
            Code::DirectoryOk => "DIRECTORY_OK",
            Code::DirectoryRefused => "DIRECTORY_REFUSED",
            Code::OnionKeyCreated => "ONION_KEY_CREATED",
            Code::OpsKeyCreated => "OPS_KEY_CREATED",
            Code::PayoutAccepted => "PAYOUT_ACCEPTED",
            Code::PayoutRefused => "PAYOUT_REFUSED",
            Code::EntryState => "ENTRY_STATE",
            Code::AckWritten => "ACK_WRITTEN",
            Code::ReconciliationOk => "RECONCILIATION_OK",
            Code::ReconciliationMismatch => "RECONCILIATION_MISMATCH",
            Code::CountersWritten => "COUNTERS_WRITTEN",
            Code::SegmentPruned => "SEGMENT_PRUNED",
            Code::JournalPruned => "JOURNAL_PRUNED",
            Code::PruneRefused => "PRUNE_REFUSED",
            Code::IssuerOnion => "ISSUER_ONION",
            Code::SlotOnion => "SLOT_ONION",
        }
    }

    /// Failure lines go to stderr, the others to stdout.
    pub fn is_failure(self) -> bool {
        matches!(
            self,
            Code::Usage
                | Code::IoError
                | Code::InputRefused
                | Code::KeyRefused
                | Code::KeyMissing
                | Code::KeyConflict
                | Code::SealRefused
                | Code::EsRefused
                | Code::DirectoryRefused
                | Code::PayoutRefused
                | Code::ReconciliationMismatch
                | Code::PruneRefused
        )
    }
}

/// The name of a `field=value` pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Field {
    Reason,
    Flag,
    File,
    Line,
    Directive,
    Kind,
    Epoch,
    KeyId,
    Public,
    Entries,
    Seq,
    Network,
    FirstWeek,
    LastWeek,
    Weeks,
    Keys,
    Slots,
    Sha256,
    ScheduleKey,
    PreviousSeq,
    Week,
    Slot,
    History,
    Batch,
    Entry,
    State,
    Total,
    PaidSoFar,
    Incoming,
    Txid,
    Images,
    Relays,
    Refused,
    Counters,
    Removed,
    Kept,
    FirstSeq,
    LastSeq,
    Applied,
    Onion,
    Port,
}

impl Field {
    pub const ALL: [Field; 41] = [
        Field::Reason,
        Field::Flag,
        Field::File,
        Field::Line,
        Field::Directive,
        Field::Kind,
        Field::Epoch,
        Field::KeyId,
        Field::Public,
        Field::Entries,
        Field::Seq,
        Field::Network,
        Field::FirstWeek,
        Field::LastWeek,
        Field::Weeks,
        Field::Keys,
        Field::Slots,
        Field::Sha256,
        Field::ScheduleKey,
        Field::PreviousSeq,
        Field::Week,
        Field::Slot,
        Field::History,
        Field::Batch,
        Field::Entry,
        Field::State,
        Field::Total,
        Field::PaidSoFar,
        Field::Incoming,
        Field::Txid,
        Field::Images,
        Field::Relays,
        Field::Refused,
        Field::Counters,
        Field::Removed,
        Field::Kept,
        Field::FirstSeq,
        Field::LastSeq,
        Field::Applied,
        Field::Onion,
        Field::Port,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Field::Reason => "reason",
            Field::Flag => "flag",
            Field::File => "file",
            Field::Line => "line",
            Field::Directive => "directive",
            Field::Kind => "kind",
            Field::Epoch => "epoch",
            Field::KeyId => "key_id",
            Field::Public => "public",
            Field::Entries => "entries",
            Field::Seq => "seq",
            Field::Network => "network",
            Field::FirstWeek => "first_week",
            Field::LastWeek => "last_week",
            Field::Weeks => "weeks",
            Field::Keys => "keys",
            Field::Slots => "slots",
            Field::Sha256 => "sha256",
            Field::ScheduleKey => "schedule_key",
            Field::PreviousSeq => "previous_seq",
            Field::Week => "week",
            Field::Slot => "slot",
            Field::History => "history",
            Field::Batch => "batch",
            Field::Entry => "entry",
            Field::State => "state",
            Field::Total => "total",
            Field::PaidSoFar => "paid_so_far",
            Field::Incoming => "incoming",
            Field::Txid => "txid",
            Field::Images => "images",
            Field::Relays => "relays",
            Field::Refused => "refused",
            Field::Counters => "counters",
            Field::Removed => "removed",
            Field::Kept => "kept",
            Field::FirstSeq => "first_seq",
            Field::LastSeq => "last_seq",
            Field::Applied => "applied",
            Field::Onion => "onion",
            Field::Port => "port",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Num(u64),
    Hex(Vec<u8>),
    Word(&'static str),
    /// A v3 onion service key, rendered as its host name `<56 base32>.onion`.
    Onion([u8; 32]),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Line {
    pub code: Code,
    pub fields: Vec<(Field, Value)>,
}

impl Line {
    pub fn new(code: Code) -> Self {
        Self {
            code,
            fields: Vec::new(),
        }
    }

    pub fn num(mut self, field: Field, value: u64) -> Self {
        self.fields.push((field, Value::Num(value)));
        self
    }

    pub fn hex(mut self, field: Field, bytes: &[u8]) -> Self {
        self.fields.push((field, Value::Hex(bytes.to_vec())));
        self
    }

    pub fn word(mut self, field: Field, word: &'static str) -> Self {
        self.fields.push((field, Value::Word(word)));
        self
    }

    /// The onion service with service key `key`, as its host name.
    pub fn onion(mut self, field: Field, key: &[u8; 32]) -> Self {
        self.fields.push((field, Value::Onion(*key)));
        self
    }

    pub fn kind_epoch(self, kind: Kind, epoch: u64) -> Self {
        self.word(Field::Kind, ghost_issuer::custody::kind_name(kind))
            .num(Field::Epoch, epoch)
    }

    /// The text of the line: `CODE field=value ...`.
    pub fn render(&self) -> String {
        let mut out = String::from(self.code.name());
        for (field, value) in &self.fields {
            out.push(' ');
            out.push_str(field.name());
            out.push('=');
            match value {
                Value::Num(n) => out.push_str(&n.to_string()),
                Value::Hex(bytes) => out.push_str(&crate::hexfmt::encode(bytes)),
                Value::Word(w) => out.push_str(w),
                Value::Onion(key) => out.push_str(&hostname(key)),
            }
        }
        out
    }
}

/// Where report lines go: the console in the binary, a vector in tests.
pub trait Sink {
    fn emit(&mut self, line: Line);
}

/// Writes failure lines to stderr and all others to stdout.
pub struct Console;

impl Sink for Console {
    fn emit(&mut self, line: Line) {
        if line.code.is_failure() {
            eprintln!("{}", line.render());
        } else {
            println!("{}", line.render());
        }
    }
}

impl Sink for Vec<Line> {
    fn emit(&mut self, line: Line) {
        self.push(line);
    }
}

pub fn network_name(network: MoneroNetwork) -> &'static str {
    match network {
        MoneroNetwork::Mainnet => "mainnet",
        MoneroNetwork::Stagenet => "stagenet",
        MoneroNetwork::Regtest => "regtest",
    }
}

/// A reconciliation mismatch as a line: its kebab-case word and the week or epoch it names.
pub fn mismatch_line(m: &Mismatch) -> Line {
    let line = Line::new(Code::ReconciliationMismatch);
    match *m {
        Mismatch::SignedAccess { week } => line
            .word(Field::Reason, "signed-access")
            .num(Field::Week, week),
        Mismatch::SignedInvite { epoch } => line
            .word(Field::Reason, "signed-invite")
            .num(Field::Epoch, epoch),
        Mismatch::SignedCredit { epoch } => line
            .word(Field::Reason, "signed-credit")
            .num(Field::Epoch, epoch),
        Mismatch::CreditsExceedSigned { epoch } => line
            .word(Field::Reason, "credits-exceed-signed")
            .num(Field::Epoch, epoch),
        Mismatch::XmrCredited { base_week } => line
            .word(Field::Reason, "xmr-credited")
            .num(Field::Week, base_week),
        Mismatch::DiscountValue => line.word(Field::Reason, "discount-value"),
        Mismatch::PayoutValue => line.word(Field::Reason, "payout-value"),
        Mismatch::RelayRedemptions { week } => line
            .word(Field::Reason, "relay-redemptions")
            .num(Field::Week, week),
        Mismatch::ViewBelowCredited => line.word(Field::Reason, "view-below-credited"),
        Mismatch::PayoutCap => line.word(Field::Reason, "payout-cap"),
    }
}

/// The kebab-case word of a schedule rule failure.
pub fn schedule_error(e: ScheduleError) -> &'static str {
    match e {
        ScheduleError::Encoding => "encoding",
        ScheduleError::Network => "network",
        ScheduleError::NoPinnedKey => "no-pinned-key",
        ScheduleError::Signature => "signature",
        ScheduleError::IssuerName => "issuer-name",
        ScheduleError::Onion => "onion",
        ScheduleError::Constants => "constants",
        ScheduleError::SlotTable => "slot-table",
        ScheduleError::PriceTable => "price-table",
        ScheduleError::DuplicateKey => "duplicate-key",
        ScheduleError::KeyFormat => "key-format",
        ScheduleError::KeyProof => "key-proof",
        ScheduleError::Coverage => "coverage",
        ScheduleError::Revocation => "revocation",
        ScheduleError::Rollback => "rollback",
        ScheduleError::KeyChanged => "key-changed",
        ScheduleError::SlotSetChanged => "slot-set-changed",
        ScheduleError::PriceChanged => "price-changed",
        ScheduleError::RevocationDropped => "revocation-dropped",
        ScheduleError::RegtestRefused => "regtest-refused",
    }
}
