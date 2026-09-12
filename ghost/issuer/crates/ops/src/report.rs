//! The only module of the operator tools that writes to the console (design §14.1, §19.17;
//! ADR-26 point 7). A line is a fixed code followed by `field=value` pairs; codes and field names
//! are closed enums, and a value is a number, lowercase hex, or a word from a static table (kind,
//! network, reason, flag name). No path, message or other runtime string can reach the console.

use ghost_entitlement::monero::MoneroNetwork;
use ghost_entitlement::{Kind, ScheduleError};

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
}

impl Code {
    pub const ALL: [Code; 18] = [
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
}

impl Field {
    pub const ALL: [Field; 23] = [
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
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Num(u64),
    Hex(Vec<u8>),
    Word(&'static str),
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
