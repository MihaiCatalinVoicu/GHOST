//! The issuer's offline operator tools (Phase 8 design §3.3, §5.1, §14.1, §19.17; ADR-26 point 7).
//!
//! ```text
//! ghost-issuer-ops keygen --new-custody-secret <file>
//! ghost-issuer-ops keygen --new-schedule-key <file>
//! ghost-issuer-ops keygen --kind <access|invite|credit> --from-epoch <e> --count <n>
//!                         --custody-secret <file> --public-dir <dir> --sealed-dir <dir>
//! ghost-issuer-ops keys-seal --schedule <es> [--schedule-public-key <hex>] --custody-secret <file>
//!                            --sealed-dir <dir> --from-week <w> --through-week <w> --out <file>
//! ghost-issuer-ops schedule-sign --source <file> --schedule-key <file> [--public-dir <dir>]
//!                                [--previous <es>] --out <es>
//! ghost-issuer-ops schedule-verify --schedule <es> [--schedule-public-key <hex>] [--previous <es>]...
//!                                  [--relay-directory <file> --now <unix seconds>]
//! ghost-issuer-ops onion-keygen --hs-dir <dir>
//! ghost-issuer-ops keygen --new-ops-key <file>
//! ghost-issuer-ops payout-check --batch <file> --ops-public-key <hex> --network <name>
//!                               --view-dump <json> --restore-height <h> --ledger <file>
//! ghost-issuer-ops payout-entry --ledger <file> --batch-id <hex> --entry <k>
//!                               --to <built|signed|submitted|confirmed|abandoned>
//!                               [--raw-tx <hex file> --txid <hex>] [--transfer <json>]
//!                               [--spent-status <json>]
//! ghost-issuer-ops payout-ack --ledger <file> --batch <file> --ops-public-key <hex> --out <file>
//! ghost-issuer-ops counters-export --database <issuer.redb copy> --out <file>
//! ghost-issuer-ops reconcile-check --database <issuer.redb copy> --schedule <es>
//!                                  [--schedule-public-key <hex>] --now <unix seconds>
//!                                  [--relay-counts <file>]...
//! ghost-issuer-ops reconcile-check --counters <file> --schedule <es>
//!                                  [--schedule-public-key <hex>] --now <unix seconds>
//!                                  [--relay-counts <file>]... [--view-dump <json>
//!                                  --restore-height <h> [--ledger <file>]]
//! ```
//!
//! - `keygen` (runbook K1): a custody secret, an Ed25519 schedule key, or RSA-2048 token keys for
//!   consecutive epochs of one kind (the epoch of an ACCESS key is its ISO week index). Each token
//!   key comes from the reference signer's key generation, passes the ceremony's prime checks and
//!   gets its permutation proof through `CheckedSigner`; its public entry and its sealed private key
//!   are written to new files (an existing file is never replaced).
//! - `keys-seal` (runbook K3): the `k_seal` values the issuer needs for access weeks
//!   `[from-week, through-week]` (with the invite and credit epochs they touch and the credit epoch
//!   before them, which `RefreshCredit` still uses), each proven to open its sealed file into the
//!   key its ES entry names, written to a load file. The runbook passes `from-week = w - 6` (keys
//!   still referenced by open invoices) and `through-week = w + 6` (§19.1).
//! - `schedule-sign` (K1): the ES from a source file, its keys from public entries or the previous
//!   ES; the result is verified (rules 1-4, and rule 5 against `--previous`) before it is written.
//! - `schedule-verify`: rules 1-4 under the pinned schedule key (or an explicit one for test and
//!   pre-pin schedules), rule 5 over the earlier versions (`--previous` repeated, oldest first: each
//!   against all before it, the schedule against all of them), and the relay directory check of
//!   §19.12 for the current and the next week.
//! - `onion-keygen` (§19.17 point 1): a Tor v3 onion service key set (`hs_ed25519_secret_key`,
//!   `hs_ed25519_public_key`, `hostname`) in a new `HiddenServiceDir`, so a schedule can name a
//!   relay's or the issuer's onion before the service first starts. The report carries the public
//!   key only.
//! - `keygen --new-ops-key` (runbook P1): the Ed25519 ops key whose seed the issuer's
//!   `ops_key_file` holds; the workstation checks batch files under its public key.
//! - `payout-check`, `payout-entry`, `payout-ack` (§9.5 steps 2–4, §19.7): the payout
//!   workstation's checks and ledger ([`workstation`], [`ledger`]).
//! - `counters-export`, `reconcile-check` (§6.9, runbook R2): the reconciliation invariants of
//!   the issuer's counters with the relay aggregates, read from an `issuer.redb` snapshot on the
//!   issuer host, or from the counters file `counters-export` writes there, which is the only
//!   issuer input the workstation checks together with its own view and ledger
//!   ([`reconcile_check`]).
//!
//! Output: fixed-vocabulary lines through [`report`] only (exit 0 ok, 1 refused, 2 usage). Files
//! are written only by [`output`].
#![forbid(unsafe_code)]

mod args;
pub mod directory;
mod hexfmt;
mod input;
mod keygen;
mod keys_seal;
pub mod ledger;
pub mod onion_keygen;
pub mod output;
pub mod public_entry;
pub mod rawtx;
pub mod reconcile_check;
pub mod report;
mod schedule_sign;
mod schedule_verify;
pub mod source;
pub mod workstation;

use std::ffi::OsString;
use std::process::ExitCode;

use report::{Code, Field, Line, Sink};

/// How a command ended; the process exit code is [`Status::code`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Ok,
    /// A check failed or an input was refused.
    Refused,
    /// The command line is malformed.
    Usage,
}

impl Status {
    pub fn code(self) -> u8 {
        match self {
            Status::Ok => 0,
            Status::Refused => 1,
            Status::Usage => 2,
        }
    }
}

/// A command's failure: the line to report and the resulting status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure {
    pub status: Status,
    pub line: Line,
}

impl Failure {
    pub(crate) fn usage(reason: &'static str, flag: Option<&'static str>) -> Self {
        let mut line = Line::new(Code::Usage).word(Field::Reason, reason);
        if let Some(flag) = flag {
            line = line.word(Field::Flag, flag);
        }
        Self {
            status: Status::Usage,
            line,
        }
    }

    pub(crate) fn refused(line: Line) -> Self {
        Self {
            status: Status::Refused,
            line,
        }
    }
}

/// Runs one command; every report line goes to `sink`.
pub fn execute(argv: &[String], sink: &mut dyn Sink) -> Status {
    let Some((command, rest)) = argv.split_first() else {
        sink.emit(Failure::usage("missing-command", None).line);
        return Status::Usage;
    };
    let result = match command.as_str() {
        "keygen" => keygen::run(rest, sink),
        "keys-seal" => keys_seal::run(rest, sink),
        "schedule-sign" => schedule_sign::run(rest, sink),
        "schedule-verify" => schedule_verify::run(rest, sink),
        "onion-keygen" => onion_keygen::run(rest, sink),
        "payout-check" => workstation::check(rest, sink),
        "payout-entry" => workstation::entry(rest, sink),
        "payout-ack" => workstation::ack(rest, sink),
        "reconcile-check" => reconcile_check::run(rest, sink),
        "counters-export" => reconcile_check::export(rest, sink),
        _ => Err(Failure::usage("unknown-command", None)),
    };
    match result {
        Ok(()) => Status::Ok,
        Err(failure) => {
            sink.emit(failure.line);
            failure.status
        }
    }
}

/// The binary's entry point: arguments as the OS passed them, lines to the console.
pub fn run(args: impl IntoIterator<Item = OsString>) -> ExitCode {
    let mut console = report::Console;
    let mut argv = Vec::new();
    for arg in args {
        match arg.into_string() {
            Ok(a) => argv.push(a),
            Err(_) => {
                console.emit(Failure::usage("argument-not-utf8", None).line);
                return ExitCode::from(Status::Usage.code());
            }
        }
    }
    ExitCode::from(execute(&argv, &mut console).code())
}
