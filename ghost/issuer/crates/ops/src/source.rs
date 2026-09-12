//! The schedule source read by `schedule-sign`: every field of the Entitlement Schedule except
//! the key material, one directive per line (`#` starts a comment line):
//!
//! ```text
//! seq <u64>                      network <mainnet|stagenet|regtest>
//! issuer_name <ascii>            issuer_onion <56 base32>.onion:<port>
//! confirmations <u8>             invoice_blocks <u16>         grace_blocks <u16>
//! access_per_slot <u8>           trial_per_slot <u8>          invites_per_pack <u8>
//! credits_per_free_pack <u8>     min_claim_credits <u8>       max_claim_credits <u8>
//! early_window_hours <u8>        capability_quota_bytes <u64>
//! slot <0..31> <onion:port> <valid_from_week> <valid_until_week | 0>     (repeated, in order)
//! price <price_epoch> <pack_price_atomic>                                (repeated, in order)
//! keys <kind> <first_epoch> <last_epoch>                                 (repeated, in order)
//! revoke <kind> <epoch>                                                  (repeated, in order)
//! ```
//! Every scalar directive appears exactly once. The schedule lists its keys in the order of the
//! `keys` lines, epochs ascending within a line; the key material comes from public entries or the
//! previous schedule. Rules 1-6 are not checked here: `schedule-sign` verifies the signed result.

use ghost_entitlement::monero::MoneroNetwork;
use ghost_entitlement::schedule::{Constants, PriceEntry, ScheduleContent, SlotEntry};
use ghost_entitlement::Kind;

use crate::args::{parse_kind, parse_u64};

/// At most this many keys in one `keys` line (a schedule holds at most 65 535 keys in all).
pub const MAX_KEYS_PER_LINE: u64 = 4096;

const SCALARS: [&str; 15] = [
    "seq",
    "network",
    "issuer_name",
    "issuer_onion",
    "confirmations",
    "invoice_blocks",
    "grace_blocks",
    "access_per_slot",
    "trial_per_slot",
    "invites_per_pack",
    "credits_per_free_pack",
    "min_claim_credits",
    "max_claim_credits",
    "early_window_hours",
    "capability_quota_bytes",
];

/// A parsed source: the schedule content without keys, and the key ranges it lists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Source {
    pub content: ScheduleContent,
    pub key_ranges: Vec<(Kind, u64, u64)>,
}

/// Why a source was refused: the 1-based line (0 when a directive is missing), the directive and
/// the reason, all static words for the report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceError {
    pub line: u64,
    pub directive: &'static str,
    pub reason: &'static str,
}

fn err(line: usize, directive: &'static str, reason: &'static str) -> SourceError {
    SourceError {
        line: line as u64,
        directive,
        reason,
    }
}

fn network(text: &str) -> Option<MoneroNetwork> {
    match text {
        "mainnet" => Some(MoneroNetwork::Mainnet),
        "stagenet" => Some(MoneroNetwork::Stagenet),
        "regtest" => Some(MoneroNetwork::Regtest),
        _ => None,
    }
}

fn number<T: TryFrom<u64>>(text: &str) -> Option<T> {
    parse_u64(text).and_then(|n| T::try_from(n).ok())
}

pub fn parse(text: &str) -> Result<Source, SourceError> {
    let mut scalars: [Option<&str>; SCALARS.len()] = [None; SCALARS.len()];
    let mut slots = Vec::new();
    let mut prices = Vec::new();
    let mut key_ranges = Vec::new();
    let mut revoked = Vec::new();
    for (index, raw) in text.lines().enumerate() {
        let n = index + 1;
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let tokens: Vec<&str> = line.split_whitespace().collect();
        let (head, args) = tokens.split_first().ok_or(err(n, "line", "format"))?;
        if let Some(i) = SCALARS.iter().position(|s| s == head) {
            let [value] = args else {
                return Err(err(n, SCALARS[i], "arity"));
            };
            if scalars[i].replace(value).is_some() {
                return Err(err(n, SCALARS[i], "duplicate"));
            }
            continue;
        }
        match *head {
            "slot" => {
                let [slot, onion, from, until] = args else {
                    return Err(err(n, "slot", "arity"));
                };
                slots.push(SlotEntry {
                    slot: number(slot).ok_or(err(n, "slot", "number"))?,
                    onion: (*onion).to_string(),
                    valid_from_week: number(from).ok_or(err(n, "slot", "number"))?,
                    valid_until_week: number(until).ok_or(err(n, "slot", "number"))?,
                });
            }
            "price" => {
                let [epoch, price] = args else {
                    return Err(err(n, "price", "arity"));
                };
                prices.push(PriceEntry {
                    price_epoch: number(epoch).ok_or(err(n, "price", "number"))?,
                    pack_price_atomic: number(price).ok_or(err(n, "price", "number"))?,
                });
            }
            "keys" => {
                let [kind, first, last] = args else {
                    return Err(err(n, "keys", "arity"));
                };
                let kind = parse_kind(kind).ok_or(err(n, "keys", "kind"))?;
                let first: u64 = number(first).ok_or(err(n, "keys", "number"))?;
                let last: u64 = number(last).ok_or(err(n, "keys", "number"))?;
                if last < first || last - first >= MAX_KEYS_PER_LINE {
                    return Err(err(n, "keys", "range"));
                }
                key_ranges.push((kind, first, last));
            }
            "revoke" => {
                let [kind, epoch] = args else {
                    return Err(err(n, "revoke", "arity"));
                };
                revoked.push((
                    parse_kind(kind).ok_or(err(n, "revoke", "kind"))?,
                    number(epoch).ok_or(err(n, "revoke", "number"))?,
                ));
            }
            _ => return Err(err(n, "line", "unknown-directive")),
        }
    }

    let mut values = [""; SCALARS.len()];
    for (i, value) in scalars.iter().enumerate() {
        values[i] = value.ok_or(err(0, SCALARS[i], "missing"))?;
    }
    let scalar = |i: usize| values[i];
    let num = |i: usize| -> Result<u64, SourceError> {
        parse_u64(scalar(i)).ok_or(err(0, SCALARS[i], "number"))
    };
    let small = |i: usize| -> Result<u8, SourceError> {
        number(scalar(i)).ok_or(err(0, SCALARS[i], "number"))
    };
    let medium = |i: usize| -> Result<u16, SourceError> {
        number(scalar(i)).ok_or(err(0, SCALARS[i], "number"))
    };
    let content = ScheduleContent {
        seq: num(0)?,
        network: network(scalar(1)).ok_or(err(0, SCALARS[1], "network"))?,
        issuer_name: scalar(2).to_string(),
        issuer_onion: scalar(3).to_string(),
        constants: Constants {
            confirmations: small(4)?,
            invoice_blocks: medium(5)?,
            grace_blocks: medium(6)?,
            access_per_slot: small(7)?,
            trial_per_slot: small(8)?,
            invites_per_pack: small(9)?,
            credits_per_free_pack: small(10)?,
            min_claim_credits: small(11)?,
            max_claim_credits: small(12)?,
            early_window_hours: small(13)?,
            capability_quota_bytes: num(14)?,
        },
        slots,
        prices,
        keys: Vec::new(),
        revoked,
    };
    Ok(Source {
        content,
        key_ranges,
    })
}
