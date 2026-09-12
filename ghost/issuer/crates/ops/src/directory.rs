//! The relay directory the Entitlement Schedule is checked against (design §19.12 point 2): every
//! slot onion of the current and the next week must be a directory relay, and three slots of the
//! week can be chosen whose relays span at least two operators (the drop-slot rule).
//!
//! ```text
//! relay <56 base32>.onion:<port> <operator id, 16 bytes in lowercase hex>
//! ```
//! One relay per line, `#` starts a comment line. The client's relay directory carries the same
//! pair (`RelayEntry`: onion address, 16-byte operator id).

use std::collections::{BTreeMap, BTreeSet};

use ghost_entitlement::grid;
use ghost_entitlement::onion::Onion;
use ghost_entitlement::Schedule;

use crate::hexfmt;

pub const OPERATOR_ID_LEN: usize = 16;
/// A drop uses three slots (design §8.2).
pub const DROP_SLOTS: usize = 3;
/// A drop's three relays span at least two operators (design §19.12).
pub const MIN_DROP_OPERATORS: usize = 2;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Directory {
    relays: BTreeMap<String, [u8; OPERATOR_ID_LEN]>,
}

/// A refused directory file: 1-based line and reason word.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirectoryError {
    pub line: u64,
    pub reason: &'static str,
}

/// A week whose slots fail the check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WeekFailure {
    pub week: u64,
    pub slot: Option<u8>,
    pub reason: &'static str,
}

impl Directory {
    pub fn parse(text: &str) -> Result<Self, DirectoryError> {
        let mut relays = BTreeMap::new();
        for (index, raw) in text.lines().enumerate() {
            let err = |reason| DirectoryError {
                line: index as u64 + 1,
                reason,
            };
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let tokens: Vec<&str> = line.split_whitespace().collect();
            let ["relay", onion, operator] = tokens.as_slice() else {
                return Err(err("format"));
            };
            let canonical = Onion::parse(onion).is_ok_and(|o| o.format() == *onion);
            if !canonical {
                return Err(err("onion"));
            }
            let operator: [u8; OPERATOR_ID_LEN] = hexfmt::decode(operator)
                .and_then(|b| b.try_into().ok())
                .ok_or(err("operator"))?;
            if relays.insert((*onion).to_string(), operator).is_some() {
                return Err(err("duplicate"));
            }
        }
        if relays.is_empty() {
            return Err(DirectoryError {
                line: 0,
                reason: "empty",
            });
        }
        Ok(Self { relays })
    }

    pub fn operator(&self, onion: &str) -> Option<&[u8; OPERATOR_ID_LEN]> {
        self.relays.get(onion)
    }

    /// Checks the weeks `week(now)` and `week(now) + 1` that the schedule covers; returns how many
    /// weeks were checked (0 when the schedule covers neither).
    pub fn check(&self, schedule: &Schedule, now_unix: u64) -> Result<u64, WeekFailure> {
        let current = grid::week(now_unix);
        let mut checked = 0;
        for week in [current, current.saturating_add(1)] {
            if week < schedule.first_access_week() || week > schedule.last_access_week() {
                continue;
            }
            checked += 1;
            let slots = schedule.slots_in_week(week);
            let mut operators = BTreeSet::new();
            for &slot in &slots {
                let operator = schedule
                    .slot_onion(slot, week)
                    .and_then(|onion| self.operator(onion))
                    .ok_or(WeekFailure {
                        week,
                        slot: Some(slot),
                        reason: "onion-not-in-directory",
                    })?;
                operators.insert(operator);
            }
            if slots.len() < DROP_SLOTS {
                return Err(WeekFailure {
                    week,
                    slot: None,
                    reason: "fewer-than-three-slots",
                });
            }
            if operators.len() < MIN_DROP_OPERATORS {
                return Err(WeekFailure {
                    week,
                    slot: None,
                    reason: "single-operator",
                });
            }
        }
        Ok(checked)
    }
}
