//! The epoch grid (Phase 8 design §4.1). Access periods are ISO weeks (Monday 00:00 UTC), invite
//! epochs are 4 weeks, credit and price epochs 13 weeks. Every epoch travels as an 8-byte
//! big-endian `epoch_id`, which keeps the T1 `period_id` at 8 bytes.

/// Seconds per week.
pub const WEEK_SECS: u64 = 604_800;
/// Seconds per day (activation slots are UTC days, design §12.3).
pub const DAY_SECS: u64 = 86_400;
/// Moves the Unix epoch (a Thursday) to Monday 1970-01-05 00:00 UTC.
pub const WEEK_OFFSET_SECS: u64 = 345_600;
/// Weeks per invite epoch.
pub const WEEKS_PER_INVITE_EPOCH: u64 = 4;
/// Weeks per credit (and price) epoch.
pub const WEEKS_PER_CREDIT_EPOCH: u64 = 13;
/// A week's access tokens stay acceptable until one hour after the week ends (design §3.4).
pub const LATE_WINDOW_SECS: u64 = 3_600;

/// Token kind; the byte is `kind_byte` of the redemption context and of the ES key table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Kind {
    /// Relay write access for one ISO week at one relay slot.
    Access,
    /// An invite (4-week epoch), redeemed at the issuer for a trial.
    Invite,
    /// A referral credit (13-week epoch), redeemed at the issuer.
    Credit,
}

impl Kind {
    pub const ALL: [Kind; 3] = [Kind::Access, Kind::Invite, Kind::Credit];

    pub fn byte(self) -> u8 {
        match self {
            Kind::Access => 0x01,
            Kind::Invite => 0x02,
            Kind::Credit => 0x03,
        }
    }

    pub fn from_byte(b: u8) -> Option<Kind> {
        match b {
            0x01 => Some(Kind::Access),
            0x02 => Some(Kind::Invite),
            0x03 => Some(Kind::Credit),
            _ => None,
        }
    }

    /// The epoch of this kind that contains access week `week`.
    pub fn epoch_of_week(self, week: u64) -> u64 {
        match self {
            Kind::Access => week,
            Kind::Invite => invite_epoch(week),
            Kind::Credit => credit_epoch(week),
        }
    }
}

/// `week(t) = floor((t - 345 600) / 604 800)` for Unix seconds t; instants before Monday
/// 1970-01-05 map to week 0.
pub fn week(unix_secs: u64) -> u64 {
    unix_secs.saturating_sub(WEEK_OFFSET_SECS) / WEEK_SECS
}

/// First second of week p (saturating, so no wire value can overflow it).
pub fn week_start(p: u64) -> u64 {
    WEEK_OFFSET_SECS.saturating_add(WEEK_SECS.saturating_mul(p))
}

pub fn invite_epoch(week: u64) -> u64 {
    week / WEEKS_PER_INVITE_EPOCH
}

pub fn credit_epoch(week: u64) -> u64 {
    week / WEEKS_PER_CREDIT_EPOCH
}

/// Prices change only at 13-week boundaries: `price_epoch = credit_epoch`.
pub fn price_epoch(week: u64) -> u64 {
    credit_epoch(week)
}

/// The 8-byte big-endian `epoch_id` of any epoch index.
pub fn epoch_id(epoch: u64) -> [u8; 8] {
    epoch.to_be_bytes()
}

/// Activation slot (UTC day) of an instant.
pub fn activation_day(unix_secs: u64) -> u64 {
    unix_secs / DAY_SECS
}

/// The half-open interval `[start(p) - early_window, start(p + 1) + 1 h)` in which a relay
/// accepts access tokens of week p (design §3.4).
pub fn access_window(p: u64, early_window_hours: u8) -> (u64, u64) {
    let early = u64::from(early_window_hours) * 3_600;
    (
        week_start(p).saturating_sub(early),
        week_start(p.saturating_add(1)).saturating_add(LATE_WINDOW_SECS),
    )
}

/// True iff a relay accepts access tokens of week p at instant t.
pub fn access_accepts(p: u64, unix_secs: u64, early_window_hours: u8) -> bool {
    let (from, until) = access_window(p, early_window_hours);
    from <= unix_secs && unix_secs < until
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn weeks_start_on_monday_utc() {
        // 1970-01-05 00:00 UTC was a Monday: week 0 starts there.
        assert_eq!(week_start(0), 345_600);
        assert_eq!(week(345_600), 0);
        assert_eq!(week(345_599 + WEEK_SECS), 0);
        assert_eq!(week(345_600 + WEEK_SECS), 1);
        // Monday 2026-09-07 00:00 UTC = 1 788 739 200 starts week 2957.
        assert_eq!(week_start(2957), 1_788_739_200);
        assert_eq!(week(1_788_739_199), 2956);
        assert_eq!(week(1_788_739_200), 2957);
    }

    #[test]
    fn epochs_group_weeks() {
        assert_eq!(invite_epoch(2956), 739);
        assert_eq!(invite_epoch(2959), 739);
        assert_eq!(invite_epoch(2960), 740);
        assert_eq!(credit_epoch(2951), 227);
        assert_eq!(credit_epoch(2950), 226);
        assert_eq!(price_epoch(2963), 227);
        assert_eq!(credit_epoch(2964), 228);
        assert_eq!(Kind::Invite.epoch_of_week(2960), 740);
        assert_eq!(epoch_id(2957), [0, 0, 0, 0, 0, 0, 0x0b, 0x8d]);
    }

    #[test]
    fn access_window_is_24h_early_and_1h_late() {
        let start = week_start(10);
        assert!(!access_accepts(10, start - 24 * 3_600 - 1, 24));
        assert!(access_accepts(10, start - 24 * 3_600, 24));
        assert!(access_accepts(10, week_start(11) + 3_599, 24));
        assert!(!access_accepts(10, week_start(11) + 3_600, 24));
    }

    #[test]
    fn wire_values_cannot_overflow() {
        assert_eq!(week_start(u64::MAX), u64::MAX);
        assert_eq!(week(0), 0);
        assert_eq!(access_window(u64::MAX, 24).1, u64::MAX);
    }

    #[test]
    fn kind_bytes_round_trip() {
        for k in Kind::ALL {
            assert_eq!(Kind::from_byte(k.byte()), Some(k));
        }
        assert_eq!(Kind::from_byte(0), None);
        assert_eq!(Kind::from_byte(4), None);
    }
}
