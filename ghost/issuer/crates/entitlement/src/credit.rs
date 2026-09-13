//! Credit tokens paying for a pack (Phase 8 design §4.6, §19.8): a credit is worth the pack price
//! of its own epoch divided by 10, and a credits-paid pack takes the smallest covering set. One
//! definition for the issuer, which enforces the rule, and the client, which never sends a set the
//! issuer would refuse.

/// True iff credits of `values` pay for a pack of `price`: at least `floor`
/// (`credits_per_free_pack`) and at most `max` credits whose values sum to at least the price, and
/// the smallest such set: dropping its least valuable credit would no longer cover the price
/// (unless it has exactly `floor` credits).
pub fn covers(values: &[u64], price: u64, floor: u8, max: usize) -> bool {
    let n = values.len();
    if n == 0 || n < usize::from(floor) || n > max {
        return false;
    }
    let sum = values.iter().copied().fold(0u64, u64::saturating_add);
    let least = values.iter().copied().min().unwrap_or(0);
    sum >= price && (n == usize::from(floor) || sum - least < price)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_smallest_covering_set_between_the_floor_and_the_maximum() {
        // Unchanged price: exactly ten credits of value price / 10.
        assert!(covers(&[20; 10], 200, 10, 20));
        assert!(!covers(&[20; 9], 200, 10, 20));
        assert!(!covers(&[20; 11], 200, 10, 20));
        // A price increase: the smallest set that covers it, never more than `max`.
        assert!(!covers(&[20; 12], 250, 10, 20));
        assert!(covers(&[20; 13], 250, 10, 20));
        assert!(!covers(&[20; 14], 250, 10, 20));
        assert!(!covers(&[1; 21], 21, 10, 20));
        // A price drop: the floor still applies.
        assert!(!covers(&[25; 8], 200, 10, 20));
        assert!(covers(&[25; 10], 200, 10, 20));
        assert!(!covers(&[], 0, 0, 20));
    }
}
