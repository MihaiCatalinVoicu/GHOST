//! The Entitlement Schedule built into this library, and the stateless entitlement functions the
//! Android `EntitlementCrypto` class reaches through JNI (Phase 8 design §3.1, §7.7, §11.7).
//!
//! The committed ES (`protocol/entitlement/schedule.ghes`) is compiled in with `include_bytes!`, so
//! the reproducible build (T12) covers it, and no network path can replace it (D5, C-7). It is
//! verified once, at first use, under the schedule key pinned for its network ([`Schedule::verify`],
//! the production entry point) and refused if it is a regtest schedule (rule 6). Kotlin never
//! handles the ES bytes: it gets the verified summary ([`schedule_summary`]) and compares it with
//! its own memory (rule 5: `ent_key`, `ent_schedule_fact`).
//!
//! Every function takes the schedule as an argument; the JNI binds them to [`embedded_schedule`].
//! Results are fixed-layout byte strings, integers big-endian, read strictly by the Kotlin decoders
//! (`org.ghost.network.EntitlementCrypto`).

use ghost_entitlement::batch::{BatchError, Layout, NO_SLOT};
use ghost_entitlement::monero::{self, AddressError, AddressPurpose, AddressType, MoneroAddress};
use ghost_entitlement::{Expect, Kind, Schedule, ScheduleError, Token, VerifiedToken};
use std::sync::OnceLock;

/// The committed Entitlement Schedule, as built into the library.
pub const EMBEDDED_SCHEDULE: &[u8] = include_bytes!("../../../protocol/entitlement/schedule.ghes");

/// Bytes of a packed verified token: `kind(1) || epoch(8) || slot(1) || nullifier(32)`.
pub const VERIFIED_TOKEN_BYTES: usize = 42;
/// Bytes of a packed layout: `digest(32) || N(4)`.
pub const LAYOUT_BYTES: usize = 36;

/// Verifies a schedule the way the production client accepts it: the signature under the schedule
/// key pinned for its network, rules 1–4, and never a regtest schedule (rule 6).
pub fn load_schedule(bytes: &[u8]) -> Result<Schedule, ScheduleError> {
    let schedule = Schedule::verify(bytes)?;
    schedule.refuse_regtest()?;
    Ok(schedule)
}

/// The embedded schedule, verified at first use ([`load_schedule`]); the verdict is cached for
/// the process.
pub fn embedded_schedule() -> Result<&'static Schedule, ScheduleError> {
    static EMBEDDED: OnceLock<Result<Schedule, ScheduleError>> = OnceLock::new();
    EMBEDDED
        .get_or_init(|| load_schedule(EMBEDDED_SCHEDULE))
        .as_ref()
        .map_err(|e| *e)
}

/// What a flow buys (design §11.7 `nativeLayoutDigest`; `ent_purchase.kind`/`pay_with`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Product {
    /// A pack paid in XMR: its layout ends with one CREDIT position.
    PackXmr,
    /// A pack paid with credits.
    PackCredits,
    /// An invite trial.
    Trial,
    /// One received credit exchanged for a fresh one (§19.8).
    Refresh,
}

impl Product {
    /// The JNI code: 1 pack-xmr, 2 pack-credits, 3 trial, 4 refresh.
    pub fn from_code(code: i32) -> Option<Self> {
        match code {
            1 => Some(Product::PackXmr),
            2 => Some(Product::PackCredits),
            3 => Some(Product::Trial),
            4 => Some(Product::Refresh),
            _ => None,
        }
    }

    /// The frozen layout (design §4.2, §4.3, §19.8): `index` is the base week of a pack or a trial
    /// and the credit epoch of a refresh.
    pub fn layout(self, schedule: &Schedule, index: u64) -> Result<Layout, BatchError> {
        match self {
            Product::PackXmr => Layout::pack(schedule, index, true),
            Product::PackCredits => Layout::pack(schedule, index, false),
            Product::Trial => Layout::trial(schedule, index),
            Product::Refresh => Layout::refresh(schedule, index),
        }
    }
}

/// `digest(32) || N(4)`: the layout digest Kotlin stores at purchase time and the number of
/// positions (tokens of a finalized batch, in layout order).
pub fn layout_digest(
    schedule: &Schedule,
    product: Product,
    index: u64,
) -> Result<[u8; LAYOUT_BYTES], BatchError> {
    let layout = product.layout(schedule, index)?;
    let n = u32::try_from(layout.len()).map_err(|_| BatchError::Layout)?;
    let mut out = [0u8; LAYOUT_BYTES];
    out[..32].copy_from_slice(&layout.digest());
    out[32..].copy_from_slice(&n.to_be_bytes());
    Ok(out)
}

/// The offline check of a token the client holds (an invite before any network call, §8.2; a
/// received credit, §19.8): an ES key of the kind, not revoked, the GHOST challenge of its
/// (kind, epoch) (any slot of the week for ACCESS), and a `ring`-verified authenticator. The
/// acceptance window of the epoch is the caller's check.
pub fn verify_token(schedule: &Schedule, token: &[u8], kind: Kind) -> Option<VerifiedToken> {
    let token = Token::parse(token).ok()?;
    let expect = match kind {
        Kind::Access => Expect::AccessAnySlot,
        Kind::Invite => Expect::Invite,
        Kind::Credit => Expect::Credit,
    };
    schedule.verify_token(&token, expect).ok()
}

/// `kind(1) || epoch(8) || slot(1, 0xFF without a slot) || nullifier(32)`.
pub fn pack_verified(v: &VerifiedToken) -> [u8; VERIFIED_TOKEN_BYTES] {
    let mut out = [0u8; VERIFIED_TOKEN_BYTES];
    out[0] = v.kind.byte();
    out[1..9].copy_from_slice(&v.epoch.to_be_bytes());
    out[9] = v.slot.unwrap_or(NO_SLOT);
    out[10..].copy_from_slice(&v.nullifier);
    out
}

/// Address type codes of [`validate_address`].
pub const ADDRESS_STANDARD: u16 = 1;
pub const ADDRESS_SUBADDRESS: u16 = 2;

/// Validates a Monero address of the ES network for `purpose` (design §7.7): an invoice takes a
/// subaddress, a payout a standard address or a subaddress. Returns `(network << 8) | type`, the
/// network being the ES network byte (1 mainnet, 2 stagenet, 3 regtest) and the type
/// [`ADDRESS_STANDARD`] or [`ADDRESS_SUBADDRESS`].
pub fn validate_address(
    schedule: &Schedule,
    address: &str,
    purpose: AddressPurpose,
) -> Result<u16, AddressError> {
    let parsed = MoneroAddress::parse(address, schedule.network(), purpose)?;
    let kind = match parsed.kind() {
        AddressType::Standard => ADDRESS_STANDARD,
        AddressType::Subaddress => ADDRESS_SUBADDRESS,
    };
    Ok((u16::from(schedule.network().schedule_byte()) << 8) | kind)
}

/// `monero:<subaddress>?tx_amount=<12 decimals>`, built locally from a validated ES-network
/// subaddress and a non-zero amount (design §7.7, §19.11: the outstanding amount).
pub fn payment_uri(
    schedule: &Schedule,
    subaddress: &str,
    amount_atomic: u64,
) -> Result<String, AddressError> {
    let parsed = MoneroAddress::parse(subaddress, schedule.network(), AddressPurpose::Invoice)?;
    monero::payment_uri(&parsed, amount_atomic)
}

/// The verified summary Kotlin works from (design §11.7 `nativeScheduleSummary`):
///
/// ```text
/// digest(32) || seq(8) || network(1) || first_week(8) || last_week(8)
/// || confirmations(1) || invoice_blocks(2) || grace_blocks(2) || access_per_slot(1)
///    || trial_per_slot(1) || invites_per_pack(1) || credits_per_free_pack(1)
///    || min_claim_credits(1) || max_claim_credits(1) || early_window_hours(1)
///    || capability_quota_bytes(8)
/// || slot_count(1) || slot_count x (slot(1) || valid_from_week(8) || valid_until_week(8)
///                                   || onion_len(1) || onion ASCII "<56>.onion:<port>")
/// || price_count(2) || price_count x (price_epoch(8) || pack_price_atomic(8))
/// || key_count(2) || key_count x (kind(1) || epoch(8) || key_id(32))
/// || revoked_count(2) || revoked_count x (kind(1) || epoch(8))
/// ```
/// Slots, prices and revocations in ES order; keys ordered by (kind, epoch).
pub fn schedule_summary(schedule: &Schedule) -> Result<Vec<u8>, ScheduleError> {
    let content = schedule.content();
    let c = schedule.constants();
    let mut w = Vec::new();
    w.extend_from_slice(schedule.digest());
    w.extend_from_slice(&schedule.seq().to_be_bytes());
    w.push(schedule.network().schedule_byte());
    w.extend_from_slice(&schedule.first_access_week().to_be_bytes());
    w.extend_from_slice(&schedule.last_access_week().to_be_bytes());
    w.push(c.confirmations);
    w.extend_from_slice(&c.invoice_blocks.to_be_bytes());
    w.extend_from_slice(&c.grace_blocks.to_be_bytes());
    w.extend_from_slice(&[
        c.access_per_slot,
        c.trial_per_slot,
        c.invites_per_pack,
        c.credits_per_free_pack,
        c.min_claim_credits,
        c.max_claim_credits,
        c.early_window_hours,
    ]);
    w.extend_from_slice(&c.capability_quota_bytes.to_be_bytes());
    w.push(u8::try_from(content.slots.len()).map_err(|_| ScheduleError::Encoding)?);
    for s in &content.slots {
        w.push(s.slot);
        w.extend_from_slice(&s.valid_from_week.to_be_bytes());
        w.extend_from_slice(&s.valid_until_week.to_be_bytes());
        w.push(u8::try_from(s.onion.len()).map_err(|_| ScheduleError::Encoding)?);
        w.extend_from_slice(s.onion.as_bytes());
    }
    put_count(&mut w, content.prices.len())?;
    for p in &content.prices {
        w.extend_from_slice(&p.price_epoch.to_be_bytes());
        w.extend_from_slice(&p.pack_price_atomic.to_be_bytes());
    }
    let keys: Vec<_> = schedule.keys().collect();
    put_count(&mut w, keys.len())?;
    for k in keys {
        w.push(k.kind.byte());
        w.extend_from_slice(&k.epoch.to_be_bytes());
        w.extend_from_slice(&k.key_id);
    }
    put_count(&mut w, content.revoked.len())?;
    for (kind, epoch) in &content.revoked {
        w.push(kind.byte());
        w.extend_from_slice(&epoch.to_be_bytes());
    }
    Ok(w)
}

fn put_count(w: &mut Vec<u8>, n: usize) -> Result<(), ScheduleError> {
    w.extend_from_slice(
        &u16::try_from(n)
            .map_err(|_| ScheduleError::Encoding)?
            .to_be_bytes(),
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghost_entitlement::grid;

    #[test]
    fn the_embedded_schedule_verifies_under_the_pinned_key() {
        let s = embedded_schedule().expect("the committed ES verifies");
        assert_eq!(s.network(), monero::MoneroNetwork::Stagenet);
        assert!(s.last_access_week() >= s.first_access_week() + 25);
        assert_eq!(
            s.digest(),
            load_schedule(EMBEDDED_SCHEDULE).unwrap().digest()
        );
        // Cached: the same instance every time.
        assert!(std::ptr::eq(s, embedded_schedule().unwrap()));
    }

    #[test]
    fn a_tampered_copy_of_the_embedded_schedule_is_refused() {
        let mut bytes = EMBEDDED_SCHEDULE.to_vec();
        let mid = bytes.len() / 2;
        bytes[mid] ^= 1;
        assert_eq!(load_schedule(&bytes).err(), Some(ScheduleError::Signature));
        let last = bytes.len() - 1;
        let mut sig = EMBEDDED_SCHEDULE.to_vec();
        sig[last] ^= 1;
        assert_eq!(load_schedule(&sig).err(), Some(ScheduleError::Signature));
        assert!(load_schedule(&EMBEDDED_SCHEDULE[..EMBEDDED_SCHEDULE.len() - 1]).is_err());
        assert!(load_schedule(&[]).is_err());
    }

    /// Reads a summary strictly (the Kotlin decoder's rules), returning (counts, total length).
    fn read_summary(b: &[u8]) -> Option<(usize, usize, usize, usize)> {
        let mut i = 77;
        let slots = usize::from(*b.get(i)?);
        i += 1;
        for _ in 0..slots {
            let len = usize::from(*b.get(i + 17)?);
            let onion = std::str::from_utf8(b.get(i + 18..i + 18 + len)?).ok()?;
            crate::OnionAddress::parse(onion).ok()?;
            i += 18 + len;
        }
        let count = |i: usize| -> Option<usize> {
            Some(usize::from(u16::from_be_bytes(
                b.get(i..i + 2)?.try_into().ok()?,
            )))
        };
        let prices = count(i)?;
        i += 2 + prices * 16;
        let keys = count(i)?;
        i += 2 + keys * 41;
        let revoked = count(i)?;
        i += 2 + revoked * 9;
        (i == b.len()).then_some((slots, prices, keys, revoked))
    }

    #[test]
    fn the_summary_of_the_embedded_schedule_has_the_documented_layout() {
        let s = embedded_schedule().unwrap();
        let b = schedule_summary(s).unwrap();
        assert_eq!(&b[..32], s.digest());
        assert_eq!(u64::from_be_bytes(b[32..40].try_into().unwrap()), s.seq());
        assert_eq!(b[40], 2);
        assert_eq!(
            u64::from_be_bytes(b[41..49].try_into().unwrap()),
            s.first_access_week()
        );
        assert_eq!(
            u64::from_be_bytes(b[49..57].try_into().unwrap()),
            s.last_access_week()
        );
        let c = s.constants();
        assert_eq!(b[57], c.confirmations);
        assert_eq!(u16::from_be_bytes([b[58], b[59]]), c.invoice_blocks);
        assert_eq!(u16::from_be_bytes([b[60], b[61]]), c.grace_blocks);
        assert_eq!(
            &b[62..69],
            &[
                c.access_per_slot,
                c.trial_per_slot,
                c.invites_per_pack,
                c.credits_per_free_pack,
                c.min_claim_credits,
                c.max_claim_credits,
                c.early_window_hours
            ]
        );
        assert_eq!(
            u64::from_be_bytes(b[69..77].try_into().unwrap()),
            c.capability_quota_bytes
        );
        let (slots, prices, keys, revoked) = read_summary(&b).expect("strictly readable");
        assert_eq!(slots, s.content().slots.len());
        assert_eq!(prices, s.content().prices.len());
        assert_eq!(keys, s.keys().count());
        assert_eq!(revoked, s.content().revoked.len());
    }

    #[test]
    fn layouts_of_the_embedded_schedule() {
        let s = embedded_schedule().unwrap();
        let base = s.first_access_week();
        let slots: usize = (base..base + 5).map(|w| s.slots_in_week(w).len()).sum();
        let per = usize::from(s.constants().access_per_slot);
        let invites = usize::from(s.constants().invites_per_pack);
        let n = |b: &[u8; LAYOUT_BYTES]| u32::from_be_bytes(b[32..].try_into().unwrap()) as usize;
        let xmr = layout_digest(s, Product::PackXmr, base).unwrap();
        let credits = layout_digest(s, Product::PackCredits, base).unwrap();
        assert_eq!(n(&xmr), per * slots + invites + 1);
        assert_eq!(n(&credits), per * slots + invites);
        assert_ne!(xmr[..32], credits[..32]);
        assert_eq!(xmr[..32], Layout::pack(s, base, true).unwrap().digest());
        let trial = layout_digest(s, Product::Trial, base).unwrap();
        let trial_slots: usize = (base..base + 2).map(|w| s.slots_in_week(w).len()).sum();
        assert_eq!(
            n(&trial),
            usize::from(s.constants().trial_per_slot) * trial_slots
        );
        let refresh = layout_digest(s, Product::Refresh, grid::credit_epoch(base)).unwrap();
        assert_eq!(n(&refresh), 1);
        // A base week the schedule does not cover has no layout.
        assert!(layout_digest(s, Product::PackXmr, s.last_access_week()).is_err());
        assert!(layout_digest(s, Product::Refresh, 0).is_err());
        assert_eq!(Product::from_code(0), None);
        assert_eq!(Product::from_code(5), None);
        for code in 1..=4 {
            assert!(Product::from_code(code).is_some());
        }
    }

    #[test]
    fn tokens_that_are_not_schedule_tokens_are_refused_offline() {
        let s = embedded_schedule().unwrap();
        let mut token = [0u8; 354];
        token[1] = 2;
        for kind in Kind::ALL {
            assert_eq!(verify_token(s, &token, kind), None);
            assert_eq!(verify_token(s, &token[..353], kind), None);
        }
        let v = VerifiedToken {
            kind: Kind::Invite,
            epoch: 0x0102,
            slot: None,
            nullifier: [9; 32],
        };
        let p = pack_verified(&v);
        assert_eq!(p[0], 2);
        assert_eq!(&p[1..9], &0x0102u64.to_be_bytes());
        assert_eq!(p[9], 0xFF);
        assert_eq!(&p[10..], &[9; 32]);
    }

    #[test]
    fn addresses_and_uris_of_the_schedule_network() {
        let s = embedded_schedule().unwrap();
        // Stagenet vectors of protocol/test-vectors/monero_addresses.txt.
        let sub = "73LhUiix4DVFMcKhsPRG51QmCsv8dYYbL6GcQoLwEEFvPvkVvc7BhebfA4pnEFF9Lq66hwvLqBvpHjTcqvpJMHmmNjPPBqa";
        let std = "53teqCAESLxeJ1REzGMAat1ZeHvuajvDiXqboEocPaDRRmqWoVPzy46GLo866qRFjbNhfkNckyhST3WEvBviDwpUDd7DSzB";
        let mainnet = "888tNkZrPN6JsEgekjMnABU4TBzc2Dt29EPAvkRxbANsAnjyPbb3iQ1YBRk1UXcdRsiKc9dhwMVgN5S9cQUiyoogDavup3H";
        assert_eq!(
            validate_address(s, sub, AddressPurpose::Invoice),
            Ok(0x0202)
        );
        assert_eq!(validate_address(s, sub, AddressPurpose::Payout), Ok(0x0202));
        assert_eq!(validate_address(s, std, AddressPurpose::Payout), Ok(0x0201));
        assert_eq!(
            validate_address(s, std, AddressPurpose::Invoice),
            Err(AddressError::WrongType)
        );
        assert_eq!(
            validate_address(s, mainnet, AddressPurpose::Payout),
            Err(AddressError::WrongNetwork)
        );
        assert_eq!(
            payment_uri(s, sub, 1_234_500_000_000).unwrap(),
            format!("monero:{sub}?tx_amount=1.234500000000")
        );
        assert_eq!(payment_uri(s, sub, 0), Err(AddressError::UriInput));
        assert_eq!(payment_uri(s, std, 1), Err(AddressError::WrongType));
    }
}
