//! The client's issuer calls (Phase 8 design §5.3, §8.3, §9.4, §19.8, §11.7). Every request is
//! built and checked here before any byte leaves the device, and every answer is validated against
//! the Entitlement Schedule before anything reaches Kotlin.
//!
//! - **Before any I/O:** the frozen layout is recomputed from (product, base week or credit epoch)
//!   and compared with the digest stored at purchase time; the blinded request is recomputed from
//!   the seed, so every retry is byte-identical; every presented credit, invite and received credit
//!   verifies under the ES (kind, challenge, `ring`, not revoked), credits are distinct and a
//!   pack's credits are the smallest set covering its price; a payout address is of the ES network.
//!   A refused request is [`IssuerError::InvalidArgument`] and never sent.
//! - **After the answer:** the result or state is a known value and every field fits it: an
//!   invoice's amount equals the ES price (0 when paid with credits) and its subaddress is a
//!   subaddress of the ES network; blind signatures come in the layout's count, each satisfies
//!   `s'^e == B` and finalizes into a token `ring` verifies; a payout's queued amount equals the value
//!   of its credits; a spent mask names only credits of the request. Anything else is
//!   [`IssuerError::Malformed`] (`malformed_response`, design §5.7).
//!
//! Protocol outcomes (`WRONG_PERIOD`, `CREDITS_SPENT`, `CLAIM_CONFLICT`, `OTHER_REQUEST_ISSUED`,
//! `REPLAYED`, `ADDRESS_REJECTED`) are answers, not errors: they travel in-band in the packed
//! results. Seeds, r, nonces, salts, blinded messages and blind signatures never leave this module;
//! Kotlin receives finished tokens with their nullifiers, in layout order.

use std::collections::BTreeSet;
use std::fmt;

use crate::entitlement::Product;
use crate::issuer_client::{IssuerError, IssuerRpc};
use ghost_entitlement::batch::{self, Layout, SEED_LEN};
use ghost_entitlement::credit;
use ghost_entitlement::grid::price_epoch;
use ghost_entitlement::monero::{AddressPurpose, MoneroAddress};
use ghost_entitlement::token::TOKEN_LEN;
use ghost_entitlement::{Expect, Schedule, Token, VerifiedToken};
use ghost_issuer_api::proto as wire;
use ghost_issuer_api::{
    CLAIM_BYTES, CLAIM_ID_BYTES, INVOICE_ID_BYTES, MAX_DISCOUNT_CREDITS, MAX_LAYOUT_POSITIONS,
    PROTOCOL_VERSION,
};

/// Bytes of one issued token in a packed result: `nullifier(32) || token(354)`.
pub const ISSUED_TOKEN_BYTES: usize = 32 + TOKEN_LEN;
/// A claim's spent mask is a `uint64` (§19.21 point 3): at most 64 credits.
const MAX_MASKED_CREDITS: usize = 64;

fn invalid<E>(_: E) -> IssuerError {
    IssuerError::InvalidArgument
}

fn malformed<E>(_: E) -> IssuerError {
    IssuerError::Malformed
}

/// Splits concatenated 354-byte tokens (the JNI form of a credit list); each must parse as a
/// type-0x0002 token.
pub fn parse_tokens(concatenated: &[u8]) -> Result<Vec<Token>, IssuerError> {
    let (chunks, rest) = concatenated.as_chunks::<TOKEN_LEN>();
    if !rest.is_empty() {
        return Err(IssuerError::InvalidArgument);
    }
    chunks
        .iter()
        .map(|c| Token::parse(c).map_err(invalid))
        .collect()
}

/// Credits that verify under the ES as CREDIT tokens, with distinct nullifiers.
fn verified_credits(
    schedule: &Schedule,
    credits: &[Token],
) -> Result<Vec<VerifiedToken>, IssuerError> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::with_capacity(credits.len());
    for token in credits {
        let v = schedule
            .verify_token(token, Expect::Credit)
            .map_err(invalid)?;
        if !seen.insert(v.nullifier) {
            return Err(IssuerError::InvalidArgument);
        }
        out.push(v);
    }
    Ok(out)
}

/// `price(epoch of its key) / 10` per credit (design §4.6, §19.8).
fn credit_values(schedule: &Schedule, credits: &[VerifiedToken]) -> Result<Vec<u64>, IssuerError> {
    credits
        .iter()
        .map(|v| {
            schedule
                .credit_value(v.epoch)
                .ok_or(IssuerError::InvalidArgument)
        })
        .collect()
}

/// The layout of `product` at `index`, which must match the digest stored at purchase time.
fn frozen_layout(
    schedule: &Schedule,
    product: Product,
    index: u64,
    layout_digest: &[u8; 32],
) -> Result<Layout, IssuerError> {
    let layout = product.layout(schedule, index).map_err(invalid)?;
    if layout.len() > MAX_LAYOUT_POSITIONS {
        return Err(IssuerError::InvalidArgument);
    }
    layout.check_digest(layout_digest).map_err(invalid)?;
    Ok(layout)
}

/// `N x (nullifier(32) || token(354))`, in layout order.
fn pack_tokens(out: &mut Vec<u8>, tokens: &[Token]) {
    for t in tokens {
        out.extend_from_slice(&t.nullifier());
        out.extend_from_slice(t.as_bytes());
    }
}

/// `mask` names only the first `count` credits and at least one of them.
fn mask_fits(mask: u64, count: usize) -> bool {
    mask != 0 && (count >= MAX_MASKED_CREDITS || mask >> count == 0)
}

/// A validated `RequestInvoice` answer.
#[derive(Clone, PartialEq, Eq)]
pub struct InvoiceAnswer {
    pub result: wire::RequestInvoiceResult,
    /// OK only; zeros otherwise.
    pub invoice_id: [u8; INVOICE_ID_BYTES],
    /// OK only: the ES price, or 0 when paid with credits.
    pub amount_atomic: u64,
    /// OK with a non-zero amount only: an ES-network subaddress.
    pub subaddress: Option<String>,
    /// CREDITS_SPENT only: bit i set iff credit i was already used.
    pub spent_mask: u32,
}

impl InvoiceAnswer {
    fn bare(result: wire::RequestInvoiceResult, spent_mask: u32) -> Self {
        InvoiceAnswer {
            result,
            invoice_id: [0; INVOICE_ID_BYTES],
            amount_atomic: 0,
            subaddress: None,
            spent_mask,
        }
    }

    /// `result(1) || invoice_id(16) || amount(8) || subaddress(0 or 95) || spent_mask(4)`.
    pub fn pack(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(124);
        out.push(self.result as i32 as u8);
        out.extend_from_slice(&self.invoice_id);
        out.extend_from_slice(&self.amount_atomic.to_be_bytes());
        if let Some(s) = &self.subaddress {
            out.extend_from_slice(s.as_bytes());
        }
        out.extend_from_slice(&self.spent_mask.to_be_bytes());
        out
    }
}

impl fmt::Debug for InvoiceAnswer {
    // Invoice ids, amounts and subaddresses are issuance secrets (R10): never printed.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "InvoiceAnswer({:?}, ..)", self.result)
    }
}

/// `RequestInvoice` (design §5.3 step 2, §5.6): an invoice for a pack of weeks
/// `base_week .. base_week + 4`, paid in XMR (`credits` empty) or with credits.
pub async fn request_invoice<R: IssuerRpc>(
    rpc: &mut R,
    schedule: &Schedule,
    claim_hash: &[u8; CLAIM_BYTES],
    credits: &[Token],
    base_week: u64,
) -> Result<InvoiceAnswer, IssuerError> {
    let paid_in_xmr = credits.is_empty();
    Layout::pack(schedule, base_week, paid_in_xmr).map_err(invalid)?;
    let price = schedule
        .pack_price(price_epoch(base_week))
        .ok_or(IssuerError::InvalidArgument)?;
    if !paid_in_xmr {
        let values = credit_values(schedule, &verified_credits(schedule, credits)?)?;
        let floor = schedule.constants().credits_per_free_pack;
        if !credit::covers(&values, price, floor, MAX_DISCOUNT_CREDITS) {
            return Err(IssuerError::InvalidArgument);
        }
    }
    let expected = if paid_in_xmr { price } else { 0 };
    let answer = rpc
        .request_invoice(wire::RequestInvoiceRequest {
            version: PROTOCOL_VERSION,
            rail: wire::Rail::Monero as i32,
            product: wire::Product::Pack as i32,
            claim_hash: claim_hash.to_vec(),
            credits: credits.iter().map(|t| t.as_bytes().to_vec()).collect(),
            base_week,
        })
        .await?;
    check_invoice(schedule, expected, credits.len(), answer)
}

fn check_invoice(
    schedule: &Schedule,
    expected_amount: u64,
    credit_count: usize,
    r: wire::RequestInvoiceResponse,
) -> Result<InvoiceAnswer, IssuerError> {
    use wire::RequestInvoiceResult as Res;
    let result = Res::try_from(r.result).map_err(malformed)?;
    let no_invoice = r.invoice_id.is_empty() && r.amount_atomic == 0 && r.subaddress.is_empty();
    match result {
        Res::Ok => {
            let invoice_id = r.invoice_id.as_slice().try_into().map_err(malformed)?;
            if r.amount_atomic != expected_amount || r.spent_mask != 0 {
                return Err(IssuerError::Malformed);
            }
            let subaddress = if expected_amount == 0 {
                if !r.subaddress.is_empty() {
                    return Err(IssuerError::Malformed);
                }
                None
            } else {
                MoneroAddress::parse(&r.subaddress, schedule.network(), AddressPurpose::Invoice)
                    .map_err(malformed)?;
                Some(r.subaddress)
            };
            Ok(InvoiceAnswer {
                result,
                invoice_id,
                amount_atomic: expected_amount,
                subaddress,
                spent_mask: 0,
            })
        }
        Res::CreditsSpent => {
            if credit_count == 0 || !no_invoice || !mask_fits(u64::from(r.spent_mask), credit_count)
            {
                return Err(IssuerError::Malformed);
            }
            Ok(InvoiceAnswer::bare(result, r.spent_mask))
        }
        Res::WrongPeriod | Res::ClaimConflict => {
            if !no_invoice || r.spent_mask != 0 {
                return Err(IssuerError::Malformed);
            }
            Ok(InvoiceAnswer::bare(result, 0))
        }
        Res::Unspecified => Err(IssuerError::Malformed),
    }
}

/// A validated `BlindSign` answer: on SIGNED, the finalized tokens in layout order.
#[derive(Clone, PartialEq, Eq)]
pub struct SignAnswer {
    pub state: wire::InvoiceState,
    pub credited_atomic: u64,
    pub seen_atomic: u64,
    pub tokens: Vec<Token>,
}

impl SignAnswer {
    /// `state(1) || credited(8) || seen(8) || N x (nullifier(32) || token(354))` (tokens on SIGNED
    /// only).
    pub fn pack(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(17 + self.tokens.len() * ISSUED_TOKEN_BYTES);
        out.push(self.state as i32 as u8);
        out.extend_from_slice(&self.credited_atomic.to_be_bytes());
        out.extend_from_slice(&self.seen_atomic.to_be_bytes());
        pack_tokens(&mut out, &self.tokens);
        out
    }
}

impl fmt::Debug for SignAnswer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SignAnswer({:?}, {} tokens, ..)",
            self.state,
            self.tokens.len()
        )
    }
}

/// `BlindSign` (design §5.3 step 4, §5.5): Rust recomputes the request from the seed, checks the
/// layout digest, and on SIGNED checks every `s'^e == B`, finalizes and verifies with `ring`.
#[allow(clippy::too_many_arguments)]
pub async fn blind_sign<R: IssuerRpc>(
    rpc: &mut R,
    schedule: &Schedule,
    invoice_id: &[u8; INVOICE_ID_BYTES],
    claim_key: &[u8; CLAIM_BYTES],
    seed: &[u8; SEED_LEN],
    product: Product,
    base_week: u64,
    layout_digest: &[u8; 32],
) -> Result<SignAnswer, IssuerError> {
    if !matches!(product, Product::PackXmr | Product::PackCredits) {
        return Err(IssuerError::InvalidArgument);
    }
    let layout = frozen_layout(schedule, product, base_week, layout_digest)?;
    let blinded = batch::blind(schedule, seed, &layout).map_err(invalid)?;
    let answer = rpc
        .blind_sign(wire::BlindSignRequest {
            version: PROTOCOL_VERSION,
            invoice_id: invoice_id.to_vec(),
            claim_key: claim_key.to_vec(),
            blinded,
        })
        .await?;
    let state = wire::InvoiceState::try_from(answer.state).map_err(malformed)?;
    let tokens = match state {
        wire::InvoiceState::Signed => {
            batch::finalize(schedule, seed, &layout, &answer.blind_signatures).map_err(malformed)?
        }
        wire::InvoiceState::Unspecified => return Err(IssuerError::Malformed),
        _ if !answer.blind_signatures.is_empty() => return Err(IssuerError::Malformed),
        _ => Vec::new(),
    };
    Ok(SignAnswer {
        state,
        credited_atomic: answer.credited_atomic,
        seen_atomic: answer.seen_atomic,
        tokens,
    })
}

/// A validated `InvoiceStatus` answer.
#[derive(Clone, PartialEq, Eq)]
pub struct StatusAnswer {
    pub state: wire::InvoiceState,
    pub credited_atomic: u64,
    pub seen_atomic: u64,
}

impl StatusAnswer {
    /// `state(1) || credited(8) || seen(8)`.
    pub fn pack(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(17);
        out.push(self.state as i32 as u8);
        out.extend_from_slice(&self.credited_atomic.to_be_bytes());
        out.extend_from_slice(&self.seen_atomic.to_be_bytes());
        out
    }
}

impl fmt::Debug for StatusAnswer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "StatusAnswer({:?}, ..)", self.state)
    }
}

/// `InvoiceStatus` (the optional "check now", design §5.3 step 5): never signs.
pub async fn invoice_status<R: IssuerRpc>(
    rpc: &mut R,
    invoice_id: &[u8; INVOICE_ID_BYTES],
    claim_key: &[u8; CLAIM_BYTES],
) -> Result<StatusAnswer, IssuerError> {
    let answer = rpc
        .invoice_status(wire::InvoiceStatusRequest {
            version: PROTOCOL_VERSION,
            invoice_id: invoice_id.to_vec(),
            claim_key: claim_key.to_vec(),
        })
        .await?;
    let state = wire::InvoiceState::try_from(answer.state).map_err(malformed)?;
    if state == wire::InvoiceState::Unspecified {
        return Err(IssuerError::Malformed);
    }
    Ok(StatusAnswer {
        state,
        credited_atomic: answer.credited_atomic,
        seen_atomic: answer.seen_atomic,
    })
}

/// A validated `RedeemInvite` answer: on OK, the trial tokens in layout order.
#[derive(Clone, PartialEq, Eq)]
pub struct TrialAnswer {
    pub result: wire::RedeemInviteResult,
    pub tokens: Vec<Token>,
}

impl TrialAnswer {
    /// `result(1) || N_t x (nullifier(32) || token(354))` (tokens on OK only).
    pub fn pack(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + self.tokens.len() * ISSUED_TOKEN_BYTES);
        out.push(self.result as i32 as u8);
        pack_tokens(&mut out, &self.tokens);
        out
    }
}

impl fmt::Debug for TrialAnswer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TrialAnswer({:?}, {} tokens, ..)",
            self.result,
            self.tokens.len()
        )
    }
}

/// `RedeemInvite` (design §8.3 step 4): the invite token must verify offline under the ES before
/// the call; the trial request is recomputed from the seed.
pub async fn redeem_invite<R: IssuerRpc>(
    rpc: &mut R,
    schedule: &Schedule,
    invite_token: &Token,
    seed: &[u8; SEED_LEN],
    base_week: u64,
    layout_digest: &[u8; 32],
) -> Result<TrialAnswer, IssuerError> {
    schedule
        .verify_token(invite_token, Expect::Invite)
        .map_err(invalid)?;
    let layout = frozen_layout(schedule, Product::Trial, base_week, layout_digest)?;
    let blinded = batch::blind(schedule, seed, &layout).map_err(invalid)?;
    let answer = rpc
        .redeem_invite(wire::RedeemInviteRequest {
            version: PROTOCOL_VERSION,
            invite_token: invite_token.as_bytes().to_vec(),
            base_week,
            blinded,
        })
        .await?;
    let result = wire::RedeemInviteResult::try_from(answer.result).map_err(malformed)?;
    let tokens = match result {
        wire::RedeemInviteResult::Ok => {
            batch::finalize(schedule, seed, &layout, &answer.blind_signatures).map_err(malformed)?
        }
        wire::RedeemInviteResult::Unspecified => return Err(IssuerError::Malformed),
        _ if !answer.blind_signatures.is_empty() => return Err(IssuerError::Malformed),
        _ => Vec::new(),
    };
    Ok(TrialAnswer { result, tokens })
}

/// A validated `ClaimPayout` answer.
#[derive(Clone, PartialEq, Eq)]
pub struct ClaimAnswer {
    pub result: wire::ClaimPayoutResult,
    /// QUEUED only: the value of the claim's credits.
    pub queued_atomic: u64,
    /// CREDITS_SPENT only.
    pub spent_mask: u64,
}

impl ClaimAnswer {
    /// `result(1) || queued(8) || spent_mask(8)` (the mask is a `uint64`, §19.21 point 3).
    pub fn pack(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(17);
        out.push(self.result as i32 as u8);
        out.extend_from_slice(&self.queued_atomic.to_be_bytes());
        out.extend_from_slice(&self.spent_mask.to_be_bytes());
        out
    }
}

impl fmt::Debug for ClaimAnswer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ClaimAnswer({:?}, ..)", self.result)
    }
}

/// `ClaimPayout` (design §9.4, §19.8): `min_claim_credits .. max_claim_credits` distinct credits
/// of the ES and a payout address of the ES network; the queued amount must equal the credits'
/// value.
pub async fn claim_payout<R: IssuerRpc>(
    rpc: &mut R,
    schedule: &Schedule,
    claim_id: &[u8; CLAIM_ID_BYTES],
    credits: &[Token],
    payout_address: &str,
) -> Result<ClaimAnswer, IssuerError> {
    let c = schedule.constants();
    let max = usize::from(c.max_claim_credits).min(MAX_MASKED_CREDITS);
    if credits.len() < usize::from(c.min_claim_credits) || credits.len() > max {
        return Err(IssuerError::InvalidArgument);
    }
    let values = credit_values(schedule, &verified_credits(schedule, credits)?)?;
    let expected = values
        .iter()
        .try_fold(0u64, |sum, v| sum.checked_add(*v))
        .ok_or(IssuerError::InvalidArgument)?;
    MoneroAddress::parse(payout_address, schedule.network(), AddressPurpose::Payout)
        .map_err(invalid)?;
    let answer = rpc
        .claim_payout(wire::ClaimPayoutRequest {
            version: PROTOCOL_VERSION,
            claim_id: claim_id.to_vec(),
            credits: credits.iter().map(|t| t.as_bytes().to_vec()).collect(),
            payout_address: payout_address.to_owned(),
        })
        .await?;
    use wire::ClaimPayoutResult as Res;
    let result = Res::try_from(answer.result).map_err(malformed)?;
    let fits = match result {
        Res::Queued => answer.queued_atomic == expected && answer.spent_mask == 0,
        Res::CreditsSpent => {
            answer.queued_atomic == 0 && mask_fits(answer.spent_mask, credits.len())
        }
        Res::ClaimConflict | Res::AddressRejected => {
            answer.queued_atomic == 0 && answer.spent_mask == 0
        }
        Res::Unspecified => false,
    };
    if !fits {
        return Err(IssuerError::Malformed);
    }
    Ok(ClaimAnswer {
        result,
        queued_atomic: answer.queued_atomic,
        spent_mask: answer.spent_mask,
    })
}

/// A validated `RefreshCredit` answer: on OK, the fresh credit.
#[derive(Clone, PartialEq, Eq)]
pub struct RefreshAnswer {
    pub result: wire::RefreshCreditResult,
    pub token: Option<Token>,
}

impl RefreshAnswer {
    /// `result(1) || nullifier(32) || token(354)` (the token on OK only).
    pub fn pack(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + ISSUED_TOKEN_BYTES);
        out.push(self.result as i32 as u8);
        pack_tokens(&mut out, self.token.as_slice());
        out
    }
}

impl fmt::Debug for RefreshAnswer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RefreshAnswer({:?}, ..)", self.result)
    }
}

/// `RefreshCredit` (design §19.8): a received credit, verified under the ES, exchanged for one
/// fresh credit of the same epoch, whose single position is recomputed from the seed.
pub async fn refresh_credit<R: IssuerRpc>(
    rpc: &mut R,
    schedule: &Schedule,
    received_credit: &Token,
    seed: &[u8; SEED_LEN],
    layout_digest: &[u8; 32],
) -> Result<RefreshAnswer, IssuerError> {
    let credit = schedule
        .verify_token(received_credit, Expect::Credit)
        .map_err(invalid)?;
    let layout = frozen_layout(schedule, Product::Refresh, credit.epoch, layout_digest)?;
    let blinded = batch::blind(schedule, seed, &layout).map_err(invalid)?;
    let answer = rpc
        .refresh_credit(wire::RefreshCreditRequest {
            version: PROTOCOL_VERSION,
            credit: received_credit.as_bytes().to_vec(),
            blinded,
        })
        .await?;
    let result = wire::RefreshCreditResult::try_from(answer.result).map_err(malformed)?;
    let token = match result {
        wire::RefreshCreditResult::Ok => {
            let mut tokens = batch::finalize(schedule, seed, &layout, &answer.blind_signature)
                .map_err(malformed)?;
            Some(tokens.pop().ok_or(IssuerError::Malformed)?)
        }
        wire::RefreshCreditResult::Replayed if answer.blind_signature.is_empty() => None,
        _ => return Err(IssuerError::Malformed),
    };
    Ok(RefreshAnswer { result, token })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks_name_only_requested_credits() {
        assert!(mask_fits(1, 1));
        assert!(!mask_fits(0, 5));
        assert!(!mask_fits(0b10, 1));
        assert!(mask_fits(0b1_0000_0000_0000_0000_0000, 21));
        assert!(!mask_fits(1 << 20, 20));
        assert!(mask_fits(1 << 63, 64));
        assert!(mask_fits(u64::MAX, 64));
    }

    #[test]
    fn token_lists_split_into_whole_tokens() {
        let mut t = [0u8; TOKEN_LEN];
        t[1] = 2;
        assert_eq!(parse_tokens(&[]).unwrap().len(), 0);
        assert_eq!(parse_tokens(&[t, t].concat()).unwrap().len(), 2);
        assert!(matches!(
            parse_tokens(&t[..TOKEN_LEN - 1]),
            Err(IssuerError::InvalidArgument)
        ));
        let mut wrong_type = t;
        wrong_type[1] = 1;
        assert!(matches!(
            parse_tokens(&[t, wrong_type].concat()),
            Err(IssuerError::InvalidArgument)
        ));
    }

    #[test]
    fn packed_answers_have_the_documented_layouts() {
        let invoice = InvoiceAnswer {
            result: wire::RequestInvoiceResult::Ok,
            invoice_id: [7; 16],
            amount_atomic: 0x0102,
            subaddress: Some("8".repeat(95)),
            spent_mask: 0,
        };
        let p = invoice.pack();
        assert_eq!(p.len(), 124);
        assert_eq!(
            (p[0], &p[1..17], &p[17..25]),
            (1, &[7u8; 16][..], &0x0102u64.to_be_bytes()[..])
        );
        assert_eq!(&p[120..], &[0, 0, 0, 0]);
        let spent = InvoiceAnswer::bare(wire::RequestInvoiceResult::CreditsSpent, 0b101);
        assert_eq!(spent.pack().len(), 29);
        assert_eq!(&spent.pack()[25..], &[0, 0, 0, 5]);
        assert_eq!(format!("{invoice:?}"), "InvoiceAnswer(Ok, ..)");
        let claim = ClaimAnswer {
            result: wire::ClaimPayoutResult::CreditsSpent,
            queued_atomic: 0,
            spent_mask: 1 << 40,
        };
        let c = claim.pack();
        assert_eq!((c.len(), c[0]), (17, 2));
        assert_eq!(&c[9..], &(1u64 << 40).to_be_bytes());
        let status = StatusAnswer {
            state: wire::InvoiceState::Underpaid,
            credited_atomic: 3,
            seen_atomic: 4,
        };
        assert_eq!(
            status.pack(),
            [&[4u8][..], &3u64.to_be_bytes(), &4u64.to_be_bytes()].concat()
        );
        let replayed = RefreshAnswer {
            result: wire::RefreshCreditResult::Replayed,
            token: None,
        };
        assert_eq!(replayed.pack(), vec![2]);
        let trial = TrialAnswer {
            result: wire::RedeemInviteResult::WrongPeriod,
            tokens: vec![],
        };
        assert_eq!(trial.pack(), vec![3]);
    }
}
