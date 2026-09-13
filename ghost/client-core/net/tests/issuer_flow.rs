//! The client's issuer calls against a model issuer signing with the test schedule's keys (design
//! §5.3, §5.7, §8.3, §9.4, §19.8, §11.7): the honest flows end in tokens that verify under the ES at
//! their layout positions; retries are byte-identical; requests the client's checks refuse never
//! reach the issuer; answers that disagree with the ES are `malformed_response`.

mod common;

use common::*;
use ghost_client_net::categories::{for_issuer, INVALID_ARGUMENT, MALFORMED_RESPONSE};
use ghost_client_net::entitlement::{self, Product};
use ghost_client_net::issuer_client::IssuerError;
use ghost_client_net::issuer_flow::{self, ISSUED_TOKEN_BYTES};
use ghost_entitlement::batch::{self, Layout};
use ghost_entitlement::grid::price_epoch;
use ghost_entitlement::{Expect, Kind, Schedule, Token};
use ghost_issuer_api::proto::*;
use tonic::Code;

const CLAIM_KEY: [u8; 32] = [0x11; 32];
const SEED: [u8; 32] = [0x22; 32];

fn digest(s: &Schedule, product: Product, index: u64) -> [u8; 32] {
    entitlement::layout_digest(s, product, index).unwrap()[..32]
        .try_into()
        .unwrap()
}

fn expect_of(kind: Kind, slot: Option<u8>) -> Expect {
    match kind {
        Kind::Access => Expect::AccessAtSlot(slot.unwrap()),
        Kind::Invite => Expect::Invite,
        Kind::Credit => Expect::Credit,
    }
}

/// Every token verifies under the ES for the (kind, epoch, slot) of its layout position.
fn assert_layout_tokens(s: &Schedule, layout: &Layout, tokens: &[Token]) {
    assert_eq!(tokens.len(), layout.len());
    let mut nullifiers = std::collections::BTreeSet::new();
    for (t, p) in tokens.iter().zip(layout.positions()) {
        let v = s.verify_token(t, expect_of(p.kind, p.slot)).unwrap();
        assert_eq!((v.kind, v.epoch, v.slot), (p.kind, p.epoch, p.slot));
        assert!(nullifiers.insert(v.nullifier));
    }
}

/// The packed tokens are `nullifier || token` in layout order.
fn assert_packed_tokens(packed: &[u8], header: usize, tokens: &[Token]) {
    assert_eq!(packed.len(), header + tokens.len() * ISSUED_TOKEN_BYTES);
    for (i, t) in tokens.iter().enumerate() {
        let at = header + i * ISSUED_TOKEN_BYTES;
        assert_eq!(&packed[at..at + 32], &t.nullifier());
        assert_eq!(&packed[at + 32..at + ISSUED_TOKEN_BYTES], t.as_bytes());
    }
}

fn malformed<T: std::fmt::Debug>(r: Result<T, IssuerError>, why: &str) {
    match r {
        Err(e @ IssuerError::Malformed) => assert_eq!(for_issuer(&e), MALFORMED_RESPONSE),
        other => panic!("{why}: expected malformed_response, got {other:?}"),
    }
}

fn refused<T: std::fmt::Debug>(r: Result<T, IssuerError>, why: &str) {
    match r {
        Err(e @ IssuerError::InvalidArgument) => assert_eq!(for_issuer(&e), INVALID_ARGUMENT),
        other => panic!("{why}: expected invalid_argument, got {other:?}"),
    }
}

#[tokio::test]
async fn a_pack_paid_in_xmr_goes_from_invoice_to_verified_tokens() {
    let s = schedule();
    let mut issuer = ModelIssuer::new();
    let claim_hash = batch::claim_hash(&CLAIM_KEY);
    let invoice = issuer_flow::request_invoice(&mut issuer, s, &claim_hash, &[], FIRST_WEEK)
        .await
        .unwrap();
    assert_eq!(invoice.result, RequestInvoiceResult::Ok);
    assert_eq!(
        invoice.amount_atomic,
        s.pack_price(price_epoch(FIRST_WEEK)).unwrap()
    );
    assert_eq!(invoice.subaddress.as_deref(), Some(SUBADDRESS));
    let p = invoice.pack();
    assert_eq!(p.len(), 1 + 16 + 8 + 95 + 4);
    assert_eq!(p[0], 1);
    assert_eq!(&p[1..17], &invoice.invoice_id);
    assert_eq!(&p[17..25], &invoice.amount_atomic.to_be_bytes());
    assert_eq!(&p[25..120], SUBADDRESS.as_bytes());
    assert_eq!(&p[120..], &[0; 4]);
    // An identical retry (after a lost answer) gets the identical invoice.
    let again = issuer_flow::request_invoice(&mut issuer, s, &claim_hash, &[], FIRST_WEEK)
        .await
        .unwrap();
    assert_eq!(again, invoice);

    let layout = Layout::pack(s, FIRST_WEEK, true).unwrap();
    assert_eq!(layout.len(), 243); // 5 weeks x 3 slots x 16 + 2 invites + 1 credit
    let d = digest(s, Product::PackXmr, FIRST_WEEK);
    async fn sign_pack(
        issuer: &mut ModelIssuer,
        s: &Schedule,
        invoice_id: &[u8; 16],
        seed: [u8; 32],
        d: &[u8; 32],
    ) -> Result<issuer_flow::SignAnswer, IssuerError> {
        issuer_flow::blind_sign(
            issuer,
            s,
            invoice_id,
            &CLAIM_KEY,
            &seed,
            Product::PackXmr,
            FIRST_WEEK,
            d,
        )
        .await
    }
    let id = invoice.invoice_id;
    let waiting = sign_pack(&mut issuer, s, &id, SEED, &d).await.unwrap();
    assert_eq!(waiting.state, InvoiceState::AwaitingPayment);
    assert!(waiting.tokens.is_empty());
    assert_eq!(waiting.pack().len(), 17);
    let first_request = issuer.last_blinded.clone().unwrap();
    assert_eq!(first_request.len(), 243 * 256);

    issuer.pay(&invoice.invoice_id);
    let signed = sign_pack(&mut issuer, s, &id, SEED, &d).await.unwrap();
    assert_eq!(signed.state, InvoiceState::Signed);
    assert_eq!(signed.credited_atomic, invoice.amount_atomic);
    assert_layout_tokens(s, &layout, &signed.tokens);
    let packed = signed.pack();
    assert_eq!(packed[0], InvoiceState::Signed as u8);
    assert_packed_tokens(&packed, 17, &signed.tokens);
    // Every attempt sends the byte-identical request; the re-serve gives the identical tokens.
    assert_eq!(issuer.last_blinded.as_ref(), Some(&first_request));
    let again = sign_pack(&mut issuer, s, &id, SEED, &d).await.unwrap();
    assert_eq!(again, signed);
    // Another seed after issuance: OTHER_REQUEST_ISSUED, nothing signed (in-band).
    let other = sign_pack(&mut issuer, s, &id, [0x23; 32], &d)
        .await
        .unwrap();
    assert_eq!(other.state, InvoiceState::OtherRequestIssued);
    assert!(other.tokens.is_empty());
    assert_eq!(other.pack().len(), 17);

    // "Check now" sees the issued invoice; a wrong claim key is the issuer's PERMISSION_DENIED.
    let status = issuer_flow::invoice_status(&mut issuer, &invoice.invoice_id, &CLAIM_KEY)
        .await
        .unwrap();
    assert_eq!(status.state, InvoiceState::Signed);
    let e = issuer_flow::invoice_status(&mut issuer, &invoice.invoice_id, &[0x12; 32])
        .await
        .unwrap_err();
    assert!(matches!(e, IssuerError::Rpc(Code::PermissionDenied)));
    assert_eq!(for_issuer(&e), "unauthorized");
}

#[tokio::test]
async fn hostile_blind_sign_answers_are_malformed() {
    let s = schedule();
    let mut issuer = ModelIssuer::new();
    let claim_hash = batch::claim_hash(&CLAIM_KEY);
    let invoice = issuer_flow::request_invoice(&mut issuer, s, &claim_hash, &[], FIRST_WEEK)
        .await
        .unwrap();
    issuer.pay(&invoice.invoice_id);
    let d = digest(s, Product::PackXmr, FIRST_WEEK);
    // Issue once; every case below is a re-serve of the same request, then rewritten.
    issuer_flow::blind_sign(
        &mut issuer,
        s,
        &invoice.invoice_id,
        &CLAIM_KEY,
        &SEED,
        Product::PackXmr,
        FIRST_WEEK,
        &d,
    )
    .await
    .unwrap();
    type Case = (&'static str, Box<dyn Fn(&mut BlindSignResponse) + Send>);
    let cases: Vec<Case> = vec![
        (
            "one signature short",
            Box::new(|a| a.blind_signatures.truncate(a.blind_signatures.len() - 256)),
        ),
        (
            "one signature too many",
            Box::new(|a| a.blind_signatures.extend_from_slice(&[1; 256])),
        ),
        (
            "a flipped byte (s'^e != B)",
            Box::new(|a| a.blind_signatures[5 * 256 + 17] ^= 1),
        ),
        (
            "two positions swapped",
            Box::new(|a| {
                let (x, y) = a.blind_signatures.split_at_mut(256);
                x.swap_with_slice(&mut y[..256]);
            }),
        ),
        (
            "a value >= n",
            Box::new(|a| a.blind_signatures[..256].fill(0xFF)),
        ),
        ("no signatures", Box::new(|a| a.blind_signatures.clear())),
        ("unspecified state", Box::new(|a| a.state = 0)),
        ("unknown state", Box::new(|a| a.state = 9)),
        (
            "signatures with AWAITING_PAYMENT",
            Box::new(|a| a.state = InvoiceState::AwaitingPayment as i32),
        ),
        (
            "signatures with EXPIRED",
            Box::new(|a| a.state = InvoiceState::Expired as i32),
        ),
    ];
    for (why, hook) in cases {
        issuer.tamper.blind_sign = Some(hook);
        let r = issuer_flow::blind_sign(
            &mut issuer,
            s,
            &invoice.invoice_id,
            &CLAIM_KEY,
            &SEED,
            Product::PackXmr,
            FIRST_WEEK,
            &d,
        )
        .await;
        malformed(r, why);
    }
    // Status answers: a state outside the enum.
    issuer.tamper.invoice_status = Some(Box::new(|a| a.state = 0));
    malformed(
        issuer_flow::invoice_status(&mut issuer, &invoice.invoice_id, &CLAIM_KEY).await,
        "unspecified status",
    );
    issuer.tamper.invoice_status = Some(Box::new(|a| a.state = 12));
    malformed(
        issuer_flow::invoice_status(&mut issuer, &invoice.invoice_id, &CLAIM_KEY).await,
        "unknown status",
    );
}

#[tokio::test]
async fn a_blind_sign_request_that_does_not_match_its_frozen_layout_is_never_sent() {
    let s = schedule();
    let mut issuer = ModelIssuer::new();
    let good = digest(s, Product::PackXmr, FIRST_WEEK);
    let cases = [
        (
            "the other product's digest",
            Product::PackXmr,
            FIRST_WEEK,
            digest(s, Product::PackCredits, FIRST_WEEK),
        ),
        ("another base week", Product::PackXmr, FIRST_WEEK + 1, good),
        (
            "a base week the ES does not cover",
            Product::PackXmr,
            2979,
            good,
        ),
        (
            "a trial is no pack",
            Product::Trial,
            FIRST_WEEK,
            digest(s, Product::Trial, FIRST_WEEK),
        ),
        (
            "a refresh is no pack",
            Product::Refresh,
            CREDIT_EPOCH,
            digest(s, Product::Refresh, CREDIT_EPOCH),
        ),
    ];
    for (why, product, week, d) in cases {
        let r = issuer_flow::blind_sign(
            &mut issuer,
            s,
            &[1; 16],
            &CLAIM_KEY,
            &SEED,
            product,
            week,
            &d,
        )
        .await;
        refused(r, why);
    }
    // An invoice for weeks the ES does not cover is refused before any I/O as well.
    let r = issuer_flow::request_invoice(&mut issuer, s, &[0; 32], &[], 2979).await;
    refused(r, "request_invoice beyond the ES");
    assert!(
        issuer.requests.is_empty(),
        "nothing reached the issuer: {:?}",
        issuer.requests
    );
}

#[tokio::test]
async fn hostile_invoice_answers_are_malformed() {
    let s = schedule();
    let price = s.pack_price(price_epoch(FIRST_WEEK)).unwrap();
    type Case = (
        &'static str,
        Box<dyn Fn(&mut RequestInvoiceResponse) + Send>,
    );
    let xmr_cases: Vec<Case> = vec![
        ("amount + 1", Box::new(move |a| a.amount_atomic = price + 1)),
        ("amount 0", Box::new(|a| a.amount_atomic = 0)),
        (
            "a stagenet subaddress",
            Box::new(|a| a.subaddress = STAGENET_SUBADDRESS.into()),
        ),
        (
            "a standard address",
            Box::new(|a| a.subaddress = PAYOUT.into()),
        ),
        ("no subaddress", Box::new(|a| a.subaddress.clear())),
        (
            "a checksum error",
            Box::new(|a| a.subaddress = a.subaddress.replace('8', "9")),
        ),
        (
            "a 15-byte invoice id",
            Box::new(|a| a.invoice_id.truncate(15)),
        ),
        ("a spent mask on OK", Box::new(|a| a.spent_mask = 1)),
        ("unspecified result", Box::new(|a| a.result = 0)),
        ("unknown result", Box::new(|a| a.result = 9)),
        (
            "CREDITS_SPENT without credits",
            Box::new(|a| {
                *a = RequestInvoiceResponse {
                    result: 3,
                    spent_mask: 1,
                    ..Default::default()
                }
            }),
        ),
        ("WRONG_PERIOD with an invoice", Box::new(|a| a.result = 2)),
        ("CLAIM_CONFLICT with an invoice", Box::new(|a| a.result = 4)),
    ];
    for (why, hook) in xmr_cases {
        let mut issuer = ModelIssuer::new();
        issuer.tamper.request_invoice = Some(hook);
        malformed(
            issuer_flow::request_invoice(&mut issuer, s, &[1; 32], &[], FIRST_WEEK).await,
            why,
        );
    }
    // The in-band answers an honest issuer gives are accepted.
    for result in [
        RequestInvoiceResult::WrongPeriod,
        RequestInvoiceResult::ClaimConflict,
    ] {
        let mut issuer = ModelIssuer::new();
        issuer.tamper.request_invoice = Some(Box::new(move |a| {
            *a = RequestInvoiceResponse {
                result: result as i32,
                ..Default::default()
            }
        }));
        let a = issuer_flow::request_invoice(&mut issuer, s, &[1; 32], &[], FIRST_WEEK)
            .await
            .unwrap();
        assert_eq!(a.result, result);
        assert_eq!(a.pack(), [&[result as u8][..], &[0; 28]].concat());
    }

    let credits = credits(10, CREDIT_EPOCH);
    let credit_cases: Vec<Case> = vec![
        (
            "a subaddress on a credits invoice",
            Box::new(|a| a.subaddress = SUBADDRESS.into()),
        ),
        (
            "the XMR price on a credits invoice",
            Box::new(move |a| a.amount_atomic = price),
        ),
        (
            "a mask beyond the credits",
            Box::new(|a| {
                *a = RequestInvoiceResponse {
                    result: 3,
                    spent_mask: 1 << 10,
                    ..Default::default()
                }
            }),
        ),
        (
            "CREDITS_SPENT with an empty mask",
            Box::new(|a| {
                *a = RequestInvoiceResponse {
                    result: 3,
                    ..Default::default()
                }
            }),
        ),
    ];
    for (why, hook) in credit_cases {
        let mut issuer = ModelIssuer::new();
        issuer.tamper.request_invoice = Some(hook);
        malformed(
            issuer_flow::request_invoice(&mut issuer, s, &[1; 32], &credits, FIRST_WEEK).await,
            why,
        );
    }
}

#[tokio::test]
async fn a_pack_paid_with_credits_takes_the_smallest_covering_set() {
    let s = schedule();
    let credits = credits(11, CREDIT_EPOCH);
    let mut issuer = ModelIssuer::new();
    let claim = batch::claim_hash(&[0x33; 32]);
    let invite = mint(Kind::Invite, INVITE_EPOCH, None, seed(1, 0x5A));
    let mut repeated = credits[..9].to_vec();
    repeated.push(credits[0].clone());
    let mut with_invite = credits[..9].to_vec();
    with_invite.push(invite);
    let revoked = resigned(|c| c.revoked = vec![(Kind::Credit, CREDIT_EPOCH)]);
    for (why, schedule, set) in [
        ("nine credits", s, &credits[..9]),
        ("eleven credits (not the smallest set)", s, &credits[..11]),
        ("a credit twice", s, &repeated[..]),
        ("an invite among the credits", s, &with_invite[..]),
        ("credits of a revoked epoch", &revoked, &credits[..10]),
    ] {
        refused(
            issuer_flow::request_invoice(&mut issuer, schedule, &claim, set, FIRST_WEEK).await,
            why,
        );
    }
    assert!(issuer.requests.is_empty());

    let invoice = issuer_flow::request_invoice(&mut issuer, s, &claim, &credits[..10], FIRST_WEEK)
        .await
        .unwrap();
    assert_eq!(invoice.result, RequestInvoiceResult::Ok);
    assert_eq!(
        (invoice.amount_atomic, invoice.subaddress.as_deref()),
        (0, None)
    );
    assert_eq!(invoice.pack().len(), 29);
    // The same credits under another claim: CREDITS_SPENT names every one of them.
    let spent = issuer_flow::request_invoice(
        &mut issuer,
        s,
        &batch::claim_hash(&[0x34; 32]),
        &credits[..10],
        FIRST_WEEK,
    )
    .await
    .unwrap();
    assert_eq!(spent.result, RequestInvoiceResult::CreditsSpent);
    assert_eq!(spent.spent_mask, 0x3FF);
    assert_eq!(&spent.pack()[25..], &0x3FFu32.to_be_bytes());

    // A credits-paid pack is confirmed at creation and has no credit position.
    let d = digest(s, Product::PackCredits, FIRST_WEEK);
    let signed = issuer_flow::blind_sign(
        &mut issuer,
        s,
        &invoice.invoice_id,
        &[0x33; 32],
        &[0x44; 32],
        Product::PackCredits,
        FIRST_WEEK,
        &d,
    )
    .await
    .unwrap();
    assert_eq!(signed.state, InvoiceState::Signed);
    assert_layout_tokens(
        s,
        &Layout::pack(s, FIRST_WEEK, false).unwrap(),
        &signed.tokens,
    );
    assert_eq!(signed.tokens.len(), 242);
}

#[tokio::test]
async fn an_invite_trial_ends_in_access_tokens_for_two_weeks() {
    let s = schedule();
    let mut issuer = ModelIssuer::new();
    let invite = mint(Kind::Invite, INVITE_EPOCH, None, seed(2, 0x5A));
    let d = digest(s, Product::Trial, FIRST_WEEK);
    let trial = issuer_flow::redeem_invite(&mut issuer, s, &invite, &SEED, FIRST_WEEK, &d)
        .await
        .unwrap();
    assert_eq!(trial.result, RedeemInviteResult::Ok);
    let layout = Layout::trial(s, FIRST_WEEK).unwrap();
    assert_eq!(layout.len(), 48); // 2 weeks x 3 slots x 8
    assert_layout_tokens(s, &layout, &trial.tokens);
    assert_packed_tokens(&trial.pack(), 1, &trial.tokens);
    // Identical retry: identical tokens. Another request with the same invite: REPLAYED.
    let again = issuer_flow::redeem_invite(&mut issuer, s, &invite, &SEED, FIRST_WEEK, &d)
        .await
        .unwrap();
    assert_eq!(again, trial);
    let replayed = issuer_flow::redeem_invite(&mut issuer, s, &invite, &[0x24; 32], FIRST_WEEK, &d)
        .await
        .unwrap();
    assert_eq!(replayed.result, RedeemInviteResult::Replayed);
    assert_eq!(replayed.pack(), vec![2]);

    let calls = issuer.requests.len();
    let access = mint(Kind::Access, FIRST_WEEK, Some(1), seed(3, 0x5A));
    let credit = mint(Kind::Credit, CREDIT_EPOCH, None, seed(4, 0x5A));
    let revoked = resigned(|c| c.revoked = vec![(Kind::Invite, INVITE_EPOCH)]);
    for (why, schedule, token, week, dig) in [
        ("an access token as invite", s, &access, FIRST_WEEK, d),
        ("a credit token as invite", s, &credit, FIRST_WEEK, d),
        ("a revoked invite epoch", &revoked, &invite, FIRST_WEEK, d),
        (
            "a pack digest",
            s,
            &invite,
            FIRST_WEEK,
            digest(s, Product::PackXmr, FIRST_WEEK),
        ),
        ("another base week", s, &invite, FIRST_WEEK + 1, d),
    ] {
        refused(
            issuer_flow::redeem_invite(&mut issuer, schedule, token, &SEED, week, &dig).await,
            why,
        );
    }
    assert_eq!(issuer.requests.len(), calls, "refused before any I/O");

    type Case = (&'static str, Box<dyn Fn(&mut RedeemInviteResponse) + Send>);
    let cases: Vec<Case> = vec![
        (
            "47 signatures",
            Box::new(|a| a.blind_signatures.truncate(47 * 256)),
        ),
        ("REPLAYED with signatures", Box::new(|a| a.result = 2)),
        ("WRONG_PERIOD with signatures", Box::new(|a| a.result = 3)),
        ("unspecified result", Box::new(|a| a.result = 0)),
        (
            "a flipped byte",
            Box::new(|a| a.blind_signatures[300] ^= 0x80),
        ),
    ];
    for (why, hook) in cases {
        issuer.tamper.redeem_invite = Some(hook);
        malformed(
            issuer_flow::redeem_invite(&mut issuer, s, &invite, &SEED, FIRST_WEEK, &d).await,
            why,
        );
    }
}

#[tokio::test]
async fn a_payout_claim_is_queued_for_the_value_of_its_credits() {
    let s = schedule();
    let credits = credits(10, CREDIT_EPOCH);
    let value = s.credit_value(CREDIT_EPOCH).unwrap();
    let mut issuer = ModelIssuer::new();
    let queued = issuer_flow::claim_payout(&mut issuer, s, &[0x66; 16], &credits, PAYOUT)
        .await
        .unwrap();
    assert_eq!(queued.result, ClaimPayoutResult::Queued);
    assert_eq!((queued.queued_atomic, queued.spent_mask), (10 * value, 0));
    let p = queued.pack();
    assert_eq!(p.len(), 17);
    assert_eq!((p[0], &p[1..9]), (1, &(10 * value).to_be_bytes()[..]));
    // Idempotent by claim id; the same credits under another id: all spent (uint64 mask).
    let again = issuer_flow::claim_payout(&mut issuer, s, &[0x66; 16], &credits, PAYOUT)
        .await
        .unwrap();
    assert_eq!(again, queued);
    let spent = issuer_flow::claim_payout(&mut issuer, s, &[0x67; 16], &credits, PAYOUT)
        .await
        .unwrap();
    assert_eq!(
        (spent.result, spent.spent_mask),
        (ClaimPayoutResult::CreditsSpent, 0x3FF)
    );
    assert_eq!(&spent.pack()[9..], &0x3FFu64.to_be_bytes());

    let calls = issuer.requests.len();
    let mut repeated = credits[..9].to_vec();
    repeated.push(credits[3].clone());
    for (why, set, address) in [
        ("nine credits", &credits[..9], PAYOUT),
        ("a credit twice", &repeated[..], PAYOUT),
        ("a stagenet address", &credits[..], STAGENET_SUBADDRESS),
        ("not an address", &credits[..], "4"),
    ] {
        refused(
            issuer_flow::claim_payout(&mut issuer, s, &[0x68; 16], set, address).await,
            why,
        );
    }
    assert_eq!(issuer.requests.len(), calls, "refused before any I/O");

    type Case = (&'static str, Box<dyn Fn(&mut ClaimPayoutResponse) + Send>);
    let cases: Vec<Case> = vec![
        ("queued + 1", Box::new(|a| a.queued_atomic += 1)),
        ("a mask on QUEUED", Box::new(|a| a.spent_mask = 1)),
        (
            "a mask beyond the credits",
            Box::new(|a| {
                *a = ClaimPayoutResponse {
                    result: 2,
                    spent_mask: 1 << 10,
                    ..Default::default()
                }
            }),
        ),
        ("CLAIM_CONFLICT with an amount", Box::new(|a| a.result = 3)),
        ("unspecified result", Box::new(|a| a.result = 0)),
    ];
    for (why, hook) in cases {
        let mut issuer = ModelIssuer::new();
        issuer.tamper.claim_payout = Some(hook);
        malformed(
            issuer_flow::claim_payout(&mut issuer, s, &[0x69; 16], &credits, PAYOUT).await,
            why,
        );
    }
    let mut issuer = ModelIssuer::new();
    issuer.tamper.claim_payout = Some(Box::new(|a| {
        *a = ClaimPayoutResponse {
            result: 4,
            ..Default::default()
        }
    }));
    let rejected = issuer_flow::claim_payout(&mut issuer, s, &[0x69; 16], &credits, PAYOUT)
        .await
        .unwrap();
    assert_eq!(rejected.result, ClaimPayoutResult::AddressRejected);
}

#[tokio::test]
async fn a_received_credit_is_exchanged_for_a_fresh_one() {
    let s = schedule();
    let mut issuer = ModelIssuer::new();
    let received = mint(Kind::Credit, CREDIT_EPOCH, None, seed(5, 0x5A));
    let d = digest(s, Product::Refresh, CREDIT_EPOCH);
    let fresh = issuer_flow::refresh_credit(&mut issuer, s, &received, &SEED, &d)
        .await
        .unwrap();
    assert_eq!(fresh.result, RefreshCreditResult::Ok);
    let token = fresh.token.clone().unwrap();
    let v = s.verify_token(&token, Expect::Credit).unwrap();
    assert_eq!(v.epoch, CREDIT_EPOCH);
    assert_ne!(token.nullifier(), received.nullifier());
    assert_packed_tokens(&fresh.pack(), 1, std::slice::from_ref(&token));
    let again = issuer_flow::refresh_credit(&mut issuer, s, &received, &SEED, &d)
        .await
        .unwrap();
    assert_eq!(again, fresh);
    let replayed = issuer_flow::refresh_credit(&mut issuer, s, &received, &[0x25; 32], &d)
        .await
        .unwrap();
    assert_eq!(
        (replayed.result, replayed.token.is_none()),
        (RefreshCreditResult::Replayed, true)
    );
    assert_eq!(replayed.pack(), vec![2]);

    let calls = issuer.requests.len();
    let invite = mint(Kind::Invite, INVITE_EPOCH, None, seed(6, 0x5A));
    for (why, token, dig) in [
        ("an invite as credit", &invite, d),
        (
            "the digest of another epoch",
            &received,
            digest(s, Product::Refresh, CREDIT_EPOCH + 1),
        ),
        (
            "a trial digest",
            &received,
            digest(s, Product::Trial, FIRST_WEEK),
        ),
    ] {
        refused(
            issuer_flow::refresh_credit(&mut issuer, s, token, &SEED, &dig).await,
            why,
        );
    }
    assert_eq!(issuer.requests.len(), calls, "refused before any I/O");

    type Case = (&'static str, Box<dyn Fn(&mut RefreshCreditResponse) + Send>);
    let cases: Vec<Case> = vec![
        (
            "OK without a signature",
            Box::new(|a| a.blind_signature.clear()),
        ),
        (
            "two signatures",
            Box::new(|a| a.blind_signature.extend_from_slice(&[1; 256])),
        ),
        ("a flipped byte", Box::new(|a| a.blind_signature[9] ^= 1)),
        ("REPLAYED with a signature", Box::new(|a| a.result = 2)),
        ("unspecified result", Box::new(|a| a.result = 0)),
    ];
    for (why, hook) in cases {
        issuer.tamper.refresh_credit = Some(hook);
        malformed(
            issuer_flow::refresh_credit(&mut issuer, s, &received, &SEED, &d).await,
            why,
        );
    }
}

#[tokio::test]
async fn issuer_statuses_map_onto_the_existing_categories() {
    let s = schedule();
    for (code, category) in [
        (Code::InvalidArgument, "rejected"),
        (Code::PermissionDenied, "unauthorized"),
        (Code::Unavailable, "relay_unavailable"),
        (Code::ResourceExhausted, "quota"),
        (Code::Internal, "relay_unavailable"),
    ] {
        let mut issuer = ModelIssuer::new();
        issuer.fail_with = Some(code);
        let e = issuer_flow::request_invoice(&mut issuer, s, &[1; 32], &[], FIRST_WEEK)
            .await
            .unwrap_err();
        assert_eq!(for_issuer(&e), category, "{code:?}");
    }
}
