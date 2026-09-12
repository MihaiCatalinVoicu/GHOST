//! T3 for the JNI error paths (design §11.8): the only thing an error carries into Kotlin is its
//! category. Canary secrets (seed, claim key, invoice id, subaddress, tokens, nullifiers,
//! `request_id`, the invite token, namespace, payout address, `claim_id`) go through every issuer
//! and redemption call, into pre-I/O refusals, hostile answers that echo them and failing statuses;
//! the resulting category must be one of the constant categories, and neither it nor the error's
//! text contains a canary in any encoding. The validated answers' `Debug` output is redacted too.

mod common;

use common::*;
use ghost_client_net::categories::{for_issuer, for_relay, ALL};
use ghost_client_net::entitlement::{self, Product};
use ghost_client_net::issuer_client::IssuerError;
use ghost_client_net::issuer_flow;
use ghost_client_net::namespace_client::redeem_with;
use ghost_client_net::RelayError;
use ghost_entitlement::batch;
use ghost_entitlement::Kind;
use ghost_relay_api::proto::Capability;
use tonic::Code;

const SEED: [u8; 32] = *b"canary-seed-3f9a1c7e5b2d4f608192";
const CLAIM_KEY: [u8; 32] = *b"canary-claim-key-7d2e9b4a1f6c830";
const INVOICE_ID: [u8; 16] = *b"canary-invoice-1";
const CLAIM_ID: [u8; 16] = *b"canary-claimid-2";
const REQUEST_ID: [u8; 16] = *b"canary-request-3";
const NAMESPACE: [u8; 32] = *b"canary-namespace-0123456789abcde";

fn encodings(secret: &[u8]) -> Vec<Vec<u8>> {
    vec![
        secret.to_vec(),
        hex::encode(secret).into_bytes(),
        hex::encode_upper(secret).into_bytes(),
    ]
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    needle.len() <= hay.len() && hay.windows(needle.len()).any(|w| w == needle)
}

struct Canaries(Vec<Vec<u8>>);

impl Canaries {
    fn new(extra: &[&[u8]]) -> Self {
        let mut all: Vec<&[u8]> = vec![
            &SEED,
            &CLAIM_KEY,
            &INVOICE_ID,
            &CLAIM_ID,
            &REQUEST_ID,
            &NAMESPACE,
            SUBADDRESS.as_bytes(),
            PAYOUT.as_bytes(),
        ];
        all.extend_from_slice(extra);
        Canaries(all.iter().flat_map(|s| encodings(s)).collect())
    }

    fn assert_clean(&self, what: &str, text: &str) {
        for c in &self.0 {
            assert!(
                !contains(text.as_bytes(), c),
                "{what} leaks a canary: {text}"
            );
        }
    }

    /// The category an issuer error crosses JNI with, and every text form of the error.
    fn issuer_error(&self, what: &str, e: &IssuerError) {
        let category = for_issuer(e);
        assert!(ALL.contains(&category), "{what}: {category}");
        self.assert_clean(what, category);
        self.assert_clean(what, &format!("{e}"));
        self.assert_clean(what, &format!("{e:?}"));
    }

    fn relay_error(&self, what: &str, e: &RelayError) {
        let category = for_relay(e);
        assert!(ALL.contains(&category), "{what}: {category}");
        self.assert_clean(what, category);
        self.assert_clean(what, &format!("{e}"));
    }
}

fn echo(canary: &[u8]) -> String {
    format!(
        "{} {}",
        hex::encode(canary),
        String::from_utf8_lossy(canary)
    )
}

#[tokio::test]
async fn issuer_error_paths_carry_categories_only() {
    let s = schedule();
    let invite = mint(Kind::Invite, INVITE_EPOCH, None, SEED);
    let received = mint(Kind::Credit, CREDIT_EPOCH, None, CLAIM_KEY);
    let credits = credits(10, CREDIT_EPOCH);
    let mut extra: Vec<Vec<u8>> = vec![invite.as_bytes().to_vec(), invite.nullifier().to_vec()];
    extra.push(received.as_bytes().to_vec());
    extra.push(received.nullifier().to_vec());
    for c in &credits {
        extra.push(c.as_bytes().to_vec());
        extra.push(c.nullifier().to_vec());
    }
    let refs: Vec<&[u8]> = extra.iter().map(|v| v.as_slice()).collect();
    let canaries = Canaries::new(&refs);
    let d = |p: Product, i: u64| -> [u8; 32] {
        entitlement::layout_digest(s, p, i).unwrap()[..32]
            .try_into()
            .unwrap()
    };
    let wrong = [0x5A; 32];

    // 1. Refused before any I/O.
    let mut issuer = ModelIssuer::new();
    let errors = vec![
        (
            "blind_sign, wrong layout",
            issuer_flow::blind_sign(
                &mut issuer,
                s,
                &INVOICE_ID,
                &CLAIM_KEY,
                &SEED,
                Product::PackXmr,
                FIRST_WEEK,
                &wrong,
            )
            .await
            .unwrap_err(),
        ),
        (
            "redeem_invite, wrong layout",
            issuer_flow::redeem_invite(&mut issuer, s, &invite, &SEED, FIRST_WEEK, &wrong)
                .await
                .unwrap_err(),
        ),
        (
            "refresh_credit, wrong layout",
            issuer_flow::refresh_credit(&mut issuer, s, &received, &SEED, &wrong)
                .await
                .unwrap_err(),
        ),
        (
            "claim_payout, nine credits",
            issuer_flow::claim_payout(&mut issuer, s, &CLAIM_ID, &credits[..9], PAYOUT)
                .await
                .unwrap_err(),
        ),
        (
            "request_invoice, nine credits",
            issuer_flow::request_invoice(&mut issuer, s, &CLAIM_KEY, &credits[..9], FIRST_WEEK)
                .await
                .unwrap_err(),
        ),
    ];
    assert!(issuer.requests.is_empty());
    for (what, e) in &errors {
        canaries.issuer_error(what, e);
    }

    // 2. Failing statuses (an issuer's text never survives: only the code is kept).
    for code in [
        Code::PermissionDenied,
        Code::InvalidArgument,
        Code::Unavailable,
        Code::Internal,
    ] {
        let mut issuer = ModelIssuer::new();
        issuer.fail_with = Some(code);
        let e = issuer_flow::invoice_status(&mut issuer, &INVOICE_ID, &CLAIM_KEY)
            .await
            .unwrap_err();
        canaries.issuer_error("invoice_status status", &e);
    }

    // 3. Hostile answers echoing the canaries in the wrong fields.
    let mut issuer = ModelIssuer::new();
    issuer.tamper.request_invoice = Some(Box::new(|a| {
        a.subaddress = echo(&CLAIM_KEY);
        a.invoice_id = SEED.to_vec();
    }));
    let e = issuer_flow::request_invoice(
        &mut issuer,
        s,
        &batch::claim_hash(&CLAIM_KEY),
        &[],
        FIRST_WEEK,
    )
    .await
    .unwrap_err();
    canaries.issuer_error("request_invoice echo", &e);

    let mut issuer = ModelIssuer::new();
    let invoice = issuer_flow::request_invoice(
        &mut issuer,
        s,
        &batch::claim_hash(&CLAIM_KEY),
        &[],
        FIRST_WEEK,
    )
    .await
    .unwrap();
    issuer.pay(&invoice.invoice_id);
    issuer.tamper.blind_sign = Some(Box::new(|a| {
        a.blind_signatures = [SEED, CLAIM_KEY].concat().repeat(8)
    }));
    let e = issuer_flow::blind_sign(
        &mut issuer,
        s,
        &invoice.invoice_id,
        &CLAIM_KEY,
        &SEED,
        Product::PackXmr,
        FIRST_WEEK,
        &d(Product::PackXmr, FIRST_WEEK),
    )
    .await
    .unwrap_err();
    canaries.issuer_error("blind_sign echo", &e);

    let mut issuer = ModelIssuer::new();
    let echoed = invite.as_bytes().to_vec();
    issuer.tamper.redeem_invite = Some(Box::new(move |a| a.blind_signatures = echoed.clone()));
    let e = issuer_flow::redeem_invite(
        &mut issuer,
        s,
        &invite,
        &SEED,
        FIRST_WEEK,
        &d(Product::Trial, FIRST_WEEK),
    )
    .await
    .unwrap_err();
    canaries.issuer_error("redeem_invite echo", &e);

    let mut issuer = ModelIssuer::new();
    issuer.tamper.claim_payout = Some(Box::new(|a| {
        a.queued_atomic = u64::from_be_bytes(CLAIM_ID[..8].try_into().unwrap())
    }));
    let e = issuer_flow::claim_payout(&mut issuer, s, &CLAIM_ID, &credits, PAYOUT)
        .await
        .unwrap_err();
    canaries.issuer_error("claim_payout echo", &e);

    let mut issuer = ModelIssuer::new();
    let echoed = received.as_bytes()[..256].to_vec();
    issuer.tamper.refresh_credit = Some(Box::new(move |a| a.blind_signature = echoed.clone()));
    let e = issuer_flow::refresh_credit(
        &mut issuer,
        s,
        &received,
        &SEED,
        &d(Product::Refresh, CREDIT_EPOCH),
    )
    .await
    .unwrap_err();
    canaries.issuer_error("refresh_credit echo", &e);

    // 4. The validated answers print no secret either.
    let mut issuer = ModelIssuer::new();
    let invoice = issuer_flow::request_invoice(
        &mut issuer,
        s,
        &batch::claim_hash(&CLAIM_KEY),
        &[],
        FIRST_WEEK,
    )
    .await
    .unwrap();
    canaries.assert_clean("InvoiceAnswer Debug", &format!("{invoice:?}"));
    let hex_id = hex::encode(invoice.invoice_id);
    assert!(!format!("{invoice:?}").contains(&hex_id));
    let trial = issuer_flow::redeem_invite(
        &mut issuer,
        s,
        &invite,
        &SEED,
        FIRST_WEEK,
        &d(Product::Trial, FIRST_WEEK),
    )
    .await
    .unwrap();
    let shown = format!("{trial:?}");
    for t in &trial.tokens {
        assert!(
            !shown.contains(&hex::encode(t.as_bytes()))
                && !shown.contains(&hex::encode(t.nullifier()))
        );
    }
    canaries.assert_clean("TrialAnswer Debug", &shown);
}

#[tokio::test]
async fn redemption_error_paths_carry_categories_only() {
    let dir = tempfile::tempdir().unwrap();
    let now = at(2959, 86_400);
    let mut relay = InProcessRelay::new(
        open_relay(dir.path(), schedule().clone(), 1, "ghost/test/relay-b", now),
        now,
    );
    let s = schedule();
    let addr = relay_address("ghost/test/relay-b", 443);
    let a1 = pinned("a1");
    let s0 = pinned("s0");
    let canaries = Canaries::new(&[&a1, &s0]);

    // Refused before any I/O: a token bound to another slot.
    let e = redeem_with(&mut relay, s, &addr, NAMESPACE, &s0, REQUEST_ID, now)
        .await
        .unwrap_err();
    canaries.relay_error("redeem pre-I/O", &e);
    assert_eq!(relay.calls, 0);

    // A hostile answer echoing the namespace and the token in the capability.
    let echoed = [&NAMESPACE[..], &a1[..66]].concat();
    relay.tamper = Some(Box::new(move |a| {
        a.capability = Some(Capability {
            token: echoed.clone(),
        })
    }));
    let e = redeem_with(&mut relay, s, &addr, NAMESPACE, &a1, REQUEST_ID, now)
        .await
        .unwrap_err();
    canaries.relay_error("redeem echo", &e);

    // An honest redemption prints no capability, and its packed form is the only carrier.
    relay.tamper = None;
    let ok = redeem_with(&mut relay, s, &addr, NAMESPACE, &a1, REQUEST_ID, now)
        .await
        .unwrap();
    let cap = ok.capability.clone().unwrap();
    let shown = format!("{ok:?}");
    assert!(!shown.contains(&hex::encode(&cap)));
    canaries.assert_clean("RedeemOutcome Debug", &shown);
}
