//! The wall-clock facade (Phase 8 design §2.8, §5.9): `BlindSign` and `RedeemInvite` answers,
//! errors included, leave at a positive multiple of the reply quantum after the request; the other
//! handlers are not held.

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::world::World;
use ghost_issuer::quantum::{ReplyQuantum, TimedIssuer};
use ghost_issuer_api::proto as wire;
use tokio::time::Instant;
use tonic::Code;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn signing_answers_leave_at_the_quantum() {
    let mut w = World::new(true);
    let issuer = Arc::new(w.take_issuer());
    let q = Duration::from_millis(400);
    let timed = TimedIssuer::new(issuer, ReplyQuantum::new(q), 2);

    let start = Instant::now();
    let r = timed
        .blind_sign(wire::BlindSignRequest {
            version: 1,
            invoice_id: vec![7; 16],
            claim_key: vec![7; 32],
            blinded: vec![1; 256],
        })
        .await;
    assert_eq!(r.unwrap_err().code(), Code::PermissionDenied);
    let elapsed = start.elapsed();
    assert!(elapsed >= q, "answered after {elapsed:?}");

    let start = Instant::now();
    let r = timed
        .redeem_invite(wire::RedeemInviteRequest {
            version: 1,
            invite_token: vec![0; 10],
            base_week: 0,
            blinded: Vec::new(),
        })
        .await;
    assert_eq!(r.unwrap_err().code(), Code::InvalidArgument);
    assert!(start.elapsed() >= q);

    let r = timed
        .invoice_status(wire::InvoiceStatusRequest {
            version: 1,
            invoice_id: vec![7; 16],
            claim_key: vec![7; 32],
        })
        .await;
    assert_eq!(r.unwrap_err().code(), Code::PermissionDenied);
}
