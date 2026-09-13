//! The wall-clock facade (Phase 8 design §2.8, §5.9): `BlindSign` and `RedeemInvite` answers,
//! errors included, leave at a positive multiple of the reply quantum after the request; the other
//! handlers are not held. A signing call holds its permit of the signing semaphore until its
//! blocking work ends, also when its caller stops waiting (a client `grpc-timeout`, a reset
//! stream), so abandoned calls never run beside the permits (review finding S5-SEC-1).

mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use common::world::{World, BASE};
use ghost_issuer::quantum::{Clock, ReplyQuantum, TimedIssuer};
use ghost_issuer::server::IssuerGrpc;
use ghost_issuer_api::proto as wire;
use ghost_issuer_api::proto::issuer_service_client::IssuerServiceClient;
use ghost_issuer_api::proto::issuer_service_server::IssuerServiceServer;
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

/// A clock that the handlers call first, inside their blocking work: while the gate is closed it
/// holds that work, so a test controls how long a signing call runs.
#[derive(Default)]
struct Gate {
    closed: Mutex<bool>,
    opened: Condvar,
    entered: AtomicUsize,
}

impl Gate {
    fn clock(gate: &Arc<Gate>) -> Clock {
        let g = Arc::clone(gate);
        Arc::new(move || {
            g.entered.fetch_add(1, Ordering::SeqCst);
            let mut closed = g.closed.lock().unwrap();
            while *closed {
                closed = g.opened.wait(closed).unwrap();
            }
            BASE
        })
    }

    fn set_closed(&self, closed: bool) {
        *self.closed.lock().unwrap() = closed;
        self.opened.notify_all();
    }

    fn entered(&self) -> usize {
        self.entered.load(Ordering::SeqCst)
    }

    /// Waits until `n` blocking works have started (bounded).
    async fn wait_entered(&self, n: usize) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while self.entered() < n {
            assert!(Instant::now() < deadline, "the signing work never started");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }
}

/// Opens the gate when dropped, also when an assertion unwinds: the runtime waits for its blocking
/// threads when it shuts down.
struct Opener(Arc<Gate>);

impl Drop for Opener {
    fn drop(&mut self) {
        self.0.set_closed(false);
    }
}

fn unknown_invoice() -> wire::BlindSignRequest {
    wire::BlindSignRequest {
        version: 1,
        invoice_id: vec![7; 16],
        claim_key: vec![7; 32],
        blinded: vec![1; 256],
    }
}

/// How long a second signing call is watched for starting beside an abandoned one.
const WATCH: Duration = Duration::from_millis(300);

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_abandoned_signing_call_keeps_its_permit_until_its_work_ends() {
    let mut w = World::new(true);
    let issuer = Arc::new(w.take_issuer());
    let gate = Arc::new(Gate::default());
    let timed = Arc::new(TimedIssuer::with_clock(
        issuer,
        ReplyQuantum::new(Duration::from_millis(1)),
        1,
        Gate::clock(&gate),
    ));
    gate.set_closed(true);
    let _opener = Opener(Arc::clone(&gate));

    // The caller stops waiting after the call took the one permit and its work started.
    let t = Arc::clone(&timed);
    let abandoned = tokio::spawn(async move { t.blind_sign(unknown_invoice()).await });
    gate.wait_entered(1).await;
    abandoned.abort();
    assert!(abandoned.await.unwrap_err().is_cancelled());

    // The next call waits for the permit the abandoned work still holds.
    let t = Arc::clone(&timed);
    let next = tokio::spawn(async move { t.blind_sign(unknown_invoice()).await });
    tokio::time::sleep(WATCH).await;
    assert_eq!(
        gate.entered(),
        1,
        "a signing call ran beside the abandoned one's work"
    );
    gate.set_closed(false);
    let r = next.await.unwrap();
    assert_eq!(r.unwrap_err().code(), Code::PermissionDenied);
    assert_eq!(gate.entered(), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_client_grpc_timeout_does_not_free_the_signing_permit() {
    let mut w = World::new(true);
    let issuer = Arc::new(w.take_issuer());
    let gate = Arc::new(Gate::default());
    let timed = TimedIssuer::with_clock(
        issuer,
        ReplyQuantum::new(Duration::from_millis(1)),
        1,
        Gate::clock(&gate),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(
        tonic::transport::Server::builder()
            .add_service(IssuerServiceServer::new(IssuerGrpc::new(timed)))
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener)),
    );
    let channel = tonic::transport::Endpoint::from_shared(format!("http://{addr}"))
        .unwrap()
        .connect()
        .await
        .unwrap();
    let mut client = IssuerServiceClient::new(channel);
    gate.set_closed(true);
    let _opener = Opener(Arc::clone(&gate));

    // tonic obeys the client's grpc-timeout and drops the handler future on the server.
    let mut request = tonic::Request::new(unknown_invoice());
    request.set_timeout(Duration::from_millis(200));
    let started = Instant::now();
    let answer = client.blind_sign(request).await.unwrap_err();
    assert_eq!(answer.code(), Code::Cancelled, "{answer:?}");
    assert!(started.elapsed() < Duration::from_secs(5));
    gate.wait_entered(1).await;

    let mut c = client.clone();
    let next = tokio::spawn(async move { c.blind_sign(unknown_invoice()).await });
    tokio::time::sleep(WATCH).await;
    assert_eq!(
        gate.entered(),
        1,
        "a signing call ran beside the timed-out one's work"
    );
    gate.set_closed(false);
    let r = next.await.unwrap();
    assert_eq!(r.unwrap_err().code(), Code::PermissionDenied);
}
