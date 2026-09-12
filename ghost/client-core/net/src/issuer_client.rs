//! gRPC client of the entitlement issuer, tunnelled through Tor (Phase 8 design §11.7).
//!
//! It uses the hyper-over-Arti connector of [`crate::RelayClient`]: HTTP/2 only, a constant origin
//! (`issuer.invalid`, identical for every client), no `user-agent` header (tonic is linked with
//! `codegen` only), every call bounded by a deadline. The destination is fixed: the issuer onion of
//! the Entitlement Schedule built into the library (`ES.issuer_onion`); no caller chooses it. The
//! circuits are those of one issuer flow ([`IsolationScope::IssuerFlow`]), so a flow never shares a
//! circuit with another flow or a namespace.
//!
//! This module only moves messages. The checks made before any byte leaves the device and the
//! validation of every answer against the ES live in [`crate::issuer_flow`], generic over
//! [`IssuerRpc`]. An error keeps the gRPC code of an answer, never its text.

use crate::isolation::IsolationScope;
use crate::onion::OnionAddress;
use crate::relay_client::{
    onion_connector, transport_cause, BoxError, Io, OnionConnector, StreamType,
};
use crate::transport::{TorTransport, TransportError};
use ghost_entitlement::Schedule;
use ghost_issuer_api::proto::issuer_service_client::IssuerServiceClient;
use ghost_issuer_api::proto::{
    BlindSignRequest, BlindSignResponse, ClaimPayoutRequest, ClaimPayoutResponse,
    InvoiceStatusRequest, InvoiceStatusResponse, RedeemInviteRequest, RedeemInviteResponse,
    RefreshCreditRequest, RefreshCreditResponse, RequestInvoiceRequest, RequestInvoiceResponse,
};
use hyper_util::client::legacy::Client as HyperClient;
use hyper_util::rt::TokioExecutor;
use std::future::Future;
use std::time::Duration;

/// Upper bound of one issuer call (design §11.7: `min(deadlineMs, 60 s)`).
pub const ISSUER_RPC_DEADLINE: Duration = Duration::from_secs(60);
/// Upper bound of `BlindSign` and `RedeemInvite`, which move up to 161 KiB each way over Tor and
/// wait for the issuer's 2 s reply quantum (design §2.8, §11.7).
pub const ISSUER_SIGNING_DEADLINE: Duration = Duration::from_secs(120);
/// Largest answer accepted: the largest layout's `BlindSign` answer is 2 563 x 256 bytes
/// (about 641 KiB, design §5.9); a hostile issuer cannot make the client buffer more.
pub const MAX_ANSWER_BYTES: usize = 1 << 20;

/// Constant origin: never resolved (the connector ignores it), identical for every client.
const ORIGIN: &str = "http://issuer.invalid";

#[derive(Debug, Clone)]
pub enum IssuerError {
    /// The onion service could not be reached (descriptor, rendezvous, circuit) or Tor is not
    /// bootstrapped.
    Transport(TransportError),
    /// The issuer answered with a gRPC status; only its code is kept.
    Rpc(tonic::Code),
    /// A caller argument or a local precondition failed; nothing was sent.
    InvalidArgument,
    /// The answer violates the protocol or disagrees with the Entitlement Schedule.
    Malformed,
    /// The call's deadline elapsed.
    Timeout,
}

impl std::fmt::Display for IssuerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IssuerError::Transport(e) => write!(f, "{e}"),
            IssuerError::Rpc(code) => write!(f, "issuer refused the request ({code:?})"),
            IssuerError::InvalidArgument => f.write_str("invalid argument"),
            IssuerError::Malformed => f.write_str("issuer returned a malformed response"),
            IssuerError::Timeout => f.write_str("issuer request timed out"),
        }
    }
}

impl std::error::Error for IssuerError {}

/// The six issuer RPCs (design §5.2). [`IssuerClient`] implements them over Tor; the checks of
/// [`crate::issuer_flow`] run against any implementation.
pub trait IssuerRpc {
    fn request_invoice(
        &mut self,
        req: RequestInvoiceRequest,
    ) -> impl Future<Output = Result<RequestInvoiceResponse, IssuerError>> + Send;
    fn blind_sign(
        &mut self,
        req: BlindSignRequest,
    ) -> impl Future<Output = Result<BlindSignResponse, IssuerError>> + Send;
    fn invoice_status(
        &mut self,
        req: InvoiceStatusRequest,
    ) -> impl Future<Output = Result<InvoiceStatusResponse, IssuerError>> + Send;
    fn redeem_invite(
        &mut self,
        req: RedeemInviteRequest,
    ) -> impl Future<Output = Result<RedeemInviteResponse, IssuerError>> + Send;
    fn claim_payout(
        &mut self,
        req: ClaimPayoutRequest,
    ) -> impl Future<Output = Result<ClaimPayoutResponse, IssuerError>> + Send;
    fn refresh_credit(
        &mut self,
        req: RefreshCreditRequest,
    ) -> impl Future<Output = Result<RefreshCreditResponse, IssuerError>> + Send;
}

pub struct IssuerClient<C> {
    inner: IssuerServiceClient<HyperClient<C, tonic::body::Body>>,
    /// The caller's deadline; each call is further capped by its own bound.
    deadline: Duration,
}

impl IssuerClient<OnionConnector> {
    /// Client for the issuer onion of `schedule` over Tor, on the circuits of
    /// `IsolationScope::IssuerFlow(flow)`. No connection is opened until the first call.
    pub fn over_tor(
        transport: &TorTransport,
        schedule: &Schedule,
        flow: [u8; 16],
    ) -> Result<Self, IssuerError> {
        let issuer = OnionAddress::parse(&schedule.content().issuer_onion)
            .map_err(|_| IssuerError::InvalidArgument)?;
        Ok(Self::with_connector(onion_connector(
            transport,
            &issuer,
            &IsolationScope::IssuerFlow(flow),
        )))
    }
}

impl<C> IssuerClient<C>
where
    C: tower::Service<http::Uri, Response = Io<C::Stream>> + Clone + Send + Sync + 'static,
    C: StreamType,
    C::Future: Unpin + Send,
    C::Error: Into<BoxError>,
{
    pub(crate) fn with_connector(connector: C) -> Self {
        let http = HyperClient::builder(TokioExecutor::new())
            .http2_only(true)
            .build(connector);
        let origin = http::Uri::from_static(ORIGIN);
        IssuerClient {
            inner: IssuerServiceClient::with_origin(http, origin)
                .max_decoding_message_size(MAX_ANSWER_BYTES),
            deadline: ISSUER_SIGNING_DEADLINE,
        }
    }

    /// Sets the deadline of every later call: `min(deadline, 60 s)`, and `min(deadline, 120 s)`
    /// for `BlindSign` and `RedeemInvite`. A zero deadline is refused (it could only fail).
    pub fn set_deadline(&mut self, deadline: Duration) -> Result<(), IssuerError> {
        if deadline.is_zero() {
            return Err(IssuerError::InvalidArgument);
        }
        self.deadline = deadline.min(ISSUER_SIGNING_DEADLINE);
        Ok(())
    }

    /// The bound of an ordinary call.
    pub fn rpc_deadline(&self) -> Duration {
        self.deadline.min(ISSUER_RPC_DEADLINE)
    }

    /// The bound of `BlindSign` and `RedeemInvite`.
    pub fn signing_deadline(&self) -> Duration {
        self.deadline.min(ISSUER_SIGNING_DEADLINE)
    }
}

async fn with_deadline<T>(
    deadline: Duration,
    fut: impl Future<Output = Result<tonic::Response<T>, tonic::Status>>,
) -> Result<T, IssuerError> {
    match tokio::time::timeout(deadline, fut).await {
        Ok(Ok(resp)) => Ok(resp.into_inner()),
        Ok(Err(status)) => Err(transport_cause(&status)
            .map(IssuerError::Transport)
            .unwrap_or(IssuerError::Rpc(status.code()))),
        Err(_) => Err(IssuerError::Timeout),
    }
}

impl<C> IssuerRpc for IssuerClient<C>
where
    C: tower::Service<http::Uri, Response = Io<C::Stream>> + Clone + Send + Sync + 'static,
    C: StreamType,
    C::Future: Unpin + Send,
    C::Error: Into<BoxError>,
{
    fn request_invoice(
        &mut self,
        req: RequestInvoiceRequest,
    ) -> impl Future<Output = Result<RequestInvoiceResponse, IssuerError>> + Send {
        let d = self.rpc_deadline();
        with_deadline(d, self.inner.request_invoice(req))
    }

    fn blind_sign(
        &mut self,
        req: BlindSignRequest,
    ) -> impl Future<Output = Result<BlindSignResponse, IssuerError>> + Send {
        let d = self.signing_deadline();
        with_deadline(d, self.inner.blind_sign(req))
    }

    fn invoice_status(
        &mut self,
        req: InvoiceStatusRequest,
    ) -> impl Future<Output = Result<InvoiceStatusResponse, IssuerError>> + Send {
        let d = self.rpc_deadline();
        with_deadline(d, self.inner.invoice_status(req))
    }

    fn redeem_invite(
        &mut self,
        req: RedeemInviteRequest,
    ) -> impl Future<Output = Result<RedeemInviteResponse, IssuerError>> + Send {
        let d = self.signing_deadline();
        with_deadline(d, self.inner.redeem_invite(req))
    }

    fn claim_payout(
        &mut self,
        req: ClaimPayoutRequest,
    ) -> impl Future<Output = Result<ClaimPayoutResponse, IssuerError>> + Send {
        let d = self.rpc_deadline();
        with_deadline(d, self.inner.claim_payout(req))
    }

    fn refresh_credit(
        &mut self,
        req: RefreshCreditRequest,
    ) -> impl Future<Output = Result<RefreshCreditResponse, IssuerError>> + Send {
        let d = self.rpc_deadline();
        with_deadline(d, self.inner.refresh_credit(req))
    }
}

#[cfg(test)]
#[allow(clippy::disallowed_methods, clippy::disallowed_types)] // loopback issuers and TCP connectors
mod tests {
    use super::*;
    use crate::categories::{for_issuer, ALL, MALFORMED_RESPONSE, QUOTA, REJECTED};
    use crate::categories::{RELAY_UNAVAILABLE, TIMEOUT, TRANSPORT, UNAUTHORIZED};
    use crate::loopback::TcpConnector;
    use ghost_issuer_api::proto::issuer_service_server::{IssuerService, IssuerServiceServer};
    use std::net::SocketAddr;
    use std::pin::Pin;
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll};
    use tokio::net::{TcpListener, TcpStream};
    use tokio_stream::wrappers::TcpListenerStream;
    use tonic::{Code, Request, Response, Status};

    /// What each request looked like at the issuer.
    #[derive(Debug, Clone)]
    struct Seen {
        user_agent: Option<String>,
        authority: Option<String>,
        path: String,
    }

    /// Answers every call; `status` turns every answer into that gRPC status (message included,
    /// so tests can check it never reaches an error). `big` makes BlindSign answer 2 MiB.
    #[derive(Clone, Default)]
    struct LoopbackIssuer {
        status: Option<Code>,
        big: bool,
        requests: Arc<Mutex<Vec<String>>>,
    }

    const ISSUER_TEXT: &str = "issuer-text-never-forwarded";

    impl LoopbackIssuer {
        fn answer<T>(&self, name: &str, value: T) -> Result<Response<T>, Status> {
            self.requests.lock().unwrap().push(name.to_owned());
            match self.status {
                Some(code) => Err(Status::new(code, ISSUER_TEXT)),
                None => Ok(Response::new(value)),
            }
        }
    }

    #[tonic::async_trait]
    impl IssuerService for LoopbackIssuer {
        async fn request_invoice(
            &self,
            r: Request<RequestInvoiceRequest>,
        ) -> Result<Response<RequestInvoiceResponse>, Status> {
            let r = r.into_inner();
            self.answer(
                "request_invoice",
                RequestInvoiceResponse {
                    result: 2,
                    amount_atomic: r.base_week,
                    ..Default::default()
                },
            )
        }
        async fn blind_sign(
            &self,
            r: Request<BlindSignRequest>,
        ) -> Result<Response<BlindSignResponse>, Status> {
            let r = r.into_inner();
            let blind_signatures = if self.big {
                vec![7u8; 2 << 20]
            } else {
                r.blinded
            };
            self.answer(
                "blind_sign",
                BlindSignResponse {
                    state: 1,
                    blind_signatures,
                    ..Default::default()
                },
            )
        }
        async fn invoice_status(
            &self,
            _r: Request<InvoiceStatusRequest>,
        ) -> Result<Response<InvoiceStatusResponse>, Status> {
            self.answer(
                "invoice_status",
                InvoiceStatusResponse {
                    state: 2,
                    ..Default::default()
                },
            )
        }
        async fn redeem_invite(
            &self,
            _r: Request<RedeemInviteRequest>,
        ) -> Result<Response<RedeemInviteResponse>, Status> {
            self.answer(
                "redeem_invite",
                RedeemInviteResponse {
                    result: 2,
                    ..Default::default()
                },
            )
        }
        async fn claim_payout(
            &self,
            _r: Request<ClaimPayoutRequest>,
        ) -> Result<Response<ClaimPayoutResponse>, Status> {
            self.answer(
                "claim_payout",
                ClaimPayoutResponse {
                    result: 3,
                    ..Default::default()
                },
            )
        }
        async fn refresh_credit(
            &self,
            _r: Request<RefreshCreditRequest>,
        ) -> Result<Response<RefreshCreditResponse>, Status> {
            self.answer(
                "refresh_credit",
                RefreshCreditResponse {
                    result: 2,
                    ..Default::default()
                },
            )
        }
    }

    async fn serve(issuer: LoopbackIssuer) -> (SocketAddr, Arc<Mutex<Vec<Seen>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let seen: Arc<Mutex<Vec<Seen>>> = Arc::default();
        let record = Arc::clone(&seen);
        tokio::spawn(async move {
            tonic::transport::Server::builder()
                .layer(tower::util::MapRequestLayer::new(
                    move |req: http::Request<tonic::body::Body>| {
                        record.lock().unwrap().push(Seen {
                            user_agent: req
                                .headers()
                                .get(http::header::USER_AGENT)
                                .map(|v| v.to_str().unwrap_or("?").to_owned()),
                            authority: req.uri().authority().map(|a| a.to_string()),
                            path: req.uri().path().to_owned(),
                        });
                        req
                    },
                ))
                .add_service(IssuerServiceServer::new(issuer))
                .serve_with_incoming(TcpListenerStream::new(listener))
                .await
                .unwrap();
        });
        (addr, seen)
    }

    #[tokio::test]
    async fn every_call_reaches_the_issuer_without_user_agent_under_a_constant_origin() {
        let (addr, seen) = serve(LoopbackIssuer::default()).await;
        let mut c = IssuerClient::with_connector(TcpConnector::new(addr));
        let r = c
            .request_invoice(RequestInvoiceRequest {
                version: 1,
                base_week: 2957,
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!((r.result, r.amount_atomic), (2, 2957));
        let b = c
            .blind_sign(BlindSignRequest {
                version: 1,
                blinded: vec![5; 512],
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(b.blind_signatures, vec![5; 512]);
        assert_eq!(
            c.invoice_status(InvoiceStatusRequest::default())
                .await
                .unwrap()
                .state,
            2
        );
        assert_eq!(
            c.redeem_invite(RedeemInviteRequest::default())
                .await
                .unwrap()
                .result,
            2
        );
        assert_eq!(
            c.claim_payout(ClaimPayoutRequest::default())
                .await
                .unwrap()
                .result,
            3
        );
        assert_eq!(
            c.refresh_credit(RefreshCreditRequest::default())
                .await
                .unwrap()
                .result,
            2
        );
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 6);
        for s in seen.iter() {
            assert_eq!(s.user_agent, None, "no user-agent: {s:?}");
            assert_eq!(s.authority.as_deref(), Some("issuer.invalid"), "{s:?}");
            assert!(
                s.path.starts_with("/ghost.issuer.v1.IssuerService/"),
                "{s:?}"
            );
        }
    }

    #[tokio::test]
    async fn statuses_keep_their_code_only_and_map_onto_existing_categories() {
        for (code, category) in [
            (Code::InvalidArgument, REJECTED),
            (Code::PermissionDenied, UNAUTHORIZED),
            (Code::Unavailable, RELAY_UNAVAILABLE),
            (Code::ResourceExhausted, QUOTA),
            (Code::Internal, RELAY_UNAVAILABLE),
            (Code::Unauthenticated, RELAY_UNAVAILABLE),
            (Code::NotFound, RELAY_UNAVAILABLE),
        ] {
            let (addr, _) = serve(LoopbackIssuer {
                status: Some(code),
                ..Default::default()
            })
            .await;
            let mut c = IssuerClient::with_connector(TcpConnector::new(addr));
            let e = c
                .invoice_status(InvoiceStatusRequest::default())
                .await
                .unwrap_err();
            assert!(matches!(e, IssuerError::Rpc(got) if got == code), "{e:?}");
            assert_eq!(for_issuer(&e), category, "{code:?}");
            assert!(!format!("{e} {e:?}").contains(ISSUER_TEXT));
            assert!(ALL.contains(&for_issuer(&e)));
        }
    }

    #[tokio::test]
    async fn an_oversized_answer_is_refused() {
        let (addr, _) = serve(LoopbackIssuer {
            big: true,
            ..Default::default()
        })
        .await;
        let mut c = IssuerClient::with_connector(TcpConnector::new(addr));
        let e = c.blind_sign(BlindSignRequest::default()).await.unwrap_err();
        assert!(matches!(e, IssuerError::Rpc(_)), "{e:?}");
    }

    #[tokio::test]
    async fn deadlines_are_capped_per_call_and_must_be_positive() {
        let mut c = IssuerClient::with_connector(TcpConnector::new("127.0.0.1:9".parse().unwrap()));
        assert_eq!(c.rpc_deadline(), ISSUER_RPC_DEADLINE);
        assert_eq!(c.signing_deadline(), ISSUER_SIGNING_DEADLINE);
        c.set_deadline(Duration::from_secs(90)).unwrap();
        assert_eq!(c.rpc_deadline(), Duration::from_secs(60));
        assert_eq!(c.signing_deadline(), Duration::from_secs(90));
        c.set_deadline(Duration::from_millis(5)).unwrap();
        assert_eq!(c.rpc_deadline(), Duration::from_millis(5));
        assert_eq!(c.signing_deadline(), Duration::from_millis(5));
        c.set_deadline(Duration::MAX).unwrap();
        assert_eq!(c.signing_deadline(), ISSUER_SIGNING_DEADLINE);
        assert!(matches!(
            c.set_deadline(Duration::ZERO),
            Err(IssuerError::InvalidArgument)
        ));
        assert_eq!(
            c.signing_deadline(),
            ISSUER_SIGNING_DEADLINE,
            "a refused deadline changes nothing"
        );
    }

    #[tokio::test]
    async fn an_issuer_that_never_answers_hits_the_deadline() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((s, _)) = listener.accept().await {
                held.push(s);
            }
        });
        let mut c = IssuerClient::with_connector(TcpConnector::new(addr));
        c.set_deadline(Duration::from_millis(300)).unwrap();
        let started = std::time::Instant::now();
        let e = c.blind_sign(BlindSignRequest::default()).await.unwrap_err();
        assert!(matches!(e, IssuerError::Timeout), "{e:?}");
        assert_eq!(for_issuer(&e), TIMEOUT);
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    /// Connector standing in for an issuer onion service that cannot be reached.
    #[derive(Clone)]
    struct UnreachableOnion;

    impl StreamType for UnreachableOnion {
        type Stream = TcpStream;
    }

    impl tower::Service<http::Uri> for UnreachableOnion {
        type Response = Io<TcpStream>;
        type Error = BoxError;
        type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;
        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }
        fn call(&mut self, _uri: http::Uri) -> Self::Future {
            Box::pin(async {
                Err(Box::new(TransportError::Connect("descriptor not found".into())) as BoxError)
            })
        }
    }

    #[tokio::test]
    async fn an_unreachable_issuer_is_reported_as_transport() {
        let mut c = IssuerClient::with_connector(UnreachableOnion);
        let e = c
            .request_invoice(RequestInvoiceRequest::default())
            .await
            .unwrap_err();
        assert!(
            matches!(e, IssuerError::Transport(TransportError::Connect(_))),
            "{e:?}"
        );
        assert_eq!(for_issuer(&e), TRANSPORT);
        assert_eq!(for_issuer(&IssuerError::Malformed), MALFORMED_RESPONSE);
    }

    #[test]
    fn the_client_dials_the_schedule_issuer_onion_on_the_flow_scope() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let _g = rt.enter();
        let dir = tempfile::tempdir().unwrap();
        let t = TorTransport::create(&crate::TransportConfig {
            state_dir: dir.path().join("state"),
            cache_dir: dir.path().join("cache"),
            bridge_lines: vec![],
        })
        .unwrap();
        let schedule = crate::entitlement::embedded_schedule().expect("embedded schedule");
        let flow = [0x3C; 16];
        let _client = IssuerClient::over_tor(&t, schedule, flow).unwrap();
        let token = t.isolation_token(&IsolationScope::IssuerFlow(flow));
        let connector = onion_connector(
            &t,
            &OnionAddress::parse(&schedule.content().issuer_onion).unwrap(),
            &IsolationScope::IssuerFlow(flow),
        );
        assert_eq!(connector.isolation_token(), token);
        assert_eq!(
            connector.address().to_string(),
            schedule.content().issuer_onion
        );
        t.end_issuer_flow(&flow);
        assert_ne!(t.isolation_token(&IsolationScope::IssuerFlow(flow)), token);
    }
}
