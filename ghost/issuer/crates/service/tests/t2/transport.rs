//! The loopback transport of the T2 world (Phase 8 design §13.4): the production client-core calls
//! (`issuer_flow::*`, `namespace_client::redeem_with`) run over in-process links to the real issuer
//! handlers (`Issuer::*_at`) and the real relays (`Relay::*_at`), and every connection carries the
//! circuit label a server would observe, `H(isolation token id ‖ service)`.
//!
//! A link records the call in the views as the server saw it: arrival time, circuit label, every
//! request and response field, the status, and for relays the capture event the handler wrote.
//! Injected faults are transport or server behaviour: `UNAVAILABLE` (the issuer refuses without
//! processing), a lost answer (the server processed the request, the client never sees the answer),
//! and, for the twin worlds, extra latency and relays that lie about their clock (NI-3).

use std::collections::HashMap;
use std::fs::File;
use std::future::Future;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

use ghost_client_net::issuer_client::{IssuerError, IssuerRpc};
use ghost_client_net::namespace_client::RedeemRpc;
use ghost_client_net::{OnionAddress, RelayError};
use ghost_issuer::Issuer;
use ghost_issuer_api::proto as wire;
use ghost_relay_api::proto as rw;
use ghost_relay_node::Relay;
use ghost_t2_join::model::{
    Field, IssuerCall, IssuerOp, IssuerTruth, Label, RelayCall, RelayOp, RelayTruth,
};
use sha2::{Digest, Sha256};
use tonic::Status;

use super::views::Recorder;

/// Runs a future that the loopback links complete without waiting.
pub fn block_on<F: Future>(f: F) -> F::Output {
    let mut f = std::pin::pin!(f);
    let mut cx = Context::from_waker(Waker::noop());
    match f.as_mut().poll(&mut cx) {
        Poll::Ready(v) => v,
        Poll::Pending => panic!("a loopback call did not complete in one poll"),
    }
}

/// `H(isolation token id ‖ service)`.
pub fn label(token: &[u8], service: &str) -> Label {
    let mut h = Sha256::new();
    h.update(b"ghost/t2/circuit");
    h.update((token.len() as u32).to_be_bytes());
    h.update(token);
    h.update(service.as_bytes());
    h.finalize().into()
}

fn blocks<'a>(name: &'static str, bytes: &'a [u8]) -> Vec<Field<'a>> {
    bytes
        .chunks(256)
        .map(|b| Field { name, bytes: b })
        .collect()
}

fn f<'a>(name: &'static str, bytes: &'a [u8]) -> Field<'a> {
    Field { name, bytes }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IssuerFault {
    None,
    /// The issuer answers `UNAVAILABLE` without processing the request.
    Unavailable,
    /// The issuer processes the request; the answer never reaches the client (a client crash
    /// after sending, or a lost connection).
    LoseAnswer,
}

/// A lying issuer layer (mutant M16 and the S4 world of §19.16): it answers the first `lies`
/// `BlindSign` calls of every invoice `AWAITING_CONFIRMATIONS` without asking the handler.
///
/// With `wrong_period > 0` it also answers that fraction of `RequestInvoice` and `RedeemInvite`
/// calls `WRONG_PERIOD` (the issuer recorded nothing), chosen by a PRF of the request's bytes, so
/// an identical retry gets the same answer and a re-prepared flow a fresh draw (mutant M23 and its
/// control, §19.27).
#[derive(Debug, Default)]
pub struct Liar {
    pub lies: u32,
    pub counts: HashMap<Vec<u8>, u32>,
    pub wrong_period: f64,
    pub key: [u8; 32],
}

impl Liar {
    /// True when the call whose request carries `parts` is answered `WRONG_PERIOD`.
    fn lies_wrong_period(&self, parts: &[&[u8]]) -> bool {
        if self.wrong_period <= 0.0 {
            return false;
        }
        let mut h = Sha256::new();
        h.update(b"ghost/t2/liar-wrong-period");
        h.update(self.key);
        for p in parts {
            h.update((p.len() as u64).to_be_bytes());
            h.update(p);
        }
        let d = h.finalize();
        let u =
            u64::from_be_bytes(d[..8].try_into().unwrap()) as f64 / 18_446_744_073_709_551_616.0;
        u < self.wrong_period
    }
}

/// One issuer call over the loopback: everything the call needs and records.
pub struct IssuerLink<'a> {
    pub issuer: &'a Issuer,
    pub rec: &'a mut Recorder,
    pub t: u64,
    pub latency: u64,
    pub label: Label,
    pub truth: IssuerTruth,
    pub fault: IssuerFault,
    pub liar: Option<&'a mut Liar>,
    /// Extra request and response fields a mutant protocol carries (recorded in the issuer view).
    pub extra_req: Vec<(&'static str, Vec<u8>)>,
    pub extra_resp: Vec<(&'static str, Vec<u8>)>,
    /// The time the answer reached the client.
    pub answered: Option<u64>,
    /// Every request the issuer's endpoint received, counted at the entry of each handler call
    /// (the completeness check compares it with the issuer view, which the recorder fills).
    pub received: &'a mut u64,
    /// NI-1: seconds added to the latency of a signing `BlindSign` answer (finalization moves inside
    /// its activation-slot cell).
    pub sign_extra: u64,
}

fn code(s: &Status) -> i32 {
    s.code() as i32
}

impl IssuerLink<'_> {
    #[allow(clippy::too_many_arguments)]
    fn record(
        &mut self,
        op: IssuerOp,
        request: Vec<Field<'_>>,
        response: Vec<Field<'_>>,
        ints: &[(&'static str, u64)],
        status: i32,
    ) {
        let extra_req = std::mem::take(&mut self.extra_req);
        let extra_resp = std::mem::take(&mut self.extra_resp);
        let mut request: Vec<Field<'_>> = request;
        let mut response: Vec<Field<'_>> = response;
        for (n, v) in &extra_req {
            request.push(f(n, v));
        }
        for (n, v) in &extra_resp {
            response.push(f(n, v));
        }
        let call = IssuerCall {
            t: self.t,
            t_resp: self.t + self.latency,
            label: self.label,
            op,
            request,
            response,
            status,
            truth: self.truth,
        };
        self.rec.issuer_call(&call, ints);
    }

    fn deliver<T>(&mut self, r: Result<T, Status>) -> Result<T, IssuerError> {
        match r {
            Ok(v) if self.fault == IssuerFault::LoseAnswer => {
                drop(v);
                Err(IssuerError::Timeout)
            }
            Ok(v) => {
                self.answered = Some(self.t + self.latency);
                Ok(v)
            }
            Err(s) => {
                self.answered = Some(self.t + self.latency);
                Err(IssuerError::Rpc(s.code()))
            }
        }
    }

    fn unavailable(&self) -> bool {
        self.fault == IssuerFault::Unavailable
    }
}

impl IssuerRpc for IssuerLink<'_> {
    fn request_invoice(
        &mut self,
        req: wire::RequestInvoiceRequest,
    ) -> impl Future<Output = Result<wire::RequestInvoiceResponse, IssuerError>> + Send {
        *self.received += 1;
        let mut parts: Vec<&[u8]> = vec![&req.claim_hash];
        parts.extend(req.credits.iter().map(Vec::as_slice));
        let week = req.base_week.to_be_bytes();
        parts.push(&week);
        let lie = self
            .liar
            .as_deref()
            .is_some_and(|l| l.lies_wrong_period(&parts));
        let r = if self.unavailable() {
            Err(Status::unavailable("unavailable"))
        } else if lie {
            Ok(wire::RequestInvoiceResponse {
                result: wire::RequestInvoiceResult::WrongPeriod as i32,
                ..Default::default()
            })
        } else {
            self.issuer.request_invoice_at(req.clone(), self.t)
        };
        let mut request = vec![f("claim_hash", &req.claim_hash)];
        request.extend(req.credits.iter().map(|c| f("credits", c)));
        let mut ints = vec![
            ("base_week", req.base_week),
            ("rail", req.rail as u64),
            ("product", req.product as u64),
        ];
        match &r {
            Ok(resp) => {
                ints.extend([
                    ("result", resp.result as u64),
                    ("amount_atomic", resp.amount_atomic),
                    ("spent_mask", u64::from(resp.spent_mask)),
                ]);
                let response = vec![
                    f("invoice_id", &resp.invoice_id),
                    f("subaddress", resp.subaddress.as_bytes()),
                ];
                self.record(IssuerOp::RequestInvoice, request, response, &ints, 0);
            }
            Err(s) => self.record(
                IssuerOp::RequestInvoice,
                request,
                Vec::new(),
                &ints,
                code(s),
            ),
        }
        std::future::ready(self.deliver(r))
    }

    fn blind_sign(
        &mut self,
        req: wire::BlindSignRequest,
    ) -> impl Future<Output = Result<wire::BlindSignResponse, IssuerError>> + Send {
        *self.received += 1;
        let lie = match self.liar.as_deref_mut() {
            Some(l) => {
                let n = l.counts.entry(req.invoice_id.clone()).or_insert(0);
                *n += 1;
                *n <= l.lies
            }
            None => false,
        };
        let r = if self.unavailable() {
            Err(Status::unavailable("unavailable"))
        } else if lie {
            Ok(wire::BlindSignResponse {
                state: wire::InvoiceState::AwaitingConfirmations as i32,
                blind_signatures: Vec::new(),
                credited_atomic: 0,
                seen_atomic: 0,
            })
        } else {
            self.issuer.blind_sign_at(req.clone(), self.t)
        };
        if matches!(&r, Ok(resp) if resp.state == wire::InvoiceState::Signed as i32) {
            self.latency += self.sign_extra;
        }
        let mut request = vec![
            f("invoice_id", &req.invoice_id),
            f("claim_key", &req.claim_key),
        ];
        request.extend(blocks("blinded", &req.blinded));
        match &r {
            Ok(resp) => {
                let ints = [
                    ("state", resp.state as u64),
                    ("credited_atomic", resp.credited_atomic),
                    ("seen_atomic", resp.seen_atomic),
                ];
                let response = blocks("blind_signatures", &resp.blind_signatures);
                self.record(IssuerOp::BlindSign, request, response, &ints, 0);
            }
            Err(s) => self.record(IssuerOp::BlindSign, request, Vec::new(), &[], code(s)),
        }
        std::future::ready(self.deliver(r))
    }

    fn invoice_status(
        &mut self,
        req: wire::InvoiceStatusRequest,
    ) -> impl Future<Output = Result<wire::InvoiceStatusResponse, IssuerError>> + Send {
        *self.received += 1;
        let r = if self.unavailable() {
            Err(Status::unavailable("unavailable"))
        } else {
            self.issuer.invoice_status_at(req.clone(), self.t)
        };
        let request = vec![
            f("invoice_id", &req.invoice_id),
            f("claim_key", &req.claim_key),
        ];
        match &r {
            Ok(resp) => {
                let ints = [
                    ("state", resp.state as u64),
                    ("credited_atomic", resp.credited_atomic),
                    ("seen_atomic", resp.seen_atomic),
                ];
                self.record(IssuerOp::InvoiceStatus, request, Vec::new(), &ints, 0);
            }
            Err(s) => self.record(IssuerOp::InvoiceStatus, request, Vec::new(), &[], code(s)),
        }
        std::future::ready(self.deliver(r))
    }

    fn redeem_invite(
        &mut self,
        req: wire::RedeemInviteRequest,
    ) -> impl Future<Output = Result<wire::RedeemInviteResponse, IssuerError>> + Send {
        *self.received += 1;
        let week = req.base_week.to_be_bytes();
        let lie = self
            .liar
            .as_deref()
            .is_some_and(|l| l.lies_wrong_period(&[&req.invite_token, &req.blinded, &week]));
        let r = if self.unavailable() {
            Err(Status::unavailable("unavailable"))
        } else if lie {
            Ok(wire::RedeemInviteResponse {
                result: wire::RedeemInviteResult::WrongPeriod as i32,
                ..Default::default()
            })
        } else {
            self.issuer.redeem_invite_at(req.clone(), self.t)
        };
        let mut request = vec![f("invite_token", &req.invite_token)];
        request.extend(blocks("blinded", &req.blinded));
        let mut ints = vec![("base_week", req.base_week)];
        match &r {
            Ok(resp) => {
                ints.push(("result", resp.result as u64));
                let response = blocks("blind_signatures", &resp.blind_signatures);
                self.record(IssuerOp::RedeemInvite, request, response, &ints, 0);
            }
            Err(s) => self.record(IssuerOp::RedeemInvite, request, Vec::new(), &ints, code(s)),
        }
        std::future::ready(self.deliver(r))
    }

    fn claim_payout(
        &mut self,
        req: wire::ClaimPayoutRequest,
    ) -> impl Future<Output = Result<wire::ClaimPayoutResponse, IssuerError>> + Send {
        *self.received += 1;
        let r = if self.unavailable() {
            Err(Status::unavailable("unavailable"))
        } else {
            self.issuer.claim_payout_at(req.clone(), self.t)
        };
        let mut request = vec![f("claim_id", &req.claim_id)];
        request.extend(req.credits.iter().map(|c| f("credits", c)));
        request.push(f("payout_address", req.payout_address.as_bytes()));
        match &r {
            Ok(resp) => {
                let ints = [
                    ("result", resp.result as u64),
                    ("queued_atomic", resp.queued_atomic),
                    ("spent_mask", resp.spent_mask),
                ];
                self.record(IssuerOp::ClaimPayout, request, Vec::new(), &ints, 0);
            }
            Err(s) => self.record(IssuerOp::ClaimPayout, request, Vec::new(), &[], code(s)),
        }
        std::future::ready(self.deliver(r))
    }

    fn refresh_credit(
        &mut self,
        req: wire::RefreshCreditRequest,
    ) -> impl Future<Output = Result<wire::RefreshCreditResponse, IssuerError>> + Send {
        *self.received += 1;
        let r = if self.unavailable() {
            Err(Status::unavailable("unavailable"))
        } else {
            self.issuer.refresh_credit_at(req.clone(), self.t)
        };
        let mut request = vec![f("credit", &req.credit)];
        request.extend(blocks("blinded", &req.blinded));
        match &r {
            Ok(resp) => {
                let ints = [("result", resp.result as u64)];
                let response = blocks("blind_signature", &resp.blind_signature);
                self.record(IssuerOp::RefreshCredit, request, response, &ints, 0);
            }
            Err(s) => self.record(IssuerOp::RefreshCredit, request, Vec::new(), &[], code(s)),
        }
        std::future::ready(self.deliver(r))
    }
}

// -------------------------------------------------------------------------------------------------
// Relays.
// -------------------------------------------------------------------------------------------------

/// Reads a relay's capture file one event per handler call (every handler records exactly one).
pub struct CaptureReader {
    reader: BufReader<File>,
}

impl CaptureReader {
    pub fn open(path: &PathBuf) -> Self {
        if !path.exists() {
            File::create(path).expect("capture file");
        }
        CaptureReader {
            reader: BufReader::new(File::open(path).expect("capture file")),
        }
    }

    pub fn next(&mut self) -> String {
        let mut line = String::new();
        self.reader.read_line(&mut line).expect("capture line");
        assert!(line.ends_with('\n'), "a relay call wrote no capture event");
        line
    }
}

/// The string value of `"key":"value"` in a capture line.
pub fn json_str<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let pat = format!("\"{key}\":\"");
    let i = line.find(&pat)? + pat.len();
    let j = line[i..].find('"')? + i;
    Some(&line[i..j])
}

/// The decoded hex fields of a capture event.
pub struct Capture {
    pub result: String,
    pub fields: Vec<(&'static str, Vec<u8>)>,
}

pub fn parse_capture(line: &str) -> Capture {
    let result = json_str(line, "result").unwrap_or("").to_string();
    let mut fields = Vec::new();
    for key in [
        "nullifier",
        "period_id",
        "capability_scope",
        "request_id",
        "namespace_id",
        "blob_hash",
    ] {
        if let Some(v) = json_str(line, key).and_then(|h| hex::decode(h).ok()) {
            fields.push((key, v));
        }
    }
    Capture { result, fields }
}

/// One relay of the world.
pub struct RelayNode {
    pub index: u8,
    pub slot: u8,
    pub relay: Arc<Relay>,
    pub dir: PathBuf,
    pub key: [u8; 32],
    pub onion: String,
    pub address: OnionAddress,
    pub capture: CaptureReader,
    pub capture_path: PathBuf,
}

/// A redeem over the loopback (the `RedeemRpc` the production `redeem_with` drives).
pub struct RelayLink<'a> {
    pub node: &'a mut RelayNode,
    pub rec: &'a mut Recorder,
    pub t: u64,
    pub label: Label,
    pub truth: RelayTruth,
    /// The relay processes the request but the answer is lost (a timeout after processing).
    pub lose_answer: bool,
    /// NI-3: the relay shifts the minute (and week) it tells this client.
    pub shift_minutes: i64,
    pub answered: bool,
}

#[allow(clippy::too_many_arguments)]
fn record_relay(
    rec: &mut Recorder,
    node: &mut RelayNode,
    t: u64,
    label: Label,
    op: RelayOp,
    request: Vec<Field<'_>>,
    response: Vec<Field<'_>>,
    ints: &[(&'static str, u64)],
    status: i32,
    truth: RelayTruth,
    drop: bool,
) {
    let line = node.capture.next();
    let cap = parse_capture(&line);
    let capture: Vec<Field<'_>> = cap.fields.iter().map(|(n, v)| f(n, v)).collect();
    let call = RelayCall {
        relay: node.index,
        t,
        label,
        op,
        request,
        response,
        status,
        result: &cap.result,
        capture,
        truth,
    };
    rec.relay_call(&call, ints, drop);
}

impl RedeemRpc for RelayLink<'_> {
    fn redeem_token(
        &mut self,
        req: rw::RedeemTokenRequest,
    ) -> impl Future<Output = Result<rw::RedeemTokenResponse, RelayError>> + Send {
        let r = self.node.relay.redeem_at(req.clone(), self.t);
        // What the relay sends this client (an NI-3 relay lies about its clock).
        let r = r.map(|mut resp| {
            if self.shift_minutes != 0 {
                let m = (resp.relay_minute as i64 + self.shift_minutes).max(0) as u64;
                resp.relay_minute = m;
                resp.relay_period_id = ghost_entitlement::grid::week(m * 60);
            }
            resp
        });
        let request = vec![
            f("token", &req.token),
            f("namespace_id", &req.namespace_id),
            f("request_id", &req.request_id),
        ];
        match &r {
            Ok(resp) => {
                let ints = [
                    ("result", resp.result as u64),
                    ("relay_period_id", resp.relay_period_id),
                    ("relay_minute", resp.relay_minute),
                ];
                let response: Vec<Field<'_>> = resp
                    .capability
                    .as_ref()
                    .map(|c| vec![f("capability", &c.token)])
                    .unwrap_or_default();
                // The relay answered; whether the client hears it is ground truth (J8 counts only
                // the refusals a client received, S12 review P8-J8-1).
                let mut truth = self.truth;
                truth.answer_lost = self.lose_answer;
                record_relay(
                    self.rec,
                    self.node,
                    self.t,
                    self.label,
                    RelayOp::Redeem,
                    request,
                    response,
                    &ints,
                    0,
                    truth,
                    false,
                );
            }
            Err(s) => record_relay(
                self.rec,
                self.node,
                self.t,
                self.label,
                RelayOp::Redeem,
                request,
                Vec::new(),
                &[],
                code(s),
                self.truth,
                false,
            ),
        }
        let out = match r {
            Ok(_) if self.lose_answer => Err(RelayError::Timeout),
            Ok(v) => {
                self.answered = true;
                Ok(v)
            }
            Err(s) => {
                self.answered = true;
                Err(RelayError::Rpc(s))
            }
        };
        std::future::ready(out)
    }
}

/// StoreBlob over the loopback.
#[allow(clippy::too_many_arguments)]
pub fn store(
    node: &mut RelayNode,
    rec: &mut Recorder,
    t: u64,
    label: Label,
    truth: RelayTruth,
    req: rw::StoreBlobRequest,
    drop: bool,
) -> Result<rw::StoreBlobResponse, Status> {
    let r = node.relay.store_at(req.clone(), t);
    let cap = req
        .capability
        .as_ref()
        .map(|c| c.token.clone())
        .unwrap_or_default();
    let request = vec![
        f("blob_hash", &req.blob_hash),
        f("data", &req.data),
        f("capability", &cap),
        f("request_id", &req.request_id),
        f("namespace_id", &req.namespace_id),
    ];
    let ints_req = [("ttl_seconds", u64::from(req.ttl_seconds))];
    match &r {
        Ok(resp) => {
            let mut ints = ints_req.to_vec();
            ints.push(("expiry_unix_seconds", resp.expiry_unix_seconds));
            let response = vec![f("stored_hash", &resp.stored_hash)];
            record_relay(
                rec,
                node,
                t,
                label,
                RelayOp::Store,
                request,
                response,
                &ints,
                0,
                truth,
                drop,
            );
        }
        Err(s) => record_relay(
            rec,
            node,
            t,
            label,
            RelayOp::Store,
            request,
            Vec::new(),
            &ints_req,
            code(s),
            truth,
            drop,
        ),
    }
    r
}

/// ListNamespace over the loopback.
pub fn list(
    node: &mut RelayNode,
    rec: &mut Recorder,
    t: u64,
    label: Label,
    truth: RelayTruth,
    req: rw::ListNamespaceRequest,
) -> Result<rw::ListNamespaceResponse, Status> {
    let r = node.relay.list_at(req.clone(), t);
    let cap = req
        .capability
        .as_ref()
        .map(|c| c.token.clone())
        .unwrap_or_default();
    let request = vec![
        f("namespace_id", &req.namespace_id),
        f("capability", &cap),
        f("cursor", &req.cursor),
    ];
    let ints = [("limit", u64::from(req.limit))];
    match &r {
        Ok(resp) => {
            let mut response: Vec<Field<'_>> = resp
                .blob_hashes
                .iter()
                .map(|h| f("blob_hashes", h))
                .collect();
            response.push(f("next_cursor", &resp.next_cursor));
            record_relay(
                rec,
                node,
                t,
                label,
                RelayOp::List,
                request,
                response,
                &ints,
                0,
                truth,
                false,
            );
        }
        Err(s) => record_relay(
            rec,
            node,
            t,
            label,
            RelayOp::List,
            request,
            Vec::new(),
            &ints,
            code(s),
            truth,
            false,
        ),
    }
    r
}

/// GetBlob over the loopback.
pub fn get(
    node: &mut RelayNode,
    rec: &mut Recorder,
    t: u64,
    label: Label,
    truth: RelayTruth,
    req: rw::GetBlobRequest,
) -> Result<rw::GetBlobResponse, Status> {
    let r = node.relay.get_at(req.clone(), t);
    let cap = req
        .capability
        .as_ref()
        .map(|c| c.token.clone())
        .unwrap_or_default();
    let request = vec![
        f("blob_hash", &req.blob_hash),
        f("capability", &cap),
        f("request_id", &req.request_id),
    ];
    match &r {
        Ok(resp) => {
            let ints = [
                ("uploaded_at_unix_seconds", resp.uploaded_at_unix_seconds),
                ("expiry_unix_seconds", resp.expiry_unix_seconds),
            ];
            let response = vec![f("data", &resp.data)];
            record_relay(
                rec,
                node,
                t,
                label,
                RelayOp::Get,
                request,
                response,
                &ints,
                0,
                truth,
                false,
            );
        }
        Err(s) => record_relay(
            rec,
            node,
            t,
            label,
            RelayOp::Get,
            request,
            Vec::new(),
            &[],
            code(s),
            truth,
            false,
        ),
    }
    r
}
