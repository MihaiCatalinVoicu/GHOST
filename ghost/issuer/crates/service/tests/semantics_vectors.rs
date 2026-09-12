//! Replays `protocol/test-vectors/issuer_semantics.txt` (Phase 8 design §13.2 "Conformance
//! models") against the real issuer with a virtual clock and a `ChainPort` wallet, through
//! `Issuer::*_at(request, now)`, `scan_tick_at` and `sweep_at`. The Kotlin `ModelIssuer` replays the
//! same file (slice S9), so the model cannot drift from the issuer. The grammar is defined at the
//! top of the vector file.

mod common;

use std::collections::HashMap;

use common::chain_port;
use common::world::{World, BASE, BASE_WEEK, PRICE};
use ghost_entitlement::batch::{self, Layout};
use ghost_entitlement::grid::week_start;
use ghost_entitlement::Kind;
use ghost_issuer_api::proto as wire;
use sha2::{Digest, Sha256};
use tonic::{Code, Status};

/// The vector file, compiled in: a change to it rebuilds and re-runs this test.
const VECTORS: &str = include_str!("../../../../protocol/test-vectors/issuer_semantics.txt");

const STAGENET: &str =
    "73LhUiix4DVFMcKhsPRG51QmCsv8dYYbL6GcQoLwEEFvPvkVvc7BhebfA4pnEFF9Lq66hwvLqBvpHjTcqvpJMHmmNjPPBqa";

/// Client category of an issuer status (design §5.7, `for_issuer`).
fn category(status: &Status) -> &'static str {
    match status.code() {
        Code::InvalidArgument => "rejected",
        Code::PermissionDenied | Code::Unauthenticated => "unauthorized",
        Code::ResourceExhausted => "quota",
        _ => "relay_unavailable",
    }
}

fn claim_key(name: &str) -> [u8; 32] {
    Sha256::digest(format!("vector-claim/{name}")).into()
}

fn seed(name: &str) -> [u8; 32] {
    Sha256::digest(format!("vector-seed/{name}")).into()
}

fn payout_id(name: &str) -> Vec<u8> {
    Sha256::digest(format!("vector-payout/{name}"))[..16].to_vec()
}

fn state_word(state: i32) -> &'static str {
    match wire::InvoiceState::try_from(state) {
        Ok(wire::InvoiceState::Signed) => "signed",
        Ok(wire::InvoiceState::AwaitingPayment) => "awaiting_payment",
        Ok(wire::InvoiceState::AwaitingConfirmations) => "awaiting_confirmations",
        Ok(wire::InvoiceState::Underpaid) => "underpaid",
        Ok(wire::InvoiceState::Expired) => "expired",
        Ok(wire::InvoiceState::OtherRequestIssued) => "other_request_issued",
        _ => "unspecified",
    }
}

struct Line<'a> {
    no: usize,
    op: &'a str,
    names: Vec<&'a str>,
    args: HashMap<&'a str, &'a str>,
    expect: Option<(&'a str, HashMap<&'a str, &'a str>)>,
}

fn parse(no: usize, text: &str) -> Option<Line<'_>> {
    let text = text.split('#').next().unwrap_or("").trim();
    if text.is_empty() {
        return None;
    }
    let (left, right) = match text.split_once("->") {
        Some((l, r)) => (l.trim(), Some(r.trim())),
        None => (text, None),
    };
    let mut words = left.split_whitespace();
    let op = words.next().unwrap();
    let mut names = Vec::new();
    let mut args = HashMap::new();
    for w in words {
        match w.split_once('=') {
            Some((k, v)) => {
                args.insert(k, v);
            }
            None => names.push(w),
        }
    }
    let expect = right.map(|r| {
        let mut words = r.split_whitespace();
        let word = words.next().expect("an expectation word");
        let fields = words
            .map(|f| f.split_once('=').expect("key=value field"))
            .collect();
        (word, fields)
    });
    Some(Line {
        no,
        op,
        names,
        args,
        expect,
    })
}

struct Invoice {
    id: [u8; 16],
    base_week: u64,
    xmr: bool,
    subaddress: String,
}

struct Section {
    w: World,
    invoices: HashMap<String, Invoice>,
    credits: HashMap<String, Vec<Vec<u8>>>,
    tokens: HashMap<String, Vec<u8>>,
    answers: HashMap<String, Vec<u8>>,
}

impl Section {
    fn new() -> Self {
        let mut w = World::new(true);
        w.external_credits = true;
        Self {
            w,
            invoices: HashMap::new(),
            credits: HashMap::new(),
            tokens: HashMap::new(),
            answers: HashMap::new(),
        }
    }

    fn week(l: &Line) -> u64 {
        let d: i64 = l.args["week"].parse().unwrap();
        (BASE_WEEK as i64 + d) as u64
    }

    fn credit_set(&self, spec: &str) -> Vec<Vec<u8>> {
        match spec.split_once('/') {
            Some((name, range)) => {
                let (a, b) = range.split_once('/').unwrap();
                self.credits[name][a.parse().unwrap()..b.parse().unwrap()].to_vec()
            }
            None => self.credits[spec].clone(),
        }
    }

    fn amount(spec: &str) -> u64 {
        match spec {
            "price" => PRICE,
            "half" => PRICE / 2,
            n => n.parse().unwrap(),
        }
    }

    fn address(spec: &str) -> String {
        match spec {
            "valid" => chain_port::address(9_999),
            "other" => chain_port::address(9_998),
            "checksum" => {
                let mut a = chain_port::address(9_999).into_bytes();
                let last = a.len() - 1;
                a[last] = if a[last] == b'2' { b'3' } else { b'2' };
                String::from_utf8(a).unwrap()
            }
            "stagenet" => STAGENET.to_string(),
            other => panic!("unknown address {other}"),
        }
    }

    /// Compares the optional `credited=` and `seen=` fields.
    fn amounts(l: &Line, fields: &HashMap<&str, &str>, credited: u64, seen: u64) {
        if let Some(c) = fields.get("credited") {
            assert_eq!(
                credited,
                c.parse::<u64>().unwrap(),
                "line {}: credited",
                l.no
            );
        }
        if let Some(s) = fields.get("seen") {
            assert_eq!(seen, s.parse::<u64>().unwrap(), "line {}: seen", l.no);
        }
    }

    fn same_answer(&mut self, key: String, bytes: &[u8], no: usize) {
        match self.answers.get(&key) {
            Some(previous) => assert_eq!(previous, bytes, "line {no}: not byte-identical"),
            None => {
                self.answers.insert(key, bytes.to_vec());
            }
        }
    }

    fn run(&mut self, l: &Line) {
        let no = l.no;
        match l.op {
            "at" => self.w.now = BASE + l.names[0].parse::<u64>().unwrap(),
            "week" => {
                let d: i64 = l.names[0].parse().unwrap();
                self.w.now = week_start((BASE_WEEK as i64 + d) as u64) + 43_200;
            }
            "tick" => {
                self.w.tick();
            }
            "mine" => self.w.mine(l.names[0].parse().unwrap()),
            "synced" => self.w.chain.set_synced(l.names[0] == "yes"),
            "sweep" => self.w.sweep(),
            "pay" => {
                let minor = self.w.chain.minor_of(&self.invoices[l.names[0]].subaddress);
                self.w.chain.pay(minor, Self::amount(l.names[1]));
            }
            "credits" => {
                let name = l.names[0];
                let count: usize = l.args["count"].parse().unwrap();
                let epoch: u64 = l.args["epoch"].parse().unwrap();
                let set = (0..count)
                    .map(|i| {
                        self.w
                            .mint(Kind::Credit, epoch, &format!("vector-credit/{name}/{i}"))
                            .as_bytes()
                            .to_vec()
                    })
                    .collect();
                self.credits.insert(name.to_string(), set);
            }
            "invite" => {
                let name = l.names[0];
                let epoch: u64 = l.args["epoch"].parse().unwrap();
                let token = self
                    .w
                    .mint(Kind::Invite, epoch, &format!("vector-invite/{name}"));
                self.tokens
                    .insert(name.to_string(), token.as_bytes().to_vec());
            }
            "token" => {
                let mut bytes = self.tokens[l.args["from"]].clone();
                bytes[l.args["flip"].parse::<usize>().unwrap()] ^= 0x01;
                self.tokens.insert(l.names[0].to_string(), bytes);
            }
            "request" => self.request(l),
            "sign" => self.sign(l),
            "status" => self.status(l),
            "redeem" => self.redeem(l),
            "payout" => self.payout(l),
            other => panic!("line {no}: unknown operation {other}"),
        }
    }

    fn request(&mut self, l: &Line) {
        let (word, fields) = l.expect.as_ref().expect("request has an outcome");
        let credits = l
            .args
            .get("credits")
            .map(|s| self.credit_set(s))
            .unwrap_or_default();
        let base_week = Self::week(l);
        let req = wire::RequestInvoiceRequest {
            version: 1,
            rail: wire::Rail::Monero as i32,
            product: wire::Product::Pack as i32,
            claim_hash: batch::claim_hash(&claim_key(l.names[0])).to_vec(),
            credits: credits.clone(),
            base_week,
        };
        let r = match self.w.call(|i, now| i.request_invoice_at(req.clone(), now)) {
            Err(s) => return assert_eq!(category(&s), *word, "line {}", l.no),
            Ok(r) => r,
        };
        let got = match wire::RequestInvoiceResult::try_from(r.result) {
            Ok(wire::RequestInvoiceResult::Ok) => "ok",
            Ok(wire::RequestInvoiceResult::WrongPeriod) => "wrong_period",
            Ok(wire::RequestInvoiceResult::CreditsSpent) => "credits_spent",
            Ok(wire::RequestInvoiceResult::ClaimConflict) => "claim_conflict",
            _ => "unspecified",
        };
        assert_eq!(got, *word, "line {}", l.no);
        match got {
            "ok" => {
                let id: [u8; 16] = r.invoice_id.as_slice().try_into().unwrap();
                assert_eq!(
                    r.amount_atomic,
                    Self::amount(fields["amount"]),
                    "line {}",
                    l.no
                );
                assert_eq!(
                    r.subaddress.is_empty(),
                    r.amount_atomic == 0,
                    "line {}",
                    l.no
                );
                let name = fields["invoice"].to_string();
                match self.invoices.get(&name) {
                    Some(known) => assert_eq!(known.id, id, "line {}: another invoice", l.no),
                    None => {
                        self.invoices.insert(
                            name,
                            Invoice {
                                id,
                                base_week,
                                xmr: credits.is_empty(),
                                subaddress: r.subaddress.clone(),
                            },
                        );
                    }
                }
            }
            "credits_spent" => {
                let mask = u32::from_str_radix(fields["mask"], 16).unwrap();
                assert_eq!(r.spent_mask, mask, "line {}", l.no);
            }
            _ => {}
        }
    }

    fn sign(&mut self, l: &Line) {
        let (word, fields) = l.expect.as_ref().expect("sign has an outcome");
        let inv = &self.invoices[l.names[0]];
        let layout = Layout::pack(&self.w.schedule, inv.base_week, inv.xmr).unwrap();
        let s = seed(l.args["seed"]);
        let mut blinded = batch::blind(&self.w.schedule, &s, &layout).unwrap();
        if l.args.get("block") == Some(&"zero") {
            blinded[..256].fill(0);
        }
        let req = wire::BlindSignRequest {
            version: 1,
            invoice_id: inv.id.to_vec(),
            claim_key: claim_key(l.args["claim"]).to_vec(),
            blinded,
        };
        let r = match self.w.call(|i, now| i.blind_sign_at(req.clone(), now)) {
            Err(e) => return assert_eq!(category(&e), *word, "line {}", l.no),
            Ok(r) => r,
        };
        assert_eq!(state_word(r.state), *word, "line {}", l.no);
        Self::amounts(l, fields, r.credited_atomic, r.seen_atomic);
        if *word == "signed" {
            let tokens = batch::finalize(&self.w.schedule, &s, &layout, &r.blind_signatures)
                .unwrap_or_else(|e| panic!("line {}: {e}", l.no));
            assert_eq!(tokens.len(), layout.len());
            let key = format!("sign/{}/{}", l.names[0], l.args["seed"]);
            self.same_answer(key, &r.blind_signatures, l.no);
        } else {
            assert!(r.blind_signatures.is_empty(), "line {}", l.no);
        }
    }

    fn status(&mut self, l: &Line) {
        let (word, fields) = l.expect.as_ref().expect("status has an outcome");
        let inv = &self.invoices[l.names[0]];
        let req = wire::InvoiceStatusRequest {
            version: 1,
            invoice_id: inv.id.to_vec(),
            claim_key: claim_key(l.args["claim"]).to_vec(),
        };
        match self.w.call(|i, now| i.invoice_status_at(req.clone(), now)) {
            Err(e) => assert_eq!(category(&e), *word, "line {}", l.no),
            Ok(r) => {
                assert_eq!(state_word(r.state), *word, "line {}", l.no);
                Self::amounts(l, fields, r.credited_atomic, r.seen_atomic);
            }
        }
    }

    fn redeem(&mut self, l: &Line) {
        let (word, _) = l.expect.as_ref().expect("redeem has an outcome");
        let base_week = Self::week(l);
        let layout = Layout::trial(&self.w.schedule, base_week).unwrap();
        let s = seed(l.args["seed"]);
        let req = wire::RedeemInviteRequest {
            version: 1,
            invite_token: self.tokens[l.names[0]].clone(),
            base_week,
            blinded: batch::blind(&self.w.schedule, &s, &layout).unwrap(),
        };
        let r = match self.w.call(|i, now| i.redeem_invite_at(req.clone(), now)) {
            Err(e) => return assert_eq!(category(&e), *word, "line {}", l.no),
            Ok(r) => r,
        };
        let got = match wire::RedeemInviteResult::try_from(r.result) {
            Ok(wire::RedeemInviteResult::Ok) => "ok",
            Ok(wire::RedeemInviteResult::Replayed) => "replayed",
            Ok(wire::RedeemInviteResult::WrongPeriod) => "wrong_period",
            _ => "unspecified",
        };
        assert_eq!(got, *word, "line {}", l.no);
        if got == "ok" {
            batch::finalize(&self.w.schedule, &s, &layout, &r.blind_signatures)
                .unwrap_or_else(|e| panic!("line {}: {e}", l.no));
            let key = format!("redeem/{}/{}/{base_week}", l.names[0], l.args["seed"]);
            self.same_answer(key, &r.blind_signatures, l.no);
        }
    }

    fn payout(&mut self, l: &Line) {
        let (word, fields) = l.expect.as_ref().expect("payout has an outcome");
        let req = wire::ClaimPayoutRequest {
            version: 1,
            claim_id: payout_id(l.names[0]),
            credits: self.credit_set(l.args["credits"]),
            payout_address: Self::address(l.args["address"]),
        };
        let r = match self.w.call(|i, now| i.claim_payout_at(req.clone(), now)) {
            Err(e) => return assert_eq!(category(&e), *word, "line {}", l.no),
            Ok(r) => r,
        };
        let got = match wire::ClaimPayoutResult::try_from(r.result) {
            Ok(wire::ClaimPayoutResult::Queued) => "queued",
            Ok(wire::ClaimPayoutResult::CreditsSpent) => "credits_spent",
            Ok(wire::ClaimPayoutResult::ClaimConflict) => "claim_conflict",
            Ok(wire::ClaimPayoutResult::AddressRejected) => "address_rejected",
            _ => "unspecified",
        };
        assert_eq!(got, *word, "line {}", l.no);
        match got {
            "queued" => assert_eq!(
                r.queued_atomic,
                fields["amount"].parse::<u64>().unwrap(),
                "line {}",
                l.no
            ),
            "credits_spent" => assert_eq!(
                r.spent_mask,
                u64::from_str_radix(fields["mask"], 16).unwrap(),
                "line {}",
                l.no
            ),
            _ => {}
        }
    }
}

#[test]
fn issuer_semantics_vectors() {
    let mut section: Option<Section> = None;
    let mut sections = 0;
    let mut outcomes = 0;
    for (i, text) in VECTORS.lines().enumerate() {
        let Some(line) = parse(i + 1, text) else {
            continue;
        };
        if line.op == "issuer" {
            if let Some(done) = section.take() {
                done.w.check();
            }
            section = Some(Section::new());
            sections += 1;
            continue;
        }
        outcomes += usize::from(line.expect.is_some());
        section
            .as_mut()
            .unwrap_or_else(|| panic!("line {}: operation before any section", line.no))
            .run(&line);
    }
    if let Some(done) = section {
        done.w.check();
    }
    assert_eq!(sections, 6);
    assert!(outcomes >= 60, "only {outcomes} outcomes replayed");
}
