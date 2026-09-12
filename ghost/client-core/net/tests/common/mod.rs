//! Shared helpers of the client-core entitlement tests: the committed test Entitlement Schedule and
//! its test-only private keys (production code never loads them: `Schedule::verify` refuses the
//! test key), a model issuer answering the six issuer RPCs honestly by default and hostilely on
//! request, single tokens minted through the client's own seed-derived blinding, and an in-process
//! relay behind the `RedeemRpc` seam.
#![allow(dead_code)]

use ed25519_dalek::{Signer as _, SigningKey};
use ghost_client_net::issuer_client::{IssuerError, IssuerRpc};
use ghost_client_net::namespace_client::RedeemRpc;
use ghost_client_net::{OnionAddress, RelayError};
use ghost_entitlement::batch::{self, Layout, Position};
use ghost_entitlement::grid::{self, price_epoch};
use ghost_entitlement::monero::{AddressPurpose, MoneroAddress};
use ghost_entitlement::schedule::{ScheduleContent, SIGNATURE_DOMAIN};
use ghost_entitlement::{Expect, Kind, Schedule, Token};
use ghost_issuer_api::proto::*;
use ghost_relay_api::proto::{RedeemTokenRequest, RedeemTokenResponse};
use ghost_relay_capability::RelayKey;
use ghost_relay_node::{Clock, EntitlementPolicy, NullifierMode, Relay, RelayConfig};
use num_bigint_dig::BigUint;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::future::{ready, Future};
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};
use tonic::Code;

/// The committed test Entitlement Schedule (regtest, issuer `ghost-issuer-test`, access weeks
/// 2957..2982, slots 0 = relay-a and 1 = relay-b from 2957, slot 2 = relay-c until 2966 and
/// relay-d from 2967; invite epochs 739..745, credit epochs 227..229).
pub const TEST_SCHEDULE: &[u8] =
    include_bytes!("../../../../issuer/crates/entitlement/tests/fixtures/test_schedule.ghes");
const TEST_KEYS: &str =
    include_str!("../../../../issuer/crates/entitlement/tests/fixtures/test_keys.txt");
const REDEEM_VECTORS: &str = include_str!("../../../../protocol/test-vectors/redeem.txt");

/// First access week of the test schedule (Monday 2026-09-07).
pub const FIRST_WEEK: u64 = 2957;
/// Invite and credit epochs of `FIRST_WEEK`.
pub const INVITE_EPOCH: u64 = 739;
pub const CREDIT_EPOCH: u64 = 227;

/// Regtest (mainnet-prefix) addresses of `protocol/test-vectors/monero_addresses.txt`.
pub const SUBADDRESS: &str =
    "888tNkZrPN6JsEgekjMnABU4TBzc2Dt29EPAvkRxbANsAnjyPbb3iQ1YBRk1UXcdRsiKc9dhwMVgN5S9cQUiyoogDavup3H";
pub const PAYOUT: &str =
    "42ey1afDFnn4886T7196doS9GPMzexD9gXpsZJDwVjeRVdFCSoHnv7KPbBeGpzJBzHRCAs9UxqeoyFQMYbqSWYTfJJQAWDm";
pub const STAGENET_SUBADDRESS: &str =
    "73LhUiix4DVFMcKhsPRG51QmCsv8dYYbL6GcQoLwEEFvPvkVvc7BhebfA4pnEFF9Lq66hwvLqBvpHjTcqvpJMHmmNjPPBqa";

/// The test schedule key: Ed25519 from SHA-256("ghost/test/schedule-key"). Test schedules only.
pub fn schedule_signing_key() -> SigningKey {
    SigningKey::from_bytes(&Sha256::digest(b"ghost/test/schedule-key").into())
}

/// The test schedule, verified under the test key once per test binary.
pub fn schedule() -> &'static Schedule {
    static S: OnceLock<Schedule> = OnceLock::new();
    S.get_or_init(|| {
        let key = schedule_signing_key().verifying_key().to_bytes();
        Schedule::verify_with_key(TEST_SCHEDULE, &key).unwrap()
    })
}

/// The test schedule with `edit` applied, re-signed with the test key (same keys, so tokens
/// minted here verify under it).
pub fn resigned(edit: impl FnOnce(&mut ScheduleContent)) -> Schedule {
    let mut content = schedule().content().clone();
    edit(&mut content);
    let key = schedule_signing_key();
    let sig = key.sign(&[SIGNATURE_DOMAIN, &content.body().unwrap()].concat());
    let bytes = content.to_signed_bytes(&sig.to_bytes()).unwrap();
    Schedule::verify_with_key(&bytes, &key.verifying_key().to_bytes()).unwrap()
}

/// A test-only RSA private key in CRT form.
struct TestKey {
    n: BigUint,
    p: BigUint,
    q: BigUint,
    dp: BigUint,
    dq: BigUint,
    qinv: BigUint,
}

/// One DER TLV of `tag`: (content, rest).
fn der(input: &[u8], tag: u8) -> (&[u8], &[u8]) {
    assert_eq!(input[0], tag, "DER tag");
    let (len, header) = match input[1] {
        l if l < 0x80 => (usize::from(l), 2),
        0x81 => (usize::from(input[2]), 3),
        0x82 => (usize::from(u16::from_be_bytes([input[2], input[3]])), 4),
        other => panic!("DER length form {other:#x}"),
    };
    (&input[header..header + len], &input[header + len..])
}

impl TestKey {
    /// PKCS #8 `PrivateKeyInfo` holding an RSA `RSAPrivateKey`.
    fn from_pkcs8(der_bytes: &[u8]) -> Self {
        let (info, _) = der(der_bytes, 0x30);
        let (_version, rest) = der(info, 0x02);
        let (_algorithm, rest) = der(rest, 0x30);
        let (octets, _) = der(rest, 0x04);
        let (rsa, _) = der(octets, 0x30);
        let mut ints = Vec::new();
        let mut rest = rsa;
        while !rest.is_empty() {
            let (i, r) = der(rest, 0x02);
            ints.push(BigUint::from_bytes_be(i));
            rest = r;
        }
        // version, n, e, d, p, q, dp, dq, qinv
        TestKey {
            n: ints[1].clone(),
            p: ints[4].clone(),
            q: ints[5].clone(),
            dp: ints[6].clone(),
            dq: ints[7].clone(),
            qinv: ints[8].clone(),
        }
    }

    /// `B^d mod n` (CRT), 256 bytes.
    fn sign(&self, blinded: &[u8]) -> Vec<u8> {
        let c = BigUint::from_bytes_be(blinded);
        let m1 = c.modpow(&self.dp, &self.p);
        let m2 = c.modpow(&self.dq, &self.q);
        let diff = (&m1 + &self.p - (&m2 % &self.p)) % &self.p;
        let h = (&self.qinv * diff) % &self.p;
        let s = m2 + h * &self.q;
        let raw = s.to_bytes_be();
        let mut out = vec![0u8; 256 - raw.len()];
        out.extend_from_slice(&raw);
        out
    }
}

fn keys() -> &'static HashMap<(Kind, u64), TestKey> {
    static K: OnceLock<HashMap<(Kind, u64), TestKey>> = OnceLock::new();
    K.get_or_init(|| {
        TEST_KEYS
            .lines()
            .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
            .map(|l| {
                let mut w = l.split_whitespace();
                let kind = Kind::from_byte(w.next().unwrap().parse().unwrap()).unwrap();
                let epoch: u64 = w.next().unwrap().parse().unwrap();
                let key = TestKey::from_pkcs8(&hex::decode(w.next().unwrap()).unwrap());
                ((kind, epoch), key)
            })
            .collect()
    })
}

/// Blind signatures already computed, per (kind, epoch, blinded block).
type SignatureCache = Mutex<HashMap<(Kind, u64, Vec<u8>), Vec<u8>>>;

/// The issuer's blind signature on one 256-byte block under the test key of (kind, epoch), or
/// None for a block out of range; cached per (key, block).
pub fn sign(kind: Kind, epoch: u64, blinded: &[u8]) -> Option<Vec<u8>> {
    static CACHE: OnceLock<SignatureCache> = OnceLock::new();
    let key = keys().get(&(kind, epoch))?;
    let b = BigUint::from_bytes_be(blinded);
    if blinded.len() != 256 || b == BigUint::from(0u32) || b >= key.n {
        return None;
    }
    let cache = CACHE.get_or_init(Default::default);
    let id = (kind, epoch, blinded.to_vec());
    if let Some(s) = cache.lock().unwrap().get(&id) {
        return Some(s.clone());
    }
    let s = key.sign(blinded);
    cache.lock().unwrap().insert(id, s.clone());
    Some(s)
}

/// Signs every position of `layout` in `blinded` (N x 256 bytes).
fn sign_layout(layout: &Layout, blinded: &[u8]) -> Option<Vec<u8>> {
    if blinded.len() != layout.len() * 256 {
        return None;
    }
    let mut out = Vec::with_capacity(blinded.len());
    for (p, block) in layout.positions().iter().zip(blinded.chunks(256)) {
        out.extend_from_slice(&sign(p.kind, p.epoch, block)?);
    }
    Some(out)
}

/// A 32-byte seed from an index and a tag.
pub fn seed(i: usize, tag: u8) -> [u8; 32] {
    let mut s = [tag; 32];
    s[..8].copy_from_slice(&(i as u64).to_be_bytes());
    s
}

/// One token of (kind, epoch, slot) minted through the client's seed-derived blinding and the
/// test key: a real token of the test schedule.
pub fn mint(kind: Kind, epoch: u64, slot: Option<u8>, seed: [u8; 32]) -> Token {
    let s = schedule();
    let layout = Layout::from_positions(s, vec![Position { kind, epoch, slot }]).unwrap();
    let blinded = batch::blind(s, &seed, &layout).unwrap();
    let sig = sign_layout(&layout, &blinded).unwrap();
    batch::finalize(s, &seed, &layout, &sig)
        .unwrap()
        .pop()
        .unwrap()
}

/// `n` distinct CREDIT tokens of `epoch`.
pub fn credits(n: usize, epoch: u64) -> Vec<Token> {
    (0..n)
        .map(|i| mint(Kind::Credit, epoch, None, seed(i, 0xC0 ^ epoch as u8)))
        .collect()
}

fn rpc(code: Code) -> IssuerError {
    IssuerError::Rpc(code)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage {
    AwaitingPayment,
    Confirmed,
    Issued([u8; 32]),
}

struct Invoice {
    claim_hash: [u8; 32],
    request: Vec<u8>,
    base_week: u64,
    paid_in_xmr: bool,
    amount: u64,
    stage: Stage,
}

type Hook<T> = Box<dyn Fn(&mut T) + Send>;

/// Rewrites answers before they are returned (a hostile issuer).
#[derive(Default)]
pub struct Tamper {
    pub request_invoice: Option<Hook<RequestInvoiceResponse>>,
    pub blind_sign: Option<Hook<BlindSignResponse>>,
    pub invoice_status: Option<Hook<InvoiceStatusResponse>>,
    pub redeem_invite: Option<Hook<RedeemInviteResponse>>,
    pub claim_payout: Option<Hook<ClaimPayoutResponse>>,
    pub refresh_credit: Option<Hook<RefreshCreditResponse>>,
}

/// An issuer that follows design §5.5–§5.6 closely enough for the client's checks: idempotent by
/// claim hash, request digest, invite nullifier and claim id; signs with the test keys.
pub struct ModelIssuer {
    pub schedule: Schedule,
    invoices: HashMap<[u8; 16], Invoice>,
    claims: HashMap<[u8; 32], [u8; 16]>,
    credit_use: HashMap<[u8; 32], Vec<u8>>,
    invites: HashMap<[u8; 32], [u8; 32]>,
    payouts: HashMap<[u8; 16], (Vec<u8>, ClaimPayoutResponse)>,
    next_invoice: u8,
    /// Every request that reached the issuer, by RPC, in order.
    pub requests: Vec<&'static str>,
    /// The blinded bytes of the latest BlindSign, RedeemInvite or RefreshCredit.
    pub last_blinded: Option<Vec<u8>>,
    pub tamper: Tamper,
    /// Every call fails with this gRPC code.
    pub fail_with: Option<Code>,
}

impl Default for ModelIssuer {
    fn default() -> Self {
        Self::new()
    }
}

impl ModelIssuer {
    pub fn new() -> Self {
        ModelIssuer {
            schedule: schedule().clone(),
            invoices: HashMap::new(),
            claims: HashMap::new(),
            credit_use: HashMap::new(),
            invites: HashMap::new(),
            payouts: HashMap::new(),
            next_invoice: 0,
            requests: Vec::new(),
            last_blinded: None,
            tamper: Tamper::default(),
            fail_with: None,
        }
    }

    /// The scanner credits an XMR invoice in full.
    pub fn pay(&mut self, invoice_id: &[u8; 16]) {
        let inv = self.invoices.get_mut(invoice_id).unwrap();
        if inv.stage == Stage::AwaitingPayment {
            inv.stage = Stage::Confirmed;
        }
    }

    fn enter(&mut self, name: &'static str) -> Result<(), IssuerError> {
        self.requests.push(name);
        self.fail_with.map_or(Ok(()), |c| Err(rpc(c)))
    }

    fn spent_mask(&self, nullifiers: &[[u8; 32]]) -> u64 {
        nullifiers
            .iter()
            .enumerate()
            .filter(|(_, n)| self.credit_use.contains_key(*n))
            .fold(0, |m, (i, _)| m | 1 << i)
    }

    fn verified_credits(&self, raw: &[Vec<u8>]) -> Result<Vec<(u64, [u8; 32])>, IssuerError> {
        raw.iter()
            .map(|c| {
                let t = Token::parse(c).map_err(|_| rpc(Code::PermissionDenied))?;
                let v = self
                    .schedule
                    .verify_token(&t, Expect::Credit)
                    .map_err(|_| rpc(Code::PermissionDenied))?;
                Ok((v.epoch, v.nullifier))
            })
            .collect()
    }

    fn invoice_answer(&self, id: [u8; 16]) -> RequestInvoiceResponse {
        let inv = &self.invoices[&id];
        RequestInvoiceResponse {
            result: RequestInvoiceResult::Ok as i32,
            invoice_id: id.to_vec(),
            amount_atomic: inv.amount,
            subaddress: if inv.amount > 0 {
                SUBADDRESS.to_owned()
            } else {
                String::new()
            },
            spent_mask: 0,
        }
    }

    fn on_request_invoice(
        &mut self,
        req: RequestInvoiceRequest,
    ) -> Result<RequestInvoiceResponse, IssuerError> {
        if req.version != 1
            || req.rail != Rail::Monero as i32
            || req.product != Product::Pack as i32
            || req.credits.iter().any(|c| c.len() != 354)
        {
            return Err(rpc(Code::InvalidArgument));
        }
        let claim_hash: [u8; 32] = req
            .claim_hash
            .as_slice()
            .try_into()
            .map_err(|_| rpc(Code::InvalidArgument))?;
        let nullifiers: Vec<[u8; 32]> = req
            .credits
            .iter()
            .map(|c| ghost_entitlement::token::nullifier(c[..98].try_into().unwrap()))
            .collect();
        let request = [req.base_week.to_be_bytes().to_vec(), nullifiers.concat()].concat();
        if let Some(id) = self.claims.get(&claim_hash) {
            if self.invoices[id].request != request {
                return Ok(RequestInvoiceResponse {
                    result: RequestInvoiceResult::ClaimConflict as i32,
                    ..Default::default()
                });
            }
            return Ok(self.invoice_answer(*id));
        }
        let paid_in_xmr = req.credits.is_empty();
        let price = self
            .schedule
            .pack_price(price_epoch(req.base_week))
            .ok_or(rpc(Code::Unavailable))?;
        if !paid_in_xmr {
            self.verified_credits(&req.credits)?;
            let mask = self.spent_mask(&nullifiers);
            if mask != 0 {
                return Ok(RequestInvoiceResponse {
                    result: RequestInvoiceResult::CreditsSpent as i32,
                    spent_mask: mask as u32,
                    ..Default::default()
                });
            }
            for n in &nullifiers {
                self.credit_use.insert(*n, b"discount".to_vec());
            }
        }
        self.next_invoice += 1;
        let id = [self.next_invoice; 16];
        self.invoices.insert(
            id,
            Invoice {
                claim_hash,
                request,
                base_week: req.base_week,
                paid_in_xmr,
                amount: if paid_in_xmr { price } else { 0 },
                stage: if paid_in_xmr {
                    Stage::AwaitingPayment
                } else {
                    Stage::Confirmed
                },
            },
        );
        self.claims.insert(claim_hash, id);
        Ok(self.invoice_answer(id))
    }

    fn invoice_for(&self, id: &[u8], claim_key: &[u8]) -> Result<[u8; 16], IssuerError> {
        let id: [u8; 16] = id.try_into().map_err(|_| rpc(Code::InvalidArgument))?;
        let key: [u8; 32] = claim_key
            .try_into()
            .map_err(|_| rpc(Code::InvalidArgument))?;
        match self.invoices.get(&id) {
            Some(inv) if inv.claim_hash == batch::claim_hash(&key) => Ok(id),
            _ => Err(rpc(Code::PermissionDenied)),
        }
    }

    fn on_blind_sign(&mut self, req: BlindSignRequest) -> Result<BlindSignResponse, IssuerError> {
        let id = self.invoice_for(&req.invoice_id, &req.claim_key)?;
        self.last_blinded = Some(req.blinded.clone());
        let inv = &self.invoices[&id];
        let (amount, stage) = (inv.amount, inv.stage);
        if stage == Stage::AwaitingPayment {
            return Ok(BlindSignResponse {
                state: InvoiceState::AwaitingPayment as i32,
                ..Default::default()
            });
        }
        let layout = Layout::pack(&self.schedule, inv.base_week, inv.paid_in_xmr).unwrap();
        let digest = batch::request_digest(&id, &req.blinded);
        if matches!(stage, Stage::Issued(d) if d != digest) {
            return Ok(BlindSignResponse {
                state: InvoiceState::OtherRequestIssued as i32,
                credited_atomic: amount,
                ..Default::default()
            });
        }
        let sigs = sign_layout(&layout, &req.blinded).ok_or(rpc(Code::InvalidArgument))?;
        self.invoices.get_mut(&id).unwrap().stage = Stage::Issued(digest);
        Ok(BlindSignResponse {
            state: InvoiceState::Signed as i32,
            blind_signatures: sigs,
            credited_atomic: amount,
            seen_atomic: 0,
        })
    }

    fn on_invoice_status(
        &mut self,
        req: InvoiceStatusRequest,
    ) -> Result<InvoiceStatusResponse, IssuerError> {
        let id = self.invoice_for(&req.invoice_id, &req.claim_key)?;
        let inv = &self.invoices[&id];
        let state = match inv.stage {
            Stage::AwaitingPayment => InvoiceState::AwaitingPayment,
            Stage::Confirmed => InvoiceState::AwaitingConfirmations,
            Stage::Issued(_) => InvoiceState::Signed,
        };
        Ok(InvoiceStatusResponse {
            state: state as i32,
            credited_atomic: if inv.stage == Stage::AwaitingPayment {
                0
            } else {
                inv.amount
            },
            seen_atomic: 0,
        })
    }

    fn on_redeem_invite(
        &mut self,
        req: RedeemInviteRequest,
    ) -> Result<RedeemInviteResponse, IssuerError> {
        let token = Token::parse(&req.invite_token).map_err(|_| rpc(Code::InvalidArgument))?;
        self.schedule
            .verify_token(&token, Expect::Invite)
            .map_err(|_| rpc(Code::PermissionDenied))?;
        self.last_blinded = Some(req.blinded.clone());
        let nullifier = token.nullifier();
        let digest = batch::trial_digest(&nullifier, req.base_week, &req.blinded);
        if self.invites.get(&nullifier).is_some_and(|d| *d != digest) {
            return Ok(RedeemInviteResponse {
                result: RedeemInviteResult::Replayed as i32,
                ..Default::default()
            });
        }
        let layout =
            Layout::trial(&self.schedule, req.base_week).map_err(|_| rpc(Code::Unavailable))?;
        let sigs = sign_layout(&layout, &req.blinded).ok_or(rpc(Code::InvalidArgument))?;
        self.invites.insert(nullifier, digest);
        Ok(RedeemInviteResponse {
            result: RedeemInviteResult::Ok as i32,
            blind_signatures: sigs,
        })
    }

    fn on_claim_payout(
        &mut self,
        req: ClaimPayoutRequest,
    ) -> Result<ClaimPayoutResponse, IssuerError> {
        let claim_id: [u8; 16] = req
            .claim_id
            .as_slice()
            .try_into()
            .map_err(|_| rpc(Code::InvalidArgument))?;
        let body = [req.payout_address.as_bytes().to_vec(), req.credits.concat()].concat();
        if let Some((digest, answer)) = self.payouts.get(&claim_id) {
            return Ok(if *digest == body {
                *answer
            } else {
                ClaimPayoutResponse {
                    result: ClaimPayoutResult::ClaimConflict as i32,
                    ..Default::default()
                }
            });
        }
        if MoneroAddress::parse(
            &req.payout_address,
            self.schedule.network(),
            AddressPurpose::Payout,
        )
        .is_err()
        {
            return Ok(ClaimPayoutResponse {
                result: ClaimPayoutResult::AddressRejected as i32,
                ..Default::default()
            });
        }
        let c = self.schedule.constants();
        if req.credits.len() < usize::from(c.min_claim_credits)
            || req.credits.len() > usize::from(c.max_claim_credits)
        {
            return Err(rpc(Code::PermissionDenied));
        }
        let credits = self.verified_credits(&req.credits)?;
        let nullifiers: Vec<[u8; 32]> = credits.iter().map(|c| c.1).collect();
        let mask = self.spent_mask(&nullifiers);
        if mask != 0 {
            return Ok(ClaimPayoutResponse {
                result: ClaimPayoutResult::CreditsSpent as i32,
                spent_mask: mask,
                ..Default::default()
            });
        }
        let queued = credits
            .iter()
            .map(|(e, _)| self.schedule.credit_value(*e).unwrap())
            .sum();
        for n in &nullifiers {
            self.credit_use.insert(*n, claim_id.to_vec());
        }
        let answer = ClaimPayoutResponse {
            result: ClaimPayoutResult::Queued as i32,
            queued_atomic: queued,
            spent_mask: 0,
        };
        self.payouts.insert(claim_id, (body, answer));
        Ok(answer)
    }

    fn on_refresh_credit(
        &mut self,
        req: RefreshCreditRequest,
    ) -> Result<RefreshCreditResponse, IssuerError> {
        let token = Token::parse(&req.credit).map_err(|_| rpc(Code::InvalidArgument))?;
        let v = self
            .schedule
            .verify_token(&token, Expect::Credit)
            .map_err(|_| rpc(Code::PermissionDenied))?;
        self.last_blinded = Some(req.blinded.clone());
        let tag = [b"refresh".to_vec(), req.blinded.clone()].concat();
        if self.credit_use.get(&v.nullifier).is_some_and(|u| *u != tag) {
            return Ok(RefreshCreditResponse {
                result: RefreshCreditResult::Replayed as i32,
                ..Default::default()
            });
        }
        let sig = sign(Kind::Credit, v.epoch, &req.blinded).ok_or(rpc(Code::InvalidArgument))?;
        self.credit_use.insert(v.nullifier, tag);
        Ok(RefreshCreditResponse {
            result: RefreshCreditResult::Ok as i32,
            blind_signature: sig,
        })
    }
}

fn tampered<T>(answer: Result<T, IssuerError>, hook: &Option<Hook<T>>) -> Result<T, IssuerError> {
    answer.map(|mut a| {
        if let Some(h) = hook {
            h(&mut a);
        }
        a
    })
}

impl IssuerRpc for ModelIssuer {
    fn request_invoice(
        &mut self,
        req: RequestInvoiceRequest,
    ) -> impl Future<Output = Result<RequestInvoiceResponse, IssuerError>> + Send {
        let a = self
            .enter("request_invoice")
            .and_then(|_| self.on_request_invoice(req));
        ready(tampered(a, &self.tamper.request_invoice))
    }

    fn blind_sign(
        &mut self,
        req: BlindSignRequest,
    ) -> impl Future<Output = Result<BlindSignResponse, IssuerError>> + Send {
        let a = self
            .enter("blind_sign")
            .and_then(|_| self.on_blind_sign(req));
        ready(tampered(a, &self.tamper.blind_sign))
    }

    fn invoice_status(
        &mut self,
        req: InvoiceStatusRequest,
    ) -> impl Future<Output = Result<InvoiceStatusResponse, IssuerError>> + Send {
        let a = self
            .enter("invoice_status")
            .and_then(|_| self.on_invoice_status(req));
        ready(tampered(a, &self.tamper.invoice_status))
    }

    fn redeem_invite(
        &mut self,
        req: RedeemInviteRequest,
    ) -> impl Future<Output = Result<RedeemInviteResponse, IssuerError>> + Send {
        let a = self
            .enter("redeem_invite")
            .and_then(|_| self.on_redeem_invite(req));
        ready(tampered(a, &self.tamper.redeem_invite))
    }

    fn claim_payout(
        &mut self,
        req: ClaimPayoutRequest,
    ) -> impl Future<Output = Result<ClaimPayoutResponse, IssuerError>> + Send {
        let a = self
            .enter("claim_payout")
            .and_then(|_| self.on_claim_payout(req));
        ready(tampered(a, &self.tamper.claim_payout))
    }

    fn refresh_credit(
        &mut self,
        req: RefreshCreditRequest,
    ) -> impl Future<Output = Result<RefreshCreditResponse, IssuerError>> + Send {
        let a = self
            .enter("refresh_credit")
            .and_then(|_| self.on_refresh_credit(req));
        ready(tampered(a, &self.tamper.refresh_credit))
    }
}

/// Service key of a test onion label (SHA-256 of the label).
pub fn onion_key(label: &str) -> [u8; 32] {
    Sha256::digest(label.as_bytes()).into()
}

/// The client-side address of a test relay.
pub fn relay_address(label: &str, port: u16) -> OnionAddress {
    let host = ghost_entitlement::onion::hostname(&onion_key(label));
    OnionAddress::parse(&format!("{host}:{port}")).unwrap()
}

/// `start(week) + secs` (secs may be negative).
pub fn at(week: u64, secs: i64) -> u64 {
    u64::try_from(grid::week_start(week) as i64 + secs).unwrap()
}

/// A relay of the test schedule serving `slot` as the onion `label`, with a fresh data directory.
pub fn open_relay(dir: &Path, schedule: Schedule, slot: u8, label: &str, now: u64) -> Arc<Relay> {
    let mut policy = EntitlementPolicy::new(schedule, slot, onion_key(label)).unwrap();
    policy.nullifiers = NullifierMode::Create;
    let clock: Clock = Arc::new(move || now);
    Relay::open(
        dir,
        RelayKey::generate(),
        RelayConfig {
            entitlement: Some(policy),
            clock,
            ..RelayConfig::default()
        },
        None,
    )
    .unwrap()
}

/// A pinned token of `protocol/test-vectors/redeem.txt` (`token <name> ... hex=<hex>`).
pub fn pinned(name: &str) -> Vec<u8> {
    REDEEM_VECTORS
        .lines()
        .filter_map(|l| l.split('#').next()?.trim().strip_prefix("token "))
        .find_map(|rest| {
            let mut w = rest.split_whitespace();
            (w.next()? == name).then(|| w.find_map(|x| x.strip_prefix("hex=")))?
        })
        .map(|h| hex::decode(h).unwrap())
        .unwrap_or_else(|| panic!("no pinned token {name}"))
}

/// A real relay called in-process (`Relay::redeem_at`) behind the `RedeemRpc` seam: the client's
/// checks run against the relay's real answers, and `calls` counts what reached it.
pub struct InProcessRelay {
    pub relay: Arc<Relay>,
    pub now: u64,
    pub calls: usize,
    pub tamper: Option<Hook<RedeemTokenResponse>>,
}

impl InProcessRelay {
    pub fn new(relay: Arc<Relay>, now: u64) -> Self {
        InProcessRelay {
            relay,
            now,
            calls: 0,
            tamper: None,
        }
    }
}

impl RedeemRpc for InProcessRelay {
    fn redeem_token(
        &mut self,
        req: RedeemTokenRequest,
    ) -> impl Future<Output = Result<RedeemTokenResponse, RelayError>> + Send {
        self.calls += 1;
        let answer = self
            .relay
            .redeem_at(req, self.now)
            .map_err(RelayError::Rpc)
            .map(|mut a| {
                if let Some(h) = &self.tamper {
                    h(&mut a);
                }
                a
            });
        ready(answer)
    }
}
