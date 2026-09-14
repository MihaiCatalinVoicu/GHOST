//! The deterministic checks stated over keys, circuits, periods, the contact schedule and a
//! client's own flows (Phase 8 design §13.4): J5 c, J6, J7, J8, J9, J10 (its per-token half runs at
//! ingest), and T2c. J6, J8, J9 and T2c are statements about the ground truth (which flow a call
//! belongs to, which runs were quiet, which client made a call); the ground truth tells the checks
//! where to look, never what the adversary saw.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use ghost_entitlement::batch::Layout;
use ghost_entitlement::grid::{access_accepts, credit_epoch, week, week_start};
use ghost_entitlement::{Kind, Token};

use crate::accumulate::{Accumulator, IssuerRecord, Redeemed};
use crate::model::{FlowKind, IssuerOp, Truth};
use crate::numbers::informative;
use crate::values::Hit;

fn hit(check: &'static str, a: String, b: String) -> Hit {
    Hit {
        check,
        value: Vec::new(),
        a,
        b,
    }
}

/// The base week and payment kind of every invoice, from its `RequestInvoice` (issuer view).
pub fn invoices(acc: &Accumulator) -> HashMap<Vec<u8>, (u64, bool)> {
    let mut out = HashMap::new();
    for r in &acc.issuer {
        if r.op == IssuerOp::RequestInvoice && r.status == 0 && r.int("result") == Some(1) {
            if let (Some(id), Some(base)) = (r.resp("invoice_id"), r.int("base_week")) {
                let xmr = r.reqs("credits").next().is_none();
                out.insert(id.to_vec(), (base, xmr));
            }
        }
    }
    out
}

/// One signing answer to verify: its layout, the blinded values, the signatures, and a label.
type SignWork = (Layout, Vec<Vec<u8>>, Vec<Vec<u8>>, String);

/// J5 c and J7 c: every blind signature the issuer returned is `s'^e ≡ B (mod n)` under the ES key of
/// its position (the layout of the invoice's base week, the trial's base week, the refreshed
/// credit's epoch).
pub fn j5c(acc: &Accumulator) -> Vec<Hit> {
    let inv = invoices(acc);
    let mut work: Vec<SignWork> = Vec::new();
    for r in &acc.issuer {
        if r.status != 0 {
            continue;
        }
        let sigs: Vec<Vec<u8>> = r
            .resps("blind_signatures")
            .chain(r.resps("blind_signature"))
            .map(|s| s.to_vec())
            .collect();
        if sigs.is_empty() {
            continue;
        }
        let blinded: Vec<Vec<u8>> = r.reqs("blinded").map(|b| b.to_vec()).collect();
        let layout = match r.op {
            IssuerOp::BlindSign => r
                .req("invoice_id")
                .and_then(|id| inv.get(id))
                .and_then(|&(base, xmr)| Layout::pack(&acc.schedule, base, xmr).ok()),
            IssuerOp::RedeemInvite => r
                .int("base_week")
                .and_then(|b| Layout::trial(&acc.schedule, b).ok()),
            IssuerOp::RefreshCredit => r
                .req("credit")
                .and_then(|c| Token::parse(c).ok())
                .and_then(|t| acc.schedule.key_by_id(t.key_id()).map(|k| k.epoch))
                .and_then(|e| Layout::refresh(&acc.schedule, e).ok()),
            _ => None,
        };
        match layout {
            Some(l) => work.push((l, blinded, sigs, format!("{} at {}", r.op.name(), r.t))),
            None => work.push((
                Layout::refresh(&acc.schedule, credit_epoch(week(r.t))).unwrap_or_else(|_| {
                    Layout::pack(&acc.schedule, week(r.t), true).expect("a layout")
                }),
                Vec::new(),
                sigs,
                format!("{} at {} (no layout for its invoice)", r.op.name(), r.t),
            )),
        }
    }
    let threads = std::thread::available_parallelism()
        .map_or(4, |n| n.get())
        .min(16);
    let chunk = work.len().div_ceil(threads).max(1);
    std::thread::scope(|s| {
        let handles: Vec<_> = work
            .chunks(chunk)
            .map(|part| {
                let schedule = &acc.schedule;
                s.spawn(move || {
                    let mut out = Vec::new();
                    for (layout, blinded, sigs, what) in part {
                        if blinded.len() != sigs.len() || sigs.len() != layout.len() {
                            out.push(hit(
                                "J5c",
                                what.clone(),
                                "count differs from the layout".into(),
                            ));
                            continue;
                        }
                        for (j, (p, (b, s))) in layout
                            .positions()
                            .iter()
                            .zip(blinded.iter().zip(sigs))
                            .enumerate()
                        {
                            let key = schedule.key(p.kind, p.epoch).expect("layout key");
                            if !ghost_blind_rsa::check_blind_signature(&key.public_key, b, s) {
                                out.push(hit(
                                    "J5c",
                                    what.clone(),
                                    format!(
                                        "position {j} not signed by the ES key of ({:?}, {})",
                                        p.kind, p.epoch
                                    ),
                                ));
                                break;
                            }
                        }
                    }
                    out
                })
            })
            .collect();
        handles
            .into_iter()
            .flat_map(|h| h.join().unwrap())
            .collect()
    })
}

/// J6: (a) every issuer circuit label belongs to exactly one flow instance; (b) no relay circuit
/// carries two namespaces (T21 extended to redeem); (c) issuer labels ∩ relay labels = ∅.
pub fn j6(acc: &Accumulator) -> Vec<Hit> {
    let mut hits = Vec::new();
    let mut by_label: HashMap<[u8; 32], BTreeSet<u64>> = HashMap::new();
    for r in &acc.issuer {
        by_label.entry(r.label).or_default().insert(r.truth.flow);
    }
    for (label, flows) in &by_label {
        if flows.len() > 1 {
            hits.push(hit(
                "J6a",
                format!("issuer circuit {}", hex::encode(&label[..8])),
                format!("{} flow instances", flows.len()),
            ));
        }
    }
    let mut flows_per_instance: HashMap<u64, BTreeSet<[u8; 32]>> = HashMap::new();
    for r in &acc.issuer {
        flows_per_instance
            .entry(r.truth.flow)
            .or_default()
            .insert(r.label);
    }
    for (label, (_, conflict)) in &acc.relay_labels {
        if *conflict {
            hits.push(hit(
                "J6b",
                format!("relay circuit {}", hex::encode(&label[..8])),
                "two namespaces".into(),
            ));
        }
        if by_label.contains_key(label) {
            hits.push(hit(
                "J6c",
                format!("circuit {}", hex::encode(&label[..8])),
                "seen by the issuer and a relay".into(),
            ));
        }
    }
    hits
}

/// J7: (a) key ids at relays ⊆ ES; (b) key ids the issuer saw ⊆ ES; (c) exactly one key id per
/// (kind, epoch) (the ES lists one; with J5 c the issuer signed with it only).
pub fn j7(acc: &Accumulator) -> Vec<Hit> {
    let mut hits = Vec::new();
    for id in &acc.relay_key_ids {
        match acc.schedule.key_by_id(id) {
            Some(k) if k.kind == Kind::Access => {}
            _ => hits.push(hit(
                "J7a",
                hex::encode(id),
                "relay-seen key id not an ES ACCESS key".into(),
            )),
        }
    }
    for id in &acc.issuer_key_ids {
        if acc.schedule.key_by_id(id).is_none() {
            hits.push(hit(
                "J7b",
                hex::encode(id),
                "issuer-seen key id not in the ES".into(),
            ));
        }
    }
    let mut per: BTreeMap<(u8, u64), BTreeSet<[u8; 32]>> = BTreeMap::new();
    for k in acc.schedule.keys() {
        per.entry((k.kind.byte(), k.epoch))
            .or_default()
            .insert(k.key_id);
    }
    for ((kind, epoch), ids) in per {
        if ids.len() != 1 {
            hits.push(hit(
                "J7c",
                format!("({kind}, {epoch})"),
                format!("{} keys", ids.len()),
            ));
        }
    }
    hits
}

/// The relay-facing clock's resolution: relay answers carry whole minutes (§10.1), so a client
/// corrected by them knows true time to within a minute.
pub const MINUTE_RESOLUTION: u64 = 60;

/// The relay-facing clock's clip (§12.5, §19.23 point 2): offsets beyond a day are corrected only to
/// within a day.
pub const CLIP_SECS: i64 = 24 * 3_600;

/// J8 (§13.4, as §19.24 point 2 reads it for a clock corrected per relay):
/// - every accepted redemption lies in its window;
/// - no redemption of a relay-corrected client (two relays answered since the device clock was last
///   set) whose device is within the clip of true time lies within ±1 h of a true week boundary, to
///   the relay minute's resolution (±(1 h − 60 s));
/// - such a client is never refused a period;
/// - an uncorrected client meets each relay at most once per process start with a refused period
///   that it received (E14): that answer's period and minute are the relay's clock for every later
///   decision about it (`ClockEstimate.relayNow`). Identical retries (R8) count like any other
///   redemption; a refusal whose answer never reached the client (a lost answer, or a relay that
///   withholds it) taught the client nothing and is reported by [`j8_lost_refusals`], not counted
///   (S12 review P8-J8-1, design §19.27).
///
/// Devices further off than the clip are corrected only to within a day: their refused periods are
/// counted by [`j8_far_skew`] and reported.
pub fn j8(acc: &Accumulator) -> Vec<Hit> {
    j8_of(&acc.redemptions)
}

/// [`j8`] over a list of redemptions (in time order).
pub fn j8_of(redemptions: &[crate::accumulate::Redemption]) -> Vec<Hit> {
    let mut hits = Vec::new();
    let mut refused: BTreeMap<(u64, u8), Vec<String>> = BTreeMap::new();
    let guard = 3_600 - MINUTE_RESOLUTION;
    for r in redemptions {
        let what = || {
            format!(
                "redemption at {} by client {} at relay {} (device offset {} s, token week {:?}, week {}{})",
                r.t,
                r.client,
                r.relay,
                r.skew,
                r.week,
                week(r.t),
                if r.retry { ", an identical retry" } else { "" }
            )
        };
        if r.result == Redeemed::Ok {
            match r.week {
                Some(p) if access_accepts(p, r.t, 24) => {}
                _ => hits.push(hit(
                    "J8",
                    format!("redemption at {} relay {}", r.t, r.relay),
                    "accepted outside its window".into(),
                )),
            }
        }
        if r.skew.abs() > CLIP_SECS {
            continue;
        }
        let p = week(r.t);
        let near = r.t - week_start(p) < guard || week_start(p + 1) - r.t < guard;
        if r.corrected && near {
            hits.push(hit("J8", what(), "within 1 h of a week boundary".into()));
        }
        if r.result == Redeemed::WrongPeriod {
            if r.corrected {
                hits.push(hit(
                    "J8",
                    what(),
                    "WRONG_PERIOD after the relay-facing clock was corrected".into(),
                ));
            }
            // A refusal the client never received taught it nothing (S12 review P8-J8-1): it is
            // reported by `j8_lost_refusals`, never counted toward the per-relay bound.
            if !r.answer_lost {
                refused
                    .entry((r.process, r.relay))
                    .or_default()
                    .push(what());
            }
        }
    }
    for ((process, relay), shown) in refused {
        if shown.len() > 1 {
            hits.push(hit(
                "J8",
                format!("process {process:x} at relay {relay}"),
                format!(
                    "{} WRONG_PERIOD redemptions in one process at one relay: {}",
                    shown.len(),
                    shown.join("; ")
                ),
            ));
        }
    }
    hits
}

/// `WRONG_PERIOD` answers the client never received (reported with J8, not counted by its
/// per-relay bound; S12 review P8-J8-1): the world's lost-answer fault, or an AD-1 relay that
/// withholds its answer.
pub fn j8_lost_refusals(redemptions: &[crate::accumulate::Redemption]) -> usize {
    redemptions
        .iter()
        .filter(|r| r.answer_lost && r.result == Redeemed::WrongPeriod)
        .count()
}

/// Identical retries (R8) answered `WRONG_PERIOD` (reported with J8; counted by it too).
pub fn j8_late_retries(acc: &Accumulator) -> usize {
    acc.redemptions
        .iter()
        .filter(|r| r.retry && r.result == Redeemed::WrongPeriod)
        .count()
}

/// `WRONG_PERIOD` redemptions of devices more than 24 h off true time (reported with J8).
pub fn j8_far_skew(acc: &Accumulator) -> usize {
    acc.redemptions
        .iter()
        .filter(|r| r.result == Redeemed::WrongPeriod && r.skew.abs() > CLIP_SECS)
        .count()
}

/// `RequestInvoice` calls per purchase and `RedeemInvite` calls per revocation (`CALL_ATTEMPTS`,
/// §19.23 point 2), per lineage (§19.27).
pub const CALL_CAP: usize = 2;

/// `RedeemInvite` calls per onboarding trial (`ONBOARDING_ATTEMPTS`, §19.23 point 2).
pub const ONBOARDING_CAP: usize = 40;

/// J9's caps per lineage (§19.27, S12 review P8-PRIV-2): a `WRONG_PERIOD` re-prepare continues a
/// purchase, trial or revocation in a new flow instance that keeps its attempt count, so the caps
/// hold per lineage, not per instance (`RequestInvoice` 2 per purchase, `RedeemInvite` 2 per
/// revocation and 40 per onboarding trial): a lying `WRONG_PERIOD` buys no more linked calls than
/// a transient failure.
pub fn j9_lineages(issuer: &[IssuerRecord]) -> Vec<Hit> {
    let mut per_lineage: BTreeMap<(u32, u64, &'static str), (usize, usize)> = BTreeMap::new();
    for r in issuer {
        let (what, cap) = match (r.op, r.truth.kind) {
            (IssuerOp::RequestInvoice, _) => ("RequestInvoice calls in one purchase", CALL_CAP),
            (IssuerOp::RedeemInvite, FlowKind::Revocation) => {
                ("RedeemInvite calls in one revocation", CALL_CAP)
            }
            (IssuerOp::RedeemInvite, FlowKind::Trial) => {
                ("RedeemInvite calls in one onboarding trial", ONBOARDING_CAP)
            }
            _ => continue,
        };
        per_lineage
            .entry((r.truth.client, r.truth.lineage, what))
            .or_insert((0, cap))
            .0 += 1;
    }
    per_lineage
        .into_iter()
        .filter(|(_, (n, cap))| n > cap)
        .map(|((c, lineage, what), (n, cap))| {
            hit(
                "J9",
                format!("lineage {lineage:x} of client {c}"),
                format!("{n} {what} (cap {cap})"),
            )
        })
        .collect()
}

/// The quiet-run probability of every periodic-job run (§12.2).
pub const QUIET_Q: f64 = 1.0 / 8.0;

/// The level of the statistical conditions of the deterministic checks (§13.4: α = 0.001).
pub const CHECK_ALPHA: f64 = 0.001;

/// J9: the contact schedule, per flow (G-4): one `RequestInvoice` byte string per flow instance, and
/// at most 2 `RequestInvoice` per purchase, 2 `RedeemInvite` per revocation and 40 per onboarding
/// trial across the flows a `WRONG_PERIOD` re-prepare chains ([`j9_lineages`], §19.27); every
/// automatic issuer call in a quiet run (a run of the client in which the relay views hold no call
/// of it) and at most one per quiet run; quiet runs drawn independently of the work that is due
/// ([`j9_quiet`], P-7); at most 5 `BlindSign` per invoice, each at or after its due minute; every
/// user-initiated call at a foreground session the user script drew before it happened;
/// `ClaimPayout` at most weekly per client and never in a run with another issuer call; the
/// onboarding `RedeemInvite` before the identity's first relay call.
pub fn j9(
    acc: &Accumulator,
    truth: &Truth,
    due: impl Fn(&[u8; 32], u64, usize) -> u64 + Copy,
) -> Vec<Hit> {
    let mut hits = Vec::new();
    // Runs by (client, run id): quiet, start, end.
    let mut runs: HashMap<(u32, u64), (bool, u64, u64)> = HashMap::new();
    // (Whether a quiet run is independent of the work that is due, P-7, is read from the job runs'
    // times and the issuer view by `j9_quiet`, never from the world's own draw.)
    for (c, ct) in truth.clients.iter().enumerate() {
        for r in &ct.runs {
            runs.insert((c as u32, r.id), (r.quiet, r.start, r.end));
        }
    }
    let mut per_run: HashMap<(u32, u64), u32> = HashMap::new();
    let mut request_bytes: HashMap<(u32, u64), BTreeSet<Vec<u8>>> = HashMap::new();
    let mut signs: HashMap<Vec<u8>, Vec<u64>> = HashMap::new();
    let mut claims: HashMap<u32, Vec<u64>> = HashMap::new();
    let mut user_calls: HashMap<u32, Vec<u64>> = HashMap::new();
    let first_relay: Vec<Option<u64>> = acc.clients.iter().map(|c| c.first_call).collect();
    for r in &acc.issuer {
        let c = r.truth.client;
        let key = (c, r.truth.run);
        *per_run.entry(key).or_default() += 1;
        if r.truth.automatic {
            // The run's relay calls come from the relay views (each call's run), never from the
            // world's count of the run.
            let relay_calls = acc.relay_runs.contains(&key);
            match runs.get(&key) {
                Some(&(true, _, _)) if !relay_calls => {}
                Some(&(quiet, _, _)) => hits.push(hit(
                    "J9",
                    format!("{} of client {c} at {}", r.op.name(), r.t),
                    format!(
                        "automatic call in a run that is not quiet (quiet {quiet}, relay calls in the run: {relay_calls})"
                    ),
                )),
                None => hits.push(hit("J9", format!("{} of client {c} at {}", r.op.name(), r.t), "automatic call in no run".into())),
            }
        } else {
            user_calls.entry(c).or_default().push(r.t);
        }
        match r.op {
            IssuerOp::RequestInvoice => {
                let mut b = Vec::new();
                for (n, v) in &r.request {
                    b.extend_from_slice(n.as_bytes());
                    b.extend_from_slice(v);
                }
                b.extend_from_slice(&r.int("base_week").unwrap_or(0).to_be_bytes());
                request_bytes
                    .entry((c, r.truth.instance))
                    .or_default()
                    .insert(b);
            }
            IssuerOp::BlindSign => {
                if let Some(id) = r.req("invoice_id") {
                    signs.entry(id.to_vec()).or_default().push(r.t);
                }
            }
            IssuerOp::ClaimPayout => claims.entry(c).or_default().push(r.t),
            IssuerOp::RedeemInvite if r.truth.kind == FlowKind::Trial => {
                let first = first_relay.get(c as usize).copied().flatten();
                if first.is_some_and(|f| f <= r.t) {
                    hits.push(hit(
                        "J9",
                        format!("onboarding RedeemInvite of client {c} at {}", r.t),
                        "after the identity's first relay call".into(),
                    ));
                }
            }
            _ => {}
        }
    }
    for ((c, run), n) in &per_run {
        if runs.get(&(*c, *run)).is_some_and(|&(q, _, _)| q) && *n > 1 {
            hits.push(hit(
                "J9",
                format!("quiet run {run} of client {c}"),
                format!("{n} issuer calls"),
            ));
        }
    }
    for ((c, inst), set) in &request_bytes {
        // Every retry of a flow instance is identical: a `WRONG_PERIOD` re-prepare (a new base
        // week and claim key) is a new instance of the same lineage (§19.27).
        if set.len() > 1 {
            hits.push(hit(
                "J9",
                format!("purchase {inst:x} of client {c}"),
                "RequestInvoice retried with other bytes".into(),
            ));
        }
    }
    hits.extend(j9_lineages(&acc.issuer));
    let invoice_truth: HashMap<&[u8], &crate::model::InvoiceTruth> = truth
        .invoices
        .iter()
        .map(|i| (&i.invoice_id[..], i))
        .collect();
    for (id, times) in &signs {
        if times.len() > 5 {
            hits.push(hit(
                "J9",
                format!("invoice {}", hex::encode(id)),
                format!("{} BlindSign calls (cap 5)", times.len()),
            ));
        }
        if let Some(it) = invoice_truth.get(&id[..]) {
            let mut sorted = times.clone();
            sorted.sort_unstable();
            for (k, &t) in sorted.iter().enumerate().take(5) {
                let d = due(&it.seed, it.receipt_minute, k);
                let skew = truth.clients[it.client as usize]
                    .skew
                    .iter()
                    .find(|&&(from, until, _)| from <= t && t < until)
                    .map_or(0, |s| s.2);
                if (t as i64 + skew) < d as i64 {
                    hits.push(hit(
                        "J9",
                        format!("invoice {}", hex::encode(id)),
                        format!("BlindSign attempt {k} before its due minute"),
                    ));
                }
            }
        }
    }
    let _ = claims;
    // ClaimPayout at most weekly: distinct claims of a client start at least a week apart (a
    // claim's one retry belongs to the same flow instance).
    let mut claim_starts: HashMap<u32, BTreeMap<u64, u64>> = HashMap::new();
    for r in acc.issuer.iter().filter(|r| r.op == IssuerOp::ClaimPayout) {
        let e = claim_starts
            .entry(r.truth.client)
            .or_default()
            .entry(r.truth.instance)
            .or_insert(r.t);
        *e = (*e).min(r.t);
    }
    for (c, starts) in claim_starts {
        let mut times: Vec<u64> = starts.values().copied().collect();
        times.sort_unstable();
        for w in times.windows(2) {
            if w[1] - w[0] < 7 * 86_400 {
                hits.push(hit(
                    "J9",
                    format!("client {c}"),
                    "two claims less than a week apart".into(),
                ));
            }
        }
    }
    // A user action happens at a foreground session the user script drew before it (within the
    // session's first minute); an issuer call at any other moment is not the user's.
    for (c, times) in &user_calls {
        let scripted: &[u64] = &truth.clients[*c as usize].scripted;
        for &t in times {
            let i = scripted.partition_point(|&s| s + USER_ACTION_SECS < t);
            if !scripted.get(i).is_some_and(|&s| s <= t) {
                hits.push(hit(
                    "J9",
                    format!("client {c} at {t}"),
                    "user-initiated call that is no scripted user action".into(),
                ));
            }
        }
    }
    let q = j9_quiet(acc, truth, due);
    if q.p < CHECK_ALPHA {
        hits.push(hit(
            "J9",
            format!("{} of {} automatic BlindSign calls", q.first, q.n),
            format!(
                "quiet runs follow due work: served by the first job run at or after their due minute (q = 1/8, p = {:.1e})",
                q.p
            ),
        ));
    }
    hits
}

/// How long after the start of its foreground session a user action's issuer call may come.
pub const USER_ACTION_SECS: u64 = 60;

/// The automatic `BlindSign` calls served by the first periodic-job run of their client at or after
/// their due minute, of all those at or after it, and the one-sided binomial p-value against q.
#[derive(Debug, Clone, Copy, Default)]
pub struct QuietIndependence {
    pub first: usize,
    pub n: usize,
    pub p: f64,
}

/// P-7 (§12.2, §19.23 point 1): every job run draws quiet with q = 1/8 whatever work is due, so the
/// first job run at or after an attempt's due minute serves it with probability at most q (less
/// where other due work competes for the one call of a quiet run); a quiet pattern that follows
/// the due work (M20) serves nearly all attempts there. Read from the job runs the world scheduled
/// (their times) and the issuer view's call times; neither the runs' quiet labels nor the world's
/// draws are used.
pub fn j9_quiet(
    acc: &Accumulator,
    truth: &Truth,
    due: impl Fn(&[u8; 32], u64, usize) -> u64,
) -> QuietIndependence {
    j9_quiet_of(&acc.issuer, truth, due)
}

/// [`j9_quiet`] over a list of issuer records.
pub fn j9_quiet_of(
    issuer: &[IssuerRecord],
    truth: &Truth,
    due: impl Fn(&[u8; 32], u64, usize) -> u64,
) -> QuietIndependence {
    let invoice_truth: HashMap<&[u8], &crate::model::InvoiceTruth> = truth
        .invoices
        .iter()
        .map(|i| (&i.invoice_id[..], i))
        .collect();
    let mut signs: BTreeMap<Vec<u8>, Vec<(u64, u32, u64)>> = BTreeMap::new();
    for r in issuer
        .iter()
        .filter(|r| r.op == IssuerOp::BlindSign && r.truth.automatic)
    {
        if let Some(id) = r.req("invoice_id") {
            signs
                .entry(id.to_vec())
                .or_default()
                .push((r.t, r.truth.client, r.truth.run));
        }
    }
    let jobs: Vec<Vec<u64>> = truth
        .clients
        .iter()
        .map(|ct| {
            let mut v: Vec<u64> = ct.runs.iter().filter(|r| r.job).map(|r| r.start).collect();
            v.sort_unstable();
            v
        })
        .collect();
    let starts: HashMap<(u32, u64), u64> = truth
        .clients
        .iter()
        .enumerate()
        .flat_map(|(c, ct)| ct.runs.iter().map(move |r| ((c as u32, r.id), r.start)))
        .collect();
    let (mut first, mut n) = (0usize, 0usize);
    for (id, mut calls) in signs {
        let Some(it) = invoice_truth.get(&id[..]) else {
            continue;
        };
        calls.sort_unstable();
        for (k, &(t, c, run)) in calls.iter().enumerate().take(5) {
            let Some(&serving) = starts.get(&(c, run)) else {
                continue;
            };
            let skew = truth.clients[c as usize]
                .skew
                .iter()
                .find(|&&(from, until, _)| from <= t && t < until)
                .map_or(0, |s| s.2);
            // A job run a minute before the due minute may already serve it (its call comes a few
            // seconds after the run starts): counted as able to, which only lowers the share.
            let d = due(&it.seed, it.receipt_minute, k) as i64 - skew - 60;
            if (serving as i64) < d {
                continue;
            }
            let js = &jobs[c as usize];
            let lo = js.partition_point(|&s| (s as i64) < d);
            let hi = js.partition_point(|&s| s < serving);
            n += 1;
            if hi <= lo {
                first += 1;
            }
        }
    }
    QuietIndependence {
        first,
        n,
        p: crate::stats::binom_tail_p(first as u64, n as u64, QUIET_Q),
    }
}

/// Completeness (§13.4): the ground-truth nullifiers (every token a client handed to a relay) that
/// appear in no relay view.
pub fn nullifiers_missing(acc: &Accumulator, truth: &Truth) -> usize {
    let seen: HashSet<[u8; 32]> = acc.redemptions.iter().map(|r| r.nullifier).collect();
    truth
        .presented
        .iter()
        .filter(|n| !seen.contains(*n))
        .count()
}

/// T2c: two flow instances (invoices, trials, refreshes, revocations, claims) of one client share
/// no value outside W at the issuer (claim hashes and keys, invoice ids, credits, blinded blocks,
/// addresses, circuits); and, in the Sybil world, no token the attacker's clients finalized is
/// presented at the issuer other than in a `RefreshCredit` (§19.8).
pub fn t2c(acc: &Accumulator, truth: &Truth) -> Vec<Hit> {
    t2c_counted(acc, truth).hits
}

/// T2c with its two counted exemptions.
#[derive(Debug, Default)]
pub struct T2cCounts {
    pub hits: Vec<Hit>,
    /// Credits re-presented by a new flow after the flow that first presented them failed before
    /// the issuer answered it (§19.23 point 2, Q28: the client releases the credits of a credits
    /// pack whose capped `RequestInvoice` got no answer and presents them again in its next
    /// credits pack).
    pub released: usize,
    /// Credits or invite tokens re-presented by a re-prepared flow of the same lineage after a
    /// `WRONG_PERIOD` answer (§19.27): the purchase, trial or revocation continues in a new flow
    /// that keeps its attempt count, so a lineage has at most as many flows as its cap of calls;
    /// a re-presentation in a lineage with more flows than that is a hit.
    pub re_prepared: usize,
}

/// Flows a lineage may have (its call cap, §19.27): `RequestInvoice` 2, a revocation's
/// `RedeemInvite` 2, an onboarding trial's 40.
fn lineage_cap(kind: FlowKind) -> usize {
    match kind {
        FlowKind::Trial => ONBOARDING_CAP,
        _ => CALL_CAP,
    }
}

/// T2c and its counted exemptions ([`T2cCounts`]). Each re-presentation links two flows at the
/// issuer; the exemptions are counted and reported, never silent.
pub fn t2c_counted(acc: &Accumulator, truth: &Truth) -> T2cCounts {
    t2c_of(
        &acc.issuer,
        |v| acc.public.contains(v),
        &truth.attacker_tokens,
    )
}

/// [`t2c_counted`] over the issuer records, with W (`is_public`) and the Sybil attacker's tokens.
pub fn t2c_of(
    issuer: &[IssuerRecord],
    is_public: impl Fn(&[u8]) -> bool,
    attacker_tokens: &[Vec<u8>],
) -> T2cCounts {
    let mut hits = Vec::new();
    // The flow instances of each lineage that made a `RequestInvoice` or `RedeemInvite`.
    let mut lineage_flows: HashMap<(u32, u64), (FlowKind, BTreeSet<u64>)> = HashMap::new();
    for r in issuer
        .iter()
        .filter(|r| matches!(r.op, IssuerOp::RequestInvoice | IssuerOp::RedeemInvite))
    {
        lineage_flows
            .entry((r.truth.client, r.truth.lineage))
            .or_insert((r.truth.kind, BTreeSet::new()))
            .1
            .insert(r.truth.instance);
    }
    let mut re_prepared = 0usize;
    let mut beyond: HashSet<(u32, u64)> = HashSet::new();
    // Flow instances that presented credits and never got an answer.
    let mut answered: HashMap<(u32, u64), bool> = HashMap::new();
    for r in issuer.iter().filter(|r| r.op == IssuerOp::RequestInvoice) {
        // A `WRONG_PERIOD` answer records nothing either (§5.3): the flow ends without an invoice,
        // and its released credits are presented again like those of an unanswered flow.
        let ok = r.status == 0 && r.int("result") != Some(REQUEST_INVOICE_WRONG_PERIOD);
        let e = answered
            .entry((r.truth.client, r.truth.instance))
            .or_insert(false);
        *e |= ok;
    }
    let mut released = 0usize;
    // value → (client, instance, field, lineage) of first sight.
    let mut first: HashMap<Vec<u8>, (u32, u64, &'static str, u64)> = HashMap::new();
    let mut reported: HashSet<(u32, u64, u64)> = HashSet::new();
    let label_field = "circuit";
    for r in issuer {
        let c = r.truth.client;
        let inst = r.truth.instance;
        let lineage = r.truth.lineage;
        let mut vals: Vec<(&'static str, &[u8])> = r
            .request
            .iter()
            .chain(r.response.iter())
            .filter(|(_, v)| informative(v) && !is_public(v))
            .map(|(n, v)| (*n, &v[..]))
            .collect();
        vals.push((label_field, &r.label[..]));
        for (n, v) in vals {
            match first.get(v) {
                Some(&(c2, i2, n2, l2))
                    if c2 == c
                        && i2 != inst
                        && l2 == lineage
                        && n == n2
                        && matches!(n, "credits" | "invite_token") =>
                {
                    let (kind, flows) = &lineage_flows[&(c, lineage)];
                    if flows.len() <= lineage_cap(*kind) {
                        re_prepared += 1;
                    } else if beyond.insert((c, lineage)) {
                        hits.push(hit(
                            "T2c",
                            format!("client {c}: {n} of flow {inst:x}"),
                            format!(
                                "re-presented by {} flows of lineage {lineage:x}, beyond its cap of {}",
                                flows.len(),
                                lineage_cap(*kind)
                            ),
                        ));
                    }
                }
                Some(&(c2, i2, n2, _))
                    if c2 == c
                        && i2 != inst
                        && n == "credits"
                        && n2 == "credits"
                        && !answered.get(&(c2, i2)).copied().unwrap_or(true) =>
                {
                    released += 1;
                }
                Some(&(c2, i2, n2, _)) if c2 == c && i2 != inst => {
                    let key = (c, inst.min(i2), inst.max(i2));
                    if reported.insert(key) {
                        hits.push(hit(
                            "T2c",
                            format!("client {c}: {n} of flow {inst:x}"),
                            format!("{n2} of flow {i2:x}"),
                        ));
                    }
                }
                Some(_) => {}
                None => {
                    first.insert(v.to_vec(), (c, inst, n, lineage));
                }
            }
        }
    }
    let known: HashSet<&[u8]> = attacker_tokens.iter().map(|t| &t[..]).collect();
    for r in issuer {
        if r.op == IssuerOp::RefreshCredit {
            continue;
        }
        for v in r.reqs("credits") {
            if known.contains(v) {
                hits.push(hit(
                    "T2c",
                    format!("{} of client {} at {}", r.op.name(), r.truth.client, r.t),
                    "presents a credit the attacker's Sybil client finalized".into(),
                ));
            }
        }
    }
    T2cCounts {
        hits,
        released,
        re_prepared,
    }
}

/// `REQUEST_INVOICE_RESULT_WRONG_PERIOD` (`issuer.proto`).
const REQUEST_INVOICE_WRONG_PERIOD: u64 = 2;

/// Everything an issuer record says about its invoice, for the statistics.
pub fn by_invoice(acc: &Accumulator) -> HashMap<Vec<u8>, Vec<&IssuerRecord>> {
    let mut out: HashMap<Vec<u8>, Vec<&IssuerRecord>> = HashMap::new();
    let mut claim_to_id: HashMap<(u32, u64), Vec<u8>> = HashMap::new();
    for r in &acc.issuer {
        if r.op == IssuerOp::RequestInvoice {
            if let Some(id) = r.resp("invoice_id").filter(|v| !v.is_empty()) {
                claim_to_id.insert((r.truth.client, r.truth.instance), id.to_vec());
            }
        }
    }
    for r in &acc.issuer {
        let id = match r.op {
            IssuerOp::BlindSign | IssuerOp::InvoiceStatus => {
                r.req("invoice_id").map(|v| v.to_vec())
            }
            IssuerOp::RequestInvoice => claim_to_id
                .get(&(r.truth.client, r.truth.instance))
                .cloned(),
            _ => None,
        };
        if let Some(id) = id {
            out.entry(id).or_default().push(r);
        }
    }
    out
}

/// J10 (schedule half): every ES key's permutation proof verifies.
pub fn j10_keys(
    acc: &Accumulator,
    proofs: &[(Kind, u64, ghost_blind_rsa::PublicKey, Vec<[u8; 256]>)],
) -> Vec<Hit> {
    let mut hits: Vec<Hit> = acc
        .j10
        .iter()
        .map(|m| hit("J10", m.clone(), String::new()))
        .collect();
    for (kind, epoch, pk, proof) in proofs {
        let rounds: Result<[[u8; 256]; 8], _> = proof.clone().try_into();
        let ok = rounds.is_ok_and(|p| ghost_blind_rsa::verify_permutation_proof(pk, &p).is_ok());
        if !ok {
            hits.push(hit(
                "J10",
                format!("ES key ({kind:?}, {epoch})"),
                "permutation proof does not verify".into(),
            ));
        }
    }
    hits
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accumulate::Redemption;
    use crate::model::{ClientKind, ClientTruth, IssuerTruth, Run};

    const P: u64 = 2_990;

    #[allow(clippy::too_many_arguments)]
    fn red(
        t: u64,
        token_week: u64,
        relay: u8,
        process: u64,
        skew: i64,
        corrected: bool,
        result: Redeemed,
        retry: bool,
    ) -> Redemption {
        Redemption {
            t,
            relay,
            client: 7,
            week: Some(token_week),
            key_id: [0; 32],
            nullifier: [t as u8; 32],
            result,
            jacobi_em: 1,
            corrected,
            skewed: skew.abs() > 4 * 3_600,
            skew,
            process,
            source: 0,
            retry,
            answer_lost: false,
        }
    }

    /// S12 review P8-J8-1 (CI run 34788951925, client 447 at relay 2): a `WRONG_PERIOD` answer lost
    /// in transit taught the client nothing, so its next fresh token at that relay, on the same
    /// uncorrected clock, is refused too. Only refusals the client received count toward "at most
    /// once per process start and relay"; the lost ones are reported (an AD-1 relay can withhold
    /// its answer on purpose), and two received refusals still fail.
    #[test]
    fn j8_counts_only_refusals_the_client_received() {
        let t = week_start(P + 1) - 36 * 3_600;
        let mut lost = red(t, P + 1, 2, 9, 60_429, false, Redeemed::WrongPeriod, false);
        lost.answer_lost = true;
        let received = red(
            t + 2,
            P + 1,
            2,
            9,
            60_429,
            false,
            Redeemed::WrongPeriod,
            false,
        );
        let hits = j8_of(&[lost.clone(), received.clone()]);
        assert!(hits.is_empty(), "{hits:?}");
        assert_eq!(j8_lost_refusals(&[lost.clone(), received.clone()]), 1);
        let mut second = received.clone();
        second.t += 600;
        let hits = j8_of(&[lost, received, second]);
        assert!(
            hits.iter().any(|h| h
                .b
                .contains("2 WRONG_PERIOD redemptions in one process at one relay")),
            "{hits:?}"
        );
    }

    /// An identical retry refused for its period counts like any other redemption.
    #[test]
    fn j8_counts_identical_retries() {
        let t = week_start(P + 1) - 36 * 3_600;
        let hits = j8_of(&[
            red(
                t,
                P + 1,
                0,
                1,
                17 * 3_600,
                false,
                Redeemed::WrongPeriod,
                false,
            ),
            red(
                t + 600,
                P + 1,
                0,
                1,
                17 * 3_600,
                false,
                Redeemed::WrongPeriod,
                true,
            ),
        ]);
        assert!(
            hits.iter()
                .any(|h| h.b.contains("in one process at one relay")),
            "{hits:?}"
        );
    }

    /// The ±1 h guard binds a corrected client up to the clip, to the relay minute's resolution.
    #[test]
    fn j8_guards_corrected_clients_up_to_the_clip() {
        let near = week_start(P) + 1_800;
        let hits = j8_of(&[red(near, P, 1, 2, 10 * 3_600, true, Redeemed::Ok, false)]);
        assert!(
            hits.iter()
                .any(|h| h.b.contains("within 1 h of a week boundary")),
            "{hits:?}"
        );
        let edge = week_start(P) + 3_550;
        assert!(j8_of(&[red(edge, P, 1, 2, 10 * 3_600, true, Redeemed::Ok, false)]).is_empty());
        // Beyond the clip the client is corrected only to within a day: reported, not a hit.
        assert!(j8_of(&[red(near, P, 1, 3, 30 * 3_600, true, Redeemed::Ok, false)]).is_empty());
        assert!(j8_of(&[
            red(
                near,
                P + 1,
                1,
                3,
                30 * 3_600,
                false,
                Redeemed::WrongPeriod,
                false
            ),
            red(
                near + 60,
                P + 1,
                1,
                3,
                30 * 3_600,
                false,
                Redeemed::WrongPeriod,
                false
            ),
        ])
        .is_empty());
    }

    /// At most one refused period per process start and relay, whatever the device clock did.
    #[test]
    fn j8_counts_per_process_start_and_relay() {
        let t = week_start(P + 1) - 36 * 3_600;
        let hits = j8_of(&[
            red(
                t,
                P + 1,
                0,
                4,
                17 * 3_600,
                false,
                Redeemed::WrongPeriod,
                false,
            ),
            // The user sets the device clock right; the process goes on.
            red(
                t + 7_200,
                P + 1,
                0,
                4,
                0,
                false,
                Redeemed::WrongPeriod,
                false,
            ),
        ]);
        assert!(
            hits.iter()
                .any(|h| h.b.contains("in one process at one relay")),
            "{hits:?}"
        );
        // Once at each relay: every relay corrects the decisions about itself.
        assert!(j8_of(&[
            red(
                t,
                P + 1,
                0,
                5,
                17 * 3_600,
                false,
                Redeemed::WrongPeriod,
                false
            ),
            red(
                t + 1,
                P + 1,
                1,
                5,
                17 * 3_600,
                false,
                Redeemed::WrongPeriod,
                false
            ),
            red(
                t + 2,
                P + 1,
                2,
                5,
                17 * 3_600,
                false,
                Redeemed::WrongPeriod,
                false
            ),
        ])
        .is_empty());
        // A corrected client is never refused a period.
        let hits = j8_of(&[red(
            t,
            P + 1,
            0,
            6,
            17 * 3_600,
            true,
            Redeemed::WrongPeriod,
            false,
        )]);
        assert!(hits
            .iter()
            .any(|h| h.b.contains("after the relay-facing clock was corrected")));
    }

    /// A client whose job runs come every 15 minutes and whose automatic `BlindSign` calls are each
    /// served `after` job runs past their due minute (due = receipt + 3 h).
    fn quiet_world(after: u64) -> (Vec<IssuerRecord>, Truth) {
        let t0 = week_start(P);
        let runs: Vec<Run> = (0..20_000u64)
            .map(|j| Run {
                id: j,
                start: t0 + 900 * j,
                end: t0 + 900 * j + 60,
                job: true,
                quiet: false,
                drawn: false,
                relay_calls: 0,
                issuer_calls: 0,
            })
            .collect();
        let mut invoices = Vec::new();
        let mut issuer = Vec::new();
        for k in 0..200u64 {
            let receipt = t0 + 86_400 + 3 * 3_600 * k;
            let first_job = (receipt + 3 * 3_600 - t0).div_ceil(900);
            let run = first_job + after;
            let mut id = [0u8; 16];
            id[..8].copy_from_slice(&k.to_be_bytes());
            invoices.push(crate::model::InvoiceTruth {
                invoice_id: id,
                client: 0,
                instance: k,
                xmr: true,
                base_week: P,
                need_triggered: false,
                scored: true,
                payments: Vec::new(),
                seed: [0; 32],
                receipt_minute: receipt,
                finalized: None,
            });
            issuer.push(IssuerRecord {
                t: t0 + 900 * run + 5,
                t_resp: t0 + 900 * run + 7,
                label: [0; 32],
                op: IssuerOp::BlindSign,
                request: vec![("invoice_id", id.to_vec())],
                response: Vec::new(),
                ints: Vec::new(),
                status: 0,
                truth: IssuerTruth {
                    client: 0,
                    flow: k,
                    instance: k,
                    lineage: k,
                    kind: FlowKind::PackXmr,
                    automatic: true,
                    run,
                },
            });
        }
        let truth = Truth {
            clients: vec![ClientTruth {
                kind: ClientKind::Existing,
                namespaces: 1,
                user_calls: Vec::new(),
                scripted: Vec::new(),
                runs,
                skew: Vec::new(),
                processes: Vec::new(),
            }],
            invoices,
            ..Truth::default()
        };
        (issuer, truth)
    }

    /// M20's signature: quiet runs that follow the due work serve every attempt at its first job run.
    #[test]
    fn j9_sees_quiet_runs_that_follow_due_work() {
        let due = |_: &[u8; 32], receipt: u64, _: usize| receipt + 3 * 3_600;
        let (issuer, truth) = quiet_world(0);
        let q = j9_quiet_of(&issuer, &truth, due);
        assert_eq!((q.first, q.n), (200, 200));
        assert!(q.p < CHECK_ALPHA);
        let (issuer, truth) = quiet_world(8);
        let q = j9_quiet_of(&issuer, &truth, due);
        assert_eq!((q.first, q.n), (0, 200));
        assert!(q.p > 0.5);
    }

    /// One issuer call of flow `instance` in `lineage` presenting `values` (as `field`), answered
    /// `result` (2: `WRONG_PERIOD`).
    fn call(
        op: IssuerOp,
        kind: FlowKind,
        instance: u64,
        lineage: u64,
        field: &'static str,
        values: &[Vec<u8>],
        result: u64,
    ) -> IssuerRecord {
        let own: Vec<u8> = (0..32u8)
            .map(|b| b.wrapping_mul(7) ^ instance as u8)
            .collect();
        let mut request = vec![("claim_hash", own)];
        request.extend(values.iter().map(|v| (field, v.clone())));
        // One fresh circuit per call (R5).
        let mut label = [0u8; 32];
        for (i, b) in label.iter_mut().enumerate() {
            *b = (i as u8 ^ instance as u8).wrapping_mul(5) | 1;
        }
        IssuerRecord {
            t: 1_000 * instance,
            t_resp: 1_000 * instance + 2,
            label,
            op,
            request,
            response: Vec::new(),
            ints: vec![("base_week", P), ("result", result)],
            status: 0,
            truth: IssuerTruth {
                client: 3,
                flow: instance,
                instance,
                lineage,
                kind,
                automatic: true,
                run: instance,
            },
        }
    }

    fn credit(n: u8) -> Vec<u8> {
        (1..=64u8).map(|b| b.wrapping_add(n)).collect()
    }

    /// S12 review P8-PRIV-2 (§19.27): the caps hold per lineage, whatever the flow instances.
    #[test]
    fn j9_caps_calls_per_lineage() {
        let pack = |i| {
            call(
                IssuerOp::RequestInvoice,
                FlowKind::PackXmr,
                i,
                1,
                "credits",
                &[],
                2,
            )
        };
        assert!(j9_lineages(&[pack(1), pack(2)]).is_empty());
        let hits = j9_lineages(&[pack(1), pack(2), pack(3)]);
        assert!(
            hits.iter()
                .any(|h| h.b == "3 RequestInvoice calls in one purchase (cap 2)"),
            "{hits:?}"
        );
        let revoke = |i| {
            call(
                IssuerOp::RedeemInvite,
                FlowKind::Revocation,
                i,
                7,
                "invite_token",
                &[credit(9)],
                2,
            )
        };
        let hits = j9_lineages(&[revoke(7), revoke(8), revoke(9)]);
        assert!(
            hits.iter()
                .any(|h| h.b == "3 RedeemInvite calls in one revocation (cap 2)"),
            "{hits:?}"
        );
        let trial: Vec<IssuerRecord> = (0..41)
            .map(|i| {
                call(
                    IssuerOp::RedeemInvite,
                    FlowKind::Trial,
                    100 + i,
                    100,
                    "invite_token",
                    &[credit(5)],
                    2,
                )
            })
            .collect();
        assert!(j9_lineages(&trial[..40]).is_empty());
        assert!(j9_lineages(&trial).iter().any(|h| h.b.contains("(cap 40)")));
    }

    /// S12 review P8-PRIV-2 (§19.27): credits re-presented by a re-prepared flow of the same
    /// purchase are counted within its cap and a hit beyond it; released credits of a purchase
    /// that ended on `WRONG_PERIOD` at its cap are counted as released when the next purchase
    /// presents them.
    #[test]
    fn t2c_counts_a_re_prepare_within_its_cap_and_refuses_one_beyond_it() {
        let set = [credit(1), credit(2)];
        let pack = |i, lineage| {
            call(
                IssuerOp::RequestInvoice,
                FlowKind::PackCredits,
                i,
                lineage,
                "credits",
                &set,
                2,
            )
        };
        let t = t2c_of(&[pack(1, 1), pack(2, 1)], |_| false, &[]);
        assert!(t.hits.is_empty(), "{:?}", t.hits);
        assert_eq!((t.re_prepared, t.released), (2, 0));
        // The purchase failed at its cap; the next purchase presents the released credits.
        let t = t2c_of(&[pack(1, 1), pack(2, 1), pack(3, 3)], |_| false, &[]);
        assert!(t.hits.is_empty(), "{:?}", t.hits);
        assert_eq!((t.re_prepared, t.released), (2, 2));
        // A third flow of one purchase: beyond the cap.
        let t = t2c_of(&[pack(1, 1), pack(2, 1), pack(3, 1)], |_| false, &[]);
        assert!(
            t.hits.iter().any(|h| h.b.contains("beyond its cap of 2")),
            "{:?}",
            t.hits
        );
        // Another purchase after one that got an invoice (result 1) is still a hit.
        let mut invoiced = pack(1, 1);
        invoiced.ints = vec![("base_week", P), ("result", 1)];
        let t = t2c_of(&[invoiced, pack(4, 4)], |_| false, &[]);
        assert_eq!(t.hits.len(), 1, "{:?}", t.hits);
    }
}
