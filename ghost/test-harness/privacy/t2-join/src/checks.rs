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

/// J8: every accepted redemption lies in its window; no redemption of a relay-corrected client
/// process whose device is within 4 h of true time lies within ±1 h of a true week boundary; for a
/// device within 24 h of true time (the relay-facing clock corrects any such offset: offsets are
/// clipped to ±24 h, §12.5, §19.23 point 2), a process sends at most one redemption per relay that
/// the relay refuses for its period before two relays answered (a `WRONG_PERIOD` answer's period
/// is adopted for that relay at once, E14). After that, one more per relay only where the adopted
/// period went stale: the relay's previous answer was `WRONG_PERIOD` (an adoption no accepted
/// answer has cleared; the estimate lives for the process, across device clock changes) and a week
/// boundary passed, which `ClockEstimate.week` keeps for 24 h; never two in a row. The estimate's
/// offsets are taken against the device wall clock, so a device clock set right mid-process starts
/// a new uncorrected count (that key holds the device offset). Devices further off are corrected
/// only to within the clip: their `WRONG_PERIOD` answers are counted by [`j8_far_skew`] and
/// reported. An identical retry of an ambiguous redemption (R8, from the ground truth: its first
/// attempt may never have reached the relay) that lands after its week is refused for its period
/// whatever the clock says; those are counted by [`j8_late_retries`] and reported, and their
/// answers' periods are adopted like any other.
pub fn j8(acc: &Accumulator) -> Vec<Hit> {
    let mut hits = Vec::new();
    let mut uncorrected: HashMap<(u64, u8, i64), Vec<String>> = HashMap::new();
    // Per (process, relay): the relay's latest answer (time, device offset, WRONG_PERIOD, and
    // whether that WRONG_PERIOD was itself the one stale adoption allowed after correction).
    let mut last: HashMap<(u64, u8), (u64, i64, bool, bool)> = HashMap::new();
    for r in &acc.redemptions {
        let key = (r.process, r.relay, r.skew);
        let relay_key = (r.process, r.relay);
        if r.retry && r.result == Redeemed::WrongPeriod {
            // The client adopts its answer's period all the same.
            last.insert(relay_key, (r.t, r.skew, true, false));
            continue;
        }
        let previous = last.get(&relay_key).copied();
        let what = || {
            let before = match previous {
                None => "none".to_string(),
                Some((t, skew, wrong, _)) => format!(
                    "{} at {t}, device offset {skew} s",
                    if wrong { "WRONG_PERIOD" } else { "accepted" }
                ),
            };
            format!(
                "redemption at {} by client {} at relay {} (device offset {} s, token week {:?}, week {}; the relay's previous answer: {before})",
                r.t,
                r.client,
                r.relay,
                r.skew,
                r.week,
                week(r.t)
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
        let p = week(r.t);
        let near = r.t - week_start(p) < 3_600 || week_start(p + 1) - r.t < 3_600;
        if r.corrected && near && r.skew.abs() <= 4 * 3_600 {
            hits.push(hit("J8", what(), "within 1 h of a week boundary".into()));
        }
        let mut stale = false;
        if r.result == Redeemed::WrongPeriod && r.skew.abs() <= 24 * 3_600 {
            if !r.corrected {
                uncorrected.entry(key).or_default().push(what());
            } else if matches!(previous, Some((_, _, true, false))) {
                stale = true;
            } else {
                hits.push(hit(
                    "J8",
                    what(),
                    "WRONG_PERIOD after the relay-facing clock was corrected".into(),
                ));
            }
        }
        // Every answer carries the relay's period: a WRONG_PERIOD adopts it, any other clears it.
        if matches!(
            r.result,
            Redeemed::Ok | Redeemed::Replayed | Redeemed::WrongPeriod
        ) {
            last.insert(
                relay_key,
                (r.t, r.skew, r.result == Redeemed::WrongPeriod, stale),
            );
        }
    }
    for ((process, relay, _), shown) in uncorrected {
        if shown.len() > 1 {
            hits.push(hit(
                "J8",
                format!("process {process:x} at relay {relay}"),
                format!(
                    "{} uncorrected WRONG_PERIOD redemptions: {}",
                    shown.len(),
                    shown.join("; ")
                ),
            ));
        }
    }
    hits
}

/// Identical retries (R8) answered `WRONG_PERIOD` (reported with J8).
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
        .filter(|r| r.result == Redeemed::WrongPeriod && r.skew.abs() > 24 * 3_600)
        .count()
}

/// J9: the contact schedule, per flow (G-4): one `RequestInvoice` byte string per purchase; every
/// automatic issuer call in a quiet run (a run with zero relay calls) and at most one per quiet
/// run; at most 5 `BlindSign` per invoice, each at or after its due minute; the user-initiated calls
/// are the scripted user actions; `ClaimPayout` at most weekly per client and never in a run with
/// another issuer call; the onboarding `RedeemInvite` before the identity's first relay call.
pub fn j9(
    acc: &Accumulator,
    truth: &Truth,
    due: impl Fn(&[u8; 32], u64, usize) -> u64,
) -> Vec<Hit> {
    let mut hits = Vec::new();
    // Runs by (client, run id).
    let mut runs: HashMap<(u32, u64), (bool, u32)> = HashMap::new();
    for (c, ct) in truth.clients.iter().enumerate() {
        for r in &ct.runs {
            runs.insert((c as u32, r.id), (r.quiet, r.relay_calls));
            // The pattern of quiet runs is independent of issuer state (P-7): every quiet run is
            // one the process's draw selected, never one forced by work that is due.
            if r.quiet && !r.drawn {
                hits.push(hit(
                    "J9",
                    format!("quiet run {} of client {c} at {}", r.id, r.start),
                    "not drawn by the process (forced)".into(),
                ));
            }
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
            match runs.get(&key) {
                Some(&(true, 0)) => {}
                Some(&(quiet, n)) => hits.push(hit(
                    "J9",
                    format!("{} of client {c} at {}", r.op.name(), r.t),
                    format!("automatic call in a run that is not quiet (quiet {quiet}, {n} relay calls)"),
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
        if runs.get(&(*c, *run)).is_some_and(|&(q, _)| q) && *n > 1 {
            hits.push(hit(
                "J9",
                format!("quiet run {run} of client {c}"),
                format!("{n} issuer calls"),
            ));
        }
    }
    for ((c, inst), set) in &request_bytes {
        // A WRONG_PERIOD re-prepare changes the base week; every other retry is identical.
        let bases: BTreeSet<&[u8]> = set.iter().map(|b| &b[b.len() - 8..]).collect();
        if set.len() > bases.len() {
            hits.push(hit(
                "J9",
                format!("purchase {inst:x} of client {c}"),
                "RequestInvoice retried with other bytes".into(),
            ));
        }
    }
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
    for (c, times) in &user_calls {
        let scripted: BTreeSet<u64> = truth.clients[*c as usize]
            .user_calls
            .iter()
            .map(|u| u.0)
            .collect();
        for t in times {
            if !scripted.contains(t) {
                hits.push(hit(
                    "J9",
                    format!("client {c} at {t}"),
                    "user-initiated call that is no scripted user action".into(),
                ));
            }
        }
    }
    hits
}

/// T2c: two flow instances (invoices, trials, refreshes, revocations, claims) of one client share
/// no value outside W at the issuer (claim hashes and keys, invoice ids, credits, blinded blocks,
/// addresses, circuits); and, in the Sybil world, no token the attacker's clients finalized is
/// presented at the issuer other than in a `RefreshCredit` (§19.8).
pub fn t2c(acc: &Accumulator, truth: &Truth) -> Vec<Hit> {
    t2c_counted(acc, truth).0
}

/// T2c and the number of credits re-presented by a new flow after the flow that first presented
/// them failed before the issuer answered it (§19.23 point 2, Q28: the client releases the
/// credits of a credits pack whose capped `RequestInvoice` got no answer and presents them again
/// in its next credits pack). That re-presentation links the two flows at the issuer; it is the
/// one exemption, and it is counted and reported, never silent.
pub fn t2c_counted(acc: &Accumulator, truth: &Truth) -> (Vec<Hit>, usize) {
    let mut hits = Vec::new();
    // Flow instances that presented credits and never got an answer.
    let mut answered: HashMap<(u32, u64), bool> = HashMap::new();
    for r in acc
        .issuer
        .iter()
        .filter(|r| r.op == IssuerOp::RequestInvoice)
    {
        let ok = r.status == 0;
        let e = answered
            .entry((r.truth.client, r.truth.instance))
            .or_insert(false);
        *e |= ok;
    }
    let mut released = 0usize;
    // value → (client, instance) of first sight.
    let mut first: HashMap<Vec<u8>, (u32, u64, &'static str)> = HashMap::new();
    let mut reported: HashSet<(u32, u64, u64)> = HashSet::new();
    let label_field = "circuit";
    for r in &acc.issuer {
        let c = r.truth.client;
        let inst = r.truth.instance;
        let mut vals: Vec<(&'static str, &[u8])> = r
            .request
            .iter()
            .chain(r.response.iter())
            .filter(|(_, v)| informative(v) && !acc.public.contains(v))
            .map(|(n, v)| (*n, &v[..]))
            .collect();
        vals.push((label_field, &r.label[..]));
        for (n, v) in vals {
            match first.get(v) {
                Some(&(c2, i2, n2))
                    if c2 == c
                        && i2 != inst
                        && n == "credits"
                        && n2 == "credits"
                        && !answered.get(&(c2, i2)).copied().unwrap_or(true) =>
                {
                    released += 1;
                }
                Some(&(c2, i2, n2)) if c2 == c && i2 != inst => {
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
                    first.insert(v.to_vec(), (c, inst, n));
                }
            }
        }
    }
    let known: HashSet<&[u8]> = truth.attacker_tokens.iter().map(|t| &t[..]).collect();
    for r in &acc.issuer {
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
    (hits, released)
}

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
