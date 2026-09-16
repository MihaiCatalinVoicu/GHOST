//! A1, the amount uniformity of FR-6′.7 (Phase 8 design §19.31): an invoice's amount is exactly the
//! public pack price of its price epoch in the Entitlement Schedule, the same for every buyer, with
//! no per-invoice component. Stated over the view of the compromised issuer holding the view key:
//! every `RequestInvoice` answer, and every transfer the view-only wallet showed to an invoice's
//! subaddress. The ground truth enters only as the documented exemptions (`Truth::user_amounts`,
//! amounts a user chose, never the issuer).
//!
//! A per-invoice amount would be a value the issuer chooses per payment: RingCT hides amounts on
//! chain, so only the view key holder sees it, and a unique amount would join the issuer's invoice
//! to the payer's own wallet or exchange records. The production client refuses such an invoice
//! before paying (`issuer_flow::request_invoice`, `malformed_response`); A1 states the property on
//! the issuer's side, whatever a client did with the answer.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use ghost_entitlement::grid::price_epoch;

use crate::accumulate::{Accumulator, IssuerRecord, Transfer};
use crate::model::{IssuerOp, Truth};
use crate::values::Hit;

/// `REQUEST_INVOICE_RESULT_OK` (`issuer.proto`).
const REQUEST_INVOICE_OK: u64 = 1;

/// What A1 found: the hits and the counts the report states.
#[derive(Debug, Default)]
pub struct Amounts {
    /// `RequestInvoice` answers OK paid in XMR, and the distinct invoices they name.
    pub xmr_answers: usize,
    pub xmr_invoices: usize,
    /// Per price epoch of those answers, the distinct amounts they quoted.
    pub quoted: BTreeMap<u64, BTreeSet<u64>>,
    /// `RequestInvoice` answers OK paid with credits (which must quote 0).
    pub credit_answers: usize,
    /// Answers naming no invoice (`WRONG_PERIOD`, `CREDITS_SPENT`, `CLAIM_CONFLICT`; which must quote
    /// 0).
    pub other_answers: usize,
    /// Wallet transfers to the subaddress of an XMR invoice, and those of them exempted as documented
    /// user amounts.
    pub transfers: usize,
    pub exempt: usize,
    /// Wallet transfers to a subaddress no invoice quoted: they credit no invoice (reported).
    pub unmatched: usize,
    pub hits: Vec<Hit>,
}

impl Amounts {
    /// Price epochs whose XMR invoices all quoted one amount.
    pub fn uniform_epochs(&self) -> usize {
        self.quoted.values().filter(|a| a.len() == 1).count()
    }
}

fn hit(a: String, b: String) -> Hit {
    Hit {
        check: "A1",
        value: Vec::new(),
        a,
        b,
    }
}

fn short(bytes: &[u8]) -> String {
    hex::encode(&bytes[..bytes.len().min(4)])
}

/// A1 on a world's issuer view, with the ES of the view.
pub fn a1(acc: &Accumulator, truth: &Truth) -> Amounts {
    a1_of(
        &acc.issuer,
        &acc.addresses,
        &acc.transfers,
        &truth.user_amounts,
        |base_week| acc.schedule.pack_price(price_epoch(base_week)),
    )
}

/// [`a1`] over the issuer records, the wallet's subaddresses (address text → minor) and transfers,
/// the documented user amounts, and `price`, the ES pack price of a base week's price epoch.
pub fn a1_of(
    issuer: &[IssuerRecord],
    addresses: &HashMap<Vec<u8>, u32>,
    transfers: &BTreeMap<[u8; 32], Transfer>,
    user_amounts: &[[u8; 32]],
    price: impl Fn(u64) -> Option<u64>,
) -> Amounts {
    let mut out = Amounts::default();
    // Minor → the XMR invoices quoted to it (invoice id → base week).
    let mut by_minor: BTreeMap<u32, BTreeMap<Vec<u8>, u64>> = BTreeMap::new();
    let mut invoices: BTreeSet<Vec<u8>> = BTreeSet::new();
    for r in issuer
        .iter()
        .filter(|r| r.op == IssuerOp::RequestInvoice && r.status == 0)
    {
        let amount = r.int("amount_atomic").unwrap_or(0);
        let id = r.resp("invoice_id").unwrap_or_default();
        let at = format!("request_invoice at {} (invoice {})", r.t, short(id));
        let result = r.int("result").unwrap_or(0);
        if result != REQUEST_INVOICE_OK {
            out.other_answers += 1;
            if amount != 0 {
                out.hits.push(hit(
                    at,
                    format!("an answer of result {result} naming no invoice quotes {amount} atomic, not 0"),
                ));
            }
            continue;
        }
        if r.reqs("credits").next().is_some() {
            out.credit_answers += 1;
            if amount != 0 {
                out.hits.push(hit(
                    at,
                    format!("a credits-paid invoice quotes {amount} atomic, not 0"),
                ));
            }
            continue;
        }
        out.xmr_answers += 1;
        invoices.insert(id.to_vec());
        let Some(base) = r.int("base_week") else {
            out.hits
                .push(hit(at, "an XMR invoice without a base week".into()));
            continue;
        };
        let epoch = price_epoch(base);
        out.quoted.entry(epoch).or_default().insert(amount);
        match price(base) {
            Some(p) if p == amount => {}
            Some(p) => out.hits.push(hit(
                at.clone(),
                format!(
                    "amount {amount} atomic for base week {base} (price epoch {epoch}): not the ES pack price {p}"
                ),
            )),
            None => out.hits.push(hit(
                at.clone(),
                format!("no ES pack price for base week {base} (price epoch {epoch})"),
            )),
        }
        match r.resp("subaddress").and_then(|s| addresses.get(s)) {
            Some(&minor) => {
                by_minor.entry(minor).or_default().insert(id.to_vec(), base);
            }
            None => out.hits.push(hit(
                at,
                "the invoice's subaddress is no subaddress the wallet view created".into(),
            )),
        }
    }
    out.xmr_invoices = invoices.len();
    let exempt: HashSet<&[u8; 32]> = user_amounts.iter().collect();
    for (txid, &(seen, minor, amount, _, _)) in transfers {
        let Some(quoted) = by_minor.get(&minor) else {
            out.unmatched += 1;
            continue;
        };
        out.transfers += 1;
        if exempt.contains(txid) {
            out.exempt += 1;
            continue;
        }
        for (id, &base) in quoted {
            if price(base) != Some(amount) {
                out.hits.push(hit(
                    format!("wallet transfer {} first seen at {seen}", short(txid)),
                    format!(
                        "{amount} atomic to the subaddress of invoice {} (base week {base}): not the ES pack price {:?} of its price epoch",
                        short(id),
                        price(base)
                    ),
                ));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{FlowKind, IssuerTruth};

    const W: u64 = 2_990;
    const PRICE: u64 = 200_000_000_000;
    const LATER: u64 = 210_000_000_000;

    /// One price per price epoch: `W`'s, and a higher one 13 weeks on.
    fn price(base: u64) -> Option<u64> {
        if price_epoch(base) == price_epoch(W) {
            Some(PRICE)
        } else if price_epoch(base) == price_epoch(W + 13) {
            Some(LATER)
        } else {
            None
        }
    }

    fn answer(
        id: u8,
        result: u64,
        base: u64,
        amount: u64,
        credits: bool,
        sub: &[u8],
    ) -> IssuerRecord {
        let mut request = vec![("claim_hash", vec![id; 32])];
        if credits {
            request.push(("credits", vec![id; 354]));
        }
        let (invoice_id, subaddress) = if result == REQUEST_INVOICE_OK {
            (vec![id; 16], sub.to_vec())
        } else {
            (Vec::new(), Vec::new())
        };
        IssuerRecord {
            t: 1_000 * u64::from(id),
            t_resp: 1_000 * u64::from(id) + 2,
            label: [id; 32],
            op: IssuerOp::RequestInvoice,
            request,
            response: vec![("invoice_id", invoice_id), ("subaddress", subaddress)],
            ints: vec![
                ("base_week", base),
                ("rail", 1),
                ("product", 1),
                ("result", result),
                ("amount_atomic", amount),
                ("spent_mask", 0),
            ],
            status: 0,
            truth: IssuerTruth {
                client: u32::from(id),
                flow: u64::from(id),
                instance: u64::from(id),
                lineage: u64::from(id),
                kind: if credits {
                    FlowKind::PackCredits
                } else {
                    FlowKind::PackXmr
                },
                automatic: true,
                run: 0,
            },
        }
    }

    fn addresses() -> HashMap<Vec<u8>, u32> {
        (1..=4u32)
            .map(|m| (format!("sub-{m}").into_bytes(), m))
            .collect()
    }

    fn transfer(k: u8, minor: u32, amount: u64) -> ([u8; 32], Transfer) {
        (
            [k; 32],
            (5_000 + u64::from(k), minor, amount, Some(7), Some(5_100)),
        )
    }

    /// An honest issuer: every XMR invoice at its epoch's price, credits-paid and refused answers at
    /// 0, every transfer at the price; a transfer to an unquoted subaddress is reported only.
    #[test]
    fn uniform_amounts_pass() {
        let issuer = vec![
            answer(1, 1, W, PRICE, false, b"sub-1"),
            answer(1, 1, W, PRICE, false, b"sub-1"),
            answer(2, 1, W + 13, LATER, false, b"sub-2"),
            answer(3, 1, W, 0, true, b""),
            answer(4, 2, W, 0, false, b""),
        ];
        let transfers = BTreeMap::from([
            transfer(1, 1, PRICE),
            transfer(2, 2, LATER),
            transfer(3, 4, 12_345),
        ]);
        let a = a1_of(&issuer, &addresses(), &transfers, &[], price);
        assert!(a.hits.is_empty(), "{:?}", a.hits);
        assert_eq!(
            (
                a.xmr_answers,
                a.xmr_invoices,
                a.credit_answers,
                a.other_answers
            ),
            (3, 2, 1, 1)
        );
        assert_eq!((a.transfers, a.exempt, a.unmatched), (2, 0, 1));
        assert_eq!((a.quoted.len(), a.uniform_epochs()), (2, 2));
    }

    /// Mutant M24's issuer: the ES price plus a per-invoice delta. The quote fails A1, and so does a
    /// transfer of that amount (a client that paid it).
    #[test]
    fn a_per_invoice_amount_fails() {
        let issuer = vec![
            answer(1, 1, W, PRICE + 4_321, false, b"sub-1"),
            answer(2, 1, W, PRICE, false, b"sub-2"),
        ];
        let transfers = BTreeMap::from([transfer(1, 1, PRICE + 4_321), transfer(2, 2, PRICE)]);
        let a = a1_of(&issuer, &addresses(), &transfers, &[], price);
        assert_eq!(a.hits.len(), 2, "{:?}", a.hits);
        assert!(
            a.hits[0].b.contains("not the ES pack price"),
            "{:?}",
            a.hits
        );
        assert!(
            a.hits[1].a.starts_with("wallet transfer")
                && a.hits[1].b.contains("not the ES pack price"),
            "{:?}",
            a.hits
        );
        assert_eq!(a.uniform_epochs(), 0);
    }

    /// An answer naming no invoice, or a credits-paid invoice, quoting an amount fails.
    #[test]
    fn an_amount_on_a_credits_paid_or_refused_answer_fails() {
        let issuer = vec![
            answer(1, 1, W, 10, true, b""),
            answer(2, 4, W, PRICE, false, b""),
        ];
        let a = a1_of(&issuer, &addresses(), &BTreeMap::new(), &[], price);
        assert_eq!(a.hits.len(), 2, "{:?}", a.hits);
        assert!(a.hits[0].b.contains("credits-paid invoice quotes 10"));
        assert!(a.hits[1].b.contains("naming no invoice"));
    }

    /// An XMR invoice of an epoch without an ES price, or on a subaddress the wallet view never
    /// created (the view would be incomplete), fails.
    #[test]
    fn an_unpriced_or_unknown_subaddress_invoice_fails() {
        let issuer = vec![
            answer(1, 1, W + 26, PRICE, false, b"sub-1"),
            answer(2, 1, W, PRICE, false, b"sub-9"),
        ];
        let a = a1_of(&issuer, &addresses(), &BTreeMap::new(), &[], price);
        assert_eq!(a.hits.len(), 2, "{:?}", a.hits);
        assert!(a.hits[0].b.contains("no ES pack price"));
        assert!(a.hits[1]
            .b
            .contains("no subaddress the wallet view created"));
    }

    /// A user's underpayment and its top-up are exempt only when documented, and counted.
    #[test]
    fn documented_user_amounts_are_exempt_and_counted() {
        let issuer = vec![answer(1, 1, W, PRICE, false, b"sub-1")];
        let transfers = BTreeMap::from([transfer(1, 1, PRICE / 4), transfer(2, 1, PRICE / 4 * 3)]);
        let a = a1_of(
            &issuer,
            &addresses(),
            &transfers,
            &[[1; 32], [2; 32]],
            price,
        );
        assert!(a.hits.is_empty(), "{:?}", a.hits);
        assert_eq!((a.transfers, a.exempt), (2, 2));
        let a = a1_of(&issuer, &addresses(), &transfers, &[[1; 32]], price);
        assert_eq!((a.hits.len(), a.exempt), (1, 1), "{:?}", a.hits);
    }
}
