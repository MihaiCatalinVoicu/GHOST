//! J3 (Phase 8 design §13.4): transform images found in every value of the other side, whatever
//! its length, and the counter suffixes of the GHOST labels.

use ghost_t2_join::transforms::j3;
use ghost_t2_join::values::{relay_bit, Public, Values, ISSUER};
use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use sha2::Sha256;

fn hmac(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut m = <Hmac<Sha256> as KeyInit>::new_from_slice(key).unwrap();
    for p in parts {
        m.update(p);
    }
    m.finalize().into_bytes().into()
}

fn issuer_value(values: &mut Values) -> Vec<u8> {
    let v: Vec<u8> = (0..16u32).map(|i| (i * 37 + 11) as u8).collect();
    let f = values.fields.id("issuer.request_invoice.resp.invoice_id");
    values.add(ISSUER, f, &v, false);
    v
}

/// A derivation of an issuer value placed inside a 1 KiB relay blob (a header or a ciphertext
/// prefix) is found.
#[test]
fn an_image_inside_a_long_relay_value_is_found() {
    let mut values = Values::default();
    let v = issuer_value(&mut values);
    let mut blob: Vec<u8> = (0..1024u32).map(|i| ((i * 7 + 3) as u8) ^ 0xa5).collect();
    blob[100..132].copy_from_slice(&hmac(b"ghost/v1/cap-serial", &[&v]));
    let f = values.fields.id("relay.store.req.data");
    values.add(relay_bit(0), f, &blob, true);
    let hits = j3(&values, &Public::new(Vec::new()));
    assert!(
        hits.iter().any(|h| h.a.contains("hmac(label, v)")),
        "{hits:?}"
    );
}

/// HKDF(ikm = v, info = label ‖ u8(position)), a counter suffix of a GHOST label, is found.
#[test]
fn a_label_counter_derivation_is_found() {
    let mut values = Values::default();
    let v = issuer_value(&mut values);
    let prk = hmac(&[], &[&v]);
    let image = hmac(&prk, &[b"ghost/v1/blind-batch", &[5], &[1]]);
    let f = values.fields.id("relay.redeem.req.token.nonce");
    values.add(relay_bit(1), f, &image, false);
    let hits = j3(&values, &Public::new(Vec::new()));
    assert!(
        hits.iter().any(|h| h.a.contains("hkdf(info=label||u8)")),
        "{hits:?}"
    );
}
