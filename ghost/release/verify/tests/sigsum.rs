//! The Sigsum log client's parsers: the key/value leaf lists (both field-name spellings) and
//! the C2SP cosigned tree head. The live probe (`examples/live.rs`) needs a network the CI
//! runner does not have; these fixtures pin the shapes. A live run against
//! `https://log.sigsum.org` is the documented manual check (V-D style).

use ghost_verify::sigsum::{parse_head_body, parse_kv, parse_leaves_body, RawCosignedHead, RawLeaf};

fn hex32(b: u8) -> String {
    hex::encode([b; 32])
}

fn hex64(b: u8) -> String {
    hex::encode([b; 64])
}

#[test]
fn parses_v1_leaf_lists() {
    let body = format!(
        "leaf_checksum={}\nleaf_signature={}\nleaf_identity={}\nleaf_checksum={}\nleaf_signature={}\nleaf_identity={}\n",
        hex32(1),
        hex64(2),
        hex32(3),
        hex32(4),
        hex64(5),
        hex32(6),
    );
    let kv = parse_kv(&body);
    assert_eq!(kv.len(), 6);
    let leaves = sample_leaves(&body);
    assert_eq!(leaves.len(), 2);
    assert_eq!(leaves[0].checksum, [1; 32]);
    assert_eq!(leaves[0].signature, [2; 64]);
    assert_eq!(leaves[0].key_hash, [3; 32]);
    assert_eq!(leaves[1].checksum, [4; 32]);
}

#[test]
fn parses_v0_spelling_too() {
    let body = format!(
        "shard_hint=0\nchecksum={}\nsignature={}\nkey_hash={}\n",
        hex32(7),
        hex64(8),
        hex32(9),
    );
    let leaves = sample_leaves(&body);
    assert_eq!(leaves.len(), 1);
    assert_eq!(leaves[0].key_hash, [9; 32]);
}

#[test]
fn refuses_mismatched_lists_and_bad_hex() {
    // The shard_hint of the v0 spelling is per-leaf state, not per-leaf data here; a length
    // mismatch must be refused.
    let body = format!("checksum={}\nsignature={}\nkey_hash={}\nchecksum={}\n", hex32(1), hex64(2), hex32(3), hex32(4));
    assert!(sample_leaves_err(&body).contains("differ in length"));

    let body = format!("checksum=zz\nsignature={}\nkey_hash={}\n", hex64(2), hex32(3));
    assert!(sample_leaves_err(&body).contains("bad hex"));
}

fn sample_leaves(body: &str) -> Vec<RawLeaf> {
    parse_leaves_body(body).unwrap()
}

fn sample_leaves_err(body: &str) -> String {
    parse_leaves_body(body).unwrap_err()
}

#[test]
fn parses_a_c2sp_cosigned_tree_head() {
    // The checkpoint framing, exactly what GHRP::checkpoint_body builds, with one cosignature.
    let root = hex32(0xAA);
    let sig = base64_of(&[7u8; 64]);
    let body = format!(
        "sigsum.org/v1/tree/{}\n3\n{}\n\n\u{2014} {} {}\n",
        hex32(0xBB),
        root,
        hex32(0xCC),
        sig,
    );
    let head = parse_head_for_test(&body).unwrap();
    assert_eq!(head.tree_size, 3);
    assert_eq!(head.root_hash, [0xAA; 32]);
    assert_eq!(head.cosignatures.len(), 1);
    assert_eq!(head.cosignatures[0].0, [0xCC; 32]);
    assert_eq!(head.cosignatures[0].1, vec![7u8; 64]);
}

fn parse_head_for_test(body: &str) -> Result<RawCosignedHead, String> {
    parse_head_body(body)
}

fn base64_of(data: &[u8]) -> String {
    const ALPH: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(ALPH[(n >> 18) as usize & 63] as char);
        out.push(ALPH[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { ALPH[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { ALPH[n as usize & 63] as char } else { '=' });
    }
    out
}


