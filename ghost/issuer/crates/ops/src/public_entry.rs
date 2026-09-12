//! Public key entries written by `keygen` and read by `schedule-sign`: one file per key, named
//! `<kind>-<epoch>.pub`, holding one line
//!
//! ```text
//! ghost-es-key-v1 <kind> <epoch> <SPKI DER hex> <permutation proof hex, 8 x 256 bytes>
//! ```
//! i.e. exactly the key entry of the Entitlement Schedule (design §3.1). The entry is only parsed
//! here; `schedule-sign` verifies the key and its proof with the whole schedule.

use ghost_blind_rsa::{PROOF_BLOCK_LEN, PROOF_ROUNDS};
use ghost_entitlement::schedule::KeyContent;
use ghost_entitlement::Kind;
use ghost_issuer::custody::kind_name;

use crate::args::{parse_kind, parse_u64};
use crate::hexfmt;

pub const TAG: &str = "ghost-es-key-v1";

pub fn file_name(kind: Kind, epoch: u64) -> String {
    format!("{}-{epoch}.pub", kind_name(kind))
}

pub fn encode(entry: &KeyContent) -> String {
    format!(
        "{TAG} {} {} {} {}\n",
        kind_name(entry.kind),
        entry.epoch,
        hexfmt::encode(&entry.spki),
        hexfmt::encode(&entry.proof.concat())
    )
}

/// Parses one entry; the error is the reason word for the report.
pub fn parse(text: &str) -> Result<KeyContent, &'static str> {
    let line = text.strip_suffix('\n').unwrap_or(text);
    let line = line.strip_suffix('\r').unwrap_or(line);
    let tokens: Vec<&str> = line.split(' ').collect();
    let [tag, kind, epoch, spki, proof] = tokens.as_slice() else {
        return Err("format");
    };
    if *tag != TAG {
        return Err("format");
    }
    let kind = parse_kind(kind).ok_or("kind")?;
    let epoch = parse_u64(epoch).ok_or("epoch")?;
    let spki = hexfmt::decode(spki)
        .filter(|s| !s.is_empty())
        .ok_or("spki")?;
    let proof_bytes = hexfmt::decode(proof).ok_or("proof")?;
    if proof_bytes.len() != PROOF_ROUNDS * PROOF_BLOCK_LEN {
        return Err("proof");
    }
    let mut blocks = [[0u8; PROOF_BLOCK_LEN]; PROOF_ROUNDS];
    for (block, chunk) in blocks
        .iter_mut()
        .zip(proof_bytes.as_chunks::<PROOF_BLOCK_LEN>().0)
    {
        *block = *chunk;
    }
    Ok(KeyContent {
        kind,
        epoch,
        spki,
        proof: blocks,
    })
}
