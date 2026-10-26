//! The Sigsum log client of `ghost-verify` (Phase 14 design §5.3's network half): v1 GET
//! endpoints over HTTPS, the responses in the log's ASCII key/value format. Field names are
//! accepted in both spellings a v1 log answers with (`leaf_checksum`/`leaf_signature`/
//! `leaf_identity`, the names sigsum-go v1 writes) and the v0 spelling (`checksum`/`signature`/
//! `key_hash`) — the parser is lenient on names, strict on shape: every leaf must carry all
//! three fields, the lists must be the same length, and hex must decode.

/// One raw leaf of a policy log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawLeaf {
    pub checksum: [u8; 32],
    pub signature: [u8; 64],
    pub key_hash: [u8; 32],
}

fn hex32(s: &str) -> Result<[u8; 32], String> {
    let b = hex::decode(s.trim()).map_err(|e| format!("bad hex: {e}"))?;
    b.try_into().map_err(|_| "not 32 bytes".to_string())
}

fn hex64(s: &str) -> Result<[u8; 64], String> {
    let b = hex::decode(s.trim()).map_err(|e| format!("bad hex: {e}"))?;
    b.try_into().map_err(|_| "not 64 bytes".to_string())
}

/// Parses the log's ASCII key/value body: `Key=Value\n`, repeated keys keep order.
pub fn parse_kv(body: &str) -> Vec<(String, String)> {
    body.lines()
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect()
}

/// GET `<log url>/get-leaves/<start>/<end>`; the leaves `start..=end` (the log may answer
/// fewer). `log url` is the base the policy file names, e.g. `https://log.example/sigsum/v1`.
pub fn get_leaves(log_url: &str, start: u64, end: u64) -> Result<Vec<RawLeaf>, String> {
    if end < start {
        return Err("end before start".into());
    }
    let url = format!("{}/get-leaves/{start}/{end}", log_url.trim_end_matches('/'));
    let body = ureq::get(&url)
        .call()
        .map_err(|e| format!("get-leaves failed: {e}"))?
        .body_mut()
        .read_to_string()
        .map_err(|e| format!("reading the answer: {e}"))?;
    parse_leaves_body(&body)
}

/// The get-leaves answer's shape: the field lists must be the same length, every leaf carries
/// all three fields, and the hex must decode. Called by [get_leaves]; tested over fixtures.
pub fn parse_leaves_body(body: &str) -> Result<Vec<RawLeaf>, String> {
    let kv = parse_kv(body);
    let get = |names: [&str; 2]| -> Result<Vec<&str>, String> {
        let values: Vec<&str> = kv
            .iter()
            .filter(|(k, _)| names.contains(&k.as_str()))
            .map(|(_, v)| v.as_str())
            .collect();
        Ok(values)
    };
    let checksums = get(["leaf_checksum", "checksum"])?;
    let signatures = get(["leaf_signature", "signature"])?;
    let key_hashes = get(["leaf_identity", "key_hash"])?;
    if checksums.is_empty() {
        return Err(format!("get-leaves answered no leaves: {body}"));
    }
    if checksums.len() != signatures.len() || checksums.len() != key_hashes.len() {
        return Err("get-leaves lists differ in length".into());
    }
    let mut out = Vec::with_capacity(checksums.len());
    for i in 0..checksums.len() {
        out.push(RawLeaf {
            checksum: hex32(checksums[i])?,
            signature: hex64(signatures[i])?,
            key_hash: hex32(key_hashes[i])?,
        });
    }
    Ok(out)
}

/// GET `<log url>/get-tree-head-cosigned`: the answer is a C2SP checkpoint (the same framing
/// `GHRP::checkpoint_body` builds, with `— <witness key hash> <base64 signature>` lines).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawCosignedHead {
    pub tree_size: u64,
    pub root_hash: [u8; 32],
    /// `(witness key hash, signature)` pairs; base64-decoded signatures.
    pub cosignatures: Vec<([u8; 32], Vec<u8>)>,
}

pub fn get_tree_head_cosigned(log_url: &str) -> Result<RawCosignedHead, String> {
    let url = format!("{}/get-tree-head-cosigned", log_url.trim_end_matches('/'));
    let body = ureq::get(&url)
        .call()
        .map_err(|e| format!("get-tree-head-cosigned failed: {e}"))?
        .body_mut()
        .read_to_string()
        .map_err(|e| format!("reading the answer: {e}"))?;
    parse_head_body(&body)
}

/// The cosigned tree head answer's shape: a C2SP checkpoint (the framing
/// `GHRP::checkpoint_body` builds) with `— <witness key hash> <base64 signature>` lines.
pub fn parse_head_body(body: &str) -> Result<RawCosignedHead, String> {
    let lines: Vec<&str> = body.lines().collect();
    if lines.len() < 4 {
        return Err("cosigned tree head is too short".into());
    }
    let size: u64 = lines[1].parse().map_err(|_| "tree size does not parse")?;
    let root_hash = hex32(lines[2])?;
    // After the blank line, C2SP note signatures: "\u{2014} <name> <base64>".
    let mut cosignatures = Vec::new();
    for line in &lines[4..] {
        let line = line.trim_start_matches('\u{2014}').trim();
        let (name, sig) = line
            .split_once(' ')
            .ok_or("cosignature line does not parse")?;
        cosignatures.push((hex32(name)?, base64_decode(sig)?));
    }
    Ok(RawCosignedHead { tree_size: size, root_hash, cosignatures })
}

fn base64_decode(s: &str) -> Result<Vec<u8>, String> {
    // A minimal base64 (RFC 4648, with padding); the checkpoint signatures are short.
    fn val(c: u8) -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some(u32::from(c - b'A')),
            b'a'..=b'z' => Some(u32::from(c - b'a') + 26),
            b'0'..=b'9' => Some(u32::from(c - b'0') + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let bytes: Vec<u8> = s.bytes().filter(|&b| b != b'=' && b != b'\n' && b != b'\r').collect();
    if bytes.len() % 4 == 1 {
        return Err("bad base64 length".into());
    }
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    for chunk in bytes.chunks(4) {
        let mut acc = 0u32;
        for (i, &c) in chunk.iter().enumerate() {
            let v = val(c).ok_or("bad base64 character")?;
            acc |= v << (18 - 6 * i);
        }
        out.push((acc >> 16) as u8);
        if chunk.len() > 2 {
            out.push((acc >> 8) as u8);
        }
        if chunk.len() > 3 {
            out.push(acc as u8);
        }
    }
    Ok(out)
}
