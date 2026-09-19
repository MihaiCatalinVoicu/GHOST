//! L0 content `DmContent` v1 and the Phase 9 TLV registry (design §7.1).
//!
//! Canonical binary, big-endian, fixed order, one encoding per value:
//!
//! ```text
//! version(1) = 0x01 || kind(1) || message_id(16) || author_minute(4) || minute_index(2)
//!   || timer_code(1) || timer_version(4) || flags(1) || quote_ref(0 or 16)
//!   || body_len(4) || body || ext_len(2) || ext
//! ext = TLVs  type(u16) || len(u16) || value,  strictly ascending type, each at most once
//! ```
//!
//! R-C1 (T13): author time exists only as `author_minute`, a u32 count of minutes, so seconds are
//! zero by type. R-C2: no field names the sender or the recipient. R-C4: an over-read, a trailing
//! byte, a non-ascending TLV list, an unknown critical TLV, invalid UTF-8 or a non-zero reserved
//! bit refuses the whole L0.

use crate::result::{DmCode, DmResult};
use crate::seal::{capacity, L0_FIXED_BYTES, MAX_BODY_BYTES, O_MAX};

/// The only content version Phase 9 writes or accepts.
pub const CONTENT_VERSION: u8 = 0x01;
/// The largest L0 a 64 KiB bucket can carry (R-C4).
pub const MAX_L0_BYTES: usize = 65536 - O_MAX;
/// The TLV list cap, raised from 1 024 for the PQ-C TLVs (§9.4).
pub const MAX_EXT_BYTES: usize = 2560;
/// `type(u16) || len(u16)`.
pub const TLV_HEADER_BYTES: usize = 4;
/// Bit 15 of a TLV type marks it critical: an unknown critical TLV refuses the whole L0.
pub const TLV_CRITICAL_BIT: u16 = 0x8000;

/// Content kind (§7.1). There is no DELIVERY and no RECEIPT kind (D10).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    /// UTF-8 text.
    Text = 0x01,
    /// A conversation timer change; no body.
    TimerSet = 0x02,
    /// A reaction: the target `message_id` and one grapheme, or nothing to remove it.
    Reaction = 0x03,
    /// A control message: no body, TLVs only.
    Control = 0x04,
}

impl Kind {
    /// The kind byte.
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// The kind of a byte. `0x05` (MEDIA) is reserved for Phase 11 and refused in Phase 9.
    pub const fn from_u8(byte: u8) -> Option<Self> {
        Some(match byte {
            0x01 => Kind::Text,
            0x02 => Kind::TimerSet,
            0x03 => Kind::Reaction,
            0x04 => Kind::Control,
            _ => return None,
        })
    }
}

/// The largest timer code (§7.1: 0 off, 1 = 5 min, 2 = 1 h, 3 = 1 d, 4 = 7 d, 5 = 30 d).
pub const MAX_TIMER_CODE: u8 = 5;
/// `flags` bit 0: a quote reference follows.
pub const FLAG_HAS_QUOTE: u8 = 0x01;
/// The largest reaction body: the target `message_id` and one grapheme.
pub const MAX_REACTION_BODY_BYTES: usize = 16 + 32;

/// TLV type: the pair root for recipient-to-sender envelopes (§6.3).
pub const TLV_SEAL_ROOT: u16 = 0x0001;
/// TLV type: reserved for the Phase 13 cut-off rotation; ignored in Phase 9.
pub const TLV_CARD_UPDATE: u16 = 0x0002;
/// TLV type: a revocation certificate v2 (§8.5).
pub const TLV_REVOCATION: u16 = 0x0003;
/// TLV type: the reconnect notice (§8.6); a contact event, no message row.
pub const TLV_SESSION_RESET: u16 = 0x0004;
/// TLV type: the PQ-C form of `seal_root` (§9.4).
pub const TLV_SEAL_ROOT_PQ: u16 = 0x0005;
/// TLV type: my current generation's X-Wing public key (§9.4).
pub const TLV_PQ_KEY: u16 = 0x0006;
/// TLV type: reserved for Phase 13 opt-in read receipts; ignored in Phase 9.
pub const TLV_READ_UPTO: u16 = 0x0010;
/// First media-descriptor TLV type (Phase 11); the range is ignored in Phase 9.
pub const TLV_MEDIA_FIRST: u16 = 0x0100;
/// Last media-descriptor TLV type (Phase 11).
pub const TLV_MEDIA_LAST: u16 = 0x01ff;

/// Length of a `seal_root` value: `root(32) || base_week(8) || root_gen(2)`.
pub const SEAL_ROOT_BYTES: usize = 42;
/// Length of a revocation certificate v2.
pub const REVOCATION_BYTES: usize = 102;
/// Length of a `seal_root_pq` value:
/// `root_rand(32) || base_week(8) || root_gen(2) || peer_gen_id(4) || xwing_ct(1120)`.
pub const SEAL_ROOT_PQ_BYTES: usize = 1166;
/// Length of a `pq_key` value: `gen_id(4) || bundle_week(8) || xwing_pk(1216)`.
pub const PQ_KEY_BYTES: usize = 1228;
/// `seal_root_pq` with its TLV header, the figure the slack rule compares (§7.1 R-C5).
pub const SEAL_ROOT_PQ_TLV_BYTES: usize = TLV_HEADER_BYTES + SEAL_ROOT_PQ_BYTES;
/// `pq_key` with its TLV header.
pub const PQ_KEY_TLV_BYTES: usize = TLV_HEADER_BYTES + PQ_KEY_BYTES;

/// One extension record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tlv {
    /// The registry type; bit 15 marks it critical.
    pub tlv_type: u16,
    /// The value, whose length the registry fixes for the types Phase 9 defines.
    pub value: Vec<u8>,
}

impl Tlv {
    /// True when an implementation that does not know this type must refuse the whole L0.
    pub const fn is_critical(&self) -> bool {
        self.tlv_type & TLV_CRITICAL_BIT != 0
    }
}

/// The length the registry fixes for a type, or `None` when Phase 9 ignores its contents.
const fn registry_length(tlv_type: u16) -> Option<usize> {
    Some(match tlv_type {
        TLV_SEAL_ROOT => SEAL_ROOT_BYTES,
        TLV_REVOCATION => REVOCATION_BYTES,
        TLV_SESSION_RESET => 0,
        TLV_SEAL_ROOT_PQ => SEAL_ROOT_PQ_BYTES,
        TLV_PQ_KEY => PQ_KEY_BYTES,
        _ => return None,
    })
}

/// True when Phase 9 knows this type, whether or not it acts on it.
const fn is_known(tlv_type: u16) -> bool {
    matches!(
        tlv_type,
        TLV_SEAL_ROOT
            | TLV_CARD_UPDATE
            | TLV_REVOCATION
            | TLV_SESSION_RESET
            | TLV_SEAL_ROOT_PQ
            | TLV_PQ_KEY
            | TLV_READ_UPTO
    ) || (tlv_type >= TLV_MEDIA_FIRST && tlv_type <= TLV_MEDIA_LAST)
}

/// An L0 content record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DmContent {
    /// What this message is.
    pub kind: Kind,
    /// The end-to-end idempotency key; never relay-visible.
    pub message_id: [u8; 16],
    /// Minutes since the Unix epoch at compose, before any HIGH send delay (R-C1).
    pub author_minute: u32,
    /// Order of the sender's own messages within `author_minute` (§7.7).
    pub minute_index: u16,
    /// This message's own timer.
    pub timer_code: u8,
    /// The sender's conversation timer version (§10.5).
    pub timer_version: u32,
    /// The quoted message's id; never copied text.
    pub quote_ref: Option<[u8; 16]>,
    /// The body, whose rules depend on the kind.
    pub body: Vec<u8>,
    /// The extension list, strictly ascending by type.
    pub ext: Vec<Tlv>,
}

fn encoded_ext_len(ext: &[Tlv]) -> usize {
    ext.iter()
        .map(|tlv| TLV_HEADER_BYTES + tlv.value.len())
        .sum()
}

fn check_body(kind: Kind, body: &[u8]) -> DmResult<()> {
    match kind {
        Kind::Text => {
            if body.len() > MAX_BODY_BYTES || core::str::from_utf8(body).is_err() {
                return Err(DmCode::NonCanonical);
            }
        }
        Kind::TimerSet | Kind::Control => {
            if !body.is_empty() {
                return Err(DmCode::NonCanonical);
            }
        }
        Kind::Reaction => {
            // The target `message_id` and one grapheme; an empty grapheme removes the reaction.
            // The byte bound is checked here; the crate takes no Unicode segmentation dependency,
            // so counting grapheme clusters stays with the caller that renders them.
            if body.len() < 16 || body.len() > MAX_REACTION_BODY_BYTES {
                return Err(DmCode::NonCanonical);
            }
            if core::str::from_utf8(&body[16..]).is_err() {
                return Err(DmCode::NonCanonical);
            }
        }
    }
    Ok(())
}

fn check_ext(ext: &[Tlv]) -> DmResult<()> {
    let mut previous: Option<u16> = None;
    for tlv in ext {
        // Strictly ascending also makes "each at most once" structural.
        if let Some(last) = previous {
            if tlv.tlv_type <= last {
                return Err(DmCode::NonCanonical);
            }
        }
        previous = Some(tlv.tlv_type);
        if tlv.value.len() > u16::MAX as usize {
            return Err(DmCode::NonCanonical);
        }
        if let Some(length) = registry_length(tlv.tlv_type) {
            if tlv.value.len() != length {
                return Err(DmCode::NonCanonical);
            }
        }
        if tlv.is_critical() && !is_known(tlv.tlv_type) {
            return Err(DmCode::NonCanonical);
        }
    }
    if encoded_ext_len(ext) > MAX_EXT_BYTES {
        return Err(DmCode::NonCanonical);
    }
    Ok(())
}

impl DmContent {
    /// The canonical bytes of this content. A record that breaks a rule of §7.1 is
    /// [`DmCode::NonCanonical`] rather than an encoding no decoder would accept.
    pub fn encode(&self) -> DmResult<Vec<u8>> {
        if self.timer_code > MAX_TIMER_CODE {
            return Err(DmCode::NonCanonical);
        }
        check_body(self.kind, &self.body)?;
        check_ext(&self.ext)?;
        let ext_len = encoded_ext_len(&self.ext);
        let mut out = Vec::with_capacity(L0_FIXED_BYTES + self.body.len() + ext_len);
        out.push(CONTENT_VERSION);
        out.push(self.kind.as_u8());
        out.extend_from_slice(&self.message_id);
        out.extend_from_slice(&self.author_minute.to_be_bytes());
        out.extend_from_slice(&self.minute_index.to_be_bytes());
        out.push(self.timer_code);
        out.extend_from_slice(&self.timer_version.to_be_bytes());
        out.push(if self.quote_ref.is_some() {
            FLAG_HAS_QUOTE
        } else {
            0
        });
        if let Some(quote) = &self.quote_ref {
            out.extend_from_slice(quote);
        }
        out.extend_from_slice(&(self.body.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.body);
        out.extend_from_slice(&(ext_len as u16).to_be_bytes());
        for tlv in &self.ext {
            out.extend_from_slice(&tlv.tlv_type.to_be_bytes());
            out.extend_from_slice(&(tlv.value.len() as u16).to_be_bytes());
            out.extend_from_slice(&tlv.value);
        }
        if out.len() > MAX_L0_BYTES {
            return Err(DmCode::Oversize);
        }
        Ok(out)
    }

    /// The bucket this content needs (R-B1): a function of the body length alone.
    pub fn bucket(&self) -> DmResult<usize> {
        crate::seal::bucket_for_body(self.body.len())
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> DmResult<&'a [u8]> {
        let end = self.at.checked_add(n).ok_or(DmCode::NonCanonical)?;
        if end > self.bytes.len() {
            return Err(DmCode::NonCanonical);
        }
        let out = &self.bytes[self.at..end];
        self.at = end;
        Ok(out)
    }

    fn u8(&mut self) -> DmResult<u8> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> DmResult<u16> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn u32(&mut self) -> DmResult<u32> {
        let bytes = self.take(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }
}

/// Decodes an L0, fail closed. Every refusal is [`DmCode::NonCanonical`] except a record longer
/// than a 64 KiB bucket can carry, which is [`DmCode::Oversize`].
pub fn decode(bytes: &[u8]) -> DmResult<DmContent> {
    if bytes.len() > MAX_L0_BYTES {
        return Err(DmCode::Oversize);
    }
    let mut reader = Reader { bytes, at: 0 };
    if reader.u8()? != CONTENT_VERSION {
        return Err(DmCode::NonCanonical);
    }
    let kind = Kind::from_u8(reader.u8()?).ok_or(DmCode::NonCanonical)?;
    let mut message_id = [0u8; 16];
    message_id.copy_from_slice(reader.take(16)?);
    let author_minute = reader.u32()?;
    let minute_index = reader.u16()?;
    let timer_code = reader.u8()?;
    if timer_code > MAX_TIMER_CODE {
        return Err(DmCode::NonCanonical);
    }
    let timer_version = reader.u32()?;
    let flags = reader.u8()?;
    if flags & !FLAG_HAS_QUOTE != 0 {
        return Err(DmCode::NonCanonical);
    }
    let quote_ref = if flags & FLAG_HAS_QUOTE != 0 {
        let mut quote = [0u8; 16];
        quote.copy_from_slice(reader.take(16)?);
        Some(quote)
    } else {
        None
    };
    let body_len = reader.u32()? as usize;
    let body = reader.take(body_len)?.to_vec();
    check_body(kind, &body)?;
    let ext_len = reader.u16()? as usize;
    if ext_len > MAX_EXT_BYTES {
        return Err(DmCode::NonCanonical);
    }
    let ext_bytes = reader.take(ext_len)?;
    if reader.at != bytes.len() {
        // A trailing byte refuses the whole L0.
        return Err(DmCode::NonCanonical);
    }
    let mut ext = Vec::new();
    let mut inner = Reader {
        bytes: ext_bytes,
        at: 0,
    };
    while inner.at < ext_bytes.len() {
        let tlv_type = inner.u16()?;
        let len = inner.u16()? as usize;
        let value = inner.take(len)?.to_vec();
        ext.push(Tlv { tlv_type, value });
    }
    check_ext(&ext)?;
    Ok(DmContent {
        kind,
        message_id,
        author_minute,
        minute_index,
        timer_code,
        timer_version,
        quote_ref,
        body,
        ext,
    })
}

/// R-C5, the slack rule for the PQ-C TLVs (§7.1, §9.4): a PQ TLV rides only if it fits in what is
/// left of the bucket the **body length alone** already chose, so the bucket never depends on a PQ
/// TLV (mutant ME-23) and nothing is ever sent for a TLV alone (T28).
pub fn pq_tlv_fits(
    bucket: usize,
    body_len: usize,
    classical_ext_len: usize,
    pq_tlv_bytes: usize,
) -> bool {
    let used = L0_FIXED_BYTES + body_len + classical_ext_len;
    capacity(bucket)
        .checked_sub(used)
        .is_some_and(|slack| slack >= pq_tlv_bytes)
}

/// `seal_root`: the root the sender wants the recipient to use for recipient-to-sender envelopes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealRoot {
    /// The 32-byte root, or `root_rand` in the PQ-C form.
    pub root: [u8; 32],
    /// The ISO week the root's first week key belongs to.
    pub base_week: u64,
    /// The generation number, which only increases per contact.
    pub root_gen: u16,
}

impl SealRoot {
    /// The 42-byte TLV value.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(SEAL_ROOT_BYTES);
        out.extend_from_slice(&self.root);
        out.extend_from_slice(&self.base_week.to_be_bytes());
        out.extend_from_slice(&self.root_gen.to_be_bytes());
        out
    }

    /// Parses a 42-byte TLV value.
    pub fn decode(value: &[u8]) -> DmResult<Self> {
        if value.len() != SEAL_ROOT_BYTES {
            return Err(DmCode::NonCanonical);
        }
        let mut root = [0u8; 32];
        root.copy_from_slice(&value[..32]);
        let mut week = [0u8; 8];
        week.copy_from_slice(&value[32..40]);
        Ok(SealRoot {
            root,
            base_week: u64::from_be_bytes(week),
            root_gen: u16::from_be_bytes([value[40], value[41]]),
        })
    }
}

/// `seal_root_pq`: the PQ-C form, which adds the generation it was encapsulated to and the
/// ciphertext (§9.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealRootPq {
    /// The classical half of the root material.
    pub root_rand: [u8; 32],
    /// The ISO week the root's first week key belongs to.
    pub base_week: u64,
    /// The generation number.
    pub root_gen: u16,
    /// The recipient's generation this root was encapsulated to.
    pub peer_gen_id: u32,
    /// The X-Wing ciphertext.
    pub xwing_ct: Vec<u8>,
}

impl SealRootPq {
    /// The 1 166-byte TLV value.
    pub fn encode(&self) -> DmResult<Vec<u8>> {
        if self.xwing_ct.len() != crate::pq::CIPHERTEXT_BYTES {
            return Err(DmCode::NonCanonical);
        }
        let mut out = Vec::with_capacity(SEAL_ROOT_PQ_BYTES);
        out.extend_from_slice(&self.root_rand);
        out.extend_from_slice(&self.base_week.to_be_bytes());
        out.extend_from_slice(&self.root_gen.to_be_bytes());
        out.extend_from_slice(&self.peer_gen_id.to_be_bytes());
        out.extend_from_slice(&self.xwing_ct);
        Ok(out)
    }

    /// Parses a 1 166-byte TLV value.
    pub fn decode(value: &[u8]) -> DmResult<Self> {
        if value.len() != SEAL_ROOT_PQ_BYTES {
            return Err(DmCode::NonCanonical);
        }
        let mut root_rand = [0u8; 32];
        root_rand.copy_from_slice(&value[..32]);
        let mut week = [0u8; 8];
        week.copy_from_slice(&value[32..40]);
        Ok(SealRootPq {
            root_rand,
            base_week: u64::from_be_bytes(week),
            root_gen: u16::from_be_bytes([value[40], value[41]]),
            peer_gen_id: u32::from_be_bytes([value[42], value[43], value[44], value[45]]),
            xwing_ct: value[46..].to_vec(),
        })
    }
}

/// `pq_key`: my current generation's X-Wing public key, announced in band (§9.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PqKey {
    /// The generation the key belongs to.
    pub gen_id: u32,
    /// The bundle week, which decides how long the key stays usable.
    pub bundle_week: u64,
    /// The 1 216-byte X-Wing encapsulation key.
    pub xwing_pk: Vec<u8>,
}

impl PqKey {
    /// The 1 228-byte TLV value.
    pub fn encode(&self) -> DmResult<Vec<u8>> {
        if self.xwing_pk.len() != crate::pq::PUBLIC_KEY_BYTES {
            return Err(DmCode::NonCanonical);
        }
        let mut out = Vec::with_capacity(PQ_KEY_BYTES);
        out.extend_from_slice(&self.gen_id.to_be_bytes());
        out.extend_from_slice(&self.bundle_week.to_be_bytes());
        out.extend_from_slice(&self.xwing_pk);
        Ok(out)
    }

    /// Parses a 1 228-byte TLV value.
    ///
    /// The key is validated whole here, at the one place a peer's in-band key is parsed
    /// (§22.8.2 rule 3, RECV R11): an ML-KEM half that fails FIPS 203 validation or a low-order
    /// X25519 half is [`DmCode::InvalidKey`], the announcement is ignored and counted, and no
    /// later call can fail on it inside a time-triggered transaction.
    pub fn decode(value: &[u8]) -> DmResult<Self> {
        if value.len() != PQ_KEY_BYTES {
            return Err(DmCode::NonCanonical);
        }
        crate::pq::validate_public_key(&value[12..])?;
        let mut week = [0u8; 8];
        week.copy_from_slice(&value[4..12]);
        Ok(PqKey {
            gen_id: u32::from_be_bytes([value[0], value[1], value[2], value[3]]),
            bundle_week: u64::from_be_bytes(week),
            xwing_pk: value[12..].to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text() -> DmContent {
        DmContent {
            kind: Kind::Text,
            message_id: [7u8; 16],
            author_minute: 29_000_000,
            minute_index: 3,
            timer_code: 4,
            timer_version: 9,
            quote_ref: None,
            body: "salut".as_bytes().to_vec(),
            ext: Vec::new(),
        }
    }

    #[test]
    fn the_fixed_part_with_a_quote_is_fifty_two_bytes() {
        let mut content = text();
        content.body.clear();
        content.quote_ref = Some([1u8; 16]);
        assert_eq!(content.encode().expect("encode").len(), L0_FIXED_BYTES);
    }

    #[test]
    fn round_trip_with_and_without_a_quote_and_with_tlvs() {
        for quote in [None, Some([2u8; 16])] {
            let mut content = text();
            content.quote_ref = quote;
            content.ext = vec![
                Tlv {
                    tlv_type: TLV_SEAL_ROOT,
                    value: vec![1u8; SEAL_ROOT_BYTES],
                },
                Tlv {
                    tlv_type: TLV_SESSION_RESET,
                    value: Vec::new(),
                },
            ];
            let bytes = content.encode().expect("encode");
            assert_eq!(decode(&bytes).expect("decode"), content);
        }
    }

    #[test]
    fn seconds_cannot_be_expressed() {
        // T13: the only time field is a u32 count of minutes, so no DM byte carries seconds.
        let content = text();
        let bytes = content.encode().expect("encode");
        let decoded = decode(&bytes).expect("decode");
        assert_eq!(decoded.author_minute, content.author_minute);
        assert_eq!(bytes[18..22], content.author_minute.to_be_bytes());
    }

    #[test]
    fn a_trailing_byte_refuses_the_whole_record() {
        let mut bytes = text().encode().expect("encode");
        bytes.push(0);
        assert_eq!(decode(&bytes).err(), Some(DmCode::NonCanonical));
    }

    /// Offsets of the fixed part of an L0 without a quote: `flags` and `body_len`.
    const FLAGS_OFFSET: usize = 29;
    const BODY_LEN_OFFSET: usize = 30;

    #[test]
    fn an_over_read_refuses_the_whole_record() {
        let mut bytes = text().encode().expect("encode");
        // Claim a body far longer than the record.
        bytes[BODY_LEN_OFFSET..BODY_LEN_OFFSET + 4].copy_from_slice(&0xffff_u32.to_be_bytes());
        assert_eq!(decode(&bytes).err(), Some(DmCode::NonCanonical));
        // And one byte too long, which is the boundary case.
        let mut bytes = text().encode().expect("encode");
        let body_len = "salut".len() as u32 + 1;
        bytes[BODY_LEN_OFFSET..BODY_LEN_OFFSET + 4].copy_from_slice(&body_len.to_be_bytes());
        assert_eq!(decode(&bytes).err(), Some(DmCode::NonCanonical));
    }

    #[test]
    fn reserved_bits_and_unknown_kinds_are_refused() {
        let mut bytes = text().encode().expect("encode");
        bytes[0] = 0x02;
        assert_eq!(decode(&bytes).err(), Some(DmCode::NonCanonical));
        let mut bytes = text().encode().expect("encode");
        bytes[1] = 0x05; // MEDIA: reserved for Phase 11.
        assert_eq!(decode(&bytes).err(), Some(DmCode::NonCanonical));
        let mut bytes = text().encode().expect("encode");
        bytes[1] = 0x00;
        assert_eq!(decode(&bytes).err(), Some(DmCode::NonCanonical));
        let mut bytes = text().encode().expect("encode");
        bytes[FLAGS_OFFSET] = 0x02; // a reserved flag bit
        assert_eq!(decode(&bytes).err(), Some(DmCode::NonCanonical));
        let mut bytes = text().encode().expect("encode");
        bytes[24] = MAX_TIMER_CODE + 1; // timer_code
        assert_eq!(decode(&bytes).err(), Some(DmCode::NonCanonical));
    }

    #[test]
    fn invalid_utf8_is_refused() {
        let mut content = text();
        content.body = vec![0xff, 0xfe];
        assert_eq!(content.encode().err(), Some(DmCode::NonCanonical));
    }

    #[test]
    fn bodies_follow_their_kind() {
        let mut timer = text();
        timer.kind = Kind::TimerSet;
        assert_eq!(timer.encode().err(), Some(DmCode::NonCanonical));
        timer.body.clear();
        assert!(timer.encode().is_ok());

        let mut reaction = text();
        reaction.kind = Kind::Reaction;
        reaction.body = vec![0u8; 15];
        assert_eq!(reaction.encode().err(), Some(DmCode::NonCanonical));
        reaction.body = vec![0u8; 16];
        assert!(reaction.encode().is_ok(), "an empty grapheme removes it");
        reaction.body = vec![0u8; MAX_REACTION_BODY_BYTES + 1];
        assert_eq!(reaction.encode().err(), Some(DmCode::NonCanonical));
    }

    #[test]
    fn tlvs_must_be_strictly_ascending_and_unique() {
        let mut content = text();
        content.ext = vec![
            Tlv {
                tlv_type: TLV_SESSION_RESET,
                value: Vec::new(),
            },
            Tlv {
                tlv_type: TLV_SEAL_ROOT,
                value: vec![0u8; SEAL_ROOT_BYTES],
            },
        ];
        assert_eq!(content.encode().err(), Some(DmCode::NonCanonical));
        content.ext = vec![
            Tlv {
                tlv_type: TLV_SESSION_RESET,
                value: Vec::new(),
            },
            Tlv {
                tlv_type: TLV_SESSION_RESET,
                value: Vec::new(),
            },
        ];
        assert_eq!(content.encode().err(), Some(DmCode::NonCanonical));
    }

    #[test]
    fn an_unknown_critical_tlv_refuses_the_record_and_an_unknown_optional_one_does_not() {
        let mut content = text();
        content.ext = vec![Tlv {
            tlv_type: 0x8001,
            value: vec![1, 2, 3],
        }];
        assert_eq!(content.encode().err(), Some(DmCode::NonCanonical));
        content.ext = vec![Tlv {
            tlv_type: 0x0200,
            value: vec![1, 2, 3],
        }];
        let bytes = content.encode().expect("encode");
        assert_eq!(decode(&bytes).expect("decode").ext, content.ext);
    }

    #[test]
    fn registry_lengths_are_pinned() {
        let mut content = text();
        for (tlv_type, length) in [
            (TLV_SEAL_ROOT, SEAL_ROOT_BYTES),
            (TLV_REVOCATION, REVOCATION_BYTES),
            (TLV_SESSION_RESET, 0),
            (TLV_SEAL_ROOT_PQ, SEAL_ROOT_PQ_BYTES),
            (TLV_PQ_KEY, PQ_KEY_BYTES),
        ] {
            content.ext = vec![Tlv {
                tlv_type,
                value: vec![0u8; length],
            }];
            assert!(content.encode().is_ok(), "type {tlv_type:#06x}");
            content.ext = vec![Tlv {
                tlv_type,
                value: vec![0u8; length + 1],
            }];
            assert_eq!(
                content.encode().err(),
                Some(DmCode::NonCanonical),
                "type {tlv_type:#06x}"
            );
        }
    }

    #[test]
    fn the_extension_list_is_capped() {
        let mut content = text();
        content.ext = vec![Tlv {
            tlv_type: 0x0200,
            value: vec![0u8; MAX_EXT_BYTES],
        }];
        assert_eq!(content.encode().err(), Some(DmCode::NonCanonical));
    }

    #[test]
    fn the_slack_rule_matches_the_design_examples() {
        // §7.1 R-C5: at 4 KiB a message carries pq_key when its body is at most 1 148 B, and
        // seal_root_pq when its body is at most 1 210 B; the two never fit together there.
        assert_eq!(PQ_KEY_TLV_BYTES, 1232);
        assert_eq!(SEAL_ROOT_PQ_TLV_BYTES, 1170);
        assert!(pq_tlv_fits(4096, 1148, 0, PQ_KEY_TLV_BYTES));
        assert!(!pq_tlv_fits(4096, 1149, 0, PQ_KEY_TLV_BYTES));
        assert!(pq_tlv_fits(4096, 1210, 0, SEAL_ROOT_PQ_TLV_BYTES));
        assert!(!pq_tlv_fits(4096, 1211, 0, SEAL_ROOT_PQ_TLV_BYTES));
        assert!(!pq_tlv_fits(
            4096,
            0,
            0,
            PQ_KEY_TLV_BYTES + SEAL_ROOT_PQ_TLV_BYTES
        ));
        // The bucket never depends on a PQ TLV (ME-23).
        let mut content = text();
        content.ext = vec![Tlv {
            tlv_type: TLV_PQ_KEY,
            value: vec![0u8; PQ_KEY_BYTES],
        }];
        assert_eq!(content.bucket(), Ok(4096));
        assert_eq!(text().bucket(), Ok(4096));
    }

    #[test]
    fn the_tlv_values_round_trip() {
        let root = SealRoot {
            root: [1u8; 32],
            base_week: 2_870,
            root_gen: 5,
        };
        assert_eq!(SealRoot::decode(&root.encode()).expect("decode"), root);
        assert_eq!(
            SealRoot::decode(&[0u8; SEAL_ROOT_BYTES - 1]).err(),
            Some(DmCode::NonCanonical)
        );

        let pq = SealRootPq {
            root_rand: [2u8; 32],
            base_week: 2_871,
            root_gen: 6,
            peer_gen_id: 0x0102_0304,
            xwing_ct: vec![3u8; crate::pq::CIPHERTEXT_BYTES],
        };
        let encoded = pq.encode().expect("encode");
        assert_eq!(encoded.len(), SEAL_ROOT_PQ_BYTES);
        assert_eq!(SealRootPq::decode(&encoded).expect("decode"), pq);

        let key = PqKey {
            gen_id: 0x0a0b_0c0d,
            bundle_week: 2_872,
            xwing_pk: crate::pq::public_key(&crate::derive::KemSecret::from_bytes([0x31; 32]))
                .expect("keygen"),
        };
        let encoded = key.encode().expect("encode");
        assert_eq!(encoded.len(), PQ_KEY_BYTES);
        assert_eq!(PqKey::decode(&encoded).expect("decode"), key);

        // An in-band key with a low-order X25519 half is refused where it is parsed.
        let mut bad = key.clone();
        bad.xwing_pk[crate::pq::ML_KEM_PUBLIC_KEY_BYTES..].copy_from_slice(&[0u8; 32]);
        assert_eq!(
            PqKey::decode(&bad.encode().expect("encode")).err(),
            Some(DmCode::InvalidKey)
        );
    }

    /// A seeded property run: the decoder never panics and never over-reads, whatever the input.
    #[test]
    fn the_decoder_never_panics_on_seeded_inputs() {
        let mut state = 0x243f_6a88_85a3_08d3u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let template = {
            let mut content = text();
            content.quote_ref = Some([3u8; 16]);
            content.ext = vec![Tlv {
                tlv_type: TLV_SEAL_ROOT,
                value: vec![9u8; SEAL_ROOT_BYTES],
            }];
            content.encode().expect("encode")
        };
        for _ in 0..20_000 {
            let mut bytes = template.clone();
            let mutations = (next() % 4) + 1;
            for _ in 0..mutations {
                let at = (next() as usize) % bytes.len();
                bytes[at] = (next() % 256) as u8;
            }
            if next() % 4 == 0 {
                bytes.truncate((next() as usize) % bytes.len().max(1));
            }
            let _ = decode(&bytes);
        }
        for len in 0..64usize {
            let mut bytes = vec![0u8; len];
            for byte in bytes.iter_mut() {
                *byte = (next() % 256) as u8;
            }
            let _ = decode(&bytes);
        }
    }
}
