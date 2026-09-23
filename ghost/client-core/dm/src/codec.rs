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
use crate::seal::{capacity, EXT_RESERVE, L0_FIXED_BYTES, MAX_BODY_BYTES, O_MAX};
use zeroize::Zeroize;

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
/// The largest `timer_version` this codec will encode or accept (§10.5, R-T9).
///
/// The field is four bytes on the wire and the rule that governs it is only "never decreases", so
/// nothing in §9.1 bounds it — and the S9 review found what that costs. A hostile peer that put
/// `0xFFFF_FFFF` on one ordinary L0 was adopted by R-T9 ("a greater version is adopted from any
/// message"), stored, and read back by the **next send of any kind**, which re-encodes the
/// conversation's version; the Kotlin facade narrows it to a `jint` there, so every send to that
/// conversation threw, for good, across restarts. One message, one conversation silenced.
///
/// The bound is what a `TIMER_SET` must still be able to write after it: a version of exactly
/// [`MAX_TIMER_VERSION`] leaves room for the `version + 1` of §10.5. It costs nothing real — the
/// number counts a conversation's timer changes, and two billion of them is not a conversation.
pub const MAX_TIMER_VERSION: u32 = i32::MAX as u32 - 1;
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
#[derive(Clone, PartialEq, Eq)]
pub struct Tlv {
    /// The registry type; bit 15 marks it critical.
    pub tlv_type: u16,
    /// The value, whose length the registry fixes for the types Phase 9 defines.
    pub value: Vec<u8>,
}

impl core::fmt::Debug for Tlv {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // A `seal_root` or `seal_root_pq` value is key material: only the shape renders.
        f.debug_struct("Tlv")
            .field("tlv_type", &format_args!("{:#06x}", self.tlv_type))
            .field("value_len", &self.value.len())
            .finish()
    }
}

/// A TLV value is erased when it is dropped (slice S13 review). A `seal_root` value **is** a pair
/// root and a `seal_root_pq` value carries `root_rand`, and a TLV is copied more often than the
/// code that builds it can follow: into a decoded record, into the candidates of R-C5, out of a
/// candidate the slack rule left behind. Erasing at the type, rather than at each call site, is
/// what makes "every copy" true.
impl Drop for Tlv {
    fn drop(&mut self) {
        self.value.zeroize();
    }
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
#[derive(Clone, PartialEq, Eq)]
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

impl core::fmt::Debug for DmContent {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // The body is the message the user wrote: only its length renders, so a panic payload or
        // a caught assertion never carries plaintext.
        f.debug_struct("DmContent")
            .field("kind", &self.kind)
            .field("author_minute", &self.author_minute)
            .field("minute_index", &self.minute_index)
            .field("timer_code", &self.timer_code)
            .field("timer_version", &self.timer_version)
            .field("has_quote", &self.quote_ref.is_some())
            .field("body_len", &self.body.len())
            .field("ext", &self.ext)
            .finish_non_exhaustive()
    }
}

fn encoded_ext_len(ext: &[Tlv]) -> usize {
    ext.iter()
        .map(|tlv| TLV_HEADER_BYTES + tlv.value.len())
        .sum()
}

/// True for the PQ-C extensions of §9.4, which ride under the slack rule R-C5 instead of inside
/// the `EXT_RESERVE` the bucket already counts.
pub const fn is_pq_tlv(tlv_type: u16) -> bool {
    matches!(tlv_type, TLV_SEAL_ROOT_PQ | TLV_PQ_KEY)
}

/// The encoded length of the classical (non PQ-C) TLVs of a list: the figure §21.11 point 3 caps
/// at [`EXT_RESERVE`] on the sending side, and the figure R-C5 subtracts from a bucket's slack.
pub fn classical_ext_len(ext: &[Tlv]) -> usize {
    ext.iter()
        .filter(|tlv| !is_pq_tlv(tlv.tlv_type))
        .map(|tlv| TLV_HEADER_BYTES + tlv.value.len())
        .sum()
}

/// The encoded length of the PQ-C TLVs of a list: what R-C5 compares with a bucket's slack.
pub fn pq_ext_len(ext: &[Tlv]) -> usize {
    ext.iter()
        .filter(|tlv| is_pq_tlv(tlv.tlv_type))
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
    ///
    /// The sender cap of §21.11 point 3 is checked here and nowhere else: classical TLVs beyond
    /// `ext_len = EXT_RESERVE` are refused, because R-B1 chose the bucket with exactly that much
    /// room reserved and a longer list would leave an L0 that its own bucket cannot carry. The
    /// receiving cap stays [`MAX_EXT_BYTES`], which is what [`decode`] applies.
    pub fn encode(&self) -> DmResult<Vec<u8>> {
        if self.timer_code > MAX_TIMER_CODE {
            return Err(DmCode::NonCanonical);
        }
        if self.timer_version > MAX_TIMER_VERSION {
            return Err(DmCode::NonCanonical);
        }
        check_body(self.kind, &self.body)?;
        check_ext(&self.ext)?;
        let classical = classical_ext_len(&self.ext);
        if classical > EXT_RESERVE {
            return Err(DmCode::NonCanonical);
        }
        // R-C5, enforced where the bytes are made (slice S13): a PQ-C TLV rides only in the slack
        // of the bucket the body length alone chose. Without this a caller could encode an L0 its
        // own bucket cannot carry — the seal would then answer `NO_FIT`, which R-B1 classes as a
        // bug — or be tempted to move to a larger bucket, which is mutant ME-23. Every L0 this
        // function returns fits `capacity(bucket(body))`, whatever TLVs it carries.
        let pq_len = pq_ext_len(&self.ext);
        if pq_len > 0 {
            let bucket = crate::seal::bucket_for_body(self.body.len())?;
            if !pq_tlv_fits(bucket, self.body.len(), classical, pq_len) {
                return Err(DmCode::NonCanonical);
            }
        }
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
    if timer_version > MAX_TIMER_VERSION {
        return Err(DmCode::NonCanonical);
    }
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

/// R-C5 applied on the sending side (§7.1, §9.4; slice S13): appends each PQ-C candidate, **in
/// the order given**, that still fits the slack of the bucket the body length alone chose, and
/// returns the types that rode.
///
/// The bucket is computed **before** any candidate is looked at and is never recomputed, so it is
/// a function of the body length alone (T29, mutant ME-23); a candidate that does not fit is left
/// out — deferred to a later user send, never sent on its own (T28). The caller orders the
/// candidates by priority: SEND puts a pending `seal_root_pq` before `pq_key`, because an offer
/// re-keys a direction now and an announcement only enables the peer's next offer, and the two
/// together never fit a 4 KiB message (§7.1 R-C5's example).
///
/// A candidate that is not a PQ-C TLV, or whose type the content already carries, is
/// [`DmCode::NonCanonical`]: the classical TLVs go through `EXT_RESERVE`, which R-B1 already
/// counted, and R-C4 allows each type once.
pub fn attach_pq_under_slack(content: &mut DmContent, candidates: Vec<Tlv>) -> DmResult<Vec<u16>> {
    let bucket = content.bucket()?;
    let body_len = content.body.len();
    let classical = classical_ext_len(&content.ext);
    let mut pq_len = pq_ext_len(&content.ext);
    let mut attached = Vec::new();
    for tlv in candidates {
        if !is_pq_tlv(tlv.tlv_type) || content.ext.iter().any(|t| t.tlv_type == tlv.tlv_type) {
            return Err(DmCode::NonCanonical);
        }
        let bytes = TLV_HEADER_BYTES + tlv.value.len();
        if pq_candidate_fits(bucket, body_len, classical, pq_len + bytes) {
            pq_len += bytes;
            attached.push(tlv.tlv_type);
            content.ext.push(tlv);
        }
    }
    content.ext.sort_by_key(|tlv| tlv.tlv_type);
    Ok(attached)
}

/// Whether PQ-C TLVs of `pq_tlv_bytes` in total may ride: R-C5's slack **and** R-C4's receiver cap
/// on the whole TLV list.
///
/// The second half is not implied by the first (found by slice S13's PQ4 walk): `EXT_RESERVE`
/// (160) plus both PQ-C TLVs (1 170 + 1 232) is 2 562 bytes, two more than R-C4's `ext_len ≤
/// 2 560`, and a 16 or 64 KiB message has the slack for all of it. No Phase 9 send carries 160
/// bytes of classical TLVs beside both PQ ones — a `seal_root_pq` *replaces* `seal_root`, and the
/// revocation notice with its reset is 110 bytes — but a Phase 13 `card_update` could, and the
/// receiver would refuse the whole L0. The sender therefore attaches only what the receiver
/// accepts, and the one deferred TLV rides on a later send.
pub fn pq_candidate_fits(
    bucket: usize,
    body_len: usize,
    classical_ext_len: usize,
    pq_tlv_bytes: usize,
) -> bool {
    classical_ext_len + pq_tlv_bytes <= MAX_EXT_BYTES
        && pq_tlv_fits(bucket, body_len, classical_ext_len, pq_tlv_bytes)
}

/// `seal_root`: the root the sender wants the recipient to use for recipient-to-sender envelopes.
#[derive(Clone, PartialEq, Eq)]
pub struct SealRoot {
    /// The 32-byte root, or `root_rand` in the PQ-C form.
    pub root: [u8; 32],
    /// The ISO week the root's first week key belongs to.
    pub base_week: u64,
    /// The generation number, which only increases per contact.
    pub root_gen: u16,
}

impl core::fmt::Debug for SealRoot {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // The root keys every pair envelope of its direction: it never renders.
        f.debug_struct("SealRoot")
            .field("base_week", &self.base_week)
            .field("root_gen", &self.root_gen)
            .finish_non_exhaustive()
    }
}

/// The root is erased with the value that carried it (see [`Tlv`]'s `Drop`).
impl Drop for SealRoot {
    fn drop(&mut self) {
        self.root.zeroize();
    }
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
#[derive(Clone, PartialEq, Eq)]
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

impl core::fmt::Debug for SealRootPq {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // `root_rand` is half the root material; the ciphertext is public but adds nothing here.
        f.debug_struct("SealRootPq")
            .field("base_week", &self.base_week)
            .field("root_gen", &self.root_gen)
            .field("peer_gen_id", &self.peer_gen_id)
            .field("xwing_ct_len", &self.xwing_ct.len())
            .finish_non_exhaustive()
    }
}

/// `root_rand` is erased on drop (slice S13 review). It keys nothing without the X-Wing secret
/// (§9.4), but it is half of every PQ root, and a copy that outlives its use is one a later
/// compromise of the KEM secret would complete.
impl Drop for SealRootPq {
    fn drop(&mut self) {
        self.root_rand.zeroize();
    }
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
    use crate::seal::{max_body, BUCKETS};

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

    /// Offsets of the fixed part of an L0 without a quote: `timer_version`, `flags`, `body_len`.
    const TIMER_VERSION_OFFSET: usize = 25;
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

    /// §10.5 R-T9 and the S9 review: a `timer_version` this device could not re-encode after
    /// incrementing is refused at the parser, both ways.
    ///
    /// Without the bound one crafted L0 from an established contact was adopted by R-T9 and then
    /// silenced every later send to that conversation, permanently: the next send re-encodes the
    /// stored version, and the facade narrows it to a signed 32-bit integer.
    #[test]
    fn a_timer_version_beyond_the_bound_is_refused_both_ways() {
        // The bound itself still round-trips, so the refusal is of the value and not of the field.
        let mut ok = text();
        ok.timer_version = MAX_TIMER_VERSION;
        let bytes = ok.encode().expect("encode");
        assert_eq!(
            decode(&bytes).expect("decode").timer_version,
            MAX_TIMER_VERSION
        );

        let mut over = text();
        over.timer_version = MAX_TIMER_VERSION + 1;
        assert_eq!(over.encode().err(), Some(DmCode::NonCanonical));

        // And a peer that writes the bytes by hand is refused at the decoder, which is the side
        // that faces the network.
        let mut crafted = text().encode().expect("encode");
        crafted[TIMER_VERSION_OFFSET..TIMER_VERSION_OFFSET + 4]
            .copy_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(decode(&crafted).err(), Some(DmCode::NonCanonical));
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
        // The receiver cap is the larger one, and it is the decoder that applies it: an `ext_len`
        // above MAX_EXT_BYTES is refused before the list is read.
        let mut bytes = text().encode().expect("encode");
        let at = bytes.len() - 2;
        bytes[at..].copy_from_slice(&((MAX_EXT_BYTES + 1) as u16).to_be_bytes());
        assert_eq!(decode(&bytes).err(), Some(DmCode::NonCanonical));
    }

    #[test]
    fn a_sender_refuses_classical_tlvs_beyond_the_reserve() {
        // §21.11 point 3: the bucket counts EXT_RESERVE = 160 B of classical TLVs, so a sender
        // may not write more. The boundary is exact.
        let mut content = text();
        content.ext = vec![Tlv {
            tlv_type: TLV_CARD_UPDATE,
            value: vec![0u8; EXT_RESERVE - TLV_HEADER_BYTES],
        }];
        assert_eq!(classical_ext_len(&content.ext), EXT_RESERVE);
        assert!(content.encode().is_ok());
        content.ext[0].value.push(0);
        assert_eq!(classical_ext_len(&content.ext), EXT_RESERVE + 1);
        assert_eq!(content.encode().err(), Some(DmCode::NonCanonical));

        // The PQ-C TLVs are not classical: they ride under R-C5 and are not counted here, so a
        // full reserve plus a `seal_root_pq` still encodes.
        let mut with_pq = text();
        with_pq.ext = vec![
            Tlv {
                tlv_type: TLV_CARD_UPDATE,
                value: vec![0u8; EXT_RESERVE - TLV_HEADER_BYTES],
            },
            Tlv {
                tlv_type: TLV_SEAL_ROOT_PQ,
                value: vec![0u8; SEAL_ROOT_PQ_BYTES],
            },
        ];
        assert_eq!(classical_ext_len(&with_pq.ext), EXT_RESERVE);
        assert!(with_pq.encode().is_ok());
        assert!(!is_pq_tlv(TLV_CARD_UPDATE));
        assert!(is_pq_tlv(TLV_PQ_KEY) && is_pq_tlv(TLV_SEAL_ROOT_PQ));
    }

    #[test]
    fn an_oversized_classical_tlv_can_never_outgrow_its_bucket() {
        // Without the sender cap, a longest body plus a 500-byte `card_update` chose bucket 4096
        // and produced an L0 of 2 760 B, which capacity(4096) = 2 432 cannot carry: the seal would
        // have answered NO_FIT, which R-B1 classes as a bug, instead of refusing the content.
        let mut content = text();
        content.body = vec![0x41; max_body(4096)];
        content.ext = vec![Tlv {
            tlv_type: TLV_CARD_UPDATE,
            value: vec![0u8; 500],
        }];
        assert_eq!(content.bucket(), Ok(4096));
        assert_eq!(content.encode().err(), Some(DmCode::NonCanonical));

        // Every encodable content fits the bucket its body length chose, in every class.
        for bucket in BUCKETS {
            let mut biggest = text();
            // The 64 KiB class is capped by the API bound, not by R-B1's class bound.
            biggest.body = vec![0x41; max_body(bucket).min(MAX_BODY_BYTES)];
            biggest.ext = vec![Tlv {
                tlv_type: TLV_CARD_UPDATE,
                value: vec![0u8; EXT_RESERVE - TLV_HEADER_BYTES],
            }];
            biggest.quote_ref = Some([9u8; 16]);
            let encoded = biggest.encode().expect("encode");
            assert_eq!(biggest.bucket(), Ok(bucket));
            assert!(
                encoded.len() <= capacity(bucket),
                "bucket {bucket}: |L0| = {} > {}",
                encoded.len(),
                capacity(bucket)
            );
        }
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

    /// Secrets never render: a `Debug` of a root or of a message body would put it in a panic
    /// payload, which is the reason every other secret-bearing type of the crate redacts.
    #[test]
    fn secret_bearing_types_do_not_render_their_bytes() {
        let root = SealRoot {
            root: [0xab; 32],
            base_week: 1,
            root_gen: 0,
        };
        let rendered = format!("{root:?}");
        assert!(!rendered.contains("root: ["), "{rendered}");
        assert!(!rendered.contains("171"), "{rendered}");
        assert!(rendered.contains("base_week"), "{rendered}");

        let pq = SealRootPq {
            root_rand: [0xcd; 32],
            base_week: 2,
            root_gen: 1,
            peer_gen_id: 3,
            xwing_ct: vec![0xef; crate::pq::CIPHERTEXT_BYTES],
        };
        let rendered = format!("{pq:?}");
        assert!(!rendered.contains("root_rand: ["), "{rendered}");
        assert!(!rendered.contains("205"), "{rendered}");
        assert!(rendered.contains("xwing_ct_len: 1120"), "{rendered}");

        let mut content = text();
        content.body = b"the message body".to_vec();
        content.ext = vec![Tlv {
            tlv_type: TLV_SEAL_ROOT,
            value: root.encode(),
        }];
        let rendered = format!("{content:?}");
        assert!(!rendered.contains("body: ["), "{rendered}");
        assert!(!rendered.contains("value: ["), "{rendered}");
        assert!(!rendered.contains("116"), "{rendered}"); // 't' of the body
        assert!(rendered.contains("body_len: 16"), "{rendered}");
        assert!(rendered.contains("value_len: 42"), "{rendered}");
    }

    /// The templates the decoder property run mutates: one of every kind, with and without a
    /// quote, with classical and PQ-C TLVs.
    fn templates() -> Vec<Vec<u8>> {
        let mut out = Vec::new();

        let mut quoted = text();
        quoted.quote_ref = Some([3u8; 16]);
        quoted.ext = vec![Tlv {
            tlv_type: TLV_SEAL_ROOT,
            value: vec![9u8; SEAL_ROOT_BYTES],
        }];
        out.push(quoted.encode().expect("encode"));

        out.push(text().encode().expect("encode"));

        let mut timer = text();
        timer.kind = Kind::TimerSet;
        timer.body.clear();
        out.push(timer.encode().expect("encode"));

        let mut reaction = text();
        reaction.kind = Kind::Reaction;
        reaction.body = {
            let mut body = vec![0x56u8; 16];
            body.extend_from_slice("👍".as_bytes());
            body
        };
        out.push(reaction.encode().expect("encode"));

        let mut control = text();
        control.kind = Kind::Control;
        control.body.clear();
        control.ext = vec![
            Tlv {
                tlv_type: TLV_SEAL_ROOT,
                value: vec![1u8; SEAL_ROOT_BYTES],
            },
            Tlv {
                tlv_type: TLV_SESSION_RESET,
                value: Vec::new(),
            },
            Tlv {
                tlv_type: TLV_SEAL_ROOT_PQ,
                value: vec![2u8; SEAL_ROOT_PQ_BYTES],
            },
        ];
        out.push(control.encode().expect("encode"));

        let mut with_pq_key = text();
        with_pq_key.ext = vec![Tlv {
            tlv_type: TLV_PQ_KEY,
            value: vec![3u8; PQ_KEY_BYTES],
        }];
        out.push(with_pq_key.encode().expect("encode"));

        out
    }

    /// R-C4 and §15.2: a seeded property run over the L0 decoder. It never panics, never
    /// over-reads, and every refusal is one of the two codes §7.1 allows.
    #[test]
    fn the_decoder_never_panics_on_seeded_inputs() {
        let templates = templates();
        let mut rng = crate::property::Seeded::new(0x243f_6a88_85a3_08d3);
        for _ in 0..crate::property::inputs() {
            let template = &templates[rng.below(templates.len())];
            let bytes = rng.mutate(template);
            match decode(&bytes) {
                Ok(content) => {
                    // What decodes re-encodes to the same bytes: one encoding per value. A record
                    // whose classical TLVs exceed the sender reserve (§21.11 point 3), or whose
                    // PQ-C TLVs exceed the slack of its body's bucket (R-C5, slice S13), is
                    // receivable but not sendable, so those are the shapes that do not re-encode.
                    if sendable(&content) {
                        assert_eq!(content.encode().expect("re-encode"), bytes);
                    } else {
                        assert_eq!(content.encode().err(), Some(DmCode::NonCanonical));
                    }
                }
                Err(code) => assert!(
                    matches!(code, DmCode::NonCanonical | DmCode::Oversize),
                    "{code:?}"
                ),
            }
        }
        // And free-form inputs, including the empty one and every short prefix length.
        for _ in 0..crate::property::inputs() / 4 {
            let bytes = rng.random_input(96);
            if let Err(code) = decode(&bytes) {
                assert!(
                    matches!(code, DmCode::NonCanonical | DmCode::Oversize),
                    "{code:?}"
                );
            }
        }
    }

    /// Whether a decoded record is one a sender may produce: the two sender-side caps.
    fn sendable(content: &DmContent) -> bool {
        let classical = classical_ext_len(&content.ext);
        if classical > EXT_RESERVE {
            return false;
        }
        let pq = pq_ext_len(&content.ext);
        pq == 0
            || crate::seal::bucket_for_body(content.body.len())
                .is_ok_and(|bucket| pq_tlv_fits(bucket, content.body.len(), classical, pq))
    }

    fn seal_root_pq_tlv() -> Tlv {
        Tlv {
            tlv_type: TLV_SEAL_ROOT_PQ,
            value: vec![0x51; SEAL_ROOT_PQ_BYTES],
        }
    }

    fn pq_key_tlv() -> Tlv {
        Tlv {
            tlv_type: TLV_PQ_KEY,
            value: vec![0x52; PQ_KEY_BYTES],
        }
    }

    /// The classical TLV sets a user send can carry (§7.1 R-C3): none, a root offer, the
    /// revocation notice with its reset, and a full `EXT_RESERVE` — the worst case R-B1 counts.
    fn classical_sets() -> Vec<Vec<Tlv>> {
        vec![
            Vec::new(),
            vec![Tlv {
                tlv_type: TLV_SEAL_ROOT,
                value: vec![1u8; SEAL_ROOT_BYTES],
            }],
            vec![
                Tlv {
                    tlv_type: TLV_REVOCATION,
                    value: vec![2u8; REVOCATION_BYTES],
                },
                Tlv {
                    tlv_type: TLV_SESSION_RESET,
                    value: Vec::new(),
                },
            ],
            vec![Tlv {
                tlv_type: TLV_CARD_UPDATE,
                value: vec![3u8; EXT_RESERVE - TLV_HEADER_BYTES],
            }],
        ]
    }

    /// The body lengths PQ4 walks per bucket: every length of the 4 KiB class (it is where the
    /// slack is tight), and for the larger classes `0 … 64`, a stride, and `[C(B) − 64, C(B)]` —
    /// the golden-size probe set of §6.6.
    fn pq4_body_lengths(bucket: usize) -> Vec<usize> {
        let top = max_body(bucket).min(MAX_BODY_BYTES);
        if bucket == 4096 {
            return (0..=top).collect();
        }
        let mut out: Vec<usize> = (0..=64).collect();
        out.extend((65..top.saturating_sub(64)).step_by(509));
        out.extend(top.saturating_sub(64)..=top);
        out
    }

    /// **PQ4** (§15.5, the Rust half; mutant ME-23): slack-rule attachment never changes the
    /// bucket, never produces an L0 its bucket cannot carry, attaches exactly what fits in the
    /// priority order given, and leaves out only what would not have fitted.
    #[test]
    fn pq4_slack_rule_attachment_never_changes_the_bucket() {
        let orders: [Vec<Tlv>; 5] = [
            Vec::new(),
            vec![seal_root_pq_tlv()],
            vec![pq_key_tlv()],
            vec![seal_root_pq_tlv(), pq_key_tlv()],
            vec![pq_key_tlv(), seal_root_pq_tlv()],
        ];
        let mut checked = 0usize;
        let mut rode = 0usize;
        let mut deferred = 0usize;
        // Deferred by R-C4's `ext_len` cap alone, with the slack available: the EXT_RESERVE +
        // both-PQ case the walk found (see `pq_candidate_fits`).
        let mut capped = 0usize;
        for bucket in BUCKETS {
            for body_len in pq4_body_lengths(bucket) {
                let expected_bucket = crate::seal::bucket_for_body(body_len).expect("bucket");
                if expected_bucket != bucket {
                    continue;
                }
                for classical in classical_sets() {
                    for candidates in &orders {
                        for quote in [None, Some([4u8; 16])] {
                            let mut content = text();
                            content.body = vec![0x41; body_len];
                            content.quote_ref = quote;
                            content.ext = classical.clone();
                            let attached = attach_pq_under_slack(&mut content, candidates.clone())
                                .expect("attach");
                            assert_eq!(
                                content.bucket(),
                                Ok(bucket),
                                "the bucket moved at body {body_len}"
                            );
                            let encoded = content.encode().unwrap_or_else(|code| {
                                panic!(
                                    "an attached L0 must encode: {code:?} at body {body_len}, \
                                     bucket {bucket}, attached {attached:?}"
                                )
                            });
                            assert!(
                                encoded.len() <= capacity(bucket),
                                "|L0| = {} > C({bucket}) at body {body_len}",
                                encoded.len()
                            );
                            // Greedy, in the order given: each candidate rides exactly when it
                            // fits beside the ones before it that rode.
                            let class_len = classical_ext_len(&classical);
                            let mut used = 0usize;
                            for tlv in candidates {
                                let bytes = TLV_HEADER_BYTES + tlv.value.len();
                                let fits = pq_tlv_fits(bucket, body_len, class_len, used + bytes)
                                    && class_len + used + bytes <= MAX_EXT_BYTES;
                                if !fits && pq_tlv_fits(bucket, body_len, class_len, used + bytes) {
                                    capped += 1;
                                }
                                assert_eq!(
                                    attached.contains(&tlv.tlv_type),
                                    fits,
                                    "{:#06x} at body {body_len}, bucket {bucket}",
                                    tlv.tlv_type
                                );
                                if fits {
                                    used += bytes;
                                    rode += 1;
                                } else {
                                    deferred += 1;
                                }
                            }
                            checked += 1;
                        }
                    }
                }
            }
        }
        // Floors, so a loop that skipped everything cannot pass: both outcomes happened.
        assert!(checked > 20_000, "{checked} cases");
        assert!(
            rode > 1_000 && deferred > 1_000,
            "rode {rode}, deferred {deferred}"
        );
        assert!(capped > 0, "the ext_len cap case was never reached");
    }

    /// PQ4's control (mutant **ME-23**): the obvious wrong implementation — attach every candidate
    /// and let the bucket follow the L0 — changes the bucket at the design's own boundary, and the
    /// encoder refuses what it would have produced for the body-length bucket.
    #[test]
    fn me_23_a_pq_tlv_that_chose_the_bucket_is_detected() {
        let mut content = text();
        content.body = vec![0x41; 1149];
        content.ext.push(pq_key_tlv());
        // What the mutant would do: a bucket from the whole L0.
        let whole = L0_FIXED_BYTES + content.body.len() + PQ_KEY_TLV_BYTES;
        let mutant_bucket = BUCKETS
            .into_iter()
            .find(|b| whole <= capacity(*b))
            .expect("some bucket");
        assert_eq!(
            mutant_bucket, 16384,
            "the mutant moves this message up a class"
        );
        assert_eq!(
            content.bucket(),
            Ok(4096),
            "R-B1 keeps it where its body put it"
        );
        assert_eq!(
            content.encode().err(),
            Some(DmCode::NonCanonical),
            "and the encoder refuses a PQ TLV beyond the slack"
        );
        // The correct attachment leaves it out, and the record stays in its class.
        let mut correct = text();
        correct.body = vec![0x41; 1149];
        assert!(attach_pq_under_slack(&mut correct, vec![pq_key_tlv()])
            .expect("attach")
            .is_empty());
        assert_eq!(correct.encode().expect("encode").len(), 52 - 16 + 1149);
    }

    /// The design's two figures of R-C5 through the attachment path itself, with no classical TLV
    /// pending and no quote.
    #[test]
    fn the_slack_rule_boundaries_hold_through_the_attachment() {
        for (body, tlv, rides) in [
            (1148usize, pq_key_tlv(), true),
            (1149, pq_key_tlv(), false),
            (1210, seal_root_pq_tlv(), true),
            (1211, seal_root_pq_tlv(), false),
        ] {
            let mut content = text();
            content.body = vec![0x41; body];
            let tlv_type = tlv.tlv_type;
            let attached = attach_pq_under_slack(&mut content, vec![tlv]).expect("attach");
            assert_eq!(attached.contains(&tlv_type), rides, "body {body}");
        }
        // Both together never fit at 4 KiB, whatever the body: the first rides, the second waits.
        let mut empty = text();
        empty.body.clear();
        let attached = attach_pq_under_slack(&mut empty, vec![seal_root_pq_tlv(), pq_key_tlv()])
            .expect("attach");
        assert_eq!(attached, vec![TLV_SEAL_ROOT_PQ]);
        // At 16 KiB both ride.
        let mut large = text();
        large.body = vec![0x41; max_body(4096) + 1];
        let attached = attach_pq_under_slack(&mut large, vec![seal_root_pq_tlv(), pq_key_tlv()])
            .expect("attach");
        assert_eq!(attached, vec![TLV_SEAL_ROOT_PQ, TLV_PQ_KEY]);
        assert_eq!(large.bucket(), Ok(16384));
    }

    /// A classical TLV is not a slack candidate, and a type the record already carries is refused
    /// rather than doubled (R-C4: each type at most once).
    #[test]
    fn the_attachment_refuses_what_is_not_a_pq_candidate() {
        let mut content = text();
        assert_eq!(
            attach_pq_under_slack(
                &mut content,
                vec![Tlv {
                    tlv_type: TLV_SEAL_ROOT,
                    value: vec![0u8; SEAL_ROOT_BYTES],
                }],
            )
            .err(),
            Some(DmCode::NonCanonical)
        );
        let mut twice = text();
        twice.ext.push(pq_key_tlv());
        assert_eq!(
            attach_pq_under_slack(&mut twice, vec![pq_key_tlv()]).err(),
            Some(DmCode::NonCanonical)
        );
    }

    /// The TLV value decoders are parsers of their own (§15.2 "every parser"): `seal_root`,
    /// `seal_root_pq` and `pq_key` over free-form inputs.
    #[test]
    fn the_tlv_value_decoders_never_panic_on_seeded_inputs() {
        let mut rng = crate::property::Seeded::new(0x9e37_79b9_7f4a_7c15);
        let pq_key_template = PqKey {
            gen_id: 1,
            bundle_week: 2,
            xwing_pk: crate::pq::public_key(&crate::derive::KemSecret::from_bytes([0x21; 32]))
                .expect("keygen"),
        }
        .encode()
        .expect("encode");
        for _ in 0..crate::property::inputs() {
            let bytes = rng.random_input(SEAL_ROOT_PQ_BYTES + 8);
            let _ = SealRoot::decode(&bytes);
            let _ = SealRootPq::decode(&bytes);
        }
        // `PqKey::decode` runs a whole-key validation, so it is fed near-valid inputs instead.
        for _ in 0..crate::property::inputs() / 1_000 {
            let bytes = rng.mutate(&pq_key_template);
            match PqKey::decode(&bytes) {
                Ok(key) => assert_eq!(key.xwing_pk.len(), crate::pq::PUBLIC_KEY_BYTES),
                Err(code) => assert!(
                    matches!(code, DmCode::NonCanonical | DmCode::InvalidKey),
                    "{code:?}"
                ),
            }
        }
    }
}
