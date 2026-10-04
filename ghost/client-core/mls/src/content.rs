//! `ChannelContent` v1, the MLS application plaintext of a channel (design §5.5):
//!
//! ```text
//! ChannelContent = version(1) = 0x01 || kind(1) || op_id(16) || author_minute(u32_be) || timer_code(1) || tlv*
//! tlv            = type(u16_be) || len(u16_be) || value
//! ```
//!
//! Canonical form: TLVs strictly ascending by type, no duplicates, only the TLVs listed for the
//! kind, lengths within bounds, no trailing bytes; otherwise `NON_CANONICAL`. The encoder refuses
//! what the decoder refuses, so every encoded content decodes to itself.

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::codec::{put_u16, put_u32, Reader};
use crate::result::{Code, MlsError, MlsResult};

pub const KIND_POST: u8 = 0x01;
pub const KIND_REACTION: u8 = 0x02;
pub const KIND_INVITE_ISSUED: u8 = 0x03;
pub const KIND_LEAVE: u8 = 0x04;
pub const KIND_REVEAL: u8 = 0x05;
/// Reserved (ADR-13, P1); refused in Phase 10 (Q15).
pub const KIND_FLAG: u8 = 0x06;
/// Reserved (FR-3.7, P2).
pub const KIND_PIN: u8 = 0x07;

pub const TLV_TEXT: u16 = 0x0001;
pub const TLV_REPLY_TO: u16 = 0x0002;
/// Phase 11's media descriptor (84 bytes); refused until the channel-media slice (§5.10, Q38).
pub const TLV_MEDIA_REF: u16 = 0x0003;
pub const TLV_TARGET: u16 = 0x0004;
pub const TLV_GRAPHEME: u16 = 0x0005;
pub const TLV_INVITE_ID: u16 = 0x0010;
pub const TLV_INVITE_PK: u16 = 0x0011;
pub const TLV_EXPIRY_DAY: u16 = 0x0012;
pub const TLV_SPONSOR_SIG: u16 = 0x0013;
pub const TLV_COMMITTERS_DIGEST: u16 = 0x0014;
pub const TLV_PW_VERSION: u16 = 0x0015;
pub const TLV_HPKE_ENC: u16 = 0x0020;
pub const TLV_CIPHERTEXT: u16 = 0x0021;

pub const TEXT_MAX: usize = 16_000;
pub const GRAPHEME_MAX: usize = 32;
pub const REVEAL_CT_MAX: usize = 512;
/// version ‖ kind ‖ op_id ‖ author_minute ‖ timer_code.
pub const HEADER_LEN: usize = 23;

/// A decoded, canonical content. It holds a post's plaintext (a reaction's grapheme, a reveal's
/// ciphertext), so every copy the crate makes is erased when it is dropped (review of S2b:
/// `contentEncode`, `contentDecode`, `encrypt`'s validation decode and a received post each left
/// one in freed memory).
#[derive(Clone, Debug, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct ChannelContent {
    pub kind: u8,
    pub op_id: [u8; 16],
    pub author_minute: u32,
    pub timer_code: u8,
    pub body: Body,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Body {
    Post {
        text: String,
        reply_to: Option<[u8; 16]>,
    },
    Reaction {
        target: [u8; 16],
        /// Empty withdraws the reaction.
        grapheme: String,
    },
    InviteIssued(InviteIssued),
    Leave,
    Reveal {
        hpke_enc: [u8; 32],
        ciphertext: Vec<u8>,
    },
}

// What `ChannelContent`'s erasure reaches in its body: the text, the grapheme, the reveal's
// ciphertext. An `INVITE_ISSUED` record is public (ids, public keys, signatures) and is left as it is.
impl Zeroize for Body {
    fn zeroize(&mut self) {
        match self {
            Body::Post { text, reply_to } => {
                text.zeroize();
                reply_to.zeroize();
            }
            Body::Reaction { target, grapheme } => {
                target.zeroize();
                grapheme.zeroize();
            }
            Body::InviteIssued(_) | Body::Leave => {}
            Body::Reveal {
                hpke_enc,
                ciphertext,
            } => {
                hpke_enc.zeroize();
                ciphertext.zeroize();
            }
        }
    }
}

/// The sponsor's record of an invite (§5.5 kind 0x03, §19.28.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InviteIssued {
    pub invite_id: [u8; 16],
    pub invite_pk: [u8; 32],
    pub expiry_day: u32,
    /// Over `"ghost/v1/ch/invite" ‖ channel_id ‖ invite_id ‖ invite_pk ‖ u32(expiry_day)`.
    pub sponsor_sig: [u8; 64],
    pub committers_digest: [u8; 32],
    /// Present, ≥ 1, exactly when the sponsor issued in a password channel; absent is the one
    /// encoding of "open" (§19.29.3).
    pub pw_version: Option<u16>,
}

fn nc() -> MlsError {
    MlsError::new(Code::NonCanonical)
}

fn tlv(out: &mut Vec<u8>, t: u16, v: &[u8]) -> MlsResult<()> {
    put_u16(out, t);
    put_u16(out, u16::try_from(v.len()).map_err(|_| nc())?);
    out.extend_from_slice(v);
    Ok(())
}

impl ChannelContent {
    /// `contentEncode` (§10.2 fn 17): refuses what [`ChannelContent::decode`] refuses.
    pub fn encode(&self) -> MlsResult<Vec<u8>> {
        if self.timer_code > 5 {
            return Err(nc());
        }
        // The exact length up front: a buffer that grew would leave the text it held in freed
        // memory, where the caller's erasure of the encoding cannot reach it (review of S2b).
        let tlvs = match &self.body {
            Body::Post { text, reply_to } => 4 + text.len() + reply_to.map_or(0, |_| 4 + 16),
            Body::Reaction { grapheme, .. } => 4 + 16 + 4 + grapheme.len(),
            Body::InviteIssued(i) => {
                5 * 4 + 16 + 32 + 4 + 64 + 32 + i.pw_version.map_or(0, |_| 4 + 2)
            }
            Body::Leave => 0,
            Body::Reveal { ciphertext, .. } => 4 + 32 + 4 + ciphertext.len(),
        };
        let mut o = Vec::with_capacity(HEADER_LEN + tlvs);
        o.push(1);
        o.push(self.kind);
        o.extend_from_slice(&self.op_id);
        put_u32(&mut o, self.author_minute);
        o.push(self.timer_code);
        match (&self.body, self.kind) {
            (Body::Post { text, reply_to }, KIND_POST) => {
                if text.is_empty() || text.len() > TEXT_MAX {
                    return Err(nc());
                }
                tlv(&mut o, TLV_TEXT, text.as_bytes())?;
                if let Some(r) = reply_to {
                    tlv(&mut o, TLV_REPLY_TO, r)?;
                }
            }
            (Body::Reaction { target, grapheme }, KIND_REACTION) => {
                if grapheme.len() > GRAPHEME_MAX {
                    return Err(nc());
                }
                tlv(&mut o, TLV_TARGET, target)?;
                tlv(&mut o, TLV_GRAPHEME, grapheme.as_bytes())?;
            }
            (Body::InviteIssued(i), KIND_INVITE_ISSUED) => {
                tlv(&mut o, TLV_INVITE_ID, &i.invite_id)?;
                tlv(&mut o, TLV_INVITE_PK, &i.invite_pk)?;
                tlv(&mut o, TLV_EXPIRY_DAY, &i.expiry_day.to_be_bytes())?;
                tlv(&mut o, TLV_SPONSOR_SIG, &i.sponsor_sig)?;
                tlv(&mut o, TLV_COMMITTERS_DIGEST, &i.committers_digest)?;
                match i.pw_version {
                    None => {}
                    Some(0) => return Err(nc()),
                    Some(v) => tlv(&mut o, TLV_PW_VERSION, &v.to_be_bytes())?,
                }
            }
            (Body::Leave, KIND_LEAVE) => {}
            (
                Body::Reveal {
                    hpke_enc,
                    ciphertext,
                },
                KIND_REVEAL,
            ) => {
                if ciphertext.len() > REVEAL_CT_MAX {
                    return Err(nc());
                }
                tlv(&mut o, TLV_HPKE_ENC, hpke_enc)?;
                tlv(&mut o, TLV_CIPHERTEXT, ciphertext)?;
            }
            _ => return Err(nc()),
        }
        Ok(o)
    }

    /// `contentDecode` (§10.2 fn 17): the canonical form or `NON_CANONICAL`.
    pub fn decode(b: &[u8]) -> MlsResult<Self> {
        let mut r = Reader::new(b);
        if r.u8().ok_or_else(nc)? != 1 {
            return Err(nc());
        }
        let kind = r.u8().ok_or_else(nc)?;
        let op_id = r.fixed::<16>().ok_or_else(nc)?;
        let author_minute = r.u32().ok_or_else(nc)?;
        let timer_code = r.u8().ok_or_else(nc)?;
        if timer_code > 5 {
            return Err(nc());
        }
        let mut tlvs: Vec<(u16, &[u8])> = Vec::new();
        while !r.done() {
            let t = r.u16().ok_or_else(nc)?;
            let len = r.u16().ok_or_else(nc)?;
            let v = r.take(usize::from(len)).ok_or_else(nc)?;
            if tlvs.last().is_some_and(|(prev, _)| *prev >= t) {
                return Err(nc()); // strictly ascending, so no duplicate either
            }
            tlvs.push((t, v));
        }
        let allowed: &[u16] = match kind {
            KIND_POST => &[TLV_TEXT, TLV_REPLY_TO],
            KIND_REACTION => &[TLV_TARGET, TLV_GRAPHEME],
            KIND_INVITE_ISSUED => &[
                TLV_INVITE_ID,
                TLV_INVITE_PK,
                TLV_EXPIRY_DAY,
                TLV_SPONSOR_SIG,
                TLV_COMMITTERS_DIGEST,
                TLV_PW_VERSION,
            ],
            KIND_LEAVE => &[],
            KIND_REVEAL => &[TLV_HPKE_ENC, TLV_CIPHERTEXT],
            // FLAG (Q15) and PIN are reserved; unknown kinds are refused.
            _ => return Err(nc()),
        };
        if tlvs.iter().any(|(t, _)| !allowed.contains(t)) {
            return Err(nc());
        }
        let get = |t: u16| tlvs.iter().find(|(x, _)| *x == t).map(|(_, v)| *v);
        let fixed = |t: u16, n: usize| -> MlsResult<Option<&[u8]>> {
            match get(t) {
                Some(v) if v.len() != n => Err(nc()),
                other => Ok(other),
            }
        };
        let arr16 = |v: &[u8]| -> [u8; 16] {
            let mut a = [0u8; 16];
            a.copy_from_slice(v);
            a
        };
        let arr32 = |v: &[u8]| -> [u8; 32] {
            let mut a = [0u8; 32];
            a.copy_from_slice(v);
            a
        };
        let body = match kind {
            KIND_POST => {
                // `media_ref` (0x0003) is refused until the channel-media slice, so a POST carries
                // its text: 1 … 16 000 bytes of strict UTF-8.
                let text = get(TLV_TEXT).ok_or_else(nc)?;
                if text.is_empty() || text.len() > TEXT_MAX {
                    return Err(nc());
                }
                let text = core::str::from_utf8(text).map_err(|_| nc())?.to_owned();
                let reply_to = fixed(TLV_REPLY_TO, 16)?.map(arr16);
                Body::Post { text, reply_to }
            }
            KIND_REACTION => {
                let target = fixed(TLV_TARGET, 16)?.ok_or_else(nc)?;
                let grapheme = get(TLV_GRAPHEME).ok_or_else(nc)?;
                if grapheme.len() > GRAPHEME_MAX {
                    return Err(nc());
                }
                Body::Reaction {
                    target: arr16(target),
                    grapheme: core::str::from_utf8(grapheme).map_err(|_| nc())?.to_owned(),
                }
            }
            KIND_INVITE_ISSUED => {
                let invite_id = fixed(TLV_INVITE_ID, 16)?.ok_or_else(nc)?;
                let invite_pk = fixed(TLV_INVITE_PK, 32)?.ok_or_else(nc)?;
                let expiry = fixed(TLV_EXPIRY_DAY, 4)?.ok_or_else(nc)?;
                let sig = fixed(TLV_SPONSOR_SIG, 64)?.ok_or_else(nc)?;
                let digest = fixed(TLV_COMMITTERS_DIGEST, 32)?.ok_or_else(nc)?;
                let pw_version = match fixed(TLV_PW_VERSION, 2)? {
                    None => None,
                    Some(v) => match u16::from_be_bytes([v[0], v[1]]) {
                        0 => return Err(nc()), // absent is the one encoding of "open"
                        n => Some(n),
                    },
                };
                let mut sponsor_sig = [0u8; 64];
                sponsor_sig.copy_from_slice(sig);
                Body::InviteIssued(InviteIssued {
                    invite_id: arr16(invite_id),
                    invite_pk: arr32(invite_pk),
                    expiry_day: u32::from_be_bytes([expiry[0], expiry[1], expiry[2], expiry[3]]),
                    sponsor_sig,
                    committers_digest: arr32(digest),
                    pw_version,
                })
            }
            KIND_LEAVE => Body::Leave,
            KIND_REVEAL => {
                let enc = fixed(TLV_HPKE_ENC, 32)?.ok_or_else(nc)?;
                let ct = get(TLV_CIPHERTEXT).ok_or_else(nc)?;
                if ct.len() > REVEAL_CT_MAX {
                    return Err(nc());
                }
                Body::Reveal {
                    hpke_enc: arr32(enc),
                    ciphertext: ct.to_vec(),
                }
            }
            _ => return Err(nc()),
        };
        Ok(Self {
            kind,
            op_id,
            author_minute,
            timer_code,
            body,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn post(text: &str) -> ChannelContent {
        ChannelContent {
            kind: KIND_POST,
            op_id: [1; 16],
            author_minute: 29_000_000,
            timer_code: 4,
            body: Body::Post {
                text: text.into(),
                reply_to: None,
            },
        }
    }

    #[test]
    fn every_kind_round_trips() {
        let invite = ChannelContent {
            kind: KIND_INVITE_ISSUED,
            body: Body::InviteIssued(InviteIssued {
                invite_id: [2; 16],
                invite_pk: [3; 32],
                expiry_day: 20_730,
                sponsor_sig: [4; 64],
                committers_digest: [5; 32],
                pw_version: Some(2),
            }),
            ..post("x")
        };
        for c in [
            post("hello"),
            ChannelContent {
                body: Body::Post {
                    text: "a".repeat(TEXT_MAX),
                    reply_to: Some([9; 16]),
                },
                ..post("x")
            },
            ChannelContent {
                kind: KIND_REACTION,
                body: Body::Reaction {
                    target: [7; 16],
                    grapheme: String::new(),
                },
                ..post("x")
            },
            invite,
            ChannelContent {
                kind: KIND_LEAVE,
                body: Body::Leave,
                ..post("x")
            },
            ChannelContent {
                kind: KIND_REVEAL,
                body: Body::Reveal {
                    hpke_enc: [1; 32],
                    ciphertext: vec![2; 512],
                },
                ..post("x")
            },
            ChannelContent {
                body: Body::InviteIssued(InviteIssued {
                    invite_id: [2; 16],
                    invite_pk: [3; 32],
                    expiry_day: 20_730,
                    sponsor_sig: [4; 64],
                    committers_digest: [5; 32],
                    pw_version: None,
                }),
                kind: KIND_INVITE_ISSUED,
                ..post("x")
            },
        ] {
            let e = c.encode().unwrap();
            assert_eq!(ChannelContent::decode(&e).unwrap(), c);
            // Allocated once at its exact length: no outgrown buffer holds a copy (review of S2b).
            assert_eq!(e.capacity(), e.len(), "kind {}", c.kind);
        }
        // The longest text post: 16 027 bytes of content (V10-4's 16 000-byte post).
        let longest = ChannelContent {
            body: Body::Post {
                text: "a".repeat(TEXT_MAX),
                reply_to: None,
            },
            ..post("x")
        };
        assert_eq!(longest.encode().unwrap().len(), 16_027);
    }

    /// A content erases what it holds of a post when it is dropped (review of S2b): the text, the
    /// grapheme, a reveal's ciphertext and the op id; an `INVITE_ISSUED` record is public.
    #[test]
    fn a_content_erases_its_plaintext() {
        fn zeroizes_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        zeroizes_on_drop::<ChannelContent>();
        // What its drop runs: the whole content, header and body.
        let mut content = post("o postare");
        content.zeroize();
        assert_eq!(content.op_id, [0; 16]);
        assert!(matches!(&content.body, Body::Post { text, .. } if text.is_empty()));
        let mut post = Body::Post {
            text: "o postare".into(),
            reply_to: Some([9; 16]),
        };
        post.zeroize();
        assert!(
            matches!(&post, Body::Post { text, reply_to } if text.is_empty() && reply_to.is_none())
        );
        let mut reaction = Body::Reaction {
            target: [7; 16],
            grapheme: "👍".into(),
        };
        reaction.zeroize();
        assert!(
            matches!(&reaction, Body::Reaction { target, grapheme } if *target == [0; 16] && grapheme.is_empty())
        );
        let mut reveal = Body::Reveal {
            hpke_enc: [1; 32],
            ciphertext: vec![2; 64],
        };
        reveal.zeroize();
        assert!(
            matches!(&reveal, Body::Reveal { hpke_enc, ciphertext } if *hpke_enc == [0; 32] && ciphertext.is_empty())
        );
    }

    #[test]
    fn non_canonical_contents_are_refused() {
        let good = post("hi").encode().unwrap();
        let nc = |b: &[u8]| ChannelContent::decode(b) == Err(MlsError::new(Code::NonCanonical));
        // Trailing byte, truncation, version, timer.
        let mut t = good.clone();
        t.push(0);
        assert!(nc(&t));
        assert!(nc(&good[..good.len() - 1]));
        let mut v = good.clone();
        v[0] = 2;
        assert!(nc(&v));
        let mut tc = good.clone();
        tc[22] = 6;
        assert!(nc(&tc));
        // Unknown, reserved (FLAG, PIN) kinds.
        for k in [KIND_FLAG, KIND_PIN, 0, 8] {
            let mut b = good.clone();
            b[1] = k;
            assert!(nc(&b), "kind {k}");
        }
        // A TLV out of order, a duplicate, an unlisted one, media_ref before the media slice.
        let mut hdr = good[..HEADER_LEN].to_vec();
        let mut two = hdr.clone();
        tlv(&mut two, TLV_REPLY_TO, &[0; 16]).unwrap();
        tlv(&mut two, TLV_TEXT, b"x").unwrap();
        assert!(nc(&two));
        let mut dup = hdr.clone();
        tlv(&mut dup, TLV_TEXT, b"x").unwrap();
        tlv(&mut dup, TLV_TEXT, b"y").unwrap();
        assert!(nc(&dup));
        let mut media = hdr.clone();
        tlv(&mut media, TLV_TEXT, b"x").unwrap();
        tlv(&mut media, TLV_MEDIA_REF, &[0; 84]).unwrap();
        assert!(nc(&media));
        // A POST without text, with empty text, with invalid UTF-8, too long.
        assert!(nc(&hdr));
        let mut empty = hdr.clone();
        tlv(&mut empty, TLV_TEXT, b"").unwrap();
        assert!(nc(&empty));
        tlv(&mut hdr, TLV_TEXT, &[0xff, 0xfe]).unwrap();
        assert!(nc(&hdr));
        assert!(post(&"a".repeat(TEXT_MAX + 1)).encode().is_err());
        // INVITE_ISSUED with pw_version 0 (two encodings of "open" refused, §19.29.3).
        let mut inv = good[..HEADER_LEN].to_vec();
        inv[1] = KIND_INVITE_ISSUED;
        for (t, n) in [
            (TLV_INVITE_ID, 16),
            (TLV_INVITE_PK, 32),
            (TLV_EXPIRY_DAY, 4),
            (TLV_SPONSOR_SIG, 64),
            (TLV_COMMITTERS_DIGEST, 32),
        ] {
            tlv(&mut inv, t, &vec![1; n]).unwrap();
        }
        assert!(ChannelContent::decode(&inv).is_ok());
        let mut zero = inv.clone();
        tlv(&mut zero, TLV_PW_VERSION, &[0, 0]).unwrap();
        assert!(nc(&zero));
        let mut short_digest = inv[..inv.len() - 36].to_vec();
        tlv(&mut short_digest, TLV_COMMITTERS_DIGEST, &[1; 31]).unwrap();
        assert!(nc(&short_digest));
    }
}
