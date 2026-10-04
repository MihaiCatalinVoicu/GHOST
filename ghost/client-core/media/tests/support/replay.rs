//! The vector replay engine of the Rust side: byte recipes, the three vector objects, and the
//! negative-case operations and steps of `protocol/test-vectors/media_object.txt`. The JDK replay
//! (`android/media/src/test/.../MediaVectorReplayTest.kt`) implements the same vocabulary from the
//! file's header, sharing no code with this.
#![allow(dead_code, clippy::disallowed_methods)]

use chacha20poly1305::aead::AeadInOut;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};

use ghost_client_media::class::SizeClass;
use ghost_client_media::consts::{CHUNK_CT, CHUNK_PT, FRAG, HASHES_OFFSET, MANIFEST_PT};
use ghost_client_media::keys::{derive, sha256, Derived};
use ghost_client_media::manifest::seal_blob;
use ghost_client_media::stream::{chunk_ad, chunk_nonce};
use ghost_client_media::{
    Code, Descriptor, Expected, FileKey, KeySlot, MediaKind, ObjectId, Reader, Sealer,
};

use super::{golden, grey_jpeg, without_mfra};

/// A byte recipe: `hex:<hex>`, `golden:<path under media3-1.11.1/>` with an optional `[a..b]`
/// (either bound may be empty), and `+` between parts.
pub fn recipe(r: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for part in r.split(" + ") {
        if let Some(h) = part.strip_prefix("hex:") {
            out.extend(hex::decode(h).expect("hex recipe"));
        } else if let Some(g) = part.strip_prefix("golden:") {
            let (path, range) = match g.split_once('[') {
                Some((p, r)) => (p, Some(r.strip_suffix(']').expect("]"))),
                None => (g, None),
            };
            let data = golden(path);
            let (a, b) = match range {
                None => (0, data.len()),
                Some(r) => {
                    let (a, b) = r.split_once("..").expect("a..b");
                    (
                        if a.is_empty() {
                            0
                        } else {
                            a.parse().expect("a")
                        },
                        if b.is_empty() {
                            data.len()
                        } else {
                            b.parse().expect("b")
                        },
                    )
                }
            };
            out.extend_from_slice(&data[a..b]);
        } else if part.is_empty() {
        } else {
            panic!("unknown recipe part {part}");
        }
    }
    out
}

/// One vector object.
#[derive(Clone)]
pub struct ObjSpec {
    pub name: &'static str,
    pub k_f: [u8; 32],
    pub object_id: [u8; 16],
    pub kind: MediaKind,
    pub view_once: bool,
    pub content: &'static str,
    pub preview: Option<(u16, u16)>,
    pub caption: &'static str,
}

fn seq32(start: u8) -> [u8; 32] {
    core::array::from_fn(|i| start.wrapping_add(i as u8))
}
fn seq16(start: u8) -> [u8; 16] {
    core::array::from_fn(|i| start.wrapping_add(i as u8))
}

/// The three objects of `media_object.txt`: an image (class 0, a STRIP golden), a video filling
/// class 0 (a quad golden) and a view-once video of class 2 (the 1080p60 golden's output), each
/// from the API 35 emulator's goldens.
pub fn specs() -> Vec<ObjSpec> {
    vec![
        ObjSpec {
            name: "image_class0",
            k_f: seq32(0x00),
            object_id: seq16(0xa0),
            kind: MediaKind::Image,
            view_once: false,
            content: "golden:api35-emulator/strip_orient1.jpg",
            preview: Some((320, 208)),
            caption: "o fotografie",
        },
        ObjSpec {
            name: "video_class0",
            k_f: seq32(0x10),
            object_id: seq16(0xb0),
            kind: MediaKind::Video,
            view_once: false,
            content: "golden:api35-emulator/quad_land.fmp4",
            preview: Some((320, 176)),
            caption: "",
        },
        ObjSpec {
            name: "video_class2_view_once",
            k_f: seq32(0x20),
            object_id: seq16(0xc0),
            kind: MediaKind::Video,
            view_once: true,
            content: "golden:api35-emulator/land1080p60.fmp4",
            preview: None,
            caption: "vezi o singură dată",
        },
    ]
}

/// An honest object, sealed by the crate.
pub struct Honest {
    pub spec: ObjSpec,
    pub content: Vec<u8>,
    pub preview: Vec<u8>,
    pub derived: Derived,
    pub chunks: Vec<Vec<u8>>,
    pub plaintexts: Vec<Vec<u8>>,
    pub mp: Vec<u8>,
    pub blob: Vec<u8>,
    pub manifest_hash: [u8; 32],
    pub class: SizeClass,
    pub width: u16,
    pub height: u16,
    pub duration_ms: u32,
    pub descriptor: Vec<u8>,
}

/// Seals a spec with the crate's sealer (a video without its `mfra`, which the sealer appends) and
/// checks that the sealed content is the recipe's bytes.
pub fn honest(spec: &ObjSpec) -> Honest {
    let content = recipe(spec.content);
    let preview = spec
        .preview
        .map(|(w, h)| grey_jpeg(w, h))
        .unwrap_or_default();
    let key = FileKey::from_bytes(spec.k_f);
    let id = ObjectId::from_bytes(spec.object_id);
    let mut sealer = Sealer::begin(
        key.clone(),
        id,
        spec.kind,
        spec.view_once,
        SizeClass::LARGEST,
    );
    let input = match spec.kind {
        MediaKind::Image => content.clone(),
        MediaKind::Video => without_mfra(&content),
    };
    let mut sealed_chunks = Vec::new();
    for piece in input.chunks(100_003) {
        sealed_chunks.extend(sealer.append(piece).expect("append"));
    }
    let sealed = sealer.finish(&preview).expect("finish");
    sealed_chunks.extend(sealed.chunks.iter().cloned());
    let n = sealed.manifest.fields.class.chunks() as usize;
    assert_eq!(sealed_chunks.len(), n);
    let mut plaintexts = Vec::new();
    for i in 0..n {
        let start = (i * CHUNK_PT).min(content.len());
        let end = ((i + 1) * CHUNK_PT).min(content.len());
        let mut p = content[start..end].to_vec();
        p.resize(CHUNK_PT, 0);
        plaintexts.push(p);
    }
    let derived = derive(&key, &id);
    let mp = sealed.manifest.encode_plaintext().expect("mp").to_vec();
    let descriptor = Descriptor {
        kind: spec.kind,
        view_once: spec.view_once,
        class: sealed.manifest.fields.class,
        object_id: id,
        key_slot: KeySlot::zero(),
        manifest_hash: sealed.manifest_hash,
        caption: spec.caption.to_string(),
    }
    .encode()
    .expect("descriptor");
    let f = sealed.manifest.fields;
    Honest {
        spec: spec.clone(),
        content,
        preview,
        derived,
        chunks: sealed_chunks.into_iter().map(|c| c.ciphertext).collect(),
        plaintexts,
        mp,
        blob: sealed.manifest_blob.clone(),
        manifest_hash: sealed.manifest_hash,
        class: f.class,
        width: f.width,
        height: f.height,
        duration_ms: f.duration_ms,
        descriptor,
    }
}

/// A negative case's state: the object as an attacker holding its keys may change it.
pub struct State {
    pub key: FileKey,
    pub derived: Derived,
    pub object_id: ObjectId,
    pub kind: MediaKind,
    pub chunks: Vec<Vec<u8>>,
    pub plaintexts: Vec<Vec<u8>>,
    pub mp: Vec<u8>,
    pub blob: Vec<u8>,
    pub expected: Expected,
    pub walked: (u16, u16, u32),
}

impl State {
    pub fn of(h: &Honest) -> State {
        State {
            key: FileKey::from_bytes(h.spec.k_f),
            derived: derive(
                &FileKey::from_bytes(h.spec.k_f),
                &ObjectId::from_bytes(h.spec.object_id),
            ),
            object_id: ObjectId::from_bytes(h.spec.object_id),
            kind: h.spec.kind,
            chunks: h.chunks.clone(),
            plaintexts: h.plaintexts.clone(),
            mp: h.mp.clone(),
            blob: h.blob.clone(),
            expected: Expected {
                object_id: ObjectId::from_bytes(h.spec.object_id),
                kind: h.spec.kind,
                view_once: h.spec.view_once,
                class: h.class,
                manifest_hash: h.manifest_hash,
            },
            walked: (h.width, h.height, h.duration_ms),
        }
    }

    fn reseal_manifest(&mut self) {
        self.blob = seal_blob(&self.derived, &self.object_id, &self.mp).expect("seal");
        self.expected.manifest_hash = sha256(&self.blob);
    }

    fn seal(
        &self,
        i: usize,
        last: bool,
        object_id: &ObjectId,
        kind: MediaKind,
        plaintext: &[u8],
    ) -> Vec<u8> {
        let mut buf = plaintext.to_vec();
        let cipher = ChaCha20Poly1305::new(self.derived.payload.as_bytes().into());
        let tag = cipher
            .encrypt_inout_detached(
                &Nonce::from(chunk_nonce(i as u32, last)),
                &chunk_ad(object_id, kind),
                buf.as_mut_slice().into(),
            )
            .expect("seal");
        buf.extend_from_slice(tag.as_slice());
        assert_eq!(buf.len(), CHUNK_CT);
        buf
    }

    fn honest_last(&self, i: usize) -> bool {
        i + 1 == self.plaintexts.len()
    }

    /// Applies one operation of the vocabulary.
    pub fn apply(&mut self, op: &str, others: &[Honest]) {
        let w: Vec<&str> = op.split_whitespace().collect();
        let num = |k: usize| -> usize { w[k].parse().expect("number") };
        match w[0] {
            "flip_fragment" => {
                let (j, byte, bit) = (num(1), num(2), num(3));
                self.chunks[j / 4][(j % 4) * FRAG + byte] ^= 1 << bit;
            }
            "swap_fragments" => {
                let (a, b) = (num(1), num(2));
                let fa = self.chunks[a / 4][(a % 4) * FRAG..(a % 4 + 1) * FRAG].to_vec();
                let fb = self.chunks[b / 4][(b % 4) * FRAG..(b % 4 + 1) * FRAG].to_vec();
                self.chunks[a / 4][(a % 4) * FRAG..(a % 4 + 1) * FRAG].copy_from_slice(&fb);
                self.chunks[b / 4][(b % 4) * FRAG..(b % 4 + 1) * FRAG].copy_from_slice(&fa);
            }
            "swap_chunks" => self.chunks.swap(num(1), num(2)),
            "foreign_fragment" => {
                let (j, other, j2) = (num(1), w[2], num(3));
                let o = others
                    .iter()
                    .find(|h| h.spec.name == other)
                    .expect("other object");
                let f = o.chunks[j2 / 4][(j2 % 4) * FRAG..(j2 % 4 + 1) * FRAG].to_vec();
                self.chunks[j / 4][(j % 4) * FRAG..(j % 4 + 1) * FRAG].copy_from_slice(&f);
            }
            "reseal_chunk" => {
                let (i, last) = (num(1), num(2) == 1);
                let p = self.plaintexts[i].clone();
                self.chunks[i] = self.seal(i, last, &self.object_id.clone(), self.kind, &p);
            }
            "reseal_chunk_ad" => {
                let i = num(1);
                let id: [u8; 16] = hex::decode(w[2]).expect("hex").try_into().expect("16");
                let kind = MediaKind::from_byte(num(3) as u8).expect("kind");
                let p = self.plaintexts[i].clone();
                let last = self.honest_last(i);
                self.chunks[i] = self.seal(i, last, &ObjectId::from_bytes(id), kind, &p);
            }
            "reseal_chunk_pad" => {
                let (i, at, v) = (num(1), num(2), num(3) as u8);
                let mut p = self.plaintexts[i].clone();
                p[at] = v;
                let last = self.honest_last(i);
                self.chunks[i] = self.seal(i, last, &self.object_id.clone(), self.kind, &p);
            }
            "rehash" => {
                for (j, f) in self.chunks.iter().flat_map(|c| c.chunks(FRAG)).enumerate() {
                    let at = HASHES_OFFSET + 32 * j;
                    self.mp[at..at + 32].copy_from_slice(&sha256(f));
                }
                self.reseal_manifest();
            }
            "manifest_set" => {
                let at = num(1);
                let bytes = hex::decode(w[2]).expect("hex");
                self.mp[at..at + bytes.len()].copy_from_slice(&bytes);
                self.reseal_manifest();
            }
            "manifest_flip" => self.blob[num(1)] ^= 1 << num(2),
            "manifest_flip_rehash" => {
                self.blob[num(1)] ^= 1 << num(2);
                self.expected.manifest_hash = sha256(&self.blob);
            }
            "key" => {
                self.key =
                    FileKey::from_bytes(hex::decode(w[1]).expect("hex").try_into().expect("32"));
            }
            "expect" => match w[1] {
                "kind" => self.expected.kind = MediaKind::from_byte(num(2) as u8).expect("kind"),
                "view_once" => self.expected.view_once = num(2) == 1,
                "class_code" => {
                    self.expected.class = SizeClass::from_code(num(2) as u8).expect("class")
                }
                other => panic!("unknown expect field {other}"),
            },
            "truncate_class" => {
                let c = SizeClass::from_code(num(1) as u8).expect("class");
                self.mp[3] = c.code();
                let len = u64::from_be_bytes(self.mp[20..28].try_into().unwrap()).min(c.capacity());
                self.mp[20..28].copy_from_slice(&len.to_be_bytes());
                let end = HASHES_OFFSET + 32 * c.fragments() as usize;
                for b in &mut self.mp[end..MANIFEST_PT] {
                    *b = 0;
                }
                self.chunks.truncate(c.chunks() as usize);
                self.plaintexts.truncate(c.chunks() as usize);
                self.expected.class = c;
                self.reseal_manifest();
            }
            other => panic!("unknown operation {other}"),
        }
    }

    /// Runs a step; `Ok` when it and every step it implies pass.
    pub fn run(&self, step: &str) -> Result<(), Code> {
        let mut reader =
            Reader::open(&self.key, &self.expected, &self.blob).map_err(|e| e.code())?;
        let w: Vec<&str> = step.split_whitespace().collect();
        match w[0] {
            "open" => Ok(()),
            "read" => {
                let i: u32 = w[1].parse().expect("index");
                let empty = vec![0u8; CHUNK_CT];
                let frags = self.chunks.get(i as usize).unwrap_or(&empty);
                let mut out = vec![0u8; CHUNK_PT];
                let r = reader
                    .read_chunk(i, frags, &mut out)
                    .map(|_| ())
                    .map_err(|e| e.code());
                if r.is_err() {
                    assert!(
                        out.iter().all(|b| *b == 0),
                        "a refused chunk exposed content"
                    );
                }
                r
            }
            "validate" => {
                for (i, c) in self.chunks.iter().enumerate() {
                    reader.validate_chunk(i as u32, c).map_err(|e| e.code())?;
                }
                reader.validate_finish().map(|_| ()).map_err(|e| e.code())
            }
            other => panic!("unknown step {other}"),
        }
    }
}
