//! The arithmetic and the rules of design §3 and §4.1, checked against the reference
//! implementation: class table (§3.6), overhead claims, Padmé counts (Appendix C.1), manifest
//! space (§3.5), the sealer discipline (§3.7), the §3.4 attack table as typed codes, the labels.
//! Run with `--nocapture` to see the numbers the evidence document cites.

use ghost_media_spike::format::*;
use ghost_media_spike::sha256;
use std::collections::BTreeSet;

const K_F: [u8; 32] = [0x11; 32];
const OID: [u8; 16] = [0x22; 16];
const VIDEO: StreamFacts = StreamFacts {
    width: 1280,
    height: 720,
    duration_ms: 10_000,
};

fn desc(o: &SealedObject, kind: u8, flags: u8, oid: [u8; 16]) -> Descriptor {
    Descriptor {
        kind,
        flags,
        class_code: o.class_code,
        object_id: oid,
        key_slot: [0; 32],
        manifest_hash: o.manifest_hash,
        caption: vec![],
    }
}

fn read_all(r: &Reader, frags: &[Vec<u8>]) -> Result<Vec<u8>, Code> {
    let mut out = Vec::new();
    for i in 0..r.chunks() {
        let f: Vec<&[u8]> = (0..4)
            .map(|k| frags[4 * i as usize + k].as_slice())
            .collect();
        out.extend(r.read_chunk(i, &f)?);
    }
    Ok(out)
}

#[test]
fn class_table_and_overheads() {
    let allowance: u64 = 268_435_456;
    let mut worst: f64 = 0.0;
    for code in 0..11u8 {
        let f = CLASSES[code as usize] as u64;
        let cap = class_capacity(code);
        let relay = (f + 1) * FRAG as u64;
        println!(
            "class {code}: F={f} chunks={} cap={cap} bytes_per_relay={relay} objects_per_256MiB={}",
            f / 4,
            allowance / relay
        );
        assert_eq!(f % 4, 0);
        if code > 0 {
            let prev_cap = class_capacity(code - 1);
            let ratio = relay as f64 / (prev_cap + 1) as f64;
            worst = worst.max(ratio - 1.0);
            println!(
                "  just above class {}: overhead {:.2} %",
                code - 1,
                (ratio - 1.0) * 100.0
            );
        }
    }
    println!(
        "worst overhead just above a boundary: {:.2} %",
        worst * 100.0
    );
    assert!(worst < 0.59);
    // Mean over sizes spread evenly within a x1.5 class: 3 ln 1.5 - 1.
    println!("3 ln 1.5 - 1 = {:.4}", 3.0 * 1.5f64.ln() - 1.0);
    // Manifest space.
    let last_hash_end = HASHES_OFFSET + 32 * CLASSES[10];
    println!(
        "manifest: MP={MANIFEST_PT} hashes end at {last_hash_end}, spare {}",
        MANIFEST_PT - last_hash_end
    );
    assert_eq!(MANIFEST_PT - last_hash_end, 6_954);
    assert_eq!(COMMIT_BYTES + MANIFEST_PT + TAG, FRAG);
    // Descriptor bucket (R-D1): 86 + 1 024 = 1 110 <= 2 220.
    assert_eq!(DESCRIPTOR_FIXED + MAX_CAPTION_BYTES, 1_110);
    // Integrity bound: L'+1 for one chunk in 16-byte blocks.
    let blocks = (CHUNK_PT as f64 / 16.0).ceil() + 1.0;
    println!(
        "chunk blocks L'+1 = {blocks} = 2^{:.3}; forgery bound 2^{:.2}",
        blocks.log2(),
        blocks.log2() - 103.0
    );
}

#[test]
fn padme_class_counts() {
    // Appendix C.1: over byte lengths 1 MiB … 50 MiB in 256-byte steps, rounded up to whole
    // chunks, count the distinct object sizes above class 0; and Padmé over fragment counts.
    let mut sizes = BTreeSet::new();
    let mut frag_counts = BTreeSet::new();
    let mut l: u64 = 1 << 20;
    while l <= MAX_CONTENT {
        let p = padme(l).min(MAX_CONTENT);
        let chunks = p.div_ceil(CHUNK_PT as u64);
        if chunks * CHUNK_PT as u64 > IMAGE_MAX_CONTENT {
            sizes.insert(chunks);
        }
        let frags = 4 * l.div_ceil(CHUNK_PT as u64);
        let pf = padme(frags);
        let pf4 = pf.div_ceil(4) * 4;
        if pf4 > 16 {
            frag_counts.insert(pf4);
        }
        l += 256;
    }
    println!(
        "Padme over bytes, rounded to chunks: {} classes above class 0",
        sizes.len()
    );
    println!(
        "Padme over fragment counts (rounded to multiples of 4): {} classes above 16",
        frag_counts.len()
    );
}

#[test]
fn sealer_discipline() {
    // Lookahead: a full chunk is held until the next byte arrives.
    let mut s = Sealer::begin(&K_F, &OID, KIND_VIDEO, 0, 10);
    assert_eq!(s.append(&vec![1u8; CHUNK_PT]).unwrap(), 0);
    assert_eq!(s.append(&[2u8]).unwrap(), 4);
    // Index reuse is refused.
    assert_eq!(s.seal_index(0, false, &[]), Err(Code::IndexReused));
    // Piece size does not change a single byte.
    let content = sha256ctr(b"pieces", 3 * CHUNK_PT + 5);
    let reference = seal_object(&K_F, &OID, KIND_VIDEO, 0, &content, VIDEO, &[], 1 << 20).unwrap();
    for piece in [7usize, 4096, CHUNK_PT - 1, CHUNK_PT, CHUNK_PT + 1] {
        let o = seal_object(&K_F, &OID, KIND_VIDEO, 0, &content, VIDEO, &[], piece).unwrap();
        assert_eq!(o.fragments, reference.fragments);
        assert_eq!(o.manifest_blob, reference.manifest_blob);
    }
    // Exactly n full chunks: the held chunk is the last one.
    let exact = sha256ctr(b"exact", 4 * CHUNK_PT);
    let o = seal_object(&K_F, &OID, KIND_VIDEO, 0, &exact, VIDEO, &[], 50_000).unwrap();
    assert_eq!(o.class_code, 0);
    // Oversize: images above IMAGE_MAX_CONTENT, anything above MAX_CONTENT or above max_class.
    let mut img = Sealer::begin(&K_F, &OID, KIND_IMAGE, 0, 10);
    assert_eq!(
        img.append(&vec![0u8; IMAGE_MAX_CONTENT as usize + 1]),
        Err(Code::Oversize)
    );
    let mut small = Sealer::begin(&K_F, &OID, KIND_VIDEO, 0, 0);
    assert_eq!(
        small.append(&vec![0u8; IMAGE_MAX_CONTENT as usize + 1]),
        Err(Code::Oversize)
    );
    // An empty object cannot be sealed.
    let empty = Sealer::begin(&K_F, &OID, KIND_VIDEO, 0, 10);
    assert!(empty.finish(VIDEO, &[]).is_err());
    // The nonce registry of §3.7 point 5 catches a resumed preparation that reuses the key:
    // different plaintext under the same (K_p, nonce).
    let a = {
        let mut s = Sealer::begin(&K_F, &OID, KIND_VIDEO, 0, 10);
        s.append(&sha256ctr(b"first transcode", 2 * CHUNK_PT))
            .unwrap();
        s.nonce_log.clone()
    };
    let b = {
        let mut s = Sealer::begin(&K_F, &OID, KIND_VIDEO, 0, 10);
        s.append(&sha256ctr(b"second transcode", 2 * CHUNK_PT))
            .unwrap();
        s.nonce_log.clone()
    };
    let reg: BTreeSet<_> = a.iter().collect();
    assert!(
        b.iter().any(|x| reg.contains(x)),
        "same key twice must repeat a (K_p, nonce)"
    );
}

#[test]
fn attack_table_gives_typed_codes() {
    let content = sha256ctr(b"attack", CHUNK_PT + 1000); // class 0, 4 chunks, content in 2
    let o = seal_object(&K_F, &OID, KIND_VIDEO, 0, &content, VIDEO, &[], 1 << 20).unwrap();
    let d = desc(&o, KIND_VIDEO, 0, OID);
    let r = Reader::open(&K_F, &d, &o.manifest_blob).unwrap();
    assert_eq!(read_all(&r, &o.fragments).unwrap(), content);
    let n = r.chunks();
    let frag = |fr: &Vec<Vec<u8>>, i: u32| -> Vec<Vec<u8>> {
        (0..4).map(|k| fr[4 * i as usize + k].clone()).collect()
    };
    let call = |r: &Reader, i: u32, f: &Vec<Vec<u8>>| {
        let v: Vec<&[u8]> = f.iter().map(|x| x.as_slice()).collect();
        r.read_chunk(i, &v)
    };

    // 1. A flipped byte in a fragment, sampled positions of every fragment: the hash catches it.
    let mut flips = 0;
    for j in 0..o.fragments.len() {
        for pos in (0..FRAG).step_by(4099) {
            let mut fr = o.fragments.clone();
            fr[j][pos] ^= 0x01;
            let i = (j / 4) as u32;
            assert_eq!(call(&r, i, &frag(&fr, i)), Err(Code::HashMismatch));
            flips += 1;
        }
    }
    // The same flip under a manifest that names the flipped hash (a sender re-hashing its own
    // object): the chunk tag catches it and no content byte is returned.
    let mut fr = o.fragments.clone();
    fr[1][100] ^= 0x80;
    let mut m2 = o.manifest.clone();
    m2.hashes[1] = sha256(&fr[1]);
    let keys = derive(&K_F, &OID);
    let blob2 = seal_manifest(&keys, &OID, &m2.encode().unwrap());
    let mut d2 = d.clone();
    d2.manifest_hash = sha256(&blob2);
    let r2 = Reader::open(&K_F, &d2, &blob2).unwrap();
    assert_eq!(call(&r2, 0, &frag(&fr, 0)), Err(Code::NotOpen));
    println!("single-bit flips checked: {flips} (hash), 1 (tag)");

    // 2. A fragment at another position (hash list order) and a swapped chunk (nonce index).
    let mut swapped = o.fragments.clone();
    swapped.swap(0, 1);
    assert_eq!(call(&r, 0, &frag(&swapped, 0)), Err(Code::HashMismatch));
    let mut m3 = o.manifest.clone();
    let mut chunk_swap = o.fragments.clone();
    for k in 0..4 {
        chunk_swap.swap(k, 4 + k);
        m3.hashes.swap(k, 4 + k);
    }
    let blob3 = seal_manifest(&keys, &OID, &m3.encode().unwrap());
    let mut d3 = d.clone();
    d3.manifest_hash = sha256(&blob3);
    let r3 = Reader::open(&K_F, &d3, &blob3).unwrap();
    assert_eq!(call(&r3, 0, &frag(&chunk_swap, 0)), Err(Code::NotOpen));

    // 3. Truncation: the final chunk re-sealed without the last flag (by the key holder).
    let mut trunc = o.fragments.clone();
    let pad = vec![0u8; CHUNK_PT];
    let ct = seal_chunk(&keys.k_p, &OID, KIND_VIDEO, n - 1, false, &pad);
    let mut m4 = o.manifest.clone();
    for (k, f) in fragments_of(&ct).into_iter().enumerate() {
        m4.hashes[4 * (n as usize - 1) + k] = sha256(&f);
        trunc[4 * (n as usize - 1) + k] = f;
    }
    let blob4 = seal_manifest(&keys, &OID, &m4.encode().unwrap());
    let mut d4 = d.clone();
    d4.manifest_hash = sha256(&blob4);
    let r4 = Reader::open(&K_F, &d4, &blob4).unwrap();
    assert_eq!(call(&r4, n - 1, &frag(&trunc, n - 1)), Err(Code::NotOpen));

    // 4. A chunk of another object: same K_f, another object_id (another K_p), and the AD alone.
    let oid2 = [0x33; 16];
    let other = seal_object(&K_F, &oid2, KIND_VIDEO, 0, &content, VIDEO, &[], 1 << 20).unwrap();
    let mut m5 = o.manifest.clone();
    let mut mixed = o.fragments.clone();
    for (k, m) in mixed.iter_mut().enumerate().take(4) {
        *m = other.fragments[k].clone();
        m5.hashes[k] = sha256(m);
    }
    let blob5 = seal_manifest(&keys, &OID, &m5.encode().unwrap());
    let mut d5 = d.clone();
    d5.manifest_hash = sha256(&blob5);
    let r5 = Reader::open(&K_F, &d5, &blob5).unwrap();
    assert_eq!(call(&r5, 0, &frag(&mixed, 0)), Err(Code::NotOpen));
    let ct_kind = seal_chunk(&keys.k_p, &OID, KIND_IMAGE, 0, false, &content[..CHUNK_PT]);
    let mut m6 = o.manifest.clone();
    let mut kinded = o.fragments.clone();
    for (k, f) in fragments_of(&ct_kind).into_iter().enumerate() {
        m6.hashes[k] = sha256(&f);
        kinded[k] = f;
    }
    let blob6 = seal_manifest(&keys, &OID, &m6.encode().unwrap());
    let mut d6 = d.clone();
    d6.manifest_hash = sha256(&blob6);
    let r6 = Reader::open(&K_F, &d6, &blob6).unwrap();
    assert_eq!(
        call(&r6, 0, &frag(&kinded, 0)),
        Err(Code::NotOpen),
        "kind is in AD_c"
    );

    // 5. Duplicated hash in the manifest: NON_CANONICAL at open.
    let mut m7 = o.manifest.clone();
    m7.hashes[2] = m7.hashes[1];
    assert_eq!(m7.encode(), Err(Code::NonCanonical));

    // 6. Manifest under another key / wrong commitment / flipped manifest byte / descriptor mismatch.
    assert_eq!(
        Reader::open(&[0x12; 32], &d, &o.manifest_blob).err(),
        Some(Code::CommitMismatch)
    );
    let mut mb = o.manifest_blob.clone();
    mb[40] ^= 1;
    let mut d8 = d.clone();
    d8.manifest_hash = sha256(&mb);
    assert_eq!(Reader::open(&K_F, &d8, &mb).err(), Some(Code::NotOpen));
    assert_eq!(
        Reader::open(&K_F, &desc(&o, KIND_VIDEO, 0, OID), &mb).err(),
        Some(Code::HashMismatch)
    );
    let mut d9 = d.clone();
    d9.flags = FLAG_VIEW_ONCE;
    assert_eq!(
        Reader::open(&K_F, &d9, &o.manifest_blob).err(),
        Some(Code::NonCanonical)
    );
    let mut d10 = d.clone();
    d10.class_code = 1;
    assert_eq!(
        Reader::open(&K_F, &d10, &o.manifest_blob).err(),
        Some(Code::NonCanonical)
    );

    // 7. A non-zero pad byte in the content's last chunk (key holder): NON_CANONICAL.
    let mut chunk1 = content[CHUNK_PT..].to_vec();
    chunk1.resize(CHUNK_PT, 0);
    chunk1[CHUNK_PT - 1] = 1;
    let ctp = seal_chunk(&keys.k_p, &OID, KIND_VIDEO, 1, false, &chunk1);
    let mut m11 = o.manifest.clone();
    let mut padded = o.fragments.clone();
    for (k, f) in fragments_of(&ctp).into_iter().enumerate() {
        m11.hashes[4 + k] = sha256(&f);
        padded[4 + k] = f;
    }
    let blob11 = seal_manifest(&keys, &OID, &m11.encode().unwrap());
    let mut d11 = d.clone();
    d11.manifest_hash = sha256(&blob11);
    let r11 = Reader::open(&K_F, &d11, &blob11).unwrap();
    assert_eq!(call(&r11, 1, &frag(&padded, 1)), Err(Code::NonCanonical));

    // 8. Manifest rules: non-zero preview pad, image above class 0, view-once with a preview,
    //    off-ladder geometry, a video over VIDEO_MAX_MS, index out of range.
    let mut mp = o.manifest.encode().unwrap();
    mp[PREVIEW_OFFSET + 5] = 1; // preview_len = 0, so this is pad
    let blob12 = seal_manifest(&keys, &OID, &mp);
    let mut d12 = d.clone();
    d12.manifest_hash = sha256(&blob12);
    assert_eq!(
        Reader::open(&K_F, &d12, &blob12).err(),
        Some(Code::NonCanonical)
    );
    let mut m13 = o.manifest.clone();
    m13.kind = KIND_IMAGE;
    m13.width = 2048;
    m13.height = 1536;
    m13.duration_ms = 0;
    assert!(m13.encode().is_ok());
    m13.width = 2000;
    assert_eq!(m13.encode(), Err(Code::NonCanonical));
    let mut m14 = o.manifest.clone();
    m14.flags = FLAG_VIEW_ONCE;
    m14.preview = vec![1, 2, 3];
    assert_eq!(m14.encode(), Err(Code::NonCanonical));
    let mut m15 = o.manifest.clone();
    m15.duration_ms = VIDEO_MAX_MS + 1;
    assert_eq!(m15.encode(), Err(Code::NonCanonical));
    let f = frag(&o.fragments, 0);
    let v: Vec<&[u8]> = f.iter().map(|x| x.as_slice()).collect();
    assert_eq!(r.read_chunk(n, &v), Err(Code::IndexRange));
}

#[test]
fn descriptor_rules() {
    let d = Descriptor {
        kind: KIND_IMAGE,
        flags: 0,
        class_code: 0,
        object_id: OID,
        key_slot: [0; 32],
        manifest_hash: [5; 32],
        caption: "ok".into(),
    };
    assert_eq!(Descriptor::decode(&d.encode()).unwrap(), d);
    let mut bad = d.encode();
    bad[3] = 1; // image with class 1
    assert_eq!(Descriptor::decode(&bad), Err(Code::NonCanonical));
    let mut bad2 = d.encode();
    bad2[2] = 2; // unknown flag
    assert_eq!(Descriptor::decode(&bad2), Err(Code::NonCanonical));
    let mut bad3 = d.clone();
    bad3.caption = vec![0xC0, 0x80]; // overlong NUL
    assert_eq!(Descriptor::decode(&bad3.encode()), Err(Code::NonCanonical));
    let mut bad4 = d.clone();
    bad4.caption = vec![b'a'; MAX_CAPTION_BYTES + 1];
    assert_eq!(Descriptor::decode(&bad4.encode()), Err(Code::NonCanonical));
    let mut trailing = d.encode();
    trailing.push(0);
    assert_eq!(Descriptor::decode(&trailing), Err(Code::NonCanonical));
}

#[test]
fn label_prefix_rule() {
    // §3.2: "no label is a prefix of another" (the DerivationLabelsTest rule).
    let hkdf_labels: [&[u8]; 3] = [LABEL_PAYLOAD, LABEL_MANIFEST, LABEL_COMMIT];
    for a in hkdf_labels {
        for b in hkdf_labels {
            if a != b {
                assert!(
                    !b.starts_with(a),
                    "{} prefixes {}",
                    String::from_utf8_lossy(a),
                    String::from_utf8_lossy(b)
                );
            }
        }
    }
    // Review I13 (2026-10-04): the rule ranges over every string the format uses (HKDF infos, the
    // AEAD associated-data prefixes, the op label, the wrap label). The 2026-09-25 labels used
    // "ghost/v1/media/manifest" both as K_m's info and as AD_m's prefix; the AD prefixes now live
    // under "ghost/v1/media/ad/", so no string of the set is a prefix of another.
    let wrap = [WRAP_LABEL, WRAP_NAME_MEDIA_FILE_KEY].concat();
    let all: [&[u8]; 7] = [
        LABEL_PAYLOAD,
        LABEL_MANIFEST,
        LABEL_COMMIT,
        AD_CHUNK,
        AD_MANIFEST,
        LABEL_OP,
        &wrap,
    ];
    let mut shared = Vec::new();
    for (i, a) in all.iter().enumerate() {
        for (j, b) in all.iter().enumerate() {
            if i < j && (b.starts_with(a) || a.starts_with(b)) {
                shared.push((
                    String::from_utf8_lossy(a).to_string(),
                    String::from_utf8_lossy(b).to_string(),
                ));
            }
        }
    }
    println!("label pairs where one is a prefix of the other, over every label: {shared:?}");
    assert!(
        shared.is_empty(),
        "no label of the format may be a prefix of another"
    );
}
