//! §3.9: the vector file is current, and every case opens, reads back and binds its key.

use ghost_media_spike::format::*;
use ghost_media_spike::vectors::{build, cases, render};

#[test]
fn vector_file_is_current() {
    let fresh = render();
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/vectors/media_object.txt");
    if std::env::var("GHOST_WRITE_VECTORS").is_ok() {
        std::fs::write(path, &fresh).expect("write vectors");
    }
    let committed = std::fs::read_to_string(path)
        .expect("vectors/media_object.txt (GHOST_WRITE_VECTORS=1 to create)");
    assert_eq!(
        committed.replace("\r\n", "\n"),
        fresh,
        "vectors/media_object.txt differs from the generator"
    );
}

#[test]
fn every_case_round_trips_and_binds() {
    for c in cases() {
        let b = build(&c);
        assert_eq!(b.object.manifest_blob.len(), FRAG);
        assert_eq!(
            b.object.fragments.len(),
            CLASSES[b.object.class_code as usize]
        );
        let encoded = b.descriptor.encode();
        assert!(encoded.len() <= DESCRIPTOR_FIXED + MAX_CAPTION_BYTES);
        let desc = Descriptor::decode(&encoded).expect("descriptor decodes");
        let r = Reader::open(&c.k_f, &desc, &b.object.manifest_blob).expect("reader opens");
        let mut back = Vec::new();
        for i in 0..r.chunks() {
            let f: Vec<&[u8]> = (0..4)
                .map(|k| b.object.fragments[4 * i as usize + k].as_slice())
                .collect();
            back.extend_from_slice(&r.read_chunk(i, &f).expect("chunk"));
        }
        assert_eq!(back, b.content, "{}", c.name);
        assert_eq!(r.manifest.preview, b.preview);
        // key_env opens only under its own binding (§4.2).
        let mh = b.object.manifest_hash;
        let good = key_env_binding(ROLE_OUT, &c.dest_id, &c.object_id, &mh);
        assert_eq!(
            unwrap_key_env(&c.state_key, &good, &b.key_env_out),
            Ok(c.k_f)
        );
        assert_eq!(b.key_env_out.len(), 60);
        let inb = key_env_binding(ROLE_IN, &c.dest_id, &c.object_id, &mh);
        assert_eq!(unwrap_key_env(&c.state_key, &inb, &b.key_env_in), Ok(c.k_f));
        // The two wraps never share (state_key, nonce): their nonce prefixes differ.
        assert_ne!(b.key_env_out[..12], b.key_env_in[..12]);
        let mut other_dest = c.dest_id;
        other_dest[0] ^= 1;
        let mut other_obj = c.object_id;
        other_obj[15] ^= 1;
        let mut other_mh = mh;
        other_mh[31] ^= 1;
        for bad in [
            key_env_binding(ROLE_IN, &c.dest_id, &c.object_id, &mh),
            key_env_binding(ROLE_OUT, &other_dest, &c.object_id, &mh),
            key_env_binding(ROLE_OUT, &c.dest_id, &other_obj, &mh),
            key_env_binding(ROLE_OUT, &c.dest_id, &c.object_id, &other_mh),
        ] {
            assert_eq!(
                unwrap_key_env(&c.state_key, &bad, &b.key_env_out),
                Err(Code::StateCorrupt)
            );
        }
    }
}
