//! Host (and emulator) tool of the Phase 11 S0 spike. Evidence tooling, not product code.
//!
//! ```text
//! mediatool jpeg <file>...              marker walk, §8.2 canonicaliser verdict (V-M6)
//! mediatool mp4 <file>                  box tree, tracks, fragments, sync starts, frame rate,
//!                                       NAL and SEI payload types, AAC first elements (V-M2/3/12/24)
//! mediatool nalcmp <source> <output>    source NAL units / AAC frames found byte for byte in output (V-M17)
//! mediatool addmfra <in> <out>          appends GHOST's mfra (tfra for the video track, mfro) (V-M2)
//! mediatool canary <file> <text>...     ASCII, UTF-16LE and UTF-16BE search
//! mediatool bench [bytes]               seal and open throughput of one object (V-M9 host/emulator)
//! ```

use ghost_media_spike::format::{self, Descriptor, Reader, StreamFacts, FRAG, KIND_VIDEO};
use ghost_media_spike::{hex, jpeg, mp4, sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

fn read(path: &str) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|e| {
        eprintln!("{path}: {e}");
        std::process::exit(2)
    })
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("jpeg") => {
            for p in &args[2..] {
                let d = read(p);
                let w = jpeg::walk(&d);
                println!("== {p} ({} B, sha256 {})", d.len(), hex(&sha256(&d)));
                print!("{}", jpeg::describe(&w));
                match jpeg::canonicalize(&d) {
                    Ok(c) => println!(
                        "canonicalize: OK, {} B, dropped {} B, fixed point: {}",
                        c.len(),
                        d.len() - c.len(),
                        jpeg::canonicalize(&c).map(|c2| c2 == c).unwrap_or(false)
                    ),
                    Err(e) => println!("canonicalize: NON_CANONICAL ({e})"),
                }
            }
        }
        Some("canon") => {
            // jpegCanonicalize of design §8.2: writes the canonical form (or fails).
            let d = read(&args[2]);
            match jpeg::canonicalize(&d) {
                Ok(c) => {
                    std::fs::write(&args[3], &c).expect("write");
                    println!("{} -> {}: {} B -> {} B", args[2], args[3], d.len(), c.len());
                }
                Err(e) => {
                    println!("{}: NON_CANONICAL ({e})", args[2]);
                    std::process::exit(1)
                }
            }
        }
        Some("mp4") => mp4_report(&args[2]),
        Some("nalcmp") => nalcmp(&args[2], &args[3]),
        Some("addmfra") => {
            let d = read(&args[2]);
            let top = mp4::parse_boxes(&d, 0, d.len()).expect("parse");
            let tracks = mp4::tracks(&d, &top);
            let video = tracks
                .iter()
                .find(|t| t.handler == "vide")
                .map(|t| t.id)
                .expect("video track");
            let mut out = d.clone();
            out.extend_from_slice(&mp4::build_mfra(&d, &top, video));
            std::fs::write(&args[3], &out).expect("write");
            println!(
                "appended mfra for track {video}: {} B -> {} B",
                d.len(),
                out.len()
            );
        }
        Some("canary") => {
            let d = read(&args[2]);
            for c in &args[3..] {
                let ascii = c.as_bytes().to_vec();
                let le: Vec<u8> = c.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
                let be: Vec<u8> = c.encode_utf16().flat_map(|u| u.to_be_bytes()).collect();
                let count = |n: &[u8]| d.windows(n.len()).filter(|w| *w == n).count();
                println!(
                    "{} canary \"{c}\": ascii={} utf16le={} utf16be={}",
                    args[2],
                    count(&ascii),
                    count(&le),
                    count(&be)
                );
            }
        }
        Some("bench") => bench(
            args.get(2)
                .and_then(|s| s.parse().ok())
                .unwrap_or(format::MAX_CONTENT as usize),
        ),
        Some("bench-stream") => bench_stream(
            args.get(2)
                .and_then(|s| s.parse().ok())
                .unwrap_or(format::MAX_CONTENT as usize),
        ),
        _ => {
            eprintln!("usage: mediatool jpeg|mp4|nalcmp|addmfra|canary|bench ...");
            std::process::exit(2)
        }
    }
}

fn mp4_report(path: &str) {
    let d = read(path);
    println!("== {path} ({} B, sha256 {})", d.len(), hex(&sha256(&d)));
    let top = match mp4::parse_boxes(&d, 0, d.len()) {
        Ok(t) => t,
        Err(e) => {
            println!("parse error: {e}");
            return;
        }
    };
    let mut tree = String::new();
    // Print the tree without the repeated moof/mdat pairs after the first two.
    let mut shown = Vec::new();
    let mut moofs = 0;
    for n in &top {
        if &n.typ == b"moof" {
            moofs += 1;
        }
        if (&n.typ == b"moof" || &n.typ == b"mdat") && moofs > 2 {
            continue;
        }
        shown.push(n.clone());
    }
    mp4::describe_tree(&d, &shown, 0, &mut tree);
    print!("{tree}");
    let inventory: BTreeMap<String, usize> = {
        let mut m = BTreeMap::new();
        fn walk(n: &[mp4::BoxNode], path: String, m: &mut BTreeMap<String, usize>) {
            for b in n {
                let p = if path.is_empty() {
                    b.type_str()
                } else {
                    format!("{path}/{}", b.type_str())
                };
                *m.entry(p.clone()).or_insert(0) += 1;
                walk(&b.children, p, m);
            }
        }
        walk(&top, String::new(), &mut m);
        m
    };
    println!("box inventory (path: count): {inventory:?}");
    println!("top level order: {}", {
        let mut s: Vec<String> = Vec::new();
        for n in &top {
            let t = n.type_str();
            if s.last().map(|l| l.starts_with(&t)).unwrap_or(false) {
                continue;
            }
            s.push(t);
        }
        s.join(",")
    });
    let tracks = mp4::tracks(&d, &top);
    let samples = mp4::samples(&d, &top);
    for t in &tracks {
        let ts: Vec<&mp4::Sample> = samples.iter().filter(|s| s.track == t.id).collect();
        let total: u64 = ts.iter().map(|s| s.duration as u64).sum();
        let bytes: usize = ts.iter().map(|s| s.size).sum();
        let secs = if t.timescale > 0 {
            total as f64 / t.timescale as f64
        } else {
            0.0
        };
        println!(
            "track {} {} entry={} ts={} samples={} duration={:.3}s bytes={} bitrate={:.0}bit/s {}",
            t.id,
            t.handler,
            t.entry,
            t.timescale,
            ts.len(),
            secs,
            bytes,
            if secs > 0.0 {
                bytes as f64 * 8.0 / secs
            } else {
                0.0
            },
            if t.handler == "vide" {
                format!("{}x{} rotation={}", t.width, t.height, t.rotation)
            } else {
                format!("channels={} rate={}", t.channels, t.samplerate)
            }
        );
        if t.handler == "vide" {
            let fps = if secs > 0.0 {
                ts.len() as f64 / secs
            } else {
                0.0
            };
            let (mut dmin, mut dmax) = (u32::MAX, 0u32);
            for s in &ts {
                if s.duration > 0 {
                    dmin = dmin.min(s.duration);
                    dmax = dmax.max(s.duration);
                }
            }
            println!(
                "  video: mean_fps={fps:.3} sample_duration_min={} max={} ({:.2}..{:.2} ms) sync_samples={}",
                dmin,
                dmax,
                dmin as f64 * 1000.0 / t.timescale.max(1) as f64,
                dmax as f64 * 1000.0 / t.timescale.max(1) as f64,
                ts.iter().filter(|s| s.sync).count()
            );
            if let Some(c) = &t.avcc {
                for s in &c.sps {
                    println!("  sps {} [{}]", hex(s), mp4::describe_sps(s));
                }
                for p in &c.pps {
                    println!("  pps {}", hex(p));
                }
                let mut nal_types: BTreeMap<u8, usize> = BTreeMap::new();
                let mut sei_types: BTreeMap<u32, usize> = BTreeMap::new();
                let mut sei_notes: BTreeSet<String> = BTreeSet::new();
                for s in &ts {
                    for n in mp4::nal_units(&d[s.offset..s.offset + s.size], c.nal_len) {
                        if n.is_empty() {
                            continue;
                        }
                        *nal_types.entry(n[0] & 31).or_insert(0) += 1;
                        if n[0] & 31 == 6 {
                            for (ty, _sz, note) in mp4::sei_payloads(n) {
                                *sei_types.entry(ty).or_insert(0) += 1;
                                if !note.is_empty() {
                                    sei_notes.insert(note);
                                }
                            }
                        }
                    }
                }
                println!("  nal types (type: count): {nal_types:?}");
                println!("  sei payload types (type: count): {sei_types:?}");
                for n in sei_notes.iter().take(5) {
                    println!("  sei user data: {n}");
                }
            }
            // Fragments: does every fragment's first video sample sync? durations?
            let mut frag: BTreeMap<usize, Vec<&mp4::Sample>> = BTreeMap::new();
            for s in &ts {
                if s.fragment != usize::MAX {
                    frag.entry(s.fragment).or_default().push(s);
                }
            }
            if !frag.is_empty() {
                let starts_sync = frag.values().filter(|v| v[0].sync).count();
                let durs: Vec<f64> = frag
                    .values()
                    .map(|v| {
                        v.iter().map(|s| s.duration as f64).sum::<f64>() / t.timescale.max(1) as f64
                    })
                    .collect();
                let syncs_inside: usize = frag
                    .values()
                    .map(|v| v.iter().skip(1).filter(|s| s.sync).count())
                    .sum();
                println!(
                    "  fragments={} starting_with_sync={} sync_samples_not_first={} fragment_durations_s={:?}",
                    frag.len(),
                    starts_sync,
                    syncs_inside,
                    durs.iter().map(|x| (x * 1000.0).round() / 1000.0).collect::<Vec<_>>()
                );
            }
        }
        if t.handler == "soun" {
            if let Some(asc) = &t.asc {
                println!("  asc {} [{}]", hex(asc), mp4::describe_asc(asc));
            }
            let mut first_ids: BTreeMap<u8, usize> = BTreeMap::new();
            for s in &ts {
                if s.size > 0 {
                    *first_ids.entry(d[s.offset] >> 5).or_insert(0) += 1;
                }
            }
            println!(
                "  aac first syntactic element id (0 SCE,1 CPE,2 CCE,3 LFE,4 DSE,5 PCE,6 FIL,7 END: count): {first_ids:?}"
            );
            let sizes: Vec<usize> = ts.iter().map(|s| s.size).collect();
            println!(
                "  aac frame sizes min={} max={}",
                sizes.iter().min().unwrap_or(&0),
                sizes.iter().max().unwrap_or(&0)
            );
        }
    }
    // mfra consistency, if present.
    if let Some(mfra) = top.iter().find(|b| &b.typ == b"mfra") {
        if let Some(tfra) = mfra.find(b"tfra") {
            let (track, entries) = mp4::parse_tfra(tfra.body(&d));
            let mut ok = 0;
            for (time, off) in &entries {
                if let Some(moof) = top
                    .iter()
                    .find(|b| &b.typ == b"moof" && b.offset as u64 == *off)
                {
                    let first = samples.iter().find(|s| {
                        s.track == track && s.offset > moof.offset && s.fragment != usize::MAX
                    });
                    if first.map(|s| s.dts == *time).unwrap_or(false) {
                        ok += 1;
                    }
                }
            }
            println!(
                "mfra: tfra track {track} entries={} pointing_at_moof_with_matching_tfdt={ok}",
                entries.len()
            );
        }
    }
    let times: Vec<String> = ["mvhd"]
        .iter()
        .filter_map(|_| {
            top.iter()
                .find(|b| &b.typ == b"moov")
                .and_then(|m| m.find(b"mvhd"))
        })
        .map(|m| {
            let b = m.body(&d);
            if b[0] == 1 {
                format!(
                    "{}/{}",
                    u64::from_be_bytes(b[4..12].try_into().unwrap()),
                    u64::from_be_bytes(b[12..20].try_into().unwrap())
                )
            } else {
                format!(
                    "{}/{}",
                    u32::from_be_bytes(b[4..8].try_into().unwrap()),
                    u32::from_be_bytes(b[8..12].try_into().unwrap())
                )
            }
        })
        .collect();
    println!("mvhd creation/modification: {times:?}");
}

fn nalcmp(src: &str, out: &str) {
    let a = read(src);
    let b = read(out);
    let ta = mp4::parse_boxes(&a, 0, a.len()).expect("source");
    let tb = mp4::parse_boxes(&b, 0, b.len()).expect("output");
    let (tra, trb) = (mp4::tracks(&a, &ta), mp4::tracks(&b, &tb));
    let (sa, sb) = (mp4::samples(&a, &ta), mp4::samples(&b, &tb));
    for handler in ["vide", "soun"] {
        let (Some(x), Some(y)) = (
            tra.iter().find(|t| t.handler == handler),
            trb.iter().find(|t| t.handler == handler),
        ) else {
            println!("{handler}: missing in one file");
            continue;
        };
        let units = |data: &[u8], samples: &[mp4::Sample], t: &mp4::TrackInfo| -> Vec<Vec<u8>> {
            let mut v = Vec::new();
            for s in samples.iter().filter(|s| s.track == t.id) {
                let bytes = &data[s.offset..s.offset + s.size];
                if let Some(c) = &t.avcc {
                    for n in mp4::nal_units(bytes, c.nal_len) {
                        v.push(n.to_vec());
                    }
                } else {
                    v.push(bytes.to_vec());
                }
            }
            v
        };
        let ua = units(&a, &sa, x);
        let ub = units(&b, &sb, y);
        let set_b: BTreeSet<[u8; 32]> = ub
            .iter()
            .filter(|u| u.len() >= 16)
            .map(|u| sha256(u))
            .collect();
        let same = ua
            .iter()
            .filter(|u| u.len() >= 16 && set_b.contains(&sha256(u)))
            .count();
        // 16-byte windows of source units found in the output (sampled: every unit's first 3 windows).
        let mut windows = BTreeSet::new();
        for u in &ub {
            for w in u.windows(16).step_by(1) {
                windows.insert(w.to_vec());
                if windows.len() > 4_000_000 {
                    break;
                }
            }
        }
        let mut hit = 0;
        let mut tried = 0;
        for u in &ua {
            for off in [u.len() / 4, u.len() / 2, 3 * u.len() / 4] {
                if u.len() >= off + 16 && u.len() >= 64 {
                    tried += 1;
                    if windows.contains(&u[off..off + 16]) {
                        hit += 1;
                    }
                }
            }
        }
        println!(
            "{handler}: source units={} output units={} identical_units(>=16B)={same} sampled_16B_windows_found={hit}/{tried}",
            ua.len(),
            ub.len()
        );
    }
}

fn vm_hwm() -> String {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("VmHWM:"))
                .map(|l| l.split_whitespace().skip(1).collect::<Vec<_>>().join(" "))
        })
        .unwrap_or_else(|| "n/a".into())
}

/// The sealer as the product runs it: content produced piece by piece (64 KiB, as a muxer
/// channel would hand it over), fragments dropped as soon as they are hashed (written to files in
/// the product), so memory is one held chunk plus the hash list. Then the reader over the same
/// object, chunk by chunk, from fragments re-derived by sealing again with the same key (the
/// test-only path; production reads files).
fn bench_stream(len: usize) {
    let k_f = [7u8; 32];
    let object_id = [9u8; 16];
    let hwm0 = vm_hwm();
    let mut piece = vec![0u8; 64 * 1024];
    let t0 = Instant::now();
    let mut s = format::Sealer::begin(&k_f, &object_id, KIND_VIDEO, 0, 10).streaming();
    let mut fed = 0usize;
    let mut counter = 0u64;
    while fed < len {
        let n = (len - fed).min(piece.len());
        for (i, b) in piece[..n].iter_mut().enumerate() {
            *b = (counter as usize + i) as u8;
        }
        counter += n as u64;
        s.append(&piece[..n]).expect("append");
        fed += n;
    }
    let obj = s
        .finish(
            StreamFacts {
                width: 1280,
                height: 720,
                duration_ms: 160_000,
            },
            &[],
        )
        .expect("finish");
    let seal = t0.elapsed();
    println!(
        "bench-stream: content={len} B class={} seal {:.1} ms = {:.1} MB/s; VmHWM before={hwm0} after={} (fragments dropped after hashing, as the product writes them to files)",
        obj.class_code,
        seal.as_secs_f64() * 1e3,
        len as f64 / seal.as_secs_f64() / 1e6,
        vm_hwm()
    );
}

fn bench(len: usize) {
    let k_f = [7u8; 32];
    let object_id = [9u8; 16];
    let content = format::sha256ctr(b"bench", len);
    let t0 = Instant::now();
    let mut s = format::Sealer::begin(&k_f, &object_id, KIND_VIDEO, 0, 10);
    let mut sealed_frags = 0usize;
    for piece in content.chunks(64 * 1024) {
        sealed_frags += s.append(piece).expect("append");
    }
    let obj = s
        .finish(
            StreamFacts {
                width: 1280,
                height: 720,
                duration_ms: 160_000,
            },
            &[],
        )
        .expect("finish");
    let seal = t0.elapsed();
    let desc = Descriptor {
        kind: KIND_VIDEO,
        flags: 0,
        class_code: obj.class_code,
        object_id,
        key_slot: [0; 32],
        manifest_hash: obj.manifest_hash,
        caption: vec![],
    };
    let t1 = Instant::now();
    let r = Reader::open(&k_f, &desc, &obj.manifest_blob).expect("open");
    let mut total = 0usize;
    for i in 0..r.chunks() {
        let f: Vec<&[u8]> = (0..4)
            .map(|k| obj.fragments[4 * i as usize + k].as_slice())
            .collect();
        total += r.read_chunk(i, &f).expect("chunk").len();
    }
    let open = t1.elapsed();
    assert_eq!(total, len);
    let blobs = obj.fragments.len() + 1;
    println!(
        "bench: content={len} B class={} fragments={} (+1 manifest, {} B on relays) appended-early={sealed_frags}",
        obj.class_code,
        obj.fragments.len(),
        blobs * FRAG
    );
    println!(
        "bench: seal {:.1} ms = {:.1} MB/s (content); open+hash+verify {:.1} ms = {:.1} MB/s; VmHWM={}",
        seal.as_secs_f64() * 1e3,
        len as f64 / seal.as_secs_f64() / 1e6,
        open.as_secs_f64() * 1e3,
        len as f64 / open.as_secs_f64() / 1e6,
        vm_hwm()
    );
}
