//! The archive walker of `ghost-verify monitor` (src/archive.rs): a fixture archive built in
//! the test — files by their SHA-256 names, the strict archive-index grammar, a recorded
//! leaves file, a served record — with the green run and one seeded violation per input
//! source. No network anywhere.

mod common;

use common::*;
use ghost_verify::archive::{ArchiveError, Monitor};
use ghost_verify::sigsum::RawLeaf;

/// Writes the fixture archive: the green manifest, its binding root, the APK, the artifact
/// and ES files — every file named by its SHA-256 — and the index line. `omit_apk` seeds the
/// missing-APK finding; `apk_bytes` overrides the archived APK's bytes.
fn fixture_archive(g: &Green, omit_apk: bool, swapped_apk: Option<&[u8]>) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let m = GHRM::parse(&g.manifest).unwrap();
    let rel = &m.body.releases[0];
    let put = |bytes: &[u8]| {
        write(&dir.path().join(hex::encode(sha256(bytes))), bytes);
    };
    put(&g.manifest);
    put(&g.root_doc);
    if !omit_apk {
        match swapped_apk {
            // A swap in a real archive: wrong bytes under the CLAIMED name (the walker's
            // name-hash check refuses it, before the rules run).
            Some(bytes) => write(&dir.path().join(hex::encode(rel.apk_sha256)), bytes),
            None => put(&g.signed),
        }
    }
    // The artifacts the manifest lists: kinds 1 and 3 are the build-id pair (kind 16's bytes
    // the walker does not need, but the archive is complete — write them too).
    for (_, sha, _) in &rel.artifacts {
        let bytes = match sha256(&g.lib) == *sha {
            true => g.lib.clone(),
            false => match sha256(&g.sym) == *sha {
                true => g.sym.clone(),
                false => b"escrow".to_vec(),
            },
        };
        put(&bytes);
    }
    put(&es_bytes_with_seq(2957)); // named by its SHA-256, the release's es_sha256 — the
                                   // same re-signed seq-2957 document the manifest embeds
    let log_key_hash = sha256(b"the policy log key");
    let index = format!(
        "1:1 {} {} 0 {}:{}\n",
        hex::encode(sha256(&g.manifest)),
        hex::encode(log_key_hash),
        hex::encode(rel.apk_sha256),
        hex::encode(rel.rollout_salt),
    );
    write(&dir.path().join("archive-index.txt"), &index);
    dir
}

/// One recorded C2SP leaf (base64 of `checksum ‖ signature ‖ key_hash`); the walker verifies
/// no leaf signatures (the log's admission job, §5.1 — see src/archive.rs), so the signature
/// bytes are arbitrary in the fixture.
fn leaf_line(checksum: &[u8; 32], key_hash: &[u8; 32]) -> String {
    let mut raw = Vec::with_capacity(128);
    raw.extend_from_slice(checksum);
    raw.extend_from_slice(&[0x5A; 64]);
    raw.extend_from_slice(key_hash);
    b64(&raw)
}

fn b64(bytes: &[u8]) -> String {
    const TBL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        let acc = (b0 << 16) | (u32::from(b1) << 8) | u32::from(b2);
        out.push(TBL[(acc >> 18) as usize & 63] as char);
        out.push(TBL[(acc >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            out.push(TBL[(acc >> 6) as usize & 63] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(TBL[acc as usize & 63] as char);
        } else {
            out.push('=');
        }
    }
    out
}

fn leaves_file(g: &Green, extra_watched: Option<[u8; 32]>) -> String {
    let key = sha256(&GHRT::parse(&g.root_doc).unwrap().body.release.keys[0]);
    let mut lines = leaf_line(&sha256(&sha256(&g.manifest)), &key);
    if let Some(key_hash) = extra_watched {
        lines.push('\n');
        lines.push_str(&leaf_line(
            &sha256(b"a leaf the archive cannot stand behind"),
            &key_hash,
        ));
    }
    lines
}

fn load_green(g: &Green, dir: &std::path::Path) -> Monitor {
    Monitor::load(dir, &g.root_doc, Some(&test_schedule_key()), DAY).unwrap()
}

#[test]
fn green_archive_runs_clean() {
    let (_w, g) = green();
    let dir = fixture_archive(&g, false, None);
    let mut monitor = load_green(&g, dir.path());
    monitor
        .attach_leaves_from_text(&leaves_file(&g, None))
        .unwrap();
    monitor
        .attach_served_record(&format!(
            "{{\"pair\":[1,1],\"mirror\":\"abc2d.onion:443\",\"first_seen_day\":{},\"last_seen_day\":{}}}",
            DAY - 1,
            DAY
        ))
        .unwrap();
    assert_eq!(monitor.run(), vec![]);
}

#[test]
fn a_missing_apk_surfaces_with_the_exact_flag_line() {
    let (_w, g) = green();
    let dir = fixture_archive(&g, true, None);
    let mut monitor = load_green(&g, dir.path());
    monitor
        .attach_served_record(&format!(
            "{{\"pair\":[1,1],\"mirror\":\"abc2d.onion:443\",\"first_seen_day\":{},\"last_seen_day\":{}}}",
            DAY - 1,
            DAY
        ))
        .unwrap();
    let findings = monitor.run();
    let m = GHRM::parse(&g.manifest).unwrap();
    assert_eq!(
        findings,
        vec![Finding::MissingApk {
            version_code: 100,
            apk_sha256: m.body.releases[0].apk_sha256,
        }]
    );
    assert_eq!(
        findings[0].to_string(),
        format!(
            "FLAG MISSING_APK version_code=100 apk_sha256={}",
            hex::encode(m.body.releases[0].apk_sha256)
        )
    );
}

#[test]
fn an_extra_watched_leaf_is_unmatched() {
    let (w, g) = green();
    let dir = fixture_archive(&g, false, None);
    let mut monitor = load_green(&g, dir.path());
    monitor
        .attach_leaves_from_text(&leaves_file(&g, Some(w.release_key_id())))
        .unwrap();
    monitor
        .attach_served_record(&format!(
            "{{\"pair\":[1,1],\"mirror\":\"abc2d.onion:443\",\"first_seen_day\":{},\"last_seen_day\":{}}}",
            DAY - 1,
            DAY
        ))
        .unwrap();
    let findings = monitor.run();
    assert_eq!(findings.len(), 1);
    assert!(findings[0].to_string().starts_with(&format!(
        "FLAG UNMATCHED_LEAF log=0 index=1 key_hash={}",
        hex::encode(w.release_key_id())
    )));
}

#[test]
fn a_short_served_window_surfaces() {
    let (_w, g) = green();
    let dir = fixture_archive(&g, false, None);
    let mut monitor = load_green(&g, dir.path());
    monitor
        .attach_leaves_from_text(&leaves_file(&g, None))
        .unwrap();
    monitor
        .attach_served_record(&format!(
            "{{\"pair\":[1,1],\"mirror\":\"abc2d.onion:443\",\"first_seen_day\":{},\"last_seen_day\":{}}}",
            DAY,
            DAY
        ))
        .unwrap();
    let findings = monitor.run();
    assert_eq!(
        findings,
        vec![Finding::ShortServed {
            pair: (1, 1),
            mirror: b"abc2d.onion:443".to_vec(),
        }]
    );
}

#[test]
fn malformed_inputs_refuse_with_fixed_words() {
    let (_w, g) = green();
    // A referenced sha-named file whose bytes hash otherwise (a swapped APK in a real
    // archive): the walker's name check refuses it before the rules run.
    let dir = fixture_archive(&g, false, None);
    let m = GHRM::parse(&g.manifest).unwrap();
    write(
        &dir.path().join(hex::encode(m.body.releases[0].apk_sha256)),
        "corruption",
    );
    let err = Monitor::load(dir.path(), &g.root_doc, Some(&test_schedule_key()), DAY).unwrap_err();
    assert_eq!(
        err,
        ArchiveError::FileHashMismatch {
            sha256: m.body.releases[0].apk_sha256,
        }
    );
    assert!(err.to_string().starts_with("ARCHIVE_FILE_HASH_MISMATCH"));

    // A broken index line.
    let dir2 = tempfile::tempdir().unwrap();
    write(&dir2.path().join("archive-index.txt"), "not-a-line\n");
    let err = Monitor::load(dir2.path(), &g.root_doc, Some(&test_schedule_key()), DAY).unwrap_err();
    assert!(err.to_string().starts_with("ARCHIVE_INDEX_LINE line=1"));

    // An index whose leaf the recorded leaves do not carry.
    let dir3 = fixture_archive(&g, false, None);
    let mut monitor = load_green(&g, dir3.path());
    let err = monitor
        .attach_leaves_from_text(&leaf_line(&sha256(b"another file"), &sha256(b"key")))
        .unwrap_err();
    assert!(err.to_string().starts_with("ARCHIVE_LEAF_MISMATCH"));
}

#[test]
fn a_swapped_apk_refuses_the_archive_before_the_rules() {
    let (_w, g) = green();
    let (_, other) = apk_pair(900 + 100 + 4096);
    let dir = fixture_archive(&g, false, Some(&other));
    let err = Monitor::load(dir.path(), &g.root_doc, Some(&test_schedule_key()), DAY).unwrap_err();
    assert!(err.to_string().starts_with("ARCHIVE_FILE_HASH_MISMATCH"));
}

#[test]
fn leaf_lines_round_trip_through_the_sigsum_parser() {
    let checksum = sha256(b"payload");
    let key_hash = sha256(b"key");
    let line = leaf_line(&checksum, &key_hash);
    let leaf = ghost_verify::sigsum::parse_leaf_line(&line).unwrap();
    assert_eq!(
        leaf,
        RawLeaf {
            checksum,
            signature: [0x5A; 64],
            key_hash,
        }
    );
    assert!(ghost_verify::sigsum::parse_leaf_line("aGVsbG8=").is_err());
}
