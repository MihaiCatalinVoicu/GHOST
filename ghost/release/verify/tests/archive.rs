//! The archive walker of `ghost-verify monitor` (src/archive.rs): a fixture archive built in
//! the test — files by their SHA-256 names, the strict archive-index grammar, a recorded
//! leaves file, a served record — with the green run and one seeded violation per input
//! source. No network anywhere.

mod common;

use common::*;
use ghost_verify::archive::{merge_observation, ArchiveError, Monitor};
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

#[test]
fn record_merge_extends_windows_and_keeps_mirrors_distinct() {
    let mut record = Vec::new();
    merge_observation(&mut record, (1, 1), b"a.onion:443", DAY);
    merge_observation(&mut record, (1, 1), b"a.onion:443", DAY + 3);
    merge_observation(&mut record, (1, 1), b"a.onion:443", DAY - 2);
    merge_observation(&mut record, (1, 1), b"b.onion:443", DAY + 1);
    assert_eq!(record.len(), 2, "one line per (pair, mirror)");
    let a = record
        .iter()
        .find(|o| o.mirror == b"a.onion:443".to_vec())
        .unwrap();
    assert_eq!((a.first_seen_day, a.last_seen_day), (DAY - 2, DAY + 3));
    let b = record
        .iter()
        .find(|o| o.mirror == b"b.onion:443".to_vec())
        .unwrap();
    assert_eq!((b.first_seen_day, b.last_seen_day), (DAY + 1, DAY + 1));
    // The record round-trips through its own exact NDJSON shape.
    let text = ghost_verify::archive::record_text(&record);
    assert_eq!(ghost_verify::archive::parse_record(&text).unwrap(), record);
}

/// A bundle around the green manifest, assembled as data (no log machinery needed: served-once
/// reads the manifest's pair, nothing cryptographic).
fn fixture_bundle(g: &Green) -> Vec<u8> {
    use ghost_client_release::bundle::GHRB;
    use ghost_client_release::chain::GHRC;
    use ghost_client_release::proof::GHRP;
    let proof = GHRP {
        message: [0; 32],
        log: 0,
        leaf_signature: [0; 64],
        leaf_key_id: [0; 32],
        tree_size: 1,
        leaf_index: 0,
        path: vec![],
        root_hash: [0; 32],
        log_signature: [0; 64],
        cosignatures: vec![],
    };
    GHRB {
        network: 2,
        chain: GHRC {
            network: 2,
            first_version: 1,
            roots: vec![GHRT::parse(&g.root_doc).unwrap()],
        },
        root_proofs: vec![],
        manifest: GHRM::parse(&g.manifest).unwrap(),
        manifest_proof: proof,
    }
    .to_bytes()
}

#[test]
fn served_once_merges_fixture_bundles_into_the_record() {
    let (_w, g) = green();
    let bundle = fixture_bundle(&g);
    let dir = tempfile::tempdir().unwrap();
    let record = dir.path().join("served.ndjson");
    let fetch = |_: &str| Ok(bundle.clone());
    let seen = ghost_verify::archive::served_once(
        &["m1.onion:443".to_string(), "m2.onion:443".to_string()],
        &record,
        DAY,
        &fetch,
    )
    .unwrap();
    assert_eq!(
        seen,
        vec![
            ("m1.onion:443".to_string(), (1, 1)),
            ("m2.onion:443".to_string(), (1, 1)),
        ]
    );
    let record_now =
        ghost_verify::archive::parse_record(&std::fs::read_to_string(&record).unwrap()).unwrap();
    assert_eq!(record_now.len(), 2);
    // A later run extends last_seen on the same line; the untouched mirror keeps its window.
    ghost_verify::archive::served_once(&["m1.onion:443".to_string()], &record, DAY + 5, &fetch)
        .unwrap();
    let record_now =
        ghost_verify::archive::parse_record(&std::fs::read_to_string(&record).unwrap()).unwrap();
    assert_eq!(
        record_now.len(),
        2,
        "no new line for a known (pair, mirror)"
    );
    let m1 = record_now
        .iter()
        .find(|o| o.mirror == b"m1.onion:443".to_vec())
        .unwrap();
    assert_eq!((m1.first_seen_day, m1.last_seen_day), (DAY, DAY + 5));
    let m2 = record_now
        .iter()
        .find(|o| o.mirror == b"m2.onion:443".to_vec())
        .unwrap();
    assert_eq!((m2.first_seen_day, m2.last_seen_day), (DAY, DAY));
    // A failing mirror refuses the run before anything is written.
    let before = std::fs::read_to_string(&record).unwrap();
    let failing = |_: &str| Err("the mirror is down".to_string());
    let err = ghost_verify::archive::served_once(
        &["m3.onion:443".to_string()],
        &record,
        DAY + 6,
        &failing,
    )
    .unwrap_err();
    assert!(err.starts_with("mirror m3.onion:443:"));
    assert_eq!(
        std::fs::read_to_string(&record).unwrap(),
        before,
        "all-or-nothing"
    );
}

#[test]
fn a_registered_drill_leaf_reports_through_the_walker() {
    let (_w, g) = green();
    let dir = fixture_archive(&g, false, None);
    let mut monitor = load_green(&g, dir.path());
    monitor
        .attach_served_record(&format!(
            "{{\"pair\":[1,1],\"mirror\":\"abc2d.onion:443\",\"first_seen_day\":{},\"last_seen_day\":{}}}",
            DAY - 1,
            DAY
        ))
        .unwrap();
    let drill_key = sha256(b"the drill root's release key");
    monitor.register_drill_key(drill_key);
    let mut leaves = leaves_file(&g, None);
    leaves.push('\n');
    leaves.push_str(&leaf_line(
        &sha256(b"a drill manifest not in the release archive"),
        &drill_key,
    ));
    monitor.attach_leaves_from_text(&leaves).unwrap();
    let findings = monitor.run();
    assert_eq!(
        findings,
        vec![Finding::DrillLeaf {
            log: 0,
            index: 1,
            key_hash: drill_key,
        }]
    );
    // Without registration the same leaf is not watched at all (rule (a) scopes watched
    // keys): nothing is flagged.
    let dir2 = fixture_archive(&g, false, None);
    let mut monitor2 = load_green(&g, dir2.path());
    monitor2
        .attach_served_record(&format!(
            "{{\"pair\":[1,1],\"mirror\":\"abc2d.onion:443\",\"first_seen_day\":{},\"last_seen_day\":{}}}",
            DAY - 1,
            DAY
        ))
        .unwrap();
    monitor2.attach_leaves_from_text(&leaves).unwrap();
    assert_eq!(monitor2.run(), vec![]);
}
