//! The `monitor` rule engine (Phase 14 design §5.3): leaves decoded by the caller
//! (the network half is a separate slice), findings pure in the input. The shared fixture
//! builders live in `tests/common`.

mod common;

use common::*;

#[test]
fn clean_run_finds_nothing() {
    let w = World::new();
    let root = GHRT::parse(&std::fs::read(&w.root).unwrap()).unwrap();
    let key = w.release_key_id();
    let leaves = vec![
        DecodedLeaf {
            index: 0,
            checksum: [0; 32],
            key_hash: key,
            doc: LeafDoc::Manifest {
                pair: (1, 1),
                verifies: true,
            },
        },
        DecodedLeaf {
            index: 1,
            checksum: [0; 32],
            key_hash: key,
            doc: LeafDoc::Manifest {
                pair: (1, 2),
                verifies: true,
            },
        },
    ];
    let served = vec![Served {
        mirror: b"mirror-a".to_vec(),
        current: Some(((1, 2), [0; 32])),
    }];
    let observations = vec![
        Observation {
            pair: (1, 1),
            mirror: b"mirror-a".to_vec(),
            first_seen_day: DAY - 2,
            last_seen_day: DAY - 1,
        },
        Observation {
            pair: (1, 2),
            mirror: b"mirror-a".to_vec(),
            first_seen_day: DAY - 1,
            last_seen_day: DAY,
        },
    ];
    let archive_day = vec![((1, 1), DAY - 2), ((1, 2), DAY - 1)];
    let input = MonitorInput {
        root: &root,
        logs: &[leaves],
        served: &served,
        observations: &observations,
        archive_day: &archive_day,
        today: DAY,
        archive: &[],
        es: &[],
        drill_keys: &[],
    };
    assert_eq!(run(&input), vec![]);
}

#[test]
fn the_rules_fire_one_by_one() {
    let w = World::new();
    let root = GHRT::parse(&std::fs::read(&w.root).unwrap()).unwrap();
    let key = w.release_key_id();
    let stranger = sha256(b"not a ghost key");
    let leaves = vec![
        DecodedLeaf {
            index: 0,
            checksum: [0; 32],
            key_hash: key,
            doc: LeafDoc::Unknown,
        },
        DecodedLeaf {
            index: 1,
            checksum: [0; 32],
            key_hash: key,
            doc: LeafDoc::Manifest {
                pair: (1, 5),
                verifies: false,
            },
        },
        DecodedLeaf {
            index: 2,
            checksum: [0; 32],
            key_hash: key,
            doc: LeafDoc::Manifest {
                pair: (1, 5),
                verifies: true,
            },
        },
        DecodedLeaf {
            index: 3,
            checksum: [0; 32],
            key_hash: stranger,
            doc: LeafDoc::Unknown,
        },
        DecodedLeaf {
            index: 4,
            checksum: [0; 32],
            key_hash: key,
            doc: LeafDoc::Manifest {
                pair: (1, 9),
                verifies: true,
            },
        },
    ];
    let served = vec![Served {
        mirror: b"m".to_vec(),
        current: Some(((1, 5), [0; 32])),
    }];
    let observations = vec![Observation {
        pair: (1, 5),
        mirror: b"m".to_vec(),
        first_seen_day: DAY,
        last_seen_day: DAY,
    }];
    let archive_day = vec![((1, 5), DAY + 9)];
    let input = MonitorInput {
        root: &root,
        logs: &[leaves],
        served: &served,
        observations: &observations,
        archive_day: &archive_day,
        today: DAY,
        archive: &[],
        es: &[],
        drill_keys: &[],
    };
    let findings = run(&input);
    assert!(findings.contains(&Finding::UnmatchedLeaf {
        log: 0,
        index: 0,
        key_hash: key
    }));
    assert!(findings.contains(&Finding::BadDocument { log: 0, index: 1 }));
    assert!(findings.contains(&Finding::PairOrder {
        log: 0,
        lower_index: 2,
        higher_index: 1,
        pair: (1, 5)
    }));
    // The never-served (1,9) is flagged; the stranger's unknown leaf is not ours to flag.
    assert!(findings.contains(&Finding::UnservedManifest { pair: (1, 9) }));
    assert!(findings.contains(&Finding::ShortServed {
        pair: (1, 5),
        mirror: b"m".to_vec()
    }));
    assert!(findings.contains(&Finding::LateArchive {
        pair: (1, 5),
        days: 9
    }));
    assert!(!findings
        .iter()
        .any(|f| matches!(f, Finding::UnmatchedLeaf { index: 3, .. })));
}

#[test]
fn archive_rules_green_run_finds_nothing() {
    let (w, g) = green();
    let root = GHRT::parse(&g.root_doc).unwrap();
    let m = GHRM::parse(&g.manifest).unwrap();
    let entry = green_entry(&g, &m, &root);
    assert_eq!(archive_findings(&w, &g, &[entry], &g.es, &[(1, 1)]), vec![]);
}

#[test]
fn rule_c_flags_a_missing_apk() {
    let (w, g) = green();
    let root = GHRT::parse(&g.root_doc).unwrap();
    let m = GHRM::parse(&g.manifest).unwrap();
    let mut entry = green_entry(&g, &m, &root);
    entry.releases[0].apk = None;
    let findings = archive_findings(&w, &g, &[entry], &g.es, &[(1, 1)]);
    assert!(findings.contains(&Finding::MissingApk {
        version_code: 100,
        apk_sha256: sha256(&g.signed)
    }));
}

#[test]
fn rule_c_flags_a_swapped_apk_on_every_clause_it_breaks() {
    let (w, g) = green();
    // The archive's file is another build's signed APK: its whole-file hash is not the
    // manifest's apk_sha256. Rule (c)'s clauses are checked in order and the FIRST failure
    // alone is flagged (a swapped file is caught at the hash; the core is never reached) —
    // the core clause's own test is rule_c_flags_a_wrong_attested_core below.
    let (_, other) = apk_pair(900 + 100 + 4096);
    let root = GHRT::parse(&g.root_doc).unwrap();
    let m = GHRM::parse(&g.manifest).unwrap();
    let mut entry = green_entry(&g, &m, &root);
    entry.releases[0].apk = Some(&other);
    let findings = archive_findings(&w, &g, &[entry], &g.es, &[(1, 1)]);
    assert!(findings.contains(&Finding::ApkHashMismatch {
        version_code: 100,
        apk_sha256: m.body.releases[0].apk_sha256
    }));
    assert!(
        !findings
            .iter()
            .any(|f| matches!(f, Finding::CoreMismatch { .. })),
        "the hash clause fires first; the core is not reached on a swapped file"
    );
}

#[test]
fn rule_c_flags_an_apk_that_is_not_a_signed_apk() {
    let (w, g) = green();
    let garbage = vec![0x55u8; 5000];
    // The manifest names the garbage (hash + length overrides): the hash clause passes and
    // the layout clause alone fires.
    let manifest = w.build_manifest(
        1,
        DAY,
        0,
        &[RelCfg::plain(100)],
        &["attest-1"],
        Some((sha256(&garbage), garbage.len() as u64)),
    );
    let root = GHRT::parse(&g.root_doc).unwrap();
    let m = GHRM::parse(&manifest).unwrap();
    let mut entry = green_entry(&g, &m, &root);
    entry.releases[0].apk = Some(&garbage);
    let findings = archive_findings(&w, &g, &[entry], &g.es, &[(1, 1)]);
    assert!(findings
        .iter()
        .any(|f| matches!(f, Finding::ApkLayout { version_code: 100 })));
    assert!(!findings
        .iter()
        .any(|f| matches!(f, Finding::ApkHashMismatch { .. })));
}

#[test]
fn rule_c_flags_a_wrong_attested_core() {
    let (w, g) = green();
    // The manifest declares another build's unsigned hash+length while the archive holds the
    // real signed APK: the hash clause passes, the core clause fires.
    let (other_unsigned, _) = apk_pair(900 + 100 + 2048);
    let mut rel = RelCfg::plain(100);
    rel.unsigned_override = Some((sha256(&other_unsigned), other_unsigned.len() as u64));
    let manifest = w.build_manifest(1, DAY, 0, &[rel], &["attest-1"], None);
    let root = GHRT::parse(&g.root_doc).unwrap();
    let m = GHRM::parse(&manifest).unwrap();
    let entry = green_entry(&g, &m, &root);
    let findings = archive_findings(&w, &g, &[entry], &g.es, &[(1, 1)]);
    assert!(findings.contains(&Finding::CoreMismatch {
        version_code: 100,
        unsigned_sha256: m.body.releases[0].unsigned_sha256
    }));
    assert!(!findings
        .iter()
        .any(|f| matches!(f, Finding::ApkHashMismatch { .. })));
}

#[test]
fn rule_c_flags_an_unattested_release() {
    let (w, g) = green();
    // The attestation block is emptied (a sigblock_or_empty): the manifest still parses and
    // its release block verifies, but no attester the root lists stands behind the release.
    let patched = resign_manifest(&w, &g.manifest, |m| {
        m.attestations[0] = SigBlock { entries: vec![] };
    });
    let root = GHRT::parse(&g.root_doc).unwrap();
    let m = GHRM::parse(&patched).unwrap();
    m.verify_block(&root.body.release.keys, root.body.release.threshold)
        .unwrap();
    let entry = green_entry(&g, &m, &root);
    let findings = archive_findings(&w, &g, &[entry], &g.es, &[(1, 1)]);
    assert!(findings.contains(&Finding::BadAttestation { version_code: 100 }));
}

#[test]
fn rule_d_accepts_an_append_only_es_chain() {
    let (w, g) = green();
    let root = GHRT::parse(&g.root_doc).unwrap();
    let m = GHRM::parse(&g.manifest).unwrap();
    let entry = green_entry(&g, &m, &root);
    let findings = archive_findings(&w, &g, &[entry], &g.es, &[(1, 1)]);
    assert!(!findings
        .iter()
        .any(|f| matches!(f, Finding::EsNotAppendOnly { .. })));
}

#[test]
fn rule_d_flags_a_changed_price() {
    let (w, g) = green();
    let root = GHRT::parse(&g.root_doc).unwrap();
    let m = GHRM::parse(&g.manifest).unwrap();
    let entry = green_entry(&g, &m, &root);
    // The second ES changes a covered epoch's price: ADR-22 rule 5's "prices never change".
    // The table stays valid (prices are multiples of 10), only different.
    let (es1_seq, _) = g.es[0].clone();
    let (es2_seq, es2) = es_doc(|c| {
        c.seq = es1_seq + 1;
        c.prices[0].pack_price_atomic += 10;
    });
    let findings = archive_findings(
        &w,
        &g,
        &[entry],
        &[(es1_seq, g.es[0].1.clone()), (es2_seq, es2)],
        &[(1, 1)],
    );
    assert!(findings.contains(&Finding::EsNotAppendOnly { es_seq: es2_seq }));
}

#[test]
fn rule_e_flags_a_build_id_mismatch_and_an_unreadable_file() {
    let (w, g) = green();
    let root = GHRT::parse(&g.root_doc).unwrap();
    let m = GHRM::parse(&g.manifest).unwrap();
    // Mutation 1: the symbol file describes another build.
    let other_sym = tiny_elf(&[9u8; 20]);
    let mut entry = green_entry(&g, &m, &root);
    entry.releases[0].artifacts[1] = Some(&other_sym);
    let findings = archive_findings(&w, &g, &[entry], &g.es, &[(1, 1)]);
    assert!(findings.contains(&Finding::BuildIdMismatch {
        version_code: 100,
        abi: "arm64-v8a"
    }));
    // Mutation 2: the symbol file is not an ELF at all.
    let junk = b"not an elf".to_vec();
    let mut entry = green_entry(&g, &m, &root);
    entry.releases[0].artifacts[1] = Some(&junk);
    let findings = archive_findings(&w, &g, &[entry], &g.es, &[(1, 1)]);
    assert!(findings.contains(&Finding::BuildIdUnreadable {
        version_code: 100,
        abi: "arm64-v8a"
    }));
    // Mutation 3: the archive holds no symbol file for the release.
    let mut entry = green_entry(&g, &m, &root);
    entry.releases[0].artifacts[1] = None;
    let findings = archive_findings(&w, &g, &[entry], &g.es, &[(1, 1)]);
    assert!(findings.contains(&Finding::MissingSymbols {
        version_code: 100,
        abi: "arm64-v8a"
    }));
}

#[test]
fn rule_g_flags_a_changed_salt_and_a_shared_salt() {
    let (w, g) = green();
    let root = GHRT::parse(&g.root_doc).unwrap();
    // Mutation 1: the same release (one apk_sha256) re-signed with another salt. The honest
    // builder refuses this with `--prev`; a malicious release key signs it, so the second
    // manifest is built unchained.
    let mut rel = RelCfg::plain(100);
    rel.salt = 0x44;
    let m2_bytes = w.build_manifest(2, DAY, 0, &[rel], &["attest-1"], None);
    let m1 = GHRM::parse(&g.manifest).unwrap();
    let m2 = GHRM::parse(&m2_bytes).unwrap();
    let e1 = green_entry(&g, &m1, &root);
    let e2 = green_entry(&g, &m2, &root);
    let findings = archive_findings(&w, &g, &[e1, e2], &g.es, &[(1, 1), (1, 2)]);
    assert!(findings.contains(&Finding::SaltChanged {
        apk_sha256: sha256(&g.signed)
    }));
    // Mutation 2: two distinct releases sharing one salt, in one manifest (each release's
    // archive APK is its own build, so the salt clause fires alone).
    let mut rel_a = RelCfg::plain(100);
    let mut rel_b = RelCfg::plain(200);
    rel_a.salt = 0x77;
    rel_b.salt = 0x77;
    let shared = w.build_manifest(1, DAY, 0, &[rel_a, rel_b], &["attest-1"], None);
    let m = GHRM::parse(&shared).unwrap();
    let (_, signed200) = apk_pair(900 + 200);
    let e = ArchiveManifest {
        manifest: &m,
        root: &root,
        releases: vec![
            ArchiveReleaseFiles {
                apk: Some(&g.signed),
                artifacts: vec![Some(&g.lib), Some(&g.sym), None],
            },
            ArchiveReleaseFiles {
                apk: Some(&signed200),
                artifacts: vec![Some(&g.lib), Some(&g.sym), None],
            },
        ],
    };
    let findings = archive_findings(&w, &g, &[e], &g.es, &[(1, 1)]);
    assert!(findings.contains(&Finding::SaltShared {
        salt: [0x77; 16],
        first_version_code: 100,
        second_version_code: 200
    }));
}

#[test]
fn rule_h_flags_a_staged_wire_change() {
    let (w, g) = green();
    // manifest-build refuses a wire-changing release at a staged permille; the malicious-key
    // path reaches the monitor re-signed.
    let patched = resign_manifest(&w, &g.manifest, |m| {
        m.body.releases[0].wire_changing = true;
        m.body.releases[0].rollout_permille = 500;
    });
    let root = GHRT::parse(&g.root_doc).unwrap();
    let m = GHRM::parse(&patched).unwrap();
    m.verify_block(&root.body.release.keys, root.body.release.threshold)
        .unwrap();
    let entry = green_entry(&g, &m, &root);
    let findings = archive_findings(&w, &g, &[entry], &g.es, &[(1, 1)]);
    assert!(findings.contains(&Finding::WireChangingStaged {
        version_code: 100,
        rollout_permille: 500
    }));
}

#[test]
fn rule_h_flags_a_floor_above_the_attested_max() {
    let (w, g) = green();
    // floor = the release's own version_code (parse's bound is ≤ the lowest release); the
    // attestation is then emptied, so §7.4 step 3's attested_max is 0 and the floor exceeds
    // it — exactly the decision the updater runs.
    let manifest = w.build_manifest(1, DAY, 100, &[RelCfg::plain(100)], &["attest-1"], None);
    let patched = resign_manifest(&w, &manifest, |m| {
        m.attestations[0] = SigBlock { entries: vec![] };
    });
    let root = GHRT::parse(&g.root_doc).unwrap();
    let m = GHRM::parse(&patched).unwrap();
    let entry = green_entry(&g, &m, &root);
    let findings = archive_findings(&w, &g, &[entry], &g.es, &[(1, 1)]);
    assert!(findings.contains(&Finding::FloorInvalid {
        root_version: 1,
        manifest_seq: 1,
        floor: 100,
        attested_max: 0
    }));
    assert!(findings.contains(&Finding::BadAttestation { version_code: 100 }));
}

#[test]
fn rule_h_flags_a_decreasing_issued_day() {
    let (w, g) = green();
    // The second manifest's issued_day is below the first's; without `--prev` the honest
    // builder does not see the pair, and the monitor catches what a release key signed.
    let m2_bytes = w.build_manifest(2, DAY - 5, 0, &[RelCfg::plain(100)], &["attest-1"], None);
    let root = GHRT::parse(&g.root_doc).unwrap();
    let m1 = GHRM::parse(&g.manifest).unwrap();
    let m2 = GHRM::parse(&m2_bytes).unwrap();
    let e1 = green_entry(&g, &m1, &root);
    let e2 = green_entry(&g, &m2, &root);
    let findings = archive_findings(&w, &g, &[e1, e2], &g.es, &[(1, 1), (1, 2)]);
    assert!(findings.contains(&Finding::IssuedDayDecreased {
        root_version: 1,
        manifest_seq: 2,
        issued_day: DAY - 5,
        previous_seq: 1,
        previous_day: DAY,
    }));
}

#[test]
fn rule_i_reports_a_registered_drill_leaf_and_never_as_a_release() {
    let (w, g) = green();
    // The drill key is the policy root's own release key: registered, its leaf reports as a
    // drill; unregistered, the same leaf hits the existing UNMATCHED_LEAF path (rule (a)
    // watches the policy root's keys). A stranger key the monitor was not taught at all would
    // not be watched either — rule (a) scopes watched keys (§5.3).
    let drill_key = w.release_key_id();
    let checksum = sha256(b"a drill manifest the release archive does not hold");
    let leaf = || DecodedLeaf {
        index: 7,
        checksum,
        key_hash: drill_key,
        doc: LeafDoc::Unknown,
    };
    let root = GHRT::parse(&g.root_doc).unwrap();
    let run_with = |drill_keys: &[[u8; 32]]| {
        let leaves = vec![leaf()];
        let input = MonitorInput {
            root: &root,
            logs: &[leaves],
            served: &[],
            observations: &[],
            archive_day: &[],
            today: DAY,
            archive: &[],
            es: &[],
            drill_keys,
        };
        run(&input)
    };
    // Registered: exactly the drill line, never UnmatchedLeaf.
    assert_eq!(
        run_with(&[drill_key]),
        vec![Finding::DrillLeaf {
            log: 0,
            index: 7,
            key_hash: drill_key,
        }]
    );
    assert_eq!(
        run_with(&[drill_key])[0].to_string(),
        format!(
            "FLAG DRILL_LEAF log=0 index=7 key_hash={}",
            hex::encode(drill_key)
        )
    );
    // Unregistered: the existing behaviour — a watched key the archive cannot stand behind.
    assert_eq!(
        run_with(&[]),
        vec![Finding::UnmatchedLeaf {
            log: 0,
            index: 7,
            key_hash: drill_key,
        }]
    );
    // A real violation beside a drill is not silenced: the drill leaf reports as a drill
    // (informational), the watched key's unknown leaf still alarms — and the alarm predicate
    // the CLI's exit code uses (any non-drill finding) sees only the second one.
    let drill_root_key = sha256(b"the drill root's own key hash");
    let drill_leaf = DecodedLeaf {
        index: 7,
        checksum,
        key_hash: drill_root_key,
        doc: LeafDoc::Unknown,
    };
    let real_leaf = DecodedLeaf {
        index: 3,
        checksum: sha256(b"a real release the archive lacks"),
        key_hash: drill_key,
        doc: LeafDoc::Unknown,
    };
    let leaves = vec![drill_leaf, real_leaf];
    let input = MonitorInput {
        root: &root,
        logs: &[leaves],
        served: &[],
        observations: &[],
        archive_day: &[],
        today: DAY,
        archive: &[],
        es: &[],
        drill_keys: &[drill_root_key],
    };
    let findings = run(&input);
    assert_eq!(
        findings,
        vec![
            Finding::DrillLeaf {
                log: 0,
                index: 7,
                key_hash: drill_root_key,
            },
            Finding::UnmatchedLeaf {
                log: 0,
                index: 3,
                key_hash: drill_key,
            },
        ]
    );
    let alarm = findings
        .iter()
        .any(|f| !matches!(f, Finding::DrillLeaf { .. }));
    assert!(alarm, "the real violation alarms");
    let drills_only = run_with(&[drill_key]);
    assert!(
        !drills_only
            .iter()
            .any(|f| !matches!(f, Finding::DrillLeaf { .. })),
        "drills alone are not an alarm"
    );
}
