//! The redemption flags of `ghost-relay serve` (Phase 8 design §10.5, §19.10): every refusal to
//! start exits with status 2 before the relay listens, and the production binary verifies the
//! schedule under the pinned key only (the committed stagenet ES verifies; the test ES never does).
//! A relay whose onion the ES lists for its slot in the current week starts, creates
//! `nullifiers.redb` in a fresh data directory, and after losing it starts again only with
//! `--nullifiers-reset` (or, for a data directory that never redeemed, `--nullifiers-init`).

use ghost_entitlement::grid;
use ghost_entitlement::onion::{hostname, Onion};
use ghost_entitlement::Schedule;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const BIN: &str = env!("CARGO_BIN_EXE_ghost-relay");
const STAGENET_ES: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../protocol/entitlement/schedule.ghes"
);
const TEST_ES: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../issuer/crates/entitlement/tests/fixtures/test_schedule.ghes"
);
const WAIT: Duration = Duration::from_secs(60);

fn serve(data_dir: &Path, extra: &[&str]) -> Child {
    Command::new(BIN)
        .args(["serve", "--data-dir"])
        .arg(data_dir)
        .args(["--listen", "127.0.0.1:0"])
        .args(extra)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

/// Stderr lines of a child, read on a thread.
fn lines(child: &mut Child) -> mpsc::Receiver<String> {
    let stderr = child.stderr.take().unwrap();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    rx
}

/// Runs `serve` and expects a refusal: exit status 2 and a stderr line containing `want`.
fn refused(data_dir: &Path, extra: &[&str], want: &str) {
    let mut child = serve(data_dir, extra);
    let rx = lines(&mut child);
    let mut output = Vec::new();
    let deadline = std::time::Instant::now() + WAIT;
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            while let Ok(l) = rx.recv_timeout(Duration::from_millis(200)) {
                output.push(l);
            }
            assert_eq!(status.code(), Some(2), "{extra:?}: {output:?}");
            assert!(
                output.iter().any(|l| l.contains(want)),
                "{extra:?}: expected '{want}' in {output:?}"
            );
            assert!(
                !output.iter().any(|l| l.contains("listening")),
                "{extra:?}: listened before refusing"
            );
            return;
        }
        while let Ok(l) = rx.try_recv() {
            output.push(l);
        }
        if std::time::Instant::now() > deadline {
            let _ = child.kill();
            panic!("{extra:?}: the relay did not exit ({output:?})");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Runs `serve` and expects it to start listening; then stops it.
fn starts(data_dir: &Path, extra: &[&str]) {
    let mut child = serve(data_dir, extra);
    let rx = lines(&mut child);
    let mut output = Vec::new();
    let deadline = std::time::Instant::now() + WAIT;
    loop {
        match rx.recv_timeout(Duration::from_millis(200)) {
            Ok(l) if l.contains("listening") => break,
            Ok(l) => output.push(l),
            Err(_) => {}
        }
        if let Some(status) = child.try_wait().unwrap() {
            panic!("{extra:?}: exited with {status:?} ({output:?})");
        }
        if std::time::Instant::now() > deadline {
            let _ = child.kill();
            panic!("{extra:?}: the relay did not start ({output:?})");
        }
    }
    child.kill().unwrap();
    child.wait().unwrap();
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// A slot of the committed stagenet ES listed in the current week, and its onion host name.
fn listed_slot() -> (u8, String) {
    let schedule = Schedule::verify(&std::fs::read(STAGENET_ES).unwrap()).unwrap();
    let week = grid::week(now());
    let slot = schedule
        .slots_in_week(week)
        .into_iter()
        .next()
        .expect("the committed schedule lists no relay for the current week (runbook K2)");
    let onion = Onion::parse(schedule.slot_onion(slot, week).unwrap()).unwrap();
    (slot, hostname(&onion.pubkey))
}

struct Files {
    dir: tempfile::TempDir,
}

impl Files {
    fn new() -> Self {
        Files {
            dir: tempfile::tempdir().unwrap(),
        }
    }

    fn write(&self, name: &str, contents: &[u8]) -> String {
        let p = self.dir.path().join(name);
        std::fs::write(&p, contents).unwrap();
        p.to_string_lossy().into_owned()
    }

    fn data(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }
}

#[test]
fn every_refusal_exits_before_listening() {
    let f = Files::new();
    let (slot, host) = listed_slot();
    let slot = slot.to_string();
    let good_host = f.write("hostname", format!("{host}\n").as_bytes());
    let unlisted = f.write("unlisted", format!("{}\n", hostname(&[7; 32])).as_bytes());
    let malformed = f.write("malformed", b"not an onion\n");
    let missing = f.data("no-such-hostname").to_string_lossy().into_owned();
    let test_es = TEST_ES.to_string();
    let mut tampered = std::fs::read(STAGENET_ES).unwrap();
    let middle = tampered.len() / 2;
    tampered[middle] ^= 1;
    let tampered = f.write("tampered.ghes", &tampered);
    let data = f.data("data");
    let es = STAGENET_ES;

    // Flags: all three or none; reset and init exclusive; reset or init alone is no mode.
    refused(&data, &["--schedule", es, "--slot", &slot], "usage:");
    refused(&data, &["--onion-hostname-file", &good_host], "usage:");
    refused(&data, &["--nullifiers-reset"], "usage:");
    refused(
        &data,
        &[
            "--schedule",
            es,
            "--slot",
            &slot,
            "--onion-hostname-file",
            &good_host,
            "--nullifiers-reset",
            "--nullifiers-init",
        ],
        "usage:",
    );
    refused(
        &data,
        &[
            "--schedule",
            es,
            "--slot",
            "x",
            "--onion-hostname-file",
            &good_host,
        ],
        "usage:",
    );
    // The hostname file: missing, malformed, not listed; the slot: another one, out of range.
    refused(
        &data,
        &[
            "--schedule",
            es,
            "--slot",
            &slot,
            "--onion-hostname-file",
            &missing,
        ],
        "onion hostname file:",
    );
    refused(
        &data,
        &[
            "--schedule",
            es,
            "--slot",
            &slot,
            "--onion-hostname-file",
            &malformed,
        ],
        "does not hold one canonical",
    );
    refused(
        &data,
        &[
            "--schedule",
            es,
            "--slot",
            &slot,
            "--onion-hostname-file",
            &unlisted,
        ],
        "does not list this relay's onion",
    );
    refused(
        &data,
        &[
            "--schedule",
            es,
            "--slot",
            "7",
            "--onion-hostname-file",
            &good_host,
        ],
        "does not list this relay's onion",
    );
    refused(
        &data,
        &[
            "--schedule",
            es,
            "--slot",
            "32",
            "--onion-hostname-file",
            &good_host,
        ],
        "relay slot must be 0..31",
    );
    // The schedule: the pinned key only (a test schedule never verifies in production), untampered.
    refused(
        &data,
        &[
            "--schedule",
            &test_es,
            "--slot",
            &slot,
            "--onion-hostname-file",
            &good_host,
        ],
        "schedule: NoPinnedKey",
    );
    refused(
        &data,
        &[
            "--schedule",
            &tampered,
            "--slot",
            &slot,
            "--onion-hostname-file",
            &good_host,
        ],
        "schedule: Signature",
    );
    refused(
        &data,
        &[
            "--schedule",
            &missing,
            "--slot",
            &slot,
            "--onion-hostname-file",
            &good_host,
        ],
        "schedule file:",
    );
    // No refusal wrote anything into the data directory: neither a nullifier store nor a relay
    // key, so a refused first start never turns a fresh directory into one that "redeemed before"
    // (review S3-MR-2), and the correct flags then start it.
    assert!(!data.join("nullifiers.redb").exists());
    assert!(!data.join("relay.key").exists());
    starts(
        &data,
        &[
            "--schedule",
            es,
            "--slot",
            &slot,
            "--onion-hostname-file",
            &good_host,
        ],
    );
    assert!(data.join("nullifiers.redb").exists());
}

#[test]
fn a_listed_relay_starts_and_a_lost_store_needs_a_reset() {
    let f = Files::new();
    let (slot, host) = listed_slot();
    let slot = slot.to_string();
    let hostname_file = f.write("hostname", format!("{host}\n").as_bytes());
    let flags = [
        "--schedule",
        STAGENET_ES,
        "--slot",
        &slot,
        "--onion-hostname-file",
        &hostname_file,
    ];
    let with = |extra: &'static str| {
        let mut v = flags.to_vec();
        v.push(extra);
        v
    };

    // A fresh data directory: the store is created.
    let data = f.data("fresh");
    starts(&data, &flags);
    assert!(data.join("nullifiers.redb").exists());
    // A restart finds it. --nullifiers-init is for a directory that never had a store.
    starts(&data, &flags);
    refused(
        &data,
        &with("--nullifiers-init"),
        "--nullifiers-init is one-time",
    );
    // Lost: refused, --nullifiers-init is still refused (it would reopen every redeemed token of
    // the open weeks, review S3-MR-1), and --nullifiers-reset starts it (runbook O1).
    std::fs::remove_file(data.join("nullifiers.redb")).unwrap();
    refused(&data, &flags, "nullifier store is missing");
    refused(
        &data,
        &with("--nullifiers-init"),
        "--nullifiers-init is one-time",
    );
    starts(&data, &with("--nullifiers-reset"));
    starts(&data, &flags);

    // A data directory of a relay that never redeemed (Phase 5-7): its relay.key exists. Without
    // the one-time --nullifiers-init it is refused like a lost store; with it, it starts.
    let old = f.data("phase7");
    std::fs::create_dir_all(&old).unwrap();
    std::fs::write(old.join("relay.key"), [9u8; 32]).unwrap();
    refused(&old, &flags, "nullifier store is missing");
    starts(&old, &with("--nullifiers-init"));
    starts(&old, &flags);
    // Once is once: after that store is lost, init is refused as in any directory that had one.
    std::fs::remove_file(old.join("nullifiers.redb")).unwrap();
    refused(
        &old,
        &with("--nullifiers-init"),
        "--nullifiers-init is one-time",
    );
    refused(&old, &flags, "nullifier store is missing");
    starts(&old, &with("--nullifiers-reset"));
    // Without the redemption flags no store is needed at all.
    let plain = f.data("plain");
    starts(&plain, &[]);
    assert!(!plain.join("nullifiers.redb").exists());
}

/// Every binding tag and serial is keyed with `relay.key`, so a store kept under another key would
/// answer an identical retry `REPLAYED` (MS-8). The key is never silently replaced (review
/// S3-MR-3): a key file of the wrong length is refused and left as it is, and a new key next to a
/// kept store is refused until `--nullifiers-reset` (runbook O1).
#[test]
fn the_relay_key_is_never_replaced_under_a_kept_store() {
    let f = Files::new();
    let (slot, host) = listed_slot();
    let slot = slot.to_string();
    let hostname_file = f.write("hostname", format!("{host}\n").as_bytes());
    let flags = [
        "--schedule",
        STAGENET_ES,
        "--slot",
        &slot,
        "--onion-hostname-file",
        &hostname_file,
    ];
    let data = f.data("keyed");
    starts(&data, &flags);
    let key_file = data.join("relay.key");
    let key = std::fs::read(&key_file).unwrap();
    assert_eq!(key.len(), 32);

    // A truncated key file is refused, by `serve` and by `mint`, and never overwritten.
    std::fs::write(&key_file, &key[..31]).unwrap();
    refused(&data, &flags, "relay key");
    refused(&data, &[], "relay key");
    let ns = "00".repeat(32);
    let status = Command::new(BIN)
        .args(["mint", "--data-dir"])
        .arg(&data)
        .args(["--namespace", &ns, "--read", "--expiry", "4000000000"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(2));
    assert_eq!(std::fs::read(&key_file).unwrap(), &key[..31]);

    // A lost key next to the kept store: refused, also on the next try; the reset adopts the new
    // key and refuses the open weeks.
    std::fs::remove_file(&key_file).unwrap();
    refused(&data, &flags, "another relay key");
    refused(&data, &flags, "another relay key");
    let with_reset = [&flags[..], &["--nullifiers-reset"]].concat();
    starts(&data, &with_reset);
    starts(&data, &flags);
}
